"""Window lifecycle and independent capability review, recorded by the ledger."""
from copy import deepcopy
import time

from .packages import ClientError, fields, string
from .constants import COORDINATOR, step
from .task_state import security_schema
from .upgrade import identifier, sha256, version
import 协作升级 as rules


ACTIONS = {"window-admin", "capability-request", "capability-resolve"}
OPERATIONS = {"transfer", "disable", "pause", "archive", "revoke-all"}


def _cap_context(state, actor, record, values=None, create=False, now=0, event_id="capability-context"):
    if security_schema(state, 3) < 5:
        return {}
    import 协作执行 as execution
    values = values or record
    if values.get("context_id") and create:
        key = str(values["context_id"]) + ":" + str(values["context_version"])
        if key not in state.get("security", {}).get("execution", {}).get("contexts", {}):
            initial = execution.default_context(state, actor)
            rules.require(initial["context_id"] == values["context_id"] and initial["version"] == values["context_version"], "申请绑定的配置不存在")
            execution.default_context(state, actor, True, now, event_id)
    selected = execution.context_record(state, actor, {"context_id": values["context_id"], "version": values["context_version"]}) if values.get("context_id") else execution.default_context(state, actor, create, now, event_id)
    rules.require(record.get("kind") != "environment" or record.get("environment") == selected["config"]["environment"], "环境证据须对应所选配置，不自动改绑")
    requested = values.get("context_dimensions")
    if requested is None and record.get("applicability"):
        requested = list(record["applicability"]["dependencies"])
    return execution.bind_evidence(state, actor, record, selected, values.get("project_id"), values.get("capability"), requested)


def allowed(state, actor, name):
    subject = rules.identity(state, name) or {}
    person = rules.identity(state, actor) or {}
    return bool(subject.get("kind") == "executor" and person.get("kind") == "human" and
                rules.active(state, actor) and (rules.system_admin(state, actor) or subject.get("owner") == actor))


def reviewers(state, project, name):
    # Use real human project grants. A scoped AI delegation cannot approve evidence.
    return sorted(key.removeprefix("identity:") for key, subject in state["pilot"].items()
                  if key.startswith("identity:") and subject.get("kind") == "human" and
                  key != "identity:" + name and rules.active(state, key.removeprefix("identity:")) and
                  set(rules.grant(state, project, key.removeprefix("identity:"))["roles"]) & {"manager", "receiver"})


def _execution_occupancies(state, name):
    if security_schema(state) < 5:
        return []
    from 协作执行 import blocking_records
    claims = {key for key, row in state.get('claims', {}).items() if row.get('origin') == name}
    data = state['security'].get('execution', {})
    return [row for row in blocking_records(state) if row.get('claim_id') in claims] + [
        row for row in data.get('actions', {}).values() if row.get('executor_id') == name and
        row.get('state') in {'start-authorized', 'running', 'unconfirmed'}]


def view(state, actor, name):
    if not allowed(state, actor, name):
        raise ClientError("须由窗口责任人或管理员查看处置影响", 403)
    subject = rules.identity(state, name)
    claims = [{"claim_id": c["claim_id"], "task_id": c["task_id"], "epoch": c["epoch"],
               "L": c["L"], "E": deepcopy(c["E"]), "W": deepcopy(c["W"]), "R": deepcopy(c.get("R", []))}
              for c in state["claims"].values() if c["origin"] == name and (c["L"] == "active" or c.get("R"))]
    grants = [{"project_id": key.split(":", 2)[1], **deepcopy(row)} for key, row in state["pilot"].items()
              if key.startswith("grant:") and key.endswith(":" + name) and (row["roles"] or row["resources"])]
    delegations = [deepcopy(row) for key, row in state["round"].items()
                   if key.startswith("delegation:") and row["executor_id"] == name and not row["revoked"]]
    return {"executor_id": name, "window": subject.get("window"), "window_name": subject.get("window_name"),
            "owner": subject["owner"], "status": subject["status"], "version": subject["credential"],
            "claims": claims, "grants": grants, "delegations": delegations,
            "execution_occupancies": len(_execution_occupancies(state, name)),
            "transfer_allowed": not claims and not _execution_occupancies(state, name),
            "consequence": "处置不会证明外部程序已停止，不释放领取或资源；实际停止、交接与验收须另行办理。"}


def payload(state, actor, action, body, key):
    if action == "window-admin":
        fields(body, "request_id name version operation reason" + (" owner" if body.get("operation") == "transfer" else ""))
        operation = body["operation"]
        if not isinstance(operation, str) or operation not in OPERATIONS:
            raise ClientError("窗口处置操作无效")
        return {"op": action, "name": identifier(body["name"], "窗口身份"), "version": version(body["version"]),
                "operation": operation, "reason": string(body["reason"], "处置依据"),
                **({"owner": identifier(body["owner"], "新责任人")} if operation == "transfer" else {})}
    if action == "capability-request":
        context_fields = " context_id context_version" if "context_id" in body or "context_version" in body else ""
        fields(body, "request_id project_id capability kind value evidence environment expires" + context_fields +
               (" context_dimensions" if "context_dimensions" in body else ""))
        cap = string(body["capability"], "能力标识", 48)
        if not rules.CAP_ID.fullmatch(cap) or not isinstance(body["kind"], str) or body["kind"] not in {"skill", "environment"}:
            raise ClientError("能力标识或类别无效")
        fields(body["evidence"], "note sha256")
        record = {"kind": body["kind"], "value": string(body["value"], "能力值", 100),
                  "evidence": {"note": string(body["evidence"]["note"], "核实证据"),
                               "sha256": sha256(body["evidence"]["sha256"])},
                  "environment": string(body["environment"], "环境标识", 160), "expires": body["expires"]}
        record.update(_cap_context(state, actor, record, body))
        return {"op": action, "id": "vr-" + key[:30], "project_id": identifier(body["project_id"], "项目"),
                "name": actor, "capability": cap, "record": record}
    fields(body, "request_id verification_id version decision level reason")
    if (not isinstance(body["decision"], str) or body["decision"] not in {"approve", "reject"} or
            not isinstance(body["level"], str) or body["level"] not in {"probed", "verified"}):
        raise ClientError("核实结论或证据等级无效")
    return {"op": action, "id": identifier(body["verification_id"], "核实申请"), "version": version(body["version"]),
            "decision": body["decision"], "level": body["level"], "reason": string(body["reason"], "核实依据")}


def plan(service, actor, action, key, body, state):
    if action not in ACTIONS:
        return None
    if state["pilot"].get("format", {}).get("schema") not in {3, 4, 5}:
        raise ClientError("须先迁移窗口数据合同", 409)
    p = payload(state, actor, action, body, key)
    candidate = deepcopy(state)
    apply(candidate, p, actor, time.time(), "transport-validation")
    extra = {"executor_id": p["name"]} if action == "window-admin" else {"verification_id": p["id"]}
    return {"round_result": extra, "steps": [step(COORDINATOR, "pilot", p, {"generation": state["generation"]})]}


def _revoke(state, name, actor, now, event_id, reason):
    for key, record in state["round"].items():
        if key.startswith("delegation:") and record["executor_id"] == name and not record["revoked"]:
            previous = {k: deepcopy(v) for k, v in record.items() if k != "history"}
            record.setdefault("history", []).append(previous)
            record.update(revoked=True, version=record["version"] + 1, revoke_reason=reason,
                          revoked_by=actor, revoked_at=now, revoked_event=event_id)


def apply(state, p, actor, now, event_id):
    if p["op"] != "window-admin":
        return capability_action(state, p, actor, now, event_id)
    name, operation = p.get("name"), p.get("operation")
    rules.require(allowed(state, actor, name), "须由窗口责任人或管理员处置", "intent-final")
    subject = rules.identity(state, name)
    rules.require(type(p.get("version")) is int and subject["credential"] == p["version"], "凭据版本已变化")
    rules.require(operation in OPERATIONS and isinstance(p.get("reason"), str) and 0 < len(p["reason"].strip()) <= 2000,
                  "处置操作或依据无效")
    if operation == "transfer":
        owner = rules.identity(state, p.get("owner")) or {}
        rules.require(owner.get("kind") == "human" and rules.active(state, p.get("owner")) and p["owner"] != subject["owner"],
                      "须选择另一位有效人员作为新责任人")
        rules.require(not any(c["origin"] == name and (c["L"] == "active" or c.get("R")) for c in state["claims"].values()),
                      "窗口仍有活动领取、待验交付或资源占用；先完成停止、交接或验收再更换责任人")
        rules.require(not _execution_occupancies(state, name),
                      '窗口还有未收口动作或物理占用；结束领取不代替实际收尾，暂不能更换责任人')
        previous_owner = subject["owner"]
        subject["owner"] = p["owner"]
        # A later return to the previous owner must not resurrect old independent grants.
        for key, grant in state["pilot"].items():
            if key.startswith("grant:") and key.endswith(":" + name):
                grant.update(roles=[], resources=[], version=grant.get("version", 0) + 1)
        subject.pop("parent", None)
    else:
        previous_owner = subject["owner"]
    _revoke(state, name, actor, now, event_id, p["reason"])
    if operation != "revoke-all":
        subject.update(status={"pause": "paused", "archive": "archived"}.get(operation, "disabled"),
                       credential=subject["credential"] + 1, credential_reason=p["reason"], token_expires=0)
        for key, enrollment in state["round"].items():
            if key.startswith("enrollment:") and enrollment.get("name") == name and enrollment.get("state") == "pending":
                enrollment.update(state="revoked", terminal_event=event_id)
    state["round"]["window-event:" + event_id] = {"name": name, "operation": operation, "by": actor,
        "previous_owner": previous_owner, "owner": subject["owner"], "reason": p["reason"], "at": now,
        "credential": subject["credential"], "status": subject["status"]}
    # E/L/R remain facts. This operation neither stops external execution nor releases locks.


def capability_action(state, p, actor, now, event_id):
    records = state["round"]
    key = "verification:" + str(p.get("id"))
    if p["op"] == "capability-request":
        name, project, record = p.get("name"), p.get("project_id"), p.get("record", {})
        subject = rules.identity(state, name) or {}
        rules.require(actor == name and subject.get("kind") in {"executor", "human"} and
                      rules.active(state, name) and bool(rules.roles(state, project, name)), "须由有效项目成员为自己申请核实", "intent-final")
        rules.require(key not in records and isinstance(p.get("capability"), str) and rules.CAP_ID.fullmatch(p["capability"]),
                      "核实申请或能力编号无效")
        rules.require(record.get("kind") in {"skill", "environment"} and isinstance(record.get("environment"), str) and
                      isinstance(record.get("value"), str) and 0 < len(record["value"]) <= 100 and
                      type(record.get("expires")) is int and now < record["expires"] <= now + 366 * 86400,
                      "核实范围、环境或有效期无效")
        evidence = record.get("evidence", {})
        rules.require(isinstance(evidence, dict) and isinstance(evidence.get("sha256"), str) and rules.SHA.fullmatch(evidence["sha256"]) and
                      isinstance(evidence.get("note"), str) and 0 < len(evidence["note"].strip()) <= 2000, "须提供证据说明和 SHA256")
        is_v5 = security_schema(state, 3) >= 5
        rules.require(is_v5 or record["kind"] != "environment" or record["environment"] == subject.get("environment", "human"),
                      "环境证据与当前窗口环境不符")
        capkey = f"cap:{project}:{name}:{p['capability']}"
        binding_values = {**record, "project_id": project, "capability": p["capability"]}
        record = {**deepcopy(record), **_cap_context(state, name, record, binding_values, True, now, event_id)}
        records[key] = {"id": p["id"], "project_id": project, "name": name, "capability": p["capability"],
                        "record": deepcopy(record), "state": "pending", "version": 1, "at": now, "event": event_id,
                        "capability_version": state["pilot"].get(capkey, {}).get("version", 0)}
        return
    request = records.get(key)
    rules.require(request and actor in reviewers(state, request["project_id"], request["name"]),
                  "须由另一位本项目管理者或验收人核实", "intent-final")
    rules.require(request["state"] == "pending" and type(p.get("version")) is int and request["version"] == p["version"],
                  "核实申请已处理或版本已变化")
    rules.require(p.get("decision") in {"approve", "reject"} and p.get("level") in {"probed", "verified"} and
                  isinstance(p.get("reason"), str) and 0 < len(p["reason"].strip()) <= 2000, "核实结论或依据无效")
    if p["decision"] == "approve":
        subject = rules.identity(state, request["name"]) or {}
        record = request["record"]
        is_v5 = security_schema(state, 3) >= 5
        if is_v5:
            import 协作执行 as execution
            selected = execution.context_record(state, request["name"], {"context_id": record["context_id"], "version": record["context_version"]})
            bound = execution.bind_evidence(state, request["name"], record, selected, request["project_id"], request["capability"],
                                           list(record["applicability"]["dependencies"]), verified=True)
            applicable = execution.match_context(state, request["name"], {**record, **bound}, selected,
                                                  {"id": request["capability"], "project_id": request["project_id"], "evidence": p["level"]})
        else:
            bound = {}
            applicable = record["kind"] != "environment" or record["environment"] == subject.get("environment", "human")
        rules.require(rules.active(state, request["name"]) and rules.roles(state, request["project_id"], request["name"]) and
                      record["expires"] > now and applicable,
                      "申请者权限、环境或证据有效期已变化")
        capkey = f"cap:{request['project_id']}:{request['name']}:{request['capability']}"
        rules.require(state["pilot"].get(capkey, {}).get("version", 0) == request["capability_version"],
                      "能力记录已变化；保留本次申请，请重新核对后提交新申请")
        state["pilot"][capkey] = {**deepcopy(record), **bound, "level": p["level"], "by": actor, "recorded": now,
                                 "version": request["capability_version"] + 1, "verification_id": request["id"]}
        # Verification changes later eligibility; it does not stop actual running work.
    request.update(state="approved" if p["decision"] == "approve" else "rejected", version=request["version"] + 1,
                   resolved_by=actor, resolved_at=now, resolution=p["reason"], level=p["level"], resolution_event=event_id)


def requests_view(state, actor):
    return [{**deepcopy(row), "reviewers": reviewers(state, row["project_id"], row["name"]),
             "can_resolve": actor in reviewers(state, row["project_id"], row["name"])}
            for key, row in state["round"].items() if key.startswith("verification:") and
            (actor == row["name"] or actor == rules.responsible(state, row["name"]) or
             actor in reviewers(state, row["project_id"], row["name"]))]
