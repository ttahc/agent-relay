"""Project capability definitions and authenticated, version-bound probe work."""
from copy import deepcopy
import hmac
import re
import time

from .constants import COORDINATOR, step
from .packages import ClientError, fields, string
from .task_state import security_schema
from .upgrade import identifier, version
from 协作存储 import digest, encoded
import 协作升级 as rules


READER = 8
LEASE_SECONDS = 120
PROBE_SECONDS = 3600
TEMPLATES = {
    "hermes-api": ("environment", "available"),
    "git-version": ("tools_version", None),
    "workspace-rw": ("environment", "rw"),
}
PROBE_WRITES = {"capability-probe-claim", "capability-probe-result"}
ADMIN_WRITE = "capability-verifier-save"
CATALOG_WRITE = "project-capability-save"
OPS = PROBE_WRITES | {ADMIN_WRITE, CATALOG_WRITE, "catalog-capability-request",
                     "catalog-capability-resolve", "catalog-capability-declare"}


def state_ready(state):
    return security_schema(state) == 5 and rules.enabled(state)


def catalog_key(project, capability):
    return f"catalog:{project}:{capability}"


def revision(state, project, capability, number):
    return state["round"].get(f"catalog-revision:{project}:{capability}:{number}")


def record_key(project, name, capability, number):
    return f"catalog-cap:{project}:{name}:{capability}:{number}"


def manage(state, actor, project):
    return ((rules.identity(state, actor) or {}).get("kind") == "human" and
            rules.manager(state, project, actor))


def verifier(state, name):
    return state["round"].get("capability-verifier:" + name, {})


def verifier_actor(name, number):
    return f"probe-{name}-{number}"


def authenticate(state, headers):
    auth = headers[0] if len(headers) == 1 else ""
    match = re.fullmatch(r"Bearer ([A-Za-z0-9][A-Za-z0-9_-]{0,47})\.([A-Za-z0-9_-]{43})", auth, re.I)
    if match:
        name, secret = match.groups()
        row = verifier(state, name)
        if row.get("active") and hmac.compare_digest(row["token_sha256"], digest(secret.encode("ascii"))):
            return verifier_actor(name, row["version"])
    raise ClientError("需要有效的独立探测凭据", 401)


def report_scope(state, job, row, now):
    subject = rules.identity(state, job["name"]) or {}
    request = job["record"]
    definition = revision(state, job["project_id"], job["capability"], job["definition_version"])
    return (row.get("active") and job["project_id"] in row["projects"] and
            request["environment_id"] == row["environment_id"] and
            definition and definition["probe"] in row["templates"] and
            rules.LEVEL[row["level"]] >= rules.LEVEL[definition["evidence"]] and
            subject.get("status") == "active" and subject.get("credential") == job["credential_version"] and
            subject.get("token_expires", now + 1) > now and bool(rules.roles(state, job["project_id"], job["name"])))


def selected_context(state, job):
    from 协作执行 import context_record
    from .environments import selected
    record = job["record"]
    context = context_record(state, job["name"], {"context_id": record["context_id"],
                                                    "version": record["context_version"]})
    environment = selected(state, job["name"], record["environment_id"])
    rules.require(context.get("environment_id") == environment["id"] and
                  context.get("environment_version") == environment["version"] == record["environment_version"],
                  "探测环境已变化，须使用当前执行配置重新申请")
    return context


def status_at(row, now):
    if row.get("definition_version") and row["state"] in {"approved", "pending"} and row["record"].get("expires", float("inf")) <= now:
        return "expired"
    if row["state"] in {"pending", "probing"} and (row.get("deadline", float("inf")) <= now or
            row.get("lease_expires", float("inf")) <= now):
        return "expired"
    return row["state"]


def definitions(state, project):
    return sorted((deepcopy(row) for key, row in state["round"].items()
                   if key.startswith(f"catalog:{project}:")), key=lambda row: row["id"])


def task_requirements(state, project, rows, task_id=None):
    if not isinstance(rows, list):
        return rows
    task = state["tasks"].get(task_id, {})
    previous = {(r["id"], r.get("definition_version")) for r in
                (task.get("contract") or {}).get("requirements", [])} if rules.task_project(task) == project else set()
    result = []
    for row in rows:
        if not isinstance(row, dict) or "definition_version" not in row:
            result.append(row)
            continue
        cid, number = row.get("id"), row["definition_version"]
        rules.require(isinstance(cid, str) and type(number) is int and number > 0 and
                      type(row.get("required")) is bool, "目录能力须选择有效版本与必需性")
        definition = revision(state, project, cid, number)
        current = state["round"].get(catalog_key(project, cid), {})
        rules.require(definition and ((current.get("active") and current["version"] == number) or
                      (cid, number) in previous), "目录能力已更新或停用，请重新选择")
        frozen = {k: deepcopy(definition[k]) for k in ("id", "kind", "value", "evidence", "dimensions", "verified_dimensions")}
        result.append({**frozen, "required": row["required"], "definition_version": number})
    return result


def applicable_record(state, project, actor, requirement):
    number = requirement.get("definition_version")
    if number is None:
        return state["pilot"].get(f"cap:{project}:{actor}:{requirement['id']}")
    return state["pilot"].get(record_key(project, actor, requirement["id"], number))


def probe_current(state, actor, record, context, requirement):
    if "verifier_id" not in record:
        return True
    row = verifier(state, record["verifier_id"])
    env = state["security"]["execution"].get("environments", {}).get(record["environment_id"], {})
    return (row.get("active") and row["version"] == record["verifier_version"] and
            requirement.get("project_id") in row["projects"] and
            env.get("active") and env.get("version") == record["environment_version"] and
            actor in env["executors"] and context.get("environment_id") == record["environment_id"] and
            context.get("environment_version") == env["version"] and
            (rules.identity(state, actor) or {}).get("credential") == record["credential_version"])


def _catalog_body(body):
    fields(body, "request_id project_id capability version label kind value evidence dimensions verified_dimensions probe active")
    from 协作执行 import DIMENSIONS
    cid = string(body["capability"], "能力编号", 48)
    kind, level, probe = (body[k] for k in ("kind", "evidence", "probe"))
    if not rules.CAP_ID.fullmatch(cid) or kind not in ("environment", "skill") or level not in ("declared", "probed", "verified") or (
            kind == "environment" and level == "declared"):
        raise ClientError("能力编号、类别或证据等级无效")
    for key in ("dimensions", "verified_dimensions"):
        if not isinstance(body[key], list) or any(x not in DIMENSIONS for x in body[key]) or len(set(body[key])) != len(body[key]):
            raise ClientError("能力适用维度无效")
    if not set(body["verified_dimensions"]) <= set(body["dimensions"]):
        raise ClientError("独立核验维度须属于适用维度")
    if type(body["active"]) is not bool or not isinstance(probe, str) or (probe and probe not in TEMPLATES):
        raise ClientError("能力状态或探测模板无效")
    value = string(body["value"], "能力值", 100).strip()
    label = string(body["label"], "名称", 100).strip()
    if not value or not label:
        raise ClientError("能力名称和要求值不能为空")
    if probe:
        dimension, expected = TEMPLATES[probe]
        if kind != "environment" or dimension not in body["dimensions"] or (
                set(body["verified_dimensions"]) - {dimension}) or (expected and value not in {expected, "*"}):
            raise ClientError("探测模板只能核验其支持的环境能力、能力值和维度")
    return {"project_id": identifier(body["project_id"], "项目"), "id": cid,
            "version": version(body["version"]), "label": label,
            "kind": kind, "value": value, "evidence": level, "probe": probe, "active": body["active"],
            "dimensions": sorted(body["dimensions"]), "verified_dimensions": sorted(body["verified_dimensions"])}


def _verifier_body(body):
    fields(body, "request_id verifier_id version environment_id projects templates level token_sha256 active")
    name = identifier(body["verifier_id"], "探测端")
    if len(name) > 48 or type(body["active"]) is not bool or body["level"] not in ("probed", "verified"):
        raise ClientError("探测端编号、状态或证据等级无效")
    projects, templates = body["projects"], body["templates"]
    if not isinstance(projects, list) or not projects or not isinstance(templates, list) or not templates or any(
            not isinstance(x, str) or x not in TEMPLATES for x in templates):
        raise ClientError("须配置项目与固定探测模板")
    if not isinstance(body["token_sha256"], str) or not rules.SHA.fullmatch(body["token_sha256"]):
        raise ClientError("须提供探测端凭据 SHA256")
    return {"id": name, "version": version(body["version"]),
            "environment_id": identifier(body["environment_id"], "环境"), "token_sha256": body["token_sha256"],
            "active": body["active"], "level": body["level"],
            "projects": sorted({identifier(x, "项目") for x in projects}), "templates": sorted(set(templates))}


def _choose_job(state, row, now):
    for job in sorted((j for k, j in state["round"].items() if k.startswith("verification:") and
                       j.get("method") == "probe"), key=lambda j: (j["at"], j["id"])):
        if job["state"] in {"pending", "probing"} and now < job["deadline"] and (
                job["state"] == "pending" or now >= job["lease_expires"]) and report_scope(state, job, row, now):
            from 协作存储 import Rejected
            try:
                selected_context(state, job)
            except Rejected:
                continue
            return job
    return None


def probe_view(state, job):
    definition = revision(state, job["project_id"], job["capability"], job["definition_version"])
    context = selected_context(state, job)
    dimension, _ = TEMPLATES[definition["probe"]]
    return {k: job[k] for k in ("id", "attempt", "project_id", "name", "capability", "definition_version", "lease_expires")} | {
        "expected_dimensions": {dimension: context["config"][dimension]},
        "template": definition["probe"], "expected_value": definition["value"],
        "environment_id": job["record"]["environment_id"], "environment_version": job["record"]["environment_version"],
        "context_id": job["record"]["context_id"], "context_version": job["record"]["context_version"]}


def plan(service, actor, action, key, body, state):
    old_job = state["round"].get("verification:" + str(body.get("verification_id")), {})
    catalog = "definition_version" in body
    if action not in PROBE_WRITES | {CATALOG_WRITE, ADMIN_WRITE} and not (
            action in {"capability-request", "capability-save"} and catalog or
            action == "capability-resolve" and old_job.get("definition_version")):
        return None
    if not state_ready(state):
        raise ClientError("项目能力目录需要执行协议 5", 409)
    result = {}
    if action == CATALOG_WRITE:
        p = _catalog_body(body)
    elif action == ADMIN_WRITE:
        p = _verifier_body(body)
    elif action in {"capability-request", "capability-save"}:
        common = "request_id project_id capability definition_version context_id context_version"
        if action == "capability-save":
            fields(body, common + " value evidence expires version")
            method = "declare"
        else:
            method = body.get("method")
            if method not in ("manual", "probe"):
                raise ClientError("请选择人工核验或可信探测")
            fields(body, common + " method" + (" value evidence expires" if method == "manual" else ""))
        p = {"project_id": identifier(body["project_id"], "项目"),
             "capability": string(body["capability"], "能力编号", 48), "definition_version": version(body["definition_version"]),
             "context_id": identifier(body["context_id"], "执行配置"), "context_version": version(body["context_version"]),
             "method": method, "name": actor, "id": "vr-" + key[:30]}
        if method != "probe":
            p.update(value=string(body["value"], "能力值", 100).strip(), evidence=body["evidence"], expires=body["expires"])
        if method == "declare":
            p["version"] = version(body["version"])
        else:
            result["verification_id"] = p["id"]
        action = "catalog-capability-declare" if method == "declare" else "catalog-capability-request"
    elif action == "capability-resolve":
        from .window_admin import payload
        p = payload(state, actor, action, body, key)
        action = "catalog-capability-resolve"
        result["verification_id"] = p["id"]
    else:
        name = actor.removeprefix("probe-").rsplit("-", 1)[0]
        row = verifier(state, name)
        if not row.get("active") or actor != verifier_actor(name, row["version"]):
            raise ClientError("探测端无效", 403)
        if action == "capability-probe-claim":
            fields(body, "request_id")
            job = _choose_job(state, row, time.time())
            if not job:
                return {"steps": [], "round_result": {"job": None}}
            p = {"id": job["id"], "version": job["version"], "attempt": "probe-" + key[:40]}
        else:
            fields(body, "request_id verification_id attempt outcome value measured evidence")
            p = {"id": identifier(body["verification_id"], "核验申请"), "attempt": identifier(body["attempt"], "探测编号"),
                 **{k: body[k] for k in ("outcome", "value", "measured", "evidence")}}
        p.update(verifier_id=name, verifier_version=row["version"])
    p["op"] = action
    candidate = deepcopy(state)
    now = time.time()
    apply(candidate, p, actor, now, "transport-validation")
    if action == "capability-probe-claim":
        result["job"] = probe_view(candidate, candidate["round"]["verification:" + p["id"]])
    if action == "capability-probe-result":
        result["verification_id"] = p["id"]
    if result.get("verification_id"):
        job = candidate["round"]["verification:" + result["verification_id"]]
        result["verification_state"] = job["state"]
        if job.get("resolution"):
            result["verification_reason"] = job["resolution"]
    return {"steps": [step(COORDINATOR, "pilot", p, {"generation": state["generation"]})], "round_result": result}


def _record_input(state, p, actor, now):
    from 协作执行 import context_record, evidence
    from .environments import selected
    project, cid, number = p["project_id"], p["capability"], p["definition_version"]
    subject = rules.identity(state, actor) or {}
    rules.require(actor == p["name"] and subject.get("kind") == "executor" and
                  "executor" in rules.roles(state, project, actor) and subject.get("token_expires", now + 1) > now,
                  "须由有效项目执行窗口为自己申报或申请核验", "intent-final")
    definition = revision(state, project, cid, number)
    rules.require(definition, "能力目录版本不存在")
    current = state["round"].get(catalog_key(project, cid), {})
    frozen = any(r["id"] == cid and r.get("definition_version") == number
                 for task in state["tasks"].values() if rules.task_project(task) == project
                 for r in (task.get("contract") or {}).get("requirements", []))
    rules.require(current.get("active") and current["version"] == number or frozen,
                  "能力目录已停用或变更，且没有引用该版本的任务")
    ctx = context_record(state, actor, {"context_id": p["context_id"], "version": p["context_version"]})
    record = {"kind": definition["kind"], "context_id": ctx["context_id"], "context_version": ctx["version"],
              "definition_version": number, "id": cid, "project_id": project,
              "environment": ctx["config"]["environment"]}
    if ctx.get("environment_id"):
        env = selected(state, actor, ctx["environment_id"])
        rules.require(ctx.get("environment_version") == env["version"], "执行环境已变化，请更新配置")
        record.update(environment_id=env["id"], environment_version=env["version"])
    if p["method"] == "probe":
        rules.require(definition["probe"] and record.get("environment_id"), "须选择已登记环境及支持可信探测的能力")
    else:
        rules.require(isinstance(p["value"], str) and p["value"] and definition["value"] in {"*", p["value"]} and
                      type(p["expires"]) is int and now < p["expires"] <= now + 366 * 86400, "能力值或证据有效期无效")
        proof = p["evidence"]
        if p["method"] == "declare" and isinstance(proof, dict) and proof.get("sha256") == "":
            proof = {**proof, "sha256": digest(encoded(proof.get("note")))}
        record.update(value=p["value"], expires=p["expires"], evidence=evidence(proof))
    return definition, record, ctx


def _record_evidence(state, job, level, context, verified_dimensions, actor, now, event_id):
    definition = revision(state, job["project_id"], job["capability"], job["definition_version"])
    key = record_key(job["project_id"], job["name"], job["capability"], job["definition_version"])
    rules.require(state["pilot"].get(key, {}).get("version", 0) == job["capability_version"],
                  "原能力记录已变化，请重新核对后申请")
    dependencies = {dim: context["config"][dim] for dim in definition["dimensions"]}
    rules.require(level == "declared" or all(v not in {"unknown", ""} for v in dependencies.values()),
                  "执行配置的相关维度未知")
    state["pilot"][key] = {**deepcopy(job["record"]), "level": level, "by": actor, "recorded": now,
                           "version": job["capability_version"] + 1, "verification_id": job["id"], "event": event_id,
                           "applicability": {"rule_version": job["definition_version"], "dependencies": dependencies,
                                             "verified_dimensions": sorted(verified_dimensions),
                                             "origin": "trusted-probe" if job["method"] == "probe" else
                                             "declared" if level == "declared" else "independent-evidence"}}


def _apply_request(state, p, actor, now, event_id):
    definition, record, context = _record_input(state, p, actor, now)
    key = record_key(p["project_id"], actor, p["capability"], p["definition_version"])
    job = {k: p[k] for k in ("id", "project_id", "name", "capability", "definition_version", "method")}
    job.update(record=record, at=now, event=event_id, state="pending", version=1,
               credential_version=rules.identity(state, actor)["credential"],
               capability_version=state["pilot"].get(key, {}).get("version", 0))
    if p["method"] == "declare":
        rules.require(definition["kind"] == "skill" and p["version"] == job["capability_version"] and
                      state["pilot"].get(key, {}).get("level", "declared") == "declared",
                      "只能申报自身技能，不能覆盖已核实能力")
        _record_evidence(state, job, "declared", context, [], actor, now, event_id)
        return
    if p["method"] == "probe":
        job["deadline"] = int(now) + PROBE_SECONDS
    key = "verification:" + job["id"]
    rules.require(key not in state["round"], "核验申请已存在")
    state["round"][key] = job


def _apply_probe(state, p, actor, now, event_id):
    job = state["round"].get("verification:" + p["id"])
    row = verifier(state, p["verifier_id"])
    rules.require(job and job.get("method") == "probe" and actor == verifier_actor(p["verifier_id"], p["verifier_version"]) and
                  p["verifier_version"] == row.get("version") and report_scope(state, job, row, now) and
                  now < job["deadline"], "探测端、能力或原核验申请已失效", "intent-final")
    context = selected_context(state, job)
    if p["op"] == "capability-probe-claim":
        rules.require(job["version"] == p["version"] and (job["state"] == "pending" or
                      job["state"] == "probing" and now >= job["lease_expires"]), "核验请求已被领取")
        job.update(state="probing", version=job["version"] + 1, attempt=p["attempt"],
                   verifier_id=row["id"], verifier_version=row["version"],
                   lease_expires=min(job["deadline"], int(now) + LEASE_SECONDS))
        return
    rules.require(job["state"] == "probing" and now < job["lease_expires"] and
                  job["attempt"] == p["attempt"] and job["verifier_id"] == row["id"] and
                  job["verifier_version"] == row["version"], "探测编号不符或已过期")
    from 协作执行 import evidence
    proof = evidence(p["evidence"])
    rules.require(p["outcome"] in ("pass", "fail"), "探测结论无效")
    if p["outcome"] == "pass":
        definition = revision(state, job["project_id"], job["capability"], job["definition_version"])
        dimension, expected = TEMPLATES[definition["probe"]]
        measured, value = p["measured"], p["value"]
        rules.require(isinstance(measured, dict) and set(measured) == {dimension} and
                      isinstance(measured[dimension], str) and measured[dimension] not in {"", "unknown"} and
                      measured[dimension] == context["config"][dimension], "实测配置与申请不符，请更新配置后重新核验")
        rules.require(isinstance(value, str) and 0 < len(value) <= 100 and
                      definition["value"] in {"*", value} and
                      (value == expected if expected else value == measured[dimension]), "实测能力值不满足目录要求")
        job["record"].update(value=value, evidence=proof, expires=int(now) + 86400, verifier_id=row["id"],
                             verifier_version=row["version"], credential_version=job["credential_version"])
        _record_evidence(state, job, row["level"], context, [dimension], actor, now, event_id)
        job["level"] = row["level"]
    else:
        rules.require(p["measured"] == {} and p["value"] == "", "失败回执不能提交能力值")
    job.update(state="approved" if p["outcome"] == "pass" else "failed", version=job["version"] + 1,
               resolved_by=actor, resolved_at=now, resolution=proof["note"], result_evidence=proof, resolution_event=event_id)


def apply(state, p, actor, now, event_id):
    rules.require(state_ready(state), "项目能力目录需要执行协议 5")
    op = p["op"]
    if op == CATALOG_WRITE:
        project, cid = p["project_id"], p["id"]
        rules.require(manage(state, actor, project), "须由本项目管理人员维护能力目录", "intent-final")
        key = catalog_key(project, cid)
        rules.require(p["version"] == state["round"].get(key, {}).get("version", 0), "目录能力版本已变化")
        row = {k: deepcopy(v) for k, v in p.items() if k not in {"op", "_audit"}}
        row.update(version=p["version"] + 1, by=actor, event=event_id)
        state["round"][key] = row
        state["round"][f"catalog-revision:{project}:{cid}:{row['version']}"] = deepcopy(row)
    elif op == ADMIN_WRITE:
        rules.require(rules.system_admin(state, actor), "须由系统管理员登记探测端", "intent-final")
        rules.require(p["version"] == verifier(state, p["id"]).get("version", 0), "探测端版本已变化")
        rules.require(p["environment_id"] in state["security"]["execution"].get("environments", {}) and
                      all(rules.project_record(state, project) for project in p["projects"]), "项目或执行环境不存在")
        state["round"]["capability-verifier:" + p["id"]] = {
            **{k: deepcopy(v) for k, v in p.items() if k not in {"op", "_audit"}},
            "version": p["version"] + 1, "by": actor, "event": event_id}
    elif op in PROBE_WRITES:
        _apply_probe(state, p, actor, now, event_id)
    elif op == "catalog-capability-resolve":
        from .window_admin import reviewers
        from 协作执行 import context_record
        job = state["round"].get("verification:" + p["id"])
        rules.require(job and job.get("method") == "manual" and job["state"] == "pending" and
                      job["version"] == p["version"] and actor in reviewers(state, job["project_id"], job["name"]),
                      "申请不存在、已处理或无人工核验授权", "intent-final")
        if p["decision"] == "approve":
            rules.require(job["record"]["expires"] > now and rules.roles(state, job["project_id"], job["name"]),
                          "申请者权限或证据有效期已变化")
            record = job["record"]
            ctx = selected_context(state, job) if record.get("environment_id") else context_record(
                state, job["name"], {"context_id": record["context_id"], "version": record["context_version"]})
            definition = revision(state, job["project_id"], job["capability"], job["definition_version"])
            _record_evidence(state, job, p["level"], ctx, definition["dimensions"], actor, now, event_id)
        job.update(state="approved" if p["decision"] == "approve" else "rejected", version=job["version"] + 1,
                   resolved_by=actor, resolved_at=now, resolution=p["reason"], level=p["level"], resolution_event=event_id)
    else:
        _apply_request(state, p, actor, now, event_id)
    fmt = state["pilot"]["format"]
    fmt["min_reader"] = max(READER, fmt.get("min_reader", 1))
