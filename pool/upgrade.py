"""Typed application entry points for the versioned task-pool contract."""

import base64
import json
import time
from urllib.parse import urlsplit

from .packages import ClientError, fields, integer, string
from .constants import ADMIN, COORDINATOR, step
from .task_state import security_schema
from 协作执行 import bind_evidence, context_record
from 协作本轮 import DEFAULT_POLICY
import 协作升级 as rules
from 协作存储 import digest, encoded


ACTIONS = {
    "project-save", "identity-bind", "project-grant", "executor-enroll", "executor-sync",
    "credential-change", "capability-save", "task-publish", "task-hold", "task-scope",
    "task-interrupt", "task-recover", "release-accept", "release-close", "release-correct",
}
INTERNAL = {"upgrade-migrate", "maintenance-mode"}


def identifier(value, label):
    value = string(value, label, 80)
    if not rules.ID.fullmatch(value):
        raise ClientError(f"{label} 须为字母、数字、下划线或连字符")
    return value


def version(value):
    if type(value) is not int or not 0 <= value <= 10**9:
        raise ClientError("须提交当前记录版本")
    return value


def sha256(value):
    if not isinstance(value, str) or not rules.SHA.fullmatch(value):
        raise ClientError("须提供 SHA256 指纹")
    return value


def role_list(value, allowed):
    if not isinstance(value, list) or any(not isinstance(role, str) or role not in allowed for role in value):
        raise ClientError("角色列表无效")
    if len(set(value)) != len(value):
        raise ClientError("角色不能重复")
    return sorted(value)


def grantable(state):
    # Reporter and observer are view-level tiers; the ledger keeps ignoring them for execution and review.
    return (rules.ROLES | {"reporter", "observer"} if state["pilot"]["format"]["schema"] >= rules.ROUND_VERSION
            else rules.ROLES)


def decide(state, env, context):
    """Recheck transport-level capability permission when a queued step commits."""
    from 协作命令 import decide as ledger_decide
    from . import delegation
    payload = env["payload"]
    audit = payload.get("_audit") or {}
    from 协作执行 import OPS as EXECUTION_OPS, action as execution_action
    if env['command'] == 'pilot' and payload.get('op') in EXECUTION_OPS:
        execution_action(state, env, context)
        return state, {}
    if env['command'] == 'pilot' and payload.get('op') == 'security-migrate':
        from 协作安全 import migrate
        rules.require(audit.get('operation') == 'security-migrate', '安全迁移缺受控操作依据')
        migrate(state, audit.get('actor'), payload.get('target'), env['event_id'], context.get('now', time.time()),
                {'head': payload.get('source_head'), 'sha256': payload.get('source_sha256')})
        return state, {}
    delegation.enforce_audit(state, env, context.get("now", time.time()))
    task_id, project = delegation.target(state, audit.get("operation"), payload)
    if env["command"] == "propose":
        project = project or audit.get("project_id")
    with delegation.operation_context(state, audit.get("actor"), audit.get("operation"), project, task_id,
                                      context.get("now", time.time()), audit):
        if env["command"] == "pilot" and payload.get("op") == "capability":
            actor = audit.get("actor")
            rules.require(bool(rules.roles(state, payload["project_id"], actor) & rules.ROLES),
                          "当前项目角色只能查看能力记录", "intent-final")
        return ledger_decide(state, env, context)


def source_profile(raw, state, owner):
    fields(raw, "platform session model environment device directory url parent" +
           (" window_name" if isinstance(raw, dict) and "window_name" in raw else ""))
    source = {key: string(raw[key], key, limit) for key, limit in
              {"platform": 20, "session": 200, "model": 120, "environment": 160,
               "device": 120, "directory": 400}.items()}
    if source["platform"] not in rules.PLATFORMS:
        raise ClientError("平台须从登记表选择")
    if raw["url"]:
        url = urlsplit(string(raw["url"], "原始会话链接", 600))
        if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password:
            raise ClientError("会话链接须为无凭据的 HTTP 或 HTTPS 地址")
    elif raw["url"] != "":
        raise ClientError("会话链接字段无效")
    if raw["parent"] is not None:
        parent = rules.identity(state, identifier(raw["parent"], "父执行端"))
        if not parent or parent["kind"] != "executor" or parent["owner"] != owner:
            raise ClientError("父执行端须属于同一责任账号")
    if "window_name" in raw:
        source["window_name"] = window_name(raw["window_name"])
    return {**source, "url": raw["url"], "parent": raw["parent"], "source_evidence": "registered"}


def window_name(value):
    if not isinstance(value, str) or len(value) > 200 or any(ord(c) < 32 for c in value):
        raise ClientError("窗口名称须为不超过 200 字符的单行文本")
    return value.strip()


def scope_contract(state, body, task_id=None):
    data = {key: body[key]
            for key in ("project_id", "iteration", "delivery", "requirements", "review_mode", "user_basis")}
    if "dispatch" in body:
        data["dispatch"] = body["dispatch"]
    spec = rules.task_spec(state, data, task_id)
    return (spec, rules.dependency_rows(state, body["dependencies"], spec["project_id"], task_id),
            rules.resources(body["resources"]))


SCOPE_FIELDS = "project_id iteration delivery requirements review_mode user_basis resources dependencies"
MAINTENANCE_ACTIONS = {"maintenance-mode", "identity-bind", "project-save",
                       "project-grant"}  # allowed during maintenance


class Operation:
    """One pilot step being prepared.

    A planner returns the step's payload.  It may also add expectations, name a file to
    store with the step, and add fields to the plan itself through ``result``.
    """

    def __init__(self, service, actor, action, key, body, state, expects):
        self.service, self.actor, self.action, self.key, self.body = service, actor, action, key, body
        self.state, self.expects = state, expects
        self.result = {}
        self.file = None


def plan(service, actor, action, key, body, snap):
    state = snap["state"]
    expects = {"generation": state["generation"]}
    if action == 'security-migrate':
        fields(body, 'request_id target')
        if actor != ADMIN or body['target'] not in (4, 5):
            raise ClientError('须由本机管理员按 4／5 顺序迁移安全语义', 403)
        return {'steps': [step(COORDINATOR, 'pilot', {'op': action, 'target': body['target'],
                         'source_head': snap['head'], 'source_sha256': snap.get('sha256')}, expects)]}
    if action == "upgrade-migrate":
        return migrate(actor, body, expects)
    if not rules.enabled(state):
        if action in ACTIONS | INTERNAL:
            raise ClientError("请先迁移数据合同", 409)
        return None
    if state["pilot"]["format"]["maintenance"] and action not in MAINTENANCE_ACTIONS:
        raise ClientError("服务处于维护窗口", 503)
    if action == "add-task":
        raise ClientError("请通过登记页或 API 填写升级后的项目与领取能力合同")
    if action == "register":
        return register(service, actor, key, body, state, expects)
    if action not in ACTIONS | INTERNAL:
        return None
    planner = PILOT.get(action)
    if planner is None:
        raise ClientError("未知升级操作", 404)
    op = Operation(service, actor, action, key, body, state, expects)
    payload = planner(op)
    operation = step(COORDINATOR, "pilot", payload, expects)
    if op.file:
        operation["file"] = op.file
    return {**op.result, "steps": [operation]}


def migrate(actor, body, expects):
    fields(body, "request_id task_id version scope_version upgrade image")
    if actor != ADMIN:
        raise ClientError("迁移须由本机管理员入口办理", 403)
    task_id = identifier(body["task_id"], "任务号")
    image = sha256(body["image"])
    requirements = [
        {"id": name, "kind": kind, "value": "*", "required": True, "evidence": level}
        for name, kind, level in (
            ("workflow-design", "skill", "declared"), ("identity-design", "skill", "declared"),
            ("official-research", "environment", "verified"), ("read-input", "environment", "verified"),
            ("markdown", "skill", "declared"), ("upload-delivery", "environment", "verified"),
        )
    ]
    payload = {"op": "migrate", "task_id": task_id, "upgrade": identifier(body["upgrade"], "升级编号"),
               "image": image, "contract": {"project_id": rules.PROJECT, "review_mode": "source", "user_basis": "",
               "iteration": {"goal": "完成任务协作平台建设方案与本机试点验收清单", "previous": [], "next": []},
               "delivery": "任务协作平台建设方案.md 与本机试点验收清单", "requirements": requirements}}
    expects.update({f"task:{task_id}": integer(body["version"], "version"),
                    f"scope:{task_id}": integer(body["scope_version"], "scope_version")})
    return {"task_id": task_id, "steps": [step(COORDINATOR, "pilot", payload, expects)]}


def register(service, actor, key, body, state, expects):
    required = "request_id title brief criteria kind " + SCOPE_FIELDS
    fields(body, required + (" receiver" if "receiver" in body else "") + (" dispatch" if "dispatch" in body else ""))
    receiver = identifier(body.get("receiver", actor), "接收者")
    title = string(body["title"], "任务标题", 200)
    if body["kind"] != "documentation":
        raise ClientError("本机升级试点登记资料类任务")
    raw = string(body["brief"], "任务说明", 40000).encode("utf-8")
    criteria = body["criteria"]
    if not isinstance(criteria, list) or not 1 <= len(criteria) <= 30:
        raise ClientError("须填写 1 至 30 条完成判据")
    criteria = [string(item, "完成判据", 100) for item in criteria]
    if len(set(criteria)) != len(criteria):
        raise ClientError("完成判据不能重复")
    spec, dependencies, resources = scope_contract(state, body)
    if state["pilot"]["format"]["schema"] >= rules.ROUND_VERSION and "dispatch" not in spec:
        spec["dispatch"] = {**DEFAULT_POLICY, "owner": rules.responsible(state, actor) or ""}
    project = spec["project_id"]
    if not (rules.manager(state, project, actor) or actor == receiver
            and "receiver" in rules.roles(state, project, actor)):
        raise ClientError("须有项目任务登记权限", 403)
    if "receiver" not in rules.roles(state, project, receiver):
        raise ClientError("须选择获授权的项目接收者")
    path = f"inputs/{digest(raw)}/brief.md"
    prepared = service.registration(actor, key, title, criteria, receiver, path, raw, expects,
                                    rules.project_record(state, project)["name"])
    prepared["steps"][-1]["payload"].update(contract=spec, resources=resources, dependencies=dependencies)
    return prepared


def maintenance_mode(op):
    body = op.body
    fields(body, "request_id enabled")
    if type(body["enabled"]) is not bool:
        raise ClientError("须声明维护状态")
    return {"op": "maintenance", "enabled": body["enabled"]}


def project_save(op):
    body = op.body
    fields(body, "request_id project_id name version")
    return {"op": "project", "project_id": identifier(body["project_id"], "项目编号"),
            "name": string(body["name"], "项目名称", 100).strip(), "version": version(body["version"])}


def identity_bind(op):
    body = op.body
    fields(body, "request_id name kind owner reason source")
    name = identifier(body["name"], "原身份")
    kind = body["kind"]
    if (not isinstance(kind, str) or kind not in {"human", "executor"} or kind == "human"
        and (body["owner"] != name or body["source"] is not None)):
        raise ClientError("人员绑定须归本人，执行端须提供责任账号及会话资料")
    owner = identifier(body["owner"], "责任账号")
    return {"op": "bind", "name": name, "kind": kind, "owner": owner,
            "reason": string(body["reason"], "绑定依据"),
            "source": source_profile(body["source"], op.state, owner) if kind == "executor" else None}


def project_grant(op):
    body = op.body
    fields(body, "request_id project_id name roles resources version")
    return {"op": "grant", "project_id": identifier(body["project_id"], "项目编号"),
            "name": identifier(body["name"], "身份"), "roles": role_list(body["roles"], grantable(op.state)),
            "resources": rules.resources(body["resources"]), "version": version(body["version"])}


def executor_enroll(op):
    body = op.body
    fields(body, "request_id project_id roles source")
    name = "x-" + digest(encoded([op.key, "executor"]))[:24]
    requested = role_list(body["roles"], {"executor", "receiver"})
    if not requested:
        raise ClientError("须至少选择一个执行端角色")
    payload = {"op": "enroll", "name": name, "project_id": identifier(body["project_id"], "项目编号"),
               "roles": requested, "source": source_profile(body["source"], op.state, op.actor)}
    op.result["enrollment"] = {"name": name, "role": "executor"}
    return payload


def executor_sync(op):
    body = op.body
    fields(body, "request_id session model environment" + (" window_name" if "window_name" in body else "") +
           (" platform" if "platform" in body else ""))
    payload = {"op": "sync", "session": string(body["session"], "原始会话", 200),
               "model": string(body["model"], "模型", 120), "environment": string(body["environment"], "环境标识", 160)}
    if "window_name" in body:
        payload["window_name"] = window_name(body["window_name"])
    if "platform" in body:
        if not isinstance(body["platform"], str) or body["platform"] not in rules.PLATFORMS:
            raise ClientError("平台须从登记表选择")
        payload["platform"] = body["platform"]
    return payload


def credential_change(op):
    body, state = op.body, op.state
    fields(body, "request_id name version status reason")
    name = identifier(body["name"], "身份")
    if not isinstance(body["status"], str) or body["status"] not in {"active", "disabled"}:
        raise ClientError("凭据状态无效")
    if state["pilot"]["format"]["schema"] >= rules.ROUND_VERSION and body["status"] == "active":
        # Windows come back through a new token. A person signs in with a password, so the
        # administrator restores a disabled person here; earlier sessions and tokens stay invalid.
        subject = rules.identity(state, name) or {}
        if subject.get("kind") != "human":
            raise ClientError("请通过待确认凭据轮换入口签发新令牌")
        if subject.get("status") != "disabled":
            raise ClientError("该人员账号未停用；需要更换密码时请签发密码重置凭据")
    payload = {"op": "credential", "name": name, "version": integer(body["version"], "version"),
               "status": body["status"], "reason": string(body["reason"], "凭据处置依据")}
    role = op.service.accounts.role(name)
    if not role:
        roles = state["origins"].get(name, {}).get("roles", [])
        role = roles[0] if roles else "executor"
    op.result["credential"] = {"name": name, "role": role, "enabled": body["status"] == "active"}
    return payload


def capability_save(op):
    body, state, actor = op.body, op.state, op.actor
    fields(body, "request_id project_id name capability kind value level evidence environment expires version" +
           ''.join(' ' + k for k in ('context_dimensions', 'context_id', 'context_version') if k in body))
    project = identifier(body["project_id"], "项目编号")
    if not rules.roles(state, project, actor) & rules.ROLES:
        raise ClientError("当前项目角色只能查看能力记录", 403)
    name = identifier(body["name"], "执行身份")
    capability = string(body["capability"], "能力标识", 48)
    if (not rules.CAP_ID.fullmatch(capability) or not isinstance(body["kind"], str) or
            body["kind"] not in {"skill", "environment"} or not isinstance(body["level"], str) or
            body["level"] not in rules.LEVEL or type(body["expires"]) is not int or
            not time.time() < body["expires"] < time.time() + 366 * 86400):
        raise ClientError("能力、证据等级或有效期无效")
    evidence = body["evidence"]
    fields(evidence, "note sha256")
    evidence = {"note": string(evidence["note"], "证据说明"), "sha256": evidence["sha256"]}
    if body["level"] in {"verified", "probed"}:
        if security_schema(state) >= 5 and (rules.identity(state, actor) or {}).get('kind') != 'human':
            raise ClientError('探测或核实等级须由有项目授权的人类办理；AI不能借旧接口相互核实', 403)
        sha256(evidence["sha256"])
    elif evidence["sha256"]:
        sha256(evidence["sha256"])
    elif evidence["sha256"] != "":
        raise ClientError("证据指纹格式无效")
    environment = string(body["environment"], "环境标识", 160)
    if (security_schema(state) < 5 and body["kind"] == "environment"
        and environment != (rules.identity(state, name) or {}).get("environment", "human")):
        raise ClientError("证据与执行端登记的环境不一致")
    payload = {"op": "capability", "project_id": project,
               "name": name, "id": capability, "version": version(body["version"]), "record": {
                   "kind": body["kind"], "value": string(body["value"], "能力值", 100).strip(), "level": body["level"],
                   "evidence": evidence, "environment": environment, "expires": body["expires"],
               }}
    if security_schema(state) >= 5:
        selected = (context_record(state, name, {'context_id': body['context_id'], 'version': body['context_version']})
                    if body.get('context_id') else None)
        payload['record'].update(bind_evidence(state, name, payload['record'], selected, project, capability,
            body.get('context_dimensions'), body['level'] in {'verified', 'probed'}))
    return payload


def task_operation(op):
    """Publish, hold or rescope a project task, or interrupt or resolve one of its claims."""
    body, state, actor = op.body, op.state, op.actor
    kind = op.action.removeprefix("task-")
    suffix = {"publish": "scope_version", "hold": "scope_version", "scope": "scope_version " + SCOPE_FIELDS,
              "interrupt": "claim_id epoch", "recover": "claim_id epoch evidence notes unresolved"}[kind]
    fields(body, "request_id task_id version reason " + suffix
           + (" dispatch" if kind == "scope" and "dispatch" in body else ""))
    task_id = identifier(body["task_id"], "任务编号")
    task = state["tasks"].get(task_id)
    if not task or not rules.contract(task) or not rules.visible(state, task, actor):
        raise ClientError("项目任务不存在或无权查看", 404)
    op.result["task_id"] = task_id
    op.expects[f"task:{task_id}"] = integer(body["version"], "version")
    payload = {"op": "resolve" if kind == "recover" else kind, "task_id": task_id,
               "reason": string(body["reason"], "操作依据")}
    if kind in {"publish", "hold", "scope"}:
        if not rules.manager(state, rules.task_project(task), actor):
            raise ClientError("仅项目管理员可调整发布及范围", 403)
        payload["scope_version"] = integer(body["scope_version"], "scope_version")
    if kind == "scope":
        spec, dependencies, resources = scope_contract(state, body, task_id)
        payload.update(contract=spec, dependencies=dependencies, resources=resources)
    if kind in {"interrupt", "recover"}:
        cid = (identifier(body["claim_id"], "领取编号") if len(str(body["claim_id"])) <= 80
               else string(body["claim_id"], "领取编号", 100))
        claim = state["claims"].get(cid)
        if not claim or claim["task_id"] != task_id:
            raise ClientError("领取与任务不匹配", 409)
        payload.update(claim_id=cid, epoch=integer(body["epoch"], "epoch"))
        op.result["claim_id"] = cid
    if kind == "recover":
        if not rules.manager(state, rules.task_project(task), actor):
            raise ClientError("仅项目管理员可处置恢复待核", 403)
        notes = string(body["notes"], "接续说明", 16000)
        evidence = string(body["evidence"], "停止与资源处置证据")
        unresolved = body["unresolved"]
        if not isinstance(unresolved, str) or len(unresolved) > 4000:
            raise ClientError("外部效果待核记录无效")
        raw = encoded({"task_id": task_id, "claim_id": cid, "origin_id": claim["origin"],
                       "inputs": claim["inputs"], "notes": notes, "stop_evidence": evidence,
                       "unresolved": unresolved, "decided_by": actor})
        path = f"handoffs/{cid}/{digest(raw)}.json"
        op.file = [path, base64.b64encode(raw).decode("ascii")]
        payload.update(evidence=evidence, unresolved=unresolved, replacement=path)
    return payload


def release_operation(op):
    body, state, action = op.body, op.state, op.action
    suffix = {"release-accept": " report", "release-close": " acceptance", "release-correct": ""}[action]
    fields(body, "request_id reason" + suffix)
    payload = {"op": action, "reason": string(body["reason"], "验收或处置依据")}
    if action == "release-accept":
        if "receiver" not in rules.roles(state, rules.PROJECT, op.actor):
            raise ClientError("仅项目接收者可提交升级验收", 403)
        rules.verify_report(state, body["report"])
        raw = encoded(body["report"])
        if len(raw) > 256 * 1024:
            raise ClientError("验收证据清单过长", 413)
        path = f"upgrade-evidence/{digest(raw)}.json"
        payload["evidence"] = {"path": path, "sha256": digest(raw)}
        op.file = [path, base64.b64encode(raw).decode("ascii")]
    elif action == "release-close":
        payload["acceptance"] = sha256(body["acceptance"])
    return payload


PILOT = {
    "maintenance-mode": maintenance_mode, "project-save": project_save, "identity-bind": identity_bind,
    "project-grant": project_grant, "executor-enroll": executor_enroll, "executor-sync": executor_sync,
    "credential-change": credential_change, "capability-save": capability_save,
    "task-publish": task_operation, "task-hold": task_operation, "task-scope": task_operation,
    "task-interrupt": task_operation, "task-recover": task_operation,
    "release-accept": release_operation, "release-close": release_operation, "release-correct": release_operation,
}


def target(state, body, prepared=None):
    task = (prepared or {}).get("task_id") or body.get("task_id")
    cid = (prepared or {}).get("claim_id") or body.get("claim_id")
    if isinstance(cid, str) and cid in state["claims"]:
        task = state["claims"][cid]["task_id"]
    if not isinstance(task, str):
        task = None
    project = rules.task_project(state["tasks"].get(task))
    supplied = body.get("project_id")
    return task, project or (supplied if isinstance(supplied, str) else None)


def task_visible(state, task, actor):
    from .delegation import operation_context
    with operation_context(state, actor, "read", rules.task_project(task), task["task_id"]):
        return rules.visible(state, task, actor)


def projects(state, actor):
    from .delegation import operation_context
    result = []
    for key, record in state["pilot"].items():
        if not key.startswith("project:"):
            continue
        with operation_context(state, actor, "read", record["id"]):
            current = sorted(rules.roles(state, record["id"], actor))
            if rules.system_admin(state, actor) or current:
                result.append({**record, "roles": current})
    return result


def sources(state, actor):
    result = []
    accessible = projects(state, actor)
    for key, subject in state["pilot"].items():
        if not key.startswith("identity:") or subject["kind"] != "executor":
            continue
        name = key.removeprefix("identity:")
        memberships = [p["id"] for p in accessible if rules.grant(state, p["id"], name)["roles"]]
        if actor not in {name, subject["owner"]} and not memberships and not rules.system_admin(state, actor):
            continue
        result.append({"executor_id": name, **subject, "projects": memberships,
                       "tasks": [{"task_id": c["task_id"], "claim_id": c["claim_id"], "epoch": c["epoch"],
                                  "lifecycle": c["L"], "execution": c["E"], "work": c["W"], "run": c.get("run")}
                                 for c in state["claims"].values() if c["origin"] == name and
                                 task_visible(state, state["tasks"][c["task_id"]], actor)]})
    return sorted(result, key=lambda item: item["number"])


def activity_rows(service, snap, actor, limit=1000):
    """Applied task events the actor may see, newest first."""
    state, admin, rows = snap["state"], service.is_admin(actor), []
    for entry in reversed(snap["entries"]):
        if len(rows) >= limit:
            break
        if entry["type"] != "decision" or entry["result"] != "applied":
            continue
        record = dict(entry.get("request", {}))
        record.setdefault("actor", entry["origin_id"])
        ids = {effect["value"]["task_id"] for effect in entry["effects"]
               if len(effect["path"]) == 2 and effect["path"][0] in {"tasks", "claims"}}
        if record.get("task_id"):
            ids.add(record["task_id"])
        known = sorted(tid for tid in ids if tid in state["tasks"])
        if not known or not (admin or all(service.visible(state, state["tasks"][tid], actor) for tid in known)):
            continue
        task = state["tasks"][known[0]]
        subject = rules.identity(state, record["actor"]) or {}
        rows.append({**record, "task_id": known[0], "title": task["title"], "project": rules.task_project(task),
                     "window_name": record.get("window_name") or subject.get("window_name"),
                     "committed_utc": entry.get("committed_utc"), "command": entry["command"],
                     "result": entry["result"],
                     "reason": entry["reason"] or record.get("reason")})
    return rows


def audit_rows(service, snap, actor, query):
    state = snap["state"]
    task_id, source, request_id = (query.get(key) for key in ("task", "actor", "request"))
    if not (task_id or source or request_id):
        raise ClientError("须按任务、执行身份或请求编号查询")
    if task_id and (task_id not in state["tasks"] or not service.visible(state, state["tasks"][task_id], actor)):
        raise ClientError("任务不存在或无权查看", 404)
    admin = service.is_admin(actor)
    previous, rows, seen = {}, [], set()

    def allowed(ids, record):
        if admin:
            return True
        if ids:
            return all(tid in state["tasks"] and service.visible(state, state["tasks"][tid], actor) for tid in ids)
        return actor in {record.get("actor"), record.get("owner")}

    def matches(ids, record):
        return (not task_id or task_id in ids) and (not source
                                                    or source in {record.get("actor"), record.get("origin_id")}) and (
            not request_id or record.get("request_id") == request_id)

    for entry in snap["entries"]:
        if entry["type"] != "decision":
            continue
        record = dict(entry.get("request", {}))
        record.setdefault("actor", entry["origin_id"])
        record["origin_id"] = entry["origin_id"]
        ids = {record["task_id"]} if record.get("task_id") else set()
        changes = []
        for effect in entry["effects"]:
            path, value = effect["path"], effect["value"]
            if len(path) != 2 or path[0] not in {"tasks", "claims"}:
                continue
            table, name = path
            tid = value["task_id"]
            ids.add(tid)
            if table == "tasks":
                item = {k: value.get(k) for k in ("status", "version", "scope_version", "accepted", "close_id")}
                if spec := rules.contract(value):
                    item["open"] = spec["open"]
            else:
                item = {k: value.get(k) for k in ("L", "E", "W", "epoch", "replacement", "recovery")}
                item["deliveries"] = {rev: data["manifest"] for rev, data in value["deliveries"].items()}
            changes.append({"record": name, "task_id": tid, "before": previous.get((table, name)), "after": item})
            previous[(table, name)] = item
        if record.get("request_id"):
            seen.add((record["actor"], record["request_id"]))
        if matches(ids, record) and allowed(ids, record):
            rows.append({**record, "tasks": sorted(ids), "seq": entry["ledger_seq"], "sha256": entry["sha256"],
                         "event_id": entry["key"].split("/", 1)[1], "committer": entry["committer"],
                         "committed_utc": entry.get("committed_utc"), "command": entry["command"],
                         "result": entry["result"], "reason": entry["reason"] or record.get("reason"),
                         "changes": changes})
    for raw, status, response in service.db.execute(
            "SELECT c.details,r.status,r.response FROM request_context c JOIN requests r ON c.request_key=r.key "
            "ORDER BY r.rowid"):
        record = json.loads(raw)
        ids = {record["task_id"]} if record.get("task_id") else set()
        if ((status is not None and (record["actor"], record["request_id"]) in seen) or not matches(ids, record)
            or not allowed(ids, record)):
            continue
        value = json.loads(response) if response else {}
        rows.append({**record, "tasks": sorted(ids), "seq": None, "committed_utc": None,
                     "result": "pending" if status is None else value["status"], "reason": value.get("message"),
                     "changes": []})
    return rows[-250:]
