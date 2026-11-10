"""Turn one accepted task request into the ledger steps that carry it out.

``plan`` is entered by ``Service.plan``.  The specialised planners are asked first;
what remains here is enrollment and the task workflow itself.  The order of the checks
inside each function decides which rejection a faulty request receives, so it is part
of the interface.
"""

import base64
import time

from . import delegation, execution, round_service, upgrade, window_admin, post_completion, task_communication
from .constants import COMMITTER, COORDINATOR, step
from .packages import (ClientError, MAX_PACKAGE, artifact_name, fields, integer, make_delivery, reference,
                       seal_metadata, string, unpack_delivery)
from .task_state import security_schema
from 协作存储 import digest, encoded
from 协作执行 import context_record
import 协作升级 as rules


CLAIM_FIELDS = {
    "handoff": "epoch scope_version stop_evidence notes",
    "deliver": "epoch scope_version package_sha256 package",
    "deliver-files": "epoch scope_version files",
    "stop": "epoch scope_version stop_evidence",
    "resume": "epoch scope_version",
    "withdraw": "epoch scope_version revision reason",
    "review": "revision manifest_sha256 checks",
    "executor-complete": "epoch scope_version revision manifest_sha256 checks",
    "return": "revision manifest_sha256 criterion reason",
}
EXECUTION_OPTIONS = ('execution_protocol', 'context_id', 'context_version')


def plan(service, actor, action, key, body, snap):
    state = snap["state"]
    generation = {"generation": state["generation"]}
    for planner in (execution.plan, delegation.plan, window_admin.plan, post_completion.plan, task_communication.plan, round_service.plan):
        if prepared := planner(service, actor, action, key, body, state):
            return prepared
    if prepared := upgrade.plan(service, actor, action, key, body, snap):
        return prepared
    if actor == COORDINATOR and action == "bootstrap":
        steps = [step(actor, "register_origin",
                      {"origin_id": name, "roles": [role], "local": name == COMMITTER,
                       "authority_ref": "bootstrap"}, generation) for name, role in body["origins"].items()]
        return {"steps": steps}
    if actor == COORDINATOR and action == "add-task":
        return service.registration(actor, key, body["title"], body["criteria"], body["receiver"],
                                    body["path"], base64.b64decode(body["input"]), generation)
    if actor == COORDINATOR and action in {"initialize-admin", "signup", "signup-password"}:
        return enrollment(service, action, body, state, generation)
    role = service.roles(state, actor)
    if "admin" in role and rules.enabled(state):
        # Administration and project work are separate grants. A human admin
        # assigned as receiver still needs their explicit project role here.
        _, project = upgrade.target(state, body)
        if project:
            role = [*role, *rules.roles(state, project, actor)]
    admin_action = "admin" in role and action in {"register", "cancel"}
    required_role = "receiver" if action in {"register", "review", "return", "close", "cancel"} else "executor"
    if action == "close" and rules.direct_closer(state, state["tasks"].get(body.get("task_id")), actor):
        required_role = "executor"
    if not admin_action and required_role not in role:
        raise ClientError("该身份无权执行此操作", 403)
    if action == "register":
        return register(service, actor, key, body, state, generation, admin_action)
    if action == "claim":
        return claim(service, actor, action, body, state)
    if action == "close":
        return close(service, actor, body, state, generation)
    if action == "cancel":
        return cancel(service, actor, body, state, generation, admin_action)
    return claim_action(service, actor, action, key, body, state, generation)


def enrollment(service, action, body, state, generation):
    name = body["name"]
    if name.casefold() in {origin.casefold() for origin in state["origins"]}:
        raise ClientError("这个身份已登记", 409)
    registration = {"name": name, "role": "admin"}
    if action in {"signup", "signup-password"}:
        invite_sha = body["invite_sha"]
        registration.update(role=service.accounts.invited_role(invite_sha), invite_sha=invite_sha)
        if action == "signup-password":
            registration["password_signup"] = True
    ledger_role = "proposer" if registration["role"] == "admin" else registration["role"]
    origin = step(COORDINATOR, "register_origin", {
        "origin_id": name, "roles": [ledger_role], "local": False, "authority_ref": "bootstrap",
        "person_signup": action in {"signup", "signup-password"},
    }, generation)
    return {"steps": [origin], "enrollment": registration}


def register(service, actor, key, body, state, generation, admin_action):
    required = "request_id title brief criteria" + (" receiver" if admin_action else "")
    fields(body, required + (" project" if "project" in body else ""))
    project = string(body["project"], "所属项目", 100).strip() if "project" in body else None
    receiver = string(body["receiver"], "接收者", 80) if admin_action else actor
    if "receiver" not in state["origins"].get(receiver, {}).get("roles", []):
        raise ClientError("须选择已登记的接收者")
    title = string(body["title"], "任务标题", 200)
    raw = string(body["brief"], "任务说明", 40000).encode("utf-8")
    criteria = body["criteria"]
    if not isinstance(criteria, list) or not 1 <= len(criteria) <= 30:
        raise ClientError("须填写 1 至 30 条完成判据")
    criteria = [string(item, "完成判据", 100) for item in criteria]
    if len(set(criteria)) != len(criteria):
        raise ClientError("完成判据不能重复")
    return service.registration(actor, key, title, criteria, receiver, f"inputs/{digest(raw)}/brief.md",
                                raw, generation, project)


def claim(service, actor, action, body, state):
    fields(body, "request_id task_id version scope_version" +
           ''.join(' ' + k for k in ('notice', *EXECUTION_OPTIONS) if k in body))
    if security_schema(state) >= 5 and body.get('execution_protocol') != 5:
        raise ClientError('领取需要支持执行协议5的客户端；请更新客户端，旧领取仍可受限收尾', 409)
    task_id = string(body["task_id"], "task_id", 16)
    if task_id not in state["tasks"] or not rules.visible(state, state["tasks"][task_id], actor):
        raise ClientError("任务不存在", 404)
    if rules.enabled(state):
        selected = None
        if security_schema(state) >= 5 and body.get('context_id'):
            if 'context_version' not in body:
                raise ClientError('指定配置时须同时提供配置版本')
            selected = context_record(state, actor, {'context_id': body['context_id'], 'version': body['context_version']})
        missing, _ = rules.eligible(state, state["tasks"][task_id], actor, time.time(), execution_context=selected)
        if missing:
            raise ClientError("；".join(missing), 409)
    version = integer(body["version"], "version")
    scope = integer(body["scope_version"], "scope_version")
    payload = {"task_id": task_id}
    payload.update({k: body[k] for k in EXECUTION_OPTIONS if k in body})
    if "notice" in body:
        notice = upgrade.sha256(body["notice"])
        if not round_service.enabled(state) or not service.notices.acknowledged(actor, notice):
            raise ClientError("请先确认有效的执行端通知", 409)
        payload["notice"] = notice
    return {"task_id": task_id, "steps": [step(actor, action, payload,
            {"task:" + task_id: version, "scope:" + task_id: scope})]}


def close(service, actor, body, state, generation):
    fields(body, "request_id task_id")
    task_id = string(body["task_id"], "task_id", 16)
    if not rules.direct_closer(state, state["tasks"].get(task_id), actor):
        service.receiver(state, task_id, actor)
    if state["tasks"][task_id]["status"] != "pending_close":
        raise ClientError("任务须已接受，且执行已停止、资源已释放", 409)
    return {"task_id": task_id, "steps": [step(COORDINATOR, "close", {"task_id": task_id}, generation)]}


def cancel(service, actor, body, state, generation, admin_action):
    fields(body, "request_id task_id version reason")
    task_id = string(body["task_id"], "task_id", 16)
    project_manager = round_service.enabled(state) and rules.manager(state, rules.task_project(state["tasks"].get(task_id)), actor)
    if not admin_action and not project_manager:
        service.receiver(state, task_id, actor)
    elif task_id not in state["tasks"]:
        raise ClientError("任务不存在", 404)
    task = state["tasks"][task_id]
    version = integer(body["version"], "version")
    if (task["status"] not in {"available", "running"} or task.get("cancel_requested")
            or task.get("accepted") or version != task["version"]):
        raise ClientError("任务已变更、已验收或已请求取消", 409)
    reason = string(body["reason"], "取消原因")
    instruction = step(COORDINATOR, "cancel", {"task_id": task_id, "authority_ref": "bootstrap",
                       "reason": reason, "requested_by": actor}, {**generation, "task:" + task_id: version})
    note = step(actor, "note", {"text": reason, "related": {"task_id": task_id, "kind": "cancel"}})
    return {"task_id": task_id, "steps": [instruction, note]}


def claim_action(service, actor, action, key, body, state, generation):
    """Requests addressed to one claim: the reviewer's verdicts and the holder's own operations."""
    suffix = CLAIM_FIELDS[action]
    optional = ""
    if round_service.enabled(state):
        name = {"deliver-files": "stop_evidence", "review": "finish", "executor-complete": "finish", "return": "criteria"}.get(action)
        optional = f" {name}" if name and name in body else ""
    if action == 'resume':
        optional += ''.join(' ' + k for k in EXECUTION_OPTIONS if k in body)
        if security_schema(state) >= 5 and body.get('execution_protocol') != 5:
            raise ClientError('继续任务需要执行协议5；旧回合事实和已有产物保留', 409)
    fields(body, "request_id claim_id " + suffix + optional)
    cid = string(body["claim_id"], "claim_id", 100)
    held = state["claims"].get(cid)
    if not held:
        raise ClientError("领取不存在", 404)
    task_id = held["task_id"]
    if action in {"review", "return"}:
        service.receiver(state, task_id, actor)
        if state["tasks"][task_id].get("cancel_requested"):
            raise ClientError("任务已请求取消，等待持有者停止", 409)
        instruction = service.review(actor, body, held, state, action)
        steps = [instruction]
        # With the holder's stop already on record, acceptance can finish the task in one request.
        if action == "review" and body.get("finish") is True and not held["R"] and held["E"] == {"state": "stopped", "reason": "complete"}:
            steps.append(step(COORDINATOR, "close", {"task_id": task_id}, generation))
        return {"task_id": task_id, "claim_id": cid, "steps": steps}
    if held["origin"] != actor:
        raise ClientError("该领取属于其他执行者", 403)
    epoch = integer(body["epoch"], "epoch")
    scope = integer(body["scope_version"], "scope_version")
    if held["L"] != "active" or epoch != held["epoch"] or scope != held["W"]["scope"]:
        raise ClientError("领取已结束或执行代次、范围已变化", 409)
    expects = {"epoch:" + cid: epoch, "scope:" + task_id: scope}
    if held.get("recovery", {}).get("status") == "pending" and action not in {"stop", "withdraw"}:
        raise ClientError("领取处于恢复待核，须先处理在途操作及占用", 409)
    if action == "executor-complete":
        task = state["tasks"][task_id]
        if rules.completion_policy(task) != "executor-direct" or task.get("cancel_requested"):
            raise ClientError("此任务未授权执行者直接完成", 403)
        instruction = service.review(actor, body, held, state, action)
        instruction["expects"].update(expects)
        steps = [instruction]
        if body.get("finish") is True and not held["R"] and held["E"] == {"state": "stopped", "reason": "complete"}:
            steps.append(step(COORDINATOR, "close", {"task_id": task_id}, generation))
    elif action in {"deliver", "deliver-files"}:
        steps = delivery(service, actor, action, key, body, held, expects)
    elif action == "resume":
        steps = resume(actor, body, state, held, scope, generation, expects)
    elif action == "withdraw":
        steps = withdraw(actor, body, state, held, expects)
    elif action == "stop":
        steps = stop(actor, body, held, expects)
    else:
        steps = handoff(actor, body, held, epoch, scope, generation, expects)
    return {"task_id": task_id, "claim_id": cid, "steps": steps}


def delivery(service, actor, action, key, body, held, expects):
    if action == "deliver-files":
        package = service.file_package(held, body["files"])
        instruction = service.deliver(actor, key, package, held, expects)
        instruction["generated_package"] = package
        steps = [instruction]
        if "stop_evidence" in body:
            proof = string(body["stop_evidence"], "stop_evidence")
            steps.append(step(actor, "stopped", {"claim_id": held["claim_id"], "evidence": proof,
                              "ended": [{"reservation_id": rid, "evidence": proof} for rid in held["R"]]}, expects))
        return steps
    return [service.deliver(actor, key, body, held, expects)]


def resume(actor, body, state, held, scope, generation, expects):
    cid, task = held["claim_id"], state["tasks"][held["task_id"]]
    extra_resume = {k: body[k] for k in EXECUTION_OPTIONS if k in body}
    extra_resume['scope_version'] = scope
    if rules.contract(task) and held["E"] == {"state": "stopped", "reason": "pause"}:
        instructions = []
        if held["scope_ack_pending"]:
            instructions.append(step(actor, "ack_scope", {"claim_id": cid}, expects))
        instructions.append(step(COORDINATOR, "resume",
                                 {"claim_id": cid, "authority_ref": "bootstrap", "baseline": task["inputs"], **extra_resume},
                                 {**generation, **expects}))
        return instructions
    if held["W"]["state"] != "revision" or held["E"] != {"state": "stopped", "reason": "complete"}:
        raise ClientError("开始返修前须完成上一次执行的实际停止", 409)
    previous = held["deliveries"][held["W"]["revision"]]["manifest"]
    baseline = {**held["inputs"], previous["path"]: previous["sha256"]}
    return [step(actor, "acquire", {"claim_id": cid, "baseline": baseline, **extra_resume}, expects)]


def withdraw(actor, body, state, held, expects):
    task = state["tasks"][held["task_id"]]
    if rules.enabled(state) and "executor" not in rules.roles(state, rules.task_project(task), actor):
        raise ClientError("撤回交付需要当前项目执行权限", 403)
    if not rules.contract(task) or held["W"]["state"] != "review":
        raise ClientError("须有本项目的待验封存修订", 409)
    return [step(actor, "withdraw_delivery", {"claim_id": held["claim_id"], "revision": string(body["revision"], "revision", 32),
                                               "reason": string(body["reason"], "撤回依据")}, expects)]


def stop(actor, body, held, expects):
    proof = string(body["stop_evidence"], "stop_evidence")
    ended = [{"reservation_id": rid, "evidence": proof} for rid in held["R"]]
    running = held["E"]["state"]
    if running != "requested" and (running != "running" or held["W"]["state"] not in {
            "review", "complete", "revision"}):
        raise ClientError("须已有交付或停止请求，且当前领取尚未停止", 409)
    return [step(actor, "stopped", {"claim_id": held["claim_id"], "evidence": proof, "ended": ended}, expects)]


def handoff(actor, body, held, epoch, scope, generation, expects):
    cid, task_id = held["claim_id"], held["task_id"]
    proof = string(body["stop_evidence"], "stop_evidence")
    ended = [{"reservation_id": rid, "evidence": proof} for rid in held["R"]]
    if held["W"]["state"] not in {"draft", "revision"} or held["E"]["state"] not in {"running", "stopped"}:
        raise ClientError("须在执行或返修阶段完成实际停止后交接", 409)
    note = string(body["notes"], "notes", 16000)
    raw = encoded({"task_id": task_id, "claim_id": cid, "origin_id": actor, "epoch": epoch,
                   "scope_version": scope, "stop_evidence": proof, "notes": note, "inputs": held["inputs"],
                   "deliveries": [rev["manifest"] for rev in held["deliveries"].values()]})
    path = f"handoffs/{cid}/{digest(raw)}.json"
    replace = step(COORDINATOR, "replace_claim",
                   {"claim_id": cid, "replacement": path, "reason": "持有者已报告实际停止并提交接续材料"},
                   {**generation, **expects})
    replace["file"] = [path, base64.b64encode(raw).decode("ascii")]
    if held["E"]["state"] == "stopped":
        releases = [step(actor, "release", {"claim_id": cid, **r}, {**expects, "epoch:" + cid: epoch + 1})
                    for r in ended]
        return [replace, *releases]
    stopped = step(actor, "stopped", {"claim_id": cid, "evidence": proof, "ended": ended},
                   {**expects, "epoch:" + cid: epoch + 1})
    return [replace, stopped]


def registration(actor, key, title, criteria, receiver, path, raw, generation, project=None):
    proposal = digest(encoded([key, 0]))
    first = step(actor, "propose", {"title": title})
    first["file"] = [path, base64.b64encode(raw).decode("ascii")]
    second = step(COORDINATOR, "register", {
        "proposal_id": proposal, "kind": "documentation", "authority_ref": "bootstrap",
        "completes_on": criteria, "requires_commit": False, "receiver": receiver, "inputs": {path: digest(raw)},
    }, generation)
    if project is not None:
        second["payload"]["related"] = {"project": project}
    return {"steps": [first, second], "proposal_id": proposal}


def file_package(held, files):
    if not isinstance(files, list) or not 1 <= len(files) <= 10:
        raise ClientError("请选择 1 至 10 个交付文件")
    artifacts = {}
    seen = set()
    total = 0
    for item in files:
        fields(item, "name content")
        name = artifact_name(item["name"])
        if "/" in name or name.casefold() in seen:
            raise ClientError("交付文件名必须唯一且不含目录")
        try:
            raw = base64.b64decode(item["content"], validate=True)
        except (ValueError, TypeError) as error:
            raise ClientError("交付文件内容无效") from error
        total += len(raw)
        if total > MAX_PACKAGE - 65536:
            raise ClientError("交付文件总大小超出限制", 413)
        seen.add(name.casefold())
        artifacts[name] = raw
    package = make_delivery(held, artifacts)
    return {"package": base64.b64encode(package).decode("ascii"), "package_sha256": digest(package)}


def receiver(state, task_id, actor):
    task = state["tasks"].get(task_id)
    if not task:
        raise ClientError("任务不存在", 404)
    if task["receiver"] != actor:
        raise ClientError("仅指定接收者可以操作", 403)


def deliver(actor, key, body, held, expects):
    if held["W"]["state"] != "draft" or held["E"]["state"] != "running":
        raise ClientError("当前领取无法封存", 409)
    files, data, receipt = unpack_delivery(body)
    revision = "revision-" + str(len(held["deliveries"]) + 1)
    meta = seal_metadata(held, revision)
    if encoded(receipt) != encoded(meta) or encoded({k: v for k, v in data.items() if k != "outputs"}) != encoded({
        **{k: meta[k] for k in ("claim_id", "revision", "scope_version", "inputs")}, "task_id": held["task_id"]
    }):
        raise ClientError("交付清单与本次领取、输入、范围或修订不匹配")
    prefix = f"deliveries/{held['task_id']}/{held['claim_id']}/{revision}/{key}"
    ref = reference(prefix + "/manifest.json", files["manifest.json"])
    result = step(actor, "seal", {**meta, "manifest": ref, "manifest_sha256": ref["sha256"],
                  "client_package_sha256": body["package_sha256"]}, expects)
    result["package_prefix"] = prefix
    return result


def review(service, actor, body, held, state, action):
    revision = string(body["revision"], "revision", 32)
    sealed = held["deliveries"].get(revision)
    if (not sealed or body["manifest_sha256"] != sealed["manifest_sha256"] or
            held["W"]["state"] != "review" or held["W"]["revision"] != revision):
        raise ClientError("修订号或待验清单 SHA256 不匹配", 409)
    if action != "executor-complete" and held["origin"] == actor and not rules.user_acceptance(state, state["tasks"][held["task_id"]], actor):
        raise ClientError("持有者不能自行验收", 403)
    payload = {"claim_id": held["claim_id"], "revision": revision, "verdict": "accept",
               "manifest": sealed["manifest"], "manifest_sha256": body["manifest_sha256"]}
    if action == "return":
        criterion = string(body["criterion"], "完成判据", 100)
        reason = string(body["reason"], "返修要求")
        picked = body.get("criteria", [criterion])
        if (not isinstance(picked, list) or not picked or len(set(map(str, picked))) != len(picked) or criterion not in picked or
                any(item not in sealed["criteria"] for item in picked)):
            raise ClientError("须选择该修订的完成判据")
        payload.update(verdict="revision", reason=reason, checks=[
            {"id": item, "status": "failed", "level": "static", "evidence": {"note": reason}} for item in picked
        ], remaining=[{"check_id": item, "criterion": item, "description": reason,
                       "kind": "failed", "required": True, "disposition": "within"} for item in picked])
        return step(actor, "review", payload)
    refs = service.delivery_refs(sealed["manifest"])
    if not isinstance(body["checks"], list) or not 1 <= len(body["checks"]) <= 30:
        raise ClientError("须逐项提供验收检查和产物证据")
    checks = []
    for check in body["checks"]:
        fields(check, "id path sha256 note")
        ref = {"path": string(check["path"], "path", 650), "sha256": check["sha256"]}
        if ref not in refs:
            raise ClientError("验收证据须引用本修订的实际输出")
        checks.append({"id": string(check["id"], "id", 100), "status": "passed", "level": "static",
                       "evidence": {"artifact": ref, "note": string(check["note"], "note")}})
    passed = {check["id"] for check in checks}
    resolved = [item for item in state["items"].values()
                if item["holder"] == held["task_id"] and item["status"] == "unresolved"
                and item["kind"] == "failed" and item["criterion"] in passed
                and state["acceptances"].get(item["source_record"], {}).get("verdict") == "revision"]
    payload.update(checks=checks, resolve=[
        {"item_id": item["item_id"], "check_id": item["criterion"]} for item in resolved
    ])
    return step(actor, "executor_complete" if action == "executor-complete" else "review", payload, {"item:" + item["item_id"]: item["version"] for item in resolved})
