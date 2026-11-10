"""Version 3 admission, enrollment and execution decisions."""
from 协作升级 import (active, active_claims, contract, grant, identity, manager, project_record,
                  require, responsible, roles, system_admin, task_project, visible)
from 协作存储 import digest, encoded

VERSION = 3
ACTIVATION_SECONDS = 600
TOKEN_SECONDS = 90 * 86400
DEFAULT_POLICY = {"mode": "open", "subjects": [], "capabilities": [], "automation": "notify", "owner": ""}
OPS = {"round-migrate", "ai-invite", "ai-revoke", "ai-prepare", "ai-activate", "token-prepare",
       "project-automation", "runner-settings", "run-report", "password-event",
       "decision-save", "task-relation", "change-open", "change-finish", "feedback-save", "feedback-update", "feedback-move",
       "delegate-grant", "delegate-revoke", "window-admin", "capability-request", "capability-resolve"}

DELEGATION_EXECUTION = {"claim", "deliver", "deliver-files", "stop", "handoff", "run-report", "resume"}
DELEGATION_MANAGEMENT = {"register", "task-publish", "task-hold", "feedback-update"}
DELEGATION_ACTIONS = {"read", "feedback-save", "capability-save"} | DELEGATION_EXECUTION | DELEGATION_MANAGEMENT
DELEGATION_PRESETS = {"task": {"read", "feedback-save", "capability-save"} | DELEGATION_EXECUTION,
                      "project": DELEGATION_ACTIONS}
DELEGATION_MAX_SECONDS = 30 * 86400


def delegation_id(delegator, executor, project):
    return "d-" + digest(encoded([delegator, executor, project]))[:30]


def delegable(state, person, project, operation):
    """Check the person's own current permissions, without inherited agent roles."""
    subject = identity(state, person) or {}
    if subject.get("kind") != "human" or not active(state, person) or not project_record(state, project):
        return False
    current = set(grant(state, project, person)["roles"])
    if operation == "read":
        return bool(current)
    if operation in DELEGATION_EXECUTION:
        return "executor" in current
    if operation in DELEGATION_MANAGEMENT:
        return "manager" in current
    if operation == "capability-save":
        return bool(current & {"manager", "executor", "receiver"})
    return operation == "feedback-save" and bool(current - {"observer"})


def usable_delegation(state, record, actor, operation, project, task_id, now):
    subject = identity(state, actor) or {}
    return bool(record and subject.get("kind") == "executor" and active(state, actor) and
                subject.get("owner") == record.get("delegator") and record.get("executor_id") == actor and
                record.get("project_id") == project and not record.get("revoked") and
                record.get("expires", 0) > now and operation in record.get("actions", []) and
                (not record.get("task_ids") or task_id in record["task_ids"] or operation == "capability-save" and task_id is None) and
                (not task_id or task_project(state["tasks"].get(task_id)) == project) and
                delegable(state, record["delegator"], project, operation))


def delegation_action(state, p, actor, now, event_id):
    from 协作升级 import ID
    records = state["round"]
    subject = identity(state, actor) or {}
    require(subject.get("kind") == "human" and active(state, actor), "委托须由人员本人办理", "intent-final")
    if p["op"] == "delegate-revoke":
        old = records.get("delegation:" + str(p.get("delegation_id")))
        require(old and old["delegator"] == actor and type(p.get("version")) is int and old["version"] == p.get("version"),
                "委托不存在、版本已变化或无撤销权限", "intent-final")
        require(isinstance(p.get("reason"), str) and 0 < len(p["reason"].strip()) <= 2000, "撤销须填写依据")
        old.setdefault("history", []).append({k: v for k, v in old.items() if k != "history"})
        old.update(revoked=True, version=old["version"] + 1, revoke_reason=p["reason"],
                   revoked_by=actor, revoked_at=now, revoked_event=event_id)
        return
    executor, project = p.get("executor_id"), p.get("project_id")
    assistant = identity(state, executor) or {}
    require(isinstance(executor, str) and ID.fullmatch(executor) and isinstance(project, str) and ID.fullmatch(project),
            "窗口或项目编号无效")
    require(assistant.get("kind") == "executor" and active(state, executor) and assistant.get("owner") == actor,
            "只能给本人关联的有效 AI 窗口授权", "intent-final")
    require(project_record(state, project), "项目不存在")
    actions, tasks = p.get("actions"), p.get("task_ids")
    require(isinstance(actions, list) and 0 < len(actions) <= len(DELEGATION_ACTIONS) and
            all(isinstance(item, str) and item in DELEGATION_ACTIONS for item in actions) and
            len(set(actions)) == len(actions), "委托动作无效")
    require(all(delegable(state, actor, project, operation) for operation in actions),
            "委托动作超出人员当前项目权限", "intent-final")
    require(isinstance(tasks, list) and len(tasks) <= 100 and
            all(isinstance(item, str) and ID.fullmatch(item) and task_project(state["tasks"].get(item)) == project for item in tasks) and
            len(set(tasks)) == len(tasks), "任务范围须为本项目的任务编号列表")
    require(not tasks or "register" not in actions, "创建任务需要项目范围委托，不能使用已有任务白名单")
    require(type(p.get("expires")) is int and now < p["expires"] <= now + DELEGATION_MAX_SECONDS,
            "委托须在未来 30 天内到期")
    require(isinstance(p.get("reason"), str) and 0 < len(p["reason"].strip()) <= 2000, "委托须填写依据")
    key_id = delegation_id(actor, executor, project)
    require(p.get("delegation_id") == key_id, "委托编号与人员、窗口或项目不符")
    old = records.get("delegation:" + key_id, {})
    require(type(p.get("version")) is int and 0 <= p["version"] <= 10**9 and old.get("version", 0) == p["version"],
            "委托版本已变化")
    records["delegation:" + key_id] = {"id": key_id, "delegator": actor, "executor_id": executor,
        "project_id": project, "actions": sorted(actions), "task_ids": sorted(tasks), "expires": p["expires"],
        "version": p["version"] + 1, "revoked": False, "reason": p["reason"], "at": now, "event": event_id,
        "history": old.get("history", []) + ([{k: v for k, v in old.items() if k != "history"}] if old else [])}


def enabled(state):
    return VERSION <= state["pilot"].get("format", {}).get("schema", 0) <= 5


def task_policy(state, project, data):
    from 协作升级 import requirement_rows
    require(isinstance(data, dict) and data.keys() == DEFAULT_POLICY.keys(), "预指定合同字段不完整")
    require(data["mode"] in ("open", "prefer", "only") and data["automation"] in ("notify", "auto"),
            "领取模式或自动执行策略无效")
    subjects, requirements, owner = data["subjects"], data["capabilities"], data["owner"]
    require(isinstance(subjects, list) and len(subjects) <= 30 and
            all(isinstance(name, str) and "executor" in roles(state, project, name) for name in subjects),
            "指定主体须有本项目执行授权")
    require(len(set(subjects)) == len(subjects) and isinstance(requirements, list), "指定范围无效")
    if requirements:
        requirements = requirement_rows(requirements)
        require(all(row["required"] for row in requirements), "目标能力组须逐项匹配")
    require(bool(subjects or requirements) == (data["mode"] != "open"), "预指定模式与目标范围不一致")
    require(isinstance(owner, str) and (not owner or
            (identity(state, owner) or {}).get("kind") == "human" and bool(roles(state, project, owner))),
            "任务责任人须为本项目人员")
    return {**data, "subjects": sorted(subjects), "capabilities": requirements}


def policy(task):
    return (contract(task) or {}).get("dispatch", DEFAULT_POLICY)


def target_match(state, task, actor, now):
    from 协作升级 import capability_matches
    selection = policy(task)
    targets = selection["capabilities"]
    return actor in selection["subjects"] or bool(targets and all(
        capability_matches(state, task_project(task), actor, row, now) for row in targets
    ))


def blocked(state, task, actor, now):
    reasons = []
    if task.get("change_pending"):
        reasons.append("任务关系变更待确认")
    if task.get("decision_holds"):
        reasons.append("任务决定待确认")
    if policy(task)["mode"] == "only" and not target_match(state, task, actor, now):
        reasons.append("当前身份不在限定领取范围")
    return reasons


def execution_settings(state, actor):
    return state["round"].get(f"runner:{actor}", {"auto": False, "limit": 1, "heartbeat": False, "adapter": ""})


def automation_allowed(state, task, actor):
    project = task_project(task)
    settings = execution_settings(state, actor)
    return (state["round"].get(f"automation:{project}", {}).get("enabled") is True and
            policy(task)["automation"] == "auto" and settings["auto"] and bool(settings["adapter"]))


def invite_allowed(state, issuer, project, owner, requested):
    issuing, owning = identity(state, issuer) or {}, identity(state, owner) or {}
    if not project_record(state, project) or not (
        issuing.get("kind") == owning.get("kind") == "human" and active(state, issuer) and active(state, owner)
    ):
        return False
    allowed = roles(state, project, owner)
    return (bool(requested) and set(requested) <= {"executor", "receiver"} and
            ("manager" in allowed or set(requested) <= allowed) and
            (manager(state, project, issuer) or issuer == owner and "receiver" not in requested))


def rotation_allowed(state, issuer, name):
    subject = identity(state, name) or {}
    return (subject.get("kind") == "executor" and active(state, subject["owner"]) and
            (system_admin(state, issuer) or issuer == subject["owner"] and active(state, issuer)))


def usable_invite(state, record):
    return record and not record.get("revoked") and invite_allowed(
        state, record["issuer"], record["project"], record["owner"], record["roles"]
    )


def ready_key(task, actor):
    return digest(encoded([task["task_id"], task["version"], task["scope_version"], actor]))


def enrollment_action(state, p, actor, now, event_id):
    from 协作升级 import assign_window
    records = state["round"]
    op = p["op"]
    if op == "ai-invite":
        require(invite_allowed(state, actor, p["project_id"], p["owner"], p["roles"]),
                "无有效邀请授权", "intent-final")
        key = "invite:" + p["invite_id"]
        require(key not in records and type(p["hours"]) is int and 1 <= p["hours"] <= 168 and
                type(p["count"]) is int and 1 <= p["count"] <= 20, "邀请有效期或额度无效")
        records[key] = {"id": p["invite_id"], "issuer": actor, "project": p["project_id"], "owner": p["owner"],
                        "roles": p["roles"], "resources": grant(state, p["project_id"], p["owner"])["resources"],
                        "expires": int(now) + 3600 * p["hours"], "count": p["count"], "used": 0, "revoked": False,
                        "event": event_id}
        return
    if op == "ai-revoke":
        record = records.get("invite:" + p["invite_id"])
        require(record and not record["revoked"] and (system_admin(state, actor) or
                manager(state, record["project"], actor) or actor == record["issuer"] and active(state, actor)),
                "邀请不存在或无撤销权限", "intent-final")
        record.update(revoked=True, revoked_by=actor, revoke_reason=p["reason"], revoked_event=event_id)
        for key, enrollment in records.items():
            if key.startswith("enrollment:") and enrollment.get("invite_id") == record["id"] and enrollment["state"] == "pending":
                enrollment.update(state="revoked", terminal_event=event_id)
                identity(state, enrollment["name"])["status"] = "disabled"
        return
    key = "enrollment:" + p["registration_id"]
    if op == "ai-prepare":
        record = records.get("invite:" + p["invite_id"])
        require(usable_invite(state, record) and record["issuer"] == actor, "邀请已撤销或授权已失效", "intent-final")
        require(record["expires"] > now and record["used"] < record["count"], "邀请已过期或额度已用完")
        name = p["name"]
        require(key not in records and name not in state["origins"], "登记编号或身份已使用")
        assign_window(state, name, record["owner"], p["source"])
        identity(state, name).update(status="pending", registration=p["registration_id"], last_contact=now)
        state["origins"][name] = {"roles": ["executor", "receiver"], "local": False, "version": 0}
        state["pilot"][f"grant:{record['project']}:{name}"] = {
            "roles": record["roles"], "resources": record["resources"], "version": 1,
        }
        record["used"] += 1
        records[key] = {"id": p["registration_id"], "kind": "invite", "invite_id": record["id"], "issuer": actor,
                        "project": record["project"], "name": name, "state": "pending", "version": 1,
                        "proof_sha": p["proof_sha"], "source_sha": p["source_sha"], "deadline": int(now) + ACTIVATION_SECONDS,
                        "event": event_id}
        return
    if op == "token-prepare":
        name = p["name"]
        subject = identity(state, name)
        require(rotation_allowed(state, actor, name), "须由责任账号或管理员轮换执行端凭据", "intent-final")
        require(key not in records and subject["credential"] == p["version"] and subject["status"] in ("active", "disabled", "disputed", "paused", "archived"),
                "凭据版本已变化或身份尚未激活")
        records[key] = {"id": p["registration_id"], "kind": "rotation", "issuer": actor, "name": name,
                        "version": p["version"] + 1, "state": "pending", "proof_sha": p["proof_sha"],
                        "deadline": int(now) + ACTIVATION_SECONDS, "reason": p["reason"], "event": event_id}
        return
    record = records.get(key)
    require(record and record["state"] == "pending" and record["deadline"] > now and record["issuer"] == actor,
            "激活凭据已到期或无效")
    subject = identity(state, record["name"])
    if record["kind"] == "invite":
        require(subject["status"] == "pending" and subject["credential"] == record["version"] and
                usable_invite(state, records.get("invite:" + record["invite_id"])), "登记状态或邀请权限已变化")
    else:
        require(rotation_allowed(state, actor, record["name"]) and subject["credential"] + 1 == record["version"],
                "轮换权限或旧凭据版本已变化")
    expires = int(now) + TOKEN_SECONDS
    subject.update(status="active", credential=record["version"], last_contact=now, token_expires=expires)
    record.update(state="active", expires=expires, activation=event_id)


def execution_action(state, p, actor, now, event_id):
    from 协作升级 import eligible
    records = state["round"]
    op = p["op"]
    if op == "project-automation":
        require(manager(state, p["project_id"], actor), "须有项目管理授权", "intent-final")
        key = f"automation:{p['project_id']}"
        old = records.get(key, {})
        require(old.get("version", 0) == p["version"], "项目自动化策略已变化")
        records[key] = {"enabled": p["enabled"], "version": p["version"] + 1, "by": actor, "event": event_id}
        return
    if op == "runner-settings":
        subject = identity(state, actor) or {}
        require(subject.get("kind") == "executor" and active(state, subject["owner"]),
                "须为有效执行端本人", "intent-final")
        key = f"runner:{actor}"
        require(records.get(key, {}).get("version", 0) == p["version"], "执行端策略已变化")
        records[key] = {**p["settings"], "version": p["version"] + 1, "by": actor, "event": event_id}
        return
    claim = state["claims"].get(p["claim_id"])
    if state.get('security',{}).get('schema',0)>=5:
        require(p['state'] not in {'intent','started'}, '新开工须使用动作开始许可；旧run-report只能收尾')
    require(claim and claim["origin"] == actor and claim["L"] == "active" and claim["epoch"] == p["epoch"],
            "领取或执行代次已变化", "intent-final")
    task = state["tasks"][claim["task_id"]]
    require(task["scope_version"] == claim["W"]["scope"] == p["scope_version"] and
            claim["E"]["state"] == "running" and not task.get("cancel_requested") and not claim.get("scope_ack_pending") and
            claim.get("recovery", {}).get("status") != "pending", "任务已暂停、撤权或改版")
    if p['state'] not in {'finished','error'}:
        missing, _ = eligible(state, task, actor, now, include_status=False, check_resources=False)
        require(not missing, "；".join(missing))
    run = claim.get("run", {})
    current = run.get("state", "claimed")
    wanted = p["state"]
    is_auto = bool(run.get("automation"))
    if wanted in {"intent", "started"} and is_auto:
        require(automation_allowed(state, task, actor), "自动执行授权已变化")
    allowed = {"intent": {"claimed"}, "started": {"intent"} if is_auto else {"claimed", "intent"},
               "waiting": {"started", "working"}, "working": {"waiting"}, "finished": {"started", "working", "waiting"},
               "error": {"intent", "started", "working", "waiting"}}
    require(current in allowed[wanted], "实际执行状态已变化或开工已登记")
    claim["run"] = {**run, "state": wanted, "event": event_id, "time": now, "evidence": p["evidence"]}
    if wanted == "started":
        claim["run"]["started"] = now
    subject = identity(state, actor)
    if subject["kind"] == "executor":
        subject["last_contact"] = now


def action(state, env, context):
    p = env["payload"]
    op, actor, now = p["op"], p["_audit"]["actor"], context["now"]
    event_id = env["event_id"]
    fmt = state["pilot"]["format"]
    if op == "round-migrate":
        require(fmt["schema"] == 2 and system_admin(state, actor) and not active_claims(state),
                "迁移需要 v2 数据、管理员和已结束的活动领取")
        require("release:" + p["upgrade"] not in state["pilot"], "本轮版本号已使用")
        state["round"]["format"] = {"from": 2, "event": event_id, "prior": dict(fmt), "at": now}
        fmt.update(schema=VERSION, min_reader=VERSION, maintenance=True, image=p["image"], upgrade=p["upgrade"])
        state["pilot"]["release:" + p["upgrade"]] = {
            "status": "pending", "image": p["image"], "by": actor, "schema": VERSION,
        }
        return
    require(enabled(state), "请先迁移本轮数据合同")
    require(not fmt["maintenance"] or op == "password-event" and p["kind"] == "admin-recovery",
            "服务处于维护窗口")
    if op in {"ai-invite", "ai-revoke", "ai-prepare", "ai-activate", "token-prepare"}:
        enrollment_action(state, p, actor, now, event_id)
    elif op in {"delegate-grant", "delegate-revoke"}:
        delegation_action(state, p, actor, now, event_id)
    elif op in {"window-admin", "capability-request", "capability-resolve"}:
        from pool.window_admin import apply
        apply(state, p, actor, now, event_id)
    elif op in {"project-automation", "runner-settings", "run-report"}:
        execution_action(state, p, actor, now, event_id)
    elif op == "password-event":
        subject = identity(state, p["name"]) or {}
        require(subject.get("kind") == "human" and
                (p["name"] == actor and active(state, actor) or system_admin(state, actor)), "无人员凭据处置授权")
        state["round"][f"password:{event_id}"] = {"name": p["name"], "kind": p["kind"], "by": actor, "at": now}
    else:
        from 协作关系 import action as project_action
        project_action(state, p, actor, now, event_id)
