#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pure revision-7 command decisions. Files/processes are checked by the ledger adapter."""
import copy
import re

from 协作存储 import Rejected, digest, encoded


SHA = re.compile(r"[0-9a-f]{64}\Z")
TASK_KINDS = {"documentation", "candidate", "implementation", "integration", "native", "repair", "parent"}
LINES = {"candidate", "implementation", "integration", "native", "repair"}
SCHEDULE = {"register", "reject_proposal", "scope", "different", "dependencies", "resume",
            "revoke", "replace_claim", "register_origin", "authority", "standing", "coverage", "commit_record",
            "close", "redirect", "repair", "gap_close", "resolve_conflict", "migration_import",
            "migration_verify", "cutover", "migration_rollback", "cancel", "pause"}
SCHEDULE.add("migration_map")
SCHEDULE.add("assign_receiver")
SCHEDULE.add("pilot")
SCHEDULE.add("board_layout")
SCHEDULE.update({"flow_setup", "flow_enable", "flow_rebase"})
HOLDER = {"ack_scope", "stopped", "acquire", "seal", "withdraw_delivery", "release", "owner_ack"}
RANK = {"pause": 1, "reject": 2, "revoke": 3, "replace": 4, "cancel": 5}
CARRYABLE = {"available", "running"}
TERMINAL = {"completed", "closed_missing", "cancelled", "replaced", "merged", "closed_candidate"}
FLAGS = {"compiled", "tested", "applied", "deployed"}


def require(condition, reason, category="format"):
    if not condition:
        raise Rejected(reason, category)


def text(value):
    return isinstance(value, str) and bool(value.strip())


def reason(payload):
    require(text(payload.get("reason")), "必须记录原因")


def authority(state, payload):
    key = payload.get("authority_ref")
    require(key in state["authorities"], "缺少已登记、可追溯的用户依据")
    return key


def relative(value):
    require(isinstance(value, str) and value and not any(c in value for c in "\\:\0<>\"|?*"), "资源路径格式错误")
    parts = value.split("/")
    require(all(p not in {"", ".", ".."} and p.rstrip(" .") == p and
                not re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", p) and
                all(ord(c) >= 32 for c in p) for p in parts), "资源路径越界或含歧义段")
    return value.casefold()


def resource(raw):
    require(isinstance(raw, dict) and set(raw) == {"id", "mode"}, "资源须声明id与mode")
    value, mode = raw["id"], raw["mode"]
    require(isinstance(value, str) and ":" in value and mode in {"read", "write", "exclusive"}, "资源格式错误")
    kind, target = value.split(":", 1)
    require(kind in {"path", "build", "app", "native"} and text(target), "未知资源种类")
    if kind == "path":
        target = relative(target)
    return {"id": kind + ":" + target, "mode": mode}


def expanded(state, requested):
    result = [resource(r) for r in requested]
    if any(r["id"].startswith("build:") for r in result):
        result.extend([{"id": "build:公共构建槽", "mode": "exclusive"},
                       {"id": "rootread:", "mode": "read"}])
        result.extend({"id": "path:" + p, "mode": "exclusive"} for p in ("bin", "obj", "tests/bin", "tests/obj"))
    if any(r["id"].startswith("app:") for r in result):
        result.append({"id": "app:串行槽", "mode": "exclusive"})
    for current in list(result):
        for raw in state["coverage"].get(current["id"], []):
            result.append(resource(raw))
    return list({(r["id"], r["mode"]): r for r in result}.values())


def covers(state, a, b):
    if a == b:
        return True
    ka, ta = a.split(":", 1)
    kb, tb = b.split(":", 1)
    if ka == kb == "path":
        return tb.startswith(ta + "/")
    if ka == "rootread" and kb == "path":
        return True
    if ka == kb == "build":
        return ta == "公共构建槽"
    if ka == kb == "app":
        return ta == "串行槽"
    if ka == kb == "native":
        if a in state["coverage"] and b in state["coverage"]:
            left = {r["id"] for r in state["coverage"][a]}
            right = {r["id"] for r in state["coverage"][b]}
            return b in left or a in right or bool(left & right)
        return True
    # Build/path interaction is represented by its fixed source/output occupancies.
    if {ka, kb} <= {"path", "build", "rootread"} or ka == kb == "rootread":
        return False
    if ka == "native" or kb == "native":
        return True  # Undeclared cross-domain coverage is unknown, therefore conflicting.
    return False


def conflicts(state, left, right):
    return (left["mode"] != "read" or right["mode"] != "read") and (
        covers(state, left["id"], right["id"]) or covers(state, right["id"], left["id"]))


def unresolved(state, task_id):
    return [i for i in state["items"].values() if i["holder"] == task_id and i["status"] == "unresolved"]


def committed_paths(state, task):
    accepted = state["acceptances"].get(task.get("accepted"), {})
    mapping = accepted.get("repository_outputs", {})
    return {path["path"] for record in state["commits"].values()
            if record["task_id"] == task["task_id"] and not record.get("pending_verification") and
            record.get("acceptance_id") == task.get("accepted") and record.get("scope_version") == task["scope_version"]
            for path in record["paths"] if path["path"] in mapping and mapping[path["path"]]["sha256"] == path["sha256"]}


def grants(state, held, wanted):
    """Unknown overlap can block another writer, but can never grant permission."""
    if held == wanted:
        return True
    if held.startswith("path:") and wanted.startswith("path:"):
        return wanted.startswith(held + "/")
    if held == "build:公共构建槽" and wanted.startswith("build:"):
        return True
    if held == "app:串行槽" and wanted.startswith("app:"):
        return True
    return any(grants(state, resource(raw)["id"], wanted) for raw in state["coverage"].get(held, []) if raw["id"] != held)


def delivery_resource(state, c):
    return {"id": "path:" + state["storage_prefix"].casefold() + "/deliveries/" + c["task_id"].casefold() + "/" + c["claim_id"].casefold(), "mode": "write"}


def writable(state, claim_id, actor, epoch, scope, target):
    c = state["claims"].get(claim_id)
    if not c or c["origin"] != actor or c["L"] != "active" or c["E"]["state"] != "running":
        return False
    if state["tasks"][c["task_id"]]["status"] != "running":
        return False
    if c["epoch"] != epoch or c["W"]["scope"] != scope or c["W"]["state"] != "draft":
        return False
    try:
        wanted = resource({"id": target, "mode": "write"})
    except Rejected:
        return False
    allowed = expanded(state, state["tasks"][c["task_id"]]["resources"]) + [delivery_resource(state, c)]
    if not any(r["mode"] != "read" and grants(state, r["id"], wanted["id"]) for r in allowed):
        return False
    if c.get("scope_ack_pending") and not any(grants(state, x, wanted["id"]) for x in c["continue"]):
        return False
    return any(state["reservations"][rid]["mode"] != "read" and
               grants(state, state["reservations"][rid]["id"], wanted["id"]) for rid in c["R"])


def check_expects(state, expects):
    require(isinstance(expects, dict), "expects须为对象")
    for key, expected in expects.items():
        require(type(expected) is int, "版本须为整数")
        if key == "generation":
            actual = state["generation"]
        else:
            require(":" in key, "未知expects字段")
            kind, record = key.split(":", 1)
            mapping = {"task": ("tasks", "version"), "scope": ("tasks", "scope_version"),
                       "claim": ("claims", "version"), "epoch": ("claims", "epoch"),
                       "item": ("items", "version"), "proposal": ("proposals", "version")}
            require(kind in mapping and record in state[mapping[kind][0]], "expects对象不存在", "retryable")
            table, field = mapping[kind]
            actual = state[table][record][field]
        require(actual == expected, "expects依据已过期：" + key, "retryable")


def reserve(state, c, requested, seq):
    from 协作安全 import blocked_resources
    require(not any(conflicts(state, wanted, blocked) for wanted in requested
                    for blocked in blocked_resources(state)), '资源物理占用待确认，不能重授', 'retryable')
    resources = expanded(state, requested)
    others = [r for r in state["reservations"].values() if r["active"] and r["claim_id"] != c["claim_id"]]
    require(not any(conflicts(state, a, b) for a in resources for b in others), "资源被占用", "retryable")
    occupied_lines = {r["claim_id"] for r in others if r["mode"] != "read" and
                      state["claims"][r["claim_id"]]["kind"] in LINES}
    if c["kind"] in LINES and any(r["mode"] != "read" for r in resources):
        require(len(occupied_lines) < 2, "已有两条实施线占用", "retryable")
    existing = {(state["reservations"][rid]["id"], state["reservations"][rid]["mode"]) for rid in c["R"]}
    for index, r in enumerate(resources):
        if (r["id"], r["mode"]) in existing:
            continue
        rid = c["claim_id"] + "/" + str(seq) + "/" + str(index)
        state["reservations"][rid] = {**r, "reservation_id": rid, "claim_id": c["claim_id"],
                                      'epoch':c['epoch'], 'scope_version':c['W']['scope'],
                                      "active": True, "ended_evidence": None, "pending_seal": False}
        c["R"].append(rid)


def release_one(state, c, rid, evidence):
    require(rid in c["R"] and text(evidence), "释放须为自身占用且有结束依据")
    from 协作安全 import preserve_unknown
    preserve_unknown(state, c, state['reservations'][rid], evidence)
    state["reservations"][rid].update(active=False, ended_evidence=evidence, pending_seal=False)
    c["R"].remove(rid)


def stop(c, why):
    old = c["E"].get("reason")
    if old in RANK:
        require(RANK[why] >= RANK[old], "已被更强停止请求覆盖", "covered")
        if why == old:
            return
    c["E"] = {"state": "stopped" if c["E"]["state"] == "stopped" else "requested", "reason": why}
    c["epoch"] += 1


def carryable(state, target):
    return (target in state["tasks"] and state["tasks"][target]["status"] in CARRYABLE or
            target in state["proposals"] and state["proposals"][target]["status"] == "proposed")


def redirect_invalid(state, target, replacement=None, cancel_authority=None):
    for item in state["items"].values():
        if item["holder"] != target or item["status"] != "unresolved":
            continue
        old = item["holder"]
        if replacement:
            require(carryable(state, replacement), "接替目标不可承接", "retryable")
            item.update(holder=replacement, disposition="task:" + replacement)
        elif item["source_task"] == target and cancel_authority:
            item.update(holder=None, status="closed", disposition="none:用户取消 " + cancel_authority)
        elif carryable(state, item["source_task"]):
            item.update(holder=item["source_task"], disposition="within")
        else:
            item.update(holder=None, disposition="pending")
        item["history"].append({"from": old, "to": item["holder"], "reason": "承接失效"})


def finish(state, c):
    if c["L"] != "active" or c["E"]["state"] != "stopped" or c["R"]:
        return
    if c["W"]["state"] not in {"complete", "terminated"} and c["E"].get("reason") not in {"cancel", "revoke", "replace"}:
        return
    c["L"] = "ended"
    task = state["tasks"][c["task_id"]]
    if any(x["task_id"] == c["task_id"] and x["L"] == "active" for x in state["claims"].values()):
        return
    if task.get("cancel_requested"):
        task["status"] = "cancelled"
        redirect_invalid(state, c["task_id"], cancel_authority=task.get("cancel_authority"))
    elif c["W"]["state"] == "complete" and c["W"]["scope"] == task["scope_version"] and not unresolved(state, c["task_id"]):
        task["status"] = "pending_commit" if task["requires_commit"] else "pending_close"
    else:
        task["status"] = "available"


def dependencies_ok(state, task):
    for dep in task["dependencies"]:
        require(set(dep) == {"task", "output", "criterion"} and text(dep["output"]) and text(dep["criterion"]), "依赖须为任务/产出/判据三元组")
        require(dep["task"] in state["tasks"], "依赖缺失", "retryable")
        other = state["tasks"][dep["task"]]
        require(dep["criterion"] in other.get("provided", {}).get(dep["output"], []), "依赖尚未满足或失败", "retryable")


def no_cycles(state):
    visiting, visited = set(), set()
    def visit(task_id):
        require(task_id not in visiting, "依赖成环")
        if task_id in visited:
            return
        visiting.add(task_id)
        for dep in state["tasks"][task_id]["dependencies"]:
            if dep["task"] in state["tasks"]:
                visit(dep["task"])
        visiting.remove(task_id)
        visited.add(task_id)
    for task_id in state["tasks"]:
        visit(task_id)


def add_proposal(state, proposal_id, actor, payload, authorities=None):
    require(text(payload.get("title")), "提议须有内容")
    require(proposal_id not in state["proposals"], "提议标识已存在")
    state["proposals"][proposal_id] = {"proposal_id": proposal_id, "origin": actor, "status": "proposed",
                                       "title": payload["title"], "related": payload.get("related"),
                                       "authorities": list(authorities or []), "version": 0}


def disposition(state, item, value, actor, env, allow_transfer=False, scope_change=False, cancellation=False):
    require(text(value), "遗留项必须指定去向")
    require(not item.get("required") or value == "within" or value.startswith("resolved:") or scope_change or cancellation,
            "必做项只能within；移出必须改范围")
    old = item.get("holder")
    if value == "within":
        require(carryable(state, item["source_task"]), "本任务已不可承接")
        item.update(holder=item["source_task"], status="unresolved")
    elif value.startswith("task:"):
        target = value[5:]
        require(allow_transfer, "跨任务转交只能由协调者决定")
        require(target != item["source_task"], "task自引用；应使用within")
        require(target in state["tasks"] and carryable(state, target), "目标任务不能承接", "retryable")
        item.update(holder=target, status="unresolved")
    elif value.startswith("resolved:"):
        require(actor == state["coordinator"] or "receiver" in state["origins"][actor]["roles"], "持有者不能自行关闭遗留项")
        parts = value[9:].split("/", 1)
        require(len(parts) == 2, "resolved须引用任务/记录")
        record = state["acceptances"].get(parts[1]) or state["closings"].get(parts[1])
        require(record and record["task_id"] == parts[0] and record.get("verdict") in {"accept", "complete"}, "解决证据不存在或不是接受/完整收口")
        require(text(item.get("evidence")), "解决覆盖关系须记录人工核定依据")
        item.update(holder=None, status="resolved")
    elif value == "propose":
        pid = "p-" + digest(encoded([env["origin_id"], env["event_id"], item["item_id"]]))[:24]
        add_proposal(state, pid, actor, {"title": item["description"], "related": item["source_task"]},
                     item.get("authorities", []))
        item.update(holder=pid, status="unresolved")
    elif value.startswith("none:"):
        require(text(value[5:]) and (item["kind"] != "failed" or cancellation), "failed项不能none，关闭原因不能为空")
        item.update(holder=None, status="closed")
    else:
        raise Rejected("未知遗留项去向")
    item["disposition"] = value
    item["history"].append({"from": old, "to": item["holder"], "disposition": value,
                             "origin": actor, "event_id": env["event_id"], "reason": env["payload"].get("reason", "")})


def add_items(state, entries, source_task, record_id, actor, env, allow_transfer=False):
    require(isinstance(entries, list), "遗留项必须为数组")
    result = []
    for index, raw in enumerate(entries):
        require(isinstance(raw, dict) and text(raw.get("description")) and type(raw.get("required", False)) is bool,
                "遗留项须有描述、必做标记和去向")
        required = raw.get("required", False)
        if required:
            require(raw.get("criterion") in state["tasks"][source_task]["completes_on"], "必做项须绑定完成判据")
        item_id = record_id + "/remaining#" + str(index + 1)
        require(item_id not in state["items"], "遗留项编号已存在")
        item = {"item_id": item_id, "source_task": source_task, "source_record": record_id,
                "description": raw["description"], "required": required, "criterion": raw.get("criterion"),
                "kind": raw.get("kind", "remaining"), "holder": None, "status": "unresolved",
                "evidence": raw.get("evidence"), "history": [], "version": 0}
        item["authorities"] = list(state["tasks"][source_task]["authorities"]) if required else []
        if raw.get("authority_ref"):
            require(raw["authority_ref"] in state["authorities"], "遗留项用户依据未登记")
            item["authorities"] = sorted(set(item["authorities"] + [raw["authority_ref"]]))
        require(item["kind"] in {"remaining", "failed", "not-run", "suggestion"}, "未知遗留项类型")
        disposition(state, item, raw.get("disposition"), actor, env, allow_transfer)
        state["items"][item_id] = item
        result.append(item_id)
    return result


def new_task(state, proposal, payload, seq, related=None):
    kind = payload.get("kind")
    require(kind in TASK_KINDS, "任务类型缺失或错误")
    require(isinstance(payload.get("completes_on"), list) and payload["completes_on"] and
            all(text(x) for x in payload["completes_on"]) and len(set(payload["completes_on"])) == len(payload["completes_on"]), "须声明不重复的完成判据")
    require(type(payload.get("requires_commit")) is bool, "须声明requires_commit")
    require(type(payload.get("priority", 0)) is int, "优先级须为整数")
    require(isinstance(payload.get("required_paths", []), list), "提交路径须为数组")
    require(payload.get("receiver") in state["origins"] and
            "receiver" in state["origins"][payload["receiver"]]["roles"], "须指定已登记的接收者")
    inputs = payload.get("inputs")
    require(isinstance(inputs, dict) and inputs and all(text(k) and SHA.fullmatch(v) for k, v in inputs.items()), "须冻结输入SHA")
    flags = payload.get("execution", {k: False for k in FLAGS})
    require(set(flags) == FLAGS and all(type(v) is bool for v in flags.values()), "执行权限须为四项布尔值")
    require(kind in {"implementation", "integration", "native", "repair"} or not any(flags.values()), "静态卡不能获取执行权限")
    resources = [resource(r) for r in payload.get("resources", [])]
    task_id = "T" + str(state["next_task"]).zfill(2)
    require(task_id not in state["tasks"], "迁移编号上界未核清")
    state["next_task"] += 1
    task = {"task_id": task_id, "title": proposal["title"], "kind": kind, "status": "merge_pending" if payload.get("possible_duplicate") else "available",
            "scope_version": 1, "version": 0, "created_seq": seq, "priority": payload.get("priority", 0),
            "authorities": list(proposal["authorities"]), "source_proposal": proposal["proposal_id"],
            "completes_on": payload["completes_on"], "requires_commit": payload["requires_commit"],
            "required_paths": payload.get("required_paths", []), "receiver": payload["receiver"],
            "resources": resources, "inputs": inputs, "execution": flags,
            "dependencies": payload.get("dependencies", []), "parent": payload.get("parent"),
            "related": related or payload.get("related"), "provided": {}, "claims": []}
    require(all(isinstance(x, dict) and set(x) == {"task", "output", "criterion"} for x in task["dependencies"]), "依赖须为三元组")
    for path in task["required_paths"]:
        relative(path)
    require(task["parent"] is None or task["parent"] in state["tasks"], "父业务项不存在")
    if "contract" in payload:
        from 协作升级 import task_spec
        task["contract"] = {**task_spec(state, payload["contract"]), "open": False}
    state["tasks"][task_id] = task
    no_cycles(state)
    proposal.update(status="registered", task_id=task_id)
    for item in state["items"].values():
        if item["holder"] == proposal["proposal_id"] and item["status"] == "unresolved":
            item["history"].append({"from": item["holder"], "to": task_id, "reason": "登记承接提议"})
            item.update(holder=task_id, disposition="task:" + task_id)
    return task


def decide(state, env, context):
    from 协作升级 import action as pilot_action, enabled as pilot_enabled, guard as pilot_guard, user_acceptance

    before = copy.deepcopy(state)
    actor, command, p = env["origin_id"], env["command"], env["payload"]
    seq = context["seq"]
    extra = {}
    require(state["migration"]["phase"] != "rolled_back", "新账本已回退关闭")
    if state["migration"]["phase"] in {"frozen", "imported", "verified"}:
        require(command in {"migration_import", "migration_map", "migration_verify", "cutover", "migration_rollback", "note", "owner_ack", "register_origin", "authority", "assign_receiver"}, "迁移切换前不受理业务命令", "retryable")
    if actor not in state["origins"]:
        require(command in {"propose", "feedback"}, "来源未登记")
        state["origins"][actor] = {"roles": ["proposer"], "local": False, "version": 0}
    origin = state["origins"][actor]
    if command in {"handoff", "takeover"}:
        require(text(p.get("intent_id")), "缺intent_id", "intent-final")
        require(p["intent_id"] not in state["intents"], "意图已终局", "intent-final")
        require(p.get("expected_generation") == state["generation"] and p.get("expected_holder") == state["coordinator"], "代次或原协调者已变", "intent-final")
    check_expects(state, env["expects"])
    if command in SCHEDULE:
        require(actor == state["coordinator"], "仅现任协调者可以调度", "intent-final")
        require(env["expects"].get("generation") == state["generation"], "调度须带当前代次", "retryable")
    pilot_guard(state, env, context)
    c = None
    if command in HOLDER:
        c = state["claims"].get(p.get("claim_id"))
        require(c and c["L"] == "active", "领取已结束或不存在", "intent-final")
        if c["origin"] != actor:
            require(command == "release" and actor == state["coordinator"], "发起者不是持有者", "intent-final")
            require(env["expects"].get("generation") == state["generation"], "代释放须核当前代次", "retryable")
            authority(state, p)
            require(c["E"]["state"] == "stopped" and text(c.get("stop_evidence")) or
                    p.get("user_decision") == "release-unknown", "他人活动未结束；未知资源须有用户处置决定")
        if command in {"ack_scope", "acquire", "seal"}:
            require(env["expects"].get("epoch:" + c["claim_id"]) == c["epoch"], "须声明当前执行代次", "retryable")
    task = state["tasks"].get(p.get("task_id"))
    if command == "pilot":
        pilot_action(state, env, context)
    elif command in {"propose", "feedback"}:
        refs = []
        if p.get("authority_ref") and origin["local"]:
            refs = [authority(state, p)]
        add_proposal(state, env["event_id"], actor, p, refs)
    elif command == "register":
        proposal = state["proposals"].get(p.get("proposal_id"))
        require(proposal is not None, "提议不存在")
        if proposal["status"] == "registered":
            extra["reason"] = "已绑定 " + proposal["task_id"]
        else:
            require(proposal["status"] == "proposed", "提议已终结")
            if p.get("authority_ref"):
                ref = authority(state, p)
                if ref not in proposal["authorities"]:
                    proposal["authorities"].append(ref)
            new_task(state, proposal, p, seq)
    elif command in {"reject_proposal", "withdraw_proposal"}:
        proposal = state["proposals"].get(p.get("proposal_id"))
        require(proposal and proposal["status"] == "proposed", "提议已终结")
        require(actor == state["coordinator"] or command == "withdraw_proposal" and actor == proposal["origin"], "无权撤回他人提议")
        reason(p)
        if proposal["authorities"]:
            authority(state, p)
            require(p.get("user_decision") in {"withdraw", "cancel", "reject"}, "须附用户撤回/驳回依据")
        proposal.update(status="rejected" if command == "reject_proposal" else "withdrawn", reason=p["reason"])
        redirect_invalid(state, proposal["proposal_id"])
    elif command == "merge":
        source = state["proposals"].get(p.get("source")) or state["tasks"].get(p.get("source"))
        target = state["proposals"].get(p.get("target")) or state["tasks"].get(p.get("target"))
        require(source and target and p["source"] != p["target"], "合并对象不存在或自引用")
        require(actor == state["coordinator"] and env["expects"].get("generation") == state["generation"] or
                p["source"] in state["proposals"] and source["origin"] == actor, "无权合并其它来源提议或任务")
        require(source["status"] in {"proposed", "merge_pending"}, "被合并方状态不可合并")
        reason(p)
        has_items = any(i["holder"] == p["source"] and i["status"] == "unresolved" for i in state["items"].values())
        require(not source["authorities"] and not has_items or carryable(state, p["target"]), "合并目标无法承接用户要求/遗留项", "retryable")
        target["authorities"] = sorted(set(target["authorities"] + source["authorities"]))
        source.update(status="merged", replacement=p["target"], reason=p["reason"])
        redirect_invalid(state, p["source"], p["target"] if has_items else None)
    elif command == "different":
        require(task and task["status"] == "merge_pending", "任务不是待合并")
        reason(p)
        task["status"] = "available"
    elif command == "claim":
        require(task and task["status"] == "available", "任务不可领取", "retryable")
        require(env["expects"].get("task:" + task["task_id"]) == task["version"] and
                env["expects"].get("scope:" + task["task_id"]) == task["scope_version"], "领取须核任务/范围版本", "retryable")
        require("executor" in origin["roles"] or actor == state["coordinator"], "来源无执行角色")
        dependencies_ok(state, task)
        cid = p.get("claim_id", "c-" + env["event_id"])
        require(text(cid) and re.fullmatch(r"[A-Za-z0-9_-]{1,100}", cid) and cid not in state["claims"], "领取编号已使用或无效")
        holder = actor
        if p.get("external"):
            holder = "external-" + env["event_id"]
            state["origins"][holder] = {"roles": ["executor"], "local": False, "version": 0}
        c = {"claim_id": cid, "task_id": task["task_id"], "origin": holder, "requester": actor,
             "kind": task["kind"], "L": "active", "E": {"state": "running", "reason": None},
             "W": {"scope": task["scope_version"], "state": "draft", "revision": 1}, "epoch": 1,
             "version": 0, "scope_ack_pending": False, "continue": [], "R": [], "deliveries": {},
             "inputs": copy.deepcopy(task["inputs"]), "execution": copy.deepcopy(task["execution"])}
        if state["pilot"].get("format", {}).get("schema",0) >= 3:
            c["run"] = {"state": "claimed", "automation": bool(p.get("notice")), "notice": p.get("notice")}
        state["claims"][cid] = c
        requested = task["resources"] + [delivery_resource(state, c)]
        if state.get('security',{}).get('schema',0) >= 5:
            from 协作执行 import freeze_claim
            freeze_claim(state,task,actor,c,context['now'],p)
        else:
            reserve(state, c, requested, seq)
        task.update(status="running", claims=task["claims"] + [cid])
    elif command in {"pause", "cancel", "revoke", "replace_claim"}:
        reason(p)
        if command in {"pause", "cancel"}:
            ref = authority(state, p)
        if command == "cancel":
            require(task and task["status"] not in TERMINAL, "任务已经终结")
            task.update(cancel_requested=True, cancel_authority=ref)
            claims = [x for x in state["claims"].values() if x["task_id"] == task["task_id"] and x["L"] == "active"]
            for active in claims:
                stop(active, "cancel")
                finish(state, active)
            if not claims:
                task["status"] = "cancelled"
                redirect_invalid(state, task["task_id"], cancel_authority=ref)
        else:
            target = state["claims"].get(p.get("claim_id"))
            require(target and target["L"] == "active", "领取已结束")
            if command == "replace_claim":
                require(text(p.get("replacement")), "替代须写接替对象")
                target["replacement"] = p["replacement"]
            stop(target, {"pause": "pause", "revoke": "revoke", "replace_claim": "replace"}[command])
            finish(state, target)
    elif command == "stopped":
        require(c["E"]["state"] in {"running", "requested"}, "已停止；后续可单独释放占用")
        require(text(p.get("evidence")), "停止报告须有实际结束依据")
        c["E"] = {"state": "stopped", "reason": c["E"].get("reason") or "complete"}
        c["stop_evidence"] = p["evidence"]
        c["outputs"] = p.get("outputs", [])
        for ended in p.get("ended", []):
            rid, proof = ended["reservation_id"], ended["evidence"]
            require(rid in c["R"] and text(proof), "结束项不属于领取或缺少依据")
            if c["E"]["reason"] == "complete" and c["W"]["state"] == "draft":
                state["reservations"][rid].update(ended_evidence=proof, pending_seal=True)
            else:
                release_one(state, c, rid, proof)
        finish(state, c)
    elif command == "release":
        release_one(state, c, p.get("reservation_id"), p.get("evidence"))
        finish(state, c)
    elif command in {"acquire", "resume"}:
        if command == "resume":
            c = state["claims"].get(p.get("claim_id"))
            require(c and c["L"] == "active" and c["E"] == {"state": "stopped", "reason": "pause"}, "不是可恢复的暂停领取")
            authority(state, p)
        else:
            require(c["W"]["state"] in {"draft", "revision"} and (c["E"]["state"] == "running" or
                    c["E"] == {"state": "stopped", "reason": "complete"}), "当前工作不可申请资源")
        require(not c["scope_ack_pending"] and not state["tasks"][c["task_id"]].get("cancel_requested"), "范围未确认或取消已请求")
        baseline = p.get("baseline")
        require(isinstance(baseline, dict) and baseline and all(SHA.fullmatch(v) for v in baseline.values()), "须附本轮基线SHA")
        task = state["tasks"][c["task_id"]]
        requested = [resource(r) for r in p.get("resources", task["resources"])]
        maximum = expanded(state, task["resources"])
        require(all(any(grants(state, allowed["id"], wanted["id"]) and
                        (wanted["mode"] == "read" or allowed["mode"] != "read") for allowed in maximum) for wanted in requested),
                "申请资源不能超出已授权任务范围；先由协调者改范围")
        if state.get('security',{}).get('schema',0)<5:
            reserve(state, c, requested + [delivery_resource(state, c)], seq)
        c.update(E={"state": "running", "reason": None}, epoch=c["epoch"] + 1, baseline=baseline)
        if state["pilot"].get("format", {}).get("schema",0) >= 3:
            c["run"] = {"state": "claimed", "automation": False, "notice": None}
        c["W"]["state"] = "draft"
        c["W"]["revision"] = len(c["deliveries"]) + 1
        if state.get('security',{}).get('schema',0)>=5:
            from 协作执行 import open_resume_segment
            open_resume_segment(state,task,p['_audit']['actor'],c,context['now'],env['event_id'],p)
    elif command == "scope":
        require(task and task["status"] in {"available", "running"}, "任务不可改范围")
        authority(state, p)
        reason(p)
        require(isinstance(p.get("completes_on"), list) and p["completes_on"] and all(text(x) for x in p["completes_on"]), "须写新完成判据")
        removed = set(task["completes_on"]) - set(p["completes_on"])
        task["scope_version"] += 1
        task["completes_on"] = p["completes_on"]
        if p.get("user_acceptance") is True:
            task["user_acceptance"] = {"authority_ref": p["authority_ref"], "scope_version": task["scope_version"]}
            task["receiver"] = actor
        if "resources" in p:
            task["resources"] = [resource(r) for r in p["resources"]]
        for item in list(state["items"].values()):
            if item["source_task"] == task["task_id"] and item["required"] and item["criterion"] in removed and item["status"] == "unresolved":
                require(item["item_id"] in p.get("removed_items", {}), "移出必做判据须同决定安排去向")
                item["required"] = False
                disposition(state, item, p["removed_items"][item["item_id"]], actor, env, True, True)
        for active in state["claims"].values():
            if active["task_id"] == task["task_id"] and active["L"] == "active":
                active["epoch"] += 1
                active["W"] = {"scope": task["scope_version"], "state": "draft", "revision": len(active["deliveries"]) + 1}
                active.update(scope_ack_pending=True, **{"continue": [resource({"id": x, "mode": "write"})["id"] for x in p.get("continue", [])]})
    elif command == "ack_scope":
        require(c["scope_ack_pending"] and env["expects"].get("scope:" + c["task_id"]) == c["W"]["scope"], "须确认新范围/代次")
        c["scope_ack_pending"] = False
    elif command == "seal":
        task = state["tasks"][c["task_id"]]
        require(c["W"]["state"] == "draft" and (c["E"]["state"] == "running" or c["E"] == {"state": "stopped", "reason": "complete"}) and
                not c["scope_ack_pending"] and c["W"]["scope"] == task["scope_version"], "当前执行/范围不能封存", "retryable")
        require(p.get("scope_version") == c["W"]["scope"], "旧范围产出仅留证据", "retryable")
        rev = "revision-" + str(len(c["deliveries"]) + 1)
        require(p.get("revision") == rev and SHA.fullmatch(p.get("manifest_sha256", "")), "修订号必须递增且有manifest SHA")
        require(p.get("inputs") == c["inputs"], "交付输入与领取不一致")
        flags = p.get("execution", {})
        require(set(flags) == FLAGS and all(type(v) is bool and (not v or c["execution"][k]) for k, v in flags.items()), "执行标记缺失或越过冻结权限")
        require(p["manifest_sha256"] in context.get("verified_manifests", set()), "封存须核实manifest及负载")
        record_id = c["claim_id"] + "/" + rev
        item_ids = add_items(state, p.get("remaining", []), c["task_id"], record_id, actor, env)
        c["deliveries"][rev] = {"revision": rev, "scope_version": c["W"]["scope"], "manifest_sha256": p["manifest_sha256"],
                                 "manifest": p.get("manifest"),
                                 "flow_record_ids": context.get("included_flow_records", []),
                                 "repository_outputs": context.get("repository_outputs", {}),
                                 "payload_status": context.get("payload_status", "verified"),
                                 "seal_seq": seq, "status": "review", "remaining": item_ids, "execution": flags,
                                 "criteria": list(task["completes_on"]),
                                 "claimed_resolved": p.get("claimed_resolved", [])}
        c["W"].update(state="review", revision=rev)
        for rid in list(c["R"]):
            r = state["reservations"][rid]
            if r["pending_seal"]:
                release_one(state, c, rid, r["ended_evidence"])
        finish(state, c)
    elif command == "withdraw_delivery":
        rev = c["deliveries"].get(p.get("revision"))
        require(rev and rev["status"] == "review", "交付不是待审")
        reason(p)
        rev.update(status="withdrawn", reason=p["reason"])
        if c["W"]["state"] == "review" and c["W"]["revision"] == p["revision"]:
            c["W"]["state"] = "revision"
    elif command == "review":
        c = state["claims"].get(p.get("claim_id"))
        require(c is not None, "领取不存在")
        task = state["tasks"][c["task_id"]]
        direct = task.get("user_acceptance", {})
        user_accepted = user_acceptance(state, task, actor) or (actor == state["coordinator"] and direct.get("scope_version") == task["scope_version"] == c["deliveries"].get(p.get("revision"), {}).get("scope_version") and
                         direct.get("authority_ref") in state["authorities"] and p.get("user_acceptance_authority") == direct.get("authority_ref"))
        require(actor == task["receiver"] and (actor != c["origin"] or user_accepted), "须由指定独立接收者或本范围用户明确授权接收")
        require(not (c["L"] == "ended" and c["E"].get("reason") in {"cancel", "revoke", "replace"}), "终止领取的待审产出仅留证据")
        rev = c["deliveries"].get(p.get("revision"))
        require(rev and rev["status"] == "review" and p.get("manifest_sha256") == rev["manifest_sha256"], "修订待审态或manifest不匹配")
        require(rev["manifest_sha256"] in context.get("verified_manifests", set()), "验收须复核原manifest及负载")
        verdict = p.get("verdict")
        require(verdict in {"received", "pending", "accept", "revision", "reject"}, "未知验收结论")
        checks = p.get("checks", [])
        require(isinstance(checks, list) and all(isinstance(x, dict) and text(x.get("id")) and
                x.get("status") in {"passed", "failed", "not-run"} and x.get("level") in {"static", "offline", "GUI", "app", "release"} for x in checks), "验收分项须声明状态与层级")
        require(len({x["id"] for x in checks}) == len(checks), "验收检查项不能重名")
        for check in checks:
            require(check.get("status") != "passed" or check.get("evidence") or check.get("reuse"), "通过项须有证据或已通过分项引用")
            if check.get("reuse"):
                ref, key = check["reuse"].split("/", 1)
                prior = state["acceptances"].get(ref)
                require(prior and prior["task_id"] == c["task_id"] and prior["scope_version"] == rev["scope_version"] and
                        any(x["id"] == key and x["status"] == "passed" for x in prior["checks"]), "复用项不存在/范围不符/未通过")
        for redirect in p.get("redirect", []):
            item = state["items"].get(redirect.get("item_id"))
            require(item and item["source_record"] == c["claim_id"] + "/" + p["revision"], "接收者只能改本交付遗留项去向")
            require(env["expects"].get("item:" + item["item_id"]) == item["version"], "须核遗留项版本", "retryable")
            if "required" in redirect:
                require(type(redirect["required"]) is bool, "必做标记须为布尔值")
                item["required"] = redirect["required"]
                if item["required"]:
                    require(redirect.get("criterion") in task["completes_on"], "须绑定完成判据")
                    item["criterion"] = redirect["criterion"]
            item["evidence"] = redirect.get("evidence")
            disposition(state, item, redirect["disposition"], actor, env)
        aid = env["event_id"]
        require(all(state["items"][iid]["disposition"] != "pending" for iid in rev["remaining"]), "旧交付遗留项须先逐项确定去向")
        passed_ids = {x["id"] for x in checks if x["status"] == "passed"}
        for resolution in p.get("resolve", []):
            item = state["items"].get(resolution.get("item_id"))
            require(item and item["holder"] == c["task_id"] and item["status"] == "unresolved" and
                    env["expects"].get("item:" + item["item_id"]) == item["version"], "待解项归属或版本不符", "retryable")
            require(resolution.get("check_id") in passed_ids, "解决项须引用本次真实通过分项")
            item["history"].append({"from": item["holder"], "to": None, "reason": "验收证实解决", "acceptance_id": aid})
            item.update(status="resolved", holder=None, evidence=aid + "/" + resolution["check_id"])
        new_items = list(p.get("remaining", []))
        failed = {x["id"] for x in checks if x["status"] in {"failed", "not-run"}}
        require(all(any(x.get("check_id") == key for x in new_items) for key in failed), "失败/未运行检查须逐项登记去向")
        for check in checks:
            if check["id"] in failed:
                corresponding = [x for x in new_items if x.get("check_id") == check["id"]]
                require(all(x.get("kind") == check["status"] for x in corresponding), "失败/未运行项类型须如实登记")
                if check["id"] in rev["criteria"]:
                    require(all(x.get("required") is True and x.get("criterion") == check["id"] for x in corresponding), "完成判据失败须标为必做项")
        add_items(state, new_items, c["task_id"], aid, actor, env)
        current = c["W"]["state"] == "review" and c["W"]["revision"] == p["revision"] and c["W"]["scope"] == rev["scope_version"]
        if verdict == "accept":
            expected_criteria = rev["criteria"]
            require(not (failed & set(expected_criteria)), "完成判据失败/未运行，不能接受")
            require(expected_criteria and set(expected_criteria) <= passed_ids, "完成判据未逐项通过")
            require(not current or not unresolved(state, c["task_id"]), "名下仍有未解决项，应需修订后继续")
            require(not task["requires_commit"] or set(task["required_paths"]) <= set(rev.get("repository_outputs", {})), "需要提交的路径未绑定已接受产物映射")
        state["acceptances"][aid] = {"acceptance_id": aid, "task_id": c["task_id"], "claim_id": c["claim_id"],
                                     "scope_version": rev["scope_version"], "inputs": c["inputs"],
                                     "revision": p["revision"], "manifest_sha256": rev["manifest_sha256"],
                                     "manifest": rev.get("manifest"), "repository_outputs": rev.get("repository_outputs", {}),
                                     "verdict": verdict, "checks": checks, "origin": actor, "seq": seq,
                                     "tested_artifacts": p.get("tested_artifacts", [])}
        if user_accepted:
            state["acceptances"][aid]["user_acceptance_authority"] = direct.get("authority_ref") or task["contract"]["user_basis"]
        rev["payload_status"] = "verified"
        if verdict not in {"received", "pending"}:
            rev.update(status={"accept": "accepted", "revision": "revision", "reject": "rejected"}[verdict], acceptance_id=aid)
            if current:
                c["W"]["state"] = {"accept": "complete", "revision": "revision", "reject": "terminated"}[verdict]
                if verdict == "reject":
                    stop(c, "reject")
                if verdict == "accept":
                    task["accepted"] = aid
                    task["provided"] = p.get("provided", {"delivery": list(passed_ids)})
                finish(state, c)
    elif command == "redirect":
        item = state["items"].get(p.get("item_id"))
        require(item and item["status"] == "unresolved", "遗留项已经解决/关闭")
        require(env["expects"].get("item:" + item["item_id"]) == item["version"], "须核遗留项版本", "retryable")
        reason(p)
        item["evidence"] = p.get("evidence")
        disposition(state, item, p.get("disposition"), actor, env, True)
    elif command == "dependencies":
        require(task and task["status"] not in TERMINAL, "任务不可调整依赖")
        reason(p)
        require(isinstance(p.get("dependencies"), list) and all(isinstance(d, dict) and set(d) == {"task", "output", "criterion"} for d in p["dependencies"]), "依赖须为三元组")
        task["dependencies"] = p["dependencies"]
        no_cycles(state)
    elif command == "register_origin":
        authority(state, p)
        oid, roles = p.get("origin_id"), p.get("roles")
        require(isinstance(oid, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", oid) and isinstance(roles, list) and
                roles and set(roles) <= {"proposer", "executor", "receiver", "integrator", "coordinator"} and type(p.get("local")) is bool,
                "来源角色/本地身份格式错误")
        state["origins"][oid] = {"roles": roles, "local": p["local"], "version": state["origins"].get(oid, {}).get("version", 0)}
        if pilot_enabled(state) and p.get("person_signup"):
            state["pilot"]["identity:" + oid] = {"kind": "human", "owner": oid, "status": "active", "credential": 1}
    elif command == "board_layout":
        authority(state, p)
        require(context.get("board_layout_verified") is True, "须核原看板快照和新目标")
        c = state["claims"].get(p.get("claim_id"))
        require(c and c["origin"] == actor and env["expects"].get("epoch:" + c["claim_id"]) == c["epoch"], "须核持有者与执行代次")
        migration = state["migration"]
        require(p.get("expected_board_path") == migration.get("board_path"), "看板路径依据过期", "retryable")
        for path in (p["expected_board_path"], p["board_path"], p["detail_path"]):
            require(writable(state, c["claim_id"], actor, c["epoch"], c["W"]["scope"], "path:" + path), "缺少看板路径资源")
        migration.update(legacy_source_path=migration.get("legacy_source_path", migration["board_path"]),
                         board_aliases=list(dict.fromkeys(migration.get("board_aliases", []) + [migration["board_path"]])),
                         board_path=p["board_path"], detail_path=p["detail_path"], board_layout="compact-v1", previous_board=p["previous_board"])
    elif command == "assign_receiver":
        require(task and task["status"] not in TERMINAL, "任务已终结")
        receiver = p.get("receiver")
        require(receiver in state["origins"] and "receiver" in state["origins"][receiver]["roles"], "须为已登记的接收者")
        require(all(state["claims"][cid]["origin"] != receiver for cid in task["claims"]), "持有者不能验收自己的领取")
        reason(p)
        task["receiver"] = receiver
    elif command == "authority":
        require(text(p.get("authority_id")) and text(p.get("reference")), "授权须有编号与用户指令位置")
        require(p["authority_id"] not in state["authorities"], "授权不可覆盖")
        state["authorities"][p["authority_id"]] = p["reference"]
    elif command == "standing":
        authority(state, p)
        require(isinstance(p.get("origins"), list) and all(state["origins"].get(x, {}).get("local") for x in p["origins"]), "D2名单只允许已登记本地窗口")
        state["standing"][p["authority_ref"]] = p["origins"]
    elif command == "coverage":
        authority(state, p)
        require(not any(r["active"] for r in state["reservations"].values()), "活动占用期间不能重定义覆盖关系", "retryable")
        root = resource({"id": p.get("resource"), "mode": "read"})["id"]
        state["coverage"][root] = [resource(r) for r in p.get("covers", [])]
        visiting, visited = set(), set()
        def visit(resource_id):
            require(resource_id not in visiting, "覆盖表成环")
            if resource_id in visited:
                return
            visiting.add(resource_id)
            for child in state["coverage"].get(resource_id, []):
                visit(child["id"])
            visiting.remove(resource_id)
            visited.add(resource_id)
        for resource_id in state["coverage"]:
            visit(resource_id)
    elif command == "contact":
        require(p.get("origin_id") in state["origins"] and text(p.get("evidence")), "联系待核须有对象和依据")
        state["contacts"][p["origin_id"]] = {"seq": seq, "generation": state["generation"], "evidence": p["evidence"]}
    elif command in {"handoff", "takeover"}:
        target = p.get("target", actor)
        require(state["origins"].get(target, {}).get("local"), "接任者必须是已登记本地窗口", "intent-final")
        require(type(p.get("snapshot_at")) is int and 0 <= p["snapshot_at"] < seq and isinstance(p.get("inflight"), list), "须附账本位置与在途清单", "intent-final")
        if command == "handoff":
            require(actor == state["coordinator"], "只有现任可以主动移交", "intent-final")
        else:
            old = state["coordinator"]
            contact = state["contacts"].get(old)
            fresh = contact and contact["generation"] == state["generation"] and context["control"]["last_applied"].get(old, 0) < contact["seq"]
            granted = actor in state["standing"].get(p.get("authority_ref"), [])
            require(granted and (fresh or p.get("user_instruction") in state["authorities"]), "不在D2名单或缺少当前持有者失联事实", "intent-final")
            require(target == actor, "接管者须自己承接", "intent-final")
        state["coordinator"] = target
        state["generation"] += 1
        state["intents"][p["intent_id"]] = {"result": "applied", "generation": state["generation"], "origin": actor}
    elif command == "gap_close":
        reason(p)
        require(p.get("origin_id") in state["origins"] and type(p.get("a")) is int and type(p.get("b")) is int and 0 < p["a"] <= p["b"], "缺口区间格式错误")
        known = [r["envelope"]["origin_seq"] for variants in context["inbox"].values()
                 for r in variants.values() if r["envelope"]["origin_id"] == p["origin_id"]]
        finalized = {r["origin_seq"] for r in context["control"]["terminal"].values() if r["origin_id"] == p["origin_id"]}
        require(known and p["b"] <= max(known) and len({n for n in finalized if p["a"] <= n <= p["b"]}) < p["b"] - p["a"] + 1, "缺口不存在")
        extra["closed"] = [{"origin_id": p["origin_id"], "a": p["a"], "b": p["b"]}]
    elif command == "resolve_conflict":
        reason(p)
        if "origin_seq" in p:
            origin, sequence = p.get("origin_id"), p.get("origin_seq")
            require(origin in state["origins"] and type(sequence) is int and sequence > 0, "来源序号格式错误")
            matching = {key: variants for key, variants in context["inbox"].items()
                        if any(r["envelope"]["origin_id"] == origin and r["envelope"]["origin_seq"] == sequence for r in variants.values())}
            require(len(matching) > 1 and p.get("key") in matching and p.get("sha256") in matching[p["key"]], "来源序号没有待裁冲突或所选事件不存在")
            chosen_envelope = matching[p["key"]][p["sha256"]]["envelope"]
            require(chosen_envelope["origin_id"] == origin and chosen_envelope["origin_seq"] == sequence, "所选内容不属于被裁定序号")
            require(not any(e["origin_id"] == origin and e["origin_seq"] == sequence for e in context["control"]["terminal"].values()), "来源序号已有终局，不追溯改写")
            require((origin, sequence) not in context["control"]["sequence_selected"], "该序号已裁定")
            extra["sequence_resolutions"] = [{"origin_id": origin, "origin_seq": sequence, "key": p["key"], "sha256": p["sha256"]}]
        else:
            variants = context["inbox"].get(p.get("key"), {})
            require(len(variants) > 1 and p.get("sha256") in variants and p["key"] not in context["control"]["terminal"], "无待裁冲突或所选内容不存在")
            extra["resolutions"] = [{"key": p["key"], "sha256": p["sha256"]}]
    elif command == "note":
        require(text(p.get("text")), "备注不能为空")
        state["notes"][env["event_id"]] = {"origin": actor, "text": p["text"], "related": p.get("related"), "seq": seq}
    elif command == "owner_ack":
        require(c.get("owner_ack_pending"), "没有待回执迁移领取")
        require(text(p.get("evidence")), "持有者回执须有依据")
        c.update(owner_ack_pending=False, owner_ack_evidence=p["evidence"])
    elif command == "commit_record":
        require(task and (task["status"] == "pending_commit" or p.get("pending_verification") is True), "不是待提交或获授权的待验节点")
        if p.get("pending_verification"):
            authority(state, p)
        require(context.get("git_verified") is True, "须逐路径核对Git blob与SHA")
        state["commits"][env["event_id"]] = {"task_id": task["task_id"], "commit": p["commit"], "paths": p["paths"],
                                             "pending_verification": p.get("pending_verification", False),
                                             "acceptance_id": context.get("accepted_commit_id"), "scope_version": task["scope_version"]}
        covered = committed_paths(state, task)
        if set(task["required_paths"]) <= covered and not p.get("pending_verification"):
            task["status"] = "pending_close"
    elif command == "close":
        require(task and task["status"] in {"pending_close", "pending_commit"}, "任务尚未满足收口条件", "retryable")
        require(all(state["claims"][cid]["L"] == "ended" for cid in task["claims"]), "领取尚未全部结束", "retryable")
        require(task.get("accepted") in state["acceptances"], "缺少当前范围接受记录")
        require(state["acceptances"][task["accepted"]]["scope_version"] == task["scope_version"], "旧范围接受不能完成新范围")
        if task["requires_commit"]:
            covered = committed_paths(state, task)
            require(set(task["required_paths"]) <= covered and task["status"] != "pending_commit", "所需路径尚未提交", "retryable")
        add_items(state, p.get("remaining", []), task["task_id"], env["event_id"], actor, env, True)
        require(not unresolved(state, task["task_id"]), "任务名下有未解决项，不能收口", "retryable")
        prepared = context.get("close_prepared")
        require(prepared is not None, "收口摘要未准备")
        state["closings"][env["event_id"]] = {"close_id": env["event_id"], "task_id": task["task_id"],
                                               "verdict": "complete" if not prepared["missing"] else "missing",
                                               "summary": prepared["summary"], "missing": prepared["missing"], "proven": p.get("proven", [])}
        state["closings"][env["event_id"]].update(acceptance_id=prepared["acceptance_id"], accepted_manifest=prepared["accepted_manifest"])
        task["status"] = "closed_missing" if prepared["missing"] else ("closed_candidate" if task["kind"] == "candidate" else "completed")
        task["close_id"] = env["event_id"]
        parent = state["tasks"].get(task.get("parent"))
        if parent and task["kind"] == "candidate":
            parent["status"] = "pending_integration"
    elif command == "correction":
        require(actor == state["coordinator"] or "receiver" in origin["roles"], "仅接收者/协调者能更正结论")
        record = state["acceptances"].get(p.get("target")) or state["closings"].get(p.get("target"))
        require(record is not None, "被更正记录不存在")
        task = state["tasks"][record["task_id"]]
        require(actor == state["coordinator"] or actor == task["receiver"], "不是原指定接收者")
        reason(p)
        if p.get("erratum"):
            require(p.get("references_before") == p.get("references_after") and p.get("same_meaning") is True, "对象或语义改变/无法判断时必须需修订")
        add_items(state, p.get("remaining", []), task["task_id"], env["event_id"], actor, env, actor == state["coordinator"])
        state["corrections"][env["event_id"]] = {"target": p["target"], "task_id": task["task_id"], "verdict": p.get("verdict"), "reason": p["reason"], "erratum": p.get("erratum", False)}
        if task["status"] == "closed_missing" and p.get("verdict") == "complete":
            require(p.get("target") == task.get("close_id"), "缺证恢复须更正对应收口记录")
            old_missing = {encoded(x["reference"]) for x in record["missing"]}
            supplied = {encoded(x) for x in p.get("evidence", [])}
            require(old_missing <= supplied, "须逐项找回并复核原缺失证据")
            require(context.get("close_prepared") is not None and not context["close_prepared"]["missing"], "新证据仍缺失")
            task["status"] = "completed"
            state["corrections"][env["event_id"]]["summary"] = context["close_prepared"]["summary"]
    elif command == "repair":
        require(task and task["status"] in TERMINAL, "只对已收口任务登记返修")
        correction = state["corrections"].get(p.get("correction_id"))
        require(correction and correction["task_id"] == task["task_id"] and correction["verdict"] == "revision", "须先更正结论指出需修订")
        pid = env["event_id"]
        add_proposal(state, pid, actor, {"title": p.get("title"), "related": task["task_id"]}, task["authorities"])
        p = {**p, "kind": "repair", "parent": task.get("parent")}
        new_task(state, state["proposals"][pid], p, seq, {"task": task["task_id"], "correction": env["payload"]["correction_id"]})
    elif command in {"migration_import", "migration_map", "migration_verify", "cutover", "migration_rollback"}:
        from 协作迁移 import migration_decision
        migration_decision(state, env, context)
    elif command.startswith("flow_"):
        from 协作流水规则 import flow_decision
        flow_decision(state, env, context)
    else:
        raise Rejected("未知命令：" + command)
    if state["migration"]["phase"] == "active" and command not in {"note", "owner_ack", "cutover"} and state != before:
        state["migration"]["business_changed"] = True
    if state.get("flow_config", {}).get("phase") == "active" and command in {"seal", "review", "withdraw_delivery", "commit_record", "correction"}:
        from 协作流水规则 import runtime_stamp
        if state != before or runtime_stamp(state) != runtime_stamp(before):
            state["flow_config"]["last_seq"] = seq
    for table in ("tasks", "claims", "items", "proposals", "origins", "reservations"):
        for key, record in state[table].items():
            old = before[table].get(key)
            if old != record:
                record["version"] = (old or {}).get("version", 0) + 1
    return state, extra
