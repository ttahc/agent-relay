"""Project decisions, task relationships and improvement evidence."""
from 协作命令 import TERMINAL, no_cycles
from 协作升级 import (active, active_claims, contract, manager, project_record, require, roles,
                  stop_if_running, system_admin, task_project)


def tasks_at(state, project, versions):
    tasks = {}
    for tid, version in versions.items():
        task = state["tasks"].get(tid)
        require(task and task_project(task) == project and task["version"] == version, "关联任务不在项目内或版本已变化")
        tasks[tid] = task
    return tasks


def decision(state, p, actor, now, event_id):
    data = state["round"]
    project = p["project_id"]
    key = "decision:" + p["id"]
    old = data.get(key, {})
    require(old.get("version", 0) == p["version"] and old.get("project_id", project) == project and
            old.get("status") not in {"superseded", "withdrawn"}, "决定版本或状态已变化")
    if old:
        require(old["area"] == p["area"] and old["scope"] == p["scope"], "同一决定的事项和范围须保持稳定")
    held = set(old.get("held", []))
    checked = tasks_at(state, project, p["tasks"])
    require(held <= checked.keys(), "须核对原受影响任务版本")
    if p["status"] == "effective":
        matches = [d for key, d in data.items() if key.startswith("decision:") and d["id"] != p["id"]
                   and (d["project_id"], d["area"], d["scope"], d["status"]) == (project, p["area"], p["scope"], "effective")]
        if matches:
            require(len(matches) == 1 and matches[0]["id"] == p["replaces"] and matches[0]["version"] == p["replaces_version"],
                    "存在相同事项及范围的有效决定，须明确替代")
            matches[0].update(status="superseded", superseded_by=p["id"], version=matches[0]["version"] + 1)
        else:
            require(not p["replaces"], "替代项不是同范围的有效决定")
    else:
        require(not p["replaces"], "只有生效决定可以替代历史决定")
    next_held = checked.keys() if p["status"] == "proposed" else set()
    for tid, task in checked.items():
        holds = set(task.get("decision_holds", []))
        if tid in next_held:
            require(task["status"] not in TERMINAL, "只对尚未终结的受影响任务暂缓")
            holds.add(p["id"])
            for claim in active_claims(state, tid):
                stop_if_running(claim, "项目决定待核")
        else:
            holds.discard(p["id"])
        task["decision_holds"] = sorted(holds)
    data[key] = {k: v for k, v in p.items() if k not in {"_audit", "tasks", "op"}}
    data[key].update(version=p["version"] + 1, held=sorted(next_held), by=actor, at=now, event=event_id)


def relation(state, p, actor, now, event_id):
    tasks = tasks_at(state, p["project_id"], p["versions"])
    require(p["source"] != p["target"] and set(tasks) == {p["source"], p["target"]}, "关系须核对两个不同任务")
    source = tasks[p["source"]]
    key = "relation:" + p["id"]
    data = state["round"]
    require(not any(k.startswith("relation:") and r["project_id"] == p["project_id"] and
                    (r["source"], r["target"], r["kind"]) == (p["source"], p["target"], p["kind"])
                    for k, r in data.items()), "关系已存在")
    require(not source.get("change_pending"), "任务关系变更待确认")
    if p["kind"] == "depends":
        require(source["status"] == "available" and not active_claims(state, source["task_id"]), "依赖变更须先结束活动领取")
        require(len(source["dependencies"]) < 30, "前置条件已达上限")
        source["dependencies"].append({"task": p["target"], "output": p["output"], "criterion": p["criterion"]})
        no_cycles(state)
        source["scope_version"] += 1
        source["contract"].update(open=False, hold_reason="前置条件已变更")
    source["round_relations"] = source.get("round_relations", []) + [p["id"]]
    data[key] = {**{k: p[k] for k in ("id", "project_id", "source", "target", "kind", "reason", "output", "criterion")},
                 "by": actor, "at": now, "event": event_id}


def change(state, p, actor, now, event_id):
    data = state["round"]
    key = "change:" + p["id"]
    project = p["project_id"]
    tasks = tasks_at(state, project, p["versions"])
    if p["op"] == "change-open":
        sources, targets = set(p["sources"]), set(p["targets"])
        require(key not in data and sources and targets and not sources & targets and set(tasks) == sources | targets,
                "拆合范围与版本清单不一致")
        require(len(sources) == 1 and len(targets) >= 2 if p["kind"] == "split" else len(targets) == 1,
                "拆分须有一个来源和多个子任务，合并须有一个承接任务")
        originals = {(tid, criterion) for tid in sources for criterion in tasks[tid]["completes_on"]}
        mapping = {(row["source"], row["criterion"]) for row in p["mapping"]}
        require(originals == mapping and all(row["target"] in targets and
                row["target_criterion"] in tasks[row["target"]]["completes_on"] for row in p["mapping"]),
                "须逐项承接全部原判据并核对目标判据")
        require(set(row["target"] for row in p["mapping"]) == targets, "每个承接任务须对应实际要求")
        require(all(t["status"] in {"available", "running"} and not t.get("accepted") and not t.get("cancel_requested")
                    and not t.get("change_pending") and not t.get("decision_holds") for t in tasks.values()),
                "任务已有验收、取消、其他变更或待核决定")
        require(all(c["W"]["state"] in {"draft", "revision"} for tid in tasks for c in active_claims(state, tid)),
                "须先处理已封存修订")
        data[key] = {k: p[k] for k in ("id", "kind", "project_id", "sources", "targets", "mapping", "reason", "benefit", "cost", "risk", "rollback")}
        data[key].update(status="pending", by=actor, at=now, event=event_id, prior={
            tid: {"scope": task["scope_version"], "contract": dict(contract(task)), "inputs": task["inputs"],
                  "criteria": task["completes_on"], "claims": task["claims"]}
            for tid, task in tasks.items()
        })
        for tid, task in tasks.items():
            task["change_pending"] = p["id"]
            for claim in active_claims(state, tid):
                stop_if_running(claim, "任务拆合待确认")
        return
    record = data.get(key)
    require(record and record["project_id"] == project and record["status"] == "pending" and
            tasks.keys() == record["prior"].keys() and all(t.get("change_pending") == p["id"] for t in tasks.values()),
            "拆合记录、范围或状态已变化")
    if p["outcome"] == "apply":
        require(all(t["status"] == "available" and not active_claims(state, tid) and
                    t["scope_version"] == record["prior"][tid]["scope"] for tid, t in tasks.items()),
                "须核对实际停止、释放、旧范围及全部活动领取")
        require(all(row["target_criterion"] in tasks[row["target"]]["completes_on"] for row in record["mapping"]),
                "目标完成判据已变化")
        for tid in record["sources"]:
            task = tasks[tid]
            task.update(status="replaced" if record["kind"] == "split" else "merged",
                        round_replacements=record["targets"])
            task["contract"].update(open=False, hold_reason=p["reason"])
        for tid in record["targets"]:
            task = tasks[tid]
            task["round_predecessors"] = sorted(set(task.get("round_predecessors", [])) | set(record["sources"]))
            task["scope_version"] += 1
            task["contract"].update(open=False, hold_reason="承接任务等待核对与发布")
        record["status"] = "applied"
    else:
        record["status"] = "aborted"
    for task in tasks.values():
        task["change_pending"] = None
    record.update(finished_by=actor, finished_at=now, finish_reason=p["reason"], finish_event=event_id)


TRANSITIONS = {
    "triage": {"evidence", "accepted", "deferred", "duplicate", "declined"},
    "evidence": {"triage", "accepted", "deferred", "duplicate", "declined"},
    "accepted": {"working", "triage", "deferred"},
    "working": {"review", "triage", "deferred"},
    "review": {"verified", "resolved", "triage", "working"},
    "verified": {"review", "triage"},
    "resolved": {"review", "triage"},
    "deferred": {"triage"},
    "duplicate": {"triage"},
    "declined": {"triage"},
}


def feedback(state, p, actor, now, event_id):
    project = p["project_id"]
    data = state["round"]
    key = "feedback:" + p["id"]
    is_manager = manager(state, project, actor)
    if p["op"] == "feedback-move":
        old = data.get(key)
        target = p["target_project_id"]
        require(old and old["project_id"] == project and old["version"] == p["version"],
                "反馈不存在、原项目或版本已变化", "intent-final")
        require(project_record(state, target) and target != project, "须选择其他有效项目")
        require(system_admin(state, actor) or is_manager and manager(state, target, actor),
                "须为系统管理员或同时管理原项目和目标项目", "intent-final")
        require(isinstance(p["reason"], str) and p["reason"].strip(), "调整项目须说明依据")
        for name in ("task_id", "linked_task"):
            require(not old.get(name) or task_project(state["tasks"].get(old[name])) == target,
                    "反馈关联任务属于原项目，须先处理关联后再调整项目")
        require(old["status"] != "duplicate" and not any(
            k.startswith("feedback:") and f["status"] == "duplicate" and f["updates"] and
            f["updates"][-1].get("duplicate") == old["id"] for k, f in data.items()),
                "反馈存在重复关联，须先解除关系后再调整项目")
        old.setdefault("project_history", []).append({"from": project, "to": target,
            "reason": p["reason"], "by": actor, "at": now, "event": event_id})
        old.update(project_id=target, version=p["version"] + 1)
        return
    require(bool(roles(state, project, actor)), "须有项目权限", "intent-final")
    if p["op"] == "feedback-save":
        require(key not in data, "反馈记录已存在")
        if p["task_id"]:
            require(task_project(state["tasks"].get(p["task_id"])) == project, "关联任务须在本项目")
        data[key] = {k: p[k] for k in ("id", "project_id", "task_id", "kind", "title", "details", "impact",
                                      "evidence", "visibility", "observed")}
        data[key].update(status="triage", version=1, author=actor, at=now, event=event_id, updates=[])
        return
    old = data.get(key)
    require(old and old["project_id"] == project and (is_manager or old["author"] == actor) and
            old["version"] == p["version"], "反馈不存在、无权调整或版本已变化", "intent-final")
    wanted = p["status"]
    require(is_manager or wanted == old["status"] and bool(p["evidence"]), "分流和关闭须由项目管理员处理")
    require(wanted == old["status"] or wanted in TRANSITIONS[old["status"]], "反馈状态不能如此变更")
    linked = p["linked_task"] or old.get("linked_task")
    task = state["tasks"].get(linked)
    if linked:
        require(task_project(task) == project, "跟踪任务须在本项目")
    if wanted in {"accepted", "working", "review", "verified", "resolved"}:
        require(task and task["completes_on"], "须关联有验收判据的任务")
    if wanted in {"review", "verified", "resolved"}:
        require(task["status"] == "completed", "关联任务尚未完成验收和收口")
    if wanted == "resolved":
        require(bool(p["evidence"]), "问题解决须有复现条件与结果证据")
        state['pilot']['format']['min_reader'] = max(state['pilot']['format'].get('min_reader', 1), 7)
    if wanted == "verified":
        require(p["metrics"] and p["evidence"] and p["lesson"] and p["limits"],
                "须有实测改善、证据、经验及适用限制")
        require(all((m["after"] <= m["before"] if m["direction"] == "lower" else m["after"] >= m["before"])
                    for m in p["metrics"]) and any(m["after"] != m["before"] for m in p["metrics"]),
                "实测未见明确改善，保留待复核或重新办理")
    if wanted == "duplicate":
        other = data.get("feedback:" + p["duplicate"])
        require(other and other is not old and other["project_id"] == project and other["status"] != "duplicate",
                "主反馈须在本项目且可继续跟踪")
        require(other["visibility"] == "project" or old["visibility"] == "restricted", "主反馈的可见范围更窄")
    if not is_manager:
        require(not p["linked_task"] and not p["duplicate"] and not p["metrics"] and not p["lesson"] and not p["limits"],
                "提交者可补充证据，处理由项目管理员办理")
    old.update(status=wanted, linked_task=linked, version=p["version"] + 1)
    old["updates"].append({**{k: p[k] for k in ("status", "reason", "evidence", "duplicate", "metrics", "lesson", "limits")},
                           "by": actor, "at": now, "event": event_id})
    if wanted == "verified":
        old["follow_up"] = "observed" if min(m["samples"] for m in p["metrics"]) >= 5 else "pending"


def action(state, p, actor, now, event_id):
    require(active(state, actor), "操作身份已失效", "intent-final")
    if p["op"] in {"feedback-save", "feedback-update", "feedback-move"}:
        return feedback(state, p, actor, now, event_id)
    require(manager(state, p["project_id"], actor), "须有项目管理授权", "intent-final")
    if p["op"] == "decision-save":
        return decision(state, p, actor, now, event_id)
    if p["op"] == "task-relation":
        return relation(state, p, actor, now, event_id)
    return change(state, p, actor, now, event_id)
