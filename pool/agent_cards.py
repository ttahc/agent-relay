"""Windows described in the vocabulary of A2A v1.0, so other agent tooling can read who takes part.

This is an export, not an implementation of A2A: the windows do not serve the A2A protocol, so each
card lists no interface to call. Work still reaches a window only through this service's tasks.
Skills are the window's current capability records at the probed or verified evidence level, which
an administrator or an independent probe confirmed; declared skills are left out, because an A2A
skill reads as a promise and a declaration proves nothing.

The second half maps this service's task stages to the A2A task states, for tools that speak both.
"""
import time

A2A_VERSION = "1.0"
CONFIRMED = {"probed", "verified"}

# Task stage (as GET /v1/tasks/<id> and the workbench name it) -> A2A TaskState.
TASK_STATES = {
    "waiting": "TASK_STATE_SUBMITTED",
    "available": "TASK_STATE_SUBMITTED",
    "claimed": "TASK_STATE_WORKING",
    "running": "TASK_STATE_WORKING",
    "handoff_pending": "TASK_STATE_WORKING",
    "review": "TASK_STATE_INPUT_REQUIRED",
    "revision": "TASK_STATE_WORKING",
    "paused": "TASK_STATE_INPUT_REQUIRED",
    "recovery": "TASK_STATE_INPUT_REQUIRED",
    "cancel_pending": "TASK_STATE_WORKING",
    "accepted": "TASK_STATE_WORKING",
    "pending_close": "TASK_STATE_WORKING",
    "completed": "TASK_STATE_COMPLETED",
    "closed_missing": "TASK_STATE_COMPLETED",
    "cancelled": "TASK_STATE_CANCELED",
    "replaced": "TASK_STATE_CANCELED",
    "merged": "TASK_STATE_CANCELED",
}
NOTES = {
    "review": "等待接收者验收：A2A 中最接近“需要输入”",
    "accepted": "已验收但执行尚未确认停止，本服务仍视为进行中",
    "pending_close": "已验收、待收口归档，本服务仍视为进行中",
    "cancel_pending": "已请求取消、待确认停止；停止前不算 CANCELED",
    "closed_missing": "已收口但证据缺失；A2A 没有对应状态",
}


def skills(records, now):
    rows = []
    for record in sorted(records, key=lambda row: (row.get("project_id", ""), row.get("id", ""))):
        if record.get("level") not in CONFIRMED or (record.get("expires") or 0) <= now:
            continue
        rows.append({"id": f'{record["project_id"]}:{record["id"]}', "name": record["id"],
                     "description": f'{record["id"]} = {record.get("value")}（证据等级 {record["level"]}）',
                     "tags": [record["project_id"], record["level"]]})
    return rows


def card(source, now):
    name = source["executor_id"]
    label = source.get("window_name") or source.get("window") or name
    return {
        "name": label,
        "description": f'Agent Relay 中登记的 AI 窗口，平台 {source.get("platform") or "未登记"}。只能通过本服务的任务派发工作。',
        "provider": {"organization": source.get("platform") or "unknown", "url": ""},
        "version": str(source.get("credential") or source.get("version") or 1),
        "capabilities": {"streaming": False, "pushNotifications": False, "extendedAgentCard": False},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json", "application/zip"],
        "skills": skills(source.get("capabilities") or [], now),
        "supportedInterfaces": [],
        "x-agent-relay": {"executor_id": name, "window": source.get("window"), "owner": source.get("owner"),
                          "status": source.get("status"), "contact": source.get("contact")},
    }


def view(sources, now=None):
    now = time.time() if now is None else now
    return {"a2a_version": A2A_VERSION,
            "cards": [card(source, now) for source in sources if source.get("status") != "archived"],
            "task_states": [{"stage": stage, "a2a_state": state, **({"note": NOTES[stage]} if stage in NOTES else {})}
                            for stage, state in TASK_STATES.items()]}
