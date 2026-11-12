"""Reminders that only time can raise: a task nobody claims, a window that went silent, a claim that stopped moving.

Nothing here writes to the ledger or changes a task, a claim or a resource. A reminder is a notice to
the people who can act on it; releasing a claim or a resource still takes the existing stop, handoff
and release steps, because silence is never evidence that work has stopped.

Times come from the ledger itself (each entry's `committed_utc`) and, for heartbeats, from the
service's contact table, so the reminders need no new data and no new format.
"""
from datetime import datetime
import threading
import time

from 协作存储 import digest, encoded
import 协作升级 as rules

UNCLAIMED_SECONDS = 24 * 3600  # a published task nobody has claimed
SILENT_SECONDS = 600  # a window with heartbeats on, holding a claim, not heard from
STALLED_SECONDS = 24 * 3600  # a claim with nothing recorded on its task
KINDS = ("task-unclaimed", "claim-silent", "claim-stalled")

_lock = threading.Lock()
_cache = {}  # ledger identity -> (entries read, sha256 of the last one, {task: [open_since, last_touched]})


def _when(entry):
    try:
        return datetime.fromisoformat(entry["committed_utc"]).timestamp()
    except (KeyError, TypeError, ValueError):
        return None


def _claimable(task):
    spec = rules.contract(task)
    return bool(spec and spec.get("open") and task.get("status") == "available")


def _touch(table, entry, when):
    if when is None:
        return
    touched = set()
    request = entry.get("request") or {}
    if isinstance(request.get("task_id"), str):
        touched.add(request["task_id"])
    for effect in entry.get("effects", []):
        path, value = effect.get("path"), effect.get("value")
        if isinstance(path, list) and len(path) == 2 and path[0] in {"tasks", "claims"} and isinstance(value, dict):
            task_id = value.get("task_id")
            if isinstance(task_id, str):
                touched.add(task_id)
                if path[0] == "tasks":
                    row = table.setdefault(task_id, [None, None])
                    if _claimable(value) and row[0] is None:
                        row[0] = when
                    elif not _claimable(value):
                        row[0] = None
    for task_id in touched:
        table.setdefault(task_id, [None, None])[1] = when


def times(entries):
    """{task_id: (claimable since, last recorded change)} in Unix seconds, read once per new ledger entry."""
    entries = entries or []
    if not entries:
        return {}
    identity = entries[0].get("sha256")
    with _lock:
        count, last, table = _cache.get(identity, (0, None, {}))
        if count > len(entries) or (count and entries[count - 1].get("sha256") != last):
            count, table = 0, {}
        table = {key: list(value) for key, value in table.items()}
        for entry in entries[count:]:
            if entry.get("type") == "decision" and entry.get("result") == "applied":
                _touch(table, entry, _when(entry))
        if len(_cache) > 8:
            _cache.clear()
        _cache[identity] = (len(entries), entries[-1].get("sha256"), table)
    return {key: tuple(value) for key, value in table.items()}


def last_contact(service, state, actor, contacts):
    subject = rules.identity(state, actor) or {}
    return max(subject.get("last_contact") or 0, contacts.get(actor) or 0) or None


def _human_manager(state, project, actor):
    return (rules.identity(state, actor) or {}).get("kind") == "human" and rules.manager(state, project, actor)


def reminders(service, state, entries, actor, now=None):
    """Every reminder this identity should see now, oldest first. Each key changes when its subject does.

    `state` is the state being answered from; `entries` are the ledger entries the times are read from.
    Only the account-and-password mode keeps contacts and raises reminders.
    """
    from .round_service import execution_settings
    notices = getattr(service, "notices", None)
    if notices is None or not rules.enabled(state):
        return []
    now = time.time() if now is None else now
    known = times(entries)
    contacts = notices.contacts()
    found = []

    def add(kind, task, subject, since, **fields):
        found.append({"type": kind, "key": digest(encoded([kind, actor, task["task_id"], *subject])),
                      "task_id": task["task_id"], "project_id": rules.task_project(task), "since": int(since),
                      "seconds": int(now - since), **fields})

    for task in state["tasks"].values():
        project = rules.task_project(task)
        if not project or not rules.visible(state, task, actor):
            continue
        manager = _human_manager(state, project, actor)
        since, touched = known.get(task["task_id"], (None, None))
        if manager and _claimable(task) and since and now - since >= UNCLAIMED_SECONDS:
            add("task-unclaimed", task, [since], since)
        for claim in rules.active_claims(state, task["task_id"]):
            holder = claim["origin"]
            if not (manager or rules.responsible(state, holder) == actor) or holder == actor:
                continue
            target = {"claim_id": claim["claim_id"], "holder": holder}
            heard = last_contact(service, state, holder, contacts)
            if execution_settings(state, holder)["heartbeat"] and heard and now - heard >= SILENT_SECONDS:
                add("claim-silent", task, [claim["claim_id"], heard], heard, **target)
            if touched and now - touched >= STALLED_SECONDS:
                add("claim-stalled", task, [claim["claim_id"], touched], touched, **target)
    return sorted(found, key=lambda row: (row["since"], row["type"], row["task_id"]))


def totals(service, state, entries, now=None):
    """How many reminders are open across the whole service, by kind, counting each subject once."""
    notices = getattr(service, "notices", None)
    from .round_service import execution_settings
    counts = dict.fromkeys(KINDS, 0)
    if notices is None or not rules.enabled(state):
        return counts
    now = time.time() if now is None else now
    known, contacts = times(entries), notices.contacts()
    for task in state["tasks"].values():
        if not rules.task_project(task):
            continue
        since, touched = known.get(task["task_id"], (None, None))
        counts["task-unclaimed"] += bool(_claimable(task) and since and now - since >= UNCLAIMED_SECONDS)
        for claim in rules.active_claims(state, task["task_id"]):
            heard = last_contact(service, state, claim["origin"], contacts)
            counts["claim-silent"] += bool(execution_settings(state, claim["origin"])["heartbeat"] and heard and
                                           now - heard >= SILENT_SECONDS)
            counts["claim-stalled"] += bool(touched and now - touched >= STALLED_SECONDS)
    return counts


def describe(row):
    hours = row["seconds"] // 3600
    span = f"{hours} 小时" if hours else f"{max(1, row['seconds'] // 60)} 分钟"
    if row["type"] == "task-unclaimed":
        return f"已开放 {span}，仍无人领取"
    if row["type"] == "claim-silent":
        return f"执行窗口已 {span}没有心跳；请核对它是否仍在运行，失联则按停止或交接流程处理"
    return f"领取后 {span}没有新的记录；请向执行窗口确认进展"


def view(service, snap, actor):
    """GET /v1/attention: the caller's reminders and the limits that raise them."""
    rows = reminders(service, snap["state"], snap["entries"], actor)
    return {"reminders": [{**row, "message": describe(row)} for row in rows],
            "limits": {"unclaimed_seconds": UNCLAIMED_SECONDS, "silent_seconds": SILENT_SECONDS,
                       "stalled_seconds": STALLED_SECONDS},
            "releases": False}
