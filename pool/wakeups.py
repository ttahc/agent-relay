"""Event-driven waiting: one request stays open until something its caller should act on changes.

A polling client asks on a timer and the service replays the ledger for every question. A waiting
client asks once; the answer is sent when a write lands. A window then learns about a new task, a
returned review or a granted resource at once, and nothing is computed while nothing happens.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import select
import threading
import time

from .lifecycle import Maintenance
from .packages import ClientError
from .task_state import security_schema
from 协作存储 import digest, encoded


MAX_HOLD = 50  # seconds one request may stay open
WAITERS = 64  # open waiting requests in total; they give their request slot back
PER_IDENTITY = 2
EVENT_LIMIT = 50
CURSOR = re.compile(r"[0-9a-f]{64}")
STOPPING = {"freezing", "frozen", "backing_up"}
PRESENCE = 1.0  # seconds between looks at whether a waiting browser page is still there


def ledger_marker(service):
    """A cheap identity of the ledger contents: its entries are numbered files that are only ever added."""
    store = getattr(getattr(service, "desk", None), "store", None)
    if store is None:
        return None
    try:
        with os.scandir(Path(store) / "ledger") as entries:
            return sum(entry.name.endswith(".json") for entry in entries)
    except OSError:
        return None


class Wakeups:
    """Wakes waiting requests when the ledger or the service phase changes."""

    def __init__(self, waiters=WAITERS, per_identity=PER_IDENTITY):
        self.condition = threading.Condition()
        self.revision = 0
        self.marker = None
        self.closed = False
        self.limit, self.per_identity = waiters, per_identity
        self.waiting = {}
        self.cached = None

    def notify(self):
        with self.condition:
            self.revision += 1
            self.condition.notify_all()

    def ledger_changed(self, service):
        """After a write request: wake the waiting requests only if the ledger grew."""
        marker = ledger_marker(service)
        with self.condition:
            if marker is None or marker != self.marker:
                self.marker = marker
                self.revision += 1
                self.condition.notify_all()

    def close(self):
        with self.condition:
            self.closed = True
            self.revision += 1
            self.condition.notify_all()

    def seen(self):
        with self.condition:
            return self.revision

    def wait(self, seen, timeout):
        """Sleep until a notification arrives after the revision the caller last saw, or the time runs out."""
        deadline = time.monotonic() + timeout
        with self.condition:
            while self.revision == seen and not self.closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.condition.wait(remaining)

    @contextmanager
    def parked(self, actor):
        with self.condition:
            if sum(self.waiting.values()) >= self.limit or self.waiting.get(actor, 0) >= self.per_identity:
                raise ClientError("等待中的连接已满，请稍后重试或改用定时查询", 429)
            self.waiting[actor] = self.waiting.get(actor, 0) + 1
        try:
            yield
        finally:
            with self.condition:
                self.waiting[actor] -= 1
                if not self.waiting[actor]:
                    del self.waiting[actor]

    def snapshot(self, service):
        """One ledger read shared by every request woken for the same ledger contents. Call with the service lock held."""
        marker = ledger_marker(service)
        if marker is None:
            return service.snapshot()
        if self.cached is None or self.cached[0] != marker:
            self.cached = (marker, service.snapshot())
        return self.cached[1]


def events(service, state, actor):
    """What this identity may need to act on now. An event's key changes whenever its subject does."""
    from .round_service import Notices, ready_tasks
    found = []

    def add(kind, subject, **fields):
        found.append({"type": kind, "key": digest(encoded([kind, actor, *subject])), **fields})
    for key, task in ready_tasks(service, state, actor).items():
        found.append({"type": "task-ready", "key": key, "task_id": task["task_id"], "version": task["version"],
                      "scope_version": task["scope_version"]})
    for key, (task, claim, revision) in Notices._returned(state, actor).items():
        if service.visible(state, task, actor):
            found.append({"type": "review-returned", "key": key, "task_id": task["task_id"],
                          "claim_id": claim["claim_id"], "revision": revision})
    for claim in state["claims"].values():
        task = state["tasks"].get(claim["task_id"])
        if claim["L"] != "active" or not task:
            continue
        target = {"task_id": task["task_id"], "claim_id": claim["claim_id"]}
        work = claim["W"]
        if task.get("receiver") == actor and work["state"] == "review" and service.visible(state, task, actor):
            add("review-requested", [claim["claim_id"], work["scope"], work.get("revision")], **target, revision=work.get("revision"))
        if claim["origin"] != actor:
            continue
        if claim.get("scope_ack_pending"):
            add("scope-changed", [claim["claim_id"], work["scope"]], **target, scope_version=work["scope"])
        recovery = claim.get("recovery") or {}
        if recovery.get("status") == "pending" and recovery.get("by") != actor:
            add("interrupted", [claim["claim_id"], recovery.get("event")], **target, reason=recovery.get("reason"))
        if task.get("cancel_requested"):
            add("cancel-requested", [claim["claim_id"]], **target)
    if security_schema(state) >= 5:
        for row in state["security"].get("execution", {}).get("actions", {}).values():
            if row.get("executor_id") == actor and row.get("state") == "granted":
                add("resource-granted", [row["id"], row.get("grant_id"), row.get("generation")], task_id=row.get("task_id"),
                    claim_id=row.get("claim_id"), action_id=row["id"], grant_id=row.get("grant_id"))
    return sorted(found, key=lambda event: (event["type"], event["key"]))[:EVENT_LIMIT]


def cursor_of(found):
    return digest(encoded(sorted(event["key"] for event in found)))


def look(handler, actor=None):
    """One evaluation under the service lock: who is asking, and what there is for them to act on."""
    server = handler.server
    service, wakeups = server.service, server.wakeups
    seen = wakeups.seen()
    if wakeups.closed or service.lifecycle.status()["phase"] in STOPPING:
        raise Maintenance("服务正在升级，请稍后重新等待")
    with service.lock:
        with service.one_snapshot(wakeups.snapshot(service)):
            caller = handler.authenticate()
            if actor is not None and caller != actor:
                raise ClientError("身份或凭据已变化，请重新等待", 401)
            state = service.snapshot()["state"]
            if state["pilot"]["format"]["maintenance"]:
                raise ClientError("服务处于维护窗口", 503)
            return caller, seen, events(service, state, caller)


def respond(handler, target):
    """GET /v1/wait: answer at once when the caller's events differ from its cursor, otherwise when they change."""
    from .httpd import JSON, parse_query
    server = handler.server
    query = parse_query(target.query, {"cursor", "timeout"})
    cursor, hold = query.get("cursor", ""), query.get("timeout", "0")
    if cursor and not CURSOR.fullmatch(cursor):
        raise ClientError("等待游标无效")
    if not (hold.isascii() and hold.isdigit() and len(hold) <= 3 and int(hold) <= MAX_HOLD):
        raise ClientError(f"等待时长须为 0 至 {MAX_HOLD} 秒")
    deadline = time.monotonic() + int(hold)

    def answer(found):
        current = cursor_of(found)
        if current != cursor or deadline - time.monotonic() <= 0:
            return 200, {"cursor": current, "changed": current != cursor, "events": found}, JSON

    actor, seen, found = look(handler)
    if response := answer(found):
        return response
    with server.wakeups.parked(actor):
        server.release_request_slot()
        while True:
            server.wakeups.wait(seen, deadline - time.monotonic())
            actor, seen, found = look(handler, actor)
            if response := answer(found):
                return response


def left(handler):
    """A waiting browser sends nothing more, so a readable connection means the page was closed or left."""
    try:
        return bool(select.select([handler.connection], [], [], 0)[0])
    except (OSError, ValueError):
        return True


def workspace_look(handler, project, actor=None):
    """One evaluation under the service lock for a signed-in page: who is asking, and the revision of what they see."""
    from . import web, workbench
    server = handler.server
    service, wakeups = server.service, server.wakeups
    seen = wakeups.seen()
    if wakeups.closed or service.lifecycle.status()["phase"] in STOPPING:
        raise Maintenance("服务正在升级，请稍后重新等待")
    with service.lock:
        with service.one_snapshot(wakeups.snapshot(service)):
            caller = server.sessions.actor(web.session_id(handler), service)
            if not caller or actor is not None and caller != actor:
                raise ClientError("登录已失效，请重新登录", 401)
            return caller, seen, workbench.workspace_revision(service.read(caller, "overview", project))


def respond_workspace(handler, target):
    """GET /workspace-state with a timeout: the workbench page's form of GET /v1/wait.

    Answers at once when the revision of what the signed-in person sees differs from the one the page
    was drawn with, otherwise when it changes or the time is over. None leaves the request to the
    ordinary page route, which answers the current revision without waiting.
    """
    if target.path != "/workspace-state" or not handler.server.is_round or "timeout=" not in target.query:
        return None
    from . import __version__
    from .httpd import JSON, parse_query
    server = handler.server
    query = parse_query(target.query, {"project", "revision", "timeout"})
    known, hold = query.get("revision", ""), query.get("timeout", "")
    if known and not CURSOR.fullmatch(known):
        raise ClientError("状态摘要无效")
    if not (hold.isascii() and hold.isdigit() and len(hold) <= 3 and int(hold) <= MAX_HOLD):
        raise ClientError(f"等待时长须为 0 至 {MAX_HOLD} 秒")
    deadline = time.monotonic() + int(hold)

    def answer(revision):
        if revision != known or deadline - time.monotonic() <= 0:
            return 200, {"revision": revision, "version": __version__, "changed": revision != known}, JSON

    actor, seen, revision = workspace_look(handler, query.get("project"))
    if response := answer(revision):
        return response
    with server.wakeups.parked("web:" + actor):
        server.release_request_slot()
        while True:
            server.wakeups.wait(seen, min(PRESENCE, max(0, deadline - time.monotonic())))
            if left(handler):
                handler.close_connection = True
                raise ConnectionAbortedError("the page that was waiting has gone")
            if server.wakeups.seen() == seen and not server.wakeups.closed and deadline - time.monotonic() > 0:
                continue
            actor, seen, revision = workspace_look(handler, query.get("project"), actor)
            if response := answer(revision):
                return response
