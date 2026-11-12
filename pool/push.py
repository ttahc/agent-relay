"""Push notices: the service calls a window back when its wait events change, so it need not hold a request.

A window registers one callback address and a secret of its own choosing. When the window's events
change, the service sends one POST to that address with `Authorization: Bearer <secret>` and a body
carrying only the event types, keys and identifiers, the same as GET /v1/wait returns. The window
then reads the details as usual; a push never authorizes, claims or starts anything, and a missed
push loses nothing, because GET /v1/wait still answers from the ledger.

The registration lives in the service's own database next to the request journal, not in the
ledger, so it changes no data format. Delivery follows no redirect, reads at most 4 KiB of the
answer, gives up on one attempt after 5 seconds and retries with growing pauses; after 20 failures
in a row the address is set aside until the window registers again.
"""
from http.client import HTTPConnection, HTTPException, HTTPSConnection
import json
import re
import ssl
import threading
import time
from urllib.parse import urlsplit

from .packages import ClientError, fields
from 协作存储 import digest, encoded

TIMEOUT = 5
MAX_FAILURES = 20
PAUSES = (5, 15, 60, 300, 900)  # seconds before the next attempt after 1, 2, 3, 4, 5+ failures
SECRET = re.compile(r"[A-Za-z0-9._~+/=-]{32,256}")
CHECK_SECONDS = 30  # how often time-raised events (reminders) are looked at without a write


def checked_url(value):
    if not isinstance(value, str) or len(value) > 512 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ClientError("回调地址须为不含空白的 http 或 https 地址")
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ClientError("回调地址须为 http 或 https，且不含账号、密码或 # 片段")
    try:
        parts.port
    except ValueError as error:
        raise ClientError("回调地址端口无效") from error
    return value


class Push:
    def __init__(self, db):
        self.db = db
        db.executescript("""
            CREATE TABLE IF NOT EXISTS push_targets(
                actor TEXT PRIMARY KEY, url TEXT NOT NULL, secret TEXT NOT NULL, created INTEGER NOT NULL,
                cursor TEXT, failures INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0,
                last_status TEXT, last_at INTEGER
            );
        """)

    def save(self, actor, body):
        fields(body, "request_id url secret")
        if body["url"] == "":
            self.db.execute("DELETE FROM push_targets WHERE actor=?", (actor,))
            return {"status": "removed"}
        url = checked_url(body["url"])
        if not isinstance(body["secret"], str) or not SECRET.fullmatch(body["secret"]):
            raise ClientError("回调密钥须为 32 至 256 个字母、数字或 ._~+/=- 字符")
        self.db.execute("INSERT OR REPLACE INTO push_targets(actor,url,secret,created) VALUES(?,?,?,?)",
                        (actor, url, body["secret"], int(time.time())))
        return {"status": "registered", **self.status(actor)}

    def status(self, actor):
        row = self.db.execute("SELECT url,created,failures,last_status,last_at FROM push_targets WHERE actor=?",
                              (actor,)).fetchone()
        if not row:
            return {"registered": False}
        url, created, failures, last_status, last_at = row
        return {"registered": True, "url": url, "created": created, "failures": failures,
                "suspended": failures >= MAX_FAILURES, "last_status": last_status, "last_at": last_at}

    def due(self, now):
        return self.db.execute("SELECT actor,url,secret,cursor,failures FROM push_targets WHERE failures<? AND next_attempt<=?",
                               (MAX_FAILURES, int(now))).fetchall()

    def delivered(self, actor, cursor, status, now):
        self.db.execute("UPDATE push_targets SET cursor=?,failures=0,next_attempt=0,last_status=?,last_at=? WHERE actor=?",
                        (cursor, status, int(now), actor))

    def failed(self, actor, status, now):
        row = self.db.execute("SELECT failures FROM push_targets WHERE actor=?", (actor,)).fetchone()
        failures = (row[0] if row else 0) + 1
        pause = PAUSES[min(failures, len(PAUSES)) - 1]
        self.db.execute("UPDATE push_targets SET failures=?,next_attempt=?,last_status=?,last_at=? WHERE actor=?",
                        (failures, int(now) + pause, status, int(now), actor))


def send(url, secret, body):
    """One POST; the answer's status line, or the reason it failed. No redirect is followed."""
    parts = urlsplit(url)
    connection = (HTTPSConnection(parts.hostname, parts.port, timeout=TIMEOUT, context=ssl.create_default_context())
                  if parts.scheme == "https" else HTTPConnection(parts.hostname, parts.port, timeout=TIMEOUT))
    target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
    try:
        connection.request("POST", target, body=body, headers={
            "Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + secret,
            "User-Agent": "agent-relay-push"})
        response = connection.getresponse()
        response.read(4096)
        return 200 <= response.status < 300, str(response.status)
    except (OSError, HTTPException, ValueError) as error:
        return False, type(error).__name__
    finally:
        connection.close()


def payload(actor, cursor, found):
    return encoded({"executor_id": actor, "cursor": cursor, "events": found,
                    "next": "收到后用 wait、poll、show 或 attention 读取详情；推送本身不授权任何操作"})


def deliver_once(server, now=None):
    """Look at every registered window once and push to those whose events changed. Returns the windows pushed to."""
    from .wakeups import cursor_of, events
    service = server.service
    now = time.time() if now is None else now
    pending = []
    with service.lock:
        targets = server.push.due(now)
        if not targets:
            return []
        with service.one_snapshot(server.wakeups.snapshot(service)):
            state = service.snapshot()["state"]
            if state["pilot"].get("format", {}).get("maintenance"):
                return []
            for actor, url, secret, cursor, _ in targets:
                if service.credential_version(actor) is None:
                    continue  # revoked or archived: nothing is sent for it
                found = events(service, state, actor)
                current = cursor_of(found)
                if current != cursor:
                    pending.append((actor, url, secret, current, found))
    pushed = []
    for actor, url, secret, current, found in pending:  # network calls run outside the service lock
        ok, status = send(url, secret, payload(actor, current, found))
        with service.lock, service.db:
            (server.push.delivered if ok else server.push.failed)(actor, *((current,) if ok else ()), status, now)
        if ok:
            pushed.append(actor)
    return pushed


def run(server):
    """The delivery loop: after every write that changed the ledger, and every CHECK_SECONDS for time-raised events."""
    from .privacy import log_exception
    wakeups = server.wakeups
    while not wakeups.closed:
        seen = wakeups.seen()
        try:
            if server.lifecycle.status()["phase"] == "running":
                deliver_once(server)
        except Exception as error:  # a broken target or a busy store must not stop the loop
            log_exception(error)
        wakeups.wait(seen, CHECK_SECONDS)
        time.sleep(0.2)  # let a burst of writes settle into one push


def start(server):
    thread = threading.Thread(target=run, args=(server,), name="push-notices", daemon=True)
    thread.start()
    return thread
