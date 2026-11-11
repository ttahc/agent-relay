"""GET /metrics: running figures in the Prometheus text format, for whatever already watches the host.

Only counts and durations leave the service: no task titles, names, paths or identifiers. The caller
presents the scrape token made by `taskpool.py metrics-token` (only its SHA256 is kept, in
metrics-token.json beside the ledger) or a system administrator's Bearer token. The loopback address
earns no exemption: the LAN port forwarding of a WSL deployment delivers every outside connection from
loopback.
"""
import hashlib
import hmac
import json
import secrets
from pathlib import Path
import threading
import time

import 协作升级 as rules

KIND = "text/plain; version=0.0.4; charset=utf-8"


class WriteTimer:
    """How many write requests (every POST, from the API and from web forms) were answered and how long they took."""

    def __init__(self):
        self.lock = threading.Lock()
        self.count, self.total, self.longest = 0, 0.0, 0.0

    def record(self, seconds):
        with self.lock:
            self.count += 1
            self.total += seconds
            self.longest = max(self.longest, seconds)

    def figures(self):
        with self.lock:
            return self.count, self.total, self.longest


TOKEN_FILE = "metrics-token.json"


def issue(store):
    """A new scrape token: printed once, its SHA256 replaces the previous one. The ledger is not touched."""
    token = secrets.token_urlsafe(32)
    target = Path(store) / TOKEN_FILE
    staging = target.with_name("." + TOKEN_FILE + ".new")
    staging.write_text(json.dumps({"sha256": hashlib.sha256(token.encode("ascii")).hexdigest()}) + "\n", encoding="utf-8")
    staging.chmod(0o600)
    staging.replace(target)
    return token


def scrape_token_matches(store, token):
    try:
        expected = json.loads((Path(store) / TOKEN_FILE).read_text(encoding="utf-8"))["sha256"]
    except (OSError, ValueError, KeyError, TypeError):
        return False
    return isinstance(expected, str) and hmac.compare_digest(expected, hashlib.sha256(token.encode("ascii", "replace")).hexdigest())


def allowed(handler):
    headers = handler.headers.get_all("Authorization", [])
    scheme, _, token = (headers[0] if len(headers) == 1 else "").partition(" ")
    if scheme.lower() == "bearer" and token.isascii() and 32 <= len(token) <= 100 and \
            scrape_token_matches(handler.server.service.desk.store, token):
        return True
    actor = handler.authenticate()
    return handler.server.service.is_admin(actor)


def _samples(lines, name, kind, text, samples):
    lines.append(f"# HELP {name} {text}")
    lines.append(f"# TYPE {name} {kind}")
    for suffix, labels, value in samples:
        label = "{" + ",".join(f'{key}="{labels[key]}"' for key in sorted(labels)) + "}" if labels else ""
        lines.append(f"{name}{suffix}{label} {round(value, 6) if isinstance(value, float) else value}")


def gauge(lines, name, text, samples):
    _samples(lines, name, "gauge", text, [("", labels, value) for labels, value in samples])


def online_windows(service, state, now):
    """Active AI windows, and those with heartbeats on that were heard from in the last 3 minutes."""
    from .round_service import execution_settings
    contacts = service.notices.contacts()
    windows = online = 0
    for key, subject in state["pilot"].items():
        if not key.startswith("identity:") or subject.get("kind") != "executor" or subject.get("status") != "active":
            continue
        name = key.split(":", 1)[1]
        windows += 1
        heard = max(subject.get("last_contact") or 0, contacts.get(name) or 0)
        online += bool(execution_settings(state, name)["heartbeat"] and heard and now - heard < 180)
    return windows, online


def render(server, now=None):
    from . import __version__
    from .attention import totals
    service = server.service
    now = time.time() if now is None else now
    started = time.monotonic()
    with service.lock:
        snap = service.snapshot()
        read = time.monotonic() - started
        state = snap["state"]
        statuses = {}
        for task in state["tasks"].values():
            statuses[task.get("status", "unknown")] = statuses.get(task.get("status", "unknown"), 0) + 1
        claimable = sum(bool((rules.contract(task) or {}).get("open")) and task.get("status") == "available"
                        for task in state["tasks"].values())
        active = sum(claim.get("L") == "active" for claim in state["claims"].values())
        round_mode = server.is_round and rules.enabled(state)
        reminders = totals(service, state, snap["entries"], now) if round_mode else {}
        windows, online = online_windows(service, state, now) if round_mode else (0, 0)
    lines = []
    gauge(lines, "agent_relay_info", "Version of the running service.", [({"version": __version__}, 1)])
    gauge(lines, "agent_relay_phase", "1 for the current service phase.", [({"phase": server.lifecycle.status()["phase"]}, 1)])
    gauge(lines, "agent_relay_ledger_entries", "Entries in the ledger.", [({}, snap["head"])])
    gauge(lines, "agent_relay_ledger_read_seconds", "Time this scrape took to read the ledger.", [({}, read)])
    gauge(lines, "agent_relay_tasks", "Tasks by status.", [({"status": key}, value) for key, value in sorted(statuses.items())])
    gauge(lines, "agent_relay_tasks_claimable", "Open tasks nobody holds.", [({}, claimable)])
    gauge(lines, "agent_relay_claims_active", "Active claims.", [({}, active)])
    if round_mode:
        gauge(lines, "agent_relay_reminders", "Open timeout and lost-contact reminders, by kind.",
              [({"type": key}, value) for key, value in sorted(reminders.items())])
        gauge(lines, "agent_relay_windows", "Active AI windows, and those with heartbeats on heard from in the last 3 minutes.",
              [({"presence": "registered"}, windows), ({"presence": "online"}, online)])
    gauge(lines, "agent_relay_wait_requests", "Requests held open by wait, and the limit.",
          [({"kind": "open"}, sum(server.wakeups.waiting.values())), ({"kind": "limit"}, server.wakeups.limit)])
    count, total, longest = server.write_timer.figures()
    _samples(lines, "agent_relay_write_seconds", "summary", "Write requests (POST) answered since start and the time they took.",
             [("_count", {}, count), ("_sum", {}, total)])
    gauge(lines, "agent_relay_write_seconds_max", "Longest write request (POST) since start.", [({}, longest)])
    return ("\n".join(lines) + "\n").encode("utf-8")
