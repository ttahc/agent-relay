"""Names shared by the service and its planners; this module imports no other pool module."""

import re


ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}")
ACCESS_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
ADMIN = "admin"
COORDINATOR = "pilot-coordinator"
COMMITTER = "pilot-committer"


class Unavailable(RuntimeError):
    pass


def step(actor, command, payload, expects=None):
    return {"actor": actor, "command": command, "payload": payload, "expects": expects or {}}
