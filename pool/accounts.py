"""Private account and invitation records in the existing request journal."""

import base64
import hmac
import json
import secrets
import time

from .packages import ClientError
from 协作存储 import digest, encoded


INVITE_ROLES = {"executor", "receiver"}
INVITE_AGE = 24 * 60 * 60


class Accounts:
    def __init__(self, db):
        self.db = db
        db.executescript("""
            CREATE TABLE IF NOT EXISTS credential_key(
                id INTEGER PRIMARY KEY CHECK(id = 1), secret BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS enrolled_accounts(
                name TEXT PRIMARY KEY COLLATE NOCASE, role TEXT NOT NULL,
                token_sha TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS account_invites(
                code_sha TEXT PRIMARY KEY, issue_key TEXT NOT NULL UNIQUE,
                actor TEXT NOT NULL, role TEXT NOT NULL, expires INTEGER NOT NULL,
                used_by TEXT
            );
            CREATE TABLE IF NOT EXISTS executor_expiry(
                name TEXT PRIMARY KEY, expires INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS executor_credential_versions(
                name TEXT PRIMARY KEY, credential INTEGER NOT NULL, token_sha TEXT NOT NULL
            );
        """)
        with db:
            if not db.execute("SELECT 1 FROM credential_key WHERE id=1").fetchone():
                db.execute("INSERT INTO credential_key VALUES(1,?)", (secrets.token_bytes(32),))
        self.secret = db.execute("SELECT secret FROM credential_key WHERE id=1").fetchone()[0]

    def token(self, kind, key, name=""):
        raw = hmac.digest(self.secret, encoded([kind, key, name]), "sha256")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    def identity(self, token):
        row = self.db.execute("SELECT a.name FROM enrolled_accounts a LEFT JOIN executor_expiry e ON a.name=e.name "
                              "WHERE a.token_sha=? AND (e.expires IS NULL OR e.expires>?)",
                              (digest(token.encode("ascii")), int(time.time()))).fetchone()
        return row[0] if row else None

    def expires(self, name):
        row = self.db.execute("SELECT expires FROM executor_expiry WHERE name=?", (name,)).fetchone()
        return row[0] if row else None

    def issue_executor(self, name, token, expires, credential):
        self.db.execute("INSERT INTO enrolled_accounts VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET token_sha=excluded.token_sha",
                        (name, "executor", digest(token.encode("ascii"))))
        self.db.execute("INSERT OR REPLACE INTO executor_expiry VALUES(?,?)", (name, expires))
        self.bind_executor(name, credential)

    def bind_executor(self, name, credential):
        if type(credential) is not int or credential < 1:
            raise ValueError("执行端发行版本无效")
        row = self.db.execute("SELECT token_sha FROM enrolled_accounts WHERE name=?", (name,)).fetchone()
        if not row:
            raise ValueError("执行端凭据尚未发行")
        self.db.execute("INSERT OR REPLACE INTO executor_credential_versions VALUES(?,?,?)", (name, credential, row[0]))

    def executor_current(self, name, credential, token=None):
        row = self.db.execute("SELECT v.credential,v.token_sha,a.token_sha FROM executor_credential_versions v "
                              "JOIN enrolled_accounts a ON a.name=v.name WHERE v.name=?", (name,)).fetchone()
        return bool(row and row[0] == credential and hmac.compare_digest(row[1], row[2]) and
                    (token is None or hmac.compare_digest(row[1], digest(token.encode("ascii")))))

    def pending_executor_changes(self, state):
        blocked = set()
        changing = {"ai-activate", "token-prepare", "credential-change", "executor-enroll", "identity-bind", "window-admin"}
        for action, raw, raw_plan in self.db.execute("SELECT action,body,plan FROM requests WHERE status IS NULL"):
            if action not in changing:
                continue
            try:
                body = json.loads(raw)
                plan = json.loads(raw_plan) if raw_plan else {}
                name = body.get("name") or plan.get("enrollment", {}).get("name")
                registration = body.get("registration_id") or plan.get("enrollment", {}).get("round_registration")
                if registration:
                    name = state.get("round", {}).get("enrollment:" + str(registration), {}).get("name") or name
                if not isinstance(name, str) or not name:
                    return None  # Ambiguous unfinished identity change: do not infer any baseline.
                blocked.add(name)
            except (ValueError, TypeError, AttributeError):
                return None
        return blocked

    def legacy_executor_bootstrap(self, state, name):
        subject = state.get("pilot", {}).get("identity:" + str(name), {})
        blocked = self.pending_executor_changes(state)
        return bool(subject.get("credential") == 1 and blocked is not None and name not in blocked and
                    not self.db.execute("SELECT 1 FROM enrolled_accounts WHERE name=?", (name,)).fetchone() and
                    not any(key.startswith("enrollment:") and row.get("name") == name
                            for key, row in state.get("round", {}).items()))

    def baseline_executors(self, snap):
        """Add version evidence to old private rows only when their issuance is provable."""
        state = snap["state"]
        blocked = self.pending_executor_changes(state)
        if blocked is None:
            return
        with self.db:
            for name, token_sha in self.db.execute("SELECT name,token_sha FROM enrolled_accounts").fetchall():
                subject = state.get("pilot", {}).get("identity:" + name, {})
                credential = subject.get("credential")
                if (subject.get("kind") != "executor" or subject.get("status") != "active" or
                        type(credential) is not int or credential < 1 or name in blocked or
                        self.db.execute("SELECT 1 FROM executor_credential_versions WHERE name=?", (name,)).fetchone()):
                    continue
                enrollments = [row for key, row in state.get("round", {}).items() if key.startswith("enrollment:") and
                               row.get("name") == name and row.get("state") == "active" and row.get("version") == credential]
                proven = any(hmac.compare_digest(token_sha, digest(self.token("round-executor", row["id"],
                            f"{name}:{credential}").encode("ascii"))) for row in enrollments)
                if not enrollments and credential == 1:
                    proven = True  # Monotonic version 1 plus no unfinished change preserves pre-mapping issuance.
                if not proven and not enrollments:
                    for key, raw_response in self.db.execute("SELECT key,response FROM requests WHERE action='credential-change' AND status=200"):
                        try:
                            response = json.loads(raw_response)
                            if response.get("issued_to") != name or not hmac.compare_digest(token_sha,
                                    digest(self.token("account", key, name).encode("ascii"))):
                                continue
                            events = {step.get("event_id") for step in response.get("steps", []) if step.get("result") == "applied"}
                            proven = any(entry.get("result") == "applied" and entry.get("key", "").rsplit("/", 1)[-1] in events and
                                         any(effect.get("path") == ["pilot", "identity:" + name] and
                                             effect.get("value", {}).get("credential") == credential and
                                             effect["value"].get("status") == "active" for effect in entry.get("effects", []))
                                         for entry in snap.get("entries", []))
                        except (ValueError, TypeError, AttributeError):
                            continue
                        if proven:
                            break
                if proven:
                    self.bind_executor(name, credential)

    def role(self, name):
        row = self.db.execute("SELECT role FROM enrolled_accounts WHERE name=? COLLATE BINARY", (name,)).fetchone()
        return row[0] if row else None

    def list(self):
        return self.db.execute("SELECT name, role FROM enrolled_accounts ORDER BY name").fetchall()

    def invite(self, actor, request_id, role):
        if role not in INVITE_ROLES:
            raise ClientError("邀请码角色须为执行者或接收者")
        key = digest(encoded([actor, request_id]))
        code = self.token("invite", key)
        previous = self.db.execute("SELECT role, expires, used_by FROM account_invites WHERE issue_key=?",
                                   (key,)).fetchone()
        if previous:
            if previous[0] != role:
                raise ClientError("此请求编号已绑定其他角色", 409)
            if previous[1] <= time.time() or previous[2]:
                raise ClientError("该邀请码已使用或已过期，请重新生成", 409)
        else:
            with self.db:
                self.db.execute("INSERT INTO account_invites VALUES(?,?,?,?,?,NULL)",
                                (digest(code.encode("ascii")), key, actor, role, int(time.time()) + INVITE_AGE))
        return code

    def invited_role(self, invite_sha):
        row = self.db.execute("SELECT role, expires, used_by FROM account_invites WHERE code_sha=?",
                              (invite_sha,)).fetchone()
        if not row or row[1] <= time.time() or row[2]:
            raise ClientError("邀请码无效、已使用或已过期", 403)
        return row[0]

    def enroll(self, key, registration):
        name, role = registration["name"], registration["role"]
        token_kind = "password-only" if registration.get("password_signup") else "account"
        token_sha = digest(self.token(token_kind, key, name).encode("ascii"))
        self.db.execute("INSERT INTO enrolled_accounts VALUES(?,?,?)", (name, role, token_sha))
        if "invite_sha" in registration:
            consumed = self.db.execute("UPDATE account_invites SET used_by=? WHERE code_sha=? AND used_by IS NULL",
                                       (name, registration["invite_sha"]))
            if consumed.rowcount != 1:
                raise RuntimeError("账号已入账，但邀请码状态不一致")

    def change_credential(self, key, record):
        if record["enabled"]:
            token_sha = digest(self.token("account", key, record["name"]).encode("ascii"))
            self.db.execute("INSERT INTO enrolled_accounts VALUES(?,?,?) "
                            "ON CONFLICT(name) DO UPDATE SET token_sha=excluded.token_sha",
                            (record["name"], record["role"], token_sha))
        else:
            self.db.execute("UPDATE enrolled_accounts SET token_sha=? WHERE name=?",
                            (digest(encoded(["disabled", key, record["name"]])), record["name"]))
