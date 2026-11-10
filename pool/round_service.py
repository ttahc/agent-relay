"""Transport contracts for the third task-pool data version."""
import hmac
import time

from .packages import ClientError, fields, integer, string
from .constants import ACCESS_TOKEN, ADMIN, COORDINATOR, ID, step
from 协作本轮 import (ACTIVATION_SECONDS, OPS, TOKEN_SECONDS, automation_allowed, enabled, execution_settings,
                  invite_allowed, ready_key, rotation_allowed, usable_invite)
from 协作存储 import digest, encoded
import 协作升级 as rules


PUBLIC = OPS - {"round-migrate", "ai-prepare", "ai-activate", "password-event", "token-prepare"}
INTERNAL = {"round-migrate", "ai-prepare", "ai-activate", "password-event", "token-prepare"}
BOOTSTRAP = {"ai-prepare", "ai-recover", "ai-activate"}
MAX_SECRET_BODY = 32768


def bounded(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ClientError(f"{label} 须为 {low} 至 {high} 的整数")
    return value


def boolean(value):
    if type(value) is not bool:
        raise ClientError("须明确选择启用状态")
    return value


def secret_hash(value):
    if not isinstance(value, str) or not ACCESS_TOKEN.fullmatch(value):
        raise ClientError("接入凭据无效或已到期", 403)
    return digest(value.encode("ascii"))


def source(raw, state, owner):
    from .upgrade import source_profile
    if not isinstance(raw, dict):
        raise ClientError("须填写来源资料")
    allowed = {"platform", "session", "model", "environment", "device", "directory", "url", "parent",
               "session_source", "window_name"}
    if not raw.keys() <= allowed or not raw.get("session"):
        raise ClientError("须提供平台会话或已持久保存的本地来源标识")
    origin = raw.get("session_source", "reported")
    if origin not in ("reported", "local") or origin == "local" and not str(raw["session"]).startswith("local-"):
        raise ClientError("来源标识类型不符")
    data = {key: raw.get(key, "unknown") for key in ("session", "model", "environment", "device", "directory")}
    data.update(platform=raw.get("platform", "external"), url=raw.get("url", ""), parent=raw.get("parent"))
    if "window_name" in raw:
        data["window_name"] = raw["window_name"]
    return {**source_profile(data, state, owner), "source_evidence": origin}


def plan(service, actor, action, key, body, state):
    from .upgrade import identifier, role_list, sha256, version
    if action not in PUBLIC | INTERNAL:
        return None
    if action != "round-migrate" and not enabled(state):
        raise ClientError("须先迁移本轮数据合同", 409)
    p = {"op": action}
    result, extra = {}, {}
    if action == "round-migrate":
        fields(body, "request_id upgrade image")
        p.update(upgrade=identifier(body["upgrade"], "发布编号"), image=sha256(body["image"]))
    elif action == "ai-invite":
        fields(body, "request_id project_id owner roles hours count")
        p.update(project_id=identifier(body["project_id"], "项目"),
                 owner=identifier(body["owner"], "责任账号"), roles=role_list(body["roles"], {"executor", "receiver"}),
                 hours=bounded(body["hours"], 1, 168, "有效小时"), count=bounded(body["count"], 1, 20, "登记额度"),
                 invite_id="i-" + key[:32])
        extra["invite_id"] = p["invite_id"]
    elif action == "ai-revoke":
        fields(body, "request_id invite_id reason")
        p.update(invite_id=identifier(body["invite_id"], "邀请编号"), reason=string(body["reason"], "撤销依据"))
        extra["invite_id"] = p["invite_id"]
    elif action == "ai-prepare":
        p.update({k: body[k]
                  for k in ("invite_id", "registration_id", "name", "source", "source_sha", "proof_sha", "project_id")})
        extra["registration_id"] = p["registration_id"]
    elif action == "token-prepare":
        fields(body, "request_id name version reason proof_sha")
        p.update(name=identifier(body["name"], "窗口身份"), version=version(body["version"]),
                 reason=string(body["reason"], "轮换依据"), proof_sha=sha256(body["proof_sha"]),
                 registration_id="r-" + key[:36])
        extra["registration_id"] = p["registration_id"]
    elif action == "ai-activate":
        registration_id = body["registration_id"]
        record = state["round"].get("enrollment:" + registration_id)
        if not record:
            raise ClientError("登记已失效", 403)
        p.update(registration_id=registration_id, project_id=record.get("project"))
        extra.update(registration_id=registration_id, executor_id=record["name"])
        result["enrollment"] = {"name": record["name"], "role": "executor", "round_registration": registration_id}
    elif action == "password-event":
        fields(body, "request_id name kind")
        p.update(name=identifier(body["name"], "人员账号"), kind=body["kind"])
        if body["kind"] in {"setup", "change", "reset", "admin-recovery"}:
            result["password_change"] = {"name": p["name"], "kind": p["kind"]}
        elif body["kind"] == "reset-issued":
            result["password_change"] = {"name": p["name"], "kind": "reset-issued", "issuer": actor}
        else:
            raise ClientError("密码操作类型无效")
    elif action == "project-automation":
        fields(body, "request_id project_id version enabled")
        p.update(project_id=identifier(body["project_id"], "项目"), version=version(body["version"]),
                 enabled=boolean(body["enabled"]))
    elif action == "runner-settings":
        fields(body, "request_id version auto limit heartbeat adapter")
        adapter = body["adapter"]
        if adapter not in ("", "local-command"):
            raise ClientError("未登记的执行接口")
        p.update(version=version(body["version"]), settings={"auto": boolean(body["auto"]),
                 "limit": bounded(body["limit"], 1, 8, "窗口并发"), "heartbeat": boolean(body["heartbeat"]),
                 "adapter": adapter})
    elif action == "run-report":
        fields(body, "request_id claim_id epoch scope_version state evidence")
        claim = state["claims"].get(string(body["claim_id"], "领取编号", 100))
        if not claim or claim["origin"] != actor:
            raise ClientError("领取不存在或无权回报", 404)
        if body["state"] not in ("intent", "started", "waiting", "working", "finished", "error"):
            raise ClientError("执行回报状态无效")
        p.update(claim_id=body["claim_id"], epoch=integer(body["epoch"], "执行代次"),
                 scope_version=integer(body["scope_version"], "范围版本"), state=body["state"],
                 evidence=string(body["evidence"], "事实或证据"))
        result.update(task_id=claim["task_id"], claim_id=claim["claim_id"])
    else:
        from .round_projects import payload
        p.update(payload(state, actor, action, body, key))
        extra["record_id"] = p.get("id")
    return {**result, "round_result": extra,
            "steps": [step(COORDINATOR, "pilot", p, {"generation": state["generation"]})]}


def prepare_token(service, actor, body):
    fields(body, "request_id name version reason recovery")
    data = {k: v for k, v in body.items() if k != "recovery"}
    data["proof_sha"] = secret_hash(body["recovery"])
    status, response = service.submit(actor, "token-prepare", body["request_id"], data)
    if status == 200:
        response = {**response, **pending_result(service, response["registration_id"], data["proof_sha"])}
    return status, response


def token_for(service, record):
    return service.accounts.token("round-executor", record["id"], f"{record['name']}:{record['version']}")


def pending_result(service, registration_id, proof_sha):
    state = service.snapshot()["state"]
    record = state["round"].get("enrollment:" + registration_id)
    if not record or not hmac.compare_digest(record["proof_sha"], proof_sha):
        raise ClientError("登记与恢复证明不符", 403)
    subject = rules.identity(state, record["name"])
    value = {"registration_id": registration_id, "executor_id": record["name"], "window": subject["window"],
             "project_id": record.get("project"), "deadline": record["deadline"]}
    if record["state"] == "active":
        return {**value, "status": "active"}
    allowed = (usable_invite(state, state["round"].get("invite:" + record["invite_id"])) if record["kind"] == "invite"
               else (rotation_allowed(state, record["issuer"], record["name"])
                     and subject["credential"] + 1 == record["version"]))
    if record["state"] != "pending" or record["deadline"] <= time.time() or not allowed:
        raise ClientError("待激活登记已过期、撤销或失去授权", 403)
    return {**value, "status": "pending_activation", "token": token_for(service, record)}


def bootstrap(service, action, body, token=""):
    from .upgrade import identifier
    with service.lock:
        if not service.recover():
            raise ClientError("前序操作待确认，请重试原请求", 503)
        state = service.snapshot()["state"]
        if not enabled(state) or state["pilot"]["format"]["maintenance"]:
            raise ClientError("登记入口暂不可用", 503)
        client_request = identifier(body.get("request_id"), "请求编号")
        if action == "ai-activate":
            fields(body, "request_id registration_id")
            reg = identifier(body["registration_id"], "登记编号")
            record = state["round"].get("enrollment:" + reg)
            if not record or not token.isascii() or not hmac.compare_digest(token_for(service, record), token):
                raise ClientError("登记凭据无效", 403)
            if record["state"] == "active":
                if service.account_actor(token) != record["name"] or not service.credential_version(record["name"]):
                    raise ClientError("登记凭据已失效", 403)
                subject = rules.identity(state, record["name"])
                return 200, {"status": "active", "executor_id": record["name"], "window": subject["window"],
                             "registration_id": reg, "expires": record["expires"]}
            if record["state"] != "pending" or record["deadline"] <= time.time():
                raise ClientError("登记凭据已到期或撤销", 403)
            rid = "activate-" + reg
            status, value = service.submit(record["issuer"], "ai-activate", rid,
                                           {"request_id": rid, "registration_id": reg})
            if status != 200:
                return status, value
            return bootstrap(service, action, body, token)

        invite_id = identifier(body.get("invite_id"), "邀请编号")
        reg = "a-" + digest(encoded([invite_id, client_request]))[:36]
        proof = secret_hash(body.get("recovery"))
        if action == "ai-recover":
            fields(body, "request_id invite_id recovery")
            return 200, pending_result(service, reg, proof)
        fields(body, "request_id invite_id code recovery source")
        record = state["round"].get("invite:" + invite_id)
        if not record or not hmac.compare_digest(secret_hash(body["code"]),
                secret_hash(service.accounts.token("ai-invite", invite_id, record["issuer"]))):
            raise ClientError("邀请码无效", 403)
        profile = source(body["source"], state, record["owner"])
        rid = "prepare-" + reg
        data = {"request_id": rid, "registration_id": reg, "invite_id": invite_id,
                "project_id": record["project"], "name": "x-" + digest(encoded([reg, "window"]))[:24],
                "source": profile, "source_sha": digest(encoded(profile)), "proof_sha": proof}
        status, response = service.submit(record["issuer"], "ai-prepare", rid, data)
        return (200, pending_result(service, reg, proof)) if status == 200 else (status, response)


def result(service, action, response):
    if action != "ai-invite" or not response.get("invite_id"):
        return response
    invite_id = response["invite_id"]
    state = service.snapshot()["state"]
    record = state["round"].get("invite:" + invite_id)
    if not usable_invite(state, record) or record["expires"] <= time.time() or record["used"] >= record["count"]:
        return response
    return {**response,
            "invitation": {**record, "code": service.accounts.token("ai-invite", invite_id, record["issuer"])}}


def invitations(state, actor):
    records = state["round"]
    values = []
    for key, invite in records.items():
        if not key.startswith("invite:") or not (rules.system_admin(state, actor) or
                rules.manager(state, invite["project"], actor) or actor in {invite["issuer"], invite["owner"]}):
            continue
        windows = []
        for key, record in records.items():
            if not key.startswith("enrollment:") or record.get("invite_id") != invite["id"]:
                continue
            subject = rules.identity(state, record["name"])
            stage = record["state"]
            if stage == "pending" and record["deadline"] <= time.time():
                stage = "expired"
            if stage == "active":
                stage = subject["status"]
            windows.append({"name": record["name"], "window": subject["window"], "state": stage})
        values.append({**invite, "windows": windows})
    return {"invitations": values}


def annotate_sources(service, state, sources):
    contacts = service.notices.contacts()
    now = time.time()
    for subject in sources:
        actor = subject["executor_id"]
        settings = execution_settings(state, actor)
        latest = max(subject.get("last_contact") or 0, contacts.get(actor) or 0)
        expiry = service.accounts.expires(actor)
        subject.update(last_contact=latest or None, contact=("stale" if latest and now - latest >= 180 else "current")
                       if settings["heartbeat"] and latest else "unconfirmed",
                       credential_expires=expiry, credential_expiring=bool(expiry and expiry - now <= 7 * 86400),
                       concurrency=settings["limit"], round=True)
        registration = state["round"].get("enrollment:" + str(subject.get("registration")), {})
        if subject["status"] == "pending" and registration.get("deadline", 0) <= now:
            subject["status"] = "expired"


def password_signup(service, request, name, invitation, password):
    if not ID.fullmatch(name) or not ID.fullmatch(request) or name.casefold() == ADMIN:
        raise ClientError("账号或请求编号格式无效")
    proof = secret_hash(invitation)
    rid = "signup-" + digest(encoded([proof, request]))
    key = digest(encoded([COORDINATOR, rid]))
    with service.lock:
        if not enabled(service.snapshot()["state"]):
            raise ClientError("人员密码注册入口未启用", 409)
        existing = service.db.execute("SELECT 1 FROM requests WHERE key=?", (key,)).fetchone()
        if not existing:
            service.accounts.invited_role(proof)
    protected = service.passwords.protect(password, name)
    with service.lock:
        if not service.recover():
            raise ClientError("前序请求待确认，请重试原表单", 503)
        if not service.db.execute("SELECT 1 FROM requests WHERE key=?", (key,)).fetchone():
            service.accounts.invited_role(proof)
            service.passwords.stage(key, name, protected, "signup")
        status, value = service.submit(COORDINATOR, "signup-password", rid,
                                       {"request_id": rid, "name": name, "invite_sha": proof})
        if status not in (200, 202, 503):
            service.passwords.discard(key)
        return status, value


def password_change(service, actor, name, kind, request, protected, reset_sha=None):
    from .upgrade import identifier
    rid = identifier(request, "请求编号")
    key = digest(encoded([actor, rid]))
    with service.lock:
        if not service.recover():
            raise ClientError("前序操作待确认，请重试原请求", 503)
        existing = service.db.execute("SELECT 1 FROM requests WHERE key=?", (key,)).fetchone()
        if not existing:
            service.passwords.stage(key, name, protected, kind, reset_sha)
        status, value = service.submit(actor, "password-event", rid, {"request_id": rid, "name": name, "kind": kind})
        if status not in (200, 202, 503):
            service.passwords.discard(key)
        return status, value


def ready_tasks(service, state, actor):
    """Open tasks this identity may claim now, keyed by the notice event each one raises."""
    return {ready_key(task, actor): task for task in state["tasks"].values()
            if rules.contract(task) and task["status"] == "available" and rules.visible(state, task, actor) and
            service.qualification(state, task, actor)["eligible"]}


class Notices:
    """Persistent delivery attempts for ready tasks and exact returned revisions."""

    def __init__(self, db):
        self.db = db
        db.executescript("""
            CREATE TABLE IF NOT EXISTS round_notices(
                seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, actor TEXT NOT NULL,
                task TEXT NOT NULL, created INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                due INTEGER NOT NULL, ack INTEGER, sent INTEGER, last_poll TEXT
            );
            CREATE INDEX IF NOT EXISTS round_notice_actor ON round_notices(actor,seq);
            CREATE TABLE IF NOT EXISTS round_contacts(actor TEXT PRIMARY KEY, seen INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS round_notice_log(
                seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL, actor TEXT NOT NULL,
                stage TEXT NOT NULL, at INTEGER NOT NULL, request TEXT NOT NULL,
                UNIQUE(event_id,stage,request)
            );
        """)

    def pulse(self, actor):
        self.db.execute("INSERT OR REPLACE INTO round_contacts VALUES(?,?)", (actor, int(time.time())))

    def contacts(self):
        return dict(self.db.execute("SELECT actor,seen FROM round_contacts"))

    @staticmethod
    def _return_key(actor, acceptance_id):
        return digest(encoded(["review-returned", actor, acceptance_id]))

    @classmethod
    def _returned(cls, state, actor):
        result = {}
        for claim in state["claims"].values():
            if claim["origin"] != actor or claim["L"] != "active" or not claim.get("deliveries"):
                continue
            name, delivery = max(claim["deliveries"].items(), key=lambda pair: (pair[1].get("seal_seq", 0), pair[0]))
            acceptance_id = delivery.get("acceptance_id")
            review = state.get("acceptances", {}).get(acceptance_id)
            task = state["tasks"].get(claim["task_id"])
            if (not task or not review or delivery.get("status") != "revision" or review.get("verdict") != "revision" or
                    review.get("acceptance_id") != acceptance_id or review.get("task_id") != task["task_id"] or
                    review.get("claim_id") != claim["claim_id"] or review.get("revision") != name or
                    review.get("manifest_sha256") != delivery.get("manifest_sha256") or
                    review.get("scope_version") != delivery.get("scope_version") or
                    review.get("manifest") is not None and review["manifest"] != delivery.get("manifest")):
                continue
            result[cls._return_key(actor, acceptance_id)] = (task, claim, name)
        return result

    def poll(self, state, actor, body, service):
        fields(body, "request_id cursor")
        from .upgrade import identifier
        request = identifier(body["request_id"], "查询编号")
        after = bounded(body["cursor"], 0, 10**12, "通知游标")
        subject = rules.identity(state, actor) or {}
        if subject.get("kind") != "executor":
            raise ClientError("通知查询须使用执行端身份", 403)
        if state["pilot"]["format"]["maintenance"]:
            raise ClientError("服务处于维护窗口", 503)
        now = int(time.time())
        ready = ready_tasks(service, state, actor)
        returned = self._returned(state, actor)
        if returned:
            entries = service.snapshot().get("entries", [])
            returned = {event: (task,
                                next((review for review in service._delivery_reviews(state, task, [claim], entries)
                                          if review["revision"] == name), None))
                        for event, (task, claim, name) in returned.items() if service.visible(state, task, actor)}
            returned = {event: value for event, value in returned.items() if value[1] is not None}
        events, cursor = [], after
        with self.db:
            if execution_settings(state, actor)["heartbeat"]:
                self.pulse(actor)
            self.db.executemany("INSERT OR IGNORE INTO round_notices(event_id,actor,task,created,due) "
                                "VALUES(?,?,?,?,?)",
                                ((event, actor, task["task_id"], now, now) for event, task in ready.items()))
            self.db.executemany("INSERT OR IGNORE INTO round_notices(event_id,actor,task,created,due) "
                                "VALUES(?,?,?,?,?)",
                                ((event, actor, task["task_id"], now, now) for event, (task, _) in returned.items()))
            rows = self.db.execute("SELECT seq,event_id,created,attempts,due,last_poll FROM round_notices "
                                   "WHERE actor=? AND ack IS NULL AND (attempts<6 OR last_poll=?) ORDER BY seq",
                                   (actor, request)).fetchall()
            for seq, event, created, attempts, due, last in rows:
                if event not in ready and event not in returned or last != request and due > now:
                    continue
                task = ready[event] if event in ready else returned[event][0]
                if last != request:
                    attempts += 1
                    self.db.execute("UPDATE round_notices SET attempts=?,sent=?,due=?,last_poll=? WHERE seq=?",
                                    (attempts, now, now + min(300, 5 * 2 ** (attempts - 1)), request, seq))
                    self.db.execute("INSERT OR IGNORE INTO round_notice_log(event_id,actor,stage,at,request) "
                                    "VALUES(?,?,?,?,?)",
                                    (event, actor, "sent", now, request))
                cursor = max(seq, cursor)
                notification = {"event_id": event, "task_id": task["task_id"], "version": task["version"],
                                "scope_version": task["scope_version"], "created": created, "attempts": attempts}
                if event in returned:
                    review = returned[event][1]
                    notification.update(type="review-returned", auto=False,
                                        **{key: review[key]
                                           for key in ("claim_id", "revision", "manifest_sha256", "acceptance_id",
                                                                       "failed_criteria", "reason", "reviewer", "at")})
                else:
                    notification.update(type="task-ready", reason="任务就绪", auto=automation_allowed(state, task, actor))
                events.append(notification)
                if len(events) >= 25:
                    break
        return {"cursor": cursor, "events": events}

    def acknowledge(self, actor, body):
        fields(body, "request_id event_id")
        from .upgrade import identifier, sha256
        event = sha256(body["event_id"])
        request = identifier(body["request_id"], "确认编号")
        with self.db:
            row = self.db.execute("SELECT ack,sent FROM round_notices WHERE event_id=? AND actor=?",
                                  (event, actor)).fetchone()
            if not row or row[1] is None:
                raise ClientError("通知不存在或尚未发送", 404)
            now = row[0] or int(time.time())
            self.db.execute("UPDATE round_notices SET ack=? WHERE event_id=?", (now, event))
            if row[0] is None:
                self.db.execute("INSERT INTO round_notice_log(event_id,actor,stage,at,request) VALUES(?,?,?,?,?)",
                                (event, actor, "acknowledged", now, request))
        return {"event_id": event, "acknowledged": now}

    def retry(self, state, actor, body):
        fields(body, "request_id event_id")
        from .upgrade import identifier, sha256
        event = sha256(body["event_id"])
        request = identifier(body["request_id"], "重投编号")
        with self.db:
            row = self.db.execute("SELECT actor,task,ack FROM round_notices WHERE event_id=?", (event,)).fetchone()
            if not row or row[2] is not None:
                raise ClientError("没有可重投的通知", 404)
            task = state["tasks"].get(row[1])
            if not task or not (actor == row[0] or rules.manager(state, rules.task_project(task), actor)):
                raise ClientError("没有可重投的通知", 404)
            if ready_key(task, row[0]) != event and event not in self._returned(state, row[0]):
                raise ClientError("原通知的任务版本已变化", 409)
            recorded = self.db.execute("INSERT OR IGNORE INTO round_notice_log(event_id,actor,stage,at,request) "
                                       "VALUES(?,?,?,?,?)",
                                       (event, actor, "retry", int(time.time()), request))
            if recorded.rowcount:
                self.db.execute("UPDATE round_notices SET due=0,attempts=0,last_poll=NULL WHERE event_id=?", (event,))
        return {"event_id": event, "queued": True}

    def acknowledged(self, actor, event):
        return bool(self.db.execute("SELECT 1 FROM round_notices WHERE actor=? AND event_id=? AND ack IS NOT NULL",
                                    (actor, event)).fetchone())
