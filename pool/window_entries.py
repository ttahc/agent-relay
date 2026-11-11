"""Windows of a joined platform ask to register; a responsible person agrees.

An entry point lets the windows of one platform ask to join one project under one responsible
person. Asking creates no identity, no window number and no permission. Agreeing is the responsible
person issuing a single-use invitation for that one application, so registration and activation run
through the existing rules and the ledger names who agreed. Entry points and applications are
private records of the service; the ledger rules are unchanged.
"""
import hmac
import json
import time

from . import round_service
from .packages import ClientError, fields, string
from .round_service import enabled, invite_allowed, secret_hash
from .upgrade import identifier, role_list
from 协作存储 import digest, encoded
import 协作升级 as rules


MAX_PENDING = 10  # applications waiting at one entry point
PENDING_SECONDS = 72 * 3600  # an application nobody decided lapses
PICKUP_HOURS = 72  # after agreement, the window has this long to come back for its credential
ROLES = {"executor", "receiver"}
REFUSED = {400, 403, 404, 409}  # answers of the registration rules that repeating the request cannot change
ENTRY_FIELDS = ("id", "project", "platform", "owner", "issuer", "created", "revoked", "revoked_by", "reason")
APPLICATION_FIELDS = ("id", "entry", "client_request", "request_sha", "proof_sha", "source", "created", "state",
                      "decided_by", "decided", "invite_id", "roles", "reason")


def ensure(db):
    db.execute("""CREATE TABLE IF NOT EXISTS window_entries(
        id TEXT PRIMARY KEY, project TEXT NOT NULL, platform TEXT NOT NULL, owner TEXT NOT NULL, issuer TEXT NOT NULL,
        created INTEGER NOT NULL, revoked INTEGER, revoked_by TEXT, reason TEXT)""")
    db.execute("""CREATE TABLE IF NOT EXISTS window_applications(
        id TEXT PRIMARY KEY, entry TEXT NOT NULL, client_request TEXT NOT NULL, request_sha TEXT NOT NULL,
        proof_sha TEXT NOT NULL, source TEXT NOT NULL, created INTEGER NOT NULL, state TEXT NOT NULL,
        decided_by TEXT, decided INTEGER, invite_id TEXT, roles TEXT, reason TEXT)""")


def entry_row(db, entry_id):
    row = db.execute(f"SELECT {','.join(ENTRY_FIELDS)} FROM window_entries WHERE id=?", (entry_id,)).fetchone()
    return dict(zip(ENTRY_FIELDS, row)) if row else None


def application_rows(db, where="1=1", values=()):
    rows = db.execute(f"SELECT {','.join(APPLICATION_FIELDS)} FROM window_applications WHERE {where} ORDER BY created, id",
                      values).fetchall()
    return [{**dict(zip(APPLICATION_FIELDS, row)), "source": json.loads(row[5]),
             "roles": json.loads(row[11]) if row[11] else None} for row in rows]


def code(service, entry):
    """The application code of an entry point. It only lets a window ask; it reads and writes nothing else."""
    return service.accounts.token("window-entry", entry["id"], entry["issuer"])


def pairing(application):
    """A short code shown to the applying window and to the person deciding, so the two can be matched."""
    number = int(digest(encoded(["window-application-pairing", application["id"], application["proof_sha"]]))[:12], 16)
    return f"{number % 1000000:06d}"


def grantable(state, issuer, project, owner):
    """The window roles this person could give by invitation to windows of that owner."""
    return [role for role in sorted(ROLES) if invite_allowed(state, issuer, project, owner, [role])]


def usable(state, entry):
    return bool(entry) and not entry["revoked"] and bool(grantable(state, entry["issuer"], entry["project"], entry["owner"]))


def claimed(service, state, platform, session, now=None):
    """Whether this platform session already has an application that is waiting or agreed and not yet picked up."""
    for row in application_rows(service.db, "state IN ('pending','approved')"):
        entry = entry_row(service.db, row["entry"])
        if entry["platform"] != platform or row["source"].get("session") != session:
            continue
        if row["state"] == "pending":
            if stage(row, entry, now) == "pending":
                return "该会话已有待处理的申请，请等待负责人处理"
            continue
        invite = state["round"].get("invite:" + row["invite_id"])
        if (invite and round_service.usable_invite(state, invite) and invite["used"] < invite["count"]
                and invite["expires"] > (time.time() if now is None else now)):
            return "该会话的申请已获同意，请用原凭据文件运行 enroll 完成登记"
    return ""


def visible(state, actor, entry):
    return bool(rules.system_admin(state, actor) or rules.manager(state, entry["project"], actor) or
                actor in {entry["issuer"], entry["owner"]} and rules.active(state, actor))


def stage(application, entry, now=None):
    """Where an application stands now; time and a revoked entry point end a waiting one."""
    if application["state"] != "pending":
        return application["state"]
    if entry["revoked"]:
        return "revoked"
    return "expired" if application["created"] + PENDING_SECONDS <= (time.time() if now is None else now) else "pending"


def create(service, actor, request_id, project, platform, owner):
    request_id = identifier(request_id, "请求编号")
    project, owner = identifier(project, "项目"), identifier(owner, "负责人")
    if platform not in rules.PLATFORMS:
        raise ClientError("平台须从登记表选择")
    with service.lock:
        ensure(service.db)
        state = service.snapshot()["state"]
        if not enabled(state):
            raise ClientError("须先迁移本轮数据合同", 409)
        if not grantable(state, actor, project, owner):
            raise ClientError("只有项目管理员，或为本人名下执行窗口设置的人员，可以建立平台接入点；负责人须在项目中有执行或验收权限", 403)
        entry_id = "e-" + digest(encoded([actor, request_id]))[:32]
        existing = entry_row(service.db, entry_id)
        if existing:
            if (existing["project"], existing["platform"], existing["owner"]) != (project, platform, owner):
                raise ClientError("此请求编号已绑定其他接入点", 409)
            return existing
        with service.db:
            service.db.execute("INSERT INTO window_entries VALUES(?,?,?,?,?,?,NULL,NULL,NULL)",
                               (entry_id, project, platform, owner, actor, int(time.time())))
        return entry_row(service.db, entry_id)


def revoke(service, actor, entry_id, reason):
    reason = string(reason, "撤销依据", 400)
    with service.lock:
        ensure(service.db)
        state = service.snapshot()["state"]
        entry = entry_row(service.db, identifier(entry_id, "接入点编号"))
        if not entry or not visible(state, actor, entry):
            raise ClientError("接入点不存在或无权处理", 404)
        if not entry["revoked"]:
            now = int(time.time())
            with service.db:
                service.db.execute("UPDATE window_entries SET revoked=?, revoked_by=?, reason=? WHERE id=?",
                                   (now, actor, reason, entry["id"]))
                service.db.execute("UPDATE window_applications SET state='revoked', decided_by=?, decided=?, reason=? "
                                   "WHERE entry=? AND state='pending'", (actor, now, "接入点已撤销：" + reason, entry["id"]))
        return entry_row(service.db, entry["id"])


def overview(service, actor):
    """Entry points this person may see, each with its applications."""
    with service.lock:
        ensure(service.db)
        state = service.snapshot()["state"]
        found = []
        for (entry_id,) in service.db.execute("SELECT id FROM window_entries ORDER BY created, id").fetchall():
            entry = entry_row(service.db, entry_id)
            if not visible(state, actor, entry):
                continue
            rows = [{**row, "stage": stage(row, entry), "pairing": pairing(row)}
                    for row in application_rows(service.db, "entry=?", (entry_id,))]
            found.append({**entry, "usable": usable(state, entry), "applications": rows,
                          "roles": [role for role in sorted(ROLES) if invite_allowed(state, actor, entry["project"], entry["owner"], [role])],
                          "pending": sum(row["stage"] == "pending" for row in rows)})
        return found


def answer(service, application, entry, state, recovery):
    """What the applying window is told about its application."""
    current = stage(application, entry)
    value = {"application_id": application["id"], "status": current, "pairing_code": pairing(application),
             "project": entry["project"], "owner": entry["owner"], "platform": entry["platform"]}
    if current == "pending":
        return {**value, "status": "pending_approval", "expires": application["created"] + PENDING_SECONDS}
    if current != "approved":
        return {**value, "message": application["reason"] or {"expired": "申请超过 72 小时无人处理，已作废",
                                                              "revoked": "接入点已撤销"}.get(current, "")}
    invite = state["round"].get("invite:" + application["invite_id"])
    try:
        if not invite:
            raise ClientError("同意记录已不存在", 403)
        status, result = round_service.bootstrap(service, "ai-prepare", {
            "request_id": application["client_request"], "invite_id": application["invite_id"],
            "code": service.accounts.token("ai-invite", application["invite_id"], invite["issuer"]),
            "recovery": recovery, "source": application["source"]})
    except ClientError as error:
        if error.status == 503:
            raise
        status, result = error.status, {"message": str(error)}
    if status == 200:
        return {**value, **result, "roles": application["roles"]}
    if status not in REFUSED:  # still being confirmed, or the service is busy: the same request can be repeated
        return {**value, "retry": True, "message": "已同意，登记尚待服务确认，请稍后用相同凭据文件重试"}
    reason = result.get("message") or (result.get("steps") or [{}])[-1].get("reason", "")
    return {**value, "status": "lapsed", "message": "同意已失效，请重新申请" + (f"（{reason}）" if reason else "")}


def apply(service, body):
    """POST /v1/window-apply: ask to register, or ask again with the same request to learn the outcome."""
    fields(body, "request_id entry_id code recovery source")
    client_request = identifier(body["request_id"], "请求编号")
    entry_id = identifier(body["entry_id"], "接入点编号")
    proof = secret_hash(body["recovery"])
    with service.lock:
        ensure(service.db)
        entry = entry_row(service.db, entry_id)
        if not entry or not hmac.compare_digest(secret_hash(body["code"]), secret_hash(code(service, entry))):
            raise ClientError("申请码无效", 403)
        if not service.recover():
            raise ClientError("前序操作待确认，请重试原请求", 503)
        state = service.snapshot()["state"]
        if not enabled(state) or state["pilot"]["format"]["maintenance"]:
            raise ClientError("申请入口暂不可用", 503)
        application_id = "w-" + digest(encoded([entry_id, client_request]))[:32]
        request_sha = digest(encoded([client_request, entry_id, body["source"]]))
        existing = application_rows(service.db, "id=?", (application_id,))
        if existing:
            application = existing[0]
            if not hmac.compare_digest(application["proof_sha"], proof):
                raise ClientError("申请与恢复证明不符", 403)
            if application["request_sha"] != request_sha:
                raise ClientError("此申请编号已绑定其他来源资料", 409)
            return answer(service, application, entry, state, body["recovery"])
        if not usable(state, entry):
            raise ClientError("接入点已撤销，或建立人的当前授权已不满足接入条件", 403)
        profile = round_service.source(body["source"], state, entry["owner"])
        if profile["platform"] != entry["platform"]:
            raise ClientError("来源平台与接入点登记的平台不符")
        if any(key.startswith("identity:") and row.get("platform") == profile["platform"] and
               row.get("session") == profile["session"] for key, row in state["pilot"].items()):
            raise ClientError("该平台会话已登记，请沿用原窗口凭据", 409)
        waiting = [row for row in application_rows(service.db, "entry=? AND state='pending'", (entry_id,))
                   if stage(row, entry) == "pending"]
        if message := claimed(service, state, profile["platform"], body["source"].get("session")):
            raise ClientError(message, 409)
        if len(waiting) >= MAX_PENDING:
            raise ClientError("该接入点待处理的申请已满，请联系负责人处理后重试", 429)
        with service.db:
            service.db.execute("INSERT INTO window_applications VALUES(?,?,?,?,?,?,?,'pending',NULL,NULL,NULL,NULL,NULL)",
                               (application_id, entry_id, client_request, request_sha, proof,
                                json.dumps(body["source"], ensure_ascii=False, sort_keys=True), int(time.time())))
        return answer(service, application_rows(service.db, "id=?", (application_id,))[0], entry, state, body["recovery"])


def decide(service, actor, application_id, agree, roles=None, reason="", authorize=None):
    """The responsible person agrees or refuses. Agreement issues one single-use invitation in their name."""
    with service.lock:
        ensure(service.db)
        state = service.snapshot()["state"]
        found = application_rows(service.db, "id=?", (identifier(application_id, "申请编号"),))
        entry = entry_row(service.db, found[0]["entry"]) if found else None
        if not entry or not visible(state, actor, entry):
            raise ClientError("申请不存在或无权处理", 404)
        application = found[0]
        if stage(application, entry) != "pending":
            raise ClientError("申请已处理、已作废或已过期", 409)
        now = int(time.time())
        if not agree:
            reason = string(reason, "拒绝原因", 400)
            with service.db:
                service.db.execute("UPDATE window_applications SET state='rejected', decided_by=?, decided=?, reason=? "
                                   "WHERE id=? AND state='pending'", (actor, now, reason, application["id"]))
            return 200, {"status": "rejected", "application_id": application["id"]}
        roles = role_list(roles, ROLES)
        if not roles:
            raise ClientError("须至少选择一个窗口权限")
        if not usable(state, entry):
            raise ClientError("接入点已撤销，或建立人的当前授权已不满足接入条件", 409)
        if not invite_allowed(state, actor, entry["project"], entry["owner"], roles):
            raise ClientError("无法按所选权限同意：权限须在负责人本人的项目权限之内，验收权限须由项目管理员同意", 403)
        request_id = "apply-" + digest(encoded([application["id"], roles]))[:40]
        status, value = service.submit(actor, "ai-invite", request_id, {
            "request_id": request_id, "project_id": entry["project"], "owner": entry["owner"], "roles": roles,
            "hours": PICKUP_HOURS, "count": 1}, authorize=authorize)
        if status != 200 or not value.get("invite_id"):
            return (status if status != 200 else 409), value
        with service.db:
            service.db.execute("UPDATE window_applications SET state='approved', decided_by=?, decided=?, invite_id=?, roles=? "
                               "WHERE id=? AND state='pending'", (actor, now, value["invite_id"], json.dumps(roles), application["id"]))
        return 200, {"status": "approved", "application_id": application["id"], "invite_id": value["invite_id"]}
