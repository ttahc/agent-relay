"""Serialize pilot operations and resume each persisted ledger envelope in order."""

import base64
from contextlib import contextmanager
import json
import os
import re
import sqlite3
import threading
import time

from . import ROOT, round_service, upgrade, delegation
from .accounts import Accounts
from .constants import ACCESS_TOKEN, ADMIN, COMMITTER, COORDINATOR, ID, Unavailable, step
from .auth import Passwords
from .packages import (ClientError, MAX_PACKAGE, SHA, artifact_name, fields, integer, ledger_package,
                       make_delivery, reference, seal_metadata, string, unpack_delivery)
from .storage import LedgerBackend
from .lifecycle import Lifecycle
from 协作账本 import cursor, envelope
from 协作交接 import import_package
from 协作存储 import digest, encoded, publish, safe
from 协作取证 import checked_file, manifest
from 协作视图 import render
from 协作存储 import Rejected
import 协作升级 as rules


PUBLIC_ACTIONS = {"register", "claim", "handoff", "deliver", "deliver-files", "stop",
                  "return", "resume", "review", "close", "cancel", "withdraw"} | upgrade.ACTIONS | round_service.PUBLIC | {
                    'context-save','segment-open','action-prepare','resource-request','resource-cancel','action-start',
                    'execution-fact','evidence-stash','resource-release'}


@contextmanager
def exclusive(store, lock_name="service.lock"):
    with safe(store, lock_name).open("a+b") as lock:
        lock.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise Unavailable("该试用账本已由另一个进程打开") from error
        yield


def state_path(name):
    if not ID.fullmatch(name):
        raise ClientError("试用库名称格式错误")
    return safe(ROOT, ".state/" + name)


def store_once(store, path, raw):
    target = safe(store, path)
    if not publish(target, raw) and target.read_bytes() != raw:
        raise Unavailable("不可变文件内容冲突")
    return target


def handoff_reference(claim):
    path = claim.get("replacement", "")
    name = path.rsplit("/", 1)[-1]
    if path.startswith("handoffs/" + claim["claim_id"] + "/") and name.endswith(".json") and SHA.fullmatch(name[:-5]):
        return {"path": path, "sha256": name[:-5]}
    return None


def active_claim(state, task):
    return next((state["claims"][cid] for cid in reversed(task["claims"])
                 if state["claims"][cid]["L"] == "active"), None)


def execution_status(state, claim):
    if not state or not claim or state.get('security',{}).get('schema',0)<5:
        return None
    data=state['security'].get('execution',{})
    all_rows=[row for row in data.get('actions',{}).values() if row.get('claim_id')==claim['claim_id']]
    rows=[row for row in all_rows if row.get('epoch')==claim['epoch'] and row.get('scope_version')==claim['W']['scope']]
    historical=[row for row in all_rows if row not in rows]
    if not all_rows and claim['claim_id'] not in data.get('claim_bindings',{}):
        return None
    unknown=sum(row.get('state')=='unconfirmed' or row.get('state') in {'finished','error','stopped'} and
                data.get('grants',{}).get(row.get('grant_id'),{}).get('physical') in {'in-use','unknown'} for row in rows)
    return {'actions':len(rows),'running':sum(row['state']=='running' for row in rows),
            'awaiting_start':sum(row['state']=='start-authorized' for row in rows),
            'unconfirmed':unknown,'finished':sum(row['state'] in {'finished','error','stopped','not-started'} for row in rows),
            'historical_live':sum(row['state'] in {'running','start-authorized','unconfirmed'} for row in historical),
            'historical_unconfirmed':sum(row['state']=='unconfirmed' or data.get('grants',{}).get(row.get('grant_id'),{}).get('physical') in {'in-use','unknown'} for row in historical)}

def stage(task, claim, state=None):
    if claim and claim.get("recovery", {}).get("status") == "pending":
        return "recovery"
    if task["status"] == "running" and claim:
        if task.get("cancel_requested"):
            return "cancel_pending"
        if claim["E"].get("reason") == "replace":
            return "handoff_pending"
        if claim["E"].get("reason") == "pause" and claim["W"]["state"] in {"draft", "revision"}:
            return "paused"
        current=execution_status(state,claim)
        if current is not None and claim['W']['state'] not in {'review','revision','complete'}:
            if current['unconfirmed']:return 'recovery'
            if current['running'] or current['finished']:return 'running'
            return 'claimed'
        return {"review": "review", "revision": "revision", "complete": "accepted"}.get(
            claim["W"]["state"], "claimed" if claim.get("run", {}).get("state") == "claimed" else "running")
    if task["status"] == "available" and (spec := rules.contract(task)):
        gate = spec.get("gate")
        if not spec["open"] or state is not None and gate and state["pilot"].get("release:" + gate, {}).get("status") != "closed":
            return "waiting"
    return task["status"]


class Service:
    def __init__(self, store):
        # Protect direct Service users too; the CLI's outer lock alone is insufficient.
        self._writer_guard = exclusive(store, "service-writer.lock")
        self._writer_guard.__enter__()
        try:
            self._initialize(store)
        except BaseException:
            if hasattr(self, "db"):
                self.db.close()
            self._writer_guard.__exit__(None, None, None)
            self._writer_guard = None
            raise

    def _initialize(self, store):
        self.desk = LedgerBackend(store)
        self.desk.check_qualification(store, self.desk.meta["qualification"])
        if self.desk.meta["migration"] or self.desk.meta["coordinator"] != COORDINATOR:
            raise Unavailable("需要独立试用账本")
        self.lock = threading.RLock()
        self.lifecycle = Lifecycle()
        self.pinned = threading.local()
        self.db = sqlite3.connect(safe(store, "http-journal.sqlite3"), check_same_thread=False)
        self.db.execute("PRAGMA synchronous=EXTRA")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS requests(
                key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, actor TEXT NOT NULL,
                action TEXT NOT NULL, body BLOB NOT NULL, plan BLOB, status INTEGER, response BLOB
            );
            CREATE TABLE IF NOT EXISTS steps(
                request_key TEXT NOT NULL, position INTEGER NOT NULL, envelope BLOB NOT NULL,
                PRIMARY KEY(request_key, position)
            );
            CREATE TABLE IF NOT EXISTS request_context(
                request_key TEXT PRIMARY KEY, details BLOB NOT NULL
            );
        """)
        self.accounts = Accounts(self.db)
        from .safety import initialize as initialize_safety
        initialize_safety(self.db)
        self.passwords = Passwords(self.db, self.lock, self.accounts)
        self.notices = round_service.Notices(self.db)
        snap = self.snapshot()
        fmt = snap["state"]["pilot"].get("format")
        if fmt and (fmt["schema"] not in {2, 3, 4, 5} or fmt["min_reader"] > 5):
            raise Unavailable("当前程序不支持数据合同版本")
        self.accounts.baseline_executors(snap)

    def close(self):
        if self._writer_guard is not None:
            try:
                with self.lock:
                    self.db.close()
            finally:
                self._writer_guard.__exit__(None, None, None)
                self._writer_guard = None

    def consistent_backup(self, archive, tag, timeout=30):
        from .backup import snapshot
        if not isinstance(archive, str) or not isinstance(tag, str):
            raise ValueError("备份需要绝对目录和唯一名称")
        with self.lifecycle.backup_window(timeout):
            result = snapshot(self.desk.store, archive, tag, service=self)
        return {**result, "phase": self.lifecycle.status()["phase"]}

    def snapshot(self):
        pinned = getattr(self.pinned, "active", False)
        if pinned and self.pinned.snap is not None:
            return self.pinned.snap
        snap = self.desk.read()
        from 协作安全 import check as check_security
        check_security(snap['state'])
        if snap["halted"]:
            raise Unavailable(f"试用账本停写，最后有效位置为 {snap['head']}")
        if pinned:
            self.pinned.snap = snap
        return snap

    @contextmanager
    def one_snapshot(self):
        """Answer every read made while rendering one page from the same ledger snapshot."""
        self.pinned.active, self.pinned.snap = True, None
        try:
            yield
        finally:
            self.pinned.active, self.pinned.snap = False, None

    @contextmanager
    def request_identity(self, verifier, supersedes=None):
        """Keep a per-request verifier without holding the lock while reading HTTP bodies."""
        with self.lock:
            actor = verifier()
        prior = getattr(self.pinned, "authentication", None)
        self.pinned.authentication = (actor, verifier, supersedes)
        try:
            yield
        finally:
            self.pinned.authentication = prior

    def submit(self, actor, action, request_id, body, reported_utc=None, authorize=None):
        self.pinned.active, self.pinned.snap = False, None
        if not isinstance(request_id, str) or not ID.fullmatch(request_id):
            raise ClientError("request_id 必须是稳定的字母数字标识，可含 - 和 _")
        inherited = getattr(self.pinned, 'authentication', None)
        if (inherited and inherited[0] == actor and len(inherited) > 2 and inherited[2] is not None and
                'supersedes_request_id' not in body and (prior_id := inherited[2]())):
            body = {**body, 'supersedes_request_id': prior_id}
        key = digest(encoded([actor, request_id]))
        fingerprint = digest(encoded([action, body]))
        business_body = dict(body)
        supersedes = business_body.pop('supersedes_request_id', None)
        with self.lock:
            inherited = getattr(self.pinned, "authentication", None)
            if authorize is None and inherited and inherited[0] == actor:
                authorize = inherited[1]
            def authenticate_current():
                if authorize is not None and authorize() != actor:
                    raise ClientError("身份或凭据已变化，请重新登录后查询原请求", 401)
            authenticate_current()
            if supersedes is not None:
                if (not isinstance(supersedes, str) or not ID.fullmatch(supersedes) or supersedes == request_id or
                    not self.db.execute('SELECT 1 FROM requests WHERE key=?',
                        (digest(encoded([actor, supersedes])),)).fetchone()):
                    raise ClientError('关联原请求不存在或编号无效', 409)
            self.lifecycle.check_new_work(action, body)
            row = self.db.execute("SELECT fingerprint, status, response FROM requests WHERE key=?", (key,)).fetchone()
            if row:
                if row[0] != fingerprint:
                    raise ClientError("request_id 已绑定其他操作或内容", 409)
                if row[1] is not None:
                    access = self.receipt_authorization(actor, key)
                    response = json.loads(row[2])
                    return row[1], self.cleanup_receipt(response) if access == "cleanup" else self.credential_result(key, action, response)
                if self.db.execute('SELECT 1 FROM request_quarantine WHERE key=?',(key,)).fetchone():
                    self.receipt_authorization(actor,key)
                    return 202, {'status':'pending','request_id':request_id,'requires_reconciliation':True,
                                 'message':'原请求需要有权人员核对；已完成事实和原输入均保留'}
                if not self.recover():
                    return 202, {"status": "pending", "request_id": request_id}
                authenticate_current()
                row = self.db.execute("SELECT status,response FROM requests WHERE key=?", (key,)).fetchone()
                access = self.receipt_authorization(actor, key)
                result = json.loads(row[1]) if row[1] else {"status": "pending", "request_id": request_id}
                return row[0] or 202, self.cleanup_receipt(result) if access == "cleanup" else self.credential_result(key, action, result)
            if not self.recover():
                return 503, {"status": "pending", "message": "前序操作待恢复，当前请求尚未登记"}
            authenticate_current()
            snap = self.snapshot()
            task_id, project = delegation.target(snap["state"], action, body)
            with delegation.operation_context(snap["state"], actor, action, project, task_id):
                try:
                    if action == "capability-save" and delegation.stamp(snap["state"], actor, project):
                        delegation.enforce_capability_self(actor, body)
                    plan = self.plan(actor, action, key, business_body, snap)
                except (ClientError, Rejected) as error:
                    status = error.status if isinstance(error, ClientError) else 409
                    if status == 503:
                        return 503, {"status": "maintenance", "retryable": True, "message": str(error),
                                     "request_id": request_id, "retry_after": 3}
                    response = {"status": "rejected", "message": str(error), "request_id": request_id}
                    with self.db:
                        self.db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)",
                                        (key, fingerprint, actor, action, b"{}", None, status, encoded(response)))
                        self.record_request(key, actor, action, body, fingerprint, snap["state"], reported_utc=reported_utc)
                    return status, response
                with self.db:
                    self.db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)",
                                    (key, fingerprint, actor, action, encoded(body), encoded(plan), None, None))
                    self.record_request(key, actor, action, body, fingerprint, snap["state"], plan, reported_utc)
                    if supersedes is not None:
                        old_key=digest(encoded([actor,supersedes]))
                        if self.db.execute('SELECT 1 FROM request_quarantine WHERE key=?',(old_key,)).fetchone():
                            response={'status':'rejected','request_id':supersedes,'superseded_by':request_id,
                                      'message':'原请求隔离后由关联新请求接续；已完成事实和原输入保留','quarantined':True}
                            self.db.execute('UPDATE requests SET status=409,response=? WHERE key=? AND status IS NULL',
                                            (encoded(response),old_key))
            return self.execute(key)

    def record_request(self, key, actor, action, body, fingerprint, state, plan=None, reported_utc=None):
        task, project = upgrade.target(state, body, plan)
        real_task, real_project = delegation.target(state, action, body)
        task, project = task or real_task, real_project or project
        from . import execution
        if action in execution.ACTIONS:
            binding=execution._binding(state,action,body)
            resolved_task=state['tasks'].get(binding.get('task_id'))
            if resolved_task:
                task=resolved_task['task_id'];project=rules.task_project(resolved_task)
        subject = rules.identity(state, actor) or {}
        details = {"schema": state["pilot"].get("format", {}).get("schema", rules.VERSION),
                   "actor": actor, "identity_kind": subject.get("kind"),
                   "owner": rules.responsible(state, actor), "window": subject.get("window"),
                   "window_name": subject.get("window_name"),
                   "model": subject.get("model"), "platform": subject.get("platform"),
                   "credential_version": subject.get("credential"),
                   "authorization": rules.auth_stamp(state, actor, project), "project_id": project,
                   "task_id": task, "request_id": body["request_id"], "fingerprint": fingerprint,
                   'claim_id':body.get('claim_id'), 'action_id':body.get('action_id'),
                   "received_utc": rules.utc(), "reported_utc": reported_utc, "operation": action,
                   "reason": body.get("reason") if isinstance(body.get("reason"), str) else None}
        if body.get('supersedes_request_id'):
            details['supersedes_request_id'] = body['supersedes_request_id']
        details.update(delegation.stamp(state, actor, project))
        if state.get('security',{}).get('schema',0)>=5 and action in PUBLIC_ACTIONS:
            from 协作执行 import default_context
            selected=default_context(state,actor)
            data=state['security'].get('execution',{})
            action_row=data.get('actions',{}).get(body.get('action_id'),{})
            segment=data.get('segments',{}).get(body.get('segment_id') or action_row.get('segment_id'),{})
            cid=body.get('context_id') or segment.get('context_id')
            cversion=body.get('context_version') or segment.get('context_version')
            if cid and cversion:
                selected=data.get('contexts',{}).get(str(cid)+':'+str(cversion),selected)
            details.update(source_platform=subject.get('platform'),execution_context=selected,
                           model=selected.get('config',{}).get('model'),platform=selected.get('config',{}).get('platform'))
            if action in {'execution-fact','evidence-stash'} and not body.get('action_id'):
                details['reporter_context']=details.pop('execution_context')
                details['original_execution_context']='unknown'
        self.db.execute("INSERT INTO request_context VALUES(?,?)", (key, encoded(details)))

    def credential_result(self, key, action, response):
        if action in {"executor-enroll", "credential-change"} and response.get("issued_to"):
            name = response["issued_to"]
            token = self.accounts.token("account", key, name)
            if not self.round_enabled() or (self.accounts.identity(token) == name and self.credential_version(name) and
                    (self.accounts.expires(name) or 0) - round_service.TOKEN_SECONDS + round_service.ACTIVATION_SECONDS > time.time()):
                return {**response, "token": token}
        return round_service.result(self, action, response)

    def receipt_authorization(self, actor, key, state=None):
        if state is None:
            state = self.snapshot()["state"]
        if not round_service.enabled(state):
            return
        raw = self.db.execute("SELECT details FROM request_context WHERE request_key=?", (key,)).fetchone()
        details = json.loads(raw[0]) if raw else {}
        project = details.get("project_id")
        with delegation.operation_context(state, actor, "read", project, details.get("task_id")):
            if not project or rules.roles(state, project, actor) or rules.system_admin(state, actor):
                return
        if details.get("operation") in {"stop", "handoff"} and any(
                c["origin"] == actor and c["task_id"] == details.get("task_id") for c in state["claims"].values()):
            return "cleanup"
        if details.get('operation') in {'execution-fact','evidence-stash','resource-release','resource-cancel'}:
            return 'cleanup'
        raise ClientError("项目请求不存在或已无查看授权", 404)

    @staticmethod
    def cleanup_receipt(response):
        result = {key: response[key] for key in ("status", "request_id", "head") if key in response}
        result["steps"] = [{key: row[key] for key in ("event_id", "result") if key in row} for row in response.get("steps", [])]
        result["cleanup_only"] = True
        return result

    def recover(self):
        with self.lock:
            pending = self.db.execute("SELECT key FROM requests WHERE status IS NULL AND key NOT IN (SELECT key FROM request_quarantine) ORDER BY rowid").fetchall()
            return all(self.execute(key)[0] != 202 for (key,) in pending)

    def execute(self, key):
        action, raw, raw_plan = self.db.execute(
            "SELECT action, body, plan FROM requests WHERE key=?", (key,)
        ).fetchone()
        body, plan = json.loads(raw), json.loads(raw_plan)
        receipts = []
        snap = self.snapshot()
        for position, instruction in enumerate(plan["steps"]):
            env = self.event(key, position, instruction, snap)
            snap, result = self.apply_step(env, instruction, body, snap)
            receipts.append({"event_id": env["event_id"], "origin_id": env["origin_id"],
                             "origin_seq": env["origin_seq"], "command": env["command"], **result})
            if result["result"] == "pending":
                return 202, {"status": "pending", "request_id": body["request_id"], "steps": receipts}
            if result["result"] != "applied":
                return self.finish(key, 409, body, receipts, snap, plan.get("task_id"))
        task_id = plan.get("task_id")
        if "proposal_id" in plan:
            task_id = snap["state"]["proposals"][plan["proposal_id"]]["task_id"]
        claim_id = plan.get("claim_id")
        if action == "claim":
            claim_id = "c-" + receipts[0]["event_id"]
        if action == "handoff":
            claim = snap["state"]["claims"][claim_id]
            if claim["L"] != "ended" or claim["R"] or snap["state"]["tasks"][task_id]["status"] != "available":
                raise Unavailable("交接步骤已记录，旧领取或资源尚未结束")
        status, response = self.finish(key, 200, body, receipts, snap, task_id, claim_id,
                                       plan.get("enrollment"), plan.get("credential"),
                                       plan.get("round_result"), plan.get("password_change"))
        return status, self.credential_result(key, action, response)

    def event(self, key, position, instruction, snap):
        row = self.db.execute("SELECT envelope FROM steps WHERE request_key=? AND position=?",
                              (key, position)).fetchone()
        if row:
            return json.loads(row[0])
        actor = instruction["actor"]
        payload = dict(instruction["payload"])
        audit = self.db.execute("SELECT details FROM request_context WHERE request_key=?", (key,)).fetchone()
        if audit:
            payload["_audit"] = json.loads(audit[0])
        env = envelope(self.desk.meta["repo_id"], actor, cursor(snap, actor) + 1,
                       instruction["command"], payload, instruction["expects"],
                       event_id=digest(encoded([key, position])))
        with self.db:
            self.db.execute("INSERT INTO steps VALUES(?,?,?)", (key, position, encoded(env)))
        return env

    def apply_step(self, env, instruction, body, snap):
        event_key = env["origin_id"] + "/" + env["event_id"]
        content_sha = digest(encoded(env))
        terminal = snap["control"]["terminal"].get(event_key)
        if not terminal:
            present = any(r["sha256"] == content_sha for r in self.desk.copies())
            if not present:
                if "file" in instruction:
                    path, raw = instruction["file"]
                    store_once(self.desk.store, path, base64.b64decode(raw))
                if "package_prefix" in instruction:
                    files, _, _ = unpack_delivery(instruction.get("generated_package", body))
                    data = ledger_package(env, instruction["package_prefix"], files)
                    package = store_once(self.desk.store, "http-packages/" + content_sha + ".zip", data)
                    import_package(self.desk, package, digest(data), COMMITTER)
                else:
                    self.desk.receive(env, COMMITTER)
            snap = self.desk.process(COMMITTER if COMMITTER in snap["state"]["origins"] else COORDINATOR,
                                     handler=self.ledger_decide)
            if snap["halted"]:
                raise Unavailable("提交期间账本停写")
            terminal = snap["control"]["terminal"].get(event_key)
        if not terminal:
            return snap, {"result": "pending"}
        if terminal["content_sha256"] != content_sha:
            raise Unavailable("持久请求与账本决定的信封不一致")
        return snap, {key: terminal[key] for key in ("result", "reason", "ledger_seq", "sha256")}

    def ledger_decide(self, state, env, context):
        pending=self.db.execute('SELECT s.envelope FROM steps s JOIN request_quarantine q ON q.key=s.request_key').fetchall()
        if any((prior:=json.loads(row[0])).get('event_id')==env.get('event_id') and
               prior.get('origin_id')==env.get('origin_id') and digest(encoded(prior))==digest(encoded(env)) for row in pending):
            raise Rejected('原请求已隔离，须经关联新请求按当前授权接续；旧信封不重放','intent-final')
        context['phase'] = self.lifecycle.status()['phase']
        context.update(self.desk.evidence_context(env, state))
        return upgrade.decide(state, env, context)

    def finish(self, key, status, body, receipts, snap, task_id=None, claim_id=None, enrollment=None, credential=None,
               extra=None, password_change=None):
        response = {"status": "applied" if status == 200 else "rejected",
                    "request_id": body["request_id"], "head": snap["head"], "steps": receipts}
        state = snap["state"]
        record = self.db.execute("SELECT actor FROM requests WHERE key=?", (key,)).fetchone()
        visible = not (task_id and round_service.enabled(state)) or self.visible(state, state["tasks"][task_id], record[0])
        if task_id and visible:
            response["task"] = snap["state"]["tasks"][task_id]
        if claim_id and visible:
            claim = snap["state"]["claims"][claim_id]
            response["claim"] = claim
            if claim["L"] == "active":
                response["initial_inputs"] = [{"path": p, "sha256": sha} for p, sha in claim["inputs"].items()]
                response["handoffs"] = self.handoffs(snap["state"], response["task"])
            elif handoff := handoff_reference(claim):
                response["handoff"] = handoff
        if status == 200 and "package_sha256" in body:
            response["package_sha256"] = body["package_sha256"]
        if extra:
            response.update(extra)
        with self.db:
            if enrollment:
                name = enrollment["name"]
                subject = rules.identity(state, name) or {}
                if registration := enrollment.get("round_registration"):
                    record = state["round"]["enrollment:" + registration]
                    self.accounts.issue_executor(name, round_service.token_for(self, record), record["expires"], subject["credential"])
                else:
                    self.accounts.enroll(key, enrollment)
                    if enrollment.get("password_signup"):
                        self.passwords.apply(key, "signup", name)
                    if round_service.enabled(state) and subject.get("kind") == "executor":
                        self.accounts.issue_executor(name, self.accounts.token("account", key, name),
                                                     int(subject["last_contact"]) + round_service.TOKEN_SECONDS, subject["credential"])
                    elif subject.get("kind") == "executor":
                        self.accounts.bind_executor(name, subject["credential"])
                response["account"] = name
                if subject.get("window"):
                    response.update(executor_id=name, window=subject["window"], issued_to=name)
            if password_change:
                if password_change["kind"] == "reset-issued":
                    self.passwords.issue_reset(password_change["issuer"], key, password_change["name"])
                else:
                    self.passwords.apply(key, password_change["kind"], password_change["name"])
            if credential:
                self.accounts.change_credential(key, credential)
                subject = rules.identity(state, credential["name"]) or {}
                if credential["enabled"] and subject.get("kind") == "executor":
                    self.accounts.bind_executor(credential["name"], subject["credential"])
                response["account"] = credential["name"]
                if credential["enabled"]:
                    response["issued_to"] = credential["name"]
            self.db.execute("UPDATE requests SET status=?, response=?, body=?, plan=NULL WHERE key=?",
                            (status, encoded(response), b"{}", key))
        return status, response

    @staticmethod
    def handoffs(state, task):
        return [ref for cid in task["claims"] if (ref := handoff_reference(state["claims"][cid]))]

    def account_actor(self, token):
        with self.lock:
            actor = self.accounts.identity(token)
            if not actor or not self.passwords.legacy_allowed(actor):
                return None
            state = self.snapshot()["state"]
            subject = rules.identity(state, actor) or {}
            if subject.get("kind") == "executor" and not self.accounts.executor_current(actor, subject.get("credential"), token):
                return None
            return actor

    def round_enabled(self):
        with self.lock:
            return round_service.enabled(self.snapshot()["state"])

    def session_version(self, actor):
        with self.lock:
            version = self.credential_version(actor)
            return (version, self.passwords.version(actor)) if version else None

    def credential_version(self, actor, bootstrap=False):
        with self.lock:
            state = self.snapshot()["state"]
            if not rules.enabled(state):
                return 1
            subject = rules.identity(state, actor)
            if (not subject or subject["status"] != "active" or
                    subject["kind"] == "executor" and not rules.active(state, subject["owner"]) or
                    bootstrap and (subject["credential"] != 1 or not self.passwords.legacy_allowed(actor) or
                                   subject["kind"] == "executor" and self.accounts.role(actor) is not None)):
                return None
            if subject["kind"] == "executor" and not (self.accounts.executor_current(actor, subject["credential"]) or
                                                       self.accounts.legacy_executor_bootstrap(state, actor)):
                return None
            return subject["credential"]

    def is_admin(self, actor):
        return self.accounts.role(actor) == "admin"

    def roles(self, state, actor):
        return ["admin"] if self.is_admin(actor) else state["origins"].get(actor, {}).get("roles", [])

    def invite(self, actor, request_id, role):
        if not ID.fullmatch(request_id):
            raise ClientError("邀请码请求编号无效")
        with self.lock:
            if not self.is_admin(actor):
                raise ClientError("仅管理员可生成邀请码", 403)
            return self.accounts.invite(actor, request_id, role)

    def signup(self, request_id, name, invitation):
        if not ID.fullmatch(request_id) or not ID.fullmatch(name) or name.casefold() == ADMIN:
            raise ClientError("身份须以字母或数字开头，可包含连字符或下划线")
        if not ACCESS_TOKEN.fullmatch(invitation):
            raise ClientError("邀请码无效", 403)
        invite_sha = digest(invitation.encode("ascii"))
        data = {"request_id": "signup-" + digest(encoded([invite_sha, request_id])),
                "name": name, "invite_sha": invite_sha}
        key = digest(encoded([COORDINATOR, data["request_id"]]))
        with self.lock:
            if not self.db.execute("SELECT 1 FROM requests WHERE key=?", (key,)).fetchone():
                self.accounts.invited_role(invite_sha)
                if name.casefold() in {origin.casefold() for origin in self.snapshot()["state"]["origins"]}:
                    raise ClientError("这个身份已登记", 409)
            return self.enroll("signup", data)

    def initialize_admin(self):
        return self.enroll("initialize-admin", {"request_id": "initialize-admin-v1", "name": ADMIN})

    def enroll(self, action, data):
        status, result = self.submit(COORDINATOR, action, data["request_id"], data)
        if status != 200:
            return status, result
        key = digest(encoded([COORDINATOR, data["request_id"]]))
        return status, {"identity": result["account"], "token": self.accounts.token("account", key, result["account"])}

    def plan(self, actor, action, key, body, snap):
        state = snap["state"]
        generation = {"generation": state["generation"]}
        from . import execution
        if prepared := execution.plan(self, actor, action, key, body, state):
            return prepared
        if prepared := delegation.plan(self, actor, action, key, body, state):
            return prepared
        from . import window_admin
        if prepared := window_admin.plan(self, actor, action, key, body, state):
            return prepared
        if prepared := round_service.plan(self, actor, action, key, body, state):
            return prepared
        if prepared := upgrade.plan(self, actor, action, key, body, snap):
            return prepared
        if actor == COORDINATOR and action == "bootstrap":
            steps = [step(actor, "register_origin",
                          {"origin_id": name, "roles": [role], "local": name == COMMITTER,
                           "authority_ref": "bootstrap"}, generation) for name, role in body["origins"].items()]
            return {"steps": steps}
        if actor == COORDINATOR and action == "add-task":
            return self.registration(actor, key, body["title"], body["criteria"], body["receiver"],
                                     body["path"], base64.b64decode(body["input"]), generation)
        if actor == COORDINATOR and action in {"initialize-admin", "signup", "signup-password"}:
            name = body["name"]
            if name.casefold() in {origin.casefold() for origin in state["origins"]}:
                raise ClientError("这个身份已登记", 409)
            registration = {"name": name, "role": "admin"}
            if action in {"signup", "signup-password"}:
                invite_sha = body["invite_sha"]
                registration.update(role=self.accounts.invited_role(invite_sha), invite_sha=invite_sha)
                if action == "signup-password":
                    registration["password_signup"] = True
            ledger_role = "proposer" if registration["role"] == "admin" else registration["role"]
            origin = step(COORDINATOR, "register_origin", {
                "origin_id": name, "roles": [ledger_role], "local": False, "authority_ref": "bootstrap",
                "person_signup": action in {"signup", "signup-password"},
            }, generation)
            return {"steps": [origin], "enrollment": registration}
        role = self.roles(state, actor)
        if "admin" in role and rules.enabled(state):
            # Administration and project work are separate grants. A human admin
            # assigned as receiver still needs their explicit project role here.
            _, project = upgrade.target(state, body)
            if project:
                role = [*role, *rules.roles(state, project, actor)]
        admin_action = "admin" in role and action in {"register", "cancel"}
        required_role = "receiver" if action in {"register", "review", "return", "close", "cancel"} else "executor"
        if not admin_action and required_role not in role:
            raise ClientError("该身份无权执行此操作", 403)
        if action == "register":
            required = "request_id title brief criteria" + (" receiver" if admin_action else "")
            fields(body, required + (" project" if "project" in body else ""))
            project = string(body["project"], "所属项目", 100).strip() if "project" in body else None
            receiver = string(body["receiver"], "接收者", 80) if admin_action else actor
            if "receiver" not in state["origins"].get(receiver, {}).get("roles", []):
                raise ClientError("须选择已登记的接收者")
            title = string(body["title"], "任务标题", 200)
            raw = string(body["brief"], "任务说明", 40000).encode("utf-8")
            criteria = body["criteria"]
            if not isinstance(criteria, list) or not 1 <= len(criteria) <= 30:
                raise ClientError("须填写 1 至 30 条完成判据")
            criteria = [string(item, "完成判据", 100) for item in criteria]
            if len(set(criteria)) != len(criteria):
                raise ClientError("完成判据不能重复")
            return self.registration(actor, key, title, criteria, receiver, f"inputs/{digest(raw)}/brief.md",
                                     raw, generation, project)
        if action == "claim":
            fields(body, "request_id task_id version scope_version" +
                   ''.join(' '+k for k in ('notice','execution_protocol','context_id','context_version') if k in body))
            if state.get('security', {}).get('schema', 0) >= 5 and body.get('execution_protocol') != 5:
                raise ClientError('领取需要支持执行协议5的客户端；请更新客户端，旧领取仍可受限收尾',409)
            task_id = string(body["task_id"], "task_id", 16)
            if task_id not in state["tasks"] or not rules.visible(state, state["tasks"][task_id], actor):
                raise ClientError("任务不存在", 404)
            if rules.enabled(state):
                selected=None
                if state.get('security',{}).get('schema',0)>=5 and body.get('context_id'):
                    from 协作执行 import context_record
                    if 'context_version' not in body:
                        raise ClientError('指定配置时须同时提供配置版本')
                    selected=context_record(state,actor,{'context_id':body['context_id'],'version':body['context_version']})
                missing, _ = rules.eligible(state, state["tasks"][task_id], actor, time.time(),execution_context=selected)
                if missing:
                    raise ClientError("；".join(missing), 409)
            version = integer(body["version"], "version")
            scope = integer(body["scope_version"], "scope_version")
            payload = {"task_id": task_id}
            payload.update({k:body[k] for k in ('execution_protocol','context_id','context_version') if k in body})
            if "notice" in body:
                notice = upgrade.sha256(body["notice"])
                if not round_service.enabled(state) or not self.notices.acknowledged(actor, notice):
                    raise ClientError("请先确认有效的执行端通知", 409)
                payload["notice"] = notice
            return {"task_id": task_id, "steps": [step(actor, action, payload,
                    {"task:" + task_id: version, "scope:" + task_id: scope})]}
        if action == "close":
            fields(body, "request_id task_id")
            task_id = string(body["task_id"], "task_id", 16)
            self.receiver(state, task_id, actor)
            if state["tasks"][task_id]["status"] != "pending_close":
                raise ClientError("任务须已接受，且执行已停止、资源已释放", 409)
            return {"task_id": task_id, "steps": [step(COORDINATOR, "close", {"task_id": task_id}, generation)]}
        if action == "cancel":
            fields(body, "request_id task_id version reason")
            task_id = string(body["task_id"], "task_id", 16)
            project_manager = round_service.enabled(state) and rules.manager(state, rules.task_project(state["tasks"].get(task_id)), actor)
            if not admin_action and not project_manager:
                self.receiver(state, task_id, actor)
            elif task_id not in state["tasks"]:
                raise ClientError("任务不存在", 404)
            task = state["tasks"][task_id]
            version = integer(body["version"], "version")
            if (task["status"] not in {"available", "running"} or task.get("cancel_requested")
                    or task.get("accepted") or version != task["version"]):
                raise ClientError("任务已变更、已验收或已请求取消", 409)
            reason = string(body["reason"], "取消原因")
            cancel = step(COORDINATOR, "cancel", {"task_id": task_id, "authority_ref": "bootstrap",
                          "reason": reason, "requested_by": actor}, {**generation, "task:" + task_id: version})
            note = step(actor, "note", {"text": reason, "related": {"task_id": task_id, "kind": "cancel"}})
            return {"task_id": task_id, "steps": [cancel, note]}
        suffix = {
            "handoff": "epoch scope_version stop_evidence notes",
            "deliver": "epoch scope_version package_sha256 package",
            "deliver-files": "epoch scope_version files",
            "stop": "epoch scope_version stop_evidence",
            "resume": "epoch scope_version",
            "withdraw": "epoch scope_version revision reason",
            "review": "revision manifest_sha256 checks",
            "return": "revision manifest_sha256 criterion reason",
        }[action]
        optional = ""
        if round_service.enabled(state):
            name = {"deliver-files": "stop_evidence", "review": "finish", "return": "criteria"}.get(action)
            optional = f" {name}" if name and name in body else ""
        if action=='resume':
            optional+=''.join(' '+k for k in ('execution_protocol','context_id','context_version') if k in body)
            if state.get('security',{}).get('schema',0)>=5 and body.get('execution_protocol')!=5:
                raise ClientError('继续任务需要执行协议5；旧回合事实和已有产物保留',409)
        fields(body, "request_id claim_id " + suffix + optional)
        cid = string(body["claim_id"], "claim_id", 100)
        claim = state["claims"].get(cid)
        if not claim:
            raise ClientError("领取不存在", 404)
        task_id = claim["task_id"]
        if action in {"review", "return"}:
            self.receiver(state, task_id, actor)
            if state["tasks"][task_id].get("cancel_requested"):
                raise ClientError("任务已请求取消，等待持有者停止", 409)
            instruction = self.review(actor, body, claim, state, action)
            steps = [instruction]
            # With the holder's stop already on record, acceptance can finish the task in one request.
            if action == "review" and body.get("finish") is True and not claim["R"] and claim["E"] == {"state": "stopped", "reason": "complete"}:
                steps.append(step(COORDINATOR, "close", {"task_id": task_id}, generation))
            return {"task_id": task_id, "claim_id": cid, "steps": steps}
        if claim["origin"] != actor:
            raise ClientError("该领取属于其他执行者", 403)
        epoch = integer(body["epoch"], "epoch")
        scope = integer(body["scope_version"], "scope_version")
        if claim["L"] != "active" or epoch != claim["epoch"] or scope != claim["W"]["scope"]:
            raise ClientError("领取已结束或执行代次、范围已变化", 409)
        expects = {"epoch:" + cid: epoch, "scope:" + task_id: scope}
        if claim.get("recovery", {}).get("status") == "pending" and action not in {"stop", "withdraw"}:
            raise ClientError("领取处于恢复待核，须先处理在途操作及占用", 409)
        if action in {"deliver", "deliver-files"}:
            if action == "deliver-files":
                package = self.file_package(claim, body["files"])
                instruction = self.deliver(actor, key, package, claim, expects)
                instruction["generated_package"] = package
                steps = [instruction]
                if "stop_evidence" in body:
                    proof = string(body["stop_evidence"], "stop_evidence")
                    steps.append(step(actor, "stopped", {"claim_id": cid, "evidence": proof,
                                      "ended": [{"reservation_id": rid, "evidence": proof} for rid in claim["R"]]}, expects))
                return {"task_id": task_id, "claim_id": cid, "steps": steps}
            instruction = self.deliver(actor, key, body, claim, expects)
            return {"task_id": task_id, "claim_id": cid, "steps": [instruction]}
        if action == "resume":
            task = state["tasks"][task_id]
            extra_resume={k:body[k] for k in ('execution_protocol','context_id','context_version') if k in body}
            extra_resume['scope_version']=scope
            if rules.contract(task) and claim["E"] == {"state": "stopped", "reason": "pause"}:
                instructions = []
                if claim["scope_ack_pending"]:
                    instructions.append(step(actor, "ack_scope", {"claim_id": cid}, expects))
                instructions.append(step(COORDINATOR, "resume",
                                         {"claim_id": cid, "authority_ref": "bootstrap", "baseline": task["inputs"],**extra_resume},
                                         {**generation, **expects}))
                return {"task_id": task_id, "claim_id": cid, "steps": instructions}
            if claim["W"]["state"] != "revision" or claim["E"] != {"state": "stopped", "reason": "complete"}:
                raise ClientError("开始返修前须完成上一次执行的实际停止", 409)
            previous = claim["deliveries"][claim["W"]["revision"]]["manifest"]
            baseline = {**claim["inputs"], previous["path"]: previous["sha256"]}
            return {"task_id": task_id, "claim_id": cid, "steps": [
                step(actor, "acquire", {"claim_id": cid, "baseline": baseline,**extra_resume}, expects)]}
        if action == "withdraw":
            if rules.enabled(state) and "executor" not in rules.roles(state, rules.task_project(state["tasks"][task_id]), actor):
                raise ClientError("撤回交付需要当前项目执行权限", 403)
            if not rules.contract(state["tasks"][task_id]) or claim["W"]["state"] != "review":
                raise ClientError("须有本项目的待验封存修订", 409)
            return {"task_id": task_id, "claim_id": cid, "steps": [step(
                actor, "withdraw_delivery", {"claim_id": cid, "revision": string(body["revision"], "revision", 32),
                                              "reason": string(body["reason"], "撤回依据")}, expects)]}
        proof = string(body["stop_evidence"], "stop_evidence")
        ended = [{"reservation_id": rid, "evidence": proof} for rid in claim["R"]]
        if action == "stop":
            execution = claim["E"]["state"]
            if execution != "requested" and (execution != "running" or claim["W"]["state"] not in {
                    "review", "complete", "revision"}):
                raise ClientError("须已有交付或停止请求，且当前领取尚未停止", 409)
            return {"task_id": task_id, "claim_id": cid, "steps": [step(
                actor, "stopped", {"claim_id": cid, "evidence": proof, "ended": ended}, expects)]}
        if claim["W"]["state"] not in {"draft", "revision"} or claim["E"]["state"] not in {"running", "stopped"}:
            raise ClientError("须在执行或返修阶段完成实际停止后交接", 409)
        note = string(body["notes"], "notes", 16000)
        raw = encoded({"task_id": task_id, "claim_id": cid, "origin_id": actor, "epoch": epoch,
                       "scope_version": scope, "stop_evidence": proof, "notes": note, "inputs": claim["inputs"],
                       "deliveries": [rev["manifest"] for rev in claim["deliveries"].values()]})
        path = f"handoffs/{cid}/{digest(raw)}.json"
        replace = step(COORDINATOR, "replace_claim",
                       {"claim_id": cid, "replacement": path, "reason": "持有者已报告实际停止并提交接续材料"},
                       {**generation, **expects})
        replace["file"] = [path, base64.b64encode(raw).decode("ascii")]
        if claim["E"]["state"] == "stopped":
            releases = [step(actor, "release", {"claim_id": cid, **r}, {**expects, "epoch:" + cid: epoch + 1})
                        for r in ended]
            return {"task_id": task_id, "claim_id": cid, "steps": [replace, *releases]}
        stopped = step(actor, "stopped", {"claim_id": cid, "evidence": proof, "ended": ended},
                       {**expects, "epoch:" + cid: epoch + 1})
        return {"task_id": task_id, "claim_id": cid, "steps": [replace, stopped]}

    @staticmethod
    def registration(actor, key, title, criteria, receiver, path, raw, generation, project=None):
        proposal = digest(encoded([key, 0]))
        first = step(actor, "propose", {"title": title})
        first["file"] = [path, base64.b64encode(raw).decode("ascii")]
        second = step(COORDINATOR, "register", {
            "proposal_id": proposal, "kind": "documentation", "authority_ref": "bootstrap",
            "completes_on": criteria, "requires_commit": False, "receiver": receiver, "inputs": {path: digest(raw)},
        }, generation)
        if project is not None:
            second["payload"]["related"] = {"project": project}
        return {"steps": [first, second], "proposal_id": proposal}

    @staticmethod
    def file_package(claim, files):
        if not isinstance(files, list) or not 1 <= len(files) <= 10:
            raise ClientError("请选择 1 至 10 个交付文件")
        artifacts = {}
        seen = set()
        total = 0
        for item in files:
            fields(item, "name content")
            name = artifact_name(item["name"])
            if "/" in name or name.casefold() in seen:
                raise ClientError("交付文件名必须唯一且不含目录")
            try:
                raw = base64.b64decode(item["content"], validate=True)
            except (ValueError, TypeError) as error:
                raise ClientError("交付文件内容无效") from error
            total += len(raw)
            if total > MAX_PACKAGE - 65536:
                raise ClientError("交付文件总大小超出限制", 413)
            seen.add(name.casefold())
            artifacts[name] = raw
        package = make_delivery(claim, artifacts)
        return {"package": base64.b64encode(package).decode("ascii"), "package_sha256": digest(package)}

    @staticmethod
    def receiver(state, task_id, actor):
        task = state["tasks"].get(task_id)
        if not task:
            raise ClientError("任务不存在", 404)
        if task["receiver"] != actor:
            raise ClientError("仅指定接收者可以操作", 403)

    @staticmethod
    def deliver(actor, key, body, claim, expects):
        if claim["W"]["state"] != "draft" or claim["E"]["state"] != "running":
            raise ClientError("当前领取无法封存", 409)
        files, data, receipt = unpack_delivery(body)
        revision = "revision-" + str(len(claim["deliveries"]) + 1)
        meta = seal_metadata(claim, revision)
        if encoded(receipt) != encoded(meta) or encoded({k: v for k, v in data.items() if k != "outputs"}) != encoded({
            **{k: meta[k] for k in ("claim_id", "revision", "scope_version", "inputs")}, "task_id": claim["task_id"]
        }):
            raise ClientError("交付清单与本次领取、输入、范围或修订不匹配")
        prefix = f"deliveries/{claim['task_id']}/{claim['claim_id']}/{revision}/{key}"
        ref = reference(prefix + "/manifest.json", files["manifest.json"])
        result = step(actor, "seal", {**meta, "manifest": ref, "manifest_sha256": ref["sha256"],
                      "client_package_sha256": body["package_sha256"]}, expects)
        result["package_prefix"] = prefix
        return result

    def review(self, actor, body, claim, state, action):
        revision = string(body["revision"], "revision", 32)
        delivery = claim["deliveries"].get(revision)
        if (not delivery or body["manifest_sha256"] != delivery["manifest_sha256"] or
                claim["W"]["state"] != "review" or claim["W"]["revision"] != revision):
            raise ClientError("修订号或待验清单 SHA256 不匹配", 409)
        if claim["origin"] == actor and not rules.user_acceptance(state, state["tasks"][claim["task_id"]], actor):
            raise ClientError("持有者不能自行验收", 403)
        payload = {"claim_id": claim["claim_id"], "revision": revision, "verdict": "accept",
                   "manifest": delivery["manifest"], "manifest_sha256": body["manifest_sha256"]}
        if action == "return":
            criterion = string(body["criterion"], "完成判据", 100)
            reason = string(body["reason"], "返修要求")
            picked = body.get("criteria", [criterion])
            if (not isinstance(picked, list) or not picked or len(set(map(str, picked))) != len(picked) or criterion not in picked or
                    any(item not in delivery["criteria"] for item in picked)):
                raise ClientError("须选择该修订的完成判据")
            payload.update(verdict="revision", reason=reason, checks=[
                {"id": item, "status": "failed", "level": "static", "evidence": {"note": reason}} for item in picked
            ], remaining=[{"check_id": item, "criterion": item, "description": reason,
                           "kind": "failed", "required": True, "disposition": "within"} for item in picked])
            return step(actor, "review", payload)
        refs = self.delivery_refs(delivery["manifest"])
        if not isinstance(body["checks"], list) or not 1 <= len(body["checks"]) <= 30:
            raise ClientError("须逐项提供验收检查和产物证据")
        checks = []
        for check in body["checks"]:
            fields(check, "id path sha256 note")
            ref = {"path": string(check["path"], "path", 650), "sha256": check["sha256"]}
            if ref not in refs:
                raise ClientError("验收证据须引用本修订的实际输出")
            checks.append({"id": string(check["id"], "id", 100), "status": "passed", "level": "static",
                           "evidence": {"artifact": ref, "note": string(check["note"], "note")}})
        passed = {check["id"] for check in checks}
        resolved = [item for item in state["items"].values()
                    if item["holder"] == claim["task_id"] and item["status"] == "unresolved"
                    and item["kind"] == "failed" and item["criterion"] in passed
                    and state["acceptances"].get(item["source_record"], {}).get("verdict") == "revision"]
        payload.update(checks=checks, resolve=[
            {"item_id": item["item_id"], "check_id": item["criterion"]} for item in resolved
        ])
        return step(actor, "review", payload, {"item:" + item["item_id"]: item["version"] for item in resolved})

    def delivery_refs(self, ref):
        _, data = manifest(self.desk, ref)
        parent = ref["path"].rsplit("/", 1)[0]
        return [{"path": parent + "/" + item["path"], "sha256": item["sha256"].lower()} for item in data["outputs"]]

    def visible(self, state, task, actor):
        with delegation.operation_context(state, actor, "read", rules.task_project(task), task["task_id"]):
            return rules.visible(state, task, actor)

    def task_roles(self, state, task, actor):
        with delegation.operation_context(state, actor, "claim", rules.task_project(task), task["task_id"]):
            return sorted(rules.roles(state, rules.task_project(task), actor))

    def independent_roles(self, state, task, actor):
        with delegation.operation_context(state, actor, "read", rules.task_project(task), task["task_id"], audit={}):
            return sorted(rules.roles(state, rules.task_project(task), actor))

    def delegated_actions(self, state, task, actor):
        result = []
        for operation in sorted(delegation.DELEGATION_ACTIONS):
            with delegation.operation_context(state, actor, operation, rules.task_project(task), task["task_id"]):
                if delegation.stamp(state, actor, rules.task_project(task)):
                    result.append(operation)
        return result

    def _delivery_reviews(self, state, task, claims, entries=None):
        """Project exact sealed-revision acceptance facts without changing stored records."""
        from copy import deepcopy
        result = []
        for claim in claims:
            for name, delivery in claim.get("deliveries", {}).items():
                acceptance_id = delivery.get("acceptance_id")
                review = state.get("acceptances", {}).get(acceptance_id)
                if (not review or review.get("acceptance_id") != acceptance_id or review.get("task_id") != task["task_id"] or
                        review.get("claim_id") != claim["claim_id"] or review.get("revision") != name or
                        delivery.get("revision", name) != name or review.get("manifest_sha256") != delivery.get("manifest_sha256") or
                        review.get("scope_version") != delivery.get("scope_version") or
                        review.get("manifest") is not None and review["manifest"] != delivery.get("manifest")):
                    continue
                if entries is None:
                    entries = self.snapshot().get("entries", [])
                event = next((entry for entry in entries if entry.get("type") == "decision" and entry.get("result") == "applied" and
                              entry.get("command") == "review" and entry.get("key") == str(review.get("origin")) + "/" + str(acceptance_id) and
                              entry.get("origin_id") == review.get("origin") and
                              (review.get("seq") is None or entry.get("ledger_seq") == review["seq"]) and
                              any(effect.get("path") == ["acceptances", acceptance_id] and effect.get("value") == review
                                  for effect in entry.get("effects", []))), None)
                failed = [check["id"] for check in review.get("checks", []) if check.get("status") in {"failed", "not-run"}]
                notes = list(dict.fromkeys(check.get("evidence", {}).get("note") for check in review.get("checks", [])
                                           if check.get("id") in failed and isinstance(check.get("evidence"), dict) and
                                           isinstance(check["evidence"].get("note"), str) and check["evidence"]["note"]))
                request = (event or {}).get("request", {})
                reason = request.get("reason") if isinstance(request.get("reason"), str) and request["reason"] else "\n".join(notes)
                metadata = {"acceptance_id": acceptance_id, "failed_criteria": failed, "reason": reason,
                            "reviewer": request.get("actor") or review.get("origin"),
                            "at": (event or {}).get("committed_utc"), "source_event": (event or {}).get("key")}
                result.append({"claim_id": claim["claim_id"], "revision": name, "manifest": deepcopy(delivery.get("manifest")),
                               "manifest_sha256": delivery.get("manifest_sha256"), **metadata,
                               "review": {**deepcopy(review), **metadata}})
        return result

    def task_view(self, state, task, actor):
        if not self.visible(state, task, actor):
            raise ClientError("任务不存在或无权查看", 404)
        claims = [state["claims"][cid] for cid in task["claims"]]
        admin = self.is_admin(actor) or round_service.enabled(state) and rules.manager(state, rules.task_project(task), actor)
        from copy import deepcopy
        permitted = [c for c in claims if admin or actor in {c["origin"], task["receiver"]}]
        spec = rules.contract(task)
        project = rules.project_record(state, spec["project_id"]) if spec else None
        return {"task": {**task, "project_name": project["name"]} if project else task,
                "stage": stage(task, active_claim(state, task), state),
                'execution_status':execution_status(state,active_claim(state,task)),
                "claims": deepcopy(permitted),
                'execution_protocol':5 if state.get('security',{}).get('schema')==5 else None,
                'default_context':state.get('security',{}).get('execution',{}).get('defaults',{}).get(actor),
                'execution_contexts':[deepcopy(row) for row in state.get('security',{}).get('execution',{}).get('contexts',{}).values()
                                      if row.get('executor_id')==actor],
                "delivery_reviews": self._delivery_reviews(state, task, [c for c in permitted if
                    actor in {c["origin"], task["receiver"]} or self.is_admin(actor) or rules.system_admin(state, actor)]),
                "handoffs": self.handoffs(state, task) if any(c["origin"] == actor and c["L"] == "active"
                                                          for c in claims) or actor == task["receiver"] or admin else [],
                "qualification": self.qualification(state, task, actor)}

    def qualification(self, state, task, actor):
        with delegation.operation_context(state, actor, "claim", rules.task_project(task), task["task_id"]):
            return self._qualification(state, task, actor)

    def _qualification(self, state, task, actor):
        if not rules.enabled(state):
            return None
        missing, preferred = rules.eligible(state, task, actor, time.time())
        gate = (rules.contract(task) or {}).get("gate")
        if state["pilot"]["format"]["maintenance"]:
            missing.append("服务维护中")
        if gate:
            release = state["pilot"].get("release:" + gate, {})
            if release.get("status") == "closed":
                try:
                    rules.verify_report(state, json.loads(checked_file(self.desk.store, release["evidence"])), gate)
                except (KeyError, ValueError, OSError, Rejected):
                    missing.append("升级收口证据待复核")
        result = {"eligible": not missing, "missing": missing, "preferred": preferred}
        if round_service.enabled(state):
            from 协作本轮 import policy, target_match
            mode = policy(task)["mode"]
            result.update(mode=mode, prioritized=mode == "prefer" and target_match(state, task, actor, time.time()))
        return result

    def detail(self, state, task, actor):
        view = self.task_view(state, task, actor)
        current = active_claim(state, task)
        participant = view["claims"] or actor == task["receiver"] or self.is_admin(actor)
        deliveries = []
        for claim in view["claims"]:
            for revision in claim["deliveries"].values():
                ref = revision["manifest"]
                try:
                    outputs = self.delivery_refs(ref)
                except (OSError, ValueError, KeyError, TypeError):
                    outputs = []
                review = state["acceptances"].get(revision.get("acceptance_id"))
                deliveries.append({"claim_id": claim["claim_id"], "revision": revision, "outputs": outputs,
                                   "review": review})
        return {**view, "active": current if current in view["claims"] else None,
                "roles": self.task_roles(state, task, actor) if rules.contract(task) else self.roles(state, actor),
                "direct_roles": self.independent_roles(state, task, actor) if rules.contract(task) else self.roles(state, actor),
                "delegated_actions": self.delegated_actions(state, task, actor),
                "deliveries": deliveries,
                "window": (rules.identity(state, current["origin"]) or {}).get("window") if current else None,
                "window_name": (rules.identity(state, current["origin"]) or {}).get("window_name") if current else None,
                "window_id": current["origin"] if current else None,
                "round": round_service.enabled(state),
                "items": [item for item in state["items"].values()
                          if participant and item["source_task"] == task["task_id"]],
                "close": state["closings"].get(task.get("close_id")) if participant else None,
                "cancel_note": next((note for note in state["notes"].values() if participant and
                                     note["related"] == {"task_id": task["task_id"], "kind": "cancel"}), None)}

    def members(self, state, project):
        return [{"identity": key.rsplit(":", 1)[1], **record,
                 "kind": (rules.identity(state, key.rsplit(":", 1)[1]) or {}).get("kind"),
                 "window_name": (rules.identity(state, key.rsplit(":", 1)[1]) or {}).get("window_name"),
                 "window": (rules.identity(state, key.rsplit(":", 1)[1]) or {}).get("window")}
                for key, record in state["pilot"].items() if key.startswith(f"grant:{project}:")]

    def capability_rows(self, state, actor, name):
        """Return whether the actor may look at a subject's capability records, and the records it may see."""
        owner = rules.responsible(state, name)
        allowed_projects = {p["id"] for p in upgrade.projects(state, actor)
                            if {"manager", "receiver"} & set(p["roles"]) and rules.grant(state, p["id"], name)["roles"]}
        permitted = actor in {name, owner} or self.is_admin(actor)
        rows = []
        for key, record in state["pilot"].items():
            if key.startswith("cap:"):
                _, project, subject, cap_id = key.split(":")
                if subject == name and (permitted or project in allowed_projects):
                    rows.append({"id": cap_id, "project_id": project, **record})
        return permitted or bool(allowed_projects), rows

    def feedback_due(self, state, actor, project=None):
        return sum(1 for key, record in state["round"].items()
                   if key.partition(":")[0] == "feedback" and record["status"] in {"triage", "review"}
                   and (not project or record["project_id"] == project)
                   and rules.manager(state, record["project_id"], actor))

    @staticmethod
    def task_summary(task):
        result={k:task[k] for k in ('task_id','title','status','stage','version','scope_version','priority',
                    'project_name','qualification','holder','holder_window','holder_window_name','receiver') if k in task}
        result['project_id']=rules.task_project(task)
        return result

    def read(self, actor, route, argument=None):
        with self.lock:
            snap = self.snapshot()
            state = snap["state"]
            list_full = state.get('security',{}).get('schema',0)<5
            if route in {'tasks','task-options'} and isinstance(argument,dict):
                list_full = argument.get('full') == '1'
                argument = argument.get('project')
            tasks = state["tasks"]
            upgraded = rules.enabled(state)
            visible_tasks = [task for task in tasks.values() if self.visible(state, task, actor)]
            round_enabled = round_service.enabled(state)
            from . import execution
            if route == 'features':
                from .input_packages import BUDGET
                result=execution.features(state)
                result.update(api_protocol=1,input_download=dict(BUDGET))
                result.setdefault('features',{})['input-package']=True
                result['features']['list-summary']=True
                return result
            if route == 'execution':
                return execution.read(state, actor, argument)
            if route == "window-impact":
                from . import window_admin
                return window_admin.view(state, actor, argument)
            if route == "capability-requests":
                from . import window_admin
                return window_admin.requests_view(state, actor)
            if route == "cleanup":
                return {"claims": [{"claim_id": c["claim_id"], "task_id": c["task_id"], "epoch": c["epoch"],
                                    "W": {"scope": c["W"]["scope"]}, "origin": actor, "L": c["L"]}
                                   for c in state["claims"].values() if c["origin"] == actor and c["L"] == "active"]}
            if round_enabled and route == "invitations":
                return round_service.invitations(state, actor)
            if round_enabled and route == "runner":
                contacts = self.notices.contacts()
                return {"settings": round_service.execution_settings(state, actor), "last_contact": contacts.get(actor),
                        "load": rules.execution_load(state, actor),
                        "automation": {p["id"]: state["round"].get("automation:" + p["id"], {"enabled": False, "version": 0})
                                       for p in upgrade.projects(state, actor)}}
            if round_enabled and route == "notices":
                rows = self.db.execute("SELECT event_id,task,attempts,sent,ack FROM round_notices WHERE actor=? ORDER BY seq DESC LIMIT 100",
                                       (actor,))
                return {"notices": [{"event_id": event, "task_id": task, "attempts": attempts, "sent": sent,
                                     "acknowledged": ack} for event, task, attempts, sent, ack in rows
                                    if task in tasks and self.visible(state, tasks[task], actor)]}
            if round_enabled and route == "collaboration":
                from .round_projects import view
                return view(state, actor, argument)
            if route == "sheet":
                if argument not in tasks:
                    raise ClientError("任务不存在", 404)
                task = tasks[argument]
                view = self.detail(state, task, actor)
                brief = next((checked_file(self.desk.store, {"path": path, "sha256": sha}).decode("utf-8")
                              for path, sha in task["inputs"].items() if path.endswith("/brief.md")), "")
                return {"view": view, "brief": brief, "events": upgrade.audit_rows(self, snap, actor, {"task": argument})}
            if route == "tasks":
                available = []
                for task in visible_tasks:
                    if task["status"] != "available" or argument and rules.task_project(task) != argument:
                        continue
                    if upgraded:
                        qualified = self.qualification(state, task, actor)
                        if not qualified["eligible"]:
                            continue
                        task = {**task, "qualification": qualified}
                    available.append(task)
                if round_enabled:
                    available.sort(key=lambda task: (not task["qualification"]["prioritized"], -task["priority"], task["created_seq"]))
                if not list_full:
                    available=[self.task_summary(task) for task in available]
                return {"repo_id": self.desk.meta["repo_id"], "head": snap["head"], "tasks": available, 'summary':not list_full}
            if route == "task-options":
                from collections import Counter
                overview = self.read(actor, "overview", argument)
                rows = overview["tasks"]
                reasons = Counter(reason for task in rows for reason in task["qualification"]["missing"])
                hints = {}
                for task in rows:
                    spec = rules.contract(task) or {}
                    for requirement in spec.get("requirements", []):
                        hint = {"project_id": rules.task_project(task), **requirement}
                        hints[encoded(hint)] = hint
                return {"tasks": rows if list_full else [self.task_summary(task) for task in rows], 'summary':not list_full,
                        "counts": {"visible": len(rows),
                        "claimable": sum(task["qualification"]["eligible"] for task in rows)},
                        "missing_summary": [{"reason": reason, "count": count} for reason, count in sorted(reasons.items())],
                        "capability_hints": sorted(hints.values(), key=lambda row: (row["project_id"], row["id"])),
                        "load": rules.execution_load(state, actor)}
            if route == "overview":
                shown = []
                for task in visible_tasks:
                    if argument and rules.task_project(task) != argument:
                        continue
                    current = active_claim(state, task)
                    project = rules.project_record(state, rules.task_project(task))
                    last = next((state["claims"][cid] for cid in reversed(task["claims"])
                                 if cid in state["claims"] and state["claims"][cid].get("task_id") == task["task_id"]), None)
                    last_identity = (rules.identity(state, last["origin"]) or {}) if last else {}
                    shown.append({**task, "stage": stage(task, current, state),
                                  'execution_status':execution_status(state,current),
                                  "project_name": project["name"] if project else None,
                                  "window": (rules.identity(state, current["origin"]) or {}).get("window") if current else None,
                                  "window_name": (rules.identity(state, current["origin"]) or {}).get("window_name") if current else None,
                                  "holder": current["origin"] if current else None,
                                  "last_executor": {"id": last["origin"], "window": last_identity.get("window"),
                                                    "window_name": last_identity.get("window_name")} if last else None,
                                  "last_claim_id": last["claim_id"] if last else None,
                                  "revisions": len(current["deliveries"]) if current else 0,
                                  "qualification": self.qualification(state, task, actor)})
                return {"roles": self.roles(state, actor), "upgraded": upgraded,
                        "projects": upgrade.projects(state, actor), "tasks": shown, "round": round_enabled,
                        "feedback_due": self.feedback_due(state, actor, argument) if round_enabled else 0}
            if route == "activity":
                return upgrade.activity_rows(self, snap, actor)
            if route == "project-cards":
                return [{**project, "members": self.members(state, project["id"])} for project in upgrade.projects(state, actor)]
            if route == "project":
                project = next((p for p in upgrade.projects(state, actor) if p["id"] == argument), None)
                if not project:
                    raise ClientError("项目不存在或无权查看", 404)
                from .release_views import identities
                return {**project, "members": self.members(state, argument), "identity_choices":identities(state,actor),
                        "automation": state["round"].get("automation:" + argument, {"enabled": False, "version": 0}) if round_enabled else None}
            if route == "projects":
                return {"projects": upgrade.projects(state, actor)}
            if route == 'input-package':
                from .input_packages import package
                return package(self,actor,state,argument)
            if route == "invitation-owners":
                from .release_views import invitation_owners
                return {"owners":invitation_owners(state,actor,argument)}
            if route == "release-readiness":
                from .release_views import readiness
                from .privacy import public
                return public(readiness(state,actor))
            if route == "project-capabilities":
                if not any(p["id"] == argument for p in upgrade.projects(state, actor)):
                    raise ClientError("项目不存在或无权查看", 404)
                found = {}
                for key, record in state["pilot"].items():
                    if key.startswith(f"cap:{argument}:"):
                        found.setdefault(key.rsplit(":", 1)[1], record["kind"])
                return sorted(found.items())
            if route in {"executors", "window-cards"}:
                sources = upgrade.sources(state, actor)
                if round_enabled:
                    round_service.annotate_sources(self, state, sources)
                from .window_admin import allowed
                from .privacy import window_source
                sources=[window_source(state,actor,source) for source in sources]
                for source in sources:
                    source['can_manage']=allowed(state,actor,source['executor_id'])
                    source['can_manage_projects']=rules.system_admin(state,actor)
                if route == "window-cards":
                    from 协作本轮 import execution_settings
                    joined = upgrade.projects(state, actor)
                    for source in sources:
                        name = source["executor_id"]
                        source.update(auto=execution_settings(state, name)["auto"], capabilities=self.capability_rows(state, actor, name)[1],
                                      memberships=[{"name": p["name"], "roles": sorted(rules.grant(state, p["id"], name)["roles"])}
                                                   for p in joined if rules.grant(state, p["id"], name)["roles"]])
                return {"executors": sources}
            if route == "identity":
                data=state.get('security',{}).get('execution',{})
                return {"identity": actor, "binding": rules.identity(state, actor), "projects": upgrade.projects(state, actor),
                        'default_context':data.get('defaults',{}).get(actor),
                        'active_task_contexts':[{'segment_id':key,**{k:row.get(k) for k in ('task_id','claim_id','context_id','context_version')}}
                            for key,row in data.get('segments',{}).items() if row.get('executor_id')==actor and
                            state['claims'].get(row.get('claim_id'),{}).get('L')=='active']}
            if route == "delegations":
                return {"delegations": delegation.view(state, actor)}
            if route == "capabilities":
                name = argument or actor
                permitted, capabilities = self.capability_rows(state, actor, name)
                if not permitted:
                    raise ClientError("无权查看能力证据", 403)
                return {"identity": name, "capabilities": capabilities}
            if route == "audit":
                return {"head": snap["head"], "events": upgrade.audit_rows(self, snap, actor, argument)}
            if route == "receipt":
                if not isinstance(argument, str) or not ID.fullmatch(argument):
                    raise ClientError("请求编号无效")
                key = digest(encoded([actor, argument]))
                row = self.db.execute("SELECT status,response FROM requests WHERE key=?", (key,)).fetchone()
                if not row:
                    raise ClientError("没有该身份的请求记录", 404)
                access = self.receipt_authorization(actor, key, state)
                response = json.loads(row[1]) if row[1] else {"status": "pending", "request_id": argument}
                return self.cleanup_receipt(response) if access == "cleanup" else response
            if route == "upgrade":
                fmt = state["pilot"].get("format")
                return {"format": fmt, "release": state["pilot"].get("release:" + fmt["upgrade"]) if fmt else None,
                        "roles": sorted(rules.roles(state, rules.PROJECT, actor)), "head": snap["head"]}
            if route == "receivers":
                if argument:
                    return sorted(name for name in state["origins"] if "receiver" in rules.roles(state, argument, name))
                return sorted(name for name, origin in state["origins"].items() if "receiver" in origin["roles"])
            if route == "account-table":
                if not self.is_admin(actor):
                    raise ClientError("仅管理员可查看账号", 403)
                joined = upgrade.projects(state, actor)
                rows, seen = [], set()
                for key, subject in state["pilot"].items():
                    if not key.startswith("identity:"):
                        continue
                    name = key.removeprefix("identity:")
                    seen.add(name)
                    if subject["kind"] not in {"human", "executor"}:
                        continue
                    rows.append({"name": name, "kind": subject["kind"], "status": subject["status"], "owner": subject.get("owner"),
                                 "platform": subject.get("platform"), "window": subject.get("window"), "admin": rules.system_admin(state, name),
                                 "window_name": subject.get("window_name"),
                                 "projects": [{"name": p["name"], "roles": sorted(rules.grant(state, p["id"], name)["roles"])}
                                              for p in joined if rules.grant(state, p["id"], name)["roles"]]})
                rows.sort(key=lambda row: (row["kind"] != "human", row["name"]))
                return rows + [{"name": name, "kind": None, "status": None, "owner": None, "platform": None, "window": None, "admin": False, "projects": []}
                               for name, _ in self.accounts.list() if name not in seen]
            if route == "accounts":
                if not self.is_admin(actor):
                    raise ClientError("仅管理员可查看账号", 403)
                roster = {name: role for name, role in self.accounts.list()}
                for name, origin in state["origins"].items():
                    role = origin["roles"][0]
                    if role in {"receiver", "executor"}:
                        roster.setdefault(name, role)
                return sorted(roster.items())
            if route == "detail":
                if argument not in tasks:
                    raise ClientError("任务不存在", 404)
                return self.detail(state, tasks[argument], actor)
            if route == "task":
                if argument not in tasks:
                    raise ClientError("任务不存在", 404)
                return self.task_view(state, tasks[argument], actor)
            if route == "board":
                if upgraded:
                    lines = ["# 内网任务看板", "", f"账本序号 {snap['head']}", ""]
                    for task in visible_tasks:
                        project = rules.project_record(state, rules.task_project(task))
                        name = project["name"] if project else "原有任务"
                        current = active_claim(state, task)
                        subject = (rules.identity(state, current["origin"]) or {}) if current else {}
                        window = subject.get("window_name") or subject.get("window")
                        if subject.get("window_name") and subject.get("window"):
                            window += " · " + subject["window"]
                        lines.append(f"- {task['task_id']} {task['title']} · {name} · {stage(task, current, state)}"
                                     + (f" · {window}" if window else ""))
                    return ("\n".join(lines) + "\n").encode("utf-8")
                return render(self.desk, snap)
            if route == 'artifact' and execution.stash_reference_allowed(state,actor,argument):
                row=next(row for row in state['security']['execution']['stashes'].values()
                         if row.get('bundle',{}).get('path')==argument)
                return checked_file(self.desk.store,row['bundle'])
            for task in visible_tasks:
                view = self.task_view(state, task, actor)
                refs = [{"path": p, "sha256": sha} for p, sha in task["inputs"].items()] + view["handoffs"]
                close = state["closings"].get(task.get("close_id"))
                if close and (view["claims"] or actor == task["receiver"]):
                    refs.append(close["summary"])
                for claim in view["claims"]:
                    refs += [{'path': p, 'sha256': sha} for p, sha in claim.get('inputs', {}).items()]
                    for delivery in claim["deliveries"].values():
                        ref = delivery["manifest"]
                        if argument == ref["path"]:
                            refs.append(ref)
                        elif argument.startswith(ref["path"].rsplit("/", 1)[0] + "/"):
                            refs += self.delivery_refs(ref)
                for ref in refs:
                    if argument == ref["path"]:
                        return checked_file(self.desk.store, ref)
            raise ClientError("文件不存在或当前身份无权读取", 404)
