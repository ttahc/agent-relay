"""Windows of a joined platform ask to register; the responsible person agrees on the web page.

The first class runs against the packaged service on a disposable real store: real HTTP requests,
the real web forms, and the real client. The second covers answers that a healthy store does not
give on demand. No production store is read.
"""
from contextlib import closing
from html import unescape
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from pool import window_entries
from pool.packages import ClientError

from verify import ROOT, call, server as running_service
from verify_round import Browser, Client, auth_checks, request_id, setup
from verify_support import scratch
from verify_upgrade import PROJECT, source

SPEC = importlib.util.spec_from_file_location("apply_client", ROOT / "ops/round-client.py")
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)

PERSON_PASSWORD = "隔离验收 更换后的不同密码 New-Fruit!"  # set for fixture-person by verify_round.auth_checks


class WindowApplications(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = scratch("window-apply-")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.project = project = Path(cls.scratch.name)
        with zipfile.ZipFile(ROOT / "dist" / "task-pool-local.zip") as package:
            package.extractall(project)
        _, tokens, cls.password = setup(project)
        cls.running = running_service(project)
        _, cls.url = cls.running.__enter__()
        cls.addClassCleanup(cls.running.__exit__, None, None, None)
        cls.admin, _, _ = auth_checks(project, cls.url, tokens, cls.password)
        cls.owner = Browser(cls.url)  # worker-a: an ordinary person with the executor role, not a manager
        cls.owner.login("worker-a", cls.password)
        cls.outsider = Browser(cls.url)  # a person with no role in the project
        cls.outsider.login("fixture-person", PERSON_PASSWORD)
        cls.database = project / ".state" / "local" / "http-journal.sqlite3"
        cls.secrets = []
        cls.entry = cls.new_entry(cls.owner, "worker-a")

    # --- helpers -------------------------------------------------------------------------------

    @staticmethod
    def form(browser, operation, **values):
        browser.send("/invitations")
        status, _, page = browser.send("/invitations", "POST", {"request_id": request_id(), "operation": operation, **values})
        return status, page.decode()

    @classmethod
    def new_entry(cls, browser, owner, platform="codex"):
        status, page = cls.form(browser, "entry-create", project_id=PROJECT, platform=platform, owner=owner)
        assert status == 200, (status, page[-800:])
        value = json.loads(unescape(re.search(r'aria-label="平台接入点申请资料">([^<]+)</textarea>', page)[1]))
        cls.secrets.append(value["code"])
        return value

    def ask(self, entry=None, session=None, platform="codex", **changes):
        entry = entry or self.entry
        body = {"request_id": request_id(), "entry_id": entry["id"], "code": entry["code"],
                "recovery": secrets.token_urlsafe(32), "source": source(session or request_id(), platform), **changes}
        self.secrets.append(body["recovery"])
        return body, call(self.url + "/window-apply", data=body)

    def waiting(self, browser, pairing):
        """The application id the page offers next to this pairing code, or None when it is not shown."""
        page = browser.send("/invitations")[2].decode()
        found = re.search(r'配对码 ' + pairing + r'</strong>.*?name="application_id" value="(w-[0-9a-f]+)"', page, re.S)
        return found[1] if found else None

    def ledger_entries(self):
        return len(list(self.project.glob(".state/**/ledger/*.json")))

    def stored(self, statement, values=()):
        with closing(sqlite3.connect(self.database, timeout=15)) as db, db:
            return db.execute(statement, values).fetchall()

    def client(self, state, *arguments, expect=0):
        done = subprocess.run([sys.executable, "-B", "-X", "utf8", str(ROOT / "ops/round-client.py"), "--state", str(state),
                               "--allow-loopback", *arguments], capture_output=True, cwd=self.project, timeout=120,
                              env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        self.assertEqual(done.returncode, expect, done.stderr.decode("utf-8", "replace")[-800:])
        return json.loads(done.stdout) if not expect else done.stderr.decode("utf-8", "replace")

    # --- the entry point -----------------------------------------------------------------------

    def test_01_an_entry_point_is_bound_to_project_platform_and_person(self):
        entry = self.entry
        self.assertEqual((entry["kind"], entry["project"], entry["owner"], entry["platform"], entry["protocol"]),
                         ("ai-window-entry", PROJECT, "worker-a", "codex", 1))
        self.assertRegex(entry["code"], r"^[A-Za-z0-9_-]{43}$")
        self.assertNotIn("invitation_url", entry)
        self.assertIn("client", entry)
        # An ordinary person may open one only for windows under their own name.
        status, page = self.form(self.owner, "entry-create", project_id=PROJECT, platform="codex", owner="admin")
        self.assertEqual(status, 403, page[-400:])
        status, page = self.form(self.outsider, "entry-create", project_id=PROJECT, platform="codex", owner="fixture-person")
        self.assertEqual(status, 403, page[-400:])
        status, page = self.form(self.owner, "entry-create", project_id=PROJECT, platform="unknown", owner="worker-a")
        self.assertEqual(status, 400, page[-400:])
        # Showing the material again gives the same code and changes nothing.
        status, page = self.form(self.owner, "entry-show", entry_id=entry["id"])
        self.assertEqual(status, 200)
        self.assertIn(entry["code"], unescape(page))
        self.assertEqual(self.form(self.outsider, "entry-show", entry_id=entry["id"])[0], 404)

    def test_02_asking_creates_no_window_and_no_permission(self):
        before = self.ledger_entries()
        body, (status, value) = self.ask(session="first-session")
        self.assertEqual(status, 200, value)
        self.assertEqual(value["status"], "pending_approval")
        self.assertRegex(value["pairing_code"], r"^\d{6}$")
        self.assertFalse({"token", "registration_id", "executor_id", "window"} & value.keys())
        self.assertEqual(self.ledger_entries(), before, "an application writes nothing to the ledger")
        # Asking again with the same request reports the same application.
        self.assertEqual(call(self.url + "/window-apply", data=body), (200, value))
        self.assertEqual(self.ledger_entries(), before)
        # Another party that learned the request id cannot read the outcome without the recovery secret.
        self.assertEqual(call(self.url + "/window-apply", data={**body, "recovery": secrets.token_urlsafe(32)})[0], 403)
        self.assertEqual(call(self.url + "/window-apply", data={**body, "source": {**body["source"], "model": "other"}})[0], 409)
        # The same session cannot queue twice.
        self.assertEqual(self.ask(session="first-session")[1][0], 409)
        type(self).first = (body, value)

    def test_03_what_the_entry_point_refuses(self):
        self.assertEqual(self.ask(code="A" * 43)[1][0], 403)
        self.assertEqual(self.ask(entry={**self.entry, "id": "e-" + "0" * 32})[1][0], 403)
        self.assertEqual(self.ask(platform="claude")[1][0], 400, "the platform is fixed by the entry point")
        self.assertEqual(self.ask(source={"platform": "codex"})[1][0], 400)
        self.assertEqual(call(self.url + "/window-apply", data={"entry_id": self.entry["id"]})[0], 400)
        # The application code opens nothing else.
        self.assertEqual(call(self.url + "/identity", self.entry["code"])[0], 401)
        status, _ = call(self.url + "/ai-prepare", data={"request_id": request_id(), "invite_id": self.entry["id"],
                                                         "code": self.entry["code"], "recovery": secrets.token_urlsafe(32),
                                                         "source": source(request_id())})
        self.assertEqual(status, 403)

    # --- deciding ------------------------------------------------------------------------------

    def test_04_only_the_people_concerned_see_and_decide(self):
        body, value = self.first
        application = self.waiting(self.owner, value["pairing_code"])
        self.assertEqual(application, value["application_id"])
        self.assertEqual(self.waiting(self.admin, value["pairing_code"]), application, "a system administrator may act for the owner")
        self.assertIsNone(self.waiting(self.outsider, value["pairing_code"]))
        page = self.owner.send("/invitations")[2].decode()
        self.assertIn("项窗口申请等待你处理", self.owner.send("/executors")[2].decode())
        self.assertNotIn("项窗口申请等待你处理", self.outsider.send("/executors")[2].decode())
        self.assertIn("未经服务核实", page)
        self.assertIn("first-session", page)
        self.assertEqual(self.form(self.outsider, "apply-approve", application_id=application, roles="executor")[0], 404)
        self.assertEqual(self.form(self.outsider, "apply-reject", application_id=application, reason="无关人员")[0], 404)
        # The owner may grant windows under their name the executor role only.
        status, page = self.form(self.owner, "apply-approve", application_id=application, roles="executor,receiver")
        self.assertEqual(status, 403, page[-400:])
        self.assertEqual(self.form(self.owner, "apply-approve", application_id=application, roles="manager")[0], 400)
        self.assertEqual(call(self.url + "/window-apply", data=body)[1]["status"], "pending_approval")

    def test_05_agreement_registers_through_the_existing_rules(self):
        body, value = self.first
        before = self.ledger_entries()
        status, page = self.form(self.owner, "apply-approve", application_id=value["application_id"], roles="executor")
        self.assertEqual(status, 200, page[-600:])
        self.assertIn("已同意", page)
        self.assertGreater(self.ledger_entries(), before, "agreement is a ledger record in the approver's name")
        self.assertEqual(self.form(self.owner, "apply-approve", application_id=value["application_id"], roles="executor")[0], 409)
        self.assertEqual(self.form(self.admin, "apply-reject", application_id=value["application_id"], reason="迟到的拒绝")[0], 409)
        status, issued = call(self.url + "/window-apply", data=body)
        self.assertEqual((status, issued["status"], issued["roles"]), (200, "pending_activation", ["executor"]), issued)
        self.assertEqual(call(self.url + "/identity", issued["token"])[0], 401, "not usable before activation")
        self.assertEqual(call(self.url + "/window-apply", data=body), (status, issued), "a lost answer can be fetched again")
        self.assertEqual(call(self.url + "/window-apply", data={**body, "recovery": secrets.token_urlsafe(32)})[0], 403)
        status, active = call(self.url + "/ai-activate", issued["token"], {"request_id": request_id(),
                                                                           "registration_id": issued["registration_id"]})
        self.assertEqual((status, active["status"]), (200, "active"), active)
        self.secrets.append(issued["token"])
        identity = Client(self.url, issued["token"]).get("identity")
        self.assertEqual(identity["binding"]["owner"], "worker-a")
        self.assertEqual([(row["id"], row["roles"]) for row in identity["projects"]], [(PROJECT, ["executor"])])
        after = call(self.url + "/window-apply", data=body)[1]
        self.assertEqual(after["status"], "active")
        self.assertNotIn("token", after, "the credential is not handed out again after activation")
        # The page keeps who agreed; the invitation issued for it is used up.
        page = self.admin.send("/invitations")[2].decode()
        self.assertRegex(page, r"配对码 " + value["pairing_code"] + r" · first-session · 已同意 · worker-a")
        record = self.stored("SELECT state, decided_by, invite_id, roles FROM window_applications WHERE id=?", (value["application_id"],))
        self.assertEqual(record[0][:2], ("approved", "worker-a"))
        self.assertRegex(page, "<strong>" + record[0][2] + r"</strong> · [^·]+ · worker-a · 1 / 1 · ",
                         "the single-use invitation issued by the agreement is used up")
        # A session that is registered cannot ask again.
        self.assertEqual(self.ask(session="first-session")[1][0], 409)

    def test_06_a_manager_may_agree_for_the_owner_and_with_wider_roles(self):
        body, (_, value) = self.ask(session="second-session")
        # Roles stay within what the owner holds in the project, whoever agrees.
        status, page = self.form(self.admin, "apply-approve", application_id=value["application_id"], roles="executor,receiver")
        self.assertEqual(status, 403, page[-600:])
        status, page = self.form(self.admin, "apply-approve", application_id=value["application_id"], roles="executor")
        self.assertEqual(status, 200, page[-600:])
        issued = call(self.url + "/window-apply", data=body)[1]
        self.assertEqual(issued["status"], "pending_activation", issued)
        self.assertEqual(self.stored("SELECT decided_by FROM window_applications WHERE id=?", (value["application_id"],)), [("admin",)])
        # Windows under a manager's name may also review.
        entry = self.new_entry(self.admin, "admin", "claude")
        self.assertIsNone(self.waiting(self.owner, self.ask(entry, "hidden-session", "claude")[1][1]["pairing_code"]),
                          "another person's entry point is not shown")
        body, (_, value) = self.ask(entry, "manager-session", "claude")
        status, page = self.form(self.admin, "apply-approve", application_id=value["application_id"], roles="executor,receiver")
        self.assertEqual(status, 200, page[-600:])
        issued = call(self.url + "/window-apply", data=body)[1]
        call(self.url + "/ai-activate", issued["token"], {"request_id": request_id(), "registration_id": issued["registration_id"]})
        identity = Client(self.url, issued["token"]).get("identity")
        self.assertEqual(identity["binding"]["owner"], "admin")
        self.assertEqual(sorted(identity["projects"][0]["roles"]), ["executor", "receiver"])

    def test_07_refusal_is_told_to_the_window(self):
        before = self.ledger_entries()
        body, (_, value) = self.ask(session="refused-session")
        self.assertEqual(self.form(self.owner, "apply-reject", application_id=value["application_id"], reason="")[0], 400)
        status, page = self.form(self.owner, "apply-reject", application_id=value["application_id"], reason="不认识这个窗口")
        self.assertEqual(status, 200, page[-400:])
        answer = call(self.url + "/window-apply", data=body)[1]
        self.assertEqual((answer["status"], answer["message"]), ("rejected", "不认识这个窗口"))
        self.assertNotIn("token", answer)
        self.assertEqual(self.ledger_entries(), before)
        self.assertEqual(self.form(self.owner, "apply-approve", application_id=value["application_id"], roles="executor")[0], 409)
        # The session may ask again with a new request.
        self.assertEqual(self.ask(session="refused-session")[1][1]["status"], "pending_approval")

    def test_08_an_undecided_application_lapses(self):
        body, (_, value) = self.ask(session="slow-session")
        self.stored("UPDATE window_applications SET created=created-? WHERE id=?", (72 * 3600 + 1, value["application_id"]))
        answer = call(self.url + "/window-apply", data=body)[1]
        self.assertEqual(answer["status"], "expired", answer)
        self.assertIsNone(self.waiting(self.owner, value["pairing_code"]))
        self.assertEqual(self.form(self.owner, "apply-approve", application_id=value["application_id"], roles="executor")[0], 409)
        self.assertEqual(self.ask(session="slow-session")[1][1]["status"], "pending_approval", "a lapsed one does not block a new one")

    def test_09_agreement_withdrawn_before_pickup(self):
        body, (_, value) = self.ask(session="withdrawn-session")
        self.assertEqual(self.form(self.owner, "apply-approve", application_id=value["application_id"], roles="executor")[0], 200)
        invite = self.stored("SELECT invite_id FROM window_applications WHERE id=?", (value["application_id"],))[0][0]
        self.assertEqual(self.form(self.owner, "revoke", invite_id=invite, reason="改变主意")[0], 200)
        answer = call(self.url + "/window-apply", data=body)[1]
        self.assertEqual(answer["status"], "lapsed", answer)
        self.assertNotIn("token", answer)

    # --- the real client -----------------------------------------------------------------------

    def test_10_the_client_applies_waits_and_activates(self):
        folder = self.project / "client-home"
        folder.mkdir(mode=0o700)
        material = folder / "entry.json"
        material.write_text(json.dumps(self.entry, ensure_ascii=False), encoding="utf-8")
        state = folder / "window.credential"
        refused = self.client(folder / "wrong.credential", "enroll", "--invite", material, "--session", "client-session", expect=1)
        self.assertIn("enroll --apply", refused)
        first = self.client(state, "enroll", "--apply", material, "--session", "client-session", "--window-name", "客户端窗口")
        self.assertEqual(first["status"], "pending_approval")
        self.assertRegex(first["pairing_code"], r"^\d{6}$")
        self.assertEqual(self.client(state, "enroll")["pairing_code"], first["pairing_code"], "asking again files nothing new")
        self.assertIn("enroll", self.client(state, "enroll", "--apply", material, "--session", "client-session", expect=1))
        self.assertIn("客户端窗口", self.owner.send("/invitations")[2].decode())
        application = self.waiting(self.owner, first["pairing_code"])
        self.assertEqual(self.form(self.owner, "apply-approve", application_id=application, roles="executor")[0], 200)
        active = self.client(state, "enroll", "--wait", "30")
        self.assertEqual(active["status"], "active", active)
        self.assertTrue(active["window"])
        self.assertEqual(self.client(state, "whoami")["owner"], "worker-a")
        self.assertEqual(self.client(state, "whoami")["window_name"], "客户端窗口")

        # A refused application frees the credential file for another attempt.
        other = folder / "refused.credential"
        asked = self.client(other, "enroll", "--apply", material, "--session", "client-refused")
        application = self.waiting(self.owner, asked["pairing_code"])
        self.assertEqual(self.form(self.owner, "apply-reject", application_id=application, reason="请换一个接入点")[0], 200)
        told = self.client(other, "enroll", "--wait", "30")
        self.assertEqual((told["status"], told["message"]), ("rejected", "请换一个接入点"))
        again = self.client(other, "enroll", "--apply", material, "--session", "client-refused")
        self.assertEqual(again["status"], "pending_approval")
        self.assertNotEqual(again["pairing_code"], asked["pairing_code"])

    # --- limits, revocation, secrets -----------------------------------------------------------

    def test_11_a_full_entry_point_takes_no_more(self):
        entry = self.new_entry(self.admin, "admin", "gemini")
        for number in range(10):
            self.assertEqual(self.ask(entry, f"crowd-{number}", "gemini")[1][0], 200)
        self.assertEqual(self.ask(entry, "crowd-late", "gemini")[1][0], 429)
        self.assertEqual(self.ask(session="elsewhere")[1][0], 200, "another entry point is not affected")
        type(self).crowded = entry

    def test_12_revoking_ends_the_entry_point_and_what_waits_there(self):
        entry = self.crowded
        body, (_, value) = self.ask(self.new_entry(self.owner, "worker-a", "claude"), "revoked-session", "claude")
        claude = value["application_id"]
        entry_id = self.stored("SELECT entry FROM window_applications WHERE id=?", (claude,))[0][0]
        self.assertEqual(self.form(self.outsider, "entry-revoke", entry_id=entry_id, reason="无关人员")[0], 404)
        self.assertEqual(self.form(self.owner, "entry-revoke", entry_id=entry_id, reason="平台停用")[0], 200)
        answer = call(self.url + "/window-apply", data=body)[1]
        self.assertEqual(answer["status"], "revoked", answer)
        self.assertEqual(self.form(self.owner, "apply-approve", application_id=claude, roles="executor")[0], 409)
        self.assertEqual(self.form(self.owner, "entry-show", entry_id=entry_id)[0], 409)
        self.assertEqual(self.form(self.admin, "entry-revoke", entry_id=entry["id"], reason="清理")[0], 200)
        self.assertEqual(self.ask(entry, "after-revoke", "gemini")[1][0], 403)
        self.assertEqual(self.stored("SELECT count(*) FROM window_applications WHERE entry=? AND state='pending'", (entry["id"],)), [(0,)])
        # Windows already registered through the first entry point keep working.
        self.assertEqual(call(self.url + "/identity", self.token())[0], 200)

    def token(self):
        return next(value for value in self.secrets if call(self.url + "/identity", value)[0] == 200)

    def test_13_no_secret_is_stored_in_plain_text(self):
        raw = self.database.read_bytes()
        wal = self.database.with_name(self.database.name + "-wal")
        raw += wal.read_bytes() if wal.exists() else b""
        self.assertGreater(len(self.secrets), 20)
        for value in self.secrets:
            self.assertNotIn(value.encode(), raw)

    def test_14_the_service_says_it_takes_applications(self):
        self.assertTrue(call(self.url + "/features", self.token())[1]["features"]["window-apply"])
        self.assertEqual(call(self.url + "/window-apply")[0], 404, "reading the address tells nothing")

    # --- boundaries reported in review ---------------------------------------------------------

    def test_15_one_session_queues_once_across_entry_points(self):
        other = self.new_entry(self.owner, "worker-a")
        self.assertEqual(self.ask(session="roaming-session")[1][0], 200)
        status, value = self.ask(other, "roaming-session")[1]
        self.assertEqual((status, "待处理" in value["message"]), (409, True), value)
        self.assertEqual(self.ask(self.new_entry(self.owner, "worker-a", "external"), "roaming-session", "external")[1][0], 200,
                         "a session is known per platform")
        # Agreed and not yet picked up: asking again elsewhere would only produce a second approval.
        body, (_, first) = self.ask(session="agreed-session")
        self.assertEqual(self.form(self.owner, "apply-approve", application_id=first["application_id"], roles="executor")[0], 200)
        for entry in (self.entry, other):
            status, value = self.ask(entry, "agreed-session")[1]
            self.assertEqual((status, "已获同意" in value["message"]), (409, True), value)
        # Once the agreement is withdrawn the session may ask again.
        invite = self.stored("SELECT invite_id FROM window_applications WHERE id=?", (first["application_id"],))[0][0]
        self.assertEqual(self.form(self.owner, "revoke", invite_id=invite, reason="撤回同意")[0], 200)
        self.assertEqual(self.ask(other, "agreed-session")[1][1]["status"], "pending_approval")

    def test_16_an_owner_with_only_the_review_role(self):
        # "reviewer" holds the receiver role only. Like an ordinary invitation, a manager may open the entry point.
        entry = self.new_entry(self.admin, "reviewer")
        body, (status, value) = self.ask(entry, "review-window")
        self.assertEqual(status, 200, value)
        page = self.admin.send("/invitations")[2].decode()
        offered = re.search(r"配对码 " + value["pairing_code"] + r"</strong>.*?同意登记", page, re.S)[0]
        self.assertEqual(re.findall(r'<option value="([a-z,]+)"', offered), ["receiver"], "only what this owner's windows may hold")
        self.assertEqual(self.form(self.admin, "apply-approve", application_id=value["application_id"], roles="executor")[0], 403)
        self.assertEqual(self.form(self.admin, "apply-approve", application_id=value["application_id"], roles="receiver")[0], 200)
        issued = call(self.url + "/window-apply", data=body)[1]
        self.assertEqual((issued["status"], issued["roles"]), ("pending_activation", ["receiver"]), issued)
        call(self.url + "/ai-activate", issued["token"], {"request_id": request_id(), "registration_id": issued["registration_id"]})
        identity = Client(self.url, issued["token"]).get("identity")
        self.assertEqual((identity["binding"]["owner"], identity["projects"][0]["roles"]), ("reviewer", ["receiver"]))
        # A person with no role in the project still cannot be given an entry point.
        self.assertEqual(self.form(self.admin, "entry-create", project_id=PROJECT, platform="codex", owner="fixture-person")[0], 403)


class Record:
    """A credential file in memory."""

    def __init__(self, **data):
        self.data, self.path, self.saved = data, Path("window.credential"), 0

    def save(self):
        self.saved += 1


class Scripted:
    """A service that gives prepared answers to window-apply."""

    def __init__(self, *answers):
        self.answers, self.bodies = list(answers), []

    def call(self, route, token=None, body=None):
        self.bodies.append(body)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


class Boundaries(unittest.TestCase):
    """Answers that must not end an application: a registration still being confirmed, and a service too old to ask."""

    APPLICATION = {"request_id": "apply-fixture", "entry_id": "e-fixture", "code": "c" * 43, "recovery": "r" * 43, "source": {}}

    def answer(self, outcome):
        application = {"id": "w-fixture", "state": "approved", "proof_sha": "0" * 64, "client_request": "apply-fixture",
                       "invite_id": "i-fixture", "source": {}, "roles": ["executor"], "reason": None, "created": 0}
        entry = {"id": "e-fixture", "project": PROJECT, "owner": "worker-a", "platform": "codex", "revoked": None}
        state = {"round": {"invite:i-fixture": {"issuer": "worker-a"}}}
        service = SimpleNamespace(accounts=SimpleNamespace(token=lambda *names: "t" * 43))
        with patch.object(window_entries.round_service, "bootstrap", side_effect=[outcome]):
            return window_entries.answer(service, application, entry, state, "r" * 43)

    def test_a_registration_still_being_confirmed_is_not_a_lapsed_agreement(self):
        for outcome in ((202, {"status": "pending", "request_id": "prepare-x"}),
                        (503, {"status": "maintenance", "retryable": True, "message": "稍后"})):
            value = self.answer(outcome)
            self.assertEqual((value["status"], value["retry"]), ("approved", True), value)
            self.assertNotIn("token", value)
        with self.assertRaises(ClientError) as raised:
            self.answer(ClientError("前序操作待确认，请重试原请求", 503))
        self.assertEqual(raised.exception.status, 503)
        self.assertEqual(self.answer((409, {"status": "rejected", "message": "邀请已撤销或授权已失效"}))["status"], "lapsed")
        self.assertEqual(self.answer(ClientError("邀请码无效", 403))["status"], "lapsed")
        self.assertEqual(self.answer((200, {"status": "pending_activation", "token": "t", "registration_id": "a-1"}))["status"],
                         "pending_activation")

    def test_the_client_keeps_its_application_until_the_registration_is_confirmed(self):
        waiting = {"status": "approved", "retry": True, "pairing_code": "123456", "project": PROJECT, "owner": "worker-a"}
        state = Record(url="http://127.0.0.1:1", application=dict(self.APPLICATION), applied=True)
        api = Scripted(waiting, waiting, {"status": "pending_activation", "token": "issued-token", "registration_id": "a-1"})
        first = client.apply_for_window(state, api, SimpleNamespace(wait=0))
        self.assertEqual(first["status"], "approved")
        self.assertEqual(state.data["application"], self.APPLICATION, "the recovery material is kept")
        with patch.object(client, "finish_activation", return_value={"status": "active"}) as finish, \
                patch.object(client.time, "sleep"):
            self.assertEqual(client.apply_for_window(state, api, SimpleNamespace(wait=30)), {"status": "active"})
        finish.assert_called_once()
        self.assertEqual(api.bodies, [self.APPLICATION] * 3, "the same request is repeated")
        self.assertEqual((state.data["token"], state.data["registration_id"]), ("issued-token", "a-1"))
        self.assertNotIn("application", state.data)

    def test_a_service_without_the_interface_leaves_the_file_free_for_an_invitation(self):
        missing = client.RequestError(404, {"message": "接口不存在"})
        state = Record(url="http://127.0.0.1:1", application=dict(self.APPLICATION))
        with self.assertRaises(ValueError) as raised:
            client.apply_for_window(state, Scripted(missing), SimpleNamespace(wait=0))
        self.assertIn("enroll --invite-url", str(raised.exception))
        self.assertEqual(state.data, {})
        # The same file now takes an ordinary invitation.
        invitation = {"protocol": 1, "kind": "ai-window", "id": "i-fixture", "code": "c" * 43, "url": "http://127.0.0.1:1"}
        options = SimpleNamespace(invite=None, invite_url="link", apply=None, wait=0)
        with patch.object(client, "load_invitation", return_value=invitation), patch.object(client, "source", return_value={}), \
                patch.object(client, "endpoint", return_value=Scripted({"token": "issued-token", "registration_id": "a-1"})), \
                patch.object(client, "finish_activation", return_value={"status": "active"}):
            self.assertEqual(client.enroll(state, options), {"status": "active"})
        self.assertEqual(state.data["request"]["invite_id"], "i-fixture")
        # An application the service had already accepted is not thrown away by a passing 404.
        state = Record(url="http://127.0.0.1:1", application=dict(self.APPLICATION), applied=True)
        with self.assertRaises(ValueError):
            client.apply_for_window(state, Scripted(missing), SimpleNamespace(wait=0))
        self.assertEqual(state.data["application"], self.APPLICATION)


if __name__ == "__main__":
    unittest.main(verbosity=2)
