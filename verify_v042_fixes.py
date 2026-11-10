"""v0.4.2 regressions: request-audit isolation (#15) and restoring a disabled person (#16)."""
from copy import deepcopy
import json
import secrets
import time
import unittest
from unittest.mock import patch

import verify_v030_credential_recovery as credential_fixture
from pool import workbench_pages
from pool.sessions import DurableSessions
import 协作升级 as rules
import 协作执行 as engine
from 协作存储 import Rejected, digest, encoded
from 协作账本 import effects_between
from verify_delegation import ASSISTANT, PERSON

FOREIGN, FOREIGN_OWNER = "foreign-window", "other-person"
MARKERS = ("foreign-model-marker", "foreign-environment-marker")
EVIDENCE = {"note": "isolated fixture evidence", "sha256": "a" * 64}


def config(model, environment):
    values = {"platform": "codex", "adapter": "manual", "model": model, "reasoning": "high",
              "tools_version": "unknown", "permissions_version": "unknown", "environment": environment}
    return {**values, "sources": {key: "unknown" if value == "unknown" else "reported" for key, value in values.items()}}


class RulesLedger(credential_fixture.MemoryLedger):
    """The fixture ledger, deciding with the upgrade rules and recording a refusal as a refusal."""

    def process(self, *_, **kwargs):
        state = self.data["state"]
        for record in self.data["copies"]:
            env = record["envelope"]
            key = env["origin_id"] + "/" + env["event_id"]
            if key in self.data["terminal"]:
                continue
            before = deepcopy(state)
            result, reason = "applied", ""
            try:
                rules.action(state, env, {"now": time.time()})
            except Rejected as error:
                state.clear()
                state.update(before)
                result, reason = "rejected", str(error)
            row = {"origin_id": env["origin_id"], "origin_seq": env["origin_seq"], "key": key, "type": "decision",
                   "command": env["command"], "result": result, "reason": reason, "content_sha256": record["sha256"],
                   "ledger_seq": len(self.data["terminal"]) + 1, "sha256": "b" * 64, "effects": effects_between(before, state)}
            self.data["terminal"][key] = row
            self.data["entries"].append(row)
        return self.read()


class ServiceFixture(unittest.TestCase):
    schema = 5

    def setUp(self):
        self.fixture = credential_fixture.CredentialRecovery()
        with patch.object(credential_fixture, "MemoryLedger", RulesLedger):
            self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.service, self.state = self.fixture.service, self.fixture.state
        self.state["pilot"]["format"].update(schema=self.schema, min_reader=self.schema)
        if self.schema >= 4:
            self.state["security"] = {"schema": self.schema, "phase": "ready"}

    def submit(self, actor, action, **body):
        body = {"request_id": "v042-" + secrets.token_hex(8), **body}
        status, value = self.service.submit(actor, action, body["request_id"], body)
        return status, value, body["request_id"]

    def recorded(self, actor, request_id):
        key = digest(encoded([actor, request_id]))
        row = self.service.db.execute("SELECT details FROM request_context WHERE request_key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None


class RequestAuditIsolation(ServiceFixture):
    """A request can name any saved configuration; its audit record keeps only one the requester may see."""

    def setUp(self):
        super().setUp()
        data = engine.ensure(self.state)
        self.foreign, self.own = "ctx-foreign", "ctx-own-second"
        for context_id, owner, values in ((self.foreign, FOREIGN, MARKERS), (self.own, ASSISTANT, ("own-second-model", "own-environment"))):
            data["contexts"][context_id + ":1"] = {"id": context_id, "context_id": context_id, "version": 1, "executor_id": owner,
                                                   "config": config(*values), "at": 0, "event": "fixture"}
        data["defaults"][FOREIGN] = {"context_id": self.foreign, "version": 1}
        data = self.state["security"]["execution"]
        common = {"task_id": "T03", "claim_id": "claim-foreign", "executor_id": FOREIGN, "scope_version": 1, "epoch": 1}
        data["segments"]["seg-foreign"] = {"id": "seg-foreign", "version": 1, "context_id": self.foreign,
                                           "context_version": 1, **common}
        data["actions"]["act-foreign"] = {"id": "act-foreign", "version": 1, "state": "prepared", "resources": [],
                                          "segment_id": "seg-foreign", **common}

    def assert_own_default(self, actor, request_id, field=None):
        details = self.recorded(actor, request_id)
        self.assertIsNotNone(details, "the request must still be recorded")
        field = field or ("execution_context" if "execution_context" in details else "reporter_context")
        self.assertEqual(details[field]["executor_id"], actor)
        text = json.dumps(details, ensure_ascii=False)
        for marker in (*MARKERS, self.foreign):
            if marker != details.get("action_id"):
                self.assertNotIn(marker, text)
        return details

    def test_ordinary_read_hides_the_other_windows_configuration(self):
        view = self.service.read(ASSISTANT, "execution", {"executor_id": FOREIGN})
        self.assertEqual(view["contexts"], [])
        self.assertIsNone(view["default_context"])

    def test_rejected_context_save_naming_another_windows_configuration_records_only_the_requesters_own(self):
        status, value, request = self.submit(ASSISTANT, "context-save", context_id=self.foreign, context_version=1,
                                             version=1, make_default=False, config=config("x", "y"))
        self.assertEqual((status, value["status"]), (400, "rejected"))
        self.assert_own_default(ASSISTANT, request)
        events = self.service.read(ASSISTANT, "audit", {"request": request})["events"]
        self.assertEqual([event["request_id"] for event in events], [request])
        for marker in MARKERS:
            self.assertNotIn(marker, json.dumps(events, ensure_ascii=False))

    def test_rejected_requests_of_other_kinds_cannot_pull_the_configuration_in_either(self):
        attempts = (
            ("context-save", {"context_id": self.foreign, "version": 1, "make_default": False, "config": config("x", "y")}),
            ("segment-open", {"task_id": "T01", "claim_id": "none", "scope_version": 1, "epoch": 1,
                              "context_id": self.foreign, "context_version": 1}),
            ("claim", {"task_id": "T01", "version": 1, "scope_version": 1, "execution_protocol": 5,
                       "context_id": self.foreign, "context_version": 1}),
            ("action-prepare", {"segment_id": "seg-foreign", "version": 1, "description": "probe", "resources": [],
                                "adapter_id": "manual"}),
            ("resource-request", {"action_id": "act-foreign", "version": 1, "resources": []}),
            ("resource-release", {"action_id": "act-foreign", "grant_id": "none", "generation": 1, "version": 1,
                                  "evidence": EVIDENCE, "basis": "unconfirmed"}),
        )
        for action, body in attempts:
            with self.subTest(action=action):
                status, value, request = self.submit(ASSISTANT, action, **body)
                self.assertEqual(value["status"], "rejected", value)
                self.assertIn(status, (400, 403, 404, 409))
                self.assert_own_default(ASSISTANT, request)

    def test_project_access_alone_does_not_expose_the_configuration_of_another_windows_action(self):
        self.state["pilot"]["grant:project-two:" + ASSISTANT] = {"roles": ["executor"], "resources": [], "version": 1}
        status, value, request = self.submit(ASSISTANT, "resource-request", action_id="act-foreign", version=1, resources=[])
        self.assertEqual(value["status"], "rejected", value)
        details = self.assert_own_default(ASSISTANT, request)
        self.assertEqual(details["task_id"], "T03")

    def test_fact_without_action_keeps_only_the_reporters_own_configuration(self):
        status, value, request = self.submit(
            ASSISTANT, "execution-fact", task_id="T03", claim_id="claim-foreign", scope_version=1, epoch=1,
            action_id=None, kind="stopped", evidence=EVIDENCE, permit_id=None,
            reporter_basis={"kind": "owner", "note": "probe"}, context_id=self.foreign)
        self.assertEqual(value["status"], "rejected", value)
        details = self.assert_own_default(ASSISTANT, request, "reporter_context")
        self.assertEqual(details["original_execution_context"], "unknown")

    def test_own_configuration_named_by_a_rejected_request_is_still_recorded(self):
        status, value, request = self.submit(ASSISTANT, "context-save", context_id=self.own, context_version=1,
                                             version=1, make_default=False, config=config("x", "y"))
        self.assertEqual(status, 400)
        details = self.recorded(ASSISTANT, request)
        self.assertEqual((details["execution_context"]["context_id"], details["model"]), (self.own, "own-second-model"))

    def test_responsible_person_and_administrator_keep_the_configuration_they_may_read(self):
        status, value, request = self.submit(PERSON, "context-save", context_id=self.own, context_version=1,
                                             version=1, make_default=False, config=config("x", "y"))
        self.assertEqual(status, 400)
        self.assertEqual(self.recorded(PERSON, request)["execution_context"]["executor_id"], ASSISTANT)
        rules.identity(self.state, PERSON)["admin"] = True
        status, value, request = self.submit(PERSON, "context-save", context_id=self.foreign, context_version=1,
                                             version=1, make_default=False, config=config("x", "y"))
        self.assertEqual(status, 400)
        self.assertEqual(self.recorded(PERSON, request)["execution_context"]["executor_id"], FOREIGN)

    def test_person_managing_the_project_keeps_the_configuration_of_an_action_they_may_report_on(self):
        # PERSON manages project-two but is neither the window's responsible person nor an administrator.
        self.assertFalse(rules.system_admin(self.state, PERSON))
        status, value, request = self.submit(PERSON, "resource-release", action_id="act-foreign", grant_id="none",
                                             generation=1, version=1, evidence=EVIDENCE, basis="human-isolation")
        self.assertEqual(value["status"], "rejected", value)
        details = self.recorded(PERSON, request)
        self.assertEqual((details["execution_context"]["executor_id"], details["model"]), (FOREIGN, MARKERS[0]))
        # Naming the configuration directly is not reporting on an action.
        status, value, request = self.submit(PERSON, "context-save", context_id=self.foreign, context_version=1,
                                             version=1, make_default=False, config=config("x", "y"))
        self.assertEqual(status, 400)
        self.assert_own_default(PERSON, request)

    def test_identifiers_of_the_wrong_type_are_rejected_instead_of_failing_the_request(self):
        fact = {"task_id": "T01", "claim_id": "none", "scope_version": 1, "epoch": 1, "action_id": None, "kind": "stopped",
                "evidence": EVIDENCE, "permit_id": None, "reporter_basis": {"kind": "owner", "note": "probe"}}
        attempts = (
            ("action-prepare", {"bogus": 1}),
            ("resource-cancel", {"bogus": 1}),
            ("context-save", {"action_id": ["act-foreign"]}),
            ("claim", {"task_id": "T01", "version": 1, "scope_version": 1, "segment_id": {"id": "seg-foreign"}}),
            ("action-prepare", {"segment_id": ["seg-foreign"], "version": 1, "description": "probe", "resources": [],
                                "adapter_id": "manual"}),
            ("resource-cancel", {"resource_request_id": {"id": 1}, "version": 1}),
            ("resource-request", {"action_id": ["act-foreign"], "version": 1, "resources": []}),
            ("execution-fact", {**fact, "task_id": ["T01"]}),
            ("execution-fact", {**fact, "claim_id": {"id": 1}}),
            ("execution-fact", {**fact, "blocker_ids": [{}]}),
            ("segment-open", {"task_id": "T01", "claim_id": "none", "scope_version": 1, "epoch": 1,
                              "context_id": [self.foreign], "context_version": 1}),
        )
        for action, body in attempts:
            with self.subTest(action=action, body=sorted(body)):
                status, value, request = self.submit(ASSISTANT, action, **body)
                self.assertEqual(value["status"], "rejected", value)
                self.assertIn(status, (400, 403))
                self.assert_own_default(ASSISTANT, request)


class PersonRestoration(ServiceFixture):
    """An administrator can disable a person and bring the same account back through the ordinary write path."""
    schema = 3
    password = "isolated fixture pass phrase"

    def setUp(self):
        super().setUp()
        rules.identity(self.state, PERSON)["admin"] = True
        service = self.service
        with service.db:
            service.passwords.stage("signup-key", FOREIGN_OWNER, service.passwords.protect(self.password, FOREIGN_OWNER), "signup")
            service.passwords.apply("signup-key", "signup", FOREIGN_OWNER)
        rules.identity(self.state, FOREIGN).update(credential=1, token_expires=int(time.time()) + 86400, last_contact=time.time())
        self.window_token = secrets.token_urlsafe(32)
        with service.db:
            service.accounts.issue_executor(FOREIGN, self.window_token, int(time.time()) + 86400, 1)
        self.sessions = DurableSessions(service)
        self.session = self.sessions.create(FOREIGN_OWNER, "", service.session_version(FOREIGN_OWNER))
        self.server = self.fixture.server

    def change(self, status, version, actor=PERSON, name=FOREIGN_OWNER):
        return self.submit(actor, "credential-change", name=name, version=version, status=status, reason="isolated account decision")

    def subject(self, name=FOREIGN_OWNER):
        return rules.identity(self.state, name)

    def can_sign_in(self):
        valid = self.service.passwords.authenticate(FOREIGN_OWNER, self.password)
        subject = self.subject()
        return bool(valid and subject["kind"] == "human" and subject["status"] == "active" and
                    self.service.passwords.version(valid[0]) == valid[1])

    def disable(self):
        status, value, _ = self.change("disabled", 7)
        self.assertEqual(status, 200, value)
        self.assertEqual((self.subject()["status"], self.subject()["credential"]), ("disabled", 8))

    def test_disabled_person_is_restored_and_earlier_sessions_stay_invalid(self):
        for schema in (3, 4, 5):
            with self.subTest(schema=schema):
                self.doCleanups()
                type(self).schema = schema
                try:
                    self.setUp()
                finally:
                    type(self).schema = 3
                self.assertTrue(self.can_sign_in())
                self.assertEqual(self.sessions.actor(self.session, self.service), FOREIGN_OWNER)
                self.assertEqual(self.server.actor_for_token(self.window_token), FOREIGN)
                self.disable()
                self.assertFalse(self.can_sign_in())
                self.assertIsNone(self.service.credential_version(FOREIGN_OWNER))
                self.assertIsNone(self.sessions.actor(self.session, self.service))
                self.assertIsNone(self.server.actor_for_token(self.window_token))
                status, value, request = self.change("active", 8)
                self.assertEqual(status, 200, value)
                self.assertNotIn("token", value)
                self.assertEqual((self.subject()["status"], self.subject()["credential"]), ("active", 9))
                self.assertTrue(self.can_sign_in())
                self.assertEqual(self.service.credential_version(FOREIGN_OWNER), 9)
                self.assertIsNone(self.sessions.actor(self.session, self.service))
                self.assertEqual(self.server.actor_for_token(self.window_token), FOREIGN)
                details = self.recorded(PERSON, request)
                self.assertEqual((details["operation"], details["actor"], details["reason"]),
                                 ("credential-change", PERSON, "isolated account decision"))

    def test_repeating_the_request_returns_the_same_result_without_another_change(self):
        self.disable()
        body = {"request_id": "restore-once", "name": FOREIGN_OWNER, "version": 8, "status": "active", "reason": "isolated restore"}
        first = self.service.submit(PERSON, "credential-change", "restore-once", body)
        second = self.service.submit(PERSON, "credential-change", "restore-once", body)
        self.assertEqual(first, second)
        self.assertEqual(first[0], 200)
        self.assertEqual(self.subject()["credential"], 9)

    def test_only_an_administrator_with_the_current_version_can_restore(self):
        self.disable()
        rules.identity(self.state, PERSON)["admin"] = False
        status, value, _ = self.change("active", 8)
        self.assertNotEqual(status, 200)
        self.assertEqual((self.subject()["status"], self.subject()["credential"]), ("disabled", 8))
        rules.identity(self.state, PERSON)["admin"] = True
        status, value, _ = self.change("active", 7)
        self.assertNotEqual(status, 200)
        self.assertEqual((self.subject()["status"], self.subject()["credential"]), ("disabled", 8))
        self.assertFalse(self.can_sign_in())

    def test_window_disabled_on_its_own_is_not_enabled_by_restoring_its_person(self):
        status, value, _ = self.change("disabled", 1, name=FOREIGN)
        self.assertEqual(status, 200, value)
        window = dict(self.subject(FOREIGN))
        self.assertNotEqual(window["status"], "active")
        self.disable()
        status, value, _ = self.change("active", 8)
        self.assertEqual(status, 200, value)
        self.assertEqual(self.subject(FOREIGN), window)
        self.assertIsNone(self.server.actor_for_token(self.window_token))
        self.assertIsNone(self.service.credential_version(FOREIGN))

    def test_windows_still_return_only_through_a_new_token_and_active_people_are_not_rotated(self):
        status, value, _ = self.change("active", 1, name=FOREIGN)
        self.assertEqual((status, value["message"]), (400, "请通过待确认凭据轮换入口签发新令牌"))
        status, value, _ = self.change("active", 7)
        self.assertEqual(status, 400)
        self.assertIn("未停用", value["message"])
        status, value, _ = self.change("active", 1, name="nobody-here")
        self.assertEqual((status, value["message"]), (400, "请通过待确认凭据轮换入口签发新令牌"))
        self.assertEqual((self.subject()["status"], self.subject()["credential"]), ("active", 7))

    def test_account_page_offers_restoring_only_disabled_ordinary_people(self):
        rows = [
            {"name": "person-off", "kind": "human", "status": "disabled", "credential": 8, "admin": False, "projects": []},
            {"name": "person-on", "kind": "human", "status": "active", "credential": 7, "admin": False, "projects": []},
            {"name": "admin-off", "kind": "human", "status": "disabled", "credential": 3, "admin": True, "projects": []},
            {"name": "window-off", "kind": "executor", "status": "disabled", "credential": 2, "admin": False, "projects": [],
             "owner": "person-on", "platform": "codex", "window": "CDX-0009", "window_name": "w"},
        ]
        page = workbench_pages.accounts_page(PERSON, rows, "", "", "")
        self.assertEqual(page.count('action="/actions/credential-change"'), 1)
        for field in ('name="name" value="person-off"', 'name="version" value="8"', 'name="status" value="active"', 'name="reason"'):
            self.assertIn(field, page)
        for name in ("person-on", "admin-off", "window-off"):
            self.assertNotIn(f'name="name" value="{name}"', page)
        rows[0]["status"] = "active"
        self.assertNotIn("/actions/credential-change", workbench_pages.accounts_page(PERSON, rows, "", "", ""))

    def test_account_table_carries_the_version_the_restore_form_needs(self):
        self.service.is_admin = lambda actor: actor == PERSON
        self.disable()
        row = next(row for row in self.service.read(PERSON, "account-table") if row["name"] == FOREIGN_OWNER)
        self.assertEqual((row["status"], row["credential"]), ("disabled", 8))


if __name__ == "__main__":
    unittest.main()
