"""Synthetic regressions for task scopes, cached cleanup receipts and read filters."""
from copy import deepcopy
import json
import sqlite3
from threading import RLock
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

from pool import delegation, round_projects, workbench, upgrade
from pool.packages import ClientError
from pool.service import Service
from pool.lifecycle import Lifecycle
import 协作关系 as relations
import 协作升级 as rules
from 协作存储 import Rejected, digest, encoded
from verify_delegation import fixture, grant_payload, decide, audited_publish, ASSISTANT, PERSON


class FeedbackScope(unittest.TestCase):
    def setUp(self):
        self.state = fixture()
        decide(self.state, grant_payload(self.state, actions=["read", "feedback-update"], task_ids=["T01"]))
        for identifier, task in (("fb-unlinked", ""), ("fb-first", "T01"), ("fb-other", "T02")):
            self.state["round"]["feedback:" + identifier] = {"id": identifier, "project_id": "project-one", "task_id": task,
                "linked_task": "", "author": "other-person", "version": 1, "status": "triage", "updates": []}

    def body(self, identifier, linked=""):
        return {"request_id": "fixture-update", "project_id": "project-one", "id": identifier, "version": 1,
                "status": "declined", "linked_task": linked, "duplicate": "", "reason": "synthetic scope probe",
                "evidence": "", "metrics": [], "lesson": "", "limits": ""}

    def apply(self, body):
        task, project = delegation.target(self.state, "feedback-update", body)
        with delegation.operation_context(self.state, ASSISTANT, "feedback-update", project, task):
            payload = round_projects.payload(self.state, ASSISTANT, "feedback-update", body, "fixture-key")
            relations.feedback(self.state, {**payload, "op": "feedback-update"}, ASSISTANT, time.time(), "fixture-event")

    def test_client_supplied_link_cannot_create_authority_over_unlinked_feedback(self):
        before = deepcopy(self.state)
        with self.assertRaises((ClientError, Rejected)):
            self.apply(self.body("fb-unlinked", "T01"))
        self.assertEqual(self.state, before)

    def test_allowed_task_feedback_cannot_be_retargeted_to_another_task(self):
        before = deepcopy(self.state)
        with self.assertRaises((ClientError, Rejected)):
            self.apply(self.body("fb-first", "T02"))
        self.assertEqual(self.state, before)

    def test_another_task_feedback_cannot_be_retargeted_into_whitelist(self):
        before = deepcopy(self.state)
        with self.assertRaises((ClientError, Rejected)):
            self.apply(self.body("fb-other", "T01"))
        self.assertEqual(self.state, before)

    def test_genuinely_associated_feedback_remains_editable_within_scope(self):
        self.apply(self.body("fb-first", "T01"))
        self.assertEqual(self.state["round"]["feedback:fb-first"]["status"], "declined")
        self.assertFalse(rules.manager(self.state, "project-one", ASSISTANT))

    def test_project_delegate_can_associate_previously_unlinked_feedback(self):
        decide(self.state, grant_payload(self.state, actions=["read", "feedback-update"], version=1))
        self.apply(self.body("fb-unlinked", "T01"))
        self.assertEqual(self.state["round"]["feedback:fb-unlinked"]["linked_task"], "T01")


class ReadScope(unittest.TestCase):
    def setUp(self):
        self.state = fixture()
        self.state.update(reservations={}, acceptances={}, items={}, notes={}, closings={})
        decide(self.state, grant_payload(self.state, actions=["read"], task_ids=["T01"]))
        for number, task in enumerate(self.state["tasks"].values(), 1):
            task.update(status="available", resources=[], dependencies=[], inputs={"inputs/" + task["task_id"] + ".md": "a" * 64},
                        version=1, scope_version=1, priority=0, created_seq=number, receiver=PERSON)
            task["contract"].update(open=True, requirements=[])
        self.state["claims"]["old-c2"] = {"claim_id": "old-c2", "origin": ASSISTANT, "task_id": "T02", "L": "ended",
                                         "epoch": 2, "W": {"scope": 1}, "E": {"state": "stopped"}, "R": []}
        self.service = object.__new__(Service)
        self.service.lifecycle = Lifecycle()
        self.service.lock, self.service.pinned = RLock(), SimpleNamespace(active=False, snap=None)
        self.service.is_admin = lambda actor: False
        self.service.desk = SimpleNamespace(meta={"repo_id": "fixture"}, store=None)
        self.service.db = sqlite3.connect(":memory:")
        self.service.db.executescript("""
            CREATE TABLE requests(key TEXT, fingerprint TEXT, actor TEXT, action TEXT, body BLOB, plan BLOB, status INTEGER, response BLOB);
            CREATE TABLE request_context(request_key TEXT, details BLOB);
        """)
        self.entries = []
        self.service.snapshot = lambda: {"state": self.state, "head": 1, "entries": self.entries}

    def tearDown(self):
        self.service.db.close()

    def save_old_receipt(self, operation="stop"):
        request = "old-" + operation
        body = {"request_id": request, "claim_id": "old-c2", "epoch": 2, "scope_version": 1, "stop_evidence": "fixture stopped"}
        key = digest(encoded([ASSISTANT, request]))
        record = {"actor": ASSISTANT, "owner": PERSON, "operation": operation, "task_id": "T02",
                  "project_id": "project-one", "request_id": request}
        response = {"status": "applied", "request_id": request, "head": 1,
                    "task": {"task_id": "T02", "private": "previous task payload"}, "claim": {"private": "claim payload"},
                    "initial_inputs": [{"path": "inputs/T02.md"}], "handoffs": [{"path": "private-handoff"}],
                    "steps": [{"event_id": "fixture", "result": "applied", "reason": "private old reason"}]}
        self.service.db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)", (
            key, digest(encoded([operation, body])), ASSISTANT, operation, b"{}", None, 200, encoded(response)))
        self.service.db.execute("INSERT INTO request_context VALUES(?,?)", (key, encoded(record)))
        return request, body

    def assert_cleanup_only(self, response):
        self.assertTrue(response["cleanup_only"])
        self.assertEqual(set(response), {"status", "request_id", "head", "steps", "cleanup_only"})
        self.assertEqual(response["steps"], [{"event_id": "fixture", "result": "applied"}])

    def test_task_and_task_options_apply_current_whitelist(self):
        options = self.service.read(ASSISTANT, "task-options")
        self.assertEqual([task["task_id"] for task in options["tasks"]], ["T01"])
        with self.assertRaises(ClientError) as failure:
            self.service.read(ASSISTANT, "task", "T02")
        self.assertEqual(failure.exception.status, 404)

    def test_artifact_cannot_read_another_task_path(self):
        with patch("pool.service.checked_file", return_value=b"fixture file") as read:
            with self.assertRaises(ClientError):
                self.service.read(ASSISTANT, "artifact", "inputs/T02.md")
            read.assert_not_called()
            self.assertEqual(self.service.read(ASSISTANT, "artifact", "inputs/T01.md"), b"fixture file")

    def test_old_cleanup_receipt_does_not_restore_revoked_task_contents(self):
        for operation in ("stop", "handoff"):
            with self.subTest(operation=operation):
                request, _ = self.save_old_receipt(operation)
                self.assert_cleanup_only(self.service.read(ASSISTANT, "receipt", request))

    def test_cached_submit_returns_the_same_minimal_cleanup_receipt(self):
        request, body = self.save_old_receipt()
        status, response = self.service.submit(ASSISTANT, "stop", request, body)
        self.assertEqual(status, 200)
        self.assert_cleanup_only(response)

    def test_current_read_allows_original_receipt_without_cleanup_redaction(self):
        request, _ = self.save_old_receipt()
        decide(self.state, grant_payload(self.state, actions=["read"], task_ids=["T02"], version=1))
        response = self.service.read(ASSISTANT, "receipt", request)
        self.assertEqual(response["task"]["task_id"], "T02")

    def test_actor_audit_cannot_reveal_task_outside_current_scope(self):
        self.entries.append({"type": "decision", "request": {"actor": ASSISTANT, "owner": PERSON, "task_id": "T02", "request_id": "old-write"},
            "origin_id": ASSISTANT, "effects": [{"path": ["tasks", "T02"], "value": self.state["tasks"]["T02"]}],
            "ledger_seq": 1, "sha256": "a" * 64, "key": ASSISTANT + "/fixture", "committer": "fixture", "command": "claim", "result": "applied", "reason": ""})
        self.save_old_receipt()
        rows = self.service.read(ASSISTANT, "audit", {"actor": ASSISTANT})["events"]
        self.assertEqual(rows, [])

    def test_no_delegation_stamp_keeps_previous_authorization_bytes(self):
        subject = rules.identity(self.state, ASSISTANT)
        owner = rules.identity(self.state, subject["owner"])
        previous = digest(encoded([subject.get("kind"), subject.get("owner"), subject.get("status"), subject.get("credential", 0),
            owner.get("status"), rules.grant(self.state, "project-one", ASSISTANT), rules.grant(self.state, "project-one", subject.get("owner"))]))
        self.assertEqual(rules.auth_stamp(self.state, ASSISTANT, "project-one"), previous)


class ManagementButtons(unittest.TestCase):
    def test_task_publish_delegate_does_not_get_other_manager_buttons(self):
        state = fixture()
        decide(state, grant_payload(state, actions=["read", "claim", "task-publish"], task_ids=["T01"]))
        service = object.__new__(Service)
        task = state["tasks"]["T01"]
        task.update(status="available", version=1, scope_version=1, receiver=PERSON)
        task["contract"]["open"] = False
        view = {"task": task, "active": None, "roles": service.task_roles(state, task, ASSISTANT),
                "delegated_actions": service.delegated_actions(state, task, ASSISTANT), "viewer": ASSISTANT}
        self.assertNotIn("manager", view["roles"])
        html = workbench.manage_box(view)
        self.assertIn("task-publish", html)
        for action in ("task-hold", "task-scope", "cancel", "task-interrupt", "task-recover"):
            self.assertNotIn(action, html)
        self.assertEqual(service.delegated_actions(state, state["tasks"]["T02"], ASSISTANT), [])

    def test_read_only_holder_cannot_see_upload_restart_or_withdraw_actions(self):
        task = {"task_id": "T01", "status": "running", "receiver": PERSON, "contract": {"project_id": "project-one"}}
        claim = {"claim_id": "fixture", "origin": ASSISTANT, "epoch": 1, "W": {"state": "draft", "scope": 1},
                 "E": {"state": "running", "reason": None}}
        view = {"task": task, "active": claim, "roles": [], "direct_roles": [], "delegated_actions": ["read"]}
        html = workbench.worker_box(ASSISTANT, view)
        self.assertNotIn("deliver-files", html)
        claim["W"].update(state="review", revision="revision-1")
        claim["E"] = {"state": "stopped", "reason": "complete"}
        self.assertNotIn("withdraw", workbench.worker_box(ASSISTANT, view))
        claim["W"]["state"] = "revision"
        self.assertNotIn("resume", workbench.worker_box(ASSISTANT, view))

    def test_explicit_resume_delegation_is_separate_from_read(self):
        state = fixture()
        decide(state, grant_payload(state, actions=["read", "resume"], task_ids=["T01"]))
        with delegation.operation_context(state, ASSISTANT, "resume", "project-one", "T01"):
            self.assertIn("executor", rules.roles(state, "project-one", ASSISTANT))
        with delegation.operation_context(state, ASSISTANT, "read", "project-one", "T01"):
            self.assertNotIn("executor", rules.roles(state, "project-one", ASSISTANT))


class PersistedContext(unittest.TestCase):
    def setUp(self):
        self.state = fixture()
        decide(self.state, grant_payload(self.state, actions=["task-publish"], task_ids=["T01"]))
        self.envelope = audited_publish(self.state)

    def test_revoked_queued_request_is_rejected_before_ledger_write(self):
        key = self.envelope["payload"]["_audit"]["delegation_id"]
        decide(self.state, {"op": "delegate-revoke", "delegation_id": key, "version": 1, "reason": "fixture revoke"})
        with patch("协作命令.decide") as commit, self.assertRaises(Rejected):
            upgrade.decide(self.state, self.envelope, {"now": time.time()})
        commit.assert_not_called()

    def test_changed_task_payload_cannot_reuse_a_valid_delegation_audit(self):
        self.envelope["payload"]["task_id"] = "T02"
        with patch("协作命令.decide") as commit, self.assertRaises(Rejected):
            upgrade.decide(self.state, self.envelope, {"now": time.time()})
        commit.assert_not_called()

    def test_later_grant_does_not_elevate_request_recorded_without_delegation(self):
        audit = self.envelope["payload"]["_audit"]
        for key in delegation.AUDIT_KEYS:
            audit.pop(key, None)

        def commit(state, envelope, context):
            self.assertFalse(rules.manager(state, "project-one", ASSISTANT))
            self.assertEqual(delegation.stamp(state, ASSISTANT, "project-one"), {})
            return "fixture no elevation"

        with patch("协作命令.decide", side_effect=commit):
            self.assertEqual(upgrade.decide(self.state, self.envelope, {"now": time.time()}), "fixture no elevation")

    def test_withdraw_cannot_commit_after_project_execution_right_is_removed(self):
        self.state["claims"]["c1"] = {"claim_id": "c1", "origin": ASSISTANT, "task_id": "T01", "L": "active"}
        env = {"command": "withdraw_delivery", "origin_id": ASSISTANT, "expects": {},
               "payload": {"claim_id": "c1", "_audit": {"schema": 3, "actor": ASSISTANT, "operation": "withdraw"}}}
        with self.assertRaisesRegex(Rejected, "执行权限"):
            rules.guard(self.state, env, {"now": time.time()})


if __name__ == "__main__":
    unittest.main()
