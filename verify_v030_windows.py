"""Synthetic v0.3 lifecycle, consent, evidence-review and request replay regressions."""
from copy import deepcopy
from email.message import Message
import json
import sqlite3
from threading import RLock
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit

from pool import delegation, delegation_pages, round_service, window_admin, window_admin_pages
from pool.packages import ClientError
from pool.service import Service
import 协作本轮 as round_rules
import 协作升级 as rules
from 协作存储 import Rejected, encoded
from verify_delegation import ASSISTANT, PERSON, decide, fixture, grant_payload, FixtureService


class WindowLifecycle(unittest.TestCase):
    def setUp(self):
        self.state = fixture()
        rules.identity(self.state, ASSISTANT)["environment"] = "fixture-env"
        self.state["pilot"][f"grant:project-one:{ASSISTANT}"] = {"roles": ["executor"], "resources": ["path:test"], "version": 1}
        decide(self.state, grant_payload(self.state))

    def change(self, operation, actor=PERSON, **extra):
        p = {"op": "window-admin", "operation": operation, "name": ASSISTANT,
             "version": rules.identity(self.state, ASSISTANT)["credential"], "reason": "synthetic lifecycle", **extra}
        decide(self.state, p, actor)

    def claim(self, lifecycle="active", execution="running", resources=None, work="draft"):
        self.state["claims"]["fixture-claim"] = {"claim_id": "fixture-claim", "task_id": "T01", "origin": ASSISTANT,
             "epoch": 1, "L": lifecycle, "E": {"state": execution, "reason": None}, "W": {"state": work, "scope": 1}, "R": resources or []}

    def test_transfer_rejects_running_review_and_orphaned_resource_facts(self):
        for lifecycle, execution, work, resources in (("active", "running", "draft", ["resource"]),
                                                     ("active", "stopped", "review", []),
                                                     ("ended", "stopped", "draft", ["resource"])):
            with self.subTest(lifecycle=lifecycle, work=work):
                self.claim(lifecycle, execution, resources, work)
                before = deepcopy(self.state)
                with self.assertRaises(Rejected):
                    self.change("transfer", owner="other-person")
                self.assertEqual(self.state, before)

    def test_only_owner_or_real_system_admin_can_manage(self):
        for actor in (ASSISTANT, "other-person", "foreign-window"):
            with self.subTest(actor=actor):
                with self.assertRaises(Rejected):
                    self.change("disable", actor=actor)
                with self.assertRaises(ClientError):
                    window_admin.view(self.state, actor, ASSISTANT)

    def test_transfer_requires_another_active_human(self):
        for target in (PERSON, ASSISTANT, "missing"):
            with self.subTest(target=target), self.assertRaises(Rejected):
                self.change("transfer", owner=target)
        rules.identity(self.state, "other-person")["status"] = "disabled"
        with self.assertRaises(Rejected):
            self.change("transfer", owner="other-person")

    def test_transfer_preserves_id_revokes_grants_and_cannot_resurrect_old_permissions(self):
        old = deepcopy(rules.identity(self.state, ASSISTANT))
        self.change("transfer", owner="other-person")
        subject = rules.identity(self.state, ASSISTANT)
        self.assertEqual((subject["window"], subject["number"]), (old["window"], old["number"]))
        self.assertEqual((subject["owner"], subject["status"], subject["credential"]), ("other-person", "disabled", 8))
        self.assertEqual(rules.grant(self.state, "project-one", ASSISTANT)["roles"], [])
        self.assertTrue(all(row["revoked"] for key, row in self.state["round"].items() if key.startswith("delegation:")))
        self.assertFalse(window_admin.allowed(self.state, PERSON, ASSISTANT))
        self.change("transfer", actor="other-person", owner=PERSON)
        self.assertEqual(rules.grant(self.state, "project-one", ASSISTANT)["roles"], [])
        self.assertTrue(self.state["round"]["delegation:" + delegation.delegation_id(PERSON, ASSISTANT, "project-one")]["revoked"])

    def test_pause_disable_archive_preserve_execution_lock_and_delivery_facts(self):
        for operation, status in (("pause", "paused"), ("disable", "disabled"), ("archive", "archived")):
            with self.subTest(operation=operation):
                self.setUp()
                self.claim(resources=["fixture-resource"])
                before = deepcopy(self.state["claims"])
                self.change(operation)
                self.assertEqual(self.state["claims"], before)
                self.assertEqual(rules.identity(self.state, ASSISTANT)["status"], status)
                self.assertEqual(rules.identity(self.state, ASSISTANT)["credential"], 8)
                self.assertEqual(rules.grant(self.state, "project-one", ASSISTANT)["roles"], ["executor"])

    def test_revoke_all_does_not_disable_independent_membership_or_fake_stop(self):
        self.claim(resources=["fixture-resource"])
        before = deepcopy(self.state["claims"])
        self.change("revoke-all")
        self.assertEqual(self.state["claims"], before)
        self.assertEqual(rules.identity(self.state, ASSISTANT)["status"], "active")
        self.assertEqual(rules.identity(self.state, ASSISTANT)["credential"], 7)
        self.assertEqual(rules.roles(self.state, "project-one", ASSISTANT), {"executor"})

    def test_restore_requires_fresh_prepare_activation_and_revoked_delegations_stay_revoked(self):
        self.change("pause")
        self.assertFalse(rules.active(self.state, ASSISTANT))
        decide(self.state, {"op": "token-prepare", "name": ASSISTANT, "version": 8, "registration_id": "fresh",
                            "proof_sha": "a" * 64, "reason": "new activation"})
        self.assertFalse(rules.active(self.state, ASSISTANT))
        decide(self.state, {"op": "ai-activate", "registration_id": "fresh"})
        self.assertEqual((rules.identity(self.state, ASSISTANT)["status"], rules.identity(self.state, ASSISTANT)["credential"]), ("active", 9))
        self.assertTrue(self.state["round"]["delegation:" + delegation.delegation_id(PERSON, ASSISTANT, "project-one")]["revoked"])

    def test_pending_old_activation_is_revoked_by_lifecycle_change(self):
        decide(self.state, {"op": "token-prepare", "name": ASSISTANT, "version": 7, "registration_id": "old",
                            "proof_sha": "a" * 64, "reason": "old preparation"})
        self.change("archive")
        with self.assertRaises(Rejected):
            decide(self.state, {"op": "ai-activate", "registration_id": "old"})
        self.assertEqual(self.state["round"]["enrollment:old"]["state"], "revoked")

    def test_impact_lists_active_review_and_resources_and_has_permission_boundary(self):
        self.claim(execution="stopped", work="review")
        impact = window_admin.view(self.state, PERSON, ASSISTANT)
        self.assertFalse(impact["transfer_allowed"])
        self.assertEqual(impact["claims"][0]["W"]["state"], "review")
        self.assertEqual(impact["version"], 7)
        self.assertIn("不释放", impact["consequence"])
        html = window_admin_pages.render(PERSON, self.state, ASSISTANT)[1].decode()
        self.assertIn('name="version" value="7"', html)
        self.assertIn("新令牌", html)


class CapabilityReview(unittest.TestCase):
    setUp = WindowLifecycle.setUp
    def request(self, **changes):
        p = {"op": "capability-request", "id": "vr-fixture", "project_id": "project-one", "name": ASSISTANT,
             "capability": "official-research", "record": {"kind": "environment", "value": "ok", "environment": "fixture-env",
                 "expires": int(time.time()) + 86400, "evidence": {"note": "reproducible isolated probe", "sha256": "a" * 64}}}
        p.update(changes)
        decide(self.state, p, ASSISTANT)

    def resolve(self, actor="other-person", **changes):
        p = {"op": "capability-resolve", "id": "vr-fixture", "version": 1, "decision": "approve", "level": "verified", "reason": "independent evidence checked"}
        p.update(changes)
        decide(self.state, p, actor)

    def test_request_creates_pending_queue_without_self_certification(self):
        self.request()
        self.assertNotIn(f"cap:project-one:{ASSISTANT}:official-research", self.state["pilot"])
        row = window_admin.requests_view(self.state, ASSISTANT)[0]
        self.assertEqual(row["state"], "pending")
        self.assertFalse(row["can_resolve"])
        self.assertIn("other-person", row["reviewers"])
        with self.assertRaises(Rejected):
            self.resolve(ASSISTANT)

    def test_only_current_project_reviewer_can_resolve(self):
        self.request()
        self.state["pilot"]["identity:unrelated-admin"] = {"kind": "human", "owner": "unrelated-admin", "status": "active", "admin": True}
        with self.assertRaises(Rejected):
            self.resolve("unrelated-admin")
        self.state["pilot"]["grant:project-one:other-person"]["roles"] = []
        with self.assertRaises(Rejected):
            self.resolve()
        self.assertFalse(window_admin.requests_view(self.state, "foreign-window"))

    def test_independent_approval_creates_verified_capability_with_request_audit(self):
        self.request()
        self.resolve()
        cap = self.state["pilot"][f"cap:project-one:{ASSISTANT}:official-research"]
        self.assertEqual((cap["level"], cap["by"], cap["verification_id"]), ("verified", "other-person", "vr-fixture"))
        with self.assertRaises(Rejected):
            self.resolve()

    def test_changed_environment_expiry_and_capability_version_preserve_pending_input(self):
        self.request()
        before = deepcopy(self.state)
        for mutate in (lambda s: rules.identity(s, ASSISTANT).update(environment="changed"),
                       lambda s: s["round"]["verification:vr-fixture"]["record"].update(expires=1),
                       lambda s: s["pilot"].update({f"cap:project-one:{ASSISTANT}:official-research": {"version": 1}})):
            self.state = deepcopy(before)
            mutate(self.state)
            request = deepcopy(self.state["round"]["verification:vr-fixture"])
            with self.assertRaises(Rejected):
                self.resolve()
            self.assertEqual(self.state["round"]["verification:vr-fixture"], request)

    def test_rejection_keeps_evidence_and_does_not_grant_verified(self):
        self.request()
        self.resolve(decision="reject")
        row = self.state["round"]["verification:vr-fixture"]
        self.assertEqual(row["state"], "rejected")
        self.assertEqual(row["record"]["evidence"]["sha256"], "a" * 64)
        self.assertNotIn(f"cap:project-one:{ASSISTANT}:official-research", self.state["pilot"])


class TaskPublication(unittest.TestCase):
    def test_publish_clears_current_hold_reason_preserves_new_reason_and_existing_claim_facts(self):
        state = fixture()
        task = state["tasks"]["T01"]
        task.update(status="running", version=3, scope_version=1, receiver=PERSON)
        task["contract"].update(open=False, hold_reason="historical hold", publication_reason="previous publication")
        state["claims"]["running-claim"] = {"origin": ASSISTANT, "task_id": "T01", "L": "active",
            "E": {"state": "running"}, "R": ["reserved"], "W": {"state": "draft"}, "epoch": 1}
        old_claims = deepcopy(state["claims"])
        env = {"event_id": "new-publication", "payload": {"op": "publish", "task_id": "T01", "scope_version": 1,
               "reason": "current user authorized opening", "_audit": {"actor": PERSON}}}
        rules.action(state, env, {"now": time.time()})
        self.assertTrue(task["contract"]["open"])
        self.assertNotIn("hold_reason", task["contract"])
        self.assertEqual(task["contract"]["publication_reason"], "current user authorized opening")
        self.assertEqual(state["claims"], old_claims)


class ConsentEditor(unittest.TestCase):
    def setUp(self):
        self.service = FixtureService()
        self.state = self.service.state

    def body(self, **changes):
        data = {"request_id": "fixture-consent", "executor_id": ASSISTANT, "project_id": "project-one", "version": "0",
                "expiry_mode": "renew", "expires": "0", "hours": "8", "reason": "keep user input", "action_read": "1", "task_T01": "1"}
        data.update(changes)
        return data

    def send(self, data):
        headers = Message()
        headers["Host"], headers["Origin"] = "localhost:8765", "http://localhost:8765"
        handler = SimpleNamespace(server=SimpleNamespace(service=self.service, is_round=True, tls=None),
            form_token="a" * 64, headers=headers,
            request_body=lambda kind, limit: urlencode({**data, "csrf": "a" * 64}).encode())
        return delegation_pages.dispatch(handler, "POST", urlsplit("/assistants"), PERSON)

    def test_one_editor_task_selection_no_page_clock_and_exact_current_actions_expiry(self):
        p = grant_payload(self.state, actions=["read", "feedback-update"], task_ids=["T01"])
        decide(self.state, p)
        html = delegation_pages.render(PERSON, self.state)[1].decode()
        self.assertEqual(html.count('name="operation" value="grant-preview"'), 1)
        self.assertIn('name="task_T01" value="1" checked', html)
        self.assertIn('name="action_feedback-update" value="1" checked', html)
        self.assertNotIn('name="action_claim" value="1" checked', html)
        self.assertIn(f'name="expires" value="{p["expires"]}"', html)
        self.assertIn('<option value="keep" selected', html)
        self.assertNotIn('name="issued"', html)

    def test_preview_does_not_apply_and_confirmation_retains_exact_actions_tasks_and_expiry(self):
        status, html, *_ = self.send(self.body(operation="grant-preview"))
        self.assertEqual(status, 200)
        self.assertFalse(self.service.calls)
        self.assertIn("保存前核对".encode(), html)
        self.assertIn(b'name="operation" value="grant"', html)
        self.send(self.body(operation="grant"))
        body = self.service.calls[-1][3]
        self.assertEqual((body["actions"], body["task_ids"], body["duration_seconds"]), (["read"], ["T01"], 8 * 3600))

    def test_edit_keeps_custom_actions_and_exact_expiry_not_remaining_rounded_hours(self):
        p = grant_payload(self.state, actions=["read", "task-hold"], task_ids=["T01"])
        decide(self.state, p)
        body = delegation_pages.grant_body(self.state, PERSON, self.body(version="1", expiry_mode="keep", expires=str(p["expires"]), **{"action_task-hold": "1"}))
        self.assertEqual(body["actions"], ["read", "task-hold"])
        self.assertEqual(body["expires"], p["expires"])
        self.assertNotIn("duration_seconds", body)

    def test_failed_validation_preserves_reason_scope_and_controls(self):
        status, html, *_ = self.send(self.body(operation="grant-preview", hours="999"))
        self.assertEqual(status, 400)
        self.assertIn(b"keep user input", html)
        self.assertIn(b'name="task_T01" value="1" checked', html)
        self.assertFalse(self.service.calls)

    def test_old_open_forms_count_duration_at_service_acceptance(self):
        data = {"request_id": "old-form", "executor_id": ASSISTANT, "project_id": "project-one", "version": "0",
                "preset": "task", "task_ids": "T01", "hours": "1", "issued": "1", "reason": "old page"}
        body = delegation_pages.grant_body(self.state, PERSON, data)
        with patch("pool.delegation.time.time", return_value=2000000000):
            planned = delegation.plan(None, PERSON, "delegate-grant", "key", body, self.state)
        self.assertEqual(planned["steps"][0]["payload"]["expires"], 2000003600)

    def test_expired_delegation_hides_revoke_and_retains_history(self):
        p = grant_payload(self.state)
        decide(self.state, p)
        row = self.state["round"]["delegation:" + p["delegation_id"]]
        row["expires"] = 1
        html = delegation_pages.render(PERSON, self.state)[1].decode()
        self.assertNotIn('name="operation" value="revoke"', html)
        self.assertIn("委托版本与代办记录", html)

    def test_ledger_history_preserves_prior_actions_and_expiry_after_edit_and_revoke(self):
        first = grant_payload(self.state, actions=["read", "task-hold"])
        decide(self.state, first)
        decide(self.state, grant_payload(self.state, actions=["read"], version=1))
        row = self.state["round"]["delegation:" + first["delegation_id"]]
        decide(self.state, {"op": "delegate-revoke", "delegation_id": row["id"], "version": 2, "reason": "fixture revoke"})
        self.assertEqual([r["version"] for r in row["history"]], [1, 2])
        self.assertEqual(row["history"][0]["actions"], ["read", "task-hold"])
        self.assertEqual(row["history"][0]["expires"], first["expires"])

    def test_actual_submit_persists_first_deadline_and_same_request_replay_never_replans(self):
        service = object.__new__(Service)
        service.lock, service.pinned = RLock(), SimpleNamespace(active=False, snap=None)
        service.lifecycle = SimpleNamespace(check_new_work=lambda *args: None)
        service.db = sqlite3.connect(":memory:")
        service.db.executescript("CREATE TABLE requests(key TEXT, fingerprint TEXT, actor TEXT, action TEXT, body BLOB, plan BLOB, status INTEGER, response BLOB); CREATE TABLE request_context(request_key TEXT, details BLOB);")
        service.snapshot = lambda: {"state": self.state, "head": 1, "entries": []}
        service.recover = lambda: True
        service.plan = lambda actor, action, key, body, snap: delegation.plan(service, actor, action, key, body, snap["state"])
        service.receipt_authorization = lambda *args: None
        service.credential_result = lambda key, action, response: response
        observed = []
        def execute(key):
            plan = json.loads(service.db.execute("SELECT plan FROM requests WHERE key=?", (key,)).fetchone()[0])
            observed.append(plan["steps"][0]["payload"]["expires"])
            response = {"status": "applied", "expires": observed[-1]}
            service.db.execute("UPDATE requests SET status=200, response=? WHERE key=?", (encoded(response), key))
            return 200, response
        service.execute = execute
        body = delegation_pages.grant_body(self.state, PERSON, self.body())
        try:
            with patch("pool.delegation.time.time", return_value=2000000000):
                first = service.submit(PERSON, "delegate-grant", body["request_id"], body)
            with patch("pool.delegation.time.time", return_value=2000007200):
                replay = service.submit(PERSON, "delegate-grant", body["request_id"], body)
            self.assertEqual(first, replay)
            self.assertEqual(observed, [2000000000 + 8 * 3600])
        finally:
            service.db.close()


if __name__ == "__main__":
    unittest.main()
