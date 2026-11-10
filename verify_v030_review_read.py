"""Exact-revision return reasons, read permissions and nonautomatic notice regressions."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pool import round_service, workbench
from pool.packages import ClientError
from pool.service import Service
from 协作存储 import encoded
from verify_delegation import ASSISTANT, PERSON, fixture


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("review_read_client", ROOT / "ops/round-client.py")
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


def fixture_service():
    state = fixture()
    task = state["tasks"]["T01"]
    state["tasks"] = {"T01": task}
    task.update(status="running", receiver=PERSON, version=5, scope_version=1, title="synthetic return task")
    task["contract"].update(open=True, requirements=[])
    claim = {"claim_id": "claim-one", "task_id": "T01", "origin": ASSISTANT, "L": "active", "epoch": 3,
             "E": {"state": "stopped", "reason": "complete"}, "R": [], "W": {"state": "revision", "revision": "revision-2", "scope": 1},
             "deliveries": {}, "inputs": {}}
    state["claims"] = {claim["claim_id"]: claim}
    task["claims"] = [claim["claim_id"]]
    state.update(acceptances={}, items={}, notes={}, closings={})
    entries = []
    for number in (1, 2):
        revision, aid, digest = "revision-" + str(number), str(number) * 64, str(number + 2) * 64
        manifest = {"path": "deliveries/fixture/" + revision + "/manifest.json", "sha256": digest}
        claim["deliveries"][revision] = {"revision": revision, "scope_version": 1, "manifest": manifest,
            "manifest_sha256": digest, "seal_seq": number * 10, "status": "revision", "acceptance_id": aid,
            "criteria": ["first", "second", "passed"], "remaining": []}
        acceptance = {"acceptance_id": aid, "task_id": "T01", "claim_id": "claim-one", "revision": revision,
                      "scope_version": 1, "manifest": deepcopy(manifest), "manifest_sha256": digest,
                      "verdict": "revision", "origin": PERSON, "seq": number * 10 + 1,
                      "checks": [{"id": "first", "status": "failed", "evidence": {"note": "criterion one reason " + str(number)}},
                                 {"id": "second", "status": "failed", "evidence": {"note": "criterion two reason " + str(number)}},
                                 {"id": "passed", "status": "passed", "evidence": {"note": "already passed"}}]}
        state["acceptances"][aid] = acceptance
        entries.append({"type": "decision", "result": "applied", "command": "review", "key": PERSON + "/" + aid,
                        "origin_id": PERSON, "ledger_seq": number * 10 + 1,
                        "committed_utc": f"2026-11-09T12:0{number}:00Z",
                        "request": {"actor": PERSON, "reason": "exact return reason " + str(number)},
                        "effects": [{"path": ["acceptances", aid], "value": deepcopy(acceptance)}]})
    state["pilot"]["identity:system-admin"] = {"kind": "human", "owner": "system-admin", "status": "active", "admin": True}
    state["pilot"]["identity:manager-only"] = {"kind": "human", "owner": "manager-only", "status": "active"}
    state["pilot"]["grant:project-one:manager-only"] = {"roles": ["manager"], "resources": [], "version": 1}
    service = object.__new__(Service)
    service.is_admin = lambda actor: actor == "system-admin"
    service.visible = lambda current, selected, actor: actor != "forbidden"
    service.snapshot = lambda: {"state": state, "entries": entries}
    service.qualification = lambda *args: {"eligible": False, "missing": [], "preferred": []}
    service.task_roles = lambda *args: ["executor"]
    service.independent_roles = lambda *args: ["executor"]
    service.delegated_actions = lambda *args: []
    service.delivery_refs = lambda *args: []
    return service, state, task, claim, entries


class ReviewRead(unittest.TestCase):
    def setUp(self):
        self.service, self.state, self.task, self.claim, self.entries = fixture_service()

    def test_two_revisions_keep_exact_manifest_reasons_and_original_reviewer_times(self):
        view = self.service.task_view(self.state, self.task, ASSISTANT)
        self.assertEqual(len(view["delivery_reviews"]), 2)
        for number, row in enumerate(view["delivery_reviews"], 1):
            self.assertEqual(row["revision"], "revision-" + str(number))
            self.assertEqual(row["reason"], "exact return reason " + str(number))
            self.assertEqual(row["at"], f"2026-11-09T12:0{number}:00Z")
            self.assertEqual(row["reviewer"], PERSON)
            self.assertEqual(row["manifest_sha256"], str(number + 2) * 64)
            self.assertEqual(row["failed_criteria"], ["first", "second"])
            self.assertEqual(row["review"]["acceptance_id"], str(number) * 64)

    def test_nonparticipant_even_project_manager_gets_no_additional_review_facts(self):
        for actor in ("window-two", "manager-only"):
            with self.subTest(actor=actor):
                view = self.service.task_view(self.state, self.task, actor)
                self.assertEqual(view["delivery_reviews"], [])
        for actor in (ASSISTANT, PERSON, "system-admin"):
            with self.subTest(actor=actor):
                self.assertEqual(len(self.service.task_view(self.state, self.task, actor)["delivery_reviews"]), 2)
        with self.assertRaises(ClientError):
            self.service.task_view(self.state, self.task, "forbidden")

    def test_reading_never_mutates_state_and_raw_claim_shape_preserves_active_membership(self):
        before = encoded(self.state)
        view = self.service.task_view(self.state, self.task, ASSISTANT)
        self.assertEqual(view["claims"], [self.claim])
        self.assertIsNot(view["claims"][0], self.claim)
        self.assertNotIn("review", view["claims"][0]["deliveries"]["revision-1"])
        view["delivery_reviews"][0]["review"]["checks"][0]["evidence"]["note"] = "caller mutation"
        view["claims"][0]["deliveries"]["revision-1"]["criteria"].append("caller mutation")
        self.assertEqual(encoded(self.state), before)

    def test_web_detail_still_has_active_claim_original_reviews_and_resume_control(self):
        detail = self.service.detail(self.state, self.task, ASSISTANT)
        self.assertEqual(detail["active"], self.claim)
        self.assertEqual(detail["deliveries"][0]["review"], self.state["acceptances"]["1" * 64])
        self.assertIn('/actions/resume', workbench.worker_box(ASSISTANT, detail))

    def test_cross_revision_acceptance_id_or_manifest_or_scope_is_never_substituted(self):
        original = deepcopy(self.claim["deliveries"]["revision-1"])
        for changes in ({"acceptance_id": "2" * 64}, {"manifest_sha256": "f" * 64}, {"scope_version": 2}):
            self.claim["deliveries"]["revision-1"] = {**deepcopy(original), **changes}
            rows = self.service.task_view(self.state, self.task, ASSISTANT)["delivery_reviews"]
            self.assertEqual([row["revision"] for row in rows], ["revision-2"])

    def test_missing_or_mismatched_original_event_uses_exact_check_notes_and_unknown_time(self):
        self.entries[1]["effects"][0]["value"]["manifest_sha256"] = "f" * 64
        row = self.service.task_view(self.state, self.task, ASSISTANT)["delivery_reviews"][1]
        self.assertEqual(row["reason"], "criterion one reason 2\ncriterion two reason 2")
        self.assertIsNone(row["at"])
        self.assertIsNone(row["source_event"])
        self.assertNotIn("exact return reason 1", row["reason"])


class ReturnNotices(unittest.TestCase):
    def setUp(self):
        self.service, self.state, self.task, self.claim, self.entries = fixture_service()
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.notices = round_service.Notices(self.db)

    def poll(self, request="poll-one", actor=ASSISTANT):
        return self.notices.poll(self.state, actor, {"request_id": request, "cursor": 0}, self.service)

    def test_latest_return_notification_is_stable_nonautomatic_and_same_poll_has_no_duplicates(self):
        first = self.poll()
        self.assertEqual(first, self.poll())
        self.assertEqual(len(first["events"]), 1)
        event = first["events"][0]
        self.assertEqual((event["type"], event["auto"], event["revision"]), ("review-returned", False, "revision-2"))
        self.assertEqual(event["failed_criteria"], ["first", "second"])
        self.assertEqual(event["reason"], "exact return reason 2")
        self.assertEqual(self.db.execute("SELECT count(*) FROM round_notices").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT count(*) FROM round_notice_log").fetchone()[0], 1)

    def test_explicit_retry_reuses_event_and_repeated_request_does_not_duplicate_queue(self):
        event = self.poll()["events"][0]
        body = {"request_id": "retry-one", "event_id": event["event_id"]}
        self.assertEqual(self.notices.retry(self.state, ASSISTANT, body), self.notices.retry(self.state, ASSISTANT, body))
        resent = self.poll("poll-after-retry")["events"][0]
        self.assertEqual((resent["event_id"], resent["auto"]), (event["event_id"], False))
        self.assertEqual(self.db.execute("SELECT count(*) FROM round_notices").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT count(*) FROM round_notice_log WHERE stage='retry'").fetchone()[0], 1)

    def test_acknowledged_return_is_not_reissued_and_new_delivery_suppresses_old_notice(self):
        event = self.poll()["events"][0]
        self.notices.acknowledge(ASSISTANT, {"request_id": "ack-one", "event_id": event["event_id"]})
        self.assertEqual(self.poll("poll-two")["events"], [])
        self.claim["deliveries"]["revision-3"] = {"revision": "revision-3", "seal_seq": 30, "status": "review"}
        self.assertEqual(self.poll("poll-three")["events"], [])
        self.assertEqual(self.notices._returned(self.state, ASSISTANT), {})

    def test_only_current_authorized_holder_receives_return(self):
        self.assertEqual(self.poll(actor="window-two")["events"], [])
        self.service.visible = lambda *args: False
        self.assertEqual(self.poll()["events"], [])
        self.service.visible = lambda *args: True
        self.claim["L"] = "ended"
        self.assertEqual(self.poll()["events"], [])

    def test_runner_does_not_claim_resume_or_start_process_for_return_notification(self):
        event = self.poll()["events"][0]
        state = SimpleNamespace(data={"token": "synthetic", "command": [sys.executable], "workdir": str(ROOT)}, save=lambda: None)
        calls = []
        def api_call(route, *args, **kwargs):
            calls.append(route)
            if route != "notices-poll":
                raise AssertionError("return notice triggered a write or start")
            return {"cursor": 1, "events": [event]}
        with patch.object(client.subprocess, "Popen", side_effect=AssertionError("external execution")):
            result = client.run_once(state, SimpleNamespace(call=api_call))
        self.assertEqual(result["status"], "idle")
        self.assertEqual(calls, ["notices-poll"])


if __name__ == "__main__":
    unittest.main()
