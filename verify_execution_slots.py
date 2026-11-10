"""Offline checks for execution slots, stopped delivery and restart competition."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

import pool
import 协作升级 as rules
from 协作存储 import Rejected


def fixture():
    state = {"pilot": {"format": {"schema": 3, "maintenance": False},
                      "project:p": {"id": "p", "name": "Fixture", "owner": "owner"},
                      "identity:owner": {"kind": "human", "owner": "owner", "status": "active"},
                      "identity:worker": {"kind": "executor", "owner": "owner", "status": "active"},
                      "grant:p:owner": {"roles": ["manager"], "resources": []},
                      "grant:p:worker": {"roles": ["executor"], "resources": []}},
             "round": {"runner:worker": {"limit": 1}}, "claims": {}, "reservations": {}, "tasks": {}}
    state["tasks"]["T1"] = {"task_id": "T1", "status": "running", "resources": [], "dependencies": [],
                            "contract": {"project_id": "p", "open": True, "requirements": []}}
    return state


def claim(cid="c1", **changes):
    value = {"claim_id": cid, "task_id": "T1", "origin": "worker", "L": "active", "epoch": 2,
             "E": {"state": "stopped", "reason": "complete"}, "R": [], "stop_evidence": "fixture process exited",
             "W": {"state": "review", "revision": "revision-1", "scope": 1},
             "deliveries": {"revision-1": {"status": "review", "manifest": {"path": "deliveries/fixture/manifest.json", "sha256": "a" * 64}}}}
    value.update(changes)
    return value


class ExecutionSlots(unittest.TestCase):
    def setUp(self):
        self.state = fixture()
        self.state["claims"]["c1"] = claim()

    def test_stopped_sealed_review_frees_slot_without_ending_business_claim(self):
        before = deepcopy(self.state)
        load = rules.execution_load(self.state, "worker")
        self.assertEqual((load["active_claims"], load["executing"], load["awaiting_review"], load["limit_exempt"]), (1, 0, 1, 1))
        self.assertEqual(self.state, before)
        task = {**self.state["tasks"]["T1"], "status": "available"}
        self.assertNotIn("窗口并发上限已满", rules.eligible(self.state, task, "worker", 1)[0])

    def test_stopped_accepted_delivery_can_also_free_slot(self):
        current = self.state["claims"]["c1"]
        current["W"]["state"] = "complete"
        current["deliveries"]["revision-1"]["status"] = "accepted"
        self.assertEqual(rules.execution_load(self.state, "worker")["limit_exempt"], 1)

    def test_resource_stop_and_seal_uncertainty_keep_slot(self):
        changes = [
            {"R": ["reserved"]}, {"stop_evidence": ""}, {"stop_evidence": None},
            {"E": {"state": "requested", "reason": "complete"}},
            {"W": {"state": "draft", "revision": 1}}, {"W": {"state": "revision", "revision": "revision-1"}},
            {"W": {"state": "review", "revision": "missing"}}, {"deliveries": {}},
            {"recovery": {"status": "pending"}}, {"recovery": {"status": "unknown"}},
        ]
        for values in changes:
            with self.subTest(values=values):
                self.state["claims"]["c1"] = claim(**values)
                self.assertEqual(rules.execution_load(self.state, "worker")["executing"], 1)

    def test_active_reservation_cannot_be_hidden_by_an_empty_claim_resource_list(self):
        self.state["reservations"]["orphan"] = {"claim_id": "c1", "active": True}
        self.assertEqual(rules.execution_load(self.state, "worker")["limit_exempt"], 0)

    def test_another_actor_and_ended_claim_do_not_fill_this_window(self):
        self.state["claims"]["c2"] = claim("c2", origin="other", E={"state": "running"})
        self.state["claims"]["c3"] = claim("c3", L="ended", E={"state": "running"})
        self.assertEqual(rules.execution_load(self.state, "worker")["active_claims"], 1)

    def guard(self, command, epoch=2):
        body = {"claim_id": "c1", "_audit": {"schema": 3, "actor": "worker",
                                             "authorization": rules.auth_stamp(self.state, "worker", "p")}}
        env = {"command": command, "payload": body, "origin_id": "worker",
               "expects": {} if epoch is None else {"epoch:c1": epoch}}
        return rules.guard(self.state, env, {"now": 1})

    def test_restart_excludes_current_claim_but_rejects_another_executing_claim(self):
        current = self.state["claims"]["c1"]
        current["W"]["state"] = "revision"
        self.guard("acquire")
        current["E"] = {"state": "stopped", "reason": "pause"}
        self.guard("resume")
        self.state["claims"]["c2"] = claim("c2", E={"state": "running"})
        for command in ("acquire", "resume"):
            with self.subTest(command=command), self.assertRaisesRegex(Rejected, "并发"):
                self.guard(command)

    def test_restart_does_not_treat_another_stopped_review_as_executing(self):
        self.state["claims"]["c1"]["W"]["state"] = "revision"
        self.state["claims"]["c2"] = claim("c2")
        self.guard("acquire")

    def test_restart_needs_current_epoch_even_when_slot_is_available(self):
        for command in ("acquire", "resume"):
            for epoch in (None, 1):
                with self.subTest(command=command, epoch=epoch), self.assertRaisesRegex(Rejected, "代次"):
                    self.guard(command, epoch)

    def test_existing_role_and_capability_checks_still_apply(self):
        self.state["pilot"]["grant:p:worker"]["roles"] = []
        with self.assertRaisesRegex(Rejected, "授权"):
            self.guard("acquire")

    def test_claim_does_not_oversubscribe_after_first_restart_takes_slot(self):
        self.state["claims"]["c1"]["W"]["state"] = "revision"
        self.guard("acquire")
        self.state["claims"]["c1"]["E"] = {"state": "running", "reason": None}
        task = {**self.state["tasks"]["T1"], "status": "available"}
        self.assertIn("窗口并发上限已满", rules.eligible(self.state, task, "worker", 1)[0])




if __name__ == "__main__":
    unittest.main()
