"""Two UI projections for new actions while the original claim.run remains unchanged."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from pool import service, task_pages, workbench


def view(stage, status):
    task = {"task_id": "T01", "title": "Fixture", "status": "running", "version": 1, "scope_version": 1,
            "receiver": "reviewer", "inputs": {}, "completes_on": ["done"], "dependencies": []}
    claim = {"claim_id": "c1", "origin": "worker", "epoch": 1, "E": {"state": "running"}, "L": "active", "R": [],
             "W": {"state": "draft", "scope": 1}, "run": {"state": "claimed", "evidence": "original receipt"}}
    return {"task": task, "active": claim, "stage": stage, "execution_protocol": 5, "execution_status": status,
            "roles": ["executor"], "qualification": {"eligible": True, "missing": []}, "deliveries": [], "handoffs": [],
            "items": [], "close": None, "cancel_note": None}


class ProjectionTests(unittest.TestCase):
    def test_started_action_does_not_show_old_claimed_report_or_begin_form(self):
        data = view("running", {"actions": 1, "running": 1, "awaiting_start": 0, "unconfirmed": 0, "finished": 0})
        before = deepcopy(data)
        state = {"security": {"schema": 5, "execution": {"claim_bindings": {"c1": {}},
                 "actions": {"a1": {"claim_id": "c1", "epoch": 1, "scope_version": 1, "state": "running", "grant_id": "g1"}},
                 "grants": {"g1": {"physical": "in-use"}}}}}
        self.assertEqual(service.execution_status(state, data["active"])["unconfirmed"], 0)
        self.assertEqual(service.stage(data["task"], data["active"], state), "running")
        state["security"]["execution"]["actions"]["a1"]["state"] = "finished"
        self.assertEqual(service.execution_status(state, data["active"])["unconfirmed"], 1)
        self.assertEqual(service.stage(data["task"], data["active"], state), "recovery")
        primary = workbench.worker_box("worker", data)
        self.assertIn("执行段与资源", primary); self.assertNotIn("/actions/run-report", primary)
        with patch("pool.upgrade_pages.task_contract", return_value=""):
            legacy = task_pages.detail("worker", data)
        self.assertIn("实际执行中 1", legacy)
        self.assertNotIn("待开始", legacy); self.assertNotIn("执行回报待确认", legacy)
        self.assertNotIn("/actions/run-report", legacy)
        self.assertEqual(data, before)

    def test_permit_and_unknown_are_not_external_start_or_completion(self):
        data = view("claimed", {"actions": 1, "running": 0, "awaiting_start": 1, "unconfirmed": 0, "finished": 0})
        before = deepcopy(data)
        self.assertIn("许可已发，实际开工待回报 1", task_pages.execution_runtime(data))
        self.assertNotIn("实际执行中 1", task_pages.execution_runtime(data))
        unknown = {**data, "stage": "recovery", "execution_status": {"actions": 1, "running": 0, "unconfirmed": 1, "finished": 1}}
        text = task_pages.execution_runtime(unknown)
        self.assertIn("执行事实待确认 1", text); self.assertIn("已登记结束事实 1", text)
        self.assertNotIn("已回报完成", text)
        self.assertEqual(data, before)


if __name__ == "__main__": unittest.main()
