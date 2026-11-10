"""Explicit schema-5 resume forms and separate historical physical facts, without a service."""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from pool import task_pages, web, workbench


class ResumeUiTests(unittest.TestCase):
    def test_resume_gets_protocol_and_optional_context_without_changing_original_binding(self):
        handler = SimpleNamespace(server=SimpleNamespace(service=SimpleNamespace(read=lambda *args: {"execution_protocol": 5})))
        fields = {"request_id": "resume-original", "claim_id": "c1", "epoch": "1", "scope_version": "2", "context_ref": "ctx-next:3"}
        before = deepcopy(fields)
        with patch("pool.web.parse_form", return_value=dict(fields)), patch("pool.round_web.current_actor", return_value="worker"):
            result = web.action_body(handler, "resume")
        self.assertEqual(result["execution_protocol"], 5)
        self.assertEqual((result["context_id"], result["context_version"]), ("ctx-next", 3))
        self.assertEqual((result["claim_id"], result["epoch"], result["scope_version"]), ("c1", 1, 2))
        self.assertEqual(fields, before)
        for work, reason in (("revision", "complete"), ("draft", "pause")):
            claim = {"origin": "worker", "claim_id": "c1", "epoch": 1, "W": {"state": work, "scope": 2}, "E": {"state": "stopped", "reason": reason}}
            view = {"task": {"status": "running", "contract": {"project_id": "p"}}, "active": claim, "roles": ["executor"], "execution_protocol": 5}
            self.assertIn('action="/actions/resume"', workbench.worker_box("worker", view))

    def test_historical_scope_counts_do_not_become_current_work_or_completion(self):
        view = {"execution_protocol": 5, "execution_status": {"actions": 0, "running": 0, "finished": 0, "unconfirmed": 0,
                "historical_live": 2, "historical_unconfirmed": 1}}
        before = deepcopy(view)
        markup = task_pages.execution_runtime(view)
        self.assertIn("本回合动作 0 项", markup)
        self.assertIn("历史未收口动作 2", markup)
        self.assertIn("历史占用待确认 1", markup)
        self.assertNotIn("实际执行中 2", markup)
        self.assertNotIn("已登记结束事实 2", markup)
        self.assertIn("原占用不自动释放", markup)
        self.assertEqual(view, before)


if __name__ == "__main__": unittest.main()
