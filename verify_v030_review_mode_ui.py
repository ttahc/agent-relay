"""The explicit human review exception follows backend qualification, without changing task state."""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from urllib.parse import urlsplit
from pool import web, workbench


class ReviewModeUiTests(unittest.TestCase):
    def test_explicit_user_mode_allows_same_receiver_but_source_and_missing_basis_block(self):
        task = {"task_id": "T1026", "version": 1, "scope_version": 1, "status": "available", "stage": "available", "receiver": "admin",
                "contract": {"review_mode": "user", "user_basis": "Explicit human direct acceptance"}, "qualification": {"eligible": True, "missing": []}}
        view = {"task": task, "active": None, "roles": ["executor"], "qualification": task["qualification"]}
        before = deepcopy(view)
        self.assertEqual(workbench.claim_block(task, "admin"), "")
        self.assertIn('action="/actions/claim"', workbench.worker_box("admin", view))
        self.assertEqual(view, before)
        for mode, basis in (("source", "Explicit basis"), ("user", ""), ("user", "  ")):
            blocked = {**task, "contract": {"review_mode": mode, "user_basis": basis}}
            self.assertIn("验收人", workbench.claim_block(blocked, "admin"))
            self.assertNotIn('action="/actions/claim"', workbench.worker_box("admin", {**view, "task": blocked}))
        denied = {**task, "qualification": {"eligible": False, "missing": ["backend qualification denied"]}}
        self.assertEqual(workbench.claim_block(denied, "admin"), "backend qualification denied")
        self.assertNotIn('action="/actions/claim"', workbench.worker_box("admin", {**view, "task": denied, "qualification": denied["qualification"]}))

    def test_same_holder_user_review_has_matching_single_home_badge_and_body(self):
        task = {"task_id": "T1026", "title": "Fixture review", "stage": "review", "receiver": "admin", "holder": "admin", "dependencies": [],
                "contract": {"project_id": "p", "review_mode": "user", "user_basis": "Explicit direct acceptance", "dispatch": {"owner": "admin"}}}
        data = {"tasks": [task, deepcopy(task)], "projects": [{"id": "p", "name": "P", "roles": ["executor", "receiver"]}], "feedback_due": 0}
        before = deepcopy(data)
        service = SimpleNamespace(read=lambda *args: data, is_admin=lambda actor: False)
        body = web.html_page("我的工作 · fixture", workbench.mine_page("admin", data, {}))[1]
        html = workbench.adopt(body, urlsplit('/'), "admin", service).decode()
        self.assertIn("待我处理<small>1 项</small>", html)
        self.assertIn('我的工作<span class="wb-count">1</span>', html)
        self.assertEqual(html.count('class="card-link" href="/tasks/T1026"'), 1)
        self.assertEqual(data, before)
        for mode, basis in (("source", "Explicit direct acceptance"), ("user", "")):
            blocked = deepcopy(data)
            for row in blocked["tasks"]: row["contract"].update(review_mode=mode, user_basis=basis)
            self.assertEqual(workbench.todo_reason(blocked["tasks"][0], "admin", {}), "")
            service.read = lambda *args: blocked
            body = web.html_page("我的工作 · fixture", workbench.mine_page("admin", blocked, {}))[1]
            html = workbench.adopt(body, urlsplit('/'), "admin", service).decode()
            self.assertIn("待我处理<small>0 项</small>", html)
            self.assertNotIn('我的工作<span class="wb-count">', html)


if __name__ == "__main__": unittest.main()
