"""Screenshot regressions: scoped badges and historical executor display, no live store."""
from copy import deepcopy
from threading import RLock
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from pool import service as model, web, workbench as wb


def task(tid="T1013", stage="review", project="p", title="keep"):
    return {"task_id": tid, "stage": stage, "status": "completed" if stage == "completed" else "running",
            "title": title, "receiver": "person", "holder": None, "window": None, "window_name": None,
            "claims": [], "created_seq": int(tid[1:]), "dependencies": [], "resources": [], "completes_on": ["ready"],
            "contract": {"project_id": project, "requirements": [], "dispatch": {"owner": ""}}}


class BadgesHistoryTests(unittest.TestCase):
    def test_one_task_plus_28_feedback_are_separate_and_match_filtered_home(self):
        one = task()
        data = {"tasks": [one, deepcopy(one), task("T1014", title="other"), task("T1015", project="other")],
                "projects": [{"id": "p", "name": "P", "roles": ["manager"]}], "feedback_due": 28}
        calls = []
        service = SimpleNamespace(read=lambda *args: calls.append(args) or data, is_admin=lambda actor: False)
        filters = {"project": "p", "q": "keep"}
        body = web.html_page("我的工作 · fixture", wb.mine_page("person", data, filters))[1]
        html = wb.adopt(body, urlsplit('/?project=p&q=keep'), "person", service).decode()
        self.assertIn('待我处理<small>1 项</small>', html)
        self.assertIn('我的工作<span class="wb-count">1</span>', html)
        self.assertIn('反馈与决定<span class="wb-count">28</span>', html)
        self.assertNotIn('wb-count">29', html)
        self.assertIn('当前筛选内待我处理的任务', html)
        self.assertEqual(calls, [("person", "overview", "p")])

    def test_project_scope_on_project_and_other_views(self):
        data = {"tasks": [task(), task("T1014", project="other")], "projects": [], "feedback_due": 4}
        calls = []
        service = SimpleNamespace(read=lambda *args: calls.append(args) or data, is_admin=lambda actor: False)
        page = web.html_page("fixture · fixture", '<main class="workspace"><header class="workspace-top"><div class="account"></div></header></main>')[1]
        for path in ('/projects/p', '/list?project=p&q=nomatch'):
            html = wb.adopt(page, urlsplit(path), "person", service).decode()
            self.assertIn('我的工作<span class="wb-count">1</span>', html)
            self.assertIn('当前项目内待我处理的任务', html)
            self.assertEqual(calls[-1], ("person", "overview", "p"))

    def test_feedback_counts_only_immediate_managed_statuses_and_project(self):
        state = {"round": {"feedback:" + str(i): {"project_id": project, "status": status} for i, (project, status) in enumerate(
            [("p", "triage"), ("p", "review"), ("p", "working"), ("p", "accepted"), ("other", "triage")])}}
        with patch.object(model.rules, "manager", side_effect=lambda state, project, actor: actor == "manager"):
            self.assertEqual(model.Service.feedback_due(None, state, "manager"), 3)
            self.assertEqual(model.Service.feedback_due(None, state, "manager", "p"), 2)
            self.assertEqual(model.Service.feedback_due(None, state, "manager", "other"), 1)
            self.assertEqual(model.Service.feedback_due(None, state, "observer", "p"), 0)

    def test_overview_last_executor_is_display_only_without_recreating_holder(self):
        closed = task(stage="completed")
        closed["claims"] = ["old", "latest"]
        empty = task("T1014", stage="completed")
        state = {"tasks": {closed["task_id"]: closed, empty["task_id"]: empty}, "round": {},
                 "claims": {key: {"claim_id": key, "task_id": closed["task_id"], "origin": who, "L": "closed",
                                   "E": {"state": "stopped"}, "epoch": index, "deliveries": {}}
                            for index, (key, who) in enumerate((("old", "old-window"), ("latest", "last-window")), 1)}}
        original = deepcopy(state)
        service = model.Service.__new__(model.Service)
        service.lock = RLock()
        service.snapshot = lambda: {"state": state}
        service.visible = lambda *args: True
        service.qualification = lambda *args: {"eligible": False}
        service.roles = lambda *args: []
        identities = {"last-window": {"window": "CDX-0042", "window_name": "Last executor", "directory": "private-must-not-leak"}}
        with patch.object(model.rules, "enabled", return_value=True), patch.object(model.round_service, "enabled", return_value=True), \
             patch.object(model.rules, "identity", side_effect=lambda state, name: identities.get(name)), \
             patch.object(model.rules, "project_record", return_value={"name": "P"}), patch.object(model.upgrade, "projects", return_value=[]):
            rows = service.read("person", "overview", "p")["tasks"]
        self.assertIsNone(rows[0]["holder"])
        self.assertIsNone(rows[0]["window"])
        self.assertEqual(rows[0]["last_claim_id"], "latest")
        self.assertEqual(rows[0]["last_executor"], {"id": "last-window", "window": "CDX-0042", "window_name": "Last executor"})
        self.assertIsNone(rows[1]["last_executor"])
        self.assertIsNone(rows[1]["last_claim_id"])
        self.assertEqual(state, original)
        self.assertIn("Last executor", wb.worker_avatar(rows[0]))
        self.assertIn("历史执行", wb.worker_avatar(rows[0]))
        self.assertNotIn("private-must-not-leak", str(rows))
        self.assertTrue(wb.matches(rows[0], "person", {"window": "CDX-0042"}))
        self.assertTrue(wb.matches(rows[0], "person", {"q": "执行:Last"}))
        self.assertIn("无执行记录", wb.worker_avatar(rows[1]))
        self.assertEqual(wb.live_tasks(rows), [])

    def test_available_task_does_not_adopt_historical_current_ownership(self):
        row = task(stage="available")
        row["last_executor"] = {"id": "person", "window": "CDX-0042", "window_name": "Past"}
        self.assertIs(wb.executor_item(row), row)
        self.assertIn("未领取", wb.worker_avatar(row))
        self.assertFalse(wb.matches(row, "person", {"window": "Past"}))
        self.assertIsNone(row["holder"])

    def test_claimed_label_does_not_assert_external_execution_has_not_started(self):
        row = task(stage="claimed")
        original = deepcopy(row)
        markup = wb.card("person", row, {}, False)
        self.assertIn("已领取", markup)
        self.assertIn("执行回报待确认", markup)
        self.assertNotIn("待开始", markup)
        self.assertEqual(wb.column_of(row), "doing")
        self.assertEqual(row, original)
        actual = {**row, "stage": "running"}
        self.assertNotIn("执行回报待确认", wb.card("person", actual, {}, False))

    def test_home_groups_are_exclusive_without_losing_roles_or_filters(self):
        review = task("T1012", "review")
        running = task("T1013", "running")
        running["holder"] = "person"
        available = task("T1014", "available")
        available["receiver"] = "someone-else"
        available["qualification"] = {"eligible": True}
        for row in (review, running, available):
            row["contract"]["dispatch"]["owner"] = "person"
        observer_only = task("T1015", "available", "observer-project")
        observer_only.update(receiver="someone-else", qualification={"eligible": True})
        data = {"tasks": [review, deepcopy(review), running, available, observer_only],
                "projects": [{"id": "p", "roles": ["executor"]}, {"id": "observer-project", "roles": ["observer"]}]}
        original = deepcopy(data)
        groups = wb.home_groups("person", data, {})
        ids = lambda name: [row["task_id"] for _, row in groups[name]]
        self.assertEqual(ids("todo"), ["T1012"])
        self.assertEqual(ids("doing"), ["T1013"])
        self.assertEqual(ids("owned"), ["T1014"])
        self.assertEqual(ids("can"), [])
        self.assertEqual(ids("cannot"), [])
        self.assertEqual(data, original)
        filtered = wb.home_groups("person", data, {"q": "T1013"})
        self.assertEqual([row["task_id"] for _, row in filtered["doing"]], ["T1013"])
        self.assertTrue(all(not filtered[key] for key in ("todo", "owned", "can", "cannot")))
        markup = wb.mine_page("person", data, {})
        self.assertEqual(markup.count('class="card-link" href="/tasks/T1012"'), 1)
        self.assertEqual(markup.count('class="card-link" href="/tasks/T1013"'), 1)
        self.assertEqual(markup.count('class="card-link" href="/tasks/T1014"'), 1)


if __name__ == "__main__":
    unittest.main()
