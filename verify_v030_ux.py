"""Focused v0.3 UX contracts using synthetic in-memory data; no live service."""

from copy import deepcopy
from datetime import datetime, timezone
import json
from threading import RLock
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit

from pool import display_time, round_web, upgrade_pages, web, workbench, workbench_pages
from pool.packages import ClientError
import 协作升级 as rules


def task(tid, owner="owner", receiver="reviewer"):
    return {"task_id": tid, "title": "title-" + tid, "stage": "claimed", "created_seq": int(tid[1:]),
            "receiver": receiver, "holder": None, "dependencies": [], "resources": [], "completes_on": ["ready"],
            "project_name": "Fixture", "contract": {"project_id": "fixture", "requirements": [], "dispatch": {"owner": owner}}}


class InvitationService:
    lock = RLock()

    def read(self, actor, route, argument=None):
        if route == "projects":
            return {"projects": [{"id": "fixture", "name": "Fixture", "roles": ["manager"]}]}
        if route == "invitation-owners":
            return [{"identity": "person", "name": "Person", "kind": "human", "status": "active"}]
        if route == "invitations":
            return {"invitations": []}
        raise AssertionError(route)

    def submit(self, *args, **kwargs):
        return 409, {"message": "角色已变化，请核对授权"}


class UxTests(unittest.TestCase):
    def test_hong_kong_rollover_and_utc_title(self):
        value = "2026-11-09T20:15:00Z"
        epoch = datetime(2026, 11, 9, 20, 15, tzinfo=timezone.utc).timestamp()
        self.assertEqual(display_time.local_text(value), "2026-11-10 04:15 UTC+8")
        self.assertEqual(display_time.time_html(value), display_time.time_html(epoch))
        self.assertIn('title="2026-11-09 20:15:00 UTC"', display_time.time_html(value))
        self.assertEqual(display_time.local_text("2026-11-09T20:15:00-05:00"), "2026-11-10 09:15 UTC+8")
        self.assertEqual(display_time.time_html("bad<script>"), "—")

    def test_grouping_and_visible_filters_use_task_fields(self):
        data = {"projects": [{"id": "fixture", "roles": ["observer"]}],
                "tasks": [task("T11", "owner-a", "receiver-a"), task("T12", "owner-b", "receiver-b")]}
        for key, expected in (("owner", "owner-a"), ("receiver", "receiver-a")):
            page = workbench.board("viewer", data, {"lane": key})
            self.assertIn(f'<div class="lane">{expected}', page)
        page = workbench.list_page("viewer", data, {"owner": "owner-a", "receiver": "receiver-a"}, [])
        self.assertIn("title-T11", page)
        self.assertNotIn("title-T12", page)
        self.assertIn('name="owner"', page)
        self.assertIn('name="receiver"', page)
        self.assertIn("data-saved-views", page)

    def test_multiple_prerequisites_keep_real_backend_gates(self):
        dep_a = [{"task": "T11", "output": "delivery", "criterion": "ready"}]
        dep_b = [{"task": "T12", "output": "delivery", "criterion": "ready"}]
        fields = [("quick", "1"), ("request_id", "fixture"), ("title", "Dependent"), ("brief", "Frozen"),
                  ("criteria", "ready"), ("receiver", "reviewer"), ("project_id", "fixture"),
                  ("dispatch_mode", "open"), ("dispatch_owner", "person"), ("cap-markdown", "skill:declared"),
                  ("depends_on", json.dumps(dep_a)), ("depends_on", json.dumps(dep_b)), ("depends_on", json.dumps(dep_a))]
        handler = SimpleNamespace(server=SimpleNamespace(is_round=True),
                                  request_body=lambda *args: urlencode(fields).encode())
        with patch("pool.round_web.verify_form"):
            body = web.action_body(handler, "register")
        self.assertEqual(body["dependencies"], dep_a + dep_b)
        self.assertFalse(handler.open_now)
        state = {"pilot": {"format": {"schema": 2}, "project:fixture": {"id": "fixture"},
                           "identity:person": {"kind": "human", "status": "active", "owner": "person"},
                           "grant:fixture:person": {"roles": ["executor"], "resources": []}},
                 "origins": {"person": {"roles": []}}, "tasks": {"T11": task("T11"), "T12": task("T12")}}
        checked = rules.dependency_rows(state, body["dependencies"], "fixture")
        dependent = {**task("T13"), "status": "available", "dependencies": checked,
                     "contract": {"project_id": "fixture", "requirements": [], "open": True}}
        missing, _ = rules.eligible(state, dependent, "person", 1, check_resources=False)
        self.assertTrue(any("T11" in row for row in missing))
        self.assertTrue(any("T12" in row for row in missing))
        state["tasks"]["T11"]["provided"] = {"delivery": ["ready"]}
        missing, _ = rules.eligible(state, dependent, "person", 1, check_resources=False)
        self.assertFalse(any("T11" in row for row in missing))
        self.assertTrue(any("T12" in row for row in missing))
        state["tasks"]["T12"]["provided"] = {"delivery": ["ready"]}
        self.assertEqual(rules.eligible(state, dependent, "person", 1, check_resources=False)[0], [])

    def test_duplicate_fields_still_rejected_outside_multi_dependency(self):
        handler = SimpleNamespace(server=SimpleNamespace(is_round=True), request_body=lambda *args: b"name=a&name=b")
        with patch("pool.round_web.verify_form"), self.assertRaisesRegex(ClientError, "重复"):
            web.parse_form(handler, 4096, 10)

    def test_multiple_prerequisites_respect_existing_backend_limit(self):
        rows = [{"task": "T11", "output": "delivery", "criterion": str(i)} for i in range(31)]
        with self.assertRaisesRegex(ClientError, "最多 30"):
            web.quick_registration(SimpleNamespace(), {"depends_on": [json.dumps(rows)]})

    def test_selectors_escape_labels_and_retain_unavailable_value(self):
        page = upgrade_pages.identity_picker("owner", "责任人", [{"identity": "person", "name": "<Person>", "kind": "human"}], "old-owner")
        self.assertIn("&lt;Person&gt;", page)
        self.assertNotIn("<Person>", page)
        self.assertIn('value="old-owner" selected', page)
        self.assertIn("保留了原值", page)
        self.assertIn("data-picker-search", page)
        project = {"id": "fixture", "roles": ["manager"], "members": [],
                   "identity_choices": [{"identity": "person", "name": "Person", "kind": "human"}]}
        page = workbench.members_section(project)
        self.assertIn('select name="name"', page)
        self.assertNotIn('input name="name"', page)

    def test_new_task_exposes_searchable_people_and_multiple_prerequisites(self):
        project = {"id": "fixture", "name": "Fixture", "roles": ["manager"]}
        member = {"identity": "person", "kind": "human", "roles": ["executor", "receiver"]}
        page = workbench.new_task("person", [project], project, ["person"], [("markdown", "skill")], [member], [task("T11")])
        self.assertIn('select name="depends_on" multiple', page)
        self.assertIn('select name="receiver"', page)
        self.assertIn('select name="dispatch_owner"', page)
        self.assertIn('data-picker-search', page)

    def test_invitation_failure_preserves_inputs_and_backend_error(self):
        handler = SimpleNamespace(server=SimpleNamespace(service=InvitationService()))
        original = {"operation": "issue", "request_id": "fixture", "project_id": "fixture", "owner": "old-owner",
                    "roles": "executor", "hours": "24", "count": "7"}
        for hours, error in (("24", "角色已变化"), ("not-a-number", "须为整数")):
            with patch("pool.web.parse_form", return_value={**original, "hours": hours}):
                result = round_web.invitations(handler, "POST", "person", urlsplit("/invitations"))
            page = result[1].decode()
            self.assertEqual(result[0], 409 if hours == "24" else 400)
            self.assertIn(error, page)
            self.assertIn('value="old-owner" selected', page)
            self.assertIn('value="7"', page)
            self.assertIn("已保留邀请表单", page)
            self.assertIn('class="wb-page"', page)

    def test_operations_are_separate_and_enforced(self):
        data = {"format": {"schema": 3, "upgrade": "fixture", "maintenance": False},
                "release": {"status": "closed"}, "roles": []}
        self.assertNotIn('/actions/identity-bind', upgrade_pages.operations_page("admin", data))
        self.assertIn('/actions/identity-bind', upgrade_pages.operations_page("admin", data, True))
        service = SimpleNamespace(read=lambda *args: {"binding": {}}, round_enabled=lambda: True, is_admin=lambda actor: False)
        with self.assertRaises(ClientError) as caught:
            web.upgrade_view(service, "person", urlsplit("/upgrade?migration=1"))
        self.assertEqual(caught.exception.status, 403)

    def test_window_details_use_chinese_state_and_private_placeholders(self):
        source = {"executor_id": "window", "window": "CDX-0001", "window_name": "Fixture window", "platform": "codex",
                  "model": "fixture", "owner": "person", "status": "active", "round": True, "can_manage": False,
                  "contact": "current", "concurrency": 1, "last_contact": 1794258000,
                  "tasks": [{"task_id": "T11", "lifecycle": "active", "execution": {"state": "working"}, "epoch": 1}]}
        page = upgrade_pages.executor_page("peer", source)
        self.assertIn("领取 进行中", page)
        self.assertIn("执行 工作中", page)
        self.assertIn("仅本人、责任人或管理员可见", page)
        self.assertNotIn('/tokens/rotate?', page)
        self.assertNotIn('/manage"', page)
        self.assertIn("权限与委托", page)
        self.assertIn("UTC+8", page)

    def test_navigation_retains_project_source_entry(self):
        rail = workbench.rail("/executors", False, 0, 0, "", "person")
        self.assertIn("窗口管理", rail)
        self.assertNotIn("来源档案", rail)
        self.assertNotIn('/capabilities', rail)

    def test_archived_windows_can_be_reopened_from_directory(self):
        profile = {"binding": {"kind": "human", "admin": False}, "projects": []}
        source = {"executor_id": "window", "window": "CDX-0001", "window_name": "Archived fixture", "status": "archived",
                  "tasks": [], "owner": "person", "memberships": [], "capabilities": [], "auto": False}
        hidden = workbench_pages.windows_page("person", profile, [source], [])
        self.assertNotIn("Archived fixture", hidden)
        self.assertIn('/executors?archived=1', hidden)
        shown = workbench_pages.windows_page("person", profile, [source], [], True)
        self.assertIn("Archived fixture", shown)
        self.assertIn('/executors/window', shown)
        self.assertIn("已归档", shown)


if __name__ == "__main__":
    unittest.main()
