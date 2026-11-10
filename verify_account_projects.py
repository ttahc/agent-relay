"""Offline project-grant UI regression; no service, credentials or data store needed."""

from contextlib import nullcontext
from copy import deepcopy
from email.message import Message
import hmac
from threading import RLock
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit

from pool import account_projects, round_web, upgrade, web, workbench_pages
from pool.packages import ClientError
import 协作升级 as rules
from 协作存储 import Rejected


class FixtureService:
    """Apply the real grant planner and ledger rule to an isolated in-memory state."""

    def __init__(self):
        self.lock, self.calls = RLock(), []
        self.state = {"generation": 1, "tasks": {}, "claims": {}, "origins": {}, "pilot": {
            "format": {"schema": 3, "maintenance": False}}}
        for name, kind, admin in (("admin", "human", True), ("person", "human", False), ("window-id", "executor", False)):
            self.state["origins"][name] = {"roles": []}
            self.state["pilot"]["identity:" + name] = {"kind": kind, "admin": admin, "status": "active",
                                                      "owner": "admin" if kind == "executor" else name,
                                                      "credential": 8, "window": "CLD-0003" if kind == "executor" else None}
        for project in ("old", "new"):
            self.state["pilot"]["project:" + project] = {"id": project, "name": project + " 项目", "owner": "admin", "version": 1}
            self.state["pilot"][f"grant:{project}:admin"] = {"roles": ["manager"], "resources": [], "version": 1}
        self.state["pilot"]["grant:old:window-id"] = {"roles": ["executor"], "version": 4,
                                                        "resources": [{"id": "path:outputs", "mode": "write"}]}

    def snapshot(self):
        return {"state": self.state}

    def one_snapshot(self):
        return nullcontext()

    def submit(self, actor, action, request_id, body):
        self.calls.append((actor, action, request_id, deepcopy(body)))
        try:
            prepared = upgrade.plan(self, actor, action, request_id, body, self.snapshot())
            candidate = deepcopy(self.state)
            payload = {**prepared["steps"][0]["payload"], "_audit": {"actor": actor}}
            rules.action(candidate, {"payload": payload}, {"now": 1})
            self.state = candidate
            return 200, {"status": "applied"}
        except (ClientError, Rejected) as error:
            return getattr(error, "status", 409), {"message": str(error)}


class AccountProjectsTest(unittest.TestCase):
    def setUp(self):
        self.service, self.actor = FixtureService(), "admin"
        self.sessions = SimpleNamespace(actor=lambda current, service: self.actor)
        self.adopt = patch("pool.workbench.adopt", side_effect=lambda html, *args: html)
        self.adopt.start()
        self.addCleanup(self.adopt.stop)

    def send(self, name="window-id", data=None, *, query=None, csrf=True, origin="http://localhost:8765"):
        headers = Message()
        headers["Host"], headers["Cookie"], headers["Origin"] = "localhost:8765", "taskpool_local_session=fixture", origin
        server = SimpleNamespace(service=self.service, sessions=self.sessions, is_round=True, tls=None, csrf_key=b"fixture")
        token = hmac.digest(server.csrf_key, b"session:fixture", "sha256").hex()
        raw = urlencode({**(data or {}), **({"csrf": token} if csrf and data is not None else {})}).encode()
        handler = SimpleNamespace(server=server, headers=headers, request_body=lambda kind, limit: raw)
        target = urlsplit("/accounts/projects?" + (query if query is not None else urlencode({"identity": name})))
        return round_web.wrap(handler, "POST" if data is not None else "GET", target,
                              lambda *args: self.fail("route was not registered"))

    def post(self, project="old", version="4", operation="save", roles="executor", **changes):
        data = {"request_id": "isolated-check", "project_id": project, "version": version, "operation": operation}
        if operation == "save":
            data["roles"] = roles
        return {**data, **changes}

    def test_page_lists_all_projects_and_current_exact_roles(self):
        status, body, *_ = self.send()
        self.assertEqual(status, 200)
        self.assertIn('old 项目'.encode(), body)
        self.assertIn('new 项目'.encode(), body)
        self.assertIn(b'value="executor" selected', body)
        self.assertIn(b'name="version" value="4"', body)
        self.assertIn(b'name="version" value="0"', body)
        self.assertIn(b'name="csrf"', body)
        self.assertNotIn(b'value="executor,manager,receiver"', body)

    def test_move_keeps_identity_resources_and_window_number(self):
        identities = deepcopy({key: value for key, value in self.service.state["pilot"].items() if key.startswith("identity:")})
        self.assertEqual(self.send(data=self.post(project="new", version="0"))[0], 200)
        self.assertEqual(rules.grant(self.service.state, "new", "window-id"), {"roles": ["executor"], "resources": [], "version": 1})
        status, body, *_ = self.send(data=self.post(operation="remove"))
        self.assertEqual(status, 200)
        old = rules.grant(self.service.state, "old", "window-id")
        self.assertEqual(old["roles"], [])
        self.assertEqual(old["resources"], [{"id": "path:outputs", "mode": "write"}])
        self.assertEqual(old["version"], 5)
        self.assertIn(b'/accounts/projects?identity=window-id', body)
        self.assertIn('项目授权已更新'.encode(), body)
        self.assertEqual(identities, {key: value for key, value in self.service.state["pilot"].items() if key.startswith("identity:")})

    def test_role_change_preserves_resources(self):
        self.assertEqual(self.send(data=self.post(roles="receiver"))[0], 200)
        grant = rules.grant(self.service.state, "old", "window-id")
        self.assertEqual(grant["roles"], ["receiver"])
        self.assertEqual(grant["resources"], [{"id": "path:outputs", "mode": "write"}])
        self.assertEqual(self.service.calls[-1][1], "project-grant")

    def test_existing_singletons_and_unusual_combinations_are_preserved(self):
        for roles in (["executor"], ["receiver"], ["reporter"], ["observer"], ["observer", "reporter"]):
            with self.subTest(roles=roles):
                self.service.state["pilot"]["grant:old:person"] = {"roles": roles, "resources": [], "version": 2}
                value = account_projects.role_value(roles)
                self.assertIn(f'value="{value}" selected'.encode(), self.send("person")[1])
                self.assertEqual(self.send("person", data=self.post(version="2", roles=value))[0], 200)
                self.assertEqual(rules.grant(self.service.state, "old", "person")["roles"], sorted(roles))

    def test_version_conflict_stays_on_editor(self):
        status, body, *_ = self.send(data=self.post(version="3"))
        self.assertEqual(status, 409)
        self.assertIn('授权版本已变化'.encode(), body)
        self.assertIn(b'/accounts/projects?identity=window-id', body)
        self.assertEqual(rules.grant(self.service.state, "old", "window-id")["version"], 4)

    def test_owner_removal_reaches_backend_and_is_refused(self):
        status, body, *_ = self.send("admin", data=self.post(version="1", operation="remove"))
        self.assertEqual(status, 409)
        self.assertIn('项目负责人须保有管理授权'.encode(), body)
        self.assertEqual(rules.grant(self.service.state, "old", "admin")["roles"], ["manager"])

    def test_non_admin_and_disabled_admin_are_denied(self):
        for actor in ("person", "window-id"):
            self.actor = actor
            self.assertEqual(self.send()[0], 403)
            self.assertEqual(self.send(data=self.post())[0], 403)
        self.actor = "admin"
        self.service.state["pilot"]["identity:admin"]["status"] = "disabled"
        self.assertEqual(self.send()[0], 403)
        self.assertEqual(self.send(data=self.post())[0], 403)
        self.assertFalse(self.service.calls)

    def test_unknown_identity_and_duplicate_query_are_denied(self):
        for data in (None, self.post()):
            self.assertEqual(self.send("unknown", data=data)[0], 404)
            self.assertEqual(self.send(query="identity=person&identity=window-id", data=data)[0], 400)
            self.assertEqual(self.send(query="identity=person&extra=1", data=data)[0], 400)
        self.assertFalse(self.service.calls)

    def test_csrf_and_cross_origin_are_denied(self):
        self.assertEqual(self.send(data=self.post(), csrf=False)[0], 403)
        self.assertEqual(self.send(data=self.post(), origin="http://other.example")[0], 403)
        self.assertFalse(self.service.calls)

    def test_tampered_roles_and_fields_are_denied(self):
        for data in (self.post(roles="executor,manager,receiver"), self.post(version="-1"),
                     self.post(resources="[]"), self.post(name="person"), self.post(project="missing")):
            self.assertIn(self.send(data=data)[0], (400, 404))
        self.assertFalse(self.service.calls)

    def test_discovery_links(self):
        row = {"name": "window-id", "kind": "executor", "status": "active", "projects": [], "admin": False, "window": "CLD-0003"}
        self.assertIn('/accounts/projects?identity=window-id', workbench_pages.accounts_page("admin", [row], "", "", ""))
        item = {"executor_id": "window-id", "tasks": [], "status": "active", "contact": "unconfirmed", "memberships": [],
                "capabilities": [], "window": "CLD-0003", "auto": False}
        admin_profile = {"binding": self.service.state["pilot"]["identity:admin"], "projects": []}
        self.assertIn('/accounts/projects?identity=window-id', workbench_pages.windows_page("admin", admin_profile, [item], []))
        profile = {"binding": self.service.state["pilot"]["identity:person"], "projects": []}
        self.assertNotIn('/accounts/projects?', workbench_pages.windows_page("person", profile, [item], []))


if __name__ == "__main__":
    unittest.main(verbosity=2)
