"""Node overview: environments, platforms and windows on one page, within what each caller may see.

The first class works on the replayable execution fixture, where environments can be registered.
The second runs the packaged service on a disposable real store: the web page, the API route and
the client command. No production store is read.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import zipfile

from pool import nodes, upgrade, window_admin
import 协作升级 as rules

from verify import ROOT, call, server as running_service
import verify_environment_domains as domains
from verify_delegation import ASSISTANT, OTHER, PERSON
from verify_round import Browser, activate, ai_prepare, auth_checks, invitation, setup
from verify_support import scratch

OUTSIDER = "other-person"
PERSON_PASSWORD = "隔离验收 更换后的不同密码 New-Fruit!"  # set for fixture-person by verify_round.auth_checks


class Overview(unittest.TestCase):
    def setUp(self):
        self.env = domains.EnvironmentTests()
        self.env.setUp()
        self.addCleanup(self.env.doCleanups)
        self.state = self.env.state

    def sources(self, actor, **contact):
        rows = upgrade.sources(self.state, actor)
        for row in rows:
            row["can_manage"] = window_admin.allowed(self.state, actor, row["executor_id"])
            row.update(contact.get(row["executor_id"].replace("-", "_"), {}))
        return rows

    def view(self, actor, **contact):
        return nodes.overview(self.state, actor, self.sources(actor, **contact))

    @staticmethod
    def window(view, name):
        return next(row for row in view["windows"] if row["executor_id"] == name)

    def test_administrator_sees_every_environment_with_its_windows(self):
        self.env.pair()
        view = self.view(PERSON)
        self.assertEqual([(row["id"], row["kind"], row["windows"], row["mappings"]) for row in view["environments"]],
                         [("cloud-instance", "cloud", [OTHER], 1), ("local-instance", "local", [ASSISTANT], 1)])
        self.assertEqual(self.window(view, ASSISTANT)["environments"], ["local-instance"])
        self.assertEqual(view["unplaced"], ["foreign-window"])
        self.assertEqual((view["summary"]["windows"], view["summary"]["environments"]), (3, 2))

    def test_a_window_sees_its_own_environment_but_not_another_windows(self):
        self.env.pair()
        view = self.view(ASSISTANT)
        self.assertEqual([row["id"] for row in view["environments"]], ["local-instance"])
        self.assertEqual(view["environments"][0]["windows"], [ASSISTANT])
        self.assertEqual(self.window(view, OTHER)["environments"], [])
        self.assertIn(OTHER, view["unplaced"])
        self.assertNotIn("cloud-instance", json.dumps(view))

    def test_another_person_sees_the_windows_but_no_foreign_environment_or_occupancy(self):
        self.env.pair()
        self.env.request(self.env.action())
        rules.identity(self.state, OUTSIDER)["admin"] = False
        view = self.view(OUTSIDER)
        self.assertEqual(view["environments"], [])
        self.assertEqual({row["executor_id"]: row["occupancies"] for row in view["windows"]},
                         {ASSISTANT: None, OTHER: None, "foreign-window": 0})
        self.assertEqual(sorted(view["unplaced"]), sorted([ASSISTANT, OTHER, "foreign-window"]))

    def test_occupancy_count_is_shown_only_to_who_may_manage_the_window(self):
        self.env.pair()
        self.env.request(self.env.action())
        self.assertEqual(self.window(self.view(PERSON), ASSISTANT)["occupancies"], 1)
        self.assertEqual(self.window(self.view(ASSISTANT), ASSISTANT)["occupancies"], 1)
        self.assertIsNone(self.window(self.view(OTHER), ASSISTANT)["occupancies"])
        self.assertEqual(self.window(self.view(OTHER), OTHER)["occupancies"], 0)

    def test_only_a_current_heartbeat_of_an_active_window_counts_as_online(self):
        self.env.pair()
        view = self.view(PERSON, window_one={"contact": "current", "last_contact": 1}, window_two={"contact": "stale", "last_contact": 1})
        self.assertEqual([self.window(view, name)["presence"] for name in (ASSISTANT, OTHER, "foreign-window")],
                         ["online", "silent", "unconfirmed"])
        self.assertEqual((view["summary"]["online"], view["summary"]["platforms"]["codex"]), (1, {"windows": 2, "online": 1}))
        rules.identity(self.state, ASSISTANT)["status"] = "disabled"
        view = self.view(PERSON, window_one={"contact": "current"})
        self.assertEqual((self.window(view, ASSISTANT)["presence"], view["summary"]["online"]), ("off", 0))

    def test_archived_windows_are_left_out_and_active_tasks_are_listed(self):
        self.env.pair()
        self.assertEqual(self.window(self.view(PERSON), ASSISTANT)["active_tasks"], ["T01"])
        self.assertEqual(self.view(PERSON)["summary"]["working"], 2)
        rules.identity(self.state, OTHER)["status"] = "archived"
        view = self.view(PERSON)
        self.assertNotIn(OTHER, [row["executor_id"] for row in view["windows"]])
        self.assertEqual(next(row for row in view["environments"] if row["id"] == "cloud-instance")["windows"], [])

    def test_a_disabled_environment_no_longer_places_its_windows(self):
        self.env.pair()
        self.env.register("cloud-instance", [OTHER], kind="cloud", active=False)
        view = self.view(PERSON)
        self.assertEqual(view["summary"]["environments"], 1)
        self.assertIn(OTHER, view["unplaced"])
        self.assertFalse(next(row for row in view["environments"] if row["id"] == "cloud-instance")["active"])

    def test_the_view_and_the_page_never_carry_server_paths_and_escape_names(self):
        self.env.pair()
        self.env.register("local-instance", [ASSISTANT], label='<b>"node" & one</b>')
        view = self.view(PERSON)
        self.assertNotIn(str(self.env.root), json.dumps(view))
        html = nodes.page(PERSON, view, "").decode() if isinstance(nodes.page(PERSON, view, ""), bytes) else nodes.page(PERSON, view, "")
        self.assertNotIn(str(self.env.root), html)
        self.assertNotIn('<b>"node"', html)
        self.assertIn("&lt;b&gt;&quot;node&quot; &amp; one&lt;/b&gt;", html)
        self.assertIn("&lt;test &quot;window&quot;&gt;", html)
        self.assertIn("未登记执行环境的窗口", html)


class Served(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = scratch("nodes-")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.project = project = Path(cls.scratch.name)
        with zipfile.ZipFile(ROOT / "dist" / "task-pool-local.zip") as package:
            package.extractall(project)
        _, tokens, cls.password = setup(project)
        cls.running = running_service(project)
        _, cls.url = cls.running.__enter__()
        cls.addClassCleanup(cls.running.__exit__, None, None, None)
        cls.admin, _, _ = auth_checks(project, cls.url, tokens, cls.password)
        invite = invitation(cls.admin, "worker-a")
        _, (status, issued) = ai_prepare(cls.url, invite, session="nodes-session")
        assert status == 200, (status, issued)
        cls.window = activate(cls.url, issued)
        cls.token = issued["token"]
        cls.name = call(cls.url + "/identity", cls.token)[1]["identity"]

    def test_the_page_lists_the_window_under_its_platform(self):
        status, _, page = self.admin.send("/nodes")
        page = page.decode()
        self.assertEqual(status, 200)
        self.assertIn('href="/nodes"', page)
        self.assertIn("节点总览", page)
        self.assertIn(f'href="/executors/{self.name}"', page)
        self.assertIn("未登记执行环境的窗口", page)
        self.assertRegex(page, r'class="badge info">[^<]+ 0/1</span>')

    def test_the_window_page_links_to_the_overview(self):
        self.assertIn('href="/nodes"', self.admin.send("/executors")[2].decode())

    def test_the_route_answers_a_window_and_refuses_no_credential(self):
        status, value = call(self.url + "/nodes", self.token)
        self.assertEqual(status, 200)
        self.assertEqual([row["executor_id"] for row in value["windows"]], [self.name])
        self.assertEqual((value["summary"]["windows"], value["windows"][0]["occupancies"], value["unplaced"]), (1, 0, [self.name]))
        self.assertEqual(call(self.url + "/nodes")[0], 401)

    def test_a_person_without_a_role_sees_no_window(self):
        outsider = Browser(self.url)
        outsider.login("fixture-person", PERSON_PASSWORD)
        status, _, page = outsider.send("/nodes")
        self.assertEqual(status, 200)
        self.assertNotIn(self.name, page.decode())
        self.assertIn("0 个窗口", page.decode())

    def test_a_signed_out_browser_is_sent_to_login(self):
        self.assertEqual(Browser(self.url).send("/nodes")[0], 303)

    def test_the_client_command_reads_the_same_view(self):
        state = self.project / "nodes.credential"
        state.write_text(json.dumps({"url": self.url.removesuffix("/v1"), "token": self.token}), encoding="utf-8")
        state.chmod(0o600)
        done = subprocess.run([sys.executable, "-B", "-X", "utf8", str(ROOT / "ops/round-client.py"), "--state", str(state),
                               "--allow-loopback", "nodes"], capture_output=True, cwd=self.project, timeout=120,
                              env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        self.assertEqual(done.returncode, 0, done.stderr.decode("utf-8", "replace")[-800:])
        self.assertEqual(json.loads(done.stdout)["summary"]["windows"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
