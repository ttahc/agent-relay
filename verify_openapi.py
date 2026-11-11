"""The interface description: generated from the routing tables, committed, and served.

    python -B verify_openapi.py            # check
    python -B verify_openapi.py --write    # regenerate docs/openapi.json after a route change

The first class compares the committed docs/openapi.json with what the tables generate now, so a
route added, removed or renamed without regenerating fails here. The second runs the packaged
service on a disposable store and reads the description over HTTP. No production store is read.
"""
import json
from pathlib import Path
import sys
import unittest
import zipfile

from pool import execution, httpd, openapi, project_capabilities, round_service
from pool.service import PUBLIC_ACTIONS

from verify import ROOT, call, server as running_service
from verify_round import activate, ai_prepare, auth_checks, invitation, setup
from verify_support import scratch

COMMITTED = Path(ROOT) / "docs" / "openapi.json"


class Generated(unittest.TestCase):
    def setUp(self):
        self.document = openapi.document()
        self.paths = self.document["paths"]

    def test_the_committed_copy_matches_the_routing_tables(self):
        self.assertEqual(COMMITTED.read_bytes(), openapi.rendered(),
                         "docs/openapi.json 与路由表不一致；运行 python -B verify_openapi.py --write 重新生成")

    def test_generation_is_stable(self):
        self.assertEqual(openapi.rendered(), openapi.rendered())
        json.loads(openapi.rendered())

    def test_every_read_route_is_listed_with_its_query_keys(self):
        for name, (allowed, _, kind, only_round) in httpd.READ_API.items():
            get = self.paths["/v1/" + name]["get"]
            self.assertEqual({p["name"] for p in get.get("parameters", [])}, set(allowed or ()), name)
            self.assertIn(kind, get["responses"]["200"]["content"], name)
            self.assertEqual(get.get("x-round-only", False), only_round, name)
        for name in ("wait", "artifact", "tasks/{task_id}", "projects/{project_id}"):
            self.assertIn("get", self.paths["/v1/" + name])
        self.assertEqual(self.paths["/v1/wait"]["get"]["parameters"][1]["schema"]["maximum"], 50)

    def test_every_write_route_is_listed_and_nothing_else(self):
        posts = {path[4:] for path, item in self.paths.items() if "post" in item}
        self.assertEqual(posts, PUBLIC_ACTIONS | httpd.ROUND_WRITES | project_capabilities.PROBE_WRITES |
                         round_service.BOOTSTRAP | {"window-apply"})
        for name in PUBLIC_ACTIONS:
            post = self.paths["/v1/" + name]["post"]
            self.assertTrue(post["x-journaled"], name)
            self.assertIn("request_id", post["requestBody"]["content"]["application/json"]["schema"]["required"], name)
        self.assertEqual(self.paths["/v1/capability-probe-claim"]["post"]["security"], [{"verifierToken": []}])
        self.assertEqual(self.paths["/v1/window-apply"]["post"]["security"], [])

    def test_field_names_follow_the_tables_that_state_them(self):
        schema = lambda name: self.paths["/v1/" + name]["post"]["requestBody"]["content"]["application/json"]["schema"]
        for name, names in execution.FIELDS.items():
            self.assertEqual(set(schema(name)["required"]), {"request_id", *names.split()}, name)
            self.assertFalse(schema(name)["additionalProperties"], name)
        self.assertIn("blocker_ids", schema("execution-fact")["properties"])
        self.assertNotIn("blocker_ids", schema("execution-fact")["required"])
        self.assertNotIn("id", schema("task-message")["properties"])  # the service derives the message id
        self.assertIn("content", schema("task-message")["required"])
        self.assertNotIn("additionalProperties", schema("claim"))  # not stated by one table: left open

    def test_the_description_names_no_host_and_no_secret(self):
        text = openapi.rendered().decode("utf-8")
        self.assertNotIn("servers", self.document)
        self.assertNotRegex(text, r"https?://")


class Served(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = scratch("openapi-")
        cls.addClassCleanup(cls.scratch.cleanup)
        project = Path(cls.scratch.name)
        with zipfile.ZipFile(ROOT / "dist" / "task-pool-local.zip") as package:
            package.extractall(project)
        _, tokens, password = setup(project)
        cls.running = running_service(project)
        _, cls.url = cls.running.__enter__()
        cls.addClassCleanup(cls.running.__exit__, None, None, None)
        admin, _, _ = auth_checks(project, cls.url, tokens, password)
        _, (status, issued) = ai_prepare(cls.url, invitation(admin, "worker-a"), session="openapi-session")
        assert status == 200, (status, issued)
        activate(cls.url, issued)
        cls.token = issued["token"]

    def test_a_window_reads_the_same_description(self):
        status, value = call(self.url + "/openapi", self.token)
        self.assertEqual(status, 200)
        self.assertEqual(value, json.loads(COMMITTED.read_bytes()))

    def test_it_is_refused_without_a_credential_and_announced_in_features(self):
        self.assertEqual(call(self.url + "/openapi")[0], 401)
        self.assertIs(call(self.url + "/features", self.token)[1]["features"]["openapi"], True)


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        COMMITTED.write_bytes(openapi.rendered())
        print(COMMITTED)
    else:
        unittest.main(verbosity=2)
