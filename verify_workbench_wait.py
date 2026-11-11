"""Event-driven refresh of the web workbench: GET /workspace-state can be held open like GET /v1/wait.

The packaged service runs on a disposable real store. A signed-in browser session asks for the
revision of what it sees; with a timeout the answer waits until that revision changes. The page
script that uses this, and its fallback to the timer, is checked in verify_v030_workspace_refresh.js.
"""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import unittest
from urllib.parse import urlsplit
import zipfile

from verify import ROOT, call, command, server as running_service
from verify_round import Browser, password_record
from verify_support import scratch
from verify_upgrade import Client, PROJECT, capability, control, register
from verify_v042_wait import Background, QUICK

PASSWORD = "隔离验收 专用长密码 2026-Workbench!"
REVISION = re.compile(rb'data-workspace-revision="([0-9a-f]{64})"')


class WorkbenchWait(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = scratch("workbench-wait-")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.project = project = Path(cls.scratch.name)
        with zipfile.ZipFile(ROOT / "dist" / "task-pool-local.zip") as package:
            package.extractall(project)
        initial = command(project, "init", "--worker", "worker-a", "--worker", "worker-b", "--receiver", "reviewer",
                          "--authority", "workbench wait fixture")
        cls.tokens = json.loads(Path(initial["credentials"]).read_bytes())["tokens"]
        cls.tokens["admin"] = command(project, "init-admin")["token"]
        brief = project / "brief.md"
        brief.write_text("synthetic input", encoding="utf-8")
        for number in (1, 2):
            command(project, "add-task", "--request-id", f"workbench-legacy-{number}", "--title", f"Old {number}",
                    "--input", brief, "--criterion", "ready")
        command(project, "upgrade-migrate", "--upgrade", "fixture-v2", "--image", "1" * 64)
        command(project, "round-migrate", "--upgrade", "fixture-v3", "--image", "2" * 64)
        command(project, "maintenance", "off", "--request-id", "workbench-fixture-open")
        cls.running = running_service(project)
        _, cls.url = cls.running.__enter__()
        cls.addClassCleanup(cls.running.__exit__, None, None, None)
        cls.origin = cls.url.removesuffix("/v1")
        cls.admin, cls.worker = Client(cls.url, cls.tokens["admin"]), Client(cls.url, cls.tokens["worker-a"])
        for name, role in (("worker-a", "executor"), ("worker-b", "executor"), ("reviewer", "receiver")):
            cls.admin.post("identity-bind", request="workbench-bind-" + name, name=name, kind="human", owner=name,
                           reason="isolated workbench fixture", source=None)
            cls.admin.post("project-grant", request="workbench-grant-" + name, project_id=PROJECT, name=name, roles=[role],
                           resources=[], version=0)
        capability(cls.worker, "worker-a")
        cls.browsers = {}
        for name in ("worker-a", "worker-b"):
            cls.browsers[name] = browser = Browser(cls.origin)
            assert password_record(browser, "/password/setup", name, PASSWORD, token=cls.tokens[name])[0] == 303
            browser.login(name, PASSWORD)
        cls.sequence = 0

    def state(self, name="worker-a", revision=None, hold=None, project=None, browser=None):
        """The answer of /workspace-state for a signed-in browser: status and decoded JSON (or the raw page)."""
        query = "&".join(f"{key}={value}" for key, value in (("project", project), ("revision", revision), ("timeout", hold))
                         if value is not None)
        status, headers, page = (browser or self.browsers[name]).send("/workspace-state" + ("?" + query if query else ""))
        return status, json.loads(page) if headers.get("Content-Type", "").startswith("application/json") else page

    def revision(self, name="worker-a", project=None):
        status, value = self.state(name, project=project)
        self.assertEqual(status, 200, value)
        return value["revision"]

    def parked(self, name="worker-a", hold=12):
        known = self.revision(name)
        waiting = Background(self.state, name, known, hold)
        time.sleep(.5)  # let the request reach the service and start waiting
        self.assertFalse(waiting.done())
        waiting.known = known
        return waiting

    def draft(self):
        """A registered task and the one write that will publish it."""
        type(self).sequence += 1
        admin = Client(self.url, self.tokens["admin"])
        admin.sequence = 1000 * self.sequence
        task = register(admin, "reviewer", dispatch={"mode": "open", "subjects": [], "capabilities": [],
                                                     "automation": "notify", "owner": "admin"})
        return task, lambda: control(admin, "task-publish", self.worker.get("tasks/" + task["task_id"])["task"])

    def held_socket(self, name, revision, hold=20):
        """A held request on a bare connection, as a browser tab that can be closed mid-wait."""
        address = urlsplit(self.origin)
        cookie = "; ".join(f"{key}={value}" for key, value in self.browsers[name].cookies.items())
        connection = socket.create_connection((address.hostname, address.port), timeout=15)
        connection.sendall((f"GET /workspace-state?revision={revision}&timeout={hold} HTTP/1.1\r\nHost: {address.netloc}\r\n"
                            f"Cookie: {cookie}\r\n\r\n").encode("ascii"))
        return connection

    def test_1_the_page_carries_the_revision_and_a_held_request_answers_only_after_its_time(self):
        status, _, page = self.browsers["worker-a"].send("/")
        self.assertEqual(status, 200)
        drawn = REVISION.search(page)[1].decode()
        self.assertEqual(drawn, self.revision(), "the page is drawn with the revision the state route reports")
        started = time.monotonic()
        status, value = self.state(revision=drawn, hold=2)
        self.assertGreaterEqual(time.monotonic() - started, 1.9)
        self.assertEqual((status, value["revision"], value["changed"]), (200, drawn, False))
        self.assertEqual(set(value), {"revision", "version", "changed"})
        started = time.monotonic()
        status, value = self.state(revision="0" * 64, hold=20)
        self.assertLess(time.monotonic() - started, QUICK, "a page that is already behind is answered at once")
        self.assertEqual((status, value["revision"], value["changed"]), (200, drawn, True))
        status, value = self.state(hold=20)
        self.assertEqual((status, value["changed"]), (200, True), "without a revision there is nothing to wait for")

    def test_2_a_published_task_reaches_the_waiting_page_at_once(self):
        task, publish = self.draft()
        waiting = self.parked()
        quiet = Background(self.state, "worker-b", self.revision("worker-b", "no-such-project-view"), 4, "no-such-project-view")
        publish()
        status, value = waiting.result(QUICK + 5)
        self.assertLess(waiting.seconds, QUICK + 5, "the hold was 12 seconds; the answer must not wait for it")
        self.assertEqual((status, value["changed"]), (200, True))
        self.assertNotEqual(value["revision"], waiting.known)
        self.assertEqual(value["revision"], self.revision(), "the held and the plain request agree")
        status, _, page = self.browsers["worker-a"].send("/board")
        self.assertIn(task["task_id"].encode(), page)
        self.assertEqual(REVISION.search(page)[1].decode(), value["revision"], "the reloaded page is drawn with that revision")
        status, value = quiet.result()
        self.assertEqual((status, value["changed"]), (200, False), "woken, but nothing this page shows has changed")
        self.assertGreaterEqual(quiet.seconds, 3.5)

    def test_3_requests_that_cannot_wait_are_refused_and_the_plain_route_is_unchanged(self):
        known = self.revision()
        for query in ("revision=xyz&timeout=5", f"revision={known}&timeout=51", f"revision={known}&timeout=-1",
                      f"revision={known}&timeout=5&extra=1", f"revision={known}&timeout="):
            status, _, _ = self.browsers["worker-a"].send("/workspace-state?" + query)
            self.assertEqual(status, 400, query)
        started = time.monotonic()
        status, value = self.state(revision=known, hold=20, browser=Browser(self.origin))
        self.assertEqual(status, 401, "a held request needs the signed-in session")
        self.assertLess(time.monotonic() - started, QUICK)
        status, value = self.state()
        self.assertEqual((status, set(value)), (200, {"revision", "version"}), "the timer fallback's route answers as before")
        status, _, _ = self.browsers["worker-a"].send(f"/workspace-state?revision={known}")
        self.assertEqual(status, 400, "the plain route still takes only the project")
        self.assertEqual(call(self.url + "/wait?timeout=0", self.tokens["worker-a"])[0], 200, "the window interface is unaffected")

    def test_4_waiting_places_are_limited_per_person_and_a_closed_page_gives_its_place_back(self):
        known = self.revision("worker-b")
        tabs = [self.held_socket("worker-b", known), self.held_socket("worker-b", known)]
        self.addClassCleanup(lambda: [tab.close() for tab in tabs])
        time.sleep(.5)
        status, _ = self.state("worker-b", known, 20)
        self.assertEqual(status, 429, "a third held request of one person is told to use the timer")
        waiting = self.parked("worker-a", 3)  # another person, and the windows' own places, are not affected
        mine = call(self.url + "/wait?cursor=" + call(self.url + "/wait", self.tokens["worker-b"])[1]["cursor"] + "&timeout=1",
                    self.tokens["worker-b"])
        self.assertEqual(mine[0], 200)
        self.assertEqual(waiting.result()[0], 200)
        tabs[0].close()  # the tab is closed or navigates away while its request is held
        deadline = time.monotonic() + QUICK
        while True:
            started = time.monotonic()
            status, value = self.state("worker-b", known, 1)
            if status == 200 or time.monotonic() > deadline:
                break
            time.sleep(.2)
        self.assertEqual(status, 200, "the place of the closed page was not given back")
        self.assertGreaterEqual(time.monotonic() - started, .9)
        type(self).idle = tabs[1]

    @unittest.skipUnless(os.name == "posix", "the upgrade control socket runs inside Linux/WSL")
    def test_5_freezing_for_an_upgrade_is_not_delayed_by_waiting_pages(self):
        from pool.lifecycle import control_request
        store = self.project / ".state" / "local"
        waiting = self.parked("worker-a", 20)
        started = time.monotonic()
        self.assertEqual(control_request(store, "freeze", 10)["phase"], "frozen")
        self.assertLess(time.monotonic() - started, QUICK)
        status, _ = waiting.result(QUICK)
        self.assertEqual(status, 503)
        self.idle.settimeout(QUICK)
        self.assertIn(b" 503 ", self.idle.recv(4096).split(b"\r\n", 1)[0])
        self.assertEqual(control_request(store, "cancel")["phase"], "running")
        self.assertEqual(self.state(revision=self.revision(), hold=1)[0], 200)

    def test_6_answering_leaves_the_shared_ledger_snapshot_as_it_was_read(self):
        self.running.__exit__(None, None, None)  # the store has one writer; the check below opens it in this place
        result = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", SNAPSHOT_CHECK, "worker-a", "worker-b", "reviewer", "admin"],
                                cwd=self.project, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        seen = json.loads(result.stdout)
        self.assertEqual(seen["reads"], 1, "every page was answered from one ledger read")
        self.assertEqual(len(set(seen["revisions"].values())) > 1, True, "people who see different things have different revisions")


# Runs inside the unpacked package: the packaged service, its real store, no HTTP.
SNAPSHOT_CHECK = r"""
import json, sys
from copy import deepcopy
from pool import wakeups, workbench
from pool.service import Service, exclusive, state_path
store = state_path("local")
with exclusive(store):
    service = Service(store)
    try:
        reads, original = [], service.desk.read
        service.desk.read = lambda: reads.append(1) or original()
        signal, revisions = wakeups.Wakeups(), {}
        with service.lock:
            snapshot = signal.snapshot(service)
            before = deepcopy(snapshot)
            for name in sys.argv[1:]:
                for _ in range(2):
                    with service.one_snapshot(signal.snapshot(service)):
                        revision = workbench.workspace_revision(service.read(name, "overview", None))
                    assert revisions.setdefault(name, revision) == revision, name
            assert snapshot == before, "answering a waiting page changed the snapshot other requests share"
        print(json.dumps({"reads": len(reads), "revisions": revisions}))
    finally:
        service.close()
"""


if __name__ == "__main__":
    unittest.main()
