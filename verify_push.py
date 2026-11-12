"""Push notices: registration rules, delivery, retries, and one real callback from the packaged service.

The first class drives the registration table and one delivery pass with stand-ins; the second runs
the packaged service on a disposable store with a callback receiver on loopback. No production store
is read and nothing leaves the host.
"""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from pool import push
from pool.packages import ClientError
from verify import ROOT, call, server as running_service
from verify_round import activate, ai_prepare, auth_checks, invitation, setup
from verify_support import scratch

SECRET = "s" * 40


class Receiver:
    """A loopback callback endpoint that records what it was sent and answers with a chosen status."""

    def __init__(self, status=204):
        self.received, self.status = [], status
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                owner.received.append({"path": self.path, "authorization": self.headers["Authorization"],
                                       "body": json.loads(self.rfile.read(length))})
                self.send_response(owner.status)
                if owner.status in (301, 302):
                    self.send_header("Location", "http://127.0.0.1:9/elsewhere")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.http.server_address[1]}/hook?window=1"
        threading.Thread(target=self.http.serve_forever, daemon=True).start()

    def close(self):
        self.http.shutdown()
        self.http.server_close()


class Registration(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.push = push.Push(self.db)

    def test_addresses_and_secrets_are_checked(self):
        for url in ("ftp://host/x", "http://user:pw@host/", "http:///nohost", "http://host/#frag", "http://host:99999/",
                    "http://ho st/", "", 5):
            if url == "":
                continue
            with self.assertRaises(ClientError, msg=url):
                self.push.save("w", {"request_id": "r", "url": url, "secret": SECRET})
        with self.assertRaises(ClientError):
            self.push.save("w", {"request_id": "r", "url": "https://host/x", "secret": "short"})
        with self.assertRaises(ClientError):
            self.push.save("w", {"request_id": "r", "url": "https://host/x"})
        self.assertEqual(self.push.save("w", {"request_id": "r", "url": "https://host:8443/x", "secret": SECRET})["status"],
                         "registered")
        self.assertEqual(self.push.status("w")["url"], "https://host:8443/x")
        self.assertNotIn(SECRET, json.dumps(self.push.status("w")))
        self.assertEqual(self.push.save("w", {"request_id": "r", "url": "", "secret": ""}), {"status": "removed"})
        self.assertEqual(self.push.status("w"), {"registered": False})

    def test_failures_pause_longer_and_suspend_until_registered_again(self):
        self.push.save("w", {"request_id": "r", "url": "http://host/x", "secret": SECRET})
        now = 1000
        self.push.failed("w", "ConnectionRefusedError", now)
        self.assertEqual(self.push.due(now + 4), [])
        self.assertEqual(len(self.push.due(now + 5)), 1)
        self.push.failed("w", "500", now)
        self.assertEqual(self.push.due(now + 14), [])
        for _ in range(push.MAX_FAILURES):
            self.push.failed("w", "500", now)
        self.assertTrue(self.push.status("w")["suspended"])
        self.assertEqual(self.push.due(now + 10 ** 6), [])
        self.push.save("w", {"request_id": "r2", "url": "http://host/x", "secret": SECRET})
        self.assertEqual(len(self.push.due(now)), 1)
        self.push.delivered("w", "c" * 64, "204", now)
        self.assertEqual(self.push.status("w")["failures"], 0)


class Delivery(unittest.TestCase):
    def setUp(self):
        self.receiver = Receiver()
        self.addCleanup(self.receiver.close)
        db = sqlite3.connect(":memory:", check_same_thread=False)
        self.table = push.Push(db)
        self.active = {"w1", "w2"}
        state = {"pilot": {}}

        @contextmanager
        def pinned(snap=None):
            yield
        service = SimpleNamespace(lock=threading.RLock(), db=db, one_snapshot=pinned, snapshot=lambda: {"state": state},
                                  credential_version=lambda actor: 1 if actor in self.active else None)
        self.server = SimpleNamespace(service=service, push=self.table,
                                      wakeups=SimpleNamespace(snapshot=lambda current: {"state": state}))
        self.events = {"w1": [], "w2": []}

    def deliver(self, later=0):
        with patch("pool.wakeups.events", lambda service, state, actor: self.events[actor]):
            return push.deliver_once(self.server, now=time.time() + later)

    def test_one_push_per_change_with_the_windows_secret_and_only_identifiers(self):
        self.table.save("w1", {"request_id": "r", "url": self.receiver.url, "secret": SECRET})
        self.assertEqual(self.deliver(), ["w1"], "first look after registering")
        self.assertEqual(self.deliver(), [], "nothing changed")
        self.events["w1"] = [{"type": "task-ready", "key": "k" * 64, "task_id": "T01", "version": 2, "scope_version": 1}]
        self.assertEqual(self.deliver(), ["w1"])
        first, second = self.receiver.received
        self.assertEqual(second["path"], "/hook?window=1")
        self.assertEqual(second["authorization"], "Bearer " + SECRET)
        self.assertEqual(second["body"]["events"], self.events["w1"])
        self.assertEqual(second["body"]["executor_id"], "w1")
        self.assertEqual(len(second["body"]["cursor"]), 64)
        self.assertEqual(first["body"]["events"], [])

    def test_a_redirect_or_error_is_a_failure_and_a_revoked_window_gets_nothing(self):
        self.table.save("w1", {"request_id": "r", "url": self.receiver.url, "secret": SECRET})
        self.table.save("w2", {"request_id": "r", "url": self.receiver.url, "secret": SECRET})
        self.active.discard("w2")
        self.receiver.status = 302
        self.assertEqual(self.deliver(), [])
        self.assertEqual(len(self.receiver.received), 1, "the revoked window was not looked at, the redirect not followed")
        status = self.table.status("w1")
        self.assertEqual((status["failures"], status["last_status"]), (1, "302"))
        self.receiver.status = 200
        self.assertEqual(self.deliver(), [], "still pausing after the failure")
        self.assertEqual(self.deliver(later=push.PAUSES[0]), ["w1"])
        self.assertEqual(self.table.status("w1")["failures"], 0)

    def test_an_unreachable_address_fails_within_the_time_limit(self):
        self.table.save("w1", {"request_id": "r", "url": "http://127.0.0.1:9/none", "secret": SECRET})
        started = time.monotonic()
        self.assertEqual(self.deliver(), [])
        self.assertLess(time.monotonic() - started, push.TIMEOUT + 2)
        self.assertEqual(self.table.status("w1")["failures"], 1)


class Served(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = scratch("push-")
        cls.addClassCleanup(cls.scratch.cleanup)
        project = Path(cls.scratch.name)
        with zipfile.ZipFile(ROOT / "dist" / "task-pool-local.zip") as package:
            package.extractall(project)
        _, tokens, password = setup(project)
        cls.running = running_service(project)
        _, cls.url = cls.running.__enter__()
        cls.addClassCleanup(cls.running.__exit__, None, None, None)
        cls.admin, _, _ = auth_checks(project, cls.url, tokens, password)
        _, (status, issued) = ai_prepare(cls.url, invitation(cls.admin, "worker-a"), session="push-session")
        assert status == 200, (status, issued)
        activate(cls.url, issued)
        cls.token = issued["token"]
        cls.receiver = Receiver()
        cls.addClassCleanup(cls.receiver.close)

    def test_a_registered_window_is_called_back_and_can_clear_it(self):
        status, value = call(self.url + "/push-config", self.token, {"request_id": "p-1", "url": self.receiver.url, "secret": SECRET})
        self.assertEqual((status, value["status"]), (200, "registered"), value)
        deadline = time.monotonic() + 15
        while not self.receiver.received and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertTrue(self.receiver.received, "no callback within 15 seconds")
        self.assertEqual(self.receiver.received[0]["authorization"], "Bearer " + SECRET)
        shown = call(self.url + "/push-config", self.token)[1]
        self.assertTrue(shown["registered"])
        self.assertNotIn(SECRET, json.dumps(shown))
        self.assertIs(call(self.url + "/features", self.token)[1]["features"]["push"], True)
        self.assertEqual(call(self.url + "/push-config", self.token, {"request_id": "p-2", "url": "", "secret": ""})[1]["status"], "removed")

    def test_a_bad_address_and_no_credential_are_refused(self):
        self.assertEqual(call(self.url + "/push-config", self.token, {"request_id": "p-3", "url": "file:///etc/passwd",
                                                                      "secret": SECRET})[0], 400)
        self.assertEqual(call(self.url + "/push-config", None, {"request_id": "p-4", "url": self.receiver.url, "secret": SECRET})[0], 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
