"""Isolated continuity checks: no production store, service or external task is touched."""
from copy import deepcopy
from contextlib import closing
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import shutil
import sqlite3
import ssl
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pool.lifecycle import Control, Lifecycle, Maintenance, control_request
from pool.service import Service, Unavailable, exclusive
from pool.sessions import DurableSessions
from pool.httpd import Server

ROOT = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


client = module("continuity_client", "ops/round-client.py")
backup = module("continuity_backup", "ops/backup-store.py")


class FixtureLedger:
    def __init__(self, store):
        self.store = Path(store)
        self.meta = {"qualification": {}, "migration": None, "coordinator": "pilot-coordinator"}

    def check_qualification(self, *_):
        pass

    def read(self):
        return {"head": 0, "sha256": "a" * 64, "halted": False, "state": {"pilot": {}}}


class ContinuityTests(unittest.TestCase):
    def setUp(self):
        (ROOT / ".state").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="v030-continuity-", dir=ROOT / ".state" if os.name == "nt" else None)
        self.root = Path(self.temporary.name)
        reader = patch("pool.backup.LedgerBackend", FixtureLedger)
        reader.start()
        self.addCleanup(reader.stop)

    def tearDown(self):
        self.temporary.cleanup()

    def service(self):
        with patch("pool.service.LedgerBackend", FixtureLedger):
            return Service(self.root)

    def tls_fixture(self):
        store = self.root / "deployment" / "local"
        store.mkdir(parents=True)
        with patch("pool.service.LedgerBackend", FixtureLedger):
            service = Service(store)
        return store, store.parent / "tls", self.root / "private-tls-backup", service

    def test_drain_rejects_new_claim_and_resume_without_terminal_receipt(self):
        service = self.service()
        try:
            service.lifecycle.drain()
            for action in ("claim", "resume"):
                with self.assertRaises(Maintenance):
                    service.submit("fixture", action, "same-request", {"request_id": "same-request"})
            self.assertEqual(service.db.execute("SELECT count(*) FROM requests").fetchone()[0], 0)
            service.lifecycle.check_new_work("deliver-files")
            service.lifecycle.check_new_work("stop")
            service.lifecycle.check_new_work("review")
            with self.assertRaises(Maintenance):
                service.lifecycle.check_new_work("run-report", {"state": "intent"})
        finally:
            service.close()

    def test_ledger_maintenance_503_does_not_bind_id_and_same_request_completes_after_resume(self):
        from pool import upgrade
        service = self.service()
        snap = service.snapshot()
        snap["state"].update(tasks={}, round={}, generation=0)
        snap["state"]["pilot"]["format"] = {"schema": 3, "maintenance": True}
        service.snapshot = lambda: snap
        # Exercise the real persisted-maintenance gate; the empty execution plan
        # isolates request admission/completion without creating a business delivery.
        def gated_plan(actor, action, key, body, current):
            return upgrade.plan(service, actor, action, key, body, current) or {"steps": []}
        service.plan = gated_plan
        body = {"request_id": "same-maintenance-request", "evidence": "unchanged synthetic payload"}
        try:
            status, response = service.submit("fixture", "deliver-files", body["request_id"], deepcopy(body))
            self.assertEqual(status, 503)
            self.assertEqual(response["status"], "maintenance")
            self.assertTrue(response["retryable"])
            self.assertEqual(service.db.execute("SELECT count(*) FROM requests").fetchone()[0], 0)
            self.assertEqual(service.db.execute("SELECT count(*) FROM request_context").fetchone()[0], 0)
            snap["state"]["pilot"]["format"]["maintenance"] = False
            status, response = service.submit("fixture", "deliver-files", body["request_id"], deepcopy(body))
            self.assertEqual((status, response["status"], response["request_id"]), (200, "applied", body["request_id"]))
            row = service.db.execute("SELECT actor, action, status FROM requests").fetchone()
            self.assertEqual(row, ("fixture", "deliver-files", 200))
            self.assertEqual(service.db.execute("SELECT count(*) FROM requests").fetchone()[0], 1)
            self.assertEqual(snap["state"]["tasks"], {})
        finally:
            service.close()

    def test_freeze_waits_for_admitted_upload_and_blocks_later_requests(self):
        lifecycle = Lifecycle()
        entered, release = threading.Event(), threading.Event()
        def upload():
            with lifecycle.admit("POST", "/v1/deliver-files"):
                entered.set()
                release.wait(2)
                lifecycle.check_new_work("deliver-files")
        thread = threading.Thread(target=upload)
        thread.start()
        self.assertTrue(entered.wait(1))
        lifecycle.drain()
        result = {}
        freezer = threading.Thread(target=lambda: result.update(lifecycle.freeze(2)))
        freezer.start()
        for _ in range(100):
            if lifecycle.status()["phase"] == "freezing":
                break
            time.sleep(.005)
        with self.assertRaises(Maintenance), lifecycle.admit("GET", "/"):
            pass
        release.set()
        thread.join(2)
        freezer.join(2)
        self.assertEqual(result["phase"], "frozen")
        self.assertEqual(result["active_requests"], 0)

    def test_freeze_timeout_cancels_upgrade(self):
        lifecycle = Lifecycle()
        with lifecycle.admit("POST", "/v1/review"):
            result = lifecycle.freeze(.01)
        self.assertEqual(result["phase"], "running")
        self.assertIn("超时", result["reason"])

    def test_direct_service_instances_cannot_share_writer_and_release_after_close(self):
        service = self.service()
        try:
            with self.assertRaises(Unavailable):
                self.service()
        finally:
            service.close()
        service = self.service()
        service.close()

    def test_browser_session_and_csrf_survive_restart_but_revocation_still_applies(self):
        service = self.service()
        service.session_version = lambda _: (2, 9)
        sessions = DurableSessions(service)
        key = sessions.csrf_key
        token = sessions.create("fixture", None, (2, 9))
        self.assertEqual(sessions.actor(token, service), "fixture")
        raw = service.db.execute("SELECT digest FROM web_sessions").fetchone()[0]
        self.assertNotEqual(raw, token)
        service.close()
        service = self.service()
        try:
            service.session_version = lambda _: (2, 9)
            sessions = DurableSessions(service)
            self.assertEqual(sessions.csrf_key, key)
            self.assertEqual(sessions.actor(token, service), "fixture")
            service.session_version = lambda _: (2, 10)
            self.assertIsNone(sessions.actor(token, service))
            service.session_version = lambda _: (2, 9)
            self.assertIsNone(sessions.actor(token, service))
        finally:
            service.close()

    def test_session_expiry_and_actor_limit(self):
        service = self.service()
        try:
            service.session_version = lambda _: (1, 1)
            sessions = DurableSessions(service, per_actor=2)
            first = sessions.create("fixture", None, (1, 1))
            sessions.create("fixture", None, (1, 1))
            last = sessions.create("fixture", None, (1, 1))
            self.assertIsNone(sessions.actor(first, service))
            with patch("pool.sessions.time.time", return_value=time.time() + sessions.age + 1):
                self.assertIsNone(sessions.actor(last, service))
        finally:
            service.close()

    def test_http_maintenance_is_retryable_and_authenticated_status(self):
        service = self.service()
        with patch("build.client_bundle_bytes", return_value=b"fixture"), Server(0, service, {"fixture": "a" * 43}) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                service.lifecycle.drain()
                conn = HTTPConnection("127.0.0.1", server.server_address[1], timeout=2)
                conn.request("POST", "/v1/claim", b"{}", {"Content-Type": "application/json"})
                response = conn.getresponse()
                self.assertEqual(response.status, 503)
                self.assertEqual(response.getheader("Retry-After"), "3")
                self.assertEqual(json.loads(response.read())["status"], "maintenance")
                conn.close()
                conn = HTTPConnection("127.0.0.1", server.server_address[1], timeout=2)
                conn.request("GET", "/v1/service-status")
                response = conn.getresponse()
                self.assertEqual(response.status, 401)
                response.read()
                conn.close()
                service.lifecycle.freeze(1)
                conn = HTTPConnection("127.0.0.1", server.server_address[1], timeout=2)
                conn.request("GET", "/readyz")
                response = conn.getresponse()
                self.assertEqual(response.status, 503)
                self.assertEqual(json.loads(response.read()), {"phase": "frozen", "ready": False})
                self.assertEqual(response.getheader("Retry-After"), "3")
                conn.close()
                conn = HTTPConnection("127.0.0.1", server.server_address[1], timeout=2)
                conn.request("POST", "/login", b"password=never-echo-this", {"Content-Type": "application/x-www-form-urlencoded"})
                response = conn.getresponse()
                self.assertEqual(response.status, 503)
                self.assertTrue(response.getheader("Content-Type").startswith("text/html"))
                self.assertNotIn(b"never-echo-this", response.read())
                conn.close()
            finally:
                server.shutdown()
                thread.join(2)
                service.close()

    def test_client_retries_exact_request_and_stops_at_bound(self):
        api = client.Pool("http://127.0.0.1:1", None, True)
        bodies = []
        def unavailable(route, token, body, response_format):
            bodies.append(deepcopy(body))
            raise client.RequestError(503, {"status": "maintenance"}, 999)
        with patch.object(api, "_call_once", side_effect=unavailable), patch.object(client.time, "sleep") as sleep:
            with self.assertRaises(client.RequestError):
                api.call("deliver-files", "private", {"request_id": "original", "files": ["frozen bytes"]})
        self.assertEqual(len(bodies), 3)
        self.assertTrue(all(body == bodies[0] for body in bodies))
        self.assertEqual(bodies[0]["request_id"], "original")
        self.assertTrue(all(call.args[0] <= 5 for call in sleep.call_args_list))

    def test_pending_write_survives_planned_maintenance(self):
        state = client.State(self.root / "private/window.credential")
        state.data = {"token": "fixture-token"}
        api = SimpleNamespace(call=lambda *args: (_ for _ in ()).throw(client.RequestError(503, {"status": "maintenance"})))
        with self.assertRaises(client.RequestError):
            client.durable_write(state, api, {"name": "deliver", "parameters": {}}, "deliver-files", lambda: {"files": ["original"]})
        first = deepcopy(state.data["pending_write"])
        reloaded = client.State(state.path)
        with reloaded.exclusive():
            self.assertEqual(reloaded.data["pending_write"], first)
        seen = []
        api.call = lambda route, token, body: seen.append(deepcopy(body)) or {"status": "applied"}
        client.durable_write(state, api)
        self.assertEqual(seen[0], first["body"])
        self.assertNotIn("pending_write", state.data)

    def test_compact_tasks_and_full_escape(self):
        row = {"task_id": "T10", "title": "fixture", "inputs": {"large": "payload"},
               "qualification": {"eligible": True, "missing": []}}
        api = SimpleNamespace(call=lambda *args: {"tasks": [row], "counts": {"visible": 1, "claimable": 1}})
        api._taskpool_features = {"api_protocol": 1, "security_schema": 3, "features": {"list-summary": False}}
        state = SimpleNamespace(data={"token": "fixture"})
        compact = client.visible_tasks(state, api, SimpleNamespace(project=None, claimable=False, full=False))
        self.assertNotIn("inputs", compact["tasks"][0])
        full = client.visible_tasks(state, api, SimpleNamespace(project=None, claimable=False, full=True))
        self.assertEqual(full["tasks"][0]["inputs"], row["inputs"])

    def test_trust_update_verifies_endpoint_before_persisting_new_pin(self):
        state = client.State(self.root / "private/window.credential")
        state.data = {"url": "https://fixture.test:443", "token": "existing-token", "executor_id": "fixture",
                      "certificate_sha256": "a" * 64, "pending_write": {"body": {"request_id": "frozen"}}}
        state.save()
        api = SimpleNamespace(pin="b" * 64, call=lambda route, token: {"identity": "fixture"})
        with patch.object(client, "Pool", return_value=api):
            client.trust_update(state, SimpleNamespace(sha256="b" * 64))
        self.assertEqual(state.data["token"], "existing-token")
        self.assertEqual(state.data["pending_write"]["body"]["request_id"], "frozen")
        with patch.object(client, "Pool", side_effect=ssl.SSLCertVerificationError("expired")):
            with self.assertRaises(ssl.SSLCertVerificationError):
                client.trust_update(state, SimpleNamespace(sha256="c" * 64))
        self.assertEqual(state.data["certificate_sha256"], "b" * 64)

    @unittest.skipUnless(shutil.which("openssl"), "real TLS fixture requires OpenSSL (available inside WSL)")
    def test_real_tls_pin_hostname_and_expiry_gate_token_transmission(self):
        key, cert, expired = (self.root / name for name in ("test.key", "test.pem", "expired.pem"))
        help_text = client.subprocess.run(["openssl", "x509", "-help"], capture_output=True, text=True)
        if "-not_after" not in help_text.stdout + help_text.stderr:
            self.skipTest("expired TLS fixture requires OpenSSL x509 -not_after")
        client.subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                               "-out", str(cert), "-days", "1", "-subj", "/CN=fixture.test", "-addext",
                               "subjectAltName=DNS:fixture.test"], check=True, capture_output=True)
        client.subprocess.run(["openssl", "x509", "-in", str(cert), "-signkey", str(key),
                               "-not_before", "20200101000000Z", "-not_after", "20200102000000Z",
                               "-out", str(expired)], check=True, capture_output=True)
        received = []
        class Identity(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                received.append(self.headers.get("Authorization"))
                raw = b'{"identity":"fixture"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
        for certificate, host, bad_pin in ((cert, "fixture.test", False), (cert, "wrong.test", False),
                                           (cert, "fixture.test", True), (expired, "fixture.test", False)):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            server = ThreadingHTTPServer(("127.0.0.1", 0), Identity)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            received.clear()
            pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate.read_text())).hexdigest()
            if bad_pin:
                pin = "0" * 64
            try:
                def call():
                    api = client.Pool(f"https://{host}:{server.server_address[1]}", pin, connect_host="127.0.0.1")
                    return api.call("identity", "existing-token")
                if certificate == cert and host == "fixture.test" and not bad_pin:
                    self.assertEqual(call()["identity"], "fixture")
                    self.assertEqual(received, ["Bearer existing-token"])
                else:
                    with self.assertRaises((ValueError, ssl.SSLCertVerificationError)):
                        call()
                    self.assertEqual(received, [])
            finally:
                server.shutdown()
                thread.join(2)
                server.server_close()

    def test_output_redacts_strings_without_mutating_source(self):
        value = {"details": "Bearer private-secret token=abc password=def https://pool/ai/join/i-123#key=xyz&sha256=aaa",
                 "token": "private", "path": r"C:\fixture\input.txt"}
        original = deepcopy(value)
        rendered = json.dumps(client.public_value(value))
        for secret in ("private-secret", "abc", "def", "xyz"):
            self.assertNotIn(secret, rendered)
        self.assertEqual(value, original)
        self.assertIn("fixture", rendered)
        self.assertNotIn("x" * 32, client.safe_error("sk-proj-" + "x" * 32))
        self.assertNotIn("private-fragment", client.safe_error("-----BEGIN PRIVATE KEY-----private-fragment-----END PRIVATE KEY-----"))

    def test_capability_request_and_resolve_use_durable_exact_contracts(self):
        state = client.State(self.root / "private/window.credential")
        state.data = {"token": "fixture-token"}
        writes = []
        def call(route, token=None, body=None, **kwargs):
            if route == "identity":
                return {"identity": "fixture", "binding": {"environment": "test-env"}}
            if route == "capability-requests":
                return [{"id": "vr-fixture", "version": 2}]
            writes.append((route, deepcopy(body)))
            return {"status": "applied"}
        api = SimpleNamespace(call=call)
        args = SimpleNamespace(project="p", capability="review", kind="skill", value="ok", environment=None,
                               evidence="fixture evidence", evidence_sha256="a" * 64, days=7)
        client.request_capability(state, api, args)
        self.assertEqual(writes[0][0], "capability-request")
        self.assertEqual(writes[0][1]["environment"], "test-env")
        self.assertEqual(writes[0][1]["evidence"]["sha256"], "a" * 64)
        client.resolve_capability(state, api, SimpleNamespace(verification_id="vr-fixture", decision="approve",
                                                             level="probed", reason="independent fixture check"))
        self.assertEqual(writes[1][0], "capability-resolve")
        self.assertEqual(writes[1][1]["version"], 2)

    def test_runner_outage_keeps_child_and_pending_results_without_duplicate_start(self):
        state = client.State(self.root / "private/window.credential")
        state.data = {"token": "fixture", "command": [sys.executable, "-c", "import sys; sys.stdin.read(); print('retained result')"],
                      "workdir": str(self.root)}
        event = {"event_id": "fixture-event", "task_id": "T10", "version": 1, "scope_version": 1, "auto": True}
        claim = {"claim_id": "c-fixture", "epoch": 4, "W": {"scope": 1}}
        unavailable = [True]
        def call(route, token=None, body=None, **kwargs):
            if route == "features":
                return {"api_protocol": 1, "security_schema": 3, "features": {"input-package": False}}
            if route == "notices-poll":
                return {"cursor": 1, "events": [event]}
            if route == "claim":
                return {"claim": claim}
            if route == "run-report" and body["state"] != "intent" and unavailable[0]:
                raise client.RequestError(503, {"status": "maintenance"})
            return {"status": "applied"}
        api = SimpleNamespace(call=call)
        with self.assertRaises(client.RequestError):
            client.run_once(state, api)
        self.assertEqual(state.data["attempt"]["phase"], "completed")
        output = Path(state.data["attempt"]["output"])
        self.assertIn("retained result", output.read_text())
        self.assertEqual([row["state"] for row in state.data["runner_reports"]], ["started", "finished"])
        unavailable[0] = False
        with patch.object(client.subprocess, "Popen", side_effect=AssertionError("duplicate process")):
            result = client.run_once(state, api)
        self.assertEqual(result["status"], "finished")
        self.assertNotIn("attempt", state.data)

    def test_backup_uses_sqlite_backup_and_refuses_live_writer(self):
        archive = self.root.parent / (self.root.name + "-archive")
        try:
            service = self.service()
            with self.assertRaises(Unavailable):
                backup.snapshot(self.root, archive, "fixture")
            with service.db:
                service.db.execute("CREATE TABLE fixture(value TEXT)")
                service.db.execute("INSERT INTO fixture VALUES('preserved')")
            service.close()
            (self.root / "inputs").mkdir()
            (self.root / "inputs/original.txt").write_text("original", encoding="utf-8")
            backup.snapshot(self.root, archive, "fixture", seed=True)
            result = backup.snapshot(self.root, archive, "fixture")
            manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
            row = manifest["files"]["http-journal.sqlite3"]
            self.assertTrue(row["sqlite_backup"])
            self.assertEqual(manifest["ledger_head"], 0)
            self.assertEqual(manifest["ledger_sha256"], "a" * 64)
            with closing(sqlite3.connect(archive / "objects" / row["sha256"])) as db:
                self.assertEqual(db.execute("SELECT value FROM fixture").fetchone()[0], "preserved")
            with self.assertRaises(ValueError):
                backup.snapshot(self.root, archive, "fixture")
        finally:
            import shutil
            shutil.rmtree(archive, ignore_errors=True)

    def test_online_backup_waits_for_original_write_and_preserves_single_writer(self):
        archive = self.root.parent / (self.root.name + "-online")
        service = self.service()
        writing, finish_write, copying, finish_copy = (threading.Event() for _ in range(4))
        result, failures = {}, []
        def write():
            with service.lifecycle.admit("POST", "/v1/review"), service.lock:
                writing.set()
                finish_write.wait(2)
                with service.db:
                    service.db.execute("CREATE TABLE completed_request(value TEXT)")
                    service.db.execute("INSERT INTO completed_request VALUES('original request finished')")
        original_archive = backup.snapshot.__globals__["archive_file"]
        def copy_file(*args):
            copying.set()
            finish_copy.wait(2)
            return original_archive(*args)
        def perform_backup():
            try:
                result.update(service.consistent_backup(str(archive), "online", 2))
            except Exception as error:
                failures.append(error)
        writer = threading.Thread(target=write)
        writer.start()
        self.assertTrue(writing.wait(1))
        try:
            with patch("pool.backup.archive_file", side_effect=copy_file):
                worker = threading.Thread(target=perform_backup)
                worker.start()
                for _ in range(100):
                    if service.lifecycle.status()["phase"] == "freezing":
                        break
                    time.sleep(.005)
                with self.assertRaises(Maintenance), service.lifecycle.admit("POST", "/v1/claim"):
                    pass
                finish_write.set()
                writer.join(2)
                self.assertTrue(copying.wait(2))
                self.assertEqual(service.lifecycle.status()["phase"], "backing_up")
                with self.assertRaises(Maintenance), service.lifecycle.admit("POST", "/v1/claim"):
                    pass
                with self.assertRaises(ValueError):
                    service.lifecycle.cancel()
                with self.assertRaises(Unavailable):
                    self.service()
                finish_copy.set()
                worker.join(3)
            self.assertEqual(failures, [])
            self.assertEqual(result["phase"], "running")
            manifest = json.loads((archive / "online.json").read_text(encoding="utf-8"))
            row = manifest["files"]["http-journal.sqlite3"]
            with closing(sqlite3.connect(archive / "objects" / row["sha256"])) as db:
                self.assertEqual(db.execute("SELECT value FROM completed_request").fetchone()[0], "original request finished")
        finally:
            finish_write.set()
            finish_copy.set()
            writer.join(2)
            service.close()
            shutil.rmtree(archive, ignore_errors=True)

    def test_online_backup_failure_restores_previous_phase_and_rejects_unsafe_target(self):
        archive = self.root.parent / (self.root.name + "-failure")
        service = self.service()
        try:
            for phase in ("running", "draining"):
                if phase == "draining":
                    service.lifecycle.drain()
                with patch("pool.backup.archive_file", side_effect=OSError("fixture copy failure")):
                    with self.assertRaises(OSError):
                        service.consistent_backup(str(archive), phase, 1)
                self.assertEqual(service.lifecycle.status()["phase"], phase)
                with service.lifecycle.admit("POST", "/v1/review"):
                    with self.assertRaises(ValueError):
                        service.consistent_backup(str(archive), "timeout", .01)
                self.assertEqual(service.lifecycle.status()["phase"], phase)
            target = self.root / "forbidden-new-directory"
            with self.assertRaises(ValueError):
                service.consistent_backup(str(target), "inside", 1)
            self.assertFalse(target.exists())
            self.assertEqual(service.lifecycle.status()["phase"], "draining")
            service.lifecycle.cancel()
            with patch("pool.backup.json.dump", side_effect=OSError("fixture manifest write failure")):
                with self.assertRaises(OSError):
                    service.consistent_backup(str(archive), "partial", 1)
            self.assertFalse((archive / "partial.json").exists())
            self.assertEqual(service.lifecycle.status()["phase"], "running")
            service.consistent_backup(str(archive), "valid", 1)
            with self.assertRaises(ValueError):
                service.consistent_backup(str(archive), "valid", 1)
            self.assertEqual(service.lifecycle.status()["phase"], "running")
            with self.assertRaises(ValueError):
                backup.snapshot(self.root, archive, "bypass", service=service)
        finally:
            service.close()
            shutil.rmtree(archive, ignore_errors=True)

    def test_tls_whitelist_objects_and_current_credentials_are_preserved(self):
        store, tls, archive, service = self.tls_fixture()
        tls.mkdir()
        material = {"key.pem": b"synthetic fixture key bytes; never a real private key",
                    "cert-v2.pem": b"synthetic current public certificate bytes",
                    "cert.pem": b"synthetic compatibility public certificate bytes"}
        for name, raw in material.items():
            (tls / name).write_bytes(raw)
        (tls / "outside-whitelist.txt").write_bytes(b"fixture material that must not be copied")
        credential = b'{"tokens":{"fixture":"synthetic-existing-token"}}'
        (store / "credentials.json").write_bytes(credential)
        service.session_version = lambda _: (3, 7)
        sessions = DurableSessions(service)
        cookie = sessions.create("fixture", None, (3, 7))
        try:
            result = service.consistent_backup(str(archive), "tls-complete", 1)
            manifest = json.loads((archive / "tls-complete.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["tls_backup"]["status"], "complete")
            self.assertTrue(manifest["tls_backup"]["included"])
            self.assertEqual(set(manifest["service_files"]), {"tls/" + name for name in material})
            self.assertTrue(all(not key.startswith("../") for key in manifest["files"]))
            for name, raw in material.items():
                row = manifest["service_files"]["tls/" + name]
                self.assertEqual(row["sha256"], hashlib.sha256(raw).hexdigest())
                obj = archive / "objects" / row["sha256"]
                self.assertEqual(obj.read_bytes(), raw)
                self.assertEqual(row["mode"], 0o600)
                if os.name == "posix":
                    self.assertEqual(obj.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(archive.stat().st_mode & 0o777, 0o700)
            credential_row = manifest["files"]["credentials.json"]
            self.assertEqual((archive / "objects" / credential_row["sha256"]).read_bytes(), credential)
            self.assertEqual(sessions.actor(cookie, service), "fixture")
            with closing(sqlite3.connect(archive / "objects" / manifest["files"]["http-journal.sqlite3"]["sha256"])) as db:
                self.assertEqual(db.execute("SELECT actor FROM web_sessions WHERE digest=?", (sessions.digest(cookie),)).fetchone()[0], "fixture")
                self.assertEqual(db.execute("SELECT value FROM web_secrets WHERE name='csrf'").fetchone()[0], sessions.csrf_key)
            summary = json.dumps(result)
            self.assertNotIn("synthetic-existing-token", summary)
            self.assertNotIn(credential_row["sha256"], summary)
            self.assertNotIn("service_files", result)
            self.assertEqual(result["service_file_count"], 3)
            self.assertEqual(result["head"], 0)
        finally:
            service.close()

    def test_missing_tls_is_explicit_and_restore_targets_are_fixed_to_current_store(self):
        store, tls, archive, service = self.tls_fixture()
        try:
            result = service.consistent_backup(str(archive), "without-tls", 1)
            manifest = json.loads((archive / "without-tls.json").read_text(encoding="utf-8"))
            self.assertEqual(result["tls_status"], "absent")
            self.assertFalse(manifest["tls_backup"]["included"])
            self.assertEqual(manifest["service_files"], {})
            tls.mkdir()
            (tls / "key.pem").write_bytes(b"synthetic key only")
            result = service.consistent_backup(str(archive), "incomplete-tls", 1)
            self.assertEqual(result["tls_status"], "incomplete")
            entries = {"tls/key.pem": {"sha256": "a" * 64}}
            scope = backup.snapshot.__globals__["service_restore_targets"](store, entries)
            self.assertEqual(scope["tls/key.pem"], store.parent / "tls" / "key.pem")
            for key in ("../tls/key.pem", "/elsewhere/key.pem", "tls/other.pem", "tls/../../secret"):
                with self.assertRaises(ValueError):
                    backup.snapshot.__globals__["service_restore_targets"](store, {key: {}})
            (tls / "cert-v2.pem").mkdir()
            with self.assertRaises(ValueError):
                service.consistent_backup(str(archive), "nonregular-tls", 1)
            self.assertEqual(service.lifecycle.status()["phase"], "running")
            self.assertFalse((archive / "nonregular-tls.json").exists())
            with self.assertRaises(ValueError):
                service.consistent_backup(str(tls / "forbidden-backup"), "inside-tls", 1)
        finally:
            service.close()

    @unittest.skipUnless(os.name == "posix", "POSIX symlink fixture uses only temporary synthetic TLS bytes")
    def test_tls_symlink_directory_or_member_is_rejected_without_manifest(self):
        store, tls, archive, service = self.tls_fixture()
        target = self.root / "synthetic-target"
        target.mkdir()
        (target / "key.pem").write_bytes(b"synthetic key behind forbidden link")
        try:
            tls.symlink_to(target, target_is_directory=True)
            with self.assertRaises(ValueError):
                service.consistent_backup(str(archive), "linked-directory", 1)
            tls.unlink()
            tls.mkdir()
            (tls / "key.pem").symlink_to(target / "key.pem")
            with self.assertRaises(ValueError):
                service.consistent_backup(str(archive), "linked-key", 1)
            self.assertEqual(service.lifecycle.status()["phase"], "running")
            self.assertFalse((archive / "linked-directory.json").exists())
            self.assertFalse((archive / "linked-key.json").exists())
            self.assertFalse(any((archive / "objects").iterdir()))
        finally:
            service.close()

    @unittest.skipUnless(os.name == "posix", "Unix private control socket runs inside Linux/WSL service")
    def test_control_requires_private_auth_and_does_not_open_second_service(self):
        lifecycle = Lifecycle()
        with Control(self.root, lifecycle, lambda: None):
            self.assertEqual(control_request(self.root, "drain")["phase"], "draining")
            self.assertEqual(control_request(self.root, "freeze")["phase"], "frozen")
            self.assertEqual(control_request(self.root, "cancel")["phase"], "running")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.connect(str(self.root / "upgrade-control.sock"))
                connection.sendall(b'{"token":"wrong","command":"shutdown"}\n')
                self.assertFalse(json.loads(connection.makefile("rb").readline())["ok"])
            self.assertEqual(lifecycle.status()["phase"], "running")

    @unittest.skipUnless(os.name == "posix", "Unix private control socket runs inside Linux/WSL service")
    def test_control_status_and_cancel_remain_available_during_freeze_wait(self):
        lifecycle = Lifecycle()
        result = {}
        with Control(self.root, lifecycle, lambda: None):
            with lifecycle.admit("POST", "/v1/deliver-files"):
                thread = threading.Thread(target=lambda: result.update(control_request(self.root, "freeze", 2)))
                thread.start()
                for _ in range(100):
                    if lifecycle.status()["phase"] == "freezing":
                        break
                    time.sleep(.005)
                self.assertEqual(control_request(self.root, "status")["phase"], "freezing")
                self.assertEqual(control_request(self.root, "cancel")["phase"], "running")
                thread.join(2)
                self.assertEqual(result["phase"], "running")

    @unittest.skipUnless(os.name == "posix", "Unix private control socket runs inside Linux/WSL service")
    def test_authenticated_control_backup_uses_existing_service(self):
        archive = self.root.parent / (self.root.name + "-control-backup")
        service = self.service()
        try:
            with Control(self.root, service.lifecycle, lambda: None, service.consistent_backup):
                result = control_request(self.root, "backup", 1, archive=str(archive), tag="scheduled")
                self.assertEqual(result["phase"], "running")
                self.assertTrue((archive / "scheduled.json").is_file())
                with self.assertRaises(Unavailable):
                    self.service()
                service.lifecycle.drain()
                with self.assertRaises(ValueError):
                    control_request(self.root, "backup", 1, archive=str(archive), tag="scheduled")
                self.assertEqual(service.lifecycle.status()["phase"], "draining")
        finally:
            service.close()
            shutil.rmtree(archive, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
