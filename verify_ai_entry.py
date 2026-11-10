"""AI invitation routing and credential-save regression with isolated TLS fixtures."""
import errno
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import shutil
import ssl
import sqlite3
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pool.httpd import Handler, Server
from pool.lifecycle import Lifecycle

SPEC = importlib.util.spec_from_file_location("round_client_entry", Path(__file__).parent / "ops" / "round-client.py")
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


def temporary_directory():
    root = Path(__file__).resolve().parent / ".state"
    root.mkdir(exist_ok=True)
    return tempfile.TemporaryDirectory(prefix="ai-entry-", dir=root)


class EntryTest(unittest.TestCase):
    def test_https_bundle_uses_service_name_and_preserves_connection_address(self):
        handler = SimpleNamespace(server=SimpleNamespace(tls=True, lan_name="taskpool.test", tls_fingerprint="a" * 64),
                                  headers={"Host": "taskpool-host:18443"})
        handler.server.client_archive = b"fixture package bytes"
        bundle = Handler.invitation_bundle(handler, {"id": "fixture", "code": "fixture-secret"})
        self.assertEqual(bundle["url"], "https://taskpool.test:18443")
        self.assertEqual(bundle["connect_host"], "taskpool-host")
        self.assertEqual(bundle["certificate_sha256"], "a" * 64)
        self.assertEqual(bundle["kind"], "ai-window")
        self.assertEqual(bundle["client"]["url"], "https://taskpool.test:18443/ai-client.zip")
        self.assertEqual(bundle["client"]["sha256"], hashlib.sha256(handler.server.client_archive).hexdigest())
        self.assertTrue(any("enroll" in line for line in bundle["instructions"]))

    def test_legacy_loopback_bundle_is_unchanged(self):
        handler = SimpleNamespace(server=SimpleNamespace(tls=None, tls_fingerprint=None), headers={"Host": "127.0.0.1:12345"})
        handler.server.client_archive = b"fixture package bytes"
        bundle = Handler.invitation_bundle(handler, {"id": "fixture", "code": "fixture-secret"})
        self.assertEqual(bundle["url"], "http://127.0.0.1:12345")
        self.assertNotIn("connect_host", bundle)

    def test_rotation_keeps_its_activation_purpose(self):
        handler = SimpleNamespace(server=SimpleNamespace(tls=True, lan_name="taskpool.test", tls_fingerprint="a" * 64),
                                  headers={"Host": "taskpool-host:18443"})
        bundle = Handler.invitation_bundle(handler, {"registration_id": "fixture", "token": "fixture-secret"})
        self.assertEqual(bundle["kind"], "ai-token-rotation")
        self.assertNotIn("instructions", bundle)

    def test_public_help_and_client_download_need_no_account_or_invite(self):
        from http.client import HTTPConnection
        fixture = SimpleNamespace(round_enabled=lambda: False, lifecycle=Lifecycle(), lock=threading.RLock(),
                                  db=sqlite3.connect(":memory:", check_same_thread=False))
        server = Server(0, fixture, {})
        server.client_archive = b"public fixture package"
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            for path in ("/ai", "/ai-client.zip"):
                connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
                connection.request("GET", path)
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                raw = response.read()
                if path.endswith(".zip"):
                    self.assertEqual(raw, server.client_archive)
                else:
                    self.assertIn(b"enroll", raw)
                connection.close()
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
            fixture.db.close()

    def test_invalid_connection_address_is_rejected_before_network_access(self):
        with patch.object(client.socket, "create_connection") as connect:
            for value in ("https://taskpool-host", "taskpool-host:18443", "user@taskpool-host", "", 7, "a\nb"):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    client.Pool("https://taskpool.test:18443", "a" * 64, connect_host=value)
            connect.assert_not_called()

    def test_plaintext_loopback_cannot_route_to_another_host(self):
        with self.assertRaises(ValueError):
            client.Pool("http://127.0.0.1:12345", None, allow_loopback=True, connect_host="taskpool-host")

    def test_atomic_save_failure_preserves_existing_credential_and_cleans_temporary_file(self):
        with temporary_directory() as name:
            root = Path(name) / "private"
            state = client.State(root / "window.credential")
            state.data = {"marker": "original fixture"}
            state.save()
            original = state.path.read_bytes()
            state.data = {"marker": "unsaved fixture"}
            error = OSError(errno.EXDEV, "fixture cross-device replacement")
            error.winerror = 17
            with patch.object(client.os, "replace", side_effect=error), self.assertRaisesRegex(ValueError, "跨设备"):
                state.save()
            self.assertEqual(state.path.read_bytes(), original)
            self.assertEqual(list(root.glob(".window-*")), [])
            self.assertEqual(json.loads(client.private_bytes(original, decrypt=True)), {"marker": "original fixture"})


class TLSRoutingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        openssl = shutil.which("openssl")
        if not openssl and os.name == "nt":
            git = shutil.which("git")
            path = Path(git).parent.parent / "usr/bin/openssl.exe" if git else Path("C:/Program Files/Git/usr/bin/openssl.exe")
            openssl = str(path) if path.is_file() else None
        if not openssl:
            raise unittest.SkipTest("OpenSSL is required for the isolated TLS fixture")
        cls.directory = temporary_directory()
        root = Path(cls.directory.name)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
                        "-subj", "/CN=taskpool.test", "-addext", "subjectAltName=DNS:taskpool.test",
                        "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
                        "-addext", "extendedKeyUsage=serverAuth", "-keyout", str(key), "-out", str(cert)],
                       check=True, capture_output=True, timeout=30)
        cls.pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text(encoding="ascii"))).hexdigest()
        cls.requests = []

        class Echo(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                cls.requests.append((self.command, self.path))
                raw = json.dumps({"host": self.headers["Host"], "path": self.path}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_POST = do_GET

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()
        cls.directory.cleanup()

    def test_routed_connection_verifies_service_name_and_sends_canonical_host(self):
        api = client.Pool(f"https://taskpool.test:{self.port}", self.pin, connect_host="127.0.0.1")
        reply = api.call("identity")
        self.assertEqual(reply, {"host": f"taskpool.test:{self.port}", "path": "/v1/identity"})

    def test_wrong_certificate_name_cannot_send_invitation(self):
        before = len(self.requests)
        api = client.Pool(f"https://wrong.test:{self.port}", self.pin, connect_host="127.0.0.1")
        with self.assertRaises(ssl.SSLCertVerificationError):
            api.call("ai-prepare", body={"code": "fixture-secret"})
        self.assertEqual(len(self.requests), before)

    def test_wrong_fingerprint_cannot_send_invitation(self):
        before = len(self.requests)
        with self.assertRaisesRegex(ValueError, "指纹"):
            client.Pool(f"https://taskpool.test:{self.port}", "0" * 64, connect_host="127.0.0.1")
        self.assertEqual(len(self.requests), before)


if __name__ == "__main__":
    unittest.main()
