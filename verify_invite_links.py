"""Read-only invite-link and minimal-client contracts using synthetic identities."""
import ast
from copy import deepcopy
from email.message import Message
from io import BytesIO
import json
import importlib.util
from pathlib import Path
import sqlite3
from threading import RLock
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import zipfile

import build
from pool.accounts import Accounts
from pool.httpd import Handler, Server
from pool import invite_links, round_web
from pool.packages import ClientError
from pool.lifecycle import Lifecycle


INVITE = "i-" + "a" * 32


class FixtureService:
    def __init__(self):
        self.lock = RLock()
        self.db = sqlite3.connect(":memory:")
        self.accounts = Accounts(self.db)
        self.state = {"pilot": {"format": {"schema": 3},
            "project:p": {"id": "p", "name": "Fixture", "owner": "person"},
            "identity:person": {"kind": "human", "status": "active", "owner": "person"},
            "grant:p:person": {"roles": ["manager"], "resources": []}}, "round": {}}
        self.record = {"id": INVITE, "issuer": "person", "owner": "person", "project": "p", "roles": ["executor"],
                       "used": 0, "count": 1, "revoked": False, "expires": int(time.time()) + 3600}
        self.state["round"]["invite:" + INVITE] = self.record

    def snapshot(self):
        return {"state": self.state}

    def read(self, actor, route, argument=None):
        if route == "invitations":
            return {"invitations": [{**self.record, "windows": []}]} if actor == "person" else {"invitations": []}
        if route == "projects":
            return {"projects": [{"id": "p", "name": "Fixture", "roles": ["manager"]}]}
        if route == 'invitation-owners':
            return {'owners':[{'identity':'person','name':'person','kind':'human','status':'active'}]}
        raise AssertionError(route)

    def submit(self, *_args, **_kwargs):
        raise AssertionError("link preview or conversion must not submit an enrollment or another invitation")


class FixtureHandler:
    dispatch = Handler.dispatch
    invitation_bundle = Handler.invitation_bundle
    authenticate = Handler.authenticate
    send = Handler.send
    handle_api = Handler.handle_api

    def __init__(self, service, path="/ai", headers=()):
        self.server = SimpleNamespace(service=service, tls=True, tls_fingerprint="a" * 64, lan_name="taskpool.test",
            lan_names={"taskpool.test", "taskpool-host"}, server_address=("127.0.0.1", 18443), is_round=True,
            client_archive=b"synthetic public package", actor_for_token=lambda *_args: None,lifecycle=Lifecycle())
        self.server.allows_host = lambda values: Server.allows_host(self.server, values)
        self.path, self.command = path, "GET"
        self.headers = Message()
        self.headers["Host"] = "taskpool-host:18443"
        for name, value in headers:
            self.headers[name] = value
        self.status, self.sent_headers, self.wfile = None, {}, BytesIO()

    def send_response(self, status):
        self.status = status

    def send_header(self, name, value):
        self.sent_headers[name] = value

    def end_headers(self):
        pass


class InviteLinks(unittest.TestCase):
    def setUp(self):
        self.service = FixtureService()
        self.handler = FixtureHandler(self.service)
        self.proof = self.service.accounts.token("ai-invite-link", INVITE, "person")

    def tearDown(self):
        self.service.db.close()

    def information(self, proof=None):
        return invite_links.information(self.handler, INVITE, self.proof if proof is None else proof)

    def test_link_keeps_proof_and_certificate_binding_in_fragment_only(self):
        original = deepcopy(self.service.state)
        url = invite_links.link(self.handler, self.service.record)
        address = urlsplit(url)
        fragment = parse_qs(address.fragment)
        self.assertEqual((address.hostname, address.path), ("taskpool-host", "/ai/join/" + INVITE))
        self.assertEqual(address.query, "")
        self.assertEqual(fragment, {"key": [self.proof], "sha256": ["a" * 64], "tls": ["taskpool.test"]})
        self.assertNotIn(self.proof, url.split("#", 1)[0])
        self.assertEqual(self.service.state, original)

    def test_public_preview_neither_contains_secret_nor_redeems_invite(self):
        before = deepcopy(self.service.state)
        self.handler.path = "/ai/join/" + INVITE
        self.handler.handle_api("GET")
        self.assertEqual(self.handler.status, 200)
        body = self.handler.wfile.getvalue().decode()
        self.assertNotIn(self.proof, body)
        self.assertNotIn(self.service.accounts.token("ai-invite", INVITE, "person"), body)
        self.assertEqual(self.service.state, before)

    def test_proof_fetch_returns_invitation_without_changing_used_count(self):
        before = deepcopy(self.service.state)
        value = self.information()
        self.assertEqual(value["code"], self.service.accounts.token("ai-invite", INVITE, "person"))
        self.assertEqual(value["connect_host"], "taskpool-host")
        self.assertTrue(value["instructions"])
        self.assertEqual(self.service.state, before)

    def test_invite_code_and_wrong_proof_cannot_act_as_link_proof(self):
        for proof in ("wrong", self.service.accounts.token("ai-invite", INVITE, "person"), "非ASCII"):
            with self.subTest(proof_type="synthetic"), self.assertRaises(ClientError) as failure:
                self.information(proof)
            self.assertEqual(failure.exception.status, 403)

    def test_revoke_expiry_limit_and_changed_person_permission_are_checked_on_fetch(self):
        for change, status in (({"revoked": True}, 410), ({"expires": 0}, 410), ({"used": 1}, 409)):
            original = deepcopy(self.service.record)
            self.service.record.update(change)
            with self.subTest(change=change), self.assertRaises(ClientError) as failure:
                self.information()
            self.assertEqual(failure.exception.status, status)
            self.service.record.clear()
            self.service.record.update(original)
        self.service.state["pilot"]["grant:p:person"]["roles"] = []
        with self.assertRaises(ClientError) as failure:
            self.information()
        self.assertEqual(failure.exception.status, 403)

    def test_info_endpoint_requires_a_dedicated_bearer_proof(self):
        path = "/v1/ai-invite-info?invite_id=" + INVITE
        for headers, expected in (([], 401), ([("Authorization", "Basic fixture")], 401),
                                  ([("Authorization", "Bearer wrong")], 401),
                                  ([("Authorization", "Bearer " + "b" * 43)], 403),
                                  ([("Authorization", "Bearer " + self.proof)], 200)):
            handler = FixtureHandler(self.service, path, headers)
            handler.handle_api("GET")
            self.assertEqual(handler.status, expected)
        handler = FixtureHandler(self.service, "/v1/identity", [("Authorization", "Bearer " + self.proof)])
        handler.handle_api("GET")
        self.assertEqual(handler.status, 401)

    def test_duplicate_authorization_headers_are_rejected(self):
        handler = FixtureHandler(self.service, "/v1/ai-invite-info?invite_id=" + INVITE,
                                 [("Authorization", "Bearer " + self.proof), ("Authorization", "Bearer wrong")])
        handler.handle_api("GET")
        self.assertEqual(handler.status, 401)

    def test_unknown_path_is_404_and_known_protected_endpoint_is_401(self):
        for path, expected in (("/docs", 404), ("/v1/does-not-exist", 404), ("/v1/tasks", 401)):
            handler = FixtureHandler(self.service, path)
            handler.handle_api("GET")
            self.assertEqual(handler.status, expected)
            data = json.loads(handler.wfile.getvalue())
            self.assertEqual(data["help_url"], "/ai")

    def test_head_has_get_content_length_and_no_response_body(self):
        handler = FixtureHandler(self.service, "/ai-client.zip")
        handler.command = "HEAD"
        Handler.do_HEAD(handler)
        self.assertEqual(handler.status, 200)
        self.assertEqual(int(handler.sent_headers["Content-Length"]), len(handler.server.client_archive))
        self.assertEqual(handler.wfile.getvalue(), b"")

    def old_link(self, actor="person"):
        with patch("pool.web.parse_form", return_value={"operation": "link", "request_id": "fixture-link", "invite_id": INVITE}):
            return round_web.invitations(self.handler, "POST", actor)

    def test_old_invitation_link_does_not_issue_invite_or_consume_quota(self):
        before = deepcopy(self.service.state)
        result = self.old_link()
        self.assertEqual(result[0], 200)
        self.assertEqual(self.service.state, before)
        self.assertTrue(invite_links.is_current(self.service, INVITE))

    def test_expired_and_exhausted_old_invitation_cannot_generate_link(self):
        for change in ({"expires": 0}, {"used": 1}):
            old = deepcopy(self.service.record)
            self.service.record.update(change)
            with self.subTest(change=change), self.assertRaises(ClientError) as failure:
                self.old_link()
            self.assertEqual(failure.exception.status, 409)
            self.service.record.clear()
            self.service.record.update(old)

    def test_another_person_cannot_retrieve_link_for_unlisted_invitation(self):
        with self.assertRaises(ClientError) as failure:
            self.old_link("other")
        self.assertEqual(failure.exception.status, 404)

    def test_presentation_metadata_stores_no_link_key_or_invite_code(self):
        invite_links.remember(self.service, INVITE)
        rows = self.service.db.execute("SELECT * FROM invite_presentations").fetchall()
        self.assertEqual(rows, [(INVITE, 2)])
        self.assertNotIn(self.proof, repr(rows))

    def test_minimal_client_archive_has_only_client_docs_and_metadata(self):
        raw = build.client_bundle_bytes()
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            self.assertEqual(set(archive.namelist()), {"ops/round-client.py", "ops/round-client.ps1", "ops/relay-mcp.py", "README.md",
                                                     "docs/AI客户端操作.md", "docs/执行环境与资源映射.md", "client-version.json", "LICENSE"})
            self.assertEqual(archive.read("README.md"), archive.read("docs/AI客户端操作.md"))
            self.assertEqual(json.loads(archive.read("client-version.json"))["purpose"], "ai-window-client")
            ast.parse(archive.read("ops/round-client.py"), feature_version=(3, 11))


class ClientLinkBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("invite_link_client", Path(__file__).parent / "ops/round-client.py")
        cls.client = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.client)

    def test_bootstrap_response_cannot_replace_the_original_connection_host(self):
        key, pin = "k" * 43, "a" * 64
        url = f"https://taskpool-host:18443/ai/join/{INVITE}#key={key}&sha256={pin}&tls=taskpool.test"
        args = SimpleNamespace(invite_url=url, allow_loopback=False)
        response = {"id": INVITE, "protocol": 1, "url": "https://taskpool.test:18443", "certificate_sha256": pin,
                    "connect_host": "taskpool.test", "code": "c" * 43,
                    "client": {"connect_host": "taskpool.test"}, "invitation_url": url}
        with patch.object(self.client, "Pool") as pool:
            pool.return_value.call.return_value = response
            result = self.client.load_invitation(args)
        pool.assert_called_once_with("https://taskpool.test:18443", pin, False, "taskpool-host")
        self.assertEqual(result["connect_host"], "taskpool-host")
        self.assertEqual(result["client"]["connect_host"], "taskpool-host")
        self.assertNotIn("invitation_url", result)

    def test_pending_registration_recovers_saved_request_without_fetching_expired_link(self):
        saved = {"request_id": "original", "invite_id": INVITE, "code": "c" * 43, "recovery": "r" * 43, "source": {}}
        state = SimpleNamespace(data={"request": deepcopy(saved)}, save=lambda: None)
        args = SimpleNamespace(invite=None, invite_url="https://fixture.invalid/expired", allow_loopback=False)
        with patch.object(self.client, "load_invitation", side_effect=AssertionError("must not refetch consumed invitation")), \
                patch.object(self.client, "endpoint") as endpoint, \
                patch.object(self.client, "finish_activation", return_value={"status": "active"}):
            endpoint.return_value.call.return_value = {"token": "t" * 43, "registration_id": "fixture-registration"}
            result = self.client.enroll(state, args)
        endpoint.return_value.call.assert_called_once_with("ai-prepare", body=saved)
        self.assertEqual(result, {"status": "active"})


if __name__ == "__main__":
    unittest.main()
