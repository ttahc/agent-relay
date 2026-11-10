"""R2 browser response protocol and typed execution forms, isolated from real stores."""
from copy import deepcopy
import json
from threading import RLock
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit

from pool import execution_pages as ui, web, workbench
from pool.packages import ClientError


class UiTests(unittest.TestCase):
    def handler(self, actor="person", read=None):
        service = SimpleNamespace(lock=RLock(), read=read or (lambda *args: {}))
        return SimpleNamespace(headers={"X-TaskPool-Response": "json", "X-TaskPool-Request-ID": "same-request"},
            form_token="c" * 64, web_request_id="same-request", web_action_result={},
            server=SimpleNamespace(service=service, tls=False, is_round=True, sessions=SimpleNamespace(actor=lambda *args: actor)))

    def test_native_redirect_envelope_preserves_cookie_and_identity(self):
        handler = self.handler()
        result = web.json_web_response(handler, web.redirect("/tasks/T01", ("Set-Cookie", "fixture=value; HttpOnly")), "/actions/register")
        value = json.loads(result[1])
        self.assertEqual(result[0], 200)
        self.assertEqual(value["state"], "completed")
        self.assertEqual(value["request_id"], "same-request")
        self.assertEqual(value["redirect_url"], "/tasks/T01")
        self.assertIn(("Set-Cookie", "fixture=value; HttpOnly"), result[3])
        self.assertFalse(any(name == "Location" for name, _ in result[3]))
        self.assertEqual(value["csrf"], "c" * 64)

    def test_expired_redirect_is_not_a_successful_post(self):
        handler = self.handler()
        result = web.json_web_response(handler, web.redirect("/login"), "/actions/claim")
        self.assertEqual(result[0], 401); self.assertEqual(json.loads(result[1])["state"], "rejected")
        handler.web_operation_completed = True
        result = web.json_web_response(handler, web.redirect("/login"), "/password")
        self.assertEqual(result[0], 200); self.assertEqual(json.loads(result[1])["state"], "completed")

    def test_pending_response_never_becomes_terminal_success(self):
        handler = self.handler(); handler.web_action_result = {"status": "pending", "request_id": "same-request"}
        result = web.json_web_response(handler, web.html_page("Pending", '<p role="status">等待原请求</p>', 202), "/actions/claim")
        value = json.loads(result[1])
        self.assertEqual(value["state"], "pending"); self.assertTrue(value["received"])
        self.assertNotIn("html", value); self.assertNotIn("redirect_url", value)

    def test_receipt_lookup_is_current_cookie_scoped_and_secret_minimal(self):
        calls = []
        handler = self.handler(read=lambda *args: calls.append(args) or {"status": "applied", "request_id": "same-request", "task": {"task_id": "T01"}, "token": "private-result"})
        result = web.workspace_receipt(handler, urlsplit('/workspace-receipt?request=same-request&path=/other-person'))
        value = json.loads(result[1])
        self.assertEqual(calls, [("person", "receipt", "same-request")])
        self.assertEqual(value["state"], "completed"); self.assertNotIn("private-result", result[1].decode())
        self.assertEqual(value["redirect_url"], "/tasks/T01")
        handler.server.sessions.actor = lambda *args: None
        result = web.workspace_receipt(handler, urlsplit('/workspace-receipt?request=same-request'))
        self.assertEqual(result[0], 401); self.assertEqual(len(calls), 1)

    def test_receipt_404_is_not_received_but_forbidden_is_not_downgraded(self):
        def unavailable(*args): raise ClientError("missing", 404)
        handler = self.handler(read=unavailable)
        value = json.loads(web.workspace_receipt(handler, urlsplit('/workspace-receipt?request=same-request'))[1])
        self.assertEqual(value["state"], "not_received"); self.assertFalse(value["received"])
        def forbidden(*args): raise ClientError("revoked", 403)
        handler.server.service.read = forbidden
        result = web.workspace_receipt(handler, urlsplit('/workspace-receipt?request=same-request'))
        self.assertEqual(result[0], 403)
        self.assertEqual(json.loads(result[1])["state"], "rejected")

    def test_supersedes_is_transport_metadata_before_strict_controller_fields(self):
        handler = self.handler(); handler.server.is_round = False
        body = {"request_id": "same-request", "supersedes_request_id": "old-request", "value": "retained"}
        handler.request_body = lambda *args: urlencode(body).encode()
        result = web.parse_form(handler, 4096, 2)
        self.assertEqual(result, {"request_id": "same-request", "value": "retained"})
        self.assertEqual(handler.web_supersedes_request_id, "old-request")

    def test_schema5_claim_uses_selected_context_without_changing_scope(self):
        handler = self.handler(read=lambda *args: {"execution_protocol": 5})
        fields = {"request_id": "same-request", "task_id": "T01", "version": "2", "scope_version": "1", "context_ref": "ctx-choice:3"}
        with patch("pool.web.parse_form", return_value=dict(fields)), patch("pool.round_web.current_actor", return_value="person"):
            result = web.action_body(handler, "claim")
        self.assertEqual(result["execution_protocol"], 5)
        self.assertEqual((result["context_id"], result["context_version"]), ("ctx-choice", 3))
        self.assertEqual(result["scope_version"], 1)

    def test_submit_action_supplies_fresh_session_verifier_after_recovery(self):
        handler = self.handler(); current = ["person"]; seen = []
        handler.server.sessions.actor = lambda *args: current[0]
        def submit(actor, action, rid, body, *, authorize):
            current[0] = None
            seen.append(authorize())
            if authorize() != actor: raise ClientError("session changed during recovery", 401)
            self.fail("revoked session reached new write")
        handler.server.service.submit = submit
        with patch("pool.web.same_origin", return_value=True), patch("pool.web.action_body", return_value={"request_id": "same-request"}):
            result = web.submit_action(handler, "person", "claim")
        self.assertEqual(result[0], 401); self.assertEqual(seen, [None])
        envelope = json.loads(web.json_web_response(handler, result, "/actions/claim")[1])
        self.assertEqual(envelope["state"], "rejected")

    def test_previews_require_current_http_identity_and_allow_plain_local_fixtures(self):
        handler = self.handler()
        web.reauthenticate(handler, "person")
        handler.server.service.pinned = SimpleNamespace(authentication=("person", lambda: None, lambda: None))
        with self.assertRaises(ClientError) as caught: web.reauthenticate(handler, "person")
        self.assertEqual(caught.exception.status, 401)
        handler.server.service.pinned.authentication = ("other", lambda: "person", None)
        with self.assertRaises(ClientError): web.reauthenticate(handler, "person")

    def test_execution_forms_show_real_states_and_typed_fields(self):
        config = {key: "manual" if key == "adapter" else "unknown" for key, _ in ui.DIMENSIONS}
        config["sources"] = {key: "unknown" for key, _ in ui.DIMENSIONS}
        context = {"id": "ctx", "context_id": "ctx", "version": 1, "config": config, "can_write": True}
        data = {"schema": 5, "can_write": True, "contexts": [context], "segments": [], "actions": [], "resource_requests": [{"id": "rq", "version": 1, "state": "queued", "resources": [], "sequence": 2}],
                "grants": [{"id": "grant", "physical": "unknown", "resources": []}]}
        before = deepcopy(data)
        page = ui.render("person", "person", data, {"execution_protocol": 5}, [], [], ["manual-unverified"])
        self.assertIn("保存新配置版本", page); self.assertIn("排队等待", page); self.assertIn("物理占用未知", page)
        self.assertNotIn('<textarea name="resources"', page); self.assertNotIn('<pre', page)
        self.assertEqual(data, before)
        fields = {"request_id": "same-request", "context_id": "", "version": "0", "make_default": "no"}
        for key, _ in ui.DIMENSIONS: fields.update({key: config[key], "source-" + key: "unknown"})
        parsed = ui.body("context-save", fields)
        self.assertEqual(set(parsed["config"]), {key for key, _ in ui.DIMENSIONS} | {"sources"})
        self.assertIsNone(parsed["context_id"]); self.assertIs(parsed["make_default"], False)
        with self.assertRaises(ClientError): ui.body("context-save", {"request_id": "same-request"})
        readonly = {**data, "can_write": False, "contexts": [{**context, "can_write": False}]}
        page = ui.render("owner", "window", readonly, {"execution_protocol": 5}, [], [], ["manual-unverified"])
        self.assertNotIn('action="/actions/context-save"', page)
        self.assertNotIn('action="/actions/resource-cancel"', page)

    def test_fact_binding_and_unknown_release_are_explicit(self):
        fields = {"request_id": "same-request", "task_id": "T01", "claim_id": "c", "scope_version": "1", "epoch": "2", "action_id": "", "permit_id": "",
                  "reporter_kind": "human", "reporter_note": "verified", "kind": "stopped", "blocker_ref": "legacy-c", "evidence_note": "physical evidence", "evidence_sha256": "a" * 64}
        parsed = ui.body("execution-fact", fields)
        self.assertEqual(parsed["blocker_ids"], ["legacy-c"])
        self.assertIsNone(parsed["action_id"]); self.assertEqual(parsed["epoch"], 2)
        parsed = ui.body("execution-fact", {**fields, "kind": "unconfirmed"})
        self.assertNotIn("blocker_ids", parsed)

    def test_form_payloads_pass_actual_execution_planner(self):
        import verify_r2_execution as sample
        from pool import execution
        fixture = sample.ExecutionTests("test_default_switch_does_not_rewrite_segments_claims_or_resources")
        fixture.setUp()
        actor = sample.ASSISTANT
        action_id = fixture.prepare(); fixture.request(action_id)
        action = fixture.data["actions"][action_id]
        grant = fixture.data["grants"][action["grant_id"]]
        service = SimpleNamespace(execution_roots={}, lifecycle=SimpleNamespace(status=lambda: {"phase": "running"}))
        forms = {
            "action-start": {"action_id": action_id, "version": str(action["version"]), "grant_id": grant["id"], "generation": str(grant["generation"])},
            "resource-release": {"action_id": action_id, "grant_id": grant["id"], "generation": str(grant["generation"]), "version": str(grant["version"]), "basis": "unconfirmed", "evidence_note": "fixture only", "evidence_sha256": "a" * 64},
            "execution-fact": {"task_id": "T01", "claim_id": "ca", "scope_version": "1", "epoch": "1", "action_id": action_id, "kind": "unconfirmed", "permit_id": "", "reporter_kind": "owner", "reporter_note": "fixture only", "evidence_note": "fixture only", "evidence_sha256": "a" * 64}}
        before = deepcopy(fixture.state)
        for index, (operation, fields) in enumerate(forms.items(), 1):
            body = ui.body(operation, {"request_id": "fixture-" + str(index), **fields})
            plan = execution.plan(service, actor, operation, str(index) * 64, body, fixture.state)
            self.assertEqual(plan["round_result"]["operation"], operation)
        self.assertEqual(fixture.state, before)


if __name__ == "__main__": unittest.main()
