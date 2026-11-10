"""Six fake-API identity checks: no registration, window rename or UI access occurs."""
from copy import deepcopy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("identity_client", ROOT / "ops" / "round-client.py")
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


class MemoryState:
    def __init__(self):
        self.path = Path("synthetic-window.credential")
        self.saved = []
        self.data = {"token": "synthetic-existing-token", "executor_id": "e-fixture", "window": "CODEX-0057",
                     "source": {"platform": "codex", "device": "keep-device", "session": "stale-local-session",
                                "model": "stale-local-model", "environment": "stale-local-environment"}}

    def save(self):
        self.saved.append(deepcopy(self.data))


class FakeAPI:
    def __init__(self):
        self.calls, self.receipts, self.applied = [], {}, 0
        self.identity_error, self.options_error, self.drop_sync_once = None, None, False
        self.profile = {"identity": "e-fixture", "binding": {"window_name": "登记的窗口名称", "window": "CODEX-0057",
                         "owner": "fixture-owner", "platform": "codex", "session": "registered-session",
                         "model": "registered-model", "environment": "registered-environment"},
                        "projects": [{"id": "fixture-project", "title": "fixture project"}]}
        self.options = {"tasks": [{"task_id": "T10", "title": "fixture", "inputs": {"large": "x" * 10000},
                                   "qualification": {"eligible": True, "missing": []}}],
                        "counts": {"visible": 1, "claimable": 1}, "capability_hints": []}

    def call(self, route, token=None, body=None, **kwargs):
        self.calls.append((route, token, deepcopy(body)))
        if route == "features":
            return {"api_protocol": 1, "security_schema": 3, "features": {"list-summary": False}}
        if route == "identity":
            if self.identity_error:
                raise self.identity_error
            return deepcopy(self.profile)
        if route == "task-options":
            if self.options_error:
                raise self.options_error
            return deepcopy(self.options)
        if route == "ai-activate":
            return {"executor_id": "e-fixture", "window": "CODEX-0057", "expires": 1999999999}
        if route == "executor-sync":
            request = body["request_id"]
            if request not in self.receipts:
                self.applied += 1
                self.profile["binding"].update({key: value for key, value in body.items() if key != "request_id"})
                self.receipts[request] = {"status": "applied", "request_id": request}
            if self.drop_sync_once:
                self.drop_sync_once = False
                raise ConnectionResetError("synthetic reply lost after apply")
            return deepcopy(self.receipts[request])
        raise AssertionError("Unexpected route: " + route)


class IdentityTests(unittest.TestCase):
    def test_whoami_reads_registered_identity_without_saving_or_writing(self):
        state, api = MemoryState(), FakeAPI()
        before = deepcopy(state.data)
        value = client.whoami(state, api)
        self.assertEqual(value, {"window_name": "登记的窗口名称", "window": "CODEX-0057", "executor_id": "e-fixture",
                                 "owner": "fixture-owner", "projects": api.profile["projects"],
                                 "name_source": "platform-registration", "chat_title_auto_detected": False})
        self.assertEqual(api.calls, [("identity", "synthetic-existing-token", None)])
        self.assertEqual(state.data, before)
        self.assertEqual(state.saved, [])

    def test_rename_changes_only_name_and_preserves_current_remote_metadata(self):
        state, api = MemoryState(), FakeAPI()
        before = deepcopy(api.profile)
        value = client.rename(state, api, "明确指定的新名称")
        body = next(body for route, _, body in api.calls if route == "executor-sync")
        self.assertEqual(set(body), {"request_id", "session", "model", "environment", "window_name"})
        for key in ("session", "model", "environment"):
            self.assertEqual(body[key], before["binding"][key])
        expected = deepcopy(before)
        expected["binding"]["window_name"] = "明确指定的新名称"
        self.assertEqual(api.profile, expected)
        self.assertEqual(state.data["source"]["device"], "keep-device")
        self.assertEqual(state.data["token"], "synthetic-existing-token")
        self.assertEqual(value["self"]["owner"], "fixture-owner")
        self.assertEqual(value["self"]["window_name"], "明确指定的新名称")
        self.assertTrue(all(route in {"identity", "executor-sync"} for route, _, _ in api.calls))

    def test_rename_lost_reply_reuses_frozen_body_and_request_id(self):
        state, api = MemoryState(), FakeAPI()
        api.drop_sync_once = True
        with self.assertRaises(ConnectionResetError):
            client.rename(state, api, "原请求名称")
        original = deepcopy(state.data["pending_write"])
        api.profile["binding"]["model"] = "later-external-model-change"
        client.rename(state, api, "原请求名称")
        writes = [body for route, _, body in api.calls if route == "executor-sync"]
        self.assertEqual(writes, [original["body"], original["body"]])
        self.assertEqual(api.applied, 1)
        self.assertNotIn("pending_write", state.data)
        self.assertEqual(api.profile["binding"]["model"], "later-external-model-change")

    def test_identity_and_rename_do_not_inspect_chat_ui_or_replace_reported_title(self):
        state, api = MemoryState(), FakeAPI()
        with patch.object(client, "source", side_effect=AssertionError("host UI/source detection is forbidden")), \
             patch.object(client.subprocess, "run", side_effect=AssertionError("no process inspection")), \
             patch.object(client.subprocess, "Popen", side_effect=AssertionError("no UI process")), \
             patch.object(client.socket, "gethostname", side_effect=AssertionError("no device inference")):
            self.assertEqual(client.whoami(state, api)["window_name"], "登记的窗口名称")
            value = client.rename(state, api, "用户明确输入的名称")
        self.assertEqual(value["self"]["window_name"], "用户明确输入的名称")
        self.assertFalse(value["self"]["chat_title_auto_detected"])

    def test_successful_activation_remains_active_when_optional_identity_read_fails(self):
        state, api = MemoryState(), FakeAPI()
        state.data.update(registration_id="synthetic-registration", request={"request_id": "original-enroll"})
        api.identity_error = OSError("synthetic identity temporarily unavailable")
        api.options_error = client.HTTPException("synthetic optional task overview unavailable")
        value = client.finish_activation(state, api)
        self.assertEqual(value["status"], "active")
        self.assertIsNone(value["self"])
        self.assertIn("whoami", value["next_commands"])
        self.assertIn("whoami", value["identity_notice"])
        self.assertNotIn("registration_id", state.data)
        self.assertNotIn("request", state.data)
        self.assertEqual(state.data["token"], "synthetic-existing-token")
        with patch.object(client, "endpoint", return_value=api):
            repeated = client.enroll(state, SimpleNamespace(invite=None, invite_url=None))
        self.assertEqual(repeated["status"], "active")
        self.assertEqual([route for route, _, _ in api.calls].count("ai-activate"), 1)
        self.assertNotIn("ai-prepare", [route for route, _, _ in api.calls])

    def test_compact_tasks_adds_small_self_and_full_keeps_original_payload(self):
        state, api = MemoryState(), FakeAPI()
        compact = client.visible_tasks(state, api, SimpleNamespace(project=None, claimable=False, full=False))
        self.assertEqual(compact["self"], {"window_name": "登记的窗口名称", "window": "CODEX-0057", "executor_id": "e-fixture"})
        self.assertNotIn("inputs", compact["tasks"][0])
        self.assertNotIn("owner", compact["self"])
        api.calls.clear()
        full = client.visible_tasks(state, api, SimpleNamespace(project=None, claimable=False, full=True))
        self.assertNotIn("self", full)
        self.assertEqual(full["tasks"][0]["inputs"], api.options["tasks"][0]["inputs"])
        self.assertEqual([route for route, _, _ in api.calls], ["features", "task-options"])
        api.identity_error = OSError("synthetic identity read failed")
        compact = client.visible_tasks(state, api, SimpleNamespace(project=None, claimable=False, full=False))
        self.assertIsNone(compact["self"])
        self.assertIn("whoami", compact["self_notice"])
        self.assertEqual(len(compact["tasks"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
