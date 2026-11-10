"""Targeted R2 client/operations checks using only synthetic inputs and fake APIs."""
from copy import deepcopy
from io import BytesIO
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import ssl
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


client = module("r2_client", "ops/round-client.py")
launch = module("r2_launch", "ops/launch-config.py")
backup = module("r2_backup", "ops/verify-backup.py")


class State:
    def __init__(self, root):
        self.path = root / "synthetic.credential"
        self.data = {"token": "synthetic-token", "executor_id": "e-own", "window": "CDX-0001"}
        self.saved = []
    def save(self):
        self.saved.append(deepcopy(self.data))


class API:
    def __init__(self):
        self.calls = []
        self.material = {"a/one.txt": b"one", "b/two.txt": b"two"}
        refs = {path: hashlib.sha256(raw).hexdigest() for path, raw in self.material.items()}
        self.view = {"task": {"task_id": "T1", "scope_version": 2, "version": 4, "inputs": {"new.txt": "a" * 64}},
                     "claims": [{"task_id": "T1", "claim_id": "c-own", "epoch": 8, "origin": "e-own", "L": "active",
                                 "W": {"scope": 1}, "inputs": refs, "deliveries": {}}]}
        self.features = {"api_protocol": 1, "security_schema": 5,
                         "features": {name: True for name in ("input-package", "context-save", "segment-open", "action-prepare",
                            "resource-request", "resource-cancel", "action-start", "execution-fact", "evidence-stash", "resource-release")},
                         "input_download": dict(client.DOWNLOAD_LIMITS)}
        self.bundle_error, self.bad_member, self.mutate_manifest = None, None, None
        self.model = {"default_context": {"context_id": "ctx", "version": 1},
            "contexts": [{"id": "ctx", "context_id": "ctx", "version": 1, "config": {"platform": "codex", "model": "old-model",
                "environment": "old-env", "sources": {"model": "probed"}}}],
            "segments": [{"id": "seg", "version": 2, "task_id": "T1", "claim_id": "c-own", "scope_version": 1, "epoch": 8}],
            "actions": [{"id": "act", "version": 3, "task_id": "T1", "claim_id": "c-own", "scope_version": 1, "epoch": 8,
                         "resources": [{"id": "path:x", "mode": "write", "domain": "host:fixture"}], "grant_id": "g", "permit_id": "p"}],
            "grants": [{"id": "g", "version": 4, "generation": 6, "action_id": "act"}],
            "resource_requests": [{"id": "req", "version": 2, "state": "queued"}], "legacy": []}

    def zip(self):
        manifest = {"task_id": "T1", "scope_version": 1, "claim_id": "c-own", "inputs": [
            {"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "member": "files/" + path}
            for path, raw in self.material.items()]}
        if self.mutate_manifest:
            self.mutate_manifest(manifest)
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path, raw in self.material.items():
                archive.writestr("files/" + path, b"bad" if path == self.bad_member else raw)
            archive.writestr("manifest.json", json.dumps(manifest).encode())
        buffer.seek(0)
        return buffer

    def call(self, route, token=None, body=None, **kwargs):
        self.calls.append((route, deepcopy(body), kwargs))
        if route == "features":
            return deepcopy(self.features)
        if route.startswith("tasks/"):
            return deepcopy(self.view)
        if route.startswith("execution"):
            return deepcopy(self.model)
        if route.startswith("input-package?"):
            if self.bundle_error:
                raise self.bundle_error
            return self.zip()
        if route.startswith(("artifact?", "source-file?")):
            from urllib.parse import parse_qs, urlsplit
            return self.material[parse_qs(urlsplit(route).query)["path"][0]]
        if body is not None:
            return {"status": "applied", "request_id": body["request_id"], "permit_id": "p"}
        raise AssertionError(route)


class R2ClientTests(unittest.TestCase):
    def setUp(self):
        (ROOT / ".state").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="taskpool-r2-client-", dir=ROOT / ".state" if os.name == "nt" else None)
        self.root = Path(self.temp.name)
        self.state, self.api = State(self.root), API()
    def tearDown(self):
        self.temp.cleanup()
    def args(self, **extra):
        return SimpleNamespace(task="T1", output=self.root / "downloads", inputs=True, artifact=None, sha256=None,
                               claim_id=None, **extra)

    def test_get_head_and_persistent_post_share_three_attempt_budget(self):
        api = client.Pool("http://127.0.0.1:1", None, True)
        for method, body in (("GET", None), ("HEAD", None), (None, {"request_id": "original", "files": ["frozen"]})):
            calls = []
            def operation(*args):
                calls.append(deepcopy(args))
                if len(calls) < 3:
                    raise ConnectionResetError("synthetic reset")
                return {"status": "ok"}
            with patch.object(api, "_call_once", side_effect=operation), patch.object(client.time, "sleep") as sleep:
                api.call("fixture", body=body, method=method)
            self.assertEqual(len(calls), 3)
            self.assertEqual(len(sleep.call_args_list), 2)
            if body:
                self.assertTrue(all(call[2] == body for call in calls))
        with patch.object(api, "_call_once", side_effect=ssl.SSLCertVerificationError("synthetic invalid trust")) as run, patch.object(client.time, "sleep"):
            with self.assertRaises(ssl.SSLCertVerificationError):
                api.call("fixture")
            self.assertEqual(run.call_count, 1)

    def test_tls_probe_retries_transport_only_and_pin_failure_never_retries(self):
        der = b"synthetic public certificate"
        secure = SimpleNamespace(getpeercert=lambda **kwargs: der)
        from contextlib import nullcontext
        probe = SimpleNamespace(wrap_socket=lambda *args, **kwargs: nullcontext(secure))
        pin = hashlib.sha256(der).hexdigest()
        with patch.object(client.ssl, "SSLContext", return_value=probe), patch.object(client.ssl, "create_default_context", return_value=SimpleNamespace()), \
             patch.object(client.socket, "create_connection", side_effect=[ConnectionResetError(), ssl.SSLEOFError(), nullcontext(object())]) as connect, \
             patch.object(client.time, "sleep"):
            client.Pool("https://fixture.test:443", pin)
            self.assertEqual(connect.call_count, 3)
        with patch.object(client.ssl, "SSLContext", return_value=probe), \
             patch.object(client.socket, "create_connection", return_value=nullcontext(object())) as connect, patch.object(client.time, "sleep"):
            with self.assertRaises(ValueError):
                client.Pool("https://fixture.test:443", "0" * 64)
            self.assertEqual(connect.call_count, 1)

    def test_input_bundle_uses_old_claim_scope_and_reuses_verified_local_files(self):
        result = client.download_task(self.state, self.api, self.args())
        first = self.root / "downloads/a/one.txt"
        before = first.stat().st_mtime_ns
        self.assertEqual((result["scope_version"], result["claim_id"], result["verified_files"]), (1, "c-own", 2))
        again = client.download_task(self.state, self.api, self.args())
        self.assertTrue(all(row["reused"] for row in again["files"]))
        self.assertEqual(first.stat().st_mtime_ns, before)
        self.assertTrue(any("scope_version=1" in route and "claim_id=c-own" in route for route, _, _ in self.api.calls))
        self.assertTrue(all(body is None for _, body, _ in self.api.calls))

    def test_partial_valid_files_survive_sha_failure_and_resume_same_manifest(self):
        self.api.bad_member = "b/two.txt"
        with self.assertRaises(ValueError):
            client.download_task(self.state, self.api, self.args())
        first = self.root / "downloads/a/one.txt"
        self.assertEqual(first.read_bytes(), b"one")
        self.assertFalse((self.root / "downloads/b/two.txt").exists())
        self.assertFalse(any(route.startswith("artifact?") for route, _, _ in self.api.calls))
        before = first.stat().st_mtime_ns
        self.api.bad_member = None
        value = client.download_task(self.state, self.api, self.args())
        self.assertTrue(value["files"][0]["reused"])
        self.assertEqual(first.stat().st_mtime_ns, before)

    def test_task_404_auth_sha_and_binding_errors_never_fallback(self):
        for failure in (client.RequestError(404, {"code": "task_not_found"}), client.RequestError(403, {"message": "synthetic forbidden"}),
                        ssl.SSLCertVerificationError("synthetic certificate error")):
            api = API(); api.bundle_error = failure
            with self.subTest(failure=type(failure).__name__), self.assertRaises((client.RequestError, ssl.SSLCertVerificationError)):
                client.download_task(self.state, api, self.args())
            self.assertFalse(any(route.startswith("artifact?") for route, _, _ in api.calls))
        self.api.mutate_manifest = lambda m: m.update(scope_version=2)
        with self.assertRaises(ValueError):
            client.download_task(self.state, self.api, self.args())

    def test_confirmed_legacy_or_413_fallback_stays_within_budgets(self):
        self.api.bundle_error = client.RequestError(413, {"message": "synthetic package budget"})
        value = client.download_task(self.state, self.api, self.args())
        self.assertEqual(value["mode"], "individual")
        self.api.features["input_download"]["total_bytes"] = 5
        self.api._taskpool_features = None
        with self.assertRaises((ValueError, client.DownloadBudgetError)):
            client.download_task(self.state, self.api, self.args())
        self.assertEqual((self.root / "downloads/a/one.txt").read_bytes(), b"one")
        class Legacy(API):
            def call(self, route, *args, **kwargs):
                if route == "features":
                    raise client.RequestError(404, {"message": "unknown interface"}, server_version="0.2.0")
                return super().call(route, *args, **kwargs)
        legacy = Legacy(); args = self.args(); args.output = self.root / "legacy-downloads"
        value = client.download_task(self.state, legacy, args)
        self.assertEqual(value["mode"], "individual")
        self.assertFalse(any(route.startswith("input-package?") for route, _, _ in legacy.calls))

    def test_full_task_list_requests_wire_full_only_when_service_declares_summary(self):
        calls = []
        def call(route, token=None, **kwargs):
            calls.append(route)
            if route == "features":
                return {"api_protocol": 1, "security_schema": 5, "features": {"list-summary": True}}
            if route == "identity":
                return {"identity": "e-own", "binding": {"window": "CDX-0001", "window_name": "synthetic"}, "projects": []}
            if route.startswith("task-options"):
                row = {"task_id": "T1", "title": "summary", "qualification": {"eligible": True}}
                if "full=1" in route: row["inputs"] = {"large": "original full payload"}
                return {"tasks": [row], "counts": {"visible": 1, "claimable": 1}}
            raise AssertionError(route)
        api = SimpleNamespace(call=call)
        args = SimpleNamespace(project=None, claimable=False, full=False)
        compact = client.visible_tasks(self.state, api, args)
        self.assertNotIn("inputs", compact["tasks"][0])
        self.assertEqual(calls[0], "task-options")
        calls.clear(); args.full = True
        full = client.visible_tasks(self.state, api, args)
        self.assertIn("inputs", full["tasks"][0])
        self.assertEqual(calls, ["features", "task-options?full=1"])

    def test_zip_paths_duplicates_symlinks_sizes_and_extra_members_reject(self):
        binding = {"task_id": "T1", "scope_version": 1, "claim_id": "c-own"}
        refs = [{"path": path, "sha256": hashlib.sha256(raw).hexdigest()} for path, raw in self.api.material.items()]
        for kind in ("traversal", "case-duplicate", "symlink", "size", "extra", "scope-bool"):
            api = API()
            if kind == "size": api.mutate_manifest = lambda m: m["inputs"][0].update(bytes=4)
            if kind == "scope-bool": api.mutate_manifest = lambda m: m.update(scope_version=True)
            stream = api.zip()
            if kind in {"traversal", "case-duplicate", "symlink", "extra"}:
                with zipfile.ZipFile(stream, "a") as archive:
                    member = "../escape" if kind == "traversal" else "FILES/A/ONE.TXT" if kind == "case-duplicate" else "extra"
                    if kind == "symlink":
                        info = zipfile.ZipInfo(member); info.create_system = 3; info.external_attr = (stat.S_IFLNK | 0o777) << 16
                        archive.writestr(info, b"target")
                    else: archive.writestr(member, b"bad")
                stream.seek(0)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                client.validate_input_zip(stream, binding, refs, client.DOWNLOAD_LIMITS)

    def test_schema5_claim_explicit_protocol_and_context(self):
        client.claim_task(self.state, self.api, SimpleNamespace(task="T1", context_id="ctx", context_version=1))
        body = next(body for route, body, _ in self.api.calls if route == "claim")
        self.assertEqual((body["execution_protocol"], body["context_id"], body["context_version"]), (5, "ctx", 1))

    def test_context_source_is_reported_and_action_start_is_permit_only(self):
        args = SimpleNamespace(action="context", operation="save", context_id=None, platform="claude", adapter=None, model="new-model",
                               reasoning=None, tools_version=None, permissions_version=None, environment=None, make_default=True,
                               supersedes_request_id=None)
        client.execution_command(self.state, self.api, args)
        body = next(body for route, body, _ in self.api.calls if route == "context-save")
        self.assertEqual(body["config"]["model"], "new-model")
        self.assertNotIn("probed", body["config"]["sources"].values())
        with patch.object(client.subprocess, "Popen", side_effect=AssertionError("must not spawn")):
            value = client.execution_command(self.state, self.api, SimpleNamespace(action="action", operation="start", action_id="act", grant_id=None))
        self.assertEqual(value["permit_id"], "p")
        self.assertIn("permit_id", self.state.data["last_write"]["result"])

    def test_execution_cli_payloads_match_real_server_plans_and_ledger_engine(self):
        from pool import execution
        import 协作执行 as engine
        import 协作升级 as rules
        from verify_r2_execution import ExecutionTests, ASSISTANT
        fixture = ExecutionTests(); fixture.setUp()
        ledger = fixture.state
        owner = self
        service = SimpleNamespace(execution_roots={}, lifecycle=SimpleNamespace(status=lambda: {"phase": "running"}))
        class Bridge:
            def call(self, route, token=None, body=None, **kwargs):
                if route == "features": return execution.features(ledger)
                if route.startswith("execution"):
                    from urllib.parse import parse_qs, urlsplit
                    query = {key: value[0] for key, value in parse_qs(urlsplit(route).query).items()}
                    return execution.read(ledger, ASSISTANT, query)
                if route.startswith("tasks/"):
                    return {"task": deepcopy(ledger["tasks"]["T01"]), "claims": deepcopy(list(ledger["claims"].values()))}
                key = hashlib.sha256(body["request_id"].encode()).hexdigest()
                plan = execution.plan(service, ASSISTANT, route, key, body, ledger)
                for step in plan["steps"]:
                    payload = {**step["payload"], "_audit": {"actor": ASSISTANT, "credential_version": rules.identity(ledger, ASSISTANT)["credential"]}}
                    engine.action(ledger, {"payload": payload, "event_id": "event-" + key}, {"now": __import__("time").time(), "phase": "running"})
                return {"status": "applied", "request_id": body["request_id"], **plan["round_result"]}
        api = Bridge(); self.state.data["executor_id"] = ASSISTANT
        def call(action, operation=None, **values):
            return client.execution_command(self.state, api, SimpleNamespace(action=action, operation=operation, **values))
        context = call("context", "save", context_id=None, platform=None, adapter="manual", model="reported-model", reasoning=None,
                       tools_version=None, permissions_version=None, environment=None, make_default=True)["context"]
        segment = call("segment", "open", task="T01", claim_id="ca", context_id=context["context_id"], context_version=context["version"])["segment"]
        action = call("action", "prepare", segment_id=segment["id"], description="synthetic manual work", domain="manual-unverified",
                      read=None, write=["path:work/item"], exclusive=None, adapter_id="manual")["action"]
        requested = call("resource", "request", action_id=action["id"])
        self.assertEqual(requested["resource_request"]["state"], "granted")
        started = call("action", "start", action_id=action["id"], grant_id=None)
        self.assertEqual(started["action"]["state"], "start-authorized")
        waiting_action = call("action", "prepare", segment_id=segment["id"], description="separate conflicting action", domain="manual-unverified",
                              read=None, write=["path:work/item"], exclusive=None, adapter_id="manual")["action"]
        waiting = call("resource", "request", action_id=waiting_action["id"])["resource_request"]
        self.assertEqual(waiting["state"], "queued")
        cancelled = call("resource", "cancel", resource_request_id=waiting["id"])
        self.assertEqual(cancelled["resource_request"]["state"], "cancelled")
        call("fact", task="T01", claim_id="ca", scope_version=None, epoch=None, action_id=action["id"],
             kind="finished", note="synthetic actual result statement", evidence_sha256=None, permit_id=None, reporter_kind="owner")
        output = self.root / "evidence.txt"; output.write_bytes(b"synthetic isolated evidence")
        stashed = call("stash", task="T01", claim_id="ca", scope_version=None, epoch=None, action_id=action["id"],
                       note="preserved result", reporter_kind="owner", file=[output])
        self.assertEqual(stashed["stash"]["state"], "pending-review")
        released = call("resource", "release", action_id=action["id"], grant_id=None, basis="unconfirmed", note="physical state not proven",
                        evidence_sha256=None)
        self.assertEqual(released["grant"]["physical"], "unknown")

    def test_control_and_input_stream_budgets_do_not_expand_upload_budget(self):
        class Reply:
            status = 200
            def __init__(self, raw, kind): self.source, self.kind = BytesIO(raw), kind
            def getheader(self, name, default=None): return self.kind if name == "Content-Type" else default
            def read(self, amount): return self.source.read(amount)
        reply = Reply(b"x" * 20, "application/zip")
        connection = SimpleNamespace(connect=lambda: None, request=lambda *args: None, getresponse=lambda: reply, close=lambda: None)
        api = client.Pool("http://127.0.0.1:1", None, True)
        with patch.object(client, "HTTPConnection", return_value=connection):
            with self.assertRaises(client.DownloadBudgetError) as error:
                api.call("input-package?task_id=T1", response_format="file", response_limit=10)
        self.assertEqual(error.exception.budget, "zip_bytes")
        reply = Reply(b'{"synthetic":"too large"}', "application/json")
        api._taskpool_control_limit = 5
        with patch.object(client, "HTTPConnection", return_value=connection), self.assertRaises(ValueError):
            api.call("features", response_limit=1024)
        self.assertEqual(client.MAX_TRANSFER, 8 * 1024 * 1024)

    def test_fact_uses_historical_binding_and_stash_freezes_file_bytes(self):
        args = SimpleNamespace(action="fact", operation=None, task="T1", claim_id="old", scope_version=1, epoch=2, action_id=None,
                               note="actual completion statement", kind="finished", permit_id=None, reporter_kind="owner", evidence_sha256=None)
        client.execution_command(self.state, self.api, args)
        body = next(body for route, body, _ in self.api.calls if route == "execution-fact")
        self.assertEqual((body["scope_version"], body["epoch"], body["action_id"]), (1, 2, None))
        path = self.root / "result.txt"; path.write_bytes(b"synthetic result")
        args = SimpleNamespace(action="stash", operation=None, task="T1", claim_id="old", scope_version=1, epoch=2, action_id=None,
                               note="saved evidence", reporter_kind="owner", file=[path])
        client.execution_command(self.state, self.api, args)
        body = next(body for route, body, _ in self.api.calls if route == "evidence-stash")
        self.assertEqual(body["files"][0]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertFalse(any(route in {"claim", "deliver-files"} for route, _, _ in self.api.calls))

    def test_state_replace_failure_preserves_original_credential_and_never_sends(self):
        state = client.State(self.root / "private/window.credential")
        state.data = {"token": "synthetic-private-original"}; state.save()
        original = state.path.read_bytes()
        with patch.object(client.os, "replace", side_effect=OSError("synthetic persistence failure")):
            with self.assertRaises(OSError):
                client.durable_write(state, self.api, {"name": "test", "parameters": {}}, "execution-fact", lambda: {"payload": "original"})
        self.assertEqual(state.path.read_bytes(), original)
        self.assertEqual(self.api.calls, [])


class OpsTests(unittest.TestCase):
    def test_launch_config_preserves_host_alias_tls_user_ports_and_backup(self):
        record = {"config": {"Cmd": ["serve", "--lan-name", "taskpool.test", "--lan-alias", "taskpool-host", "--tls-key", "/app/.state/tls/key.pem"],
                             "User": "10001:10001", "Env": ["PRIVATE_VALUE=synthetic"], "Labels": {"project": "intranet-task-pool"}},
                  "host": {"PortBindings": {"18443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18765"}]},
                           "RestartPolicy": {"Name": "unless-stopped"}, "ReadonlyRootfs": True},
                  "mounts": [{"Type": "volume", "Name": "original-volume", "Destination": "/app/.state", "RW": True, "Options": []}]}
        args = launch.launch_arguments(record, "sha256:" + "a" * 64, "fixture", "/private-backup", "test", "b" * 64)
        for value in ("taskpool-host", "10001:10001", "127.0.0.1:18765:18443/tcp", "original-volume:/app/.state:rw", "/private-backup:/backup:rw"):
            self.assertIn(value, args)
        self.assertIn("TASKPOOL_LAUNCH_CONFIG_SHA256=" + "b" * 64, args)

    def test_backup_requires_tls_configuration_and_all_object_hashes(self):
        with tempfile.TemporaryDirectory(prefix="taskpool-r2-backup-", dir=ROOT / ".state" if os.name == "nt" else None) as temporary:
            root = Path(temporary)
            if os.name == "posix": os.chmod(root, 0o700)
            (root / "objects").mkdir()
            files = {}
            for name in ("service-config.json", "repo.json", "http-journal.sqlite3", "credentials.json", "ledger/000000000001.json", "tls/key.pem", "tls/cert-v2.pem"):
                raw = ("synthetic " + name).encode(); sha = hashlib.sha256(raw).hexdigest()
                obj = root / "objects" / sha; obj.write_bytes(raw)
                if os.name == "posix": os.chmod(obj, 0o600)
                files[name] = {"sha256": sha, "bytes": len(raw)}
            manifest = {"tag": "fixture", "ledger_head": 1, "ledger_sha256": "a" * 64,
                        "tls_backup": {"status": "complete", "included": True},
                        "configuration_backup": {"status": "complete", "file": "service-config.json", "sha256": files["service-config.json"]["sha256"]},
                        "files": {key: row for key, row in files.items() if not key.startswith("tls/")},
                        "service_files": {key: row for key, row in files.items() if key.startswith("tls/")}}
            path = root / "fixture.json"; path.write_text(json.dumps(manifest))
            result = backup.verify(root, "fixture")
            self.assertEqual(result["snapshot"], "fixture.json")
            self.assertNotIn("sha256", json.dumps(result))
            manifest["tls_backup"]["status"] = "absent"; path.write_text(json.dumps(manifest))
            with self.assertRaises(ValueError): backup.verify(root, "fixture")
            manifest["tls_backup"]["status"] = "complete"; path.write_text(json.dumps(manifest))
            (root / "objects" / files["tls/key.pem"]["sha256"]).write_bytes(b"corrupt")
            with self.assertRaises(ValueError): backup.verify(root, "fixture")

    @unittest.skipUnless(os.name == "posix", "isolated shell rehearsal uses a fake Podman executable only")
    def test_upgrade_rehearsal_preserves_thc_and_never_restarts_old_after_migration_attempt(self):
        with tempfile.TemporaryDirectory(prefix="taskpool-fake-upgrade-") as temporary:
            root = Path(temporary); binary = root / "bin"; binary.mkdir()
            image = "sha256:" + "a" * 64
            verification = root / "verified.json"; verification.write_text(json.dumps({"image": image, "verified": True}))
            original = {"Image": "sha256:" + "b" * 64, "Config": {"Cmd": ["serve", "--port", "18443", "--lan-name", "taskpool.test",
                         "--lan-alias", "taskpool-host", "--tls-cert", "/app/.state/tls/cert-v2.pem", "--tls-key", "/app/.state/tls/key.pem"],
                         "User": "10001:10001", "Labels": {"project": "intranet-task-pool"}, "Env": []},
                        "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}, "PortBindings": {
                         "18443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18765"}]}},
                        "Mounts": [{"Type": "volume", "Name": "original-volume", "Destination": "/app/.state", "RW": True, "Options": []}]}
            config = root / "original.json"; config.write_text(json.dumps(original))
            fake = binary / "podman"
            fake.write_text("#!" + __import__("sys").executable + "\n" + r'''
import hashlib,json,os,pathlib,sys
a=sys.argv[1:]
with open(os.environ['FAKE_LOG'],'a') as f:f.write(json.dumps(a)+'\n')
if a[:2]==['container','exists']:sys.exit(1)
if a[0]=='inspect':
    if '--format' not in a:print('['+pathlib.Path(os.environ['FAKE_CONFIG']).read_text()+']')
    else:
        form=a[a.index('--format')+1]
        print('intranet-task-pool running' if '.State.Status' in form else 'original-volume' if '.Mounts' in form else 'sha256:'+'b'*64)
elif a[:2]==['image','inspect']:print('sha256:'+'a'*64)
elif a[0]=='run' and 'security-migrate' in a:
    sys.exit(7 if os.environ.get('FAKE_FAIL')=='1' else 0)
elif a[0]=='run' and '--entrypoint' in a and 'backup-store.py' in ' '.join(a):
    if '--seed' in a:sys.exit(0)
    folder=pathlib.Path(next(v.rsplit(':/backup',1)[0] for v in a if v.endswith(':/backup')))
    tag=a[a.index('--tag')+1];objects=folder/'objects';objects.mkdir(exist_ok=True)
    entries={}
    for name in ['repo.json','http-journal.sqlite3','credentials.json','ledger/000000000001.json','tls/key.pem','tls/cert-v2.pem']:
        raw=('synthetic '+name).encode();sha=hashlib.sha256(raw).hexdigest();p=objects/sha;p.write_bytes(raw);p.chmod(0o600)
        entries[name]={'sha256':sha,'bytes':len(raw)}
    value={'tag':tag,'ledger_head':1,'ledger_sha256':'a'*64,'files':{k:v for k,v in entries.items() if not k.startswith('tls/')},
           'service_files':{k:v for k,v in entries.items() if k.startswith('tls/')},'tls_backup':{'status':'complete','included':True}}
    (folder/(tag+'.json')).write_text(json.dumps(value))
elif a[0]=='run':print('synthetic-candidate-container')
''')
            fake.chmod(0o755)
            (binary / "id").write_text("#!/bin/sh\nprintf '0\\n'\n"); (binary / "id").chmod(0o755)
            (binary / "chown").write_text("#!/bin/sh\nexit 0\n"); (binary / "chown").chmod(0o755)
            for fail in (False, True):
                archive = root / ("backup-fail" if fail else "backup-ok"); archive.mkdir(mode=0o700)
                log = root / ("fail.log" if fail else "ok.log")
                env = {**os.environ, "PATH": str(binary) + os.pathsep + os.environ["PATH"], "FAKE_LOG": str(log),
                       "FAKE_CONFIG": str(config), "FAKE_FAIL": "1" if fail else "0"}
                result = subprocess.run(["sh", str(ROOT / "ops/safe-local-upgrade.sh"), image, "fixture", str(archive), str(verification),
                                         "--legacy-v020"], env=env, capture_output=True, text=True)
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                self.assertEqual(result.returncode, 1 if fail else 0, result.stderr)
                self.assertFalse(any(call and call[0] == "start" for call in calls))
                self.assertTrue(any("security-migrate" in call for call in calls))
                if not fail:
                    started = next(call for call in calls if call and call[0] == "run" and "--name" in call)
                    self.assertIn("taskpool-host", started)
                    self.assertIn("10001:10001", started)
                    self.assertIn("127.0.0.1:18765:18443/tcp", started)


class GlobalCorrectionTests(unittest.TestCase):
    def test_explicit_pending_correction_preserves_original_frozen_input(self):
        state=State(Path('.'))
        original={'operation':{'name':'old','parameters':{}},'route':'old','body':{'request_id':'prior','file':'unchanged-bytes'}}
        state.data['pending_write']=deepcopy(original)
        state.supersedes_request_id='prior'
        api=SimpleNamespace(call=lambda route,token,body:{'status':'applied','request_id':body['request_id']})
        client.durable_write(state,api,client.operation_key('new',{}),'new',lambda:{'fixed':True})
        self.assertEqual(state.data['superseded_writes']['prior'],original)

    def test_correction_is_bound_before_any_write_and_original_id_is_preserved(self):
        state=State(Path('.'))
        state.supersedes_request_id='previous-request'
        seen=[]
        def call(route,token,body):
            seen.append(deepcopy(body))
            return {'status':'applied','request_id':body['request_id']}
        client.durable_write(state,SimpleNamespace(call=call),client.operation_key('declare',{'capability':'sample'}),
                             'capability-save',lambda:{'capability':'sample'})
        self.assertEqual(seen[0]['supersedes_request_id'],'previous-request')
        self.assertNotEqual(seen[0]['request_id'],'previous-request')
        self.assertEqual(state.saved[0]['pending_write']['body'],seen[0])

if __name__ == "__main__":
    unittest.main(verbosity=2)
