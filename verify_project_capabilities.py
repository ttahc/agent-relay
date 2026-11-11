"""Real HTTP and ledger regression for versioned project capabilities on a disposable store."""
from contextlib import contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

from pool import project_capabilities as catalog
from pool.storage import LedgerBackend
from 协作安全 import check
from 协作存储 import Rejected
from verify import ROOT, call, command, server, sha
from verify_round import Browser, Client, activate, bind, browser_admin_api, invitation, setup
from verify_support import scratch
from verify_upgrade import PROJECT, capability, control, register, source


@contextmanager
def hermes_api(key):
    class Fixture(BaseHTTPRequestHandler):
        def do_GET(self):
            assert self.path == "/v1/capabilities"
            assert self.headers.get("Authorization") == "Bearer " + key
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"features":{},"endpoints":{}}')

        def log_message(self, *_):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Fixture) as api:
        thread = threading.Thread(target=api.serve_forever, daemon=True)
        thread.start()
        try:
            yield api.server_address[1]
        finally:
            api.shutdown()
            thread.join()


def local_admin(project, operation, request, **fields):
    config = project / "admin-config.json"
    config.write_text(json.dumps(fields), encoding="utf-8")
    try:
        run = subprocess.run([sys.executable, "-B", "-X", "utf8", str(project / "taskpool.py"), operation,
                              "--config", str(config), "--request-id", request], capture_output=True, text=True, encoding="utf-8")
        assert run.returncode == 0, run.stderr + run.stdout
        return json.loads(run.stdout)
    finally:
        config.unlink()


def client_command(project, script, state, *args):
    run = subprocess.run([sys.executable, "-B", "-X", "utf8", str(project / "ops" / script),
                          "--state", str(state), *args], capture_output=True, text=True, encoding="utf-8")
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


def prober(project, state, *args):
    return client_command(project, "capability-prober.py", state, *args)


def admin_session(project, url, password):
    browser = Browser(url)
    browser.login("admin", password)
    browser.send("/")
    return browser, browser_admin_api(project, browser)


def check_runtime_permissions(project):
    if os.name != "posix" or os.geteuid() != 0:
        return
    import pwd
    try:
        account = pwd.getpwnam("nobody")
    except KeyError:
        return
    from importlib.util import module_from_spec, spec_from_file_location
    spec = spec_from_file_location("prober_permissions", project / "ops/capability-prober.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix="pcap-permissions-", dir="/var/tmp") as directory:
        config = {"scratch": directory, "environment_label": "fixture-env", "runtime_user": account.pw_name}
        try:
            module.workspace(config)
        except (OSError, ValueError):
            pass
        else:
            raise AssertionError("A root verifier must not attest write access denied to the runtime account")
        os.chown(directory, account.pw_uid, account.pw_gid)
        assert module.workspace(config) == ("rw", {"environment": "fixture-env"})
        assert not list(Path(directory).iterdir())
    print("PASS probe uses the actual POSIX runtime account")


def exercise(project):
    check_runtime_permissions(project)
    _, _, password = setup(project)
    command(project, "security-migrate", "--target", "5", "--request-id", "catalog-security")
    with server(project) as (_, url):
        browser, admin = admin_session(project, url, password)
        bind(admin, "reviewer", "receiver")
        admin.post("project-save", project_id="different-project", name="Other fixture project", version=0)
        invite = invitation(browser)
        data = {"request_id": "catalog-enrollment", "invite_id": invite["id"], "code": invite["code"],
                "recovery": secrets.token_urlsafe(32), "source": source("fixture-hermes", "external")}
        status, issued = call(url + "/ai-prepare", data=data)
        assert status == 200
        node = activate(url, issued)
        name = node.get("identity")["identity"]

    local_admin(project, "environment-save", "catalog-environment", environment_id="fixture-hermes-env",
                version=0, kind="local", label="Fixture Hermes", executors=[name], active=True)
    # Bind the probe credential to a private fixture on this host.
    secret = secrets.token_urlsafe(32)
    secret_file = project / "hermes-fixture-key"
    with secret_file.open("x", encoding="utf-8") as file:
        secret_file.chmod(0o600)
        file.write(secret)
    state_path = project / "private-probe" / "probe.credential"
    git = shutil.which("git")
    assert git, "Git is required to verify the Git-version probe"
    git_version = subprocess.check_output([git, "--version"], text=True).strip().removeprefix("git version ")
    workspace = project / "probe-scratch"
    workspace.mkdir()
    with hermes_api(secret) as port:
        with server(project) as (_, url):
            registration = prober(project, state_path, "init", "--url", url.removesuffix("/v1"),
                                  "--verifier-id", "fixture", "--environment-id", "fixture-hermes-env",
                                  "--environment-label", "fixture-env", "--hermes-port", str(port),
                                  "--hermes-key-file", str(secret_file), "--git", git, "--scratch", str(workspace))
        local_admin(project, "capability-verifier-save", "catalog-verifier", **registration, version=0,
                    projects=[PROJECT], templates=["hermes-api", "git-version", "workspace-rw"], level="verified", active=True)
        # Load the current server address into the private client configuration after restart.
        from importlib.util import module_from_spec, spec_from_file_location
        spec = spec_from_file_location("fixture_client", project / "ops/round-client.py")
        module = module_from_spec(spec)
        spec.loader.exec_module(module)
        with server(project) as (_, url):
            state = module.State(state_path)
            with state.exclusive():
                state.data["url"] = url.removesuffix("/v1")
                state.save()
                probe_token = state.data["token"]
            node = Client(url, issued["token"])
            browser, admin = admin_session(project, url, password)
            scope = dict(platform="external", adapter="manual", model="fixture-model", reasoning="unknown",
                         tools_version=git_version, permissions_version="fixture-permissions", environment="fixture-env")
            config = node.post("context-save", context_id="fixture-profile", version=0, environment_id="fixture-hermes-env",
                               config={**scope, "sources": {k: "reported" for k in scope}}, make_default=True)
            assert config["context"]["version"] == 1
            capability(node, name)
            legacy = register(admin, "reviewer")
            assert "definition_version" not in node.get("tasks/" + legacy["task_id"])["task"]["contract"]["requirements"][0]
            save = {"project_id": PROJECT, "capability": "hermes-api", "label": "Hermes API", "version": 0,
                    "kind": "environment", "value": "available", "evidence": "verified", "dimensions": "environment",
                    "verified_dimensions": "environment", "probe": "hermes-api", "active": "yes"}
            admin.post("project-capability-save", **save)
            status, _, html = browser.send(f"/projects/{PROJECT}?tab=capabilities")
            assert status == 200 and b"Hermes API" in html
            status, _, html = browser.send(f"/tasks/new?project={PROJECT}")
            assert status == 200 and b'value="catalog:1"' in html
            form = {"quick": "1", "project_id": PROJECT, "receiver": "reviewer", "dispatch_mode": "open",
                    "request_id": "catalog-task", "title": "Probe-gated fixture", "brief": "Fixture only",
                    "criteria": "ready", "completion_policy": "review-required", "cap-hermes-api": "catalog:1"}
            status, headers, page = browser.send("/actions/register", "POST", form)
            assert status == 303, page.decode()[-700:]
            tid = headers["Location"].rsplit("/", 1)[-1]
            task = node.get("tasks/" + tid)["task"]
            control(admin, "task-publish", task)
            task = node.get("tasks/" + tid)["task"]
            assert task["contract"]["requirements"][0]["definition_version"] == 1
            claim = {k: task[k] for k in ("task_id", "version", "scope_version")}
            claim.update(execution_protocol=5, context_id="fixture-profile", context_version=1)
            node.post("claim", 409, **claim)
            request = {"project_id": PROJECT, "capability": "hermes-api", "definition_version": 1,
                       "context_id": "fixture-profile", "context_version": 1, "method": "probe"}
            node.post("capability-request", 409, **{**request, "project_id": "different-project"})
            assert call(url + "/project-capability-catalog?project=different-project", node.token)[0] == 404
            node_state = state_path.with_name("node.credential")
            private_node = module.State(node_state)
            with private_node.exclusive():
                private_node.data = {"url": url.removesuffix("/v1"), "token": node.token, "executor_id": name}
                private_node.save()
            job = client_command(project, "round-client.py", node_state, "--allow-loopback", "capabilities", "request",
                                 "--project", PROJECT, "--capability", "hermes-api", "--definition-version", "1",
                                 "--context-id", "fixture-profile", "--context-version", "1", "--method", "probe")["verification_id"]
            assert call(url + "/capability-probe-claim", node.token, {"request_id": "forged"})[0] == 401
            assert call(url + "/tasks", probe_token)[0] == 401
            result = prober(project, state_path, "once", "--allow-loopback")
            assert result["verification_id"] == job and result["verification_state"] == "approved"
            for template, value, dim in (("git-version", git_version, "tools_version"), ("workspace-rw", "rw", "environment")):
                admin.post("project-capability-save", **{**save, "label": template, "capability": template,
                           "probe": template, "value": value, "dimensions": dim, "verified_dimensions": dim})
                other_job = node.post("capability-request", **{**request, "capability": template})["verification_id"]
                measured = prober(project, state_path, "once", "--allow-loopback")
                assert measured["verification_id"] == other_job and measured["verification_state"] == "approved"
            assert not list(workspace.iterdir())
            admin.post("project-capability-save", **{**save, "label": "Document review", "capability": "catalog-review",
                       "kind": "skill", "value": "ok", "probe": "", "dimensions": "platform", "verified_dimensions": "platform"})
            manual = node.post("capability-request", **{**request, "capability": "catalog-review", "method": "manual"},
                               value="ok", evidence={"note": "Sample reviewed", "sha256": "2" * 64},
                               expires=int(time.time()) + 3600)["verification_id"]
            admin.post("capability-resolve", verification_id=manual, version=1, decision="approve", level="verified",
                       reason="Reviewed the sample")
            rows = node.get("capability-requests")
            assert next(r for r in rows if r["id"] == manual)["state"] == "approved"
            evidence = next(x for x in node.get("capabilities")["capabilities"] if x["id"] == "hermes-api")
            assert evidence["level"] == "verified" and evidence["applicability"]["verified_dimensions"] == ["environment"]
            assert prober(project, state_path, "once", "--allow-loopback") == {"status": "idle"}
            attempt_job = node.post("capability-request", request="catalog-lease-job", **request)["verification_id"]
            verifier = Client(url, probe_token)
            lease = verifier.post("capability-probe-claim", request="catalog-lease")["job"]
            assert lease["id"] == attempt_job
            assert verifier.post("capability-probe-claim", request="catalog-lease")["job"] == lease
            report = {"verification_id": attempt_job, "attempt": lease["attempt"], "outcome": "pass", "value": "available",
                      "measured": {"environment": "wrong-environment"}, "evidence": {"note": "Fixture", "sha256": "1" * 64}}
            verifier.post("capability-probe-result", 409, **report)
            report["measured"] = {"environment": "fixture-env"}
            first = verifier.post("capability-probe-result", request="catalog-result-replay", **report)
            assert first == verifier.post("capability-probe-result", request="catalog-result-replay", **report)
            verifier.post("capability-probe-result", 409, **report)
            attempt_job = node.post("capability-request", request="catalog-expiry-job", **request)["verification_id"]
            assert verifier.post("capability-probe-claim")["job"]["id"] == attempt_job
            # A new catalog revision cannot rewrite the task's frozen requirement.
            admin.post("project-capability-save", **{**save, "label": "Hermes API updated", "version": 1})
            newer = node.get("tasks/" + tid)["task"]
            assert newer["contract"]["requirements"] == task["contract"]["requirements"]
            changed = {**scope, "environment": "other-env"}
            node.post("context-save", context_id="fixture-profile", version=1, environment_id="fixture-hermes-env",
                      config={**changed, "sources": {k: "reported" for k in changed}}, make_default=True)
            node.post("claim", 409, **{**claim, "context_version": 2})
            node.post("claim", **claim)

    snap = LedgerBackend(project / ".state/local").read()
    assert not snap["halted"]
    state = snap["state"]
    assert state["pilot"]["format"]["min_reader"] == 8
    try:
        check(state, reader=7)
    except ValueError:
        pass
    else:
        raise AssertionError("Old readers must refuse new project-capability semantics")
    pending = state["round"]["verification:" + attempt_job]
    data = {"op": "capability-probe-result", "id": attempt_job, "attempt": pending["attempt"], "verifier_id": "fixture",
            "verifier_version": 1, "outcome": "pass", "value": "available", "measured": {"environment": "fixture-env"},
            "evidence": {"note": "Fixture", "sha256": "1" * 64}}
    cross_project = deepcopy(state)
    catalog.verifier(cross_project, "fixture")["projects"] = ["different-project"]
    try:
        catalog.apply(cross_project, data, "probe-fixture-1", pending["lease_expires"] - 1, "wrong-project-test")
    except Rejected:
        pass
    else:
        raise AssertionError("A verifier for another existing project must not report this result")
    try:
        catalog.apply(deepcopy(state), data, "probe-fixture-1", pending["lease_expires"], "expired-test")
    except Rejected:
        pass
    else:
        raise AssertionError("An expired probe lease must never create evidence")
    print("PASS project catalog, real loopback Hermes probe, claim gate, scope, replay, revision and expiry")


if __name__ == "__main__":
    with scratch("cap-cat-") as directory:
        project = Path(directory)
        with zipfile.ZipFile(ROOT / "dist/task-pool-local.zip") as package:
            package.extractall(project)
        exercise(project)
