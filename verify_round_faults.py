"""Supplemental v3 fault, expiry and project-isolation scenarios."""
import argparse
from contextlib import contextmanager
from http.client import RemoteDisconnected
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import zipfile

from verify import ROOT, call, server, sha
from verify_round import Browser, Client, ai_prepare, bind, browser_admin_api, invitation, post_browser, request_id, setup
from verify_upgrade import PROJECT, capability, control, register


@contextmanager
def fault_server(project, stage):
    code = """
import os,runpy,sys
from pool.service import Service
import 协作本轮 as rules
stage=sys.argv[1]
if stage == 'expiry':
    rules.ACTIVATION_SECONDS = 6
else:
    original=Service.apply_step
    def crash_after_apply(self,env,instruction,body,snap):
        output=original(self,env,instruction,body,snap)
        if env['payload'].get('op') == stage and output[1]['result'] == 'applied':
            os._exit(86)
        return output
    Service.apply_step=crash_after_apply
sys.argv=['taskpool.py','serve','--port','0']
runpy.run_path('taskpool.py',run_name='__main__')
"""
    process = subprocess.Popen([sys.executable, "-B", "-X", "utf8", "-c", code, stage], cwd=project,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        lines = []
        for line in iter(process.stdout.readline, b""):
            lines.append(line)
            if line.rstrip() == b"}":
                break
        if not lines:
            raise RuntimeError(process.stderr.read().decode("utf-8", errors="replace"))
        yield process, json.loads(b"".join(lines))["url"] + "/v1"
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=15)


def disconnect(process, url, body, token=None):
    try:
        call(url, token, body)
    except (ConnectionResetError, RemoteDisconnected):
        assert process.wait(timeout=15) == 86
    else:
        raise AssertionError("故障注入未中断 HTTP 回应")


def exercise(project):
    _, tokens, password = setup(project)
    with server(project) as (_, url):
        b = Browser(url)
        b.login("admin", password)
        invite = invitation(b)
        expiring = invitation(b)
    from verify_upgrade import source
    registration = {"request_id": request_id(), "invite_id": invite["id"], "code": invite["code"],
                    "recovery": secrets.token_urlsafe(32), "source": source(request_id())}
    with fault_server(project, "ai-prepare") as (process, url):
        disconnect(process, url + "/ai-prepare", registration)
    with server(project) as (_, url):
        proof = {k: registration[k] for k in ("request_id", "invite_id", "recovery")}
        status, ready = call(url + "/ai-recover", data=proof)
        assert status == 200 and ready["status"] == "pending_activation"
        assert call(url + "/identity", ready["token"])[0] == 401
        assert call(url + "/ai-prepare", data=registration) == (200, ready)
        assert ai_prepare(url, invite)[1][0] == 409
    activation = {"request_id": request_id(), "registration_id": ready["registration_id"]}
    with fault_server(project, "ai-activate") as (process, url):
        disconnect(process, url + "/ai-activate", activation, ready["token"])
    with server(project) as (_, url):
        status, activated = call(url + "/ai-activate", ready["token"], activation)
        assert status == 200 and activated["status"] == "active" and activated["window"] == ready["window"]
        assert call(url + "/identity", ready["token"])[0] == 200
        assert "token" not in call(url + "/ai-recover", data=proof)[1]
    print("PASS N23 persisted enrollment and activation recovered after two real process exits", flush=True)
    with fault_server(project, "expiry") as (_, url):
        body, (status, candidate) = ai_prepare(url, expiring)
        assert status == 200
        time.sleep(max(0, candidate["deadline"] - time.time() + 0.2))
        assert call(url + "/ai-activate", candidate["token"], {"request_id": request_id(),
                    "registration_id": candidate["registration_id"]})[0] == 403
        assert call(url + "/identity", candidate["token"])[0] == 401
        assert ai_prepare(url, expiring)[1][0] == 409
    print("PASS N26 pending expiry leaves identity unavailable and consumes no extra seat", flush=True)
    with server(project) as (_, url):
        b = Browser(url)
        b.login("admin", password)
        b.send("/")
        a = browser_admin_api(project, b)
        bind(a, "worker-a", "executor")
        bind(a, "reviewer", "receiver")
        worker = Client(url, tokens["worker-a"])
        capability(worker, "worker-a")
        rows = [register(a, "reviewer") for _ in range(2)]
        t1, t2 = (row["task_id"] for row in rows)
        a.post("project-save", project_id="fixture-private", name="隔离私有项目", version=0)
        a.post("project-grant", project_id="fixture-private", name="reviewer", roles=["receiver"], resources=[], version=0)
        hidden = register(a, "reviewer", project_id="fixture-private", title="<script>fixture</script>")["task_id"]
        assert call(url + "/tasks/" + hidden, worker.token)[0] == 404
        page = b.send("/tasks/" + hidden)[2].decode()
        assert "&lt;script&gt;fixture&lt;/script&gt;" in page and "<script>fixture</script>" not in page
        print("PASS N06 project denial and escaped task title", flush=True)
        common = {"project_id": PROJECT, "kind": "depends", "output": "documentation", "criterion": "ready",
                  "reason": "核对真实依赖关系"}
        current = lambda: {tid: worker.get("tasks/" + tid)["task"]["version"] for tid in (t1, t2)}
        b.send("/collaboration?project=" + PROJECT)
        assert post_browser(b, "task-relation", {**common, "source": t1, "target": t2, "versions": current()})[0] == 303
        assert post_browser(b, "task-relation", {**common, "source": t2, "target": t1, "versions": current()})[0] == 409
        assert post_browser(b, "task-relation", {**common, "source": t1, "target": t1, "versions": current()})[0] == 409
        print("PASS N41 dependencies reject self-reference and cycles", flush=True)
        b.send("/")
        only = register(a, "reviewer", dispatch={"mode": "only", "subjects": ["worker-a"], "capabilities": [],
                                                 "automation": "notify", "owner": "admin"})["task_id"]
        task = worker.get("tasks/" + only)["task"]
        control(a, "task-publish", task)
        b.send("/invitations")
        invite = invitation(b, "worker-a")
        _, (status, issued) = ai_prepare(url, invite)
        assert status == 200
        from verify_round import activate
        other = activate(url, issued)
        capability(other, issued["executor_id"])
        decision = other.get("tasks/" + only)["qualification"]
        assert not decision["eligible"] and "当前身份不在限定领取范围" in decision["missing"]
        print("PASS N29 new window does not inherit a named person's only-target policy", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    archive = ROOT / "dist" / "task-pool-local.zip"
    state = ROOT / ".state"
    state.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="v3-faults-", dir=state) as name:
        with zipfile.ZipFile(archive) as zipped:
            zipped.extractall(name)
        exercise(Path(name))
    args.report.write_text(json.dumps({"artifact_sha256": sha(archive.read_bytes()),
                                       "checks": ["N06", "N23", "N26", "N29", "N41"],
                                       "expiry_fixture_seconds": 6, "passed": 5}, indent=2), encoding="utf-8")
