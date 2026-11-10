"""Regress phase-1 combined operations, read-only roles and path boundaries."""
from pathlib import Path
import argparse
import base64
import importlib.util
import os
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from verify import command, server, claim_args
from verify_round import Browser, Client, browser_admin_api, bind, setup
from verify_upgrade import PROJECT, capability, claim, control, register, review

def storage_boundary():
    spec = importlib.util.spec_from_file_location("review_storage", ROOT / "vendor/ledger/协作存储.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    state = ROOT / ".state"
    directory = None if os.name != "nt" else state
    state.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="phase1-path-", dir=directory) as name:
        base = Path(name)
        parent = base / "parent"
        root = parent / "store"
        alternate = base / "alternate"
        root.mkdir(parents=True)
        (alternate / "store").mkdir(parents=True)
        (root / "proof").write_text("intended")
        (alternate / "store/proof").write_text("redirected")
        assert module.safe(root, "proof").read_text() == "intended"
        parent.rename(base / "original-parent")
        if os.name == "nt":
            create = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(parent), str(alternate)],
                                    capture_output=True)
            assert create.returncode == 0, create.stderr.decode(errors="replace")
        else:
            parent.symlink_to(alternate, target_is_directory=True)
        try:
            try:
                module.safe(root, "proof")
            except ValueError:
                pass
            else:
                raise AssertionError("Ancestor replacement escaped the storage boundary")
            assert (alternate / "store/proof").read_text() == "redirected"
        finally:
            if os.name == "nt":
                parent.rmdir()
            else:
                parent.unlink()
        parent.mkdir()
        assert module.safe(parent / "new-store", "file").name == "file"
    print("ANCESTOR_REPLACEMENT_REJECTED_IMMEDIATELY", flush=True)


def application(compatibility=False):
    with tempfile.TemporaryDirectory(prefix="phase1-review-", dir=ROOT / ".state") as directory:
        copy = Path(directory)
        for name in ("build.py", "taskpool.py", "README.md", ".gitignore", "verify.py", "verify_upgrade.py"):
            shutil.copy2(ROOT / name, copy / name)
        for folder in ("pool", "vendor", "ops", "docs"):
            shutil.copytree(ROOT / folder, copy / folder, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        result = subprocess.run([sys.executable, "-B", "-X", "utf8", "build.py"], cwd=copy, capture_output=True, timeout=60)
        assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
        print("BUILD_OK", flush=True)
        if compatibility:
            for script in ("verify.py", "verify_upgrade.py"):
                checked = subprocess.run([sys.executable, "-B", "-X", "utf8", script,
                                          "--report", str(copy / "dist" / (script + ".json"))],
                                         cwd=copy, capture_output=True, timeout=600)
                assert checked.returncode == 0, checked.stderr.decode("utf-8", errors="replace")
                print("COMPATIBILITY_OK", script, flush=True)
        _, tokens, password = setup(copy)
        with server(copy) as (_, url):
            browser = Browser(url)
            browser.login("admin", password)
            browser.send("/")
            admin = browser_admin_api(copy, browser)
            bind(admin, "worker-a", "executor")
            bind(admin, "reviewer", "receiver")
            bind(admin, "worker-b", "observer")
            worker = Client(url, tokens["worker-a"])
            receiver = Client(url, tokens["reviewer"])
            observer = Client(url, tokens["worker-b"])
            capability(worker, "worker-a")
            registration = register(admin, "reviewer", criteria=["ready", "format"])
            task = worker.get("tasks/" + registration["task_id"])["task"]
            control(admin, "task-publish", task)
            task = worker.get("tasks/" + task["task_id"])["task"]
            receipt = claim(worker, task)
            data = base64.b64encode(b"synthetic review artifact").decode()
            delivery = worker.post("deliver-files", request="combined-delivery", **claim_args(receipt),
                                   files=[{"name": "output.md", "content": data}], stop_evidence="test worker stopped")
            assert delivery["claim"]["E"]["state"] == "stopped" and not delivery["claim"]["R"]
            revision, sealed = next(reversed(delivery["claim"]["deliveries"].items()))
            receiver.post("return", claim_id=receipt["claim"]["claim_id"], revision=revision,
                          manifest_sha256=sealed["manifest_sha256"], criterion="ready", criteria=["ready", "format"], reason="two fixture findings")
            resumed = worker.post("resume", **claim_args(receipt))
            delivery = worker.post("deliver-files", **claim_args(resumed),
                                   files=[{"name": "output.md", "content": data}], stop_evidence="test revision stopped")
            revision, sealed = next(reversed(delivery["claim"]["deliveries"].items()))
            output = sealed["manifest"]["path"].rsplit("/", 1)[0] + "/output.md"
            close = receiver.post("review", claim_id=receipt["claim"]["claim_id"], revision=revision,
                                  manifest_sha256=sealed["manifest_sha256"], finish=True, checks=[
                                      {"id": name, "path": output, "sha256": hashlib.sha256(b"synthetic review artifact").hexdigest(),
                                       "note": "fixture bytes checked"} for name in ("ready", "format")
                                  ])
            assert close["task"]["status"] == "completed"
            print("COMBINED_DELIVERY_RETURN_REVIEW_CLOSE_OK", flush=True)

            from verify import call
            expires = int(time.time()) + 86400
            def capability_body(request):
                return {"request_id": request, "project_id": PROJECT, "name": "worker-b",
                        "capability": "observer-write", "kind": "skill", "value": "test", "level": "declared",
                        "evidence": {"note": "observer write regression", "sha256": ""},
                        "environment": "human", "expires": expires, "version": 0}
            status, response = call(url + "/capability-save", tokens["worker-b"], capability_body("observer-capability"))
            assert status == 403, (status, response)
            assert observer.get("capabilities")["capabilities"] == []
            admin.post("project-grant", project_id=PROJECT, name="worker-b", roles=["reporter"], resources=[], version=1)
            status, response = call(url + "/capability-save", tokens["worker-b"], capability_body("reporter-capability"))
            assert status == 403, (status, response)
            observer.post("feedback-save", project_id=PROJECT, task_id="", kind="feedback", title="Reporter feedback",
                          details="Reporters may submit feedback", impact="fixture", evidence="",
                          visibility="project", observed="fixture")
            admin.post("project-grant", project_id=PROJECT, name="worker-b", roles=["executor"], resources=[], version=2)
            capability(observer, "worker-b")
            admin.post("project-grant", project_id=PROJECT, name="worker-b", roles=["observer"], resources=[], version=3)
            from verify_round import password_record
            assert password_record(Browser(url), "/password/setup", "worker-b", password, token=tokens["worker-b"])[0] == 303
            reader = Browser(url)
            reader.login("worker-b", password)
            status, _, page = reader.send("/capabilities")
            assert status == 200 and b'/actions/capability-save' not in page
            print("OBSERVER_READ_ONLY_AND_REPORTER_FEEDBACK_OK", flush=True)
        queued_capability(copy)


def queued_capability(project):
    script = """
import json,time
from pool.service import Service,exclusive,state_path,COMMITTER
from 协作账本 import envelope,cursor
from 协作存储 import digest,encoded
with exclusive(state_path("local")):
    service=Service(state_path("local"))
    try:
        state=service.snapshot()["state"]
        actor="worker-a"
        body={"request_id":"queued-capability","project_id":"intranet-task-system","name":actor,
              "capability":"queued-write","kind":"skill","value":"test","level":"declared",
              "evidence":{"note":"queued fixture","sha256":""},"environment":"human",
              "expires":int(time.time())+86400,"version":0}
        key=digest(encoded([actor,body["request_id"]]))
        plan=service.plan(actor,"capability-save",key,body,service.snapshot())
        with service.db:
            service.db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)",
                (key,digest(encoded(["capability-save",body])),actor,"capability-save",encoded(body),encoded(plan),None,None))
            service.record_request(key,actor,"capability-save",body,digest(encoded(["capability-save",body])),state,plan)
        snap=service.snapshot()
        payload={"op":"grant","project_id":"intranet-task-system","name":actor,"roles":["observer"],"resources":[],
                 "version":1,"_audit":{"schema":3,"actor":"admin"}}
        origin=state["coordinator"]
        env=envelope(service.desk.meta["repo_id"],origin,cursor(snap,origin)+1,"pilot",payload,
                     {"generation":state["generation"]})
        receipt=service.desk.receive(env,COMMITTER)
        current=service.desk.process(COMMITTER)
        assert current["control"]["terminal"][receipt["key"]]["result"]=="applied"
        assert service.recover()
        status,raw=service.db.execute("SELECT status,response FROM requests WHERE key=?",(key,)).fetchone()
        result=json.loads(raw)
        assert status==409 and result["steps"][-1]["result"]=="rejected",result
        assert "cap:intranet-task-system:worker-a:queued-write" not in service.snapshot()["state"]["pilot"]
    finally:
        service.close()
"""
    completed = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", script], cwd=project,
                               capture_output=True, timeout=120)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    print("QUEUED_CAPABILITY_RECHECKS_REVOKED_PERMISSION", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--storage-only", action="store_true")
    parser.add_argument("--compatibility", action="store_true")
    args = parser.parse_args()
    storage_boundary()
    if not args.storage_only:
        application(args.compatibility)
