"""Run the v2 workflow acceptance scenarios on a disposable qualified store."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlencode
import zipfile

from verify import ROOT, browser_client, call, claim_args, command, download, lost_response, server, sha
from verify_support import report_path, scratch


PROJECT = "intranet-task-system"
IMAGE = "1" * 64
SKILL = {"id": "markdown", "kind": "skill", "value": "*", "required": True, "evidence": "declared"}
RESOURCE = {"id": "path:fixtures/shared.md", "mode": "write"}
CASES = {}


def passed(case, detail, condition=True):
    if not condition:
        raise AssertionError(f"{case}: {detail}")
    CASES[case] = {"status": "passed", "evidence": detail}
    print("PASS", case, detail, flush=True)


class Client:
    def __init__(self, url, token):
        self.url, self.token, self.sequence = url, token, 0

    def post(self, action, expect=200, request=None, **payload):
        self.sequence += 1
        data = {"request_id": request or f"v2-{self.sequence}", **payload}
        code, result = call(self.url + "/" + action, self.token, data)
        assert code == expect, (action, code, expect, result.get("message"), result.get("steps"))
        return result

    def get(self, route):
        code, data = call(self.url + "/" + route, self.token)
        assert code == 200, (route, code, data.get("message"))
        return data


def source(session, platform="codex"):
    return {"platform": platform, "session": session, "model": "fixture-model", "environment": "fixture-env",
            "device": "isolated-device", "directory": "fixture", "url": "", "parent": None}


def register(admin, receiver, resources=(), requirements=None, mode="source", basis="", **extra):
    values = {"title": "升级验证任务", "brief": "冻结输入", "criteria": ["ready"], "kind": "documentation",
              "project_id": PROJECT, "iteration": {"goal": "核对升级", "previous": [], "next": []},
              "delivery": "output.md", "requirements": requirements if requirements is not None else [SKILL],
              "review_mode": mode, "user_basis": basis, "resources": list(resources), "dependencies": [],
              "receiver": receiver}
    values.update(extra)
    return admin.post("register", **values)["task"]


def control(client, action, task, status=200, **extra):
    values = {"task_id": task["task_id"], "version": task["version"], "reason": "隔离验收场景"}
    if action in {"task-publish", "task-hold", "task-scope"}:
        values["scope_version"] = task["scope_version"]
    return client.post(action, status, **values, **extra)


def claim(client, task, status=200, request=None):
    return client.post("claim", status, request, **{k: task[k] for k in ("task_id", "version", "scope_version")})


def capability(client, name, key="markdown", *, level="declared", kind="skill", env="fixture-env", version=0, status=200):
    return client.post("capability-save", status, project_id=PROJECT, name=name, capability=key, kind=kind,
                       value="ok", level=level, evidence={"note": "隔离验收可重现探针", "sha256": sha(key.encode())},
                       environment=env, expires=int(time.time()) + 86400, version=version)


def seal(client, receipt):
    return client.post("deliver-files", **claim_args(receipt),
                       files=[{"name": "output.md", "content": base64.b64encode(b"fixture output").decode("ascii")}])


def review(client, sealed, status=200):
    c = sealed["claim"]
    revision, record = next(reversed(c["deliveries"].items()))
    parent = record["manifest"]["path"].rsplit("/", 1)[0]
    return client.post("review", status, claim_id=c["claim_id"], revision=revision,
                       manifest_sha256=record["manifest_sha256"], checks=[{
                           "id": "ready", "path": parent + "/output.md",
                           "sha256": sha(b"fixture output"), "note": "实际核对隔离产物"}])


def browser_session(url, identity, token):
    request, origin = browser_client(url)
    code, headers, _ = request("/login", "POST", {"Origin": origin, "Content-Type": "application/x-www-form-urlencoded"},
                               urlencode({"identity": identity, "token": token}))
    assert code == 303
    return request, origin, headers["Set-Cookie"].split(";", 1)[0]


def revoke_before_recovery(project, name, task):
    # Stage a durable, as-yet-unapplied request. Apply an authorized control
    # event first, then exercise the real journal recovery.
    script = """
import json,sys
from pool.service import Service,exclusive,state_path
from 协作账本 import envelope,cursor
from 协作存储 import digest,encoded
name,task_id=sys.argv[1:]
store=state_path("local")
with exclusive(store):
    service=Service(store)
    try:
        snap=service.snapshot()
        task=snap["state"]["tasks"][task_id]
        body={"request_id":"pending-before-revoke","task_id":task_id,"version":task["version"],"scope_version":task["scope_version"]}
        key=digest(encoded([name,body["request_id"]]))
        finger=digest(encoded(["claim",body]))
        plan=service.plan(name,"claim",key,body,snap)
        with service.db:
            service.db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)",
                               (key,finger,name,"claim",encoded(body),encoded(plan),None,None))
            service.record_request(key,name,"claim",body,finger,snap["state"],plan)
        origin=snap["state"]["coordinator"]
        payload={"op":"grant","project_id":"intranet-task-system","name":name,"roles":[],"resources":[],"version":1,
                 "_audit":{"schema":2,"actor":"admin"}}
        env=envelope(service.desk.meta["repo_id"],origin,cursor(snap,origin)+1,"pilot",payload,
                     {"generation":snap["state"]["generation"]})
        received=service.desk.receive(env,"pilot-committer")
        current=service.desk.process("pilot-committer")
        assert current["control"]["terminal"][received["key"]]["result"]=="applied"
        assert service.recover()
        status,raw=service.db.execute("SELECT status,response FROM requests WHERE key=?",(key,)).fetchone()
        reply=json.loads(raw)
        assert status==409 and "授权已变更" in reply["steps"][-1]["reason"], reply
        assert service.snapshot()["state"]["tasks"][task_id]["claims"]==[]
    finally:
        service.close()
"""
    check = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", script, name, task],
                           cwd=project, capture_output=True, timeout=90)
    assert check.returncode == 0, check.stderr.decode("utf-8", errors="replace")


def exercise(project):
    initial = command(project, "init", "--worker", "worker-a", "--worker", "worker-b", "--receiver", "reviewer",
                      "--authority", "T22 upgrade acceptance fixture")
    credentials = json.loads(Path(initial["credentials"]).read_bytes())
    admin_token = command(project, "init-admin")["token"]
    brief = project / "brief.md"
    brief.write_text("synthetic input", encoding="utf-8")
    for task in ("T01", "T02"):
        command(project, "add-task", "--request-id", "baseline-" + task, "--title", task, "--input", brief, "--criterion", "ready")
    migrated = command(project, "upgrade-migrate", "--upgrade", "fixture", "--image", IMAGE)
    assert migrated["task"]["contract"]["open"] is False
    assert command(project, "upgrade-migrate", "--upgrade", "fixture", "--image", IMAGE) == migrated
    with server(project) as (_, url):
        a = Client(url, admin_token)
        assert a.get("upgrade")["format"]["maintenance"]
        code, result = call(url + "/claim", credentials["tokens"]["worker-a"],
                            {"request_id": "during-maintenance", "task_id": "T01", "version": 1, "scope_version": 1})
        assert code == 503
    command(project, "maintenance", "off", "--request-id", "fixture-activate")

    with server(project) as (_, url):
        a = Client(url, admin_token)
        r = Client(url, credentials["tokens"]["reviewer"])
        human = Client(url, credentials["tokens"]["worker-a"])
        for name in ("reviewer", "worker-a"):
            a.post("identity-bind", name=name, kind="human", owner=name, reason="隔离测试身份确认", source=None)
            a.post("project-grant", project_id=PROJECT, name=name, roles=["executor", "receiver"], resources=[], version=0)
        a.post("project-grant", project_id=PROJECT, name="admin", roles=["manager"], resources=[RESOURCE], version=1)
        with ThreadPoolExecutor(2) as workers:
            issued = list(workers.map(lambda name: Client(url, admin_token).post(
                "executor-enroll", request="enroll-" + name, project_id=PROJECT,
                roles=["executor", "receiver"], source=source(name)), ("one", "two")))
        first, second = issued
        third = a.post("executor-enroll", project_id=PROJECT, roles=["executor"], source=source("three", "claude"))
        n1, n2, n3 = (item["executor_id"] for item in (first, second, third))
        x1, x2, x3 = (Client(url, item["token"]) for item in (first, second, third))
        assert first == Client(url, admin_token).post("executor-enroll", request="enroll-one", project_id=PROJECT,
                                                     roles=["executor", "receiver"], source=source("one"))
        assert Client(url, admin_token).post("executor-enroll", 409, project_id=PROJECT,
                                             roles=["executor"], source=source("one"))
        passed("A02", "concurrent same-model enrollments have unique window numbers and credentials",
               first["window"] != second["window"] and first["token"] != second["token"] and
               all(item["window"].startswith("CDX-") for item in issued))
        for client, name in ((x1, n1), (x2, n2), (x3, n3)):
            capability(client, name)

        binding = x1.get("identity")["binding"]
        assert binding["owner"] == "admin" and binding["kind"] == "executor"
        enrollment = a.get("audit?request=enroll-one")["events"][-1]
        passed("A01", "authenticated owner, executor and ledger committer are distinct fields",
               enrollment["actor"] == "admin" and enrollment["origin_id"] == "pilot-coordinator"
               and enrollment["committer"] == "pilot-committer")
        request, origin, cookie = browser_session(url, n1, first["token"])
        page = request("/executors/" + n1, headers={"Cookie": cookie})[2]
        passed("A03", "window page shows the same searchable number and registered session as the API",
               ("[" + first["window"] + "]").encode() in page and b"one" in page)
        synced = x1.post("executor-sync", request="sync-original", session="one", model="fixture-model", environment="fixture-env")
        replay = Client(url, first["token"]).post("executor-sync", request="sync-original", session="one", model="fixture-model", environment="fixture-env")
        passed("A04", "reconnect preserves window and original response", replay == synced and x1.get("identity")["binding"]["window"] == first["window"])
        x1.post("executor-sync", session="one", model="fixture-model-changed", environment="fixture-env")
        current = x1.get("identity")["binding"]
        passed("A06", "model change keeps window ID with new model metadata",
               current["window"] == first["window"] and current["model"] == "fixture-model-changed")
        fourth = a.post("executor-enroll", project_id=PROJECT, roles=["executor"], source=source("four"))
        conflict = Client(url, fourth["token"])
        conflict.post("executor-sync", session="wrong-window", model="fixture-model", environment="fixture-env")
        passed("A07", "different session places source in disputed state and blocks further writes",
               call(url + "/identity", fourth["token"])[0] == 401 and any(
                   w["executor_id"] == fourth["executor_id"] and w["status"] == "disputed"
                   for w in a.get("executors")["executors"]))

        code, failure = call(url + "/register", admin_token, {"request_id": "missing-contract", "title": "缺项"})
        passed("A08", "creation rejects missing capability contract", code == 400)
        strict = register(a, "reviewer", requirements=[{**SKILL, "evidence": "verified"}])
        strict = control(a, "task-publish", strict)["task"]
        blocked = claim(x1, strict, 409)
        passed("A09", "declared skill cannot satisfy verified requirement", "markdown" in blocked["message"])
        env = register(a, "reviewer", requirements=[{**SKILL, "id": "runtime", "kind": "environment", "evidence": "verified"}])
        env = control(a, "task-publish", env)["task"]
        capability(r, n1, "runtime", level="verified", kind="environment")
        x1.post("executor-sync", session="one", model="fixture-model-changed", environment="changed")
        passed("A10", "changed environment invalidates the bound evidence", "runtime" in claim(x1, env, 409)["message"])
        x1.post("executor-sync", session="one", model="fixture-model-changed", environment="fixture-env")

        shared = control(a, "task-publish", register(a, "reviewer", [RESOURCE]))["task"]
        shared2 = control(a, "task-publish", register(a, "reviewer", [RESOURCE]))["task"]
        capability(human, "worker-a")
        passed("A11", "capability cannot grant shared-file authorization", "资源授权" in claim(human, shared, 409)["message"])
        req = urlencode({"request_id": "browser-race", **{k: shared[k] for k in ("task_id", "version", "scope_version")}})
        with ThreadPoolExecutor(2) as workers:
            web = workers.submit(request, "/actions/claim", "POST", {
                "Origin": origin, "Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"}, req)
            api = workers.submit(call, url + "/claim", second["token"], {"request_id": "api-race", **{
                k: shared[k] for k in ("task_id", "version", "scope_version")}})
            ws, _, _ = web.result()
            api_status, _ = api.result()
        passed("A12", "real web session and bearer API contest one resource atomically",
               (ws, api_status) in {(303, 409), (409, 200)})
        winning, owner = (x1, n1) if ws == 303 else (x2, n2)
        claimant = winning.get("tasks/" + shared["task_id"])["claims"][-1]
        other = control(a, "task-publish", register(a, "reviewer"))["task"]
        other_claim = claim(winning, other, request="retry-one")
        replay = Client(url, winning.token).post("claim", request="retry-one", **{k: other[k] for k in ("task_id", "version", "scope_version")})
        conflict_id = Client(url, winning.token).post("claim", 409, "retry-one", task_id=other["task_id"],
                                                        version=other["version"] + 1, scope_version=other["scope_version"])
        passed("A13", "same request returns same receipt and changed content conflicts", replay == other_claim and "内容" in conflict_id["message"])
        entries = next(item for item in a.get("executors")["executors"] if item["executor_id"] == owner)["tasks"]
        passed("A14", "one window holds two distinct active claims", len({c["claim_id"] for c in entries if c["lifecycle"] == "active"}) == 2)
        passed("A15", "shared write conflict is checked between claims of the same window", "资源占用" in claim(winning, shared2, 409)["message"])
        handoff = winning.post("handoff", claim_id=claimant["claim_id"], epoch=claimant["epoch"], scope_version=claimant["W"]["scope"],
                               notes="交付目录和输入清单已记录", stop_evidence="隔离进程已实际停止")
        result = claim(x3, handoff["task"])
        passed("A05", "cross-platform handoff uses a new source and new claim", result["claim"]["origin"] == n3 and
               result["claim"]["claim_id"] != claimant["claim_id"] and third["window"].startswith("CLD-"))
        passed("A16", "handoff of one task retains the other task's claim and epoch",
               winning.get("tasks/" + other["task_id"])["claims"][-1] == other_claim["claim"])
        env_claim = claim(x1, env)
        env_handoff = x1.post("handoff", **claim_args(env_claim), notes="能力相关接续", stop_evidence="实际停止")
        passed("A17", "handoff successor must satisfy the actual environment requirement",
               "runtime" in claim(x3, env_handoff["task"], 409)["message"])
        current = result["task"]
        old = result["claim"]
        held = control(x3, "task-interrupt", current, claim_id=old["claim_id"], epoch=old["epoch"])
        assert held["claim"]["E"]["state"] == "requested" and held["claim"]["R"] == old["R"]
        assert claim(x1, held["task"], 409)
        unresolved = control(a, "task-recover", held["task"], claim_id=old["claim_id"], epoch=held["claim"]["epoch"],
                             evidence="在途操作已查到", notes="等待实际文件关闭", unresolved="共享文件仍有活动")
        passed("A19", "interruption and unresolved external effects preserve reservations",
               unresolved["claim"]["R"] == old["R"] and unresolved["claim"]["recovery"]["status"] == "pending")
        successor = control(a, "task-recover", unresolved["task"], claim_id=old["claim_id"], epoch=held["claim"]["epoch"],
                            evidence="隔离进程已退出且文件写操作结束", notes="接续材料已复核", unresolved="")
        stale = x3.post("deliver-files", 409, **claim_args(result), files=[{"name": "late.md", "content": "eA=="}])
        passed("A21", "old epoch cannot seal after cross-platform recovery", "代次" in stale["message"] and successor["claim"]["L"] == "ended")

        subject_review = control(a, "task-publish", register(a, n2))["task"]
        production = claim(x1, subject_review)
        sealed = seal(x1, production)
        before = x1.get("tasks/" + subject_review["task_id"])
        interrupt = control(x1, "task-interrupt", before["task"], claim_id=production["claim"]["claim_id"],
                            epoch=before["claims"][-1]["epoch"])
        reviewed = review(x2, sealed)
        actual = x1.get("tasks/" + subject_review["task_id"])
        finish = control(a, "task-recover", actual["task"], claim_id=production["claim"]["claim_id"],
                         epoch=actual["claims"][-1]["epoch"], evidence="已确认隔离进程结束", notes="封存产物保留", unresolved="")
        x2.post("close", task_id=subject_review["task_id"])
        passed("A20", "sealed revision can be accepted during recovery and closed after stop", interrupt["claim"]["W"]["state"] == "review"
               and finish["task"]["status"] == "pending_close")
        passed("A22", "source independence allows different sources of one owner", reviewed["claim"]["W"]["state"] == "complete")
        distinct = control(a, "task-publish", register(a, n2, mode="account"))["task"]
        review(x2, seal(x1, claim(x1, distinct)), 409)
        direct = control(a, "task-publish", register(a, "worker-a", mode="user", basis="隔离验收明确授权人工直接接受"))["task"]
        direct_review = review(human, seal(human, claim(human, direct)))
        passed("A23", "owner-level independence blocks same owner while explicit human confirmation applies",
               direct_review["claim"]["W"]["state"] == "complete")
        claim(x3, other, 409)
        timeline = winning.get("audit?" + urlencode({"task": other["task_id"]}))["events"]
        legacy = a.get("audit?task=T02")["events"]
        passed("A24", "timeline preserves unknown legacy timestamps and distinguishes rejected requests",
               any(e["result"] == "applied" and e["committed_utc"] and e["changes"] for e in timeline) and
               any(e["result"] == "rejected" for e in timeline) and
               any(e["committed_utc"] is None for e in legacy))

        scope_task = winning.get("tasks/" + other["task_id"])["task"]
        update = control(a, "task-scope", scope_task, project_id=PROJECT, iteration={"goal": "范围已更新", "previous": [], "next": []},
                         delivery="修订结果", requirements=[SKILL], review_mode="source", user_basis="", resources=[], dependencies=[])
        changed = winning.get("tasks/" + other["task_id"])["claims"][-1]
        winning.post("deliver-files", 409, **claim_args(other_claim), files=[{"name": "late.md", "content": "eA=="}])
        stopped = winning.post("stop", **claim_args({"claim": changed}), stop_evidence="实际停止")
        control(a, "task-publish", stopped["task"])
        resumed = winning.post("resume", **claim_args(stopped))
        passed("A25", "scope change fences old epoch and requires stop plus explicit resume",
               update["task"]["scope_version"] == other["scope_version"] + 1 and resumed["claim"]["epoch"] > changed["epoch"])
        rotate = a.post("credential-change", name=n3, version=1, status="active", reason="隔离测试轮换")
        x3 = Client(url, rotate["token"])
        assert call(url + "/identity", third["token"])[0] == 401 and x3.get("identity")["identity"] == n3
        queued = control(a, "task-publish", register(a, "reviewer"))["task"]

        gate = a.get("tasks/T02")["task"]
        control(a, "task-publish", gate, 409)
        fixture_report = {"upgrade": "fixture", "image": IMAGE, "baseline": {"passed": 110, "failed": 0, "ext4": 33},
                          "cases": {f"A{i:02d}": {"status": "passed", "evidence": "测试用合成证明，仅用于门槛逻辑"} for i in range(1, 35)}}
        accepted = r.post("release-accept", reason="测试接收", report=fixture_report)
        control(a, "task-publish", gate, 409)
        acceptance = accepted["steps"][-1]["event_id"]
        a.post("release-close", reason="测试收口", acceptance=acceptance)
        opened = control(a, "task-publish", gate)["task"]
        for item in opened["contract"]["requirements"]:
            if item["id"] != "markdown":
                capability(r if item["evidence"] == "verified" else x1, n1, item["id"],
                           level=item["evidence"], kind=item["kind"])
        released_claim = claim(x1, opened)
        passed("A28", "valid acceptance, close and explicit publication open the gate",
               opened["contract"]["open"] and released_claim["task"]["task_id"] == "T02"
               and a.get("upgrade")["release"]["status"] == "closed")
        a.post("release-correct", reason="测试更正收口")
        assert "收口" in claim(x1, opened, 409)["message"]
        passed("A27", "gate blocks before final close and after correction")
        renamed = a.post("project-save", project_id=PROJECT, name="项目改名核对", version=1)
        project_info = a.get("projects/" + PROJECT)
        passed("A29", "migration keeps original IDs and frozen inputs, rename keeps stable project ID",
               renamed["status"] == "applied" and "任务协作平台" in project_info["previous_names"] and
               gate["inputs"] == migrated["task"]["inputs"] and gate["task_id"] == "T02")

        fault_task = control(a, "task-publish", register(a, "reviewer"))["task"]
        fault_claim = claim(x1, fault_task)
        payload = {"request_id": "fault-handoff-v2", **claim_args(fault_claim),
                   "notes": "记录已持久化", "stop_evidence": "隔离工作已经停止"}
    with server(project, "replace_claim") as (process, url):
        lost_response(process, url + "/handoff", first["token"], payload, "v2 injected exit after applied replacement")
    with server(project) as (_, url):
        status, receipt = call(url + "/handoff", first["token"], payload)
        check = receipt["claim"]["L"] == "ended" and len(receipt["steps"]) == 2
        passed("A18", "after process loss the original handoff request returns both applied steps", status == 200 and check)
    revoke_before_recovery(project, n3, queued["task_id"])
    passed("A26", "rotation preserves the source; a durable queued claim is rejected after its grant changes")
    return initial["qualification_passed"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="默认 dist/verify_upgrade.json")
    args = parser.parse_args()
    args.report = args.report or report_path("verify_upgrade.json")
    archive = ROOT / "dist" / "task-pool-local.zip"
    with scratch("verify-upgrade-") as directory:
        project = Path(directory)
        with zipfile.ZipFile(archive) as package:
            package.extractall(project)
        qualification = exercise(project)
    assert set(CASES) == {f"A{i:02d}" for i in range(1, 30)}
    report = {"passed": len(CASES), "failed": 0, "cases": CASES, "qualification": qualification,
              "artifact_sha256": sha(archive.read_bytes()), "backend": "ntfs" if os.name == "nt" else "ext4"}
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{len(CASES)} upgraded workflow checks passed")


if __name__ == "__main__":
    main()
