"""Exercise the built ZIP over real loopback HTTP on the qualified backend."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
from http.client import HTTPConnection, RemoteDisconnected
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen
from verify_support import report_path, scratch
import zipfile


ROOT = Path(__file__).resolve().parent
AUTHORITY = "T22 synthetic integration verification"
CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError(name)
    CHECKS.append(name)
    print("PASS", name, flush=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def command(project, *args):
    result = subprocess.run([sys.executable, "-B", "-X", "utf8", str(project / "taskpool.py"), *map(str, args)],
                            capture_output=True, timeout=60, cwd=project)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    return json.loads(result.stdout)


@contextmanager
def server(project, fault=None):
    script = ([str(Path(__file__).resolve()), "--fault-server", str(project), fault]
              if fault else [str(project / "taskpool.py"), "serve", "--port", "0"])
    process = subprocess.Popen([sys.executable, "-B", "-X", "utf8", *script], cwd=project,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        # Taskpool emits a short JSON object at startup.
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
        process.wait(timeout=10)
        process.communicate(timeout=10)


def call(url, token=None, data=None, raw=False):
    headers = {"Authorization": "Bearer " + token} if token else {}
    if data is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(data, ensure_ascii=False).encode("utf-8")
    try:
        with urlopen(Request(url, data=data, headers=headers), timeout=15) as response:
            payload = response.read()
            return response.status, payload if raw else json.loads(payload)
    except HTTPError as error:
        return error.code, json.loads(error.read())


def body(request_id, **data):
    return {"request_id": request_id, **data}


def claim_args(receipt):
    c = receipt["claim"]
    return {"claim_id": c["claim_id"], "epoch": c["epoch"], "scope_version": c["W"]["scope"]}


def download(url, token, ref):
    status, raw = call(url + "/artifact?" + urlencode({"path": ref["path"]}), token, raw=True)
    check("artifact SHA " + ref["path"].rsplit("/", 1)[-1], status == 200 and sha(raw) == ref["sha256"])
    return raw


def lost_response(process, url, token, request, name):
    try:
        call(url, token, request)
    except (RemoteDisconnected, ConnectionResetError):
        check(name, process.wait(timeout=10) == 86)
    else:
        raise AssertionError("Fault server should exit before the HTTP response")


def browser_client(url):
    address = urlsplit(url)
    origin = f"{address.scheme}://{address.netloc}"

    def request(path, method="GET", headers=None, data=None):
        conn = HTTPConnection(address.hostname, address.port, timeout=15)
        try:
            conn.request(method, path, body=data, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    return request, origin


def verify_web(url, token, title):
    request, origin = browser_client(url)
    status, headers, page = request("/")
    check("browser login served with same-origin form policy", status == 200 and "登录任务池".encode() in page and
          "form-action 'self'" in headers["Content-Security-Policy"])
    status, headers, css = request("/assets/taskpool.css")
    check("bundled browser stylesheet served", status == 200 and headers["Content-Type"].startswith("text/css") and
          b".login-shell" in css)
    check("anonymous board download requires login", request("/board.md")[:2][1].get("Location") == "/login")
    form = {"Content-Type": "application/x-www-form-urlencoded", "Origin": origin}
    credentials = urlencode({"identity": "worker-a", "token": token})
    status, headers, _ = request("/login", "POST", {**form, "Origin": "https://other.test"}, credentials)
    check("cross-origin login rejected", status == 403 and "Set-Cookie" not in headers)
    status, headers, page = request("/login", "POST", form, urlencode({"identity": "worker-a", "token": "invalid-token"}))
    check("incorrect credential leaves login page and sets no session", status == 401 and
          "身份或访问令牌有误".encode() in page and "Set-Cookie" not in headers)
    status, headers, _ = request("/login", "POST", form, credentials)
    cookie = headers.get("Set-Cookie", "")
    check("login issues an HttpOnly same-site session", status == 303 and headers["Location"] == "/" and
          "HttpOnly" in cookie and "SameSite=Strict" in cookie and token not in cookie)
    signed_in = {"Cookie": cookie.split(";", 1)[0]}
    status, _, page = request("/", headers=signed_in)
    check("signed-in browser sees available tasks", status == 200 and title.encode() in page and
          "可领任务".encode() in page and token.encode() not in page)
    status, headers, _ = request("/board.md", headers=signed_in)
    check("authenticated browser can download board", status == 200 and headers["Content-Disposition"].startswith("attachment;"))
    check("browser session cannot authenticate bearer API", request("/v1/tasks", headers=signed_in)[0] == 401)
    check("cross-origin logout rejected", request("/logout", "POST", {**signed_in, "Origin": "https://other.test"})[0] == 403)
    status, headers, _ = request("/logout", "POST", {**signed_in, "Origin": origin})
    check("logout revokes server-side session", status == 303 and "Max-Age=0" in headers["Set-Cookie"] and
          request("/board.md", headers=signed_in)[0] == 303)


def verify_workflow(url, tokens):
    request, origin = browser_client(url)
    form = {"Origin": origin, "Content-Type": "application/x-www-form-urlencoded"}
    sessions = {}
    for actor, token in tokens.items():
        status, headers, _ = request("/login", "POST", form, urlencode({"identity": actor, "token": token}))
        check("workflow login for " + actor, status == 303)
        sessions[actor] = {"Cookie": headers["Set-Cookie"].split(";", 1)[0]}
    a, b, receiver = "worker-a", "worker-b", "reviewer"

    def submit(actor, action, request_id, **values):
        return request("/actions/" + action, "POST", {**form, **sessions[actor]},
                       urlencode(body(request_id, **values)))

    def current(tid, actor):
        result = call(url + "/tasks/" + tid, tokens[actor])[1]
        return result["task"], next((c for c in reversed(result["claims"]) if c["L"] == "active"), None)

    def epoch_args(claim):
        return claim_args({"claim": claim})

    def claim_task(tid, actor, request_id):
        task, _ = current(tid, actor)
        return submit(actor, "claim", request_id, task_id=tid, version=task["version"],
                      scope_version=task["scope_version"])

    def upload(actor, request_id, claim, raw, boundary="T22FixtureBoundary"):
        fields = body(request_id, **epoch_args(claim))
        data = b"".join((f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n'
                         f'{value}\r\n').encode() for key, value in fields.items())
        data += (f'--{boundary}\r\nContent-Disposition: form-data; name="artifact"; filename="成果.md"\r\n'
                 'Content-Type: application/octet-stream\r\n\r\n').encode() + raw + f'\r\n--{boundary}--\r\n'.encode()
        return request("/actions/deliver-files", "POST", {**sessions[actor], "Origin": origin,
                       "Content-Type": f"multipart/form-data; boundary={boundary}"}, data)

    registration = {"title": "网页流程 <资料>", "brief": "冻结的试用说明", "criteria": "report-ready"}
    check("worker cannot register from browser", submit(a, "register", "web-register", **registration)[0] == 403)
    check("worker cannot load registration form", request("/tasks/new", headers=sessions[a])[0] == 403)
    status, headers, _ = submit(receiver, "register", "web-register", **registration)
    check("receiver registers available task in browser", status == 303 and headers["Location"] == "/tasks/T02")
    check("browser registration retry keeps one task",
          submit(receiver, "register", "web-register", **registration)[1]["Location"] == "/tasks/T02")
    task, _ = current("T02", a)
    path, checksum = next(iter(task["inputs"].items()))
    status, _, raw = request("/download?" + urlencode({"path": path}), headers=sessions[a])
    check("browser downloads registered frozen input", status == 200 and sha(raw) == checksum and raw == registration["brief"].encode())
    detail = request("/tasks/T02", headers=sessions[a])[2]
    check("task title is HTML-escaped and worker can claim", b"&lt;" in detail and "领取任务".encode() in detail)
    check("worker A claims via browser", claim_task("T02", a, "web-claim-a")[0] == 303)
    _, first = current("T02", a)
    check("browser handoff records actual stop and notes", submit(a, "handoff", "web-handoff", **epoch_args(first),
          stop_evidence="Fixture worker stopped.", notes="交接记录")[0] == 303)
    check("worker B claims after browser handoff", claim_task("T02", b, "web-claim-b")[0] == 303)
    _, active = current("T02", b)
    check("new browser holder sees handoff material", "接续材料".encode() in request("/tasks/T02", headers=sessions[b])[2])
    first_bytes = b"first\r\n\x00binary\r\n"
    check("browser multipart upload seals revision one", upload(b, "web-upload-1", active, first_bytes)[0] == 303)
    _, sealed = current("T02", b)
    first_rev = sealed["deliveries"]["revision-1"]
    file_path = first_rev["manifest"]["path"].rsplit("/", 1)[0] + "/成果.md"
    check("multipart keeps non-ASCII name and exact bytes", request(
        "/download?" + urlencode({"path": file_path}), headers=sessions[receiver])[2] == first_bytes)
    check("other worker cannot download sealed files", request(
        "/download?" + urlencode({"path": file_path}), headers=sessions[a])[0] == 404)
    check("receiver can return exact revision for failed criterion", submit(
        receiver, "return", "web-return", claim_id=sealed["claim_id"], revision="revision-1",
        manifest_sha256=first_rev["manifest_sha256"], criterion="report-ready", reason="补齐资料结论")[0] == 303)
    _, returned = current("T02", b)
    check("retrying execution requires previous actual stop", submit(
        b, "resume", "web-resume-too-early", **epoch_args(returned))[0] == 409)
    check("worker records stop after return", submit(b, "stop", "web-stop-1", **epoch_args(returned),
          stop_evidence="Fixture stopped revision one.")[0] == 303)
    check("worker starts returned work with a new epoch", submit(
        b, "resume", "web-resume", **epoch_args(returned))[0] == 303)
    _, resumed = current("T02", b)
    check("previous epoch cannot upload again", resumed["epoch"] == returned["epoch"] + 1 and
          upload(b, "web-stale-upload", returned, b"late")[0] == 409)
    corrected = b"revised fixture output\n"
    check("browser uploads corrected revision", upload(b, "web-upload-2", resumed, corrected)[0] == 303)
    check("multipart retries ignore boundary changes", upload(
        b, "web-upload-2", resumed, corrected, boundary="NewFixtureBoundary")[0] == 303)
    _, sealed = current("T02", b)
    second = sealed["deliveries"]["revision-2"]
    evidence = {"path": second["manifest"]["path"].rsplit("/", 1)[0] + "/成果.md", "sha256": sha(corrected)}
    review_fields = {"claim_id": sealed["claim_id"], "revision": "revision-2",
                     "manifest_sha256": second["manifest_sha256"], "check_count": "1",
                     "criterion-0": "report-ready", "artifact-0": json.dumps(evidence),
                     "note-0": "修订已补齐资料结论"}
    check("worker cannot accept own revision through web", submit(b, "review", "web-self", **review_fields)[0] == 403)
    check("receiver accepts corrected evidence", submit(receiver, "review", "web-accept", **review_fields)[0] == 303)
    check("acceptance still requires actual stop before archive", submit(
        receiver, "close", "web-early-close", task_id="T02")[0] == 409)
    check("worker reports final stop", submit(b, "stop", "web-stop-2", **epoch_args(sealed),
          stop_evidence="Fixture stopped revision two.")[0] == 303)
    check("receiver closes and archives via browser", submit(
        receiver, "close", "web-close", task_id="T02")[0] == 303 and current("T02", b)[0]["status"] == "completed")
    detail = request("/tasks/T02", headers=sessions[receiver])[2]
    check("archive retains resolved finding and close evidence", "已解决".encode() in detail and "归档证据".encode() in detail)

    check("second browser registration", submit(receiver, "register", "web-cancel-task", **registration)[1]["Location"] == "/tasks/T03")
    check("claim task before cancellation", claim_task("T03", a, "web-claim-cancel")[0] == 303)
    task, old = current("T03", a)
    check("receiver requests cancellation with a reason", submit(receiver, "cancel", "web-cancel", task_id="T03",
          version=task["version"], reason="不再需要该资料")[0] == 303)
    task, ending = current("T03", a)
    check("cancellation retains occupation until holder stops", task["status"] == "running" and
          ending["E"]["state"] == "requested" and bool(ending["R"]) and claim_task("T03", b, "web-blocked-claim")[0] == 409)
    check("stop based on pre-cancel epoch is rejected", submit(a, "stop", "web-stale-stop", **epoch_args(old),
          stop_evidence="Stale fixture report")[0] == 409)
    check("holder stop finalizes cancellation and archives reason", submit(a, "stop", "web-cancel-stopped",
          **epoch_args(ending), stop_evidence="Fixture confirmed stopped.")[0] == 303 and
          current("T03", a)[0]["status"] == "cancelled" and "不再需要该资料".encode() in
          request("/tasks/T03", headers=sessions[receiver])[2])


def verify_accounts(url, tokens, admin):
    request, origin = browser_client(url)
    form = {"Origin": origin, "Content-Type": "application/x-www-form-urlencoded"}

    def post(path, cookie=None, **values):
        return request(path, "POST", {**form, **({"Cookie": cookie} if cookie else {})}, urlencode(values))

    def session(identity, token):
        status, headers, _ = post("/login", identity=identity, token=token)
        if status != 303:
            raise AssertionError("Account cannot log in")
        return headers["Set-Cookie"].split(";", 1)[0]

    def credential(page):
        return re.search(br'<code class="credential">([A-Za-z0-9_-]{43})</code>', page)[1].decode("ascii")

    owner = session("admin", admin["token"])
    worker = session("worker-a", tokens["worker-a"])
    check("public signup page explains invitations", request("/register")[0] == 200)
    check("ordinary worker cannot open account management", request("/accounts", headers={"Cookie": worker})[0] == 403)
    check("ordinary worker cannot issue invitations", post("/accounts", worker, role="executor", request_id="bad-invite")[0] == 403)
    check("admin role cannot be self-registered", post("/accounts", owner, role="admin", request_id="bad-role")[0] == 400)
    check("invalid invitation cannot register", post("/register", request_id="bad-signup",
          identity="intruder", invitation="a" * 43)[0] == 403)
    _, _, first = post("/accounts", owner, role="executor", request_id="invite-executor")
    invite = credential(first)
    _, _, replay = post("/accounts", owner, role="executor", request_id="invite-executor")
    check("retrying invitation creation returns the same code", credential(replay) == invite)
    check("invited signup cannot reuse existing identity case-insensitively", post("/register", request_id="name-conflict",
          identity="Worker-A", invitation=invite)[0] == 409)
    status, _, page = post("/register", request_id="register-executor", identity="worker-new", invitation=invite)
    check("invitation registers new executor immediately", status == 200)
    worker_token = credential(page)
    status, _, replay = post("/register", request_id="register-executor", identity="worker-new", invitation=invite)
    check("retrying signup returns the same credential", status == 200 and credential(replay) == worker_token)
    check("consumed invite cannot create another account", post("/register", request_id="reuse-invite",
          identity="other-worker", invitation=invite)[0] == 403)
    _, _, second = post("/accounts", owner, role="receiver", request_id="invite-receiver")
    status, _, page = post("/register", request_id="register-receiver", identity="reviewer-new", invitation=credential(second))
    check("invitation registers independent receiver", status == 200)
    receiver_token = credential(page)
    roster = request("/accounts", headers={"Cookie": owner})[2]
    check("admin can see new accounts without their credentials", b"worker-new" in roster and b"reviewer-new" in roster
          and worker_token.encode() not in roster and receiver_token.encode() not in roster)
    check("new receiver appears in admin task form", b"reviewer-new" in request("/tasks/new", headers={"Cookie": owner})[2])
    status, headers, _ = post("/actions/register", owner, request_id="admin-task",
                              title="新账号试用", brief="核对账号角色", criteria="approved", receiver="reviewer-new",
                              project="验收样例项目")
    check("admin assigns task to the new receiver", status == 303 and headers["Location"] == "/tasks/T04")
    task = call(url + "/tasks/T04", worker_token)[1]["task"]
    check("registered project belongs to the ledger task", task["related"] == {"project": "验收样例项目"})
    check("project is shown on board and task detail", all("验收样例项目".encode() in request(
        page, headers={"Cookie": owner})[2] for page in ("/", "/tasks/T04")))
    claim = {"task_id": "T04", "version": task["version"], "scope_version": task["scope_version"]}
    check("admin cannot claim tasks as executor", call(url + "/claim", admin["token"], body("admin-claim", **claim))[0] == 403)
    check("registered worker can claim with new token", call(url + "/claim", worker_token,
          body("new-worker-claim", **claim))[0] == 200 and task["receiver"] == "reviewer-new")
    check("registered receiver can log in with new token", session("reviewer-new", receiver_token).startswith("t22_local_session="))
    return worker_token, receiver_token


def fault_server(project, fault):
    # Test-only crash after a real applied decision and before advancing the journal.
    sys.path.insert(0, project)
    from pool.service import Service
    from taskpool import main

    original = Service.apply_step

    def crash(self, env, instruction, request, snap):
        result = original(self, env, instruction, request, snap)
        if env["command"] == fault and result[1]["result"] == "applied":
            os._exit(86)
        return result

    Service.apply_step = crash
    sys.argv = ["taskpool.py", "serve", "--port", "0"]
    return main()


def validate(project):
    init = ("init", "--worker", "worker-a", "--worker", "worker-b", "--receiver", "reviewer",
            "--authority", AUTHORITY)
    first = command(project, *init)
    check("real storage qualification", first["qualification_passed"] == 33)
    store = Path(first["store"])
    check("bootstrap replay", command(project, *init) == first)
    admin = command(project, "init-admin")
    check("admin token issued and initialization is repeatable",
          admin["identity"] == "admin" and len(admin["token"]) == 43 and command(project, "init-admin") == admin)
    tokens = json.loads(Path(first["credentials"]).read_bytes())["tokens"]
    a, b, reviewer = (tokens[key] for key in ("worker-a", "worker-b", "reviewer"))
    brief = project / "brief.md"
    brief.write_bytes("# 试用输入\n".encode())
    add = ("add-task", "--request-id", "register-01", "--title", "整理试用资料",
           "--input", brief, "--criterion", "report-ready")
    task = command(project, *add)["task"]
    check("task registration replay", command(project, *add)["task"] == task)
    tid = task["task_id"]
    version = {"task_id": tid, "version": task["version"], "scope_version": task["scope_version"]}
    compete = body("compete", **version)
    with server(project) as (process, url):
        check("authentication required", call(url + "/tasks")[0] == 401)
        verify_web(url, a, task["title"])
        check("only available tasks listed", call(url + "/tasks", a)[1]["tasks"] == [task])
        check("reviewer cannot claim", call(url + "/claim", reviewer, compete)[0] == 403)
        lock_test = subprocess.run([sys.executable, "-B", "-X", "utf8", str(project / "taskpool.py"),
                                    "serve", "--port", "0"], capture_output=True, timeout=10)
        check("second writer excluded", lock_test.returncode == 1 and "另一个进程" in lock_test.stderr.decode("utf-8"))
        with ThreadPoolExecutor(2) as clients:
            replies = list(clients.map(lambda token: call(url + "/claim", token, compete), [a, b]))
        check("two clients produce one claim and one conflict", sorted(status for status, _ in replies) == [200, 409])
        if replies[1][0] == 200:
            a, b = b, a
            replies.reverse()
        winner, loser = replies[0][1], replies[1][1]
        check("conflict returns current running task", loser["task"]["status"] == "running")
        check("claim receipt replay", call(url + "/claim", a, compete) == (200, winner))
        check("same id changed content rejected", call(url + "/claim", a, {**compete, "version": 99})[0] == 409)
        check("input bytes preserved", download(url, a, winner["initial_inputs"][0]) == brief.read_bytes())
        handoff = body("handoff", **claim_args(winner), stop_evidence="Synthetic worker stopped writing.")
        check("incomplete handoff preserves claim", call(url + "/handoff", a, handoff)[0] == 400)
        check("task remains occupied", call(url + "/tasks/" + tid, a)[1]["task"]["status"] == "running")
    handoff = {**handoff, "request_id": "handoff-fixed", "notes": "第一段已经整理，下一位补充结论。"}
    with server(project, "replace_claim") as (process, url):
        lost_response(process, url + "/handoff", a, handoff, "crash after replacement before stopped")

    with server(project) as (_, url):
        status, released = call(url + "/handoff", a, handoff)
        check("handoff recovered and replayed", status == 200 and
              [s["command"] for s in released["steps"]] == ["replace_claim", "stopped"] and
              released["claim"]["L"] == "ended" and released["claim"]["R"] == [])
        check("handoff replay stable", call(url + "/handoff", a, handoff) == (200, released))
        current = released["task"]
        check("available only after stop and release", current["status"] == "available")
        check("old claim generation rejected", call(url + "/deliver", a, body(
            "late-write", **claim_args(winner), package="", package_sha256="0" * 64))[0] == 409)
        resume = body("resume", task_id=tid, version=current["version"], scope_version=current["scope_version"])

    with server(project, "claim") as (process, url):
        lost_response(process, url + "/claim", b, resume, "claim committed before response is lost")

    with server(project) as (_, url):
        status, resumed = call(url + "/claim", b, resume)
        check("claim retry after process restart", status == 200 and resumed["claim"]["claim_id"] != winner["claim"]["claim_id"])
        check("resumed claim returns original input and handoff",
              resumed["initial_inputs"] == winner["initial_inputs"] and resumed["handoffs"] == [released["handoff"]])
        check("handoff contents recovered", json.loads(download(url, b, resumed["handoffs"][0]))["notes"] == handoff["notes"])
        check("claim reply stable", call(url + "/claim", b, resume) == (200, resumed))
        artifact = project / "report.md"
        artifact.write_bytes("# 独立端实际交付\n".encode())
        receipt = project / "claim.json"
        receipt.write_bytes(json.dumps(resumed).encode())
        package = project / "delivery.zip"
        info = command(project, "pack", "--claim", receipt, "--artifact", artifact, "--output", package)
        delivery = body("deliver", **claim_args(resumed), package=base64.b64encode(package.read_bytes()).decode(),
                        package_sha256=info["sha256"])
        bad = {**delivery, "request_id": "bad-digest", "package_sha256": "0" * 64}
        check("bad package hash rejected", call(url + "/deliver", b, bad)[0] == 400)
        with zipfile.ZipFile(package) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        invalid = project / "invalid.zip"
        with zipfile.ZipFile(invalid, "w") as archive:
            for name, raw in files.items():
                archive.writestr(name, raw)
            archive.writestr("../escape.md", "fixture")
        bad = {**delivery, "request_id": "zip-traversal", "package_sha256": sha(invalid.read_bytes()),
               "package": base64.b64encode(invalid.read_bytes()).decode()}
        check("ZIP traversal rejected", call(url + "/deliver", b, bad)[0] == 400)
        status, sealed = call(url + "/deliver", b, delivery)
        check("actual delivery verified and sealed", status == 200 and sealed["package_sha256"] == info["sha256"] and
              sealed["claim"]["deliveries"]["revision-1"]["payload_status"] == "verified")
        check("delivery replay stable", call(url + "/deliver", b, delivery) == (200, sealed))
        ref = sealed["claim"]["deliveries"]["revision-1"]["manifest"]
        data = json.loads(download(url, reviewer, ref))
        report = next(row for row in data["outputs"] if row["path"] == "report.md")
        report_ref = {"path": ref["path"].rsplit("/", 1)[0] + "/report.md", "sha256": report["sha256"]}
        check("reviewer downloads exact delivered bytes", download(url, reviewer, report_ref) == artifact.read_bytes())
        check("other worker cannot download delivery", call(url + "/artifact?" + urlencode({"path": report_ref["path"]}), a)[0] == 404)
        review = body("review", claim_id=resumed["claim"]["claim_id"], revision="revision-1",
                      manifest_sha256=ref["sha256"], checks=[{
                          **report_ref, "id": "report-ready", "note": "核对正文与冻结输入，满足资料整理判据。"}])
        check("self acceptance forbidden", call(url + "/review", b, review)[0] == 403)
        bad = {**review, "request_id": "wrong-revision", "manifest_sha256": "0" * 64}
        check("acceptance requires exact manifest hash", call(url + "/review", reviewer, bad)[0] == 409)
        status, accepted = call(url + "/review", reviewer, review)
        check("designated receiver accepts exact revision", status == 200 and accepted["claim"]["W"]["state"] == "complete")
        check("close blocked before actual stop", call(url + "/close", reviewer, body("too-early", task_id=tid))[0] == 409)
        status, stopped = call(url + "/stop", b, body(
            "stop", **claim_args(resumed), stop_evidence="Synthetic worker finished and released its delivery path."))
        check("actual stop releases reservations", status == 200 and stopped["claim"]["R"] == [] and
              stopped["claim"]["L"] == "ended" and stopped["task"]["status"] == "pending_close")
        status, closed = call(url + "/close", reviewer, body("close", task_id=tid))
        check("original ledger closes accepted task", status == 200 and closed["task"]["status"] == "completed")
        board = call(url + "/board", reviewer, raw=True)
        check("derived board reflects completion", board[0] == 200 and "已完成".encode() in board[1] and tid.encode() in board[1])
    sys.path.insert(0, str(project))
    import pool  # Add the bundled vendor path before loading the ledger.
    from 协作账本 import Ledger, cursor

    snap = Ledger(store).read()
    decisions = list(snap["control"]["terminal"].values())
    check("ledger replays without source gaps", snap["halted"] is None and all(
        cursor(snap, origin) == sum(entry["origin_id"] == origin for entry in decisions)
        for origin in snap["state"]["origins"]))
    check("claim and replacement each applied exactly once per intent",
          sum(e["command"] == "claim" and e["result"] == "applied" for e in decisions) == 2 and
          sum(e["command"] == "replace_claim" and e["result"] == "applied" for e in decisions) == 1)
    with server(project) as (_, url):
        verify_workflow(url, tokens)
        enrolled = verify_accounts(url, tokens, admin)
    with server(project) as (_, url):
        check("enrolled tokens survive service restart", all(call(url + "/tasks", token)[0] == 200
              for token in (admin["token"], *enrolled)))
    return {"qualification": first["qualification_passed"], "ledger_head": Ledger(store).read()["head"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="默认 dist/phase1-verification.json")
    args = parser.parse_args()
    args.report = args.report or report_path("phase1-verification.json")
    archive = ROOT / "dist" / "task-pool-local.zip"
    with scratch("verify-") as directory:
        project = Path(directory)
        with zipfile.ZipFile(archive) as package:
            package.extractall(project)
        result = validate(project)
    result.update(passed=len(CHECKS), failed=0, checks=CHECKS, artifact_sha256=sha(archive.read_bytes()),
                  backend="ntfs" if os.name == "nt" else "ext4")
    args.report.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{result['passed']} checks passed, {result['qualification']} {result['backend']} checks passed")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--fault-server":
        sys.exit(fault_server(sys.argv[2], sys.argv[3]))
    sys.exit(main())
