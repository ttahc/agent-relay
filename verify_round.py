"""Run the v3 scenarios on a disposable qualified task-pool store."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
from urllib.parse import urlencode
import zipfile

from verify import ROOT, browser_client, call, claim_args, command, server, sha
from verify_support import report_path, scratch
from verify_upgrade import Client as PreviousClient, PROJECT, capability, claim, control, register, review, seal, source

CASES = {}


def passed(case, detail, condition=True):
    assert condition, (case, detail)
    CASES[case] = {"status": "passed", "evidence": detail}
    print("PASS", case, detail, flush=True)


def request_id():
    return "v3-" + secrets.token_hex(16)


class Client(PreviousClient):
    def post(self, action, expect=200, request=None, **payload):
        return super().post(action, expect, request or request_id(), **payload)


class Browser:
    def __init__(self, url):
        self.request, self.origin = browser_client(url)
        self.cookies = {}
        self.csrf = None

    def send(self, path, method="GET", data=None, *, csrf=True, origin=None):
        headers = {}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if method == "POST":
            headers.update(Origin=origin or self.origin, **{"Content-Type": "application/x-www-form-urlencoded"})
            data = {**(data or {})}
            if csrf and self.csrf:
                data["csrf"] = self.csrf
            data = urlencode(data)
        status, response, page = self.request(path, method, headers, data)
        if cookie := response.get("Set-Cookie"):
            key, value = cookie.split(";", 1)[0].split("=", 1)
            if value:
                self.cookies[key] = value
            else:
                self.cookies.pop(key, None)
        match = re.search(rb'name="csrf" value="([a-f0-9]{64})"', page)
        if match:
            self.csrf = match[1].decode()
        return status, response, page

    def login(self, name, password, expected=303):
        self.send("/login")
        status, headers, page = self.send("/login", "POST",
                                          {"request_id": request_id(), "identity": name, "password": password})
        assert status in (expected if isinstance(expected, tuple) else (expected,)), (status, expected, page[:240])
        return headers


def password_record(browser, path, name, password, **fields):
    browser.send(path)
    return browser.send(path, "POST", {"request_id": request_id(), "identity": name, "password": password,
                                       "confirm": password, **fields})


def setup(project):
    initial = command(project, "init", "--worker", "worker-a", "--worker", "worker-b", "--receiver", "reviewer",
                      "--authority", "v3 isolated acceptance fixture")
    tokens = json.loads(Path(initial["credentials"]).read_bytes())["tokens"]
    tokens["admin"] = command(project, "init-admin")["token"]
    brief = project / "brief.md"
    brief.write_text("synthetic v3 input", encoding="utf-8")
    for n in (1, 2):
        command(project, "add-task", "--request-id", f"v3-legacy-{n}", "--title", f"Old {n}", "--input", brief, "--criterion", "ready")
    command(project, "upgrade-migrate", "--upgrade", "fixture-v2", "--image", "1" * 64)
    before = command(project, "inspect-store")
    command(project, "round-migrate", "--upgrade", "fixture-v3", "--image", "2" * 64)
    after = command(project, "inspect-store")
    passed("N01", "迁移保留原任务、输入、范围和待启动状态",
           before["tasks"] == after["tasks"] and before["window_high_water"] == after["window_high_water"] and
           not after["active_claims"] and after["format"]["schema"] == 3)
    password = "隔离验收 专用长密码 2026-Fixture!"
    secret_file = project / "fixture-password"
    secret_file.write_text(password, encoding="utf-8")
    try:
        command(project, "admin-recover", "--request-id", "fixture-admin-recover", "--password-file", secret_file)
    finally:
        secret_file.unlink()
    command(project, "maintenance", "off", "--request-id", "fixture-v3-open")
    return initial, tokens, password


def bind(admin, name, role):
    admin.post("identity-bind", name=name, kind="human", owner=name, reason="隔离用途映射", source=None)
    admin.post("project-grant", project_id=PROJECT, name=name, roles=[role], resources=[], version=0)


def browser_admin_api(project, b):
    # The offline recovery intentionally revoked the old admin bearer. In this fixture
    # use the real authenticated browser for administration and the same command dispatcher.
    class Admin:
        def post(self, action, expect=200, request=None, **payload):
            form = dict(payload)
            form["request_id"] = request or request_id()
            if action == "register":
                form["requirements"] = "\n".join(" | ".join([r["id"], r["kind"], r["value"],
                    "必需" if r["required"] else "优选", r["evidence"]]) for r in form["requirements"])
                form["criteria"] = "\n".join(form["criteria"])
                iteration = form.pop("iteration")
                form.update(iteration_goal=iteration["goal"], iteration_previous=",".join(iteration["previous"]),
                            iteration_next=",".join(iteration["next"]))
                if dispatch := form.pop("dispatch", None):
                    form.update(dispatch_mode=dispatch["mode"], dispatch_owner=dispatch["owner"],
                                dispatch_subjects=",".join(dispatch["subjects"]), dispatch_automation=dispatch["automation"],
                                dispatch_capabilities=json.dumps(dispatch["capabilities"]))
            for key in ("source", "resources", "dependencies", "report"):
                if key in form:
                    form[key] = json.dumps(form[key], ensure_ascii=False)
            if "roles" in form:
                form["roles"] = ",".join(form["roles"])
            status, headers, page = b.send("/actions/" + action, "POST", form)
            if expect == 200:
                assert status == 303, (action, status, page.decode()[-600:])
                return {"task": {"task_id": headers["Location"].rsplit("/", 1)[-1]}} if action == "register" else headers["Location"]
            assert status == expect, (action, status, expect)
            return {}

    return Admin()


def auth_checks(project, url, tokens, password):
    admin_browser = Browser(url)
    passed("N13", "离线管理员恢复后密码可用，原令牌已失效",
           admin_browser.login("admin", password)["Location"] == "/" and call(url + "/identity", tokens["admin"])[0] == 401)
    admin_browser.send("/")
    admin = browser_admin_api(project, admin_browser)
    for name, role in (("worker-a", "executor"), ("worker-b", "executor"), ("reviewer", "receiver")):
        bind(admin, name, role)

    worker_browser = Browser(url)
    result = password_record(worker_browser, "/password/setup", "worker-a", password, token=tokens["worker-a"])
    passed("N14", "旧人员账号用原凭据首次设密，保留既有调用身份",
           result[0] == 303 and call(url + "/identity", tokens["worker-a"])[0] == 200)
    worker_browser.login("worker-a", password)
    worker_browser.send("/")
    result = worker_browser.send("/logout", "POST", {"form": "missing"}, csrf=False)
    passed("N11", "v3 表单校验 CSRF，正确来源、退出与会话失效", result[0] == 403)
    result = worker_browser.send("/logout", "POST")
    assert result[0] == 303 and "Max-Age=0" in result[1]["Set-Cookie"]
    admin_browser.send("/accounts")
    issue = admin_browser.send("/accounts", "POST", {"request_id": request_id(), "role": "executor"})
    human_code = re.search(rb'class="credential">([A-Za-z0-9_-]{43})<', issue[2])[1].decode()
    person = Browser(url)
    assert password_record(person, "/register", "fixture-person", "passwordpassword", invitation=human_code)[0] == 400
    assert password_record(person, "/register", "fixture-person", password, invitation=human_code)[0] == 303
    person.login("fixture-person", password)
    passed("N07", "人员一次性邀请码注册、密码登录及阻止复用",
           password_record(Browser(url), "/register", "fixture-other", password, invitation=human_code)[0] == 403)
    passwd = "e\u0301cole  试用密码   NFC  检查 " + ("字" * 80)
    assert password_record(Browser(url), "/password/setup", "worker-b", passwd, token=tokens["worker-b"])[0] == 303
    import unicodedata
    Browser(url).login("worker-b", unicodedata.normalize("NFC", passwd))
    passed("N08", "弱密码被拒；Unicode NFC、空格和长密码实际登录")
    admin_browser.send("/accounts/reset")
    reset = admin_browser.send("/accounts/reset", "POST", {"request_id": request_id(), "identity": "fixture-person"})
    code = re.search(rb'class="credential">([A-Za-z0-9_-]{43})<', reset[2])[1].decode()
    new_password = "隔离验收 更换后的不同密码 New-Fruit!"
    assert password_record(Browser(url), "/password/reset", "fixture-person", new_password, reset=code)[0] == 303
    assert password_record(Browser(url), "/password/reset", "fixture-person", password, reset=code)[0] == 403
    assert person.send("/board.md")[0] == 303
    person.login("fixture-person", new_password)
    passed("N12", "一次性重置、旧会话失效、新密码登录")
    for i in range(5):
        Browser(url).login("unknown-fixture", "fixture wrong password", 401)
    Browser(url).login("unknown-fixture", "fixture wrong password", 429)
    passed("N10", "未知账号使用统一失败响应及持续退避")
    return admin_browser, admin, human_code


def invitation(browser, owner="admin", count=1):
    browser.send("/invitations")
    status, _, html = browser.send("/invitations", "POST", {
        "request_id": request_id(), "operation": "issue", "project_id": PROJECT, "owner": owner,
        "roles": "executor", "hours": "24", "count": str(count),
    })
    assert status == 200, (status, html.decode()[-600:])
    from html import unescape
    return json.loads(unescape(re.search(r'aria-label="AI 接入信息">([^<]+)</textarea>', html.decode())[1]))


def ai_prepare(url, invite, *, session=None, request=None, recovery=None):
    body = {"request_id": request or request_id(), "invite_id": invite["id"], "code": invite["code"],
            "recovery": recovery or secrets.token_urlsafe(32), "source": source(session or request_id())}
    return body, call(url + "/ai-prepare", data=body)


def activate(url, issued):
    status, value = call(url + "/ai-activate", issued["token"], {"request_id": request_id(),
                                                                "registration_id": issued["registration_id"]})
    assert status == 200 and value["status"] == "active", (status, value)
    return Client(url, issued["token"])


def enrollment_checks(url, b, human_code):
    invite = invitation(b, count=2)
    orig, (status, first) = ai_prepare(url, invite)
    assert status == 200 and first["status"] == "pending_activation"
    assert call(url + "/identity", first["token"])[0] == 401
    recovery = {k: orig[k] for k in ("invite_id", "request_id", "recovery")}
    recovered = call(url + "/ai-recover", data=recovery)
    assert recovered == (200, first)
    assert call(url + "/ai-recover", data={**recovery, "recovery": secrets.token_urlsafe(32)})[0] == 403
    altered = {**orig, "source": {**orig["source"], "model": "changed"}}
    assert call(url + "/ai-prepare", data=altered)[0] == 409
    passed("N24", "丢响应时仅用本地原请求信息安全取回，错误证明和改内容均拒绝")
    worker = activate(url, first)
    assert call(url + "/ai-recover", data=recovery)[1]["status"] == "active"
    assert "token" not in call(url + "/ai-recover", data=recovery)[1]
    activate(url, first)
    passed("N25", "激活确认可重试；激活后秘密恢复关闭")
    _, (status, second) = ai_prepare(url, invite)
    assert status == 200
    second_worker = activate(url, second)
    passed("N18", "相同平台和模型的独立窗口有唯一编号", first["window"] != second["window"])
    assert ai_prepare(url, {**invite, "code": human_code})[1][0] == 403
    assert ai_prepare(url, invite)[1][0] == 409
    assert "manager" not in worker.get("identity")["projects"][0]["roles"]
    passed("N16", "邀请码项目、角色和配额由服务绑定，人员邀请码不能兑换窗口")
    race = invitation(b)
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda _: ai_prepare(url, race)[1], range(2)))
    passed("N22", "两个客户端争用单次邀请，仅一个获得待激活窗口", sorted(status for status, _ in results) == [200, 409])
    b.send("/invitations")
    status, _, _ = b.send("/invitations", "POST", {"request_id": request_id(), "operation": "revoke", "invite_id": race["id"],
                                                   "reason": "撤销隔离测试邀请"})
    assert status == 200
    pending = next(value for status, value in results if status == 200)
    assert call(url + "/ai-activate", pending["token"], {"request_id": request_id(), "registration_id": pending["registration_id"]})[0] == 403
    passed("N21", "撤销阻止新兑换并保留已激活窗口独立凭据", ai_prepare(url, race)[1][0] == 409 and worker.get("identity"))
    return worker, second_worker, first, second, orig, invite


def post_browser(b, action, payload):
    data = {**payload, "operation": action, "request_id": request_id()}
    for k in ("tasks", "versions", "sources", "targets", "mapping", "metrics"):
        if k in data:
            data[k] = json.dumps(data[k], ensure_ascii=False)
    return b.send("/collaboration", "POST", data)


def workflow(url, b, admin, tokens, worker, other, first):
    a = Client(url, tokens["worker-a"])
    receiver = Client(url, tokens["reviewer"])
    for client, name in ((worker, first["executor_id"]), (a, "worker-a")):
        capability(client, name)
    fixture_tasks = []
    for mode, selected in (("open", []), ("prefer", [first["executor_id"]]), ("only", ["worker-a"])):
        registered = register(admin, "reviewer", dispatch={"mode": mode, "subjects": selected, "capabilities": [],
                                                    "automation": "notify", "owner": "admin"})
        task = a.get("tasks/" + registered["task_id"])["task"]
        control(admin, "task-publish", task)
        fixture_tasks.append(a.get("tasks/" + task["task_id"])["task"])
    normal, prefer, limited = fixture_tasks
    assert a.get("tasks/" + prefer["task_id"])["qualification"]["eligible"]
    assert worker.get("tasks/" + prefer["task_id"])["qualification"]["prioritized"]
    assert not worker.get("tasks/" + limited["task_id"])["qualification"]["eligible"]
    claim(worker, limited, 409)
    passed("N28", "公开、优先及限定三种规则同样约束页面和 API")
    claim(other, normal, 409)
    passed("N30", "未声明的必需能力不允许领取")
    events = worker.post("notices-poll", cursor=0)
    event = next(row for row in events["events"] if row["task_id"] == normal["task_id"])
    assert not event["auto"]
    worker.post("notice-ack", event_id=event["event_id"])
    worker.post("claim", 409, task_id=normal["task_id"], version=normal["version"],
                scope_version=normal["scope_version"], notice=event["event_id"])
    passed("N33", "通知已确认，默认仍不能自动领取")
    receipt = claim(worker, normal)
    proof = {"evidence": "启动隔离资料任务", **claim_args(receipt)}
    worker.post("run-report", state="started", **proof)
    worker.post("run-report", 409, state="started", **proof)
    old_run = worker.get("tasks/" + normal["task_id"])["claims"][0]
    assert old_run["run"]["state"] == "started"
    claim(worker, prefer, 409)
    worker.post("runner-settings", version=0, auto=False, limit=2, heartbeat=True, adapter="")
    second = claim(worker, prefer)
    handed = worker.post("handoff", **claim_args(receipt), notes="隔离接续内容", stop_evidence="已停止隔离工作")
    claim(worker, handed["task"], 200)
    # Restore a valid prior-work chain by closing this attempt in the test flow below.
    current = worker.get("tasks/" + normal["task_id"])
    new_claim = current["claims"][-1]
    assert new_claim["claim_id"] != receipt["claim"]["claim_id"]
    worker.post("deliver-files", 409, **claim_args(receipt), files=[{"name": "old.md", "content": "eA=="}])
    passed("N32", "接力后拒绝旧领取与旧代次的迟到写入")
    hand = worker.post("handoff", **claim_args({"claim": new_claim}), notes="转给独立窗口",
                       stop_evidence="隔离工作实际结束")
    successor = claim(a, hand["task"])
    assert successor["handoffs"]
    passed("N38", "接续者使用另一主体凭据，收到冻结接续资料")
    sealed = seal(a, successor)
    review(receiver, sealed)
    a.post("stop", **claim_args(successor), stop_evidence="隔离执行器已停止")
    closed = receiver.post("close", task_id=normal["task_id"])
    passed("N39", "独立验收、实际停止、资源释放及收口各有回执", closed["task"]["status"] == "completed")
    assert worker.get("tasks/" + prefer["task_id"])["claims"][-1]["L"] == "active"
    passed("N36", "同窗两个任务独立，接力和收口不影响另一领取")
    worker.post("handoff", **claim_args(second), notes="解除隔离试用领取", stop_evidence="隔离执行已结束")
    return normal, prefer, limited


def project_checks(url, b, admin, tokens, tasks):
    worker = Client(url, tokens["worker-a"])
    normal, prefer, limited = [worker.get("tasks/" + t["task_id"])["task"] for t in tasks]
    common = {"project_id": PROJECT, "reason": "隔离评估", "benefit": "减少重复任务", "cost": "一次归集",
              "risk": "核对原独有要求", "rollback": "保留历史与恢复说明"}
    b.send("/collaboration?project=" + PROJECT)
    draft = {**common, "id": "fixture-decision", "version": 0, "area": "窗口接入", "scope": "手机",
             "status": "effective", "replaces": "", "replaces_version": 0, "tasks": {}}
    assert post_browser(b, "decision-save", draft)[0] == 303
    assert post_browser(b, "decision-save", {**draft, "id": "fixture-desktop", "scope": "桌面"})[0] == 303
    assert post_browser(b, "decision-save", {**draft, "id": "fixture-conflict"})[0] == 409
    assert post_browser(b, "decision-save", {**draft, "id": "fixture-new", "replaces": "fixture-decision", "replaces_version": 1})[0] == 303
    passed("N40", "同范围冲突需明确替代，其他范围可独立有效")
    t1, t2 = prefer["task_id"], limited["task_id"]
    relation = {"project_id": PROJECT, "source": t1, "target": t2, "kind": "overlap", "output": "", "criterion": "",
                "reason": "只有部分目标相同", "versions": {t1: prefer["version"], t2: limited["version"]}}
    assert post_browser(b, "task-relation", relation)[0] == 303
    prefer = worker.get("tasks/" + t1)["task"]
    change = {**common, "kind": "merge", "sources": [t1], "targets": [t2],
              "mapping": [{"source": t1, "criterion": "ready", "target": t2, "target_criterion": "ready"}],
              "versions": {t1: prefer["version"], t2: limited["version"]}}
    assert post_browser(b, "change-open", {**change, "mapping": [{**change["mapping"][0], "criterion": "missing"}]})[0] == 409
    claim(worker, prefer)
    change["versions"][t1] = worker.get("tasks/" + t1)["task"]["version"]
    assert post_browser(b, "change-open", change)[0] == 303
    view = worker.get("collaboration?project=" + PROJECT)
    record = view["change"][-1]
    versions = {tid: worker.get("tasks/" + tid)["task"]["version"] for tid in (t1, t2)}
    assert post_browser(b, "change-finish", {"project_id": PROJECT, "id": record["id"], "versions": versions,
                                             "outcome": "apply", "reason": "隔离中提前提交"})[0] == 409
    pending = worker.get("tasks/" + t1)["claims"][-1]
    assert pending["E"]["state"] == "requested"
    worker.post("stop", **claim_args({"claim": pending}), stop_evidence="测试持有者实际停止")
    stopped = worker.get("tasks/" + t1)["claims"][-1]
    worker.post("handoff", **claim_args({"claim": stopped}), notes="已有工作随原任务保留", stop_evidence="测试持有者实际停止")
    versions[t1] = worker.get("tasks/" + t1)["task"]["version"]
    assert post_browser(b, "change-finish", {"project_id": PROJECT, "id": record["id"], "versions": versions,
                                             "outcome": "apply", "reason": "已核对无活动资源"})[0] == 303
    assert worker.get("tasks/" + t1)["task"]["status"] == "merged"
    passed("N42", "局部重合记录、要求承接与归并历史保留")
    passed("N43", "活动任务拆合先冻结和核实停止；缺原判据或仍占用时拒绝生效")
    result = worker.post("feedback-save", project_id=PROJECT, task_id=normal["task_id"], kind="feedback", title="隔离反馈",
                         details="上传步骤较多", impact="使用时间", evidence="", visibility="restricted", observed="fixture time")
    rid = result["record_id"]
    assert not Client(url, tokens["reviewer"]).get("collaboration?project=" + PROJECT)["feedback"]
    passed("N45", "AI／人员接口可登记反馈，受限证据不向其他成员暴露")
    updates = {"project_id": PROJECT, "id": rid, "linked_task": normal["task_id"], "duplicate": "", "reason": "核对任务及效果",
               "evidence": "隔离样本", "metrics": [], "lesson": "", "limits": ""}
    for ver, stage in enumerate(("accepted", "working", "review"), 1):
        assert post_browser(b, "feedback-update", {**updates, "version": ver, "status": stage})[0] == 303
    assert post_browser(b, "feedback-update", {**updates, "version": 4, "status": "verified",
            "metrics": [{"metric": "步骤", "before": 8, "after": 5, "unit": "步", "samples": 1, "direction": "lower"}],
            "lesson": "复用经过验证的表单", "limits": "同一任务流程"})[0] == 303
    passed("N46", "反馈关联任务并用实测指标闭环，样本不足仍待复看",
           worker.get("collaboration?project=" + PROJECT)["feedback"][0]["follow_up"] == "pending")


def automation_checks(project, url, admin, worker, first):
    import importlib.util
    spec = importlib.util.spec_from_file_location("round_client", project / "ops" / "round-client.py")
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    admin.post("project-automation", project_id=PROJECT, enabled="yes", version=0)
    worker.post("runner-settings", version=1, auto=True, limit=2, heartbeat=True, adapter="local-command")

    def new_task():
        registered = register(admin, "reviewer", dispatch={"mode": "only", "subjects": [first["executor_id"]],
                             "capabilities": [], "automation": "auto", "owner": "admin"})
        task = worker.get("tasks/" + registered["task_id"])["task"]
        control(admin, "task-publish", task)
        return worker.get("tasks/" + task["task_id"])["task"]

    task = new_task()
    rid = request_id()
    first_poll = worker.post("notices-poll", request=rid, cursor=0)
    assert first_poll == worker.post("notices-poll", request=rid, cursor=0)
    notice = next(e for e in first_poll["events"] if e["task_id"] == task["task_id"])
    worker.post("notice-retry", event_id=notice["event_id"])
    marker = project / "adapter-marker"
    program = project / "adapter.py"
    program.write_text("import json,sys\nfrom pathlib import Path\n"
                       "data=json.load(sys.stdin)\n"
                       "with Path(sys.argv[1]).open('a',encoding='utf-8') as file: file.write(data['task_id']+'\\n')\n",
                       encoding="utf-8")
    state = app.State(project / "window" / "credential")
    api = app.Pool(url.removesuffix("/v1"), None, allow_loopback=True)
    with state.exclusive():
        state.data = {"token": worker.token, "command": [sys.executable, str(program), str(marker)], "workdir": str(project)}
        state.save()
        result = app.run_once(state, api)
        assert result["status"] == "finished" and result["task_id"] == task["task_id"]
        assert app.run_once(state, api)["status"] == "idle"
    assert marker.read_text(encoding="utf-8").splitlines() == [task["task_id"]]
    active = worker.get("tasks/" + task["task_id"])["claims"][-1]
    assert active["run"]["state"] == "finished" and active["L"] == "active"
    worker.post("handoff", **claim_args({"claim": active}), notes="本机程序已退出", stop_evidence="真实隔离子进程已退出")
    control(admin, "task-hold", worker.get("tasks/" + task["task_id"])["task"])
    passed("N34", "真实本机执行入口仅启动一次；重复通知和已结束事件未重复启动")
    late = new_task()
    notice = next(e for e in worker.post("notices-poll", cursor=0)["events"] if e["task_id"] == late["task_id"])
    worker.post("notice-ack", event_id=notice["event_id"])
    control(admin, "task-hold", late)
    worker.post("claim", 409, task_id=late["task_id"], version=late["version"],
                scope_version=late["scope_version"], notice=notice["event_id"])
    passed("N37", "实际回执后暂停，过期通知的自动领取被拒绝")


def rotation_checks(url, browser, first):
    from html import unescape
    query = "/tokens/rotate?identity=" + first["executor_id"]
    _, _, form = browser.send(query)
    recovery = re.search(rb'name="recovery" value="([A-Za-z0-9_-]{43})"', form)[1].decode()
    rid = request_id()
    inputs = {"request_id": rid, "name": first["executor_id"], "version": "1", "recovery": recovery,
              "reason": "隔离测试轮换"}
    status, _, page = browser.send("/tokens/rotate", "POST", inputs)
    assert status == 200
    data = json.loads(unescape(re.search(rb'aria-label="[^"]+">([^<]+)</textarea>', page)[1].decode()))
    assert call(url + "/identity", first["token"])[0] == 200
    assert call(url + "/identity", data["token"])[0] == 401
    client = activate(url, data)
    assert call(url + "/identity", first["token"])[0] == 401
    passed("N15", "待确认轮换保留旧凭据，激活后立即撤销旧令牌且窗口编号不变",
           client.get("identity")["binding"]["window"] == first["window"])
    return data["token"]


def exercise(project):
    initial, tokens, password = setup(project)
    with server(project) as (_, url):
        b, admin, human = auth_checks(project, url, tokens, password)
        worker, other, first, second, orig, invite = enrollment_checks(url, b, human)
        tasks = workflow(url, b, admin, tokens, worker, other, first)
        project_checks(url, b, admin, tokens, tasks)
        automation_checks(project, url, admin, worker, first)
        current_token = rotation_checks(url, b, first)
    with server(project) as (_, url):
        Browser(url).login("unknown-fixture", "fixture wrong password", (401, 429))
        Browser(url).login("unknown-fixture", "fixture wrong password", 429)
        assert call(url + "/identity", current_token)[0] == 200
        assert call(url + "/identity", first["token"])[0] == 401
    import sqlite3
    database = project / ".state" / "local" / "http-journal.sqlite3"
    from contextlib import closing
    with closing(sqlite3.connect(database)) as db:
        stored = db.execute("SELECT algorithm,length(salt),n,r,p FROM person_passwords").fetchall()
        assert stored and all(row == ("scrypt", 16, 32768, 8, 3) for row in stored)
        assert db.execute("SELECT count(DISTINCT salt)=count(*) FROM person_passwords").fetchone()[0]
    passed("N09", "实际密码认证使用独立盐及固定 scrypt 参数")
    raw = database.read_bytes()
    for secret in (orig["recovery"], invite["code"], first["token"], second["token"], current_token, password, human):
        assert secret.encode() not in raw
    passed("N27", "认证和请求数据库未出现本轮测试密码、邀请码、恢复秘密和令牌明文")
    return initial["qualification_passed"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="默认 dist/verify_round.json")
    args = parser.parse_args()
    args.report = args.report or report_path("verify_round.json")
    archive = ROOT / "dist" / "task-pool-local.zip"
    with scratch("verify-round-") as name:
        with zipfile.ZipFile(archive) as package:
            package.extractall(name)
        qualification = exercise(Path(name))
    args.report.write_text(json.dumps({"cases": CASES, "artifact_sha256": sha(archive.read_bytes()),
                                       "backend": "ntfs" if os.name == "nt" else "ext4", "qualification": qualification},
                                      indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{len(CASES)} v3 isolation checks passed")


if __name__ == "__main__":
    main()
