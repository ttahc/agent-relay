"""Session-authenticated pages that submit the same commands as the HTTP API."""

import base64
import json
from email import policy
from email.parser import BytesParser
from html import escape, unescape
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
import re
import secrets
from threading import Lock
from time import monotonic
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from . import round_web, task_pages, upgrade_pages, workbench, workbench_pages
from .packages import ClientError, MAX_PACKAGE, strict_json
from .service import PUBLIC_ACTIONS


PATHS = {"/", "/login", "/logout", "/register", "/accounts", "/board.md", "/assets/taskpool.css", "/tasks/new", "/workspace-receipt"}
WORKBENCH_PATHS = {"/board", "/list"}
TASK_PATH = re.compile(r"/tasks/(T[0-9]{2,15})")
UPGRADE_PATHS = {"/projects", "/executors", "/nodes", "/capabilities", "/audit", "/upgrade"}
UPGRADE_DETAIL = re.compile(r"/(projects|executors)/([A-Za-z0-9_-]{1,80})")
WEB_ACTIONS = PUBLIC_ACTIONS - {"deliver"}
SESSION_AGE = 8 * 60 * 60
FILTERS = set(workbench.FILTER_KEYS)
SESSIONS_PER_ACTOR = 8
PAGE_HEADERS = (
    ("Content-Security-Policy", "default-src 'none'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),
    ("Referrer-Policy", "same-origin"),
)
STYLESHEET = Path(__file__).with_name("taskpool.css").read_bytes()


class Sessions:
    def __init__(self):
        self.lock = Lock()
        self.active = {}

    def actor(self, session_id, service):
        with self.lock:
            entry = self.active.get(session_id)
        if entry and entry[1] > monotonic() and service.session_version(entry[0]) == entry[2]:
            return entry[0]
        self.end(session_id)
        return None

    def create(self, actor, previous, credential):
        session_id = secrets.token_urlsafe(32)
        now = monotonic()
        with self.lock:
            self.active = {key: entry for key, entry in self.active.items() if entry[1] > now and key != previous}
            own = [key for key, entry in self.active.items() if entry[0] == actor]
            if len(own) >= SESSIONS_PER_ACTOR:
                del self.active[own[0]]
            self.active[session_id] = (actor, now + SESSION_AGE, credential)
        return session_id

    def end(self, session_id):
        with self.lock:
            self.active.pop(session_id, None)


def cookie_name(handler):
    name = "taskpool" if handler.server.is_round else "t22"
    return f"__Host-{name}_session" if handler.server.tls else f"{name}_local_session"


def session_cookie(handler, value, age):
    secure = "; Secure" if handler.server.tls else ""
    return ("Set-Cookie", f"{cookie_name(handler)}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}{secure}")


def session_id(handler):
    cookies = SimpleCookie()
    try:
        cookies.load(handler.headers.get("Cookie", ""))
    except CookieError:
        return None
    entry = cookies.get(cookie_name(handler))
    return entry.value if entry else None


def same_origin(handler):
    protocol = "https" if handler.server.tls else "http"
    expected = protocol + "://" + handler.headers["Host"].lower()
    origins = handler.headers.get_all("Origin", [])
    if origins:
        return origins == [expected]
    referers = handler.headers.get_all("Referer", [])
    if len(referers) != 1:
        return False
    try:
        source = urlsplit(referers[0])
    except ValueError:
        return False
    return source.scheme + "://" + source.netloc.lower() == expected


def html_page(title, body, status=200):
    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <link rel="stylesheet" href="/assets/taskpool.css">
</head>
<body>{body}</body>
</html>
"""
    return status, html.encode("utf-8"), "text/html; charset=utf-8", PAGE_HEADERS


def login(identity="", error="", status=200):
    feedback = f'<p class="form-error" role="alert">{escape(error)}</p>' if error else ""
    return html_page("登录 · 内网任务服务", f"""
<main class="login-shell">
  <section class="brand" aria-label="内网任务服务">
    <div class="brand-top"><span class="mark" aria-hidden="true">任务</span><span>内网协作</span></div>
    <div class="brand-content">
      <p class="brand-title">任务池</p>
      <p class="brand-description">自主领取资料任务，跟踪交付与验收进度。</p>
    </div>
    <p class="brand-footer">本机试用</p>
  </section>
  <section class="form-panel" aria-labelledby="login-title">
    <div>
      <h1 id="login-title">登录任务池</h1>
      <p class="muted intro">使用分配给你的身份和访问令牌。</p>
      {feedback}
      <form method="post" action="/login">
        <label for="identity">身份</label>
        <input id="identity" name="identity" type="text" value="{escape(identity, quote=True)}"
          placeholder="例如 worker-a" required maxlength="80" autocomplete="username"
          spellcheck="false" autocapitalize="none">
        <label for="token">访问令牌</label>
        <input id="token" name="token" type="password" placeholder="输入访问令牌"
          required maxlength="100" autocomplete="current-password">
        <button class="primary" type="submit">登录</button>
      </form>
      <p class="register-link"><a href="/register">使用邀请码注册账号</a></p>
    </div>
  </section>
</main>""", status)


def redirect(location, *headers):
    return 303, b"", "text/plain; charset=utf-8", (("Location", location), *PAGE_HEADERS, *headers)


def matches(target):
    from .execution_pages import PATH as execution_path
    if execution_path.fullmatch(target.path):
        return True
    if target.path == "/workspace-receipt":
        return True
    if target.path in round_web.PATHS or target.path in WORKBENCH_PATHS or target.path == "/":
        return True
    if target.path == "/download":
        return True
    if target.path in UPGRADE_PATHS or UPGRADE_DETAIL.fullmatch(target.path):
        return True
    if target.path == "/tasks/new" and target.query:
        return True
    if target.query:
        return False
    if target.path.startswith("/actions/"):
        return target.path.removeprefix("/actions/") in WEB_ACTIONS
    return target.path in PATHS or TASK_PATH.fullmatch(target.path) is not None


def parse_form(handler, limit, max_fields, multi=()):
    raw = handler.request_body("application/x-www-form-urlencoded", limit + (96 if handler.server.is_round else 0))
    try:
        fields = parse_qs(raw.decode("utf-8"), keep_blank_values=True, strict_parsing=True,
                          encoding="utf-8", errors="strict", max_num_fields=max_fields + int(handler.server.is_round) + 1)
    except ValueError as error:
        raise ClientError("表单格式无效") from error
    if any(len(values) != 1 for key, values in fields.items() if key not in multi):
        raise ClientError("表单包含重复字段")
    data = {key: values if key in multi else values[0] for key, values in fields.items()}
    round_web.verify_form(handler, data)
    record_web_request(handler, data)
    return data


def uploads(handler):
    boundary = handler.headers.get_param("boundary")
    if not isinstance(boundary, str) or not re.fullmatch(r"[A-Za-z0-9._+-]{1,70}", boundary):
        raise ClientError("上传表单边界无效")
    raw = handler.request_body("multipart/form-data", MAX_PACKAGE)
    mime = f"Content-Type: multipart/form-data; boundary={boundary}\r\n\r\n".encode("ascii")
    message = BytesParser(policy=policy.default).parsebytes(mime + raw)
    parts = list(message.iter_parts())
    if message.defects or len(parts) > 15 + 2 * int(handler.server.is_round):
        raise ClientError("上传表单格式或文件数量无效")
    data, files = {}, []
    for part in parts:
        name = part.get_param("name", header="content-disposition")
        if (part.defects or part.get_content_disposition() != "form-data" or part.is_multipart()
                or part.get("Content-Transfer-Encoding") or not name):
            raise ClientError("上传字段格式无效")
        content, filename = part.get_payload(decode=True), part.get_filename()
        if not isinstance(content, bytes):
            raise ClientError("上传字段没有有效内容")
        if name == "artifact" and filename:
            files.append({"name": filename, "content": base64.b64encode(content).decode("ascii")})
        elif (name in {"request_id", "claim_id", "epoch", "scope_version", "supersedes_request_id"} or name in {"csrf", "stop_evidence"} and handler.server.is_round
              ) and filename is None and name not in data:
            try:
                data[name] = content.decode("utf-8")
            except UnicodeError as error:
                raise ClientError("上传字段编码无效") from error
        else:
            raise ClientError("上传字段或文件名无效")
    round_web.verify_form(handler, data)
    record_web_request(handler, data)
    return {**data, "files": files}


def record_web_request(handler, data):
    previous = data.pop("supersedes_request_id", None)
    if previous is not None:
        if not isinstance(previous, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", previous):
            raise ClientError("关联原请求编号无效", 400)
        handler.web_supersedes_request_id = previous
    request_id = data.get("request_id")
    if request_id:
        claimed = getattr(handler, "headers", {}).get("X-TaskPool-Request-ID")
        if claimed and claimed != request_id:
            raise ClientError("网页请求编号不匹配，请保留原请求核对", 400)
        handler.web_request_id = request_id


def reauthenticate(handler, actor):
    """Recheck the HTTP-bound identity after reading a POST body, inside caller's lock."""
    binding = getattr(getattr(handler.server.service, "pinned", None), "authentication", None)
    if binding and (binding[0] != actor or binding[1]() != actor):
        raise ClientError("登录或授权主体已变化，请重新认证后核对原请求。", 401)


def json_web_response(handler, response, path):
    """Keep native forms compatible while fetch clients retain their original DOM."""
    if handler.headers.get("X-TaskPool-Response") != "json":
        return response
    status, body, kind = response[:3]
    headers = response[3] if len(response) == 4 else ()
    location = next((value for name, value in headers if name.lower() == "location"), None)
    request_id = getattr(handler, "web_request_id", None) or handler.headers.get("X-TaskPool-Request-ID", "")
    successful_login_redirect = bool(getattr(handler, "web_operation_completed", False))
    expired = location == "/login" and not successful_login_redirect
    code = 401 if expired else 200 if status == 303 else status
    state = "pending" if code in {202, 429, 503} else "completed" if 200 <= code < 300 else "rejected"
    result = getattr(handler, "web_action_result", {})
    received = state == "completed" or bool(result.get("request_id") == request_id and result.get("status") in {"applied", "pending", "rejected"})
    value = {"status": code, "request_id": request_id, "state": state,
             "received": received if state == "completed" or result else None, "csrf": getattr(handler, "form_token", None)}
    if state == "completed":
        if location:
            value["redirect_url"] = location
        elif kind.startswith("text/html"):
            value["html"] = body.decode("utf-8") if isinstance(body, bytes) else body
    else:
        text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
        found = re.search(r'<p\b[^>]*(?:role=["\'](?:alert|status)["\']|class=["\'][^"\']*form-error)[^>]*>(.*?)</p>', text, re.S)
        value["message"] = unescape(re.sub("<[^>]+>", "", found[1])).strip() if found else (
            "登录或授权已变化，请在新页面重新登录后查询原请求。" if expired else "操作尚未确认，请核对原请求后重试。")
    kept = tuple((name, item) for name, item in headers if name.lower() not in {"location", "content-type", "content-length"})
    return code, json.dumps(value, ensure_ascii=False).encode(), "application/json; charset=utf-8", (*kept, ("Cache-Control", "no-store"))


def workspace_receipt(handler, target):
    service = handler.server.service
    try:
        values = parse_qs(target.query, strict_parsing=True, max_num_fields=2)
        if not values.keys() <= {"request", "path"} or any(len(value) != 1 for value in values.values()):
            raise ValueError()
        request_id = values.get("request", [""])[0]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", request_id):
            raise ValueError()
    except ValueError as error:
        raise ClientError("原请求查询参数无效", 400) from error
    with service.lock:
        actor = handler.server.sessions.actor(session_id(handler), service)
        if not actor:
            value, status = {"state": "rejected", "message": "请先在新页面登录，再恢复原请求。"}, 401
        else:
            try:
                result = service.read(actor, "receipt", request_id)
                original = result.get("status")
                state = "completed" if original == "applied" else "pending" if original == "pending" else "rejected"
                value = {"state": state, "received": True}
                if state == "completed" and isinstance(result.get("task"), dict) and result["task"].get("task_id"):
                    value["redirect_url"] = "/tasks/" + quote(result["task"]["task_id"])
                if state == "rejected":
                    steps = result.get("steps") or []
                    value["message"] = result.get("message") or (steps[-1].get("reason") if steps else "原请求已被拒绝，修正时须使用关联的新请求编号。")
                status = 202 if state == "pending" else 200
            except ClientError as error:
                if error.status == 404:
                    value, status = {"state": "not_received", "received": False}, 200
                else:
                    value, status = {"state": "rejected", "received": None, "message": str(error)}, error.status
            value["csrf"] = getattr(handler, "form_token", None)
    value.update(status=status, request_id=request_id)
    return status, json.dumps(value, ensure_ascii=False).encode(), "application/json; charset=utf-8", (("Cache-Control", "no-store"),)


def action_body(handler, action):
    data = uploads(handler) if action == "deliver-files" else parse_form(handler, 1024 * 1024, 100,
                                                                 {"depends_on"} if action == "register" else ())
    from .execution_pages import ACTIONS as execution_actions, body as execution_body
    if action in execution_actions:
        return execution_body(action, data)
    if action in {"claim", "resume"}:
        actor = round_web.current_actor(handler)
        if actor and handler.server.service.read(actor, "features").get("execution_protocol") == 5:
            data["execution_protocol"] = 5
        selected = data.pop("context_ref", "")
        if selected:
            try:
                identity, version = selected.rsplit(":", 1)
                data.update(context_id=identity, context_version=int(version))
            except (ValueError, TypeError) as error:
                raise ClientError("本次工作回合的配置版本无效，请重新选择", 400) from error
    if action == "register" and data.pop("quick", "") == "1":
        quick_registration(handler, data)
    if action == "return" and data.pop("criteria_form", "") == "1":
        picked = [data.pop(key) for key in sorted(data) if key.startswith("failed-")]
        if not picked:
            raise ClientError("请勾选至少一条未通过的判据")
        data.update(criterion=picked[0], criteria=picked)
    if action in {"review", "executor-complete"} and "finish" in data:
        data["finish"] = data["finish"] == "1"
    for key in ("version", "scope_version", "epoch"):
        if key in data:
            if not re.fullmatch(r"[0-9]{1,10}", data[key]):
                raise ClientError("任务版本或执行代次无效")
            data[key] = int(data[key])
    if action == "register":
        data["criteria"] = [line.strip() for line in data.get("criteria", "").splitlines() if line.strip()]
        if not data.get("project", "").strip():
            data.pop("project", None)
    if action in {"register", "task-scope"} and "project_id" in data:
        rows = []
        for line in data.pop("requirements", "").splitlines():
            if not line.strip():
                continue
            parts = [part.strip() for part in line.split("|")]
            if len(parts) != 5 or parts[3] not in {"必需", "优选"}:
                raise ClientError("每行须填写五列领取能力要求")
            key, kind, value, necessity, evidence = parts
            rows.append({"id": key, "kind": kind, "value": value, "required": necessity == "必需", "evidence": evidence})
        data["requirements"] = rows
        data["iteration"] = {"goal": data.pop("iteration_goal", ""),
                             "previous": split_items(data.pop("iteration_previous", "")),
                             "next": split_items(data.pop("iteration_next", ""))}
    if action in {"register", "task-scope", "project-grant", "identity-bind", "release-accept"}:
        for key in ("resources", "dependencies", "source", "report"):
            if key in data:
                data[key] = strict_json(data[key].encode("utf-8"))
    if action in {"project-grant", "executor-enroll"}:
        data["roles"] = split_items(data.get("roles", ""))
    if action in {"register", "task-scope"} and "dispatch_mode" in data:
        data["dispatch"] = {"mode": data.pop("dispatch_mode"), "subjects": split_items(data.pop("dispatch_subjects", "")),
                            "capabilities": strict_json(data.pop("dispatch_capabilities", "[]").encode("utf-8")),
                            "automation": data.pop("dispatch_automation"), "owner": data.pop("dispatch_owner", "")}
    if action == "project-automation":
        data["enabled"] = data["enabled"] == "yes"
    if action == "identity-bind" and data.get("kind") == "human":
        data["owner"] = data.get("owner") or data.get("name", "")
    if action == "executor-enroll":
        data["source"] = {key: data.pop(key, "") for key in
                          ("platform", "session", "model", "environment", "device", "directory", "url", "parent")}
        if "window_name" in data:
            data["source"]["window_name"] = data.pop("window_name")
        data["source"]["parent"] = data["source"]["parent"] or None
    if action == "capability-save":
        issued, days = data.pop("issued", ""), data.pop("valid_days", "")
        if not re.fullmatch(r"[0-9]{1,10}", issued) or not re.fullmatch(r"[0-9]{1,3}", days):
            raise ClientError("有效期格式无效")
        data["expires"] = int(issued) + int(days) * 86400
        data["evidence"] = {"note": data.pop("evidence_note", ""), "sha256": data.pop("evidence_sha256", "")}
    if action in {"review", "executor-complete"}:
        count = data.pop("check_count", "")
        if not re.fullmatch(r"(?:[1-9]|[12][0-9]|30)", count):
            raise ClientError("验收判据数量无效")
        checks = []
        for index in range(int(count)):
            ref = strict_json(data.pop(f"artifact-{index}", "").encode("utf-8"))
            if not isinstance(ref, dict) or set(ref) != {"path", "sha256"}:
                raise ClientError("须为每条判据选择核验文件")
            checks.append({**ref, "id": data.pop(f"criterion-{index}", ""),
                           "note": data.pop(f"note-{index}", "")})
        data["checks"] = checks
    return data


def quick_registration(handler, data):
    """Expand the short task form into the same fields the full contract form posts."""
    handler.open_now = data.pop("open_now", "") == "1"
    rows = []
    for key in sorted(data):
        if key.startswith("cap-"):
            choice = data.pop(key)
            if choice:
                kind, level = choice.split(":", 1) if ":" in choice else ("", "")
                rows.append(f"{key[4:]} | {kind} | * | 必需 | {level}")
    if new := data.pop("cap_new", "").strip():
        rows.append(f"{new} | skill | * | 必需 | declared")
    mode = data.get("dispatch_mode", "open")
    if mode == "open":
        data["dispatch_subjects"] = ""
    elif not data.get("dispatch_subjects"):
        raise ClientError("优先通知或只给某人时，请选择指定对象")
    dependencies = []
    choices = data.pop("depends_on", [])
    choices = choices if isinstance(choices, list) else [choices]
    for choice in choices:
        try:
            selected = strict_json((choice or "[]").encode("utf-8"))
        except (ValueError, TypeError) as error:
            raise ClientError("前置任务选项无效，请重新选择") from error
        if not isinstance(selected, list) or any(not isinstance(item, dict) for item in selected):
            raise ClientError("前置任务选项无效，请重新选择")
        if len(selected) > 30:
            raise ClientError("前置判据最多 30 条，请减少所选前置任务")
        for item in selected:
            if item not in dependencies:
                if len(dependencies) == 30:
                    raise ClientError("前置判据最多 30 条，请减少所选前置任务")
                dependencies.append(item)
    data.update(kind="documentation", requirements="\n".join(rows), iteration_goal=data.get("title", ""), iteration_previous="",
                iteration_next="", delivery="按任务说明交付", resources="[]", dependencies=json.dumps(dependencies, ensure_ascii=False),
                review_mode="source", user_basis="", dispatch_capabilities="[]", dispatch_automation="notify")


def split_items(text):
    return [item.strip() for item in text.replace("，", ",").split(",") if item.strip()]


def operation_message(actor, status, message, request_id=""):
    receipt = f'<p class="muted intro">请求编号 {escape(request_id)}</p>' if request_id else ""
    return html_page("操作结果 · 内网任务服务", task_pages.workspace(actor, f"""<section class="task-panel">
  <h1>{"操作待确认" if status in {202, 503} else "操作未完成"}</h1>
  <p class="form-error intro" role="alert">{escape(message)}</p>
  {receipt}
  <a class="secondary" href="/">返回任务看板</a>
</section>"""), status)


def submit_action(handler, actor, action):
    if not same_origin(handler):
        return operation_message(actor, 403, "请从当前任务页重新提交。")
    try:
        body = action_body(handler, action)
        server = handler.server
        with server.service.lock:
            reauthenticate(handler, actor)
            if server.sessions.actor(session_id(handler), server.service) != actor:
                return redirect("/login")
            status, result = server.service.submit(actor, action, body.get("request_id"), body,
                                                   authorize=lambda: server.sessions.actor(session_id(handler), server.service))
            handler.web_action_result = result
    except ClientError as error:
        return operation_message(actor, error.status, str(error))
    if status == 200:
        from .execution_pages import ACTIONS as execution_actions
        if action in execution_actions:
            return redirect("/executors/" + quote(actor) + "/execution")
        if result.get("token"):
            account = escape(result["account"])
            token = escape(result["token"])
            window = escape(result.get("window", ""))
            return html_page("访问凭据 · 内网任务服务", upgrade_pages.panel(actor, "访问凭据",
                             f'<p>{account} {window}</p><code class="credential">{token}</code>'))
        if result.get("task"):
            task = result["task"]
            if action == "register" and getattr(handler, "open_now", False):
                # A failed publish leaves a draft; the task page then shows why it is still closed.
                server.service.submit(actor, "task-publish", body["request_id"] + "-open", {
                    "request_id": body["request_id"] + "-open", "task_id": task["task_id"], "version": task["version"],
                    "scope_version": task["scope_version"], "reason": "登记时开放"},
                    authorize=lambda: server.sessions.actor(session_id(handler), server.service))
            return redirect("/tasks/" + task["task_id"])
        if action.startswith("release-"):
            return redirect("/upgrade")
        if action.startswith("executor-"):
            return redirect("/executors")
        if action == "capability-save":
            return redirect("/capabilities?" + urlencode({"identity": body["name"]}))
        if action in {"identity-bind", "credential-change"}:
            return redirect("/accounts")
        if body.get("project_id"):
            tab = {"project-grant": "?tab=members", "project-save": "?tab=settings", "project-automation": "?tab=settings"}.get(action, "") if server.is_round else ""
            return redirect("/projects/" + quote(body["project_id"]) + tab)
        return redirect("/")
    steps = result.get("steps", [])
    message = result.get("message") or (steps[-1]["reason"] if steps else "")
    if status in {202, 503}:
        message = (message + " " if message else "") + "请刷新当前页并确认重新发送原表单。"
    return operation_message(actor, status, message or "请回任务页检查当前状态。", body["request_id"])


def registration_page(message="", status=200):
    warning = f'<p class="form-error" role="alert">{escape(message)}</p>' if message else ""
    return html_page("注册账号 · 内网任务服务", f"""<main class="workspace narrow">
  <section class="task-panel">
    <h1>注册账号</h1>
    <p class="muted intro">输入管理员提供的一次性邀请码。账号角色由邀请码决定。</p>
    {warning}
    <form class="operation" action="/register" method="post">
      {task_pages.hidden("request_id", "signup-" + secrets.token_hex(16))}
      <label>身份<input name="identity" required maxlength="80"
        autocomplete="username" autocapitalize="none" spellcheck="false" placeholder="例如 worker-c"></label>
      <label>邀请码<input name="invitation" type="password" required maxlength="43" autocomplete="off"></label>
      <button class="primary" type="submit">注册账号</button>
    </form>
    <p class="register-link"><a href="/login">返回登录</a></p>
  </section>
</main>""", status)


def register_account(handler, method):
    if method == "GET":
        return registration_page()
    if not same_origin(handler):
        return registration_page("请从当前注册页重新提交。", 403)
    try:
        data = parse_form(handler, 1024, 3)
        if set(data) != {"request_id", "identity", "invitation"}:
            raise ClientError("请填写身份和邀请码。")
        status, result = handler.server.service.signup(data["request_id"], data["identity"].strip(),
                                                       data["invitation"].strip())
    except ClientError as error:
        return registration_page(str(error), error.status)
    if status != 200:
        if status in {202, 503}:
            return html_page("注册待确认 · 内网任务服务", """<main class="workspace narrow"><section class="task-panel">
  <h1>注册待确认</h1><p class="intro">请刷新当前页并确认重新发送原表单。</p>
</section></main>""", status)
        return registration_page(result.get("message") or "注册未完成，请核对邀请码与身份。", status)
    return html_page("注册成功 · 内网任务服务", f"""<main class="workspace narrow">
  <section class="task-panel">
    <h1>注册成功</h1><p class="muted intro">请保存访问令牌，再用它登录。</p>
    <p>身份　<strong>{escape(result["identity"])}</strong></p>
    <code class="credential">{escape(result["token"])}</code>
    <a class="primary" href="/login">前往登录</a>
  </section>
</main>""")


def account_page(handler, actor, method):
    service = handler.server.service
    code = ""
    try:
        roster = service.read(actor, "accounts")
        if method == "POST":
            if not same_origin(handler):
                raise ClientError("请从当前账号管理页重新提交。", 403)
            data = parse_form(handler, 1024, 2)
            if set(data) != {"request_id", "role"}:
                raise ClientError("请选择邀请码角色。")
            code = service.invite(actor, data["request_id"], data["role"])
    except ClientError as error:
        return operation_message(actor, error.status, str(error))
    roles = {"admin": "管理员", "receiver": "接收者", "executor": "执行者"}
    names = "".join(f"<li>{escape(name)} <span class='status'>{roles[role]}</span></li>" for name, role in roster)
    invitation = (f'<div class="intro"><p>请把<a href="/register">注册入口</a>和邀请码交给对应用户。'
                  f'邀请码 24 小时有效，使用一次后失效。</p><code class="credential">{escape(code)}</code></div>'
                  if code else "")
    controls = ""
    if handler.server.is_round:
        form = (f'<form class="operation" action="/accounts" method="post">{task_pages.hidden("request_id", "invite-" + secrets.token_hex(16))}'
                '<label>人员注册预设<select name="role" required><option value="executor">执行权限</option><option value="receiver">验收权限</option></select></label>'
                '<button class="primary" type="submit">生成邀请码</button></form>')
        links = '<p class="muted-text"><a href="/accounts/reset">签发密码重置凭据</a></p>'
        return html_page("账号管理 · 内网任务服务", workbench_pages.accounts_page(actor, service.read(actor, "account-table"), form, invitation, links + controls))
    return html_page("账号管理 · 内网任务服务", task_pages.workspace(actor, f"""<section class="task-panel">
  <h1>账号管理</h1>
  {invitation}
  <form class="operation" action="/accounts" method="post">
    {task_pages.hidden("request_id", "invite-" + secrets.token_hex(16))}
    <label>邀请码角色<select name="role" required>
      <option value="executor">执行者</option><option value="receiver">接收者</option>
    </select></label>
    <button class="primary" type="submit">生成邀请码</button>
  </form>
  <section class="detail-group"><h2>已登记账号</h2><ul class="roster">{names}</ul></section>
  {controls}
</section>"""))


def upgrade_view(service, actor, target):
    path = target.path
    profile = service.read(actor, "identity")
    workspace = service.round_enabled()
    if path == "/projects":
        if workspace:
            return "项目", workbench_pages.project_index(actor, service.read(actor, "project-cards"), service.read(actor, "overview")["tasks"], service.is_admin(actor))
        return "项目", upgrade_pages.project_index(actor, profile["projects"], service.is_admin(actor))
    if path.startswith("/projects/"):
        project = service.read(actor, "project", path.split("/")[-1])
        tasks = service.read(actor, "overview", project["id"])["tasks"]
        if workspace:
            tab = parse_qs(target.query).get("tab", [""])[0]
            return "项目", workbench_pages.project_page(actor, project, tasks, service.read(actor, "activity"), tab)
        return "项目", upgrade_pages.project_page(actor, project, tasks)
    if path == "/executors" and workspace:
        from . import window_entries_pages
        return "窗口管理", window_entries_pages.banner(service, actor) + workbench_pages.windows_page(
            actor, profile, service.read(actor, "window-cards")["executors"], service.read(actor, "overview")["tasks"],
            parse_qs(target.query).get("archived") == ["1"])
    if path == "/nodes":
        if not workspace:
            raise ClientError("节点总览需要本轮工作台", 404)
        from . import nodes, window_entries_pages
        return "节点总览", nodes.page(actor, service.read(actor, "nodes"), window_entries_pages.banner(service, actor))
    if path == "/executors":
        return "窗口目录", upgrade_pages.executor_index(actor, profile, service.read(actor, "executors")["executors"], service.round_enabled())
    if path.startswith("/executors/"):
        name = path.split("/")[-1]
        item = next((item for item in service.read(actor, "executors")["executors"] if item["executor_id"] == name), None)
        if not item:
            raise ClientError("执行端不存在或无权查看", 404)
        return "窗口详情", upgrade_pages.executor_page(actor, item)
    if path == "/capabilities":
        from .httpd import parse_query
        query = parse_query(target.query, {"identity"})
        return "能力与证据", upgrade_pages.capability_page(actor, profile, service.read(actor, "capabilities", query.get("identity")))
    if path == "/audit":
        values = parse_qs(target.query, max_num_fields=4)
        if not values.keys() <= {"task", "actor", "request", "who"} or any(len(v) != 1 for v in values.values()):
            raise ClientError("追溯查询参数无效")
        who = values.pop("who", [""])[0]
        query = {key: value[0] for key, value in values.items()}
        if workspace:
            return "动态", workbench_pages.activity_page(actor, service.read(actor, "activity"), who, query, service.read(actor, "audit", query) if query else {})
        return "状态追溯", upgrade_pages.audit_page(actor, query, service.read(actor, "audit", query) if query else {})
    if not service.is_admin(actor):
        if parse_qs(target.query).get("migration") == ["1"]:
            raise ClientError("只有系统管理员可使用迁移运维工具", 403)
        return "升级验收", upgrade_pages.release_page(actor, service.read(actor, "upgrade"))
    return "运维工具", upgrade_pages.operations_page(actor, service.read(actor, "upgrade"),
                                                       parse_qs(target.query).get("migration") == ["1"])


def dispatch(handler, method, target):
    if handler.server.is_round:
        return round_web.wrap(handler, method, target, dispatch_core)
    return dispatch_core(handler, method, target)


def dispatch_core(handler, method, target):
    server = handler.server
    service = server.service
    path = target.path
    if path == "/workspace-receipt" and method == "GET":
        return workspace_receipt(handler, target)
    if method == "GET" and path == "/assets/taskpool.css":
        return 200, STYLESHEET, "text/css; charset=utf-8"
    current = session_id(handler)
    actor = server.sessions.actor(current, service)
    if method == "GET" and path in {"/", "/login"}:
        return home_page(handler, target, actor)
    if method == "GET" and path == "/board.md":
        if not actor:
            return redirect("/login")
        return 200, server.service.read(actor, "board"), "text/markdown; charset=utf-8", (
            ("Content-Disposition", 'attachment; filename="task-board.md"'), *PAGE_HEADERS,
        )
    if method == "POST" and path in {"/login", "/logout"}:
        return session_change(handler, path, current)
    if path == "/register" and method in {"GET", "POST"}:
        return register_account(handler, method)
    if not actor:
        return redirect("/login")
    if path == "/accounts" and method in {"GET", "POST"}:
        return account_page(handler, actor, method)
    if method == "GET" and server.is_round and path in WORKBENCH_PATHS:
        query = filter_query(target, bool(target.query))
        data = service.read(actor, "overview", query.get("project"))
        if path == "/board":
            return html_page("任务看板 · 内网任务服务", workbench.board(actor, data, query))
        return html_page("列表 · 内网任务服务", workbench.list_page(actor, data, query, service.read(actor, "activity")))
    if method == "GET" and (path in UPGRADE_PATHS or UPGRADE_DETAIL.fullmatch(path)):
        try:
            title, content = upgrade_view(service, actor, target)
        except (ClientError, ValueError) as error:
            return operation_message(actor, error.status if isinstance(error, ClientError) else 400, str(error))
        return html_page(title + " · 内网任务服务", content)
    if method == "GET" and path == "/tasks/new":
        return new_task_page(handler, target, actor)
    if method == "GET" and (match := TASK_PATH.fullmatch(path)):
        try:
            if server.is_round:
                sheet = server.service.read(actor, "sheet", match[1])
                return html_page("任务详情 · 内网任务服务", workbench.detail(actor, sheet["view"], sheet["brief"], sheet["events"]))
            view = server.service.read(actor, "detail", match[1])
        except ClientError as error:
            return operation_message(actor, error.status, str(error))
        return html_page("任务详情 · 内网任务服务", task_pages.detail(actor, view))
    if method == "GET" and path == "/download":
        return download(handler, target, actor)
    if method == "POST" and path.startswith("/actions/"):
        return submit_action(handler, actor, path.removeprefix("/actions/"))
    raise ClientError("页面不存在", 404)


def filter_query(target, strict):
    """The workbench filters of a page request; ``strict`` also rejects a malformed or empty query string."""
    try:
        values = parse_qs(target.query, max_num_fields=len(FILTERS), keep_blank_values=True, strict_parsing=strict)
    except ValueError as error:
        raise ClientError("筛选参数无效") from error
    if not values.keys() <= FILTERS or any(len(v) != 1 for v in values.values()):
        raise ClientError("筛选参数无效")
    return {k: v[0] for k, v in values.items() if v[0]}


def home_page(handler, target, actor):
    server = handler.server
    if not actor:
        return login()
    if target.path == "/login":
        return redirect("/")
    query = {}
    if server.is_round:
        query = filter_query(target, True)
    data = server.service.read(actor, "overview", query.get("project"))
    if server.is_round:
        return html_page("我的工作 · 内网任务服务", workbench.mine_page(actor, data, query))
    return html_page("任务看板 · 内网任务服务", task_pages.overview(actor, data))


def session_change(handler, path, current):
    """POST /login with an identity and access token, or POST /logout."""
    server = handler.server
    service = server.service
    if not same_origin(handler):
        return login(error="请从当前登录页重新提交。", status=403)
    if path == "/logout":
        if server.is_round:
            parse_form(handler, 64, 0)
        server.sessions.end(current)
        handler.web_operation_completed = True
        return redirect("/login", session_cookie(handler, "", 0))
    try:
        fields = parse_form(handler, 1024, 2)
        if set(fields) != {"identity", "token"}:
            raise ValueError("Invalid form fields")
    except ValueError:
        return login(error="请填写身份和访问令牌。", status=400)
    identity, token = fields["identity"].strip(), fields["token"].strip()
    with service.lock:
        if server.actor_for_token(token, identity):
            issued = server.sessions.create(identity, current, service.session_version(identity))
            return redirect("/", session_cookie(handler, issued, SESSION_AGE))
    return login(identity[:80], error="身份或访问令牌有误。", status=401)


def new_task_page(handler, target, actor):
    server = handler.server
    service = server.service
    overview = service.read(actor, "overview")
    if overview["upgraded"]:
        from .httpd import parse_query
        query = parse_query(target.query, {"project"})
        if server.is_round:
            allowed = [p for p in overview["projects"] if {"manager", "receiver"} & set(p["roles"])]
            if not allowed:
                return operation_message(actor, 403, "当前角色不能直接新建任务。报告者可以在「反馈与决定」提需求，由项目管理员转为任务。")
            project = next((p for p in allowed if p["id"] == query.get("project")), allowed[0])
            receivers = service.read(actor, "receivers", project["id"]) if "manager" in project["roles"] else [actor]
            return html_page("新建任务 · 内网任务服务", workbench.new_task(
                actor, allowed, project, receivers, service.read(actor, "project-capabilities", project["id"]),
                service.read(actor, "project", project["id"])["members"], overview["tasks"]))
        allowed = [p for p in overview["projects"] if {"manager", "receiver"} & set(p["roles"]) and
                   (not query or p["id"] == query.get("project"))]
        if len(allowed) != 1:
            return redirect("/projects") if allowed else operation_message(actor, 403, "需要项目登记授权。")
        project = allowed[0]
        receivers = service.read(actor, "receivers", project["id"]) if "manager" in project["roles"] else [actor]
        return html_page("登记任务 · 内网任务服务", upgrade_pages.task_form(actor, project, receivers, server.is_round))
    roles = overview["roles"]
    if not {"receiver", "admin"} & set(roles):
        return operation_message(actor, 403, "仅管理员或接收者可登记资料任务。")
    receivers = server.service.read(actor, "receivers") if "admin" in roles else None
    return html_page("登记任务 · 内网任务服务", task_pages.new_task(actor, receivers))


def download(handler, target, actor):
    try:
        query = parse_qs(target.query, strict_parsing=True, max_num_fields=1)
        if set(query) != {"path"}:
            raise ValueError("Invalid download fields")
    except ValueError:
        return operation_message(actor, 400, "需要一个文件引用。")
    artifact = query["path"][0]
    try:
        raw = handler.server.service.read(actor, "artifact", artifact)
    except ClientError as error:
        return operation_message(actor, error.status, str(error))
    filename = quote(artifact.rsplit("/", 1)[-1], safe="")
    return 200, raw, "application/octet-stream", (
        ("Content-Disposition", f"attachment; filename*=UTF-8''{filename}"), *PAGE_HEADERS,
    )
