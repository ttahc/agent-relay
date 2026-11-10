"""Browser entry points for people, invitations and independent execution windows."""
import hmac
from html import escape
from http.cookies import CookieError, SimpleCookie
import json
from pathlib import Path
import re
import secrets
import time
from urllib.parse import quote

from . import round_service, task_pages, upgrade_pages, workbench, workbench_pages
from .packages import ClientError
from 协作本轮 import enabled
from 协作存储 import digest, encoded
import 协作升级 as rules


PATHS = {"/password", "/password/setup", "/password/reset", "/accounts/reset", "/accounts/projects", "/invitations",
         "/assistants",
         "/tokens/rotate", "/permissions", "/assets/round.js", "/assets/workbench.js", "/assets/workbench.css",
         "/collaboration", "/release-status", "/workspace-state"}
WORKBENCH_JS = Path(__file__).with_name("workbench.js").read_bytes()
WORKBENCH_CSS = Path(__file__).with_name("workbench.css").read_bytes()
POST_FORM = re.compile(rb"(<form\b[^>]*\bmethod=[\"']post[\"'][^>]*>)", re.IGNORECASE)
SCRIPT = """document.addEventListener('click', event => {
  if (!event.target.matches('[data-show-password]')) return;
  const field = document.getElementById(event.target.dataset.showPassword);
  field.type = field.type === 'password' ? 'text' : 'password';
  event.target.textContent = field.type === 'password' ? '显示密码' : '隐藏密码';
});
document.addEventListener('submit', event => {
  const button = event.submitter;
  if (!button || event.target.method !== 'post' || event.defaultPrevented) return;
  const message = document.createElement('p');
  message.setAttribute('role', 'status');
  message.textContent = event.target.enctype === 'multipart/form-data'
    ? '正在上传并核对文件，请等待回执。' : '正在处理，请等待回执。';
  button.after(message);
  // Let the browser collect a named submitter's value before disabling it.
  setTimeout(() => { if (!event.defaultPrevented) button.disabled = true; }, 0);
});
window.addEventListener('pageshow', event => {
  if (event.persisted) document.querySelectorAll('button[disabled]').forEach(button => button.disabled = false);
});
""".encode("utf-8")


def form_cookie(handler):
    return "__Host-taskpool_form" if handler.server.tls else "taskpool_form_local"


def csrf_context(handler, method):
    from .web import session_id
    current = session_id(handler)
    if current:
        nonce = "session:" + current
        headers = ()
    else:
        cookies = SimpleCookie()
        try:
            cookies.load(handler.headers.get("Cookie", ""))
        except CookieError:
            cookies = SimpleCookie()
        cookie = cookies.get(form_cookie(handler))
        value = cookie.value if cookie else ""
        headers = ()
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
            value = secrets.token_urlsafe(32) if method == "GET" else ""
            if value:
                secure = "; Secure" if handler.server.tls else ""
                headers = (("Set-Cookie", f"{form_cookie(handler)}={value}; Path=/; HttpOnly; SameSite=Strict; "
                                          f"Max-Age=3600{secure}"),)
        nonce = "form:" + value if value else ""
    handler.form_token = hmac.digest(handler.server.csrf_key, nonce.encode(), "sha256").hex() if nonce else None
    return headers


def verify_form(handler, data):
    if not handler.server.is_round:
        return
    token = data.pop("csrf", "")
    if not handler.form_token or not token.isascii() or not hmac.compare_digest(handler.form_token, token):
        raise ClientError("表单已过期，请重新打开页面", 403)


def wrap(handler, method, target, original):
    if method != "GET":
        return respond(handler, method, target, original)
    with handler.server.service.one_snapshot():
        return respond(handler, method, target, original)


def respond(handler, method, target, original):
    from . import web
    if method == "POST":
        handler.web_request_id = handler.headers.get("X-TaskPool-Request-ID", "")
        handler.web_action_result = {}
        handler.web_operation_completed = False
        handler.web_supersedes_request_id = None
    if method == "GET" and target.path == "/assets/round.js":
        return 200, SCRIPT, "text/javascript; charset=utf-8"
    if method == "GET" and target.path == "/assets/workbench.js":
        return 200, WORKBENCH_JS, "text/javascript; charset=utf-8"
    if method == "GET" and target.path == "/assets/workbench.css":
        return 200, WORKBENCH_CSS, "text/css; charset=utf-8"
    headers = csrf_context(handler, method)
    current = web.session_id(handler)
    actor = handler.server.sessions.actor(current, handler.server.service)
    if method == "POST" and not web.same_origin(handler):
        response = page("操作未完成", "请从服务当前页面提交。", 403, actor=actor)
    else:
        try:
            response = route(handler, method, target, current, actor) or original(handler, method, target)
        except ClientError as error:
            response = page("操作未完成", str(error), error.status, actor=actor)
    if len(response) == 4 and response[2].startswith("text/html"):
        status, html, kind, original_headers = response
        if handler.form_token:
            hidden = task_pages.hidden("csrf", handler.form_token).encode()
            html = POST_FORM.sub(lambda match: match[0] + hidden, html)
        if actor := handler.server.sessions.actor(web.session_id(handler), handler.server.service):
            html = workbench.adopt(html, target, actor, handler.server.service)
        html = html.replace(b"</head>", b'<link rel="stylesheet" href="/assets/workbench.css">'
                            b'<script src="/assets/round.js" defer></script>'
                            b'<script src="/assets/workbench.js" defer></script></head>', 1)
        policy = tuple((name, value + "; script-src 'self'" if name == "Content-Security-Policy" else value)
                       for name, value in original_headers)
        response = status, html, kind, (*policy, *headers)
    return web.json_web_response(handler, response, target.path) if method == "POST" else response


def page(title, message="", status=200, body="", actor=None):
    from .web import html_page
    text = f'<p class="intro" role="status">{escape(message)}</p>' if message else ""
    main = f'<section class="task-panel"><h1>{escape(title)}</h1>{text}{body}</section>'
    return html_page(escape(title) + " · 内网任务服务",
                     task_pages.workspace(actor, main) if actor else f'<main class="workspace narrow">{main}</main>',
                     status)


def work_page(title, body, actor, status=200):
    from .web import html_page
    return html_page(escape(title) + " · 内网任务服务", workbench_pages.work(actor, body), status)


def password_input(name, label, completion):
    required = " required" if completion == "off" else ""
    return (f'<label for="{name}">{label}</label><input id="{name}" name="{name}" type="password" '
            f'autocomplete="{completion}"{required}><button class="secondary" type="button" '
            f'data-show-password="{name}">显示密码</button>')


def identity_input(name="identity", value=""):
    return (f'<label>账号<input name="{name}" value="{escape(value, quote=True)}" required maxlength="80" '
            'autocomplete="username" spellcheck="false" autocapitalize="none"></label>')


def password_form(path, fields, label):
    rid = task_pages.hidden("request_id", "web-" + secrets.token_hex(16))
    return (f'<form class="operation" method="post" action="{path}">{rid}{fields}'
            f'<button class="primary" type="submit">{label}</button></form>')


def current_actor(handler):
    from .web import session_id
    return handler.server.sessions.actor(session_id(handler), handler.server.service)


def login(identity="", message="", status=200):
    from .web import html_page
    from . import __version__, RELEASE_NAME
    feedback = f'<p class="form-error" role="alert">{escape(message)}</p>' if message else ""
    form = password_form("/login",
                         identity_input(value=identity) + password_input("password", "密码", "current-password"), "登录")
    return html_page("登录 · 内网任务服务", f"""
<main class="login-shell">
  <section class="brand" aria-label="内网任务服务">
    <div class="brand-top"><span class="mark" aria-hidden="true">任务</span><span>内网协作</span></div>
    <div class="brand-content"><p class="brand-title">内网任务服务</p>
    <p class="brand-description">发现可领取任务，查看执行窗口，追踪交付和验收。</p></div>
    <p class="brand-footer">v{__version__} · {escape(RELEASE_NAME)}</p>
  </section>
  <section class="form-panel"><div><h1>账号登录</h1>{feedback}{form}
    <p class="register-link"><a href="/register">使用人员邀请码注册</a></p>
    <p class="register-link"><a href="/ai">AI 窗口接入说明与客户端下载</a></p>
    <p class="register-link"><a href="/password/setup">原账号首次设置密码</a> · <a href="/password/reset">重置密码</a></p>
  </div></section>
</main>""", status)


def ai_entry():
    from .web import html_page
    return html_page("AI 窗口接入 · 内网任务服务", """
<main class="login-shell"><section class="form-panel"><div>
  <h1>AI 窗口接入</h1><p>收到完整邀请链接后，使用客户端登记独立窗口。保留链接中 # 后的接入凭据与证书核对信息。</p>
  <p>AI 窗口邀请码用于客户端 enroll；人员邀请码用于人员注册页面。</p>
  <p><a href="/ai-client.zip">下载客户端包</a> · <a href="/login">人员登录</a></p>
  <ol><li>取得最小客户端包，按可信邀请内的证书与包 SHA256 信息核对。</li>
    <li>解压后使用 enroll --invite-url，并把完整邀请链接作为一个带引号的参数传入。</li>
    <li>Windows 可用 ops/round-client.ps1，Linux/macOS 使用 Python 3.11 或更新版本运行 ops/round-client.py；填写实际平台、聊天标题和窗口独有的私有凭据文件。</li>
    <li>出现 active、窗口编号和项目权限后完成接入，再申报能力并查看可领取任务。</li></ol>
  <p>旧 JSON 邀请继续使用 enroll --invite。登记后用 capabilities / declare 查看和自报技能，tasks 会显示可见、可领数量及不可领取原因。</p>
  <p>本说明、链接预览与客户端下载无需登录，不消耗邀请码。详细说明在包内 README.md 或 docs/AI客户端操作.md。</p>
</div></section></main>""")


def password_fields(kind, identity):
    fields = "" if kind == "change" else identity_input(value=identity)
    if kind == "change":
        fields += password_input("current", "当前密码", "current-password")
    elif kind == "signup":
        fields += password_input("invitation", "人员邀请码", "off")
    elif kind == "setup":
        fields += password_input("token", "原账号访问令牌", "off")
    else:
        fields += password_input("reset", "管理员提供的重置凭据", "off")
    return (fields + password_input("password", "新密码", "new-password")
            + password_input("confirm", "确认新密码", "new-password"))


def password_route(handler, method, path, current, actor):
    from .web import parse_form, redirect, session_cookie
    server = handler.server
    service = server.service
    if path == "/login":
        if method == "GET":
            return redirect("/") if actor else login()
        data = parse_form(handler, 8192, 3)
        from .packages import fields
        fields(data, "request_id identity password")
        name = data["identity"].strip()
        try:
            valid = service.passwords.authenticate(name, data["password"])
        except ClientError as error:
            return login(name[:80], str(error), error.status)
        with service.lock:
            subject = rules.identity(service.snapshot()["state"], valid[0]) if valid else None
            if (subject and subject["kind"] == "human" and subject["status"] == "active"
                and service.passwords.version(valid[0]) == valid[1]):
                issued = server.sessions.create(valid[0], current, service.session_version(valid[0]))
                from .web import SESSION_AGE
                return redirect("/", session_cookie(handler, issued, SESSION_AGE))
        return login(name[:80], "账号或密码有误。", 401)

    kind = {"/register": "signup", "/password/setup": "setup", "/password/reset": "reset", "/password": "change"}[path]
    title = {"signup": "人员注册", "setup": "原账号首次设置密码", "reset": "重置密码", "change": "修改密码"}[kind]
    if kind == "change" and not actor:
        return redirect("/login")
    name = ""
    message, status = "密码无长度要求，允许留空。", 200
    if method == "POST":
        from .packages import fields
        try:
            data = parse_form(handler, 8192, 5)
            identity_fields = {"signup": "identity invitation", "setup": "identity token", "reset": "identity reset",
                               "change": "current"}[kind]
            fields(data, "request_id password confirm " + identity_fields)
            name = actor if kind == "change" else data["identity"].strip()
            if data["password"] != data["confirm"]:
                raise ClientError("两次输入不一致")
            if kind == "signup":
                status, result = round_service.password_signup(service, data["request_id"], name,
                                                               data["invitation"].strip(), data["password"])
            else:
                authenticated = service.passwords.authenticate(name, data["current"]) if kind == "change" else None
                if kind == "change" and not authenticated:
                    raise ClientError("当前密码或登录状态无效", 403)
                with service.lock:
                    if kind == "setup" and not server.actor_for_token(data["token"].strip(), name):
                        raise ClientError("原账号或凭据无效", 403)
                    if kind == "reset":
                        service.passwords.check_reset(name, data["reset"].strip())
                protected = service.passwords.protect(data["password"], name)
                with service.lock:
                    state = service.snapshot()["state"]
                    subject = rules.identity(state, name) or {}
                    if subject.get("kind") != "human" or subject.get("status") != "active":
                        raise ClientError("无法确认该人员账号", 403)
                    if kind == "setup" and (service.passwords.version(name)
                                            or not server.actor_for_token(data["token"].strip(), name)):
                        raise ClientError("原账号或凭据无效，已设置密码时请直接登录", 403)
                    if kind == "change" and (not authenticated or authenticated[1] != service.passwords.version(name) or
                                             server.sessions.actor(current, service) != name):
                        raise ClientError("当前密码或登录状态无效", 403)
                    proof = service.passwords.check_reset(name, data["reset"].strip()) if kind == "reset" else None
                    status, result = round_service.password_change(service, name, name, kind, data["request_id"],
                                                                   protected, proof)
            if status == 200:
                handler.web_operation_completed = True
                server.sessions.end(current)
                return redirect("/login", session_cookie(handler, "", 0))
            message = result.get("message") or (result.get("steps") or [{}])[-1].get("reason") or "操作待确认，请重送原表单。"
            if status in {202, 503}:
                return page(title, message + " 请用浏览器重送原表单。", status, actor=actor)
        except ClientError as error:
            message, status = str(error), error.status
    if kind == "change":
        from .web import html_page
        return html_page("修改密码 · 内网任务服务", workbench_pages.self_page(
            actor, service.read(actor, "identity"), service.read(actor, "capabilities")["capabilities"],
            password_form(path, password_fields(kind, name), "保存密码"), message, status != 200), status)
    return page(title, message, status, password_form(path, password_fields(kind, name), "保存密码") +
                '<p><a href="/login">返回登录</a></p>', actor=actor)


def reset_issue(handler, method, actor, target):
    from .web import parse_form, reauthenticate
    from .packages import fields
    from .upgrade import identifier
    service = handler.server.service
    data = parse_form(handler, 1024, 2) if method == "POST" else None
    with service.lock:
        reauthenticate(handler, actor)
        if not rules.system_admin(service.snapshot()["state"], actor):
            raise ClientError("仅管理员可发出人员重置凭据", 403)
        if method == "GET":
            from .httpd import parse_query
            name = parse_query(target.query, {"identity"}).get("identity", "")
            return page("人员密码恢复", "核对人员身份后签发 15 分钟有效的重置凭据。",
                        body=password_form("/accounts/reset", identity_input(value=name), "生成重置凭据"), actor=actor)
        fields(data, "request_id identity")
        name = identifier(data["identity"], "人员账号")
        status, value = service.submit(actor, "password-event", data["request_id"],
                                       {"request_id": data["request_id"], "name": name, "kind": "reset-issued"},
                                       authorize=lambda: current_actor(handler))
        handler.web_action_result = value
        if status != 200:
            return page("人员密码恢复", value.get("message") or (value.get("steps") or [{}])[-1].get("reason", "请求待确认"),
                        status, actor=actor)
        code = service.passwords.reset_reply(digest(encoded([actor, data["request_id"]])), name)
        return page("人员密码恢复", "请将重置凭据交给已核对的人员。",
                    body=f'<code class="credential">{escape(code)}</code><p><a href="/password/reset">重置入口</a></p>',
                    actor=actor)


def invitations(handler, method, actor, target=None):
    from .web import parse_form, reauthenticate
    from .packages import fields
    service = handler.server.service
    from . import invite_links
    issued = ""
    attempted, message, status = {}, "", 200

    def present(record):
        bundle = {k: record[k] for k in ("id", "code", "url", "certificate_sha256", "protocol", "connect_host",
                  "kind", "client", "instructions", "invitation_url") if k in record}
        invite_links.remember(service, record["id"])
        link = record.get("invitation_url", "")
        return ('<h2>复制邀请链接</h2><p>把这一条完整链接交给对应 AI 窗口，接入说明和客户端可在链接中取得。</p>'
                f'<textarea rows="3" readonly aria-label="AI 邀请链接">{escape(link)}</textarea>'
                '<details><summary>高级：旧客户端兼容资料</summary>'
                f'<textarea rows="8" readonly aria-label="AI 接入信息">'
                f'{escape(json.dumps(bundle, indent=2, ensure_ascii=False))}</textarea></details>')
    if method == "POST":
        data = parse_form(handler, 4096, 9)
        op = data.pop("operation", "")
        attempted = dict(data) if op == "issue" else {}
        with service.lock:
            reauthenticate(handler, actor)
            if op == "issue":
                try:
                    fields(data, "request_id project_id owner roles hours count")
                    data.update(hours=int(data["hours"]), count=int(data["count"]))
                    data["roles"] = [role.strip() for role in data["roles"].split(",") if role.strip()]
                    status, value = service.submit(actor, "ai-invite", data["request_id"], data,
                                                   authorize=lambda: current_actor(handler))
                    handler.web_action_result = value
                except (ValueError, ClientError) as error:
                    status, value = (getattr(error, "status", 400),
                                     {"message": str(error) if isinstance(error, ClientError) else "有效时间和登记额度须为整数"})
                if status == 200 and value.get("invitation"):
                    record = handler.invitation_bundle(value["invitation"])
                    issued = present(record)
            elif op == "link":
                fields(data, "request_id invite_id")
                row = next((row for row in service.read(actor, "invitations")["invitations"]
                            if row["id"] == data["invite_id"]), None)
                if not row:
                    raise ClientError("邀请不存在或当前人员无权查看", 404)
                if (row["expires"] <= time.time() or row["used"] >= row["count"] or
                        not round_service.usable_invite(service.snapshot()["state"], row)):
                    raise ClientError("邀请已失效或额度不足，请重新生成", 409)
                record = handler.invitation_bundle(
                    {**row, "code": service.accounts.token("ai-invite", row["id"], row["issuer"])})
                issued = present(record)
                status = 200
            elif op == "revoke":
                fields(data, "request_id invite_id reason")
                status, value = service.submit(actor, "ai-revoke", data["request_id"], data,
                                               authorize=lambda: current_actor(handler))
                handler.web_action_result = value
            else:
                raise ClientError("邀请操作无效")
        if status != 200:
            message = value.get("message") or (value.get("steps") or [{}])[-1].get("reason", "请求待确认")
    projects = service.read(actor, "projects")["projects"]
    own = [p for p in projects if p["roles"]]
    editor = ""
    if own:
        from .httpd import parse_query
        query = parse_query(target.query, {"project"}) if target else {}
        selected = attempted.get("project_id", query.get("project", own[0]["id"]))
        try:
            owners = service.read(actor, "invitation-owners", selected)
        except ClientError as error:
            owners = []
            if not message:
                message, status = str(error), error.status
        owners = owners.get("owners", owners.get("identity_choices", [])) if isinstance(owners, dict) else owners
        choose_project = ('<form class="wb-inline" action="/invitations" method="get" data-auto>'
                          + upgrade_pages.selection("project", "项目", upgrade_pages.project_options(own), selected)
                          + '<noscript><button class="secondary" type="submit">切换项目</button></noscript></form>')
        defaults = {"owner": actor, "roles": "executor", "hours": "24", "count": "1", **attempted}
        count = upgrade_pages.input_field("count", "可登记窗口数", defaults["count"]).replace(
            '<input ', '<input type="number" min="1" max="20" step="1" ')
        editor = password_form("/invitations", task_pages.hidden("operation", "issue")
                               + task_pages.hidden("project_id", selected)
                               + upgrade_pages.identity_picker("owner", "责任人（窗口归属人员）", owners, defaults["owner"])
                               + upgrade_pages.selection("roles", "窗口项目权限",
                                                         [("executor,receiver", "贡献者"), ("executor", "仅任务执行权限"),
                                                          ("receiver", "仅任务验收权限")], defaults["roles"])
                               + upgrade_pages.selection("hours", "邀请有效期",
                                                         [("1", "1 小时"), ("4", "4 小时"), ("8", "8 小时"), ("24", "1 天"),
                                                          ("72", "3 天"), ("168", "7 天")], defaults["hours"])
                               + count, "生成 AI 邀请")
        editor = choose_project + editor
    items = []
    for row in service.read(actor, "invitations")["invitations"]:
        name = escape(row["id"])
        used = f'{row["used"]} / {row["count"]}'
        stage = ("已撤销" if row["revoked"] else "已到期" if row["expires"] <= time.time() else "额度已用完"
                 if row["used"] >= row["count"] else "可用")
        format_note = "链接邀请" if invite_links.is_current(service, row["id"]) else "旧格式邀请：可生成新版接入链接，已登记窗口继续使用原凭据"
        windows = "".join(
            f'<li><a href="/executors/{quote(w["name"])}">{escape(w["window"])}</a> · '
            f'{escape(workbench_pages.STATUS.get(w["state"], ("待核实", ""))[0])}</li>'
            for w in row["windows"])
        controls = "" if row["revoked"] else password_form("/invitations", task_pages.hidden("operation", "revoke") +
                    task_pages.hidden("invite_id", row["id"]) + upgrade_pages.input_field("reason", "撤销依据"), "撤销邀请")
        if stage == "可用":
            controls = password_form(
                "/invitations", task_pages.hidden("operation", "link") + task_pages.hidden("invite_id", row["id"]),
                "生成接入链接") + controls
        items.append(
            f'<li><strong>{name}</strong> · {escape(row["project"])} · {escape(row["owner"])} · {used} · {stage}'
            f'<p class="muted-text">{format_note}</p>'
            f'<ul>{windows}</ul><details><summary>邀请操作</summary>{controls}</details></li>')
    notice = f'<p class="form-error" role="status">{escape(message)}；已保留邀请表单，可修正后重试。</p>' if message else ""
    return work_page("邀请窗口",
                     notice + issued + editor + '<h2>邀请记录</h2><ul class="roster">' + "".join(items) + "</ul>",
                     actor, status)


def token_rotation(handler, method, actor, target):
    from .web import parse_form, reauthenticate
    from .httpd import parse_query
    from .upgrade import identifier
    from .packages import fields
    service = handler.server.service
    if method == "GET":
        name = identifier(parse_query(target.query, {"identity"}).get("identity"), "执行端")
        with service.lock:
            state = service.snapshot()["state"]
            if not round_service.rotation_allowed(state, actor, name):
                raise ClientError("无凭据轮换权限", 403)
            version = rules.identity(state, name)["credential"]
        return page("轮换窗口令牌", "新令牌激活后，原令牌失效。窗口编号保留。",
                    body=password_form("/tokens/rotate",
                                       task_pages.hidden("name", name) + task_pages.hidden("version", version)
                                  + task_pages.hidden("recovery", secrets.token_urlsafe(32)) +
                                  upgrade_pages.input_field("reason", "轮换依据"), "签发待激活令牌"), actor=actor)
    data = parse_form(handler, 8192, 5)
    fields(data, "request_id name version recovery reason")
    try:
        data["version"] = int(data["version"])
    except ValueError as error:
        raise ClientError("凭据版本无效") from error
    with service.lock:
        reauthenticate(handler, actor)
        status, value = round_service.prepare_token(service, actor, data)
    if status != 200 or "token" not in value:
        return page("轮换窗口令牌", value.get("message") or (value.get("steps") or [{}])[-1].get("reason", "无可领取的新令牌"),
                    status, actor=actor)
    bundle = handler.invitation_bundle({k: value[k]
                                        for k in ("registration_id", "executor_id", "window", "token", "deadline")})
    return page("待激活令牌", "将信息交给对应窗口，用 round-client.py activate 激活。",
                body='<textarea readonly rows="8" aria-label="待激活令牌">'
                     f'{escape(json.dumps(bundle, indent=2))}</textarea>', actor=actor)


def route(handler, method, target, current, actor):
    from .web import redirect
    path = target.path
    from .execution_pages import PATH as execution_path, dispatch as execution_dispatch
    if execution_path.fullmatch(path):
        return execution_dispatch(handler, method, target, actor) if actor else redirect("/login")
    if method == "GET" and path == "/" and not actor:
        return login()
    if path in {"/login", "/register", "/password", "/password/setup", "/password/reset"}:
        return password_route(handler, method, path, current, actor)
    if path in PATHS and not actor:
        return redirect("/login")
    if path == '/workspace-state':
        if method != 'GET':
            raise ClientError('状态摘要仅支持查看', 405)
        from .httpd import parse_query
        from . import __version__
        project = parse_query(target.query, {'project'}).get('project') or None
        data = handler.server.service.read(actor, 'overview', project)
        return (200, {'revision': workbench.workspace_revision(data), 'version': __version__},
                'application/json; charset=utf-8')
    if path == '/release-status':
        from .release_pages import page as release_page
        if method != 'GET':
            raise ClientError('版本复验页仅支持查看', 405)
        return release_page(handler.server.service, actor)
    if path == "/accounts/reset":
        return reset_issue(handler, method, actor, target)
    if path == "/accounts/projects":
        from .account_projects import dispatch
        return dispatch(handler, method, target, actor)
    if path == "/assistants":
        from .delegation_pages import dispatch
        return dispatch(handler, method, target, actor)
    if path == "/permissions":
        from .web import html_page
        return html_page("权限说明 · 内网任务服务", workbench_pages.permissions_page(actor))
    if path == "/invitations":
        return invitations(handler, method, actor, target)
    if path == "/tokens/rotate":
        return token_rotation(handler, method, actor, target)
    if path == "/collaboration":
        from .round_projects_web import dispatch
        return dispatch(handler, method, target, actor)
    return None
