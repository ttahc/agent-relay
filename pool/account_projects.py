"""System-administrator entry for an identity's existing project grants."""

from html import escape
import re
from urllib.parse import urlencode

from . import task_pages as pages, upgrade, upgrade_pages as ui
from .packages import ClientError, fields
import 协作升级 as rules


ROLE_NAMES = {"manager": "项目管理权限", "executor": "执行权限", "receiver": "验收权限", "reporter": "报告者", "observer": "观察者"}
ROLE_OPTIONS = (("manager,executor,receiver", "项目管理员"), ("executor,receiver", "贡献者"),
                ("executor", "仅执行权限"), ("receiver", "仅验收权限"),
                ("reporter", "报告者"), ("observer", "观察者"))


def role_value(roles):
    return ",".join(sorted(roles))


def role_options(subject, current):
    options = [(role_value(value.split(",")), title) for value, title in ROLE_OPTIONS
               if subject["kind"] == "human" or "manager" not in value.split(",")]
    value = role_value(current)
    if value and value not in {key for key, _ in options} and (subject["kind"] == "human" or "manager" not in current):
        label = "保留现有组合（" + "、".join(ROLE_NAMES.get(role, role) for role in sorted(current)) + "）"
        options.insert(0, (value, label))
    return options


def render(actor, name, state, message="", status=200, attempted=None):
    from .round_web import password_form, work_page
    subject = rules.identity(state, name)
    action = "/accounts/projects?" + urlencode({"identity": name})
    rows = []
    projects = sorted((record for key, record in state["pilot"].items() if key.startswith("project:")),
                      key=lambda item: (item["name"], item["id"]))
    for project in projects:
        grant = rules.grant(state, project["id"], name)
        roles, version = grant["roles"], grant.get("version", 0)
        current = "、".join(ROLE_NAMES.get(role, role) for role in roles) or "未加入"
        selected = (attempted.get("roles", "") if attempted and attempted.get("project_id") == project["id"] and attempted.get("operation") == "save"
                    else role_value(roles) if roles else "observer")
        fixed = pages.hidden("project_id", project["id"]) + pages.hidden("version", version)
        editor = password_form(action, fixed + pages.hidden("operation", "save")
                               + ui.selection("roles", "项目角色", role_options(subject, roles),
                                              selected),
                               "修改角色" if roles else "加入项目")
        if roles:
            editor += password_form(action, fixed + pages.hidden("operation", "remove"), "移除授权")
        rows.append(f'<tr><td>{escape(project["name"])}<div class="muted-text">{escape(project["id"])}</div></td>'
                    f'<td>{escape(current)}</td><td>{editor}</td></tr>')
    label = subject.get("window") or name
    notice = f'<p role="status">{escape(message)}</p>' if message else ""
    back = f'/executors/{name}' if subject["kind"] == "executor" else "/accounts"
    body = (f'<div class="phead"><h2>调整项目 · {escape(label)}</h2><a class="secondary" href="{escape(back, quote=True)}">返回{"窗口详情" if subject["kind"] == "executor" else "账号管理"}</a></div>'
            f'<p class="muted-text">身份：{escape(name)}。选择角色后提交；加入项目时默认选择观察者。'
            'AI 窗口不能担任项目管理员，实际权限同时受责任人项目授权限制。</p>' + notice
            + '<div class="table-wrap"><table><thead><tr><th>项目</th><th>当前授权</th><th>操作</th></tr></thead><tbody>'
            + ("".join(rows) or '<tr><td colspan="3">暂无项目。</td></tr>') + '</tbody></table></div>')
    return work_page("调整项目", body, actor, status)


def dispatch(handler, method, target, actor):
    from .httpd import parse_query
    from .web import parse_form, same_origin, reauthenticate
    service = handler.server.service
    if method == 'POST' and not same_origin(handler):
        raise ClientError('请从当前账号项目页面提交',403)
    parse_error=None
    try:
        posted = parse_form(handler,8192,6) if method == 'POST' else None
    except ClientError as error:
        posted,parse_error=None,error
    with service.lock:
        reauthenticate(handler,actor)
        state = service.snapshot()["state"]
        if not rules.system_admin(state, actor):
            raise ClientError("仅系统管理员可调整账号项目", 403)
        name = upgrade.identifier(parse_query(target.query, {"identity"}).get("identity"), "身份")
        subject = rules.identity(state, name)
        if not subject or subject["kind"] not in {"human", "executor"}:
            raise ClientError("人员或 AI 窗口不存在", 404)
        if method not in {"GET", "POST"}:
            raise ClientError("请求方法无效", 405)
        message, status, attempted = "", 200, None
        if method == "POST":
            try:
                if parse_error:raise parse_error
                data = posted
                attempted = dict(data)
                operation = data.pop("operation", "")
                fields(data, "request_id project_id version" + (" roles" if operation == "save" else ""))
                if operation not in {"save", "remove"}:
                    raise ClientError("项目授权操作无效")
                project = upgrade.identifier(data["project_id"], "项目编号")
                if not rules.project_record(state, project):
                    raise ClientError("项目不存在", 404)
                if not re.fullmatch(r"[0-9]{1,10}", data["version"]):
                    raise ClientError("授权版本无效")
                version = upgrade.version(int(data["version"]))
                roles = data.get("roles", "")
                allowed = {key for key, _ in role_options(subject, rules.grant(state, project, name)["roles"])}
                if operation == "save" and roles not in allowed:
                    raise ClientError("项目角色无效")
                body = {"request_id": data["request_id"], "project_id": project, "name": name,
                        "roles": roles.split(",") if operation == "save" else [],
                        "resources": rules.grant(state, project, name)["resources"], "version": version}
                status, result = service.submit(actor, "project-grant", data["request_id"], body)
                message = ("项目授权已更新。" if status == 200 else
                           result.get("message") or (result.get("steps") or [{}])[-1].get("reason", "请求待确认"))
            except ClientError as error:
                message, status = str(error), error.status
            state = service.snapshot()["state"]
        return render(actor, name, state, message, status, attempted if status != 200 else None)
