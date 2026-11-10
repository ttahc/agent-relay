"""Owner-visible lifecycle controls with a concrete impact preview."""
from html import escape
import re
from urllib.parse import quote

from . import task_pages as pages, upgrade_pages as ui, window_admin
from .packages import ClientError
from 协作存储 import Rejected
import 协作升级 as rules


PATH = re.compile(r"/executors/([A-Za-z0-9][A-Za-z0-9_-]{0,79})/manage")
LABELS = {"transfer": "更换责任人（解除旧关系）", "disable": "停用窗口", "pause": "暂停助理", "archive": "归档窗口", "revoke-all": "撤回本窗口全部委托"}


def controls(state, actor, name):
    if not window_admin.allowed(state, actor, name):
        return ""
    return (f'<a class="secondary" href="/executors/{quote(name)}/manage">查看影响并处置窗口</a>'
            f'<a class="secondary" href="/tokens/rotate?identity={quote(name)}">签发新令牌并重新启用</a>')


def render(actor, state, name, message="", status=200, draft=None):
    from .round_web import password_form, work_page
    from .workbench import window_tabs
    impact = window_admin.view(state, actor, name)
    draft = draft or {}
    claims = "".join(f'<tr><td><a href="/tasks/{quote(c["task_id"])}">{escape(c["task_id"])}</a><small>{escape(c["claim_id"])}</small></td>'
                     f'<td>{escape(c["L"])}</td><td>{escape(c["E"]["state"])}</td><td>{escape(c["W"]["state"])}</td>'
                     f'<td>{len(c["R"])}</td></tr>' for c in impact["claims"])
    grants = "".join(f'<li>{escape(row["project_id"])}：{escape("、".join(row["roles"]))}；资源 {len(row["resources"])}</li>'
                     for row in impact["grants"])
    delegates = "".join(f'<li>{escape(row["project_id"])}：{escape("、".join(row["actions"]))}；v{row["version"]}</li>'
                        for row in impact["delegations"])
    humans = [(key.removeprefix("identity:"), key.removeprefix("identity:")) for key, person in state["pilot"].items()
              if key.startswith("identity:") and person.get("kind") == "human" and person["status"] == "active" and
              key != "identity:" + impact["owner"]]
    fixed = pages.hidden("name", name) + pages.hidden("version", impact["version"])
    form = (ui.selection("operation", "处置方式", list(LABELS.items()), draft.get("operation", "pause"))
            + ui.selection("owner", "新责任人（仅更换责任人时使用）", [("", "请选择")]+humans, draft.get("owner", ""))
            + ui.text_field("reason", "处置依据", draft.get("reason", "")))
    notice = f'<p role="status">{escape(message)}</p>' if message else ""
    body = (window_tabs("/executors") + f'<h2>{escape(impact.get("window_name") or impact.get("window") or name)}：处置影响</h2>'
            f'<p>责任人 {escape(impact["owner"])} · 状态 {escape(impact["status"])} · 当前凭据版本 {impact["version"]}</p>' + notice
            + '<p>暂停、停用、归档会立即使旧令牌失效并撤回全部委托。重新启用须签发并激活新令牌，原委托需重新确认。</p>'
            + '<p>更换责任人保留窗口编号和历史记录，撤回旧委托并清空窗口全部项目授权。新责任人须重新取得项目授权并激活新令牌。'
              '存在活动领取（含待验收）或资源占用时拒绝更换责任人。</p>'
            + f'<p>{escape(impact["consequence"])}</p>'
            + '<h3>活动领取、待验交付与资源</h3><table><thead><tr><th>任务与领取</th><th>领取</th><th>执行</th><th>交付</th><th>资源占用</th></tr></thead><tbody>'
            + (claims or '<tr><td colspan="5">没有活动领取或资源占用。</td></tr>') + '</tbody></table>'
            + '<h3>窗口独立项目授权</h3><ul>' + (grants or '<li>无独立项目授权。</li>') + '</ul>'
            + '<h3>将撤回的委托</h3><ul>' + (delegates or '<li>无未撤回委托。</li>') + '</ul>'
            + '<p>仅撤回全部委托会保留独立项目授权；需要移出项目时由项目有权人员调整成员权限。</p>'
            + password_form(f'/executors/{quote(name)}/manage', fixed + form, "确认上述影响并处置")
            + controls(state, actor, name)
            + f'<p><a href="/executors/{quote(name)}">返回窗口详情及任务交接入口</a></p>')
    return work_page("窗口处置", body, actor, status)


def dispatch(handler, method, target, actor):
    from .web import parse_form, same_origin, reauthenticate
    match = PATH.fullmatch(target.path)
    if not match or target.query or method not in {"GET", "POST"}:
        raise ClientError("窗口处置页面路径或方法无效", 405)
    name, service = match[1], handler.server.service
    if method == 'POST' and not same_origin(handler):
        raise ClientError('请从当前窗口处置页面提交',403)
    parse_error=None
    try:
        posted=parse_form(handler,8192,7) if method=='POST' else None
    except ClientError as error:
        posted,parse_error=None,error
    with service.lock:
        reauthenticate(handler,actor)
        state = service.snapshot()["state"]
        window_admin.view(state, actor, name)
        message, status, draft = "", 200, None
        if method == "POST":
            if not same_origin(handler):
                raise ClientError("请从当前窗口处置页面提交", 403)
            try:
                if parse_error:raise parse_error
                draft = posted
                from .packages import fields
                fields(draft, "request_id name version operation owner reason")
                if draft["name"] != name or not re.fullmatch(r"[0-9]{1,10}", draft["version"]):
                    raise ClientError("窗口身份或凭据版本无效")
                body = {key: value for key, value in draft.items() if key != "owner"}
                body["version"] = int(body["version"])
                if body["operation"] == "transfer":
                    body["owner"] = draft["owner"]
                status, result = service.submit(actor, "window-admin", body["request_id"], body)
                message = ("窗口处置已登记。外部停止、资源释放和任务交接仍按实际办理。" if status == 200 else
                           result.get("message") or (result.get("steps") or [{}])[-1].get("reason", "请求待确认"))
                if status == 200:
                    draft = None
            except (ClientError, Rejected) as error:
                message, status = str(error), getattr(error, "status", 409)
            state = service.snapshot()["state"]
            # A previous owner loses management access as soon as transfer commits.
            if not window_admin.allowed(state, actor, name):
                from .round_web import work_page
                return work_page("窗口处置", '<p role="status">更换责任人已登记。请由新责任人重新授权并激活新令牌。</p>', actor, status)
        return render(actor, state, name, message, status, draft)
