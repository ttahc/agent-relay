"""One consent editor with exact scopes, fixed expiries, and delegation history."""
from html import escape
import re
import time
from urllib.parse import urlencode

from . import delegation, task_pages as pages, upgrade, upgrade_pages as ui
from .packages import ClientError, fields
from 协作存储 import Rejected
import 协作升级 as rules


STATUS = {"active": "有效", "restricted": "当前权限受限", "expired": "已到期", "revoked": "已撤回"}
PRESETS = (("task", "任务助理"), ("project", "项目助理"))


def available_actions(state, person, project, preset, task_ids):
    if preset not in delegation.DELEGATION_PRESETS:
        raise ClientError("助理动作预设无效")
    return sorted(action for action in delegation.DELEGATION_PRESETS[preset]
                  if delegation.delegable(state, person, project, action) and not (task_ids and action == "register"))


def timestamp(value):
    from .display_time import time_html
    return time_html(value)


def history_html(item, entries):
    versions = list(item.get("history", [])) + [item]
    versions_html = "".join(f'<li>v{row["version"]} · {timestamp(row["at"])} · '
                            f'{escape("、".join(delegation.ACTION_LABELS[a] for a in row["actions"]))} · '
                            f'任务 {escape("、".join(row["task_ids"]) or "整个项目")} · 到期 {timestamp(row["expires"])}</li>'
                            for row in reversed(versions))
    events = [entry for entry in reversed(entries) if entry.get("type") == "decision" and
              entry.get("request", {}).get("delegation_id") == item["id"]]
    operations = "".join(f'<li>{timestamp(row.get("request", {}).get("received_utc"))} · '
                         f'{escape(row.get("request", {}).get("operation", "操作"))} · '
                         f'{escape(row.get("request", {}).get("actor", ""))} · {escape(row.get("result", ""))}'
                         + (f' · <a href="/tasks/{escape(row["request"]["task_id"], quote=True)}">{escape(row["request"]["task_id"])}</a>'
                            if row.get("request", {}).get("task_id") else "") + '</li>' for row in events[:40])
    return ('<details><summary>委托版本与代办记录</summary><h4>授权变更</h4><ul>' + versions_html + '</ul><h4>代办操作</h4><ul>'
            + (operations or '<li>尚无该委托的操作记录。</li>') + '</ul></details>')


def render(actor, state, message="", status=200, selected=None, draft=None, entries=(), preview=False):
    from .round_web import password_form, work_page
    from .workbench import window_text, window_tabs
    subject = rules.identity(state, actor) or {}
    human = subject.get("kind") == "human"
    projects = sorted((p for key, p in state["pilot"].items() if key.startswith("project:") and
                       rules.grant(state, p["id"], actor)["roles"]), key=lambda p: p["name"])
    windows = sorted(({"executor_id": key.removeprefix("identity:"), **item} for key, item in state["pilot"].items()
                      if key.startswith("identity:") and item.get("kind") == "executor" and item.get("owner") == actor and
                      item.get("status") == "active"), key=lambda item: item.get("number", 0))
    current = {item["id"]: item for item in delegation.view(state, actor)}
    rows, now = [], time.time()
    for item in current.values():
        actions = "、".join(delegation.ACTION_LABELS[name] for name in item["actions"])
        scope = "、".join(item["task_ids"]) if item["task_ids"] else "整个项目"
        project = rules.project_record(state, item["project_id"]) or {"name": item["project_id"]}
        controls = ""
        if human and item["delegator"] == actor:
            query = urlencode({"window": item["executor_id"], "project": item["project_id"]})
            controls = f'<a href="/assistants?{escape(query, quote=True)}#consent-editor">编辑或续期</a>'
            if not item["revoked"] and item["expires"] > now:
                controls += password_form("/assistants", pages.hidden("operation", "revoke") + pages.hidden("delegation_id", item["id"])
                                          + pages.hidden("version", item["version"])
                                          + ui.input_field("reason", "撤回依据", "人员撤回本项委托"), "撤回委托")
        rows.append(f'<tr><td>{escape(window_text(item))}</td><td>{escape(project["name"])}<p>{escape(scope)}</p></td>'
                    f'<td>{escape(actions)}</td><td>{STATUS[item["status"]]}<p>{timestamp(item["expires"])}</p></td>'
                    f'<td>{controls}{history_html(item, entries)}</td></tr>')
    editor = ""
    if human and windows and projects:
        selected = selected or {}
        draft = draft or {}
        executor = draft.get("executor_id") or selected.get("window") or windows[0]["executor_id"]
        project_id = draft.get("project_id") or selected.get("project") or projects[0]["id"]
        window = next((row for row in windows if row["executor_id"] == executor), None)
        project = next((row for row in projects if row["id"] == project_id), None)
        picker = ('<form method="get" action="/assistants">'
                  + ui.selection("window", "选择窗口", [(row["executor_id"], window_text(row)) for row in windows], executor)
                  + ui.selection("project", "选择项目", [(row["id"], row["name"]) for row in projects], project_id)
                  + '<button class="secondary" type="submit">载入当前委托</button></form>')
        editor = '<section id="consent-editor"><h3>授权、编辑或续期</h3>' + picker
        if not window or not project:
            editor += '<p>请选择当前有效的本人窗口与项目后载入。</p></section>'
        else:
            previous = current.get(delegation.delegation_id(actor, executor, project_id), {})
            editing = bool(previous)
            legacy = "preset" in draft
            picked_actions = (available_actions(state, actor, project_id, draft["preset"], []) if legacy else
                              [key[7:] for key in draft if key.startswith("action_")] if draft else
                              previous.get("actions", available_actions(state, actor, project_id, "task", [])))
            picked_tasks = ([item.strip() for item in draft["task_ids"].split(",") if item.strip()] if legacy else
                            [key[5:] for key in draft if key.startswith("task_")] if draft else previous.get("task_ids", []))
            choices = sorted(delegation.DELEGATION_ACTIONS)
            action_fields = "".join(f'<label><input type="checkbox" name="action_{action}" value="1"'
                                    f'{" checked" if action in picked_actions else ""}> {escape(delegation.ACTION_LABELS[action])}'
                                    f'{"（当前无权，请取消或恢复人员权限）" if not delegation.delegable(state, actor, project_id, action) else ""}</label>'
                                    for action in choices)
            tasks = sorted((task for task in state["tasks"].values() if rules.task_project(task) == project_id), key=lambda task: task["task_id"])
            task_fields = "".join(f'<label><input type="checkbox" name="task_{task["task_id"]}" value="1"'
                                  f'{" checked" if task["task_id"] in picked_tasks else ""}> {escape(task["task_id"])} · {escape(task.get("title", task["task_id"]))}</label>' for task in tasks)
            expiry_mode = draft.get("expiry_mode", "keep" if editing and previous["expires"] > now else "renew")
            expiry = draft.get("expires", previous.get("expires", 0))
            fixed = (pages.hidden("operation", "grant" if preview else "grant-preview") + pages.hidden("executor_id", executor)
                     + pages.hidden("project_id", project_id) + pages.hidden("version", draft.get("version", previous.get("version", 0))))
            fields_html = ('<fieldset><legend>精确委托动作</legend>' + action_fields + '</fieldset>'
                           + '<p>读取、技能自报和任务执行可按需要勾选；创建、开放和暂缓任务等动作仍受你当前项目权限限制。</p>'
                           + '<fieldset><legend>任务范围（不选择表示整个项目）</legend>' + (task_fields or '<p>本项目暂无任务。</p>') + '</fieldset>'
                           + '<p>选择已有任务时须取消“创建任务”。</p>' + pages.hidden("expires", expiry)
                           + ui.selection("expiry_mode", "到期时间", [("keep", "保留当前准确到期时间"), ("renew", "从本次受理起重新计时")], expiry_mode)
                           + (f'<p>当前到期：{timestamp(previous["expires"])}</p>' if editing else '<p>首次授权请选择重新计时。</p>')
                           + ui.selection("hours", "重新计时的有效时长", [("1", "1 小时"), ("8", "8 小时"), ("24", "1 天"), ("168", "7 天"), ("720", "30 天")], draft.get("hours", "24"))
                           + ui.text_field("reason", "授权依据", draft.get("reason", previous.get("reason", "人员确认所选范围和期限内的委托"))))
            comparison = ""
            if preview:
                old_actions = "、".join(delegation.ACTION_LABELS[a] for a in previous.get("actions", [])) or "无"
                new_actions = "、".join(delegation.ACTION_LABELS[a] for a in picked_actions) or "无"
                comparison = (f'<div role="status"><h4>保存前核对</h4><p>动作：{escape(old_actions)} → {escape(new_actions)}</p>'
                              f'<p>任务：{escape("、".join(previous.get("task_ids", [])) or "整个项目")} → {escape("、".join(picked_tasks) or "整个项目")}</p>'
                              + (f'<p>到期保持 {timestamp(int(expiry))}</p>' if expiry_mode == "keep" else
                                 f'<p>到期从最终受理时起计算 {escape(draft.get("hours", "24"))} 小时。</p>') + '</div>')
            editor += comparison + password_form("/assistants", fixed + fields_html, "确认上述委托" if preview else "预览变更") + '</section>'
    elif human:
        editor = '<p>请先关联有效 AI 窗口并取得相应项目权限。</p>'
    else:
        editor = '<p>AI 可查看自己的委托。授权与撤回由关联人员本人办理。</p>'
    notice = f'<p role="status">{escape(message)}</p>' if message else ""
    body = (window_tabs("/assistants") + '<div class="phead"><h2>我的 AI 助理</h2></div>'
            + '<p>委托是附加授权。撤回不会移除独立项目权限，也不证明外部程序已停止；活动领取、资源占用与交接须按实际办理。</p>' + notice
            + '<div class="table-wrap"><table><thead><tr><th>窗口</th><th>项目与任务范围</th><th>委托动作</th><th>状态与到期时间</th><th>操作与历史</th></tr></thead><tbody>'
            + ("".join(rows) or '<tr><td colspan="5">尚无委托记录。</td></tr>') + '</tbody></table></div>' + editor)
    return work_page("我的 AI 助理", body, actor, status)


def grant_body(state, actor, data):
    """Normalize consent without reading a page-open timestamp."""
    if "preset" in data:  # Retained for already-open v0.2.0 forms.
        fields(data, "request_id executor_id project_id version preset task_ids hours issued reason")
        tasks = [item.strip() for item in data["task_ids"].replace("，", ",").split(",") if item.strip()]
        project = upgrade.identifier(data["project_id"], "项目")
        actions = available_actions(state, actor, project, data["preset"], tasks)
        mode = "renew"
    else:
        extras = {key for key in data if key.startswith("action_") or key.startswith("task_")}
        fields(data, "request_id executor_id project_id version expiry_mode expires hours reason " + " ".join(extras))
        if any(data[key] != "1" for key in extras):
            raise ClientError("动作或任务选择无效")
        actions = sorted(key[7:] for key in extras if key.startswith("action_"))
        tasks = sorted(key[5:] for key in extras if key.startswith("task_"))
        project, mode = upgrade.identifier(data["project_id"], "项目"), data["expiry_mode"]
    if not re.fullmatch(r"[0-9]{1,10}", data["version"]):
        raise ClientError("委托版本无效")
    body = {"request_id": data["request_id"], "executor_id": data["executor_id"], "project_id": project,
            "version": upgrade.version(int(data["version"])), "reason": data["reason"], "actions": actions, "task_ids": tasks}
    if mode == "renew":
        if not re.fullmatch(r"[0-9]{1,3}", data["hours"]) or not 1 <= int(data["hours"]) <= 720:
            raise ClientError("有效时长须为 1 至 720 小时")
        body["duration_seconds"] = int(data["hours"]) * 3600
    elif mode == "keep":
        if not re.fullmatch(r"[0-9]{1,12}", data["expires"]):
            raise ClientError("当前到期时间无效")
        current = state["round"].get("delegation:" + delegation.delegation_id(actor, data["executor_id"], project))
        if not current or int(data["expires"]) != current["expires"]:
            raise ClientError("当前到期时间已变化，请重新载入委托", 409)
        body["expires"] = int(data["expires"])
    else:
        raise ClientError("请选择保留到期时间或重新计时")
    return body


def dispatch(handler, method, target, actor):
    from .web import parse_form, same_origin, reauthenticate
    from .httpd import parse_query
    service = handler.server.service
    if method not in {"GET", "POST"}:
        raise ClientError("请求方法无效", 405)
    selected = parse_query(target.query, {"window", "project"}) if method == "GET" else {}
    if method == "POST" and target.query:
        raise ClientError("请从当前助理表单提交")
    if method=='POST' and not same_origin(handler):
        raise ClientError('请从当前助理页面提交',403)
    parse_error=None
    try:
        posted=parse_form(handler,32768,160) if method=='POST' else None
    except ClientError as error:
        posted,parse_error=None,error
    with service.lock:
        reauthenticate(handler,actor)
        snap = service.snapshot()
        state = snap["state"]
        subject = rules.identity(state, actor) or {}
        if not rules.active(state, actor) or subject.get("kind") not in {"human", "executor"}:
            raise ClientError("须为有效人员或 AI 窗口", 403)
        message, status, draft, preview = "", 200, None, False
        if method == "POST":
            if not same_origin(handler):
                raise ClientError("请从当前助理页面提交", 403)
            if subject["kind"] != "human":
                raise ClientError("AI 不能为自己授权或撤回人员委托", 403)
            try:
                if parse_error:raise parse_error
                draft = posted
                op = draft.pop("operation", "")
                if op in {"grant", "grant-preview"}:
                    body = grant_body(state, actor, draft)
                    if op == "grant-preview":
                        delegation.plan(service, actor, "delegate-grant", body["request_id"], body, state)
                        preview, message = True, "请核对精确动作、任务和到期设置后确认。"
                elif op == "revoke":
                    fields(draft, "request_id delegation_id version reason")
                    if not re.fullmatch(r"[0-9]{1,10}", draft["version"]):
                        raise ClientError("委托版本无效")
                    body = {**draft, "version": int(draft["version"])}
                else:
                    raise ClientError("委托操作无效")
                if not preview:
                    action = "delegate-grant" if op == "grant" else "delegate-revoke"
                    status, result = service.submit(actor, action, body["request_id"], body)
                    message = ("委托已更新。" if op == "grant" else "委托已撤回。") if status == 200 else (
                        result.get("message") or (result.get("steps") or [{}])[-1].get("reason", "请求待确认"))
                    if status == 200:
                        selected = {"window": body.get("executor_id"), "project": body.get("project_id")}
                        draft = None
            except (ClientError, Rejected) as error:
                message, status = str(error), getattr(error, "status", 409)
            snap = service.snapshot()
            state = snap["state"]
        return render(actor, state, message, status, selected, draft, snap.get("entries", ()), preview)
