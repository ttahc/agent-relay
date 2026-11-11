"""Project, execution-source and audit views for the upgraded task pool."""

import json
from html import escape
import time
from urllib.parse import quote, urlencode

from . import task_pages as pages
from .display_time import time_html


def panel(actor, title, content):
    return pages.workspace(actor, f'<section class="task-panel"><h1>{title}</h1>{content}</section>')


def input_field(name, label, value="", required=True, size=200):
    need = " required" if required else ""
    return f'<label>{label}<input name="{name}" maxlength="{size}" value="{escape(str(value), quote=True)}"{need}></label>'


def selection(name, label, options, current=None):
    options = list(options)
    if current is not None and current not in {key for key, _ in options}:
        options.insert(0, (str(current), f"当前值不可用：{current}（请重新选择）"))
    rows = "".join(f'<option value="{escape(value, quote=True)}"{" selected" if value == current else ""}>'
                   f'{escape(title)}</option>' for value, title in options)
    return f'<label>{label}<select name="{name}" required>{rows}</select></label>'


def identity_picker(name, label, candidates, current="", optional=False):
    """Searchable native select, restricted to server-provided visible identities."""
    options = [("", "暂不指定" if optional else "请选择账号或窗口")]
    for item in candidates:
        key = item.get("identity") or item.get("id") or item.get("name")
        if not key:
            continue
        title = item.get("window_name") or item.get("window") or item.get("name") or key
        base_title = title
        title = (f'{title} · 窗口 · 责任人 {item.get("owner") or "待确认"}' if item.get("kind") == "executor"
                 else f'{title} · {"人员" if item.get("kind") == "human" else "身份类型待确认"}')
        if item.get("window_name") and item.get("window"):
            title += f' · {item["window"]}'
        if key != base_title and item.get("kind") != "executor":
            title += f"（{key}）"
        options.append((key, title))
    picker = selection(name, label, options, current)
    if optional:
        picker = picker.replace(" required", "")
    note = '<small class="muted-text">没有可选身份；请先登记账号或确认当前项目授权。</small>' if len(options) == 1 else ""
    if current and current not in {key for key, _ in options}:
        note += '<small class="form-error">保留了原值；该身份当前不可选，请核对状态和权限后重新选择。</small>'
    return ('<div class="identity-picker" data-identity-picker><input type="search" data-picker-search '
            f'placeholder="搜索{escape(label, quote=True)}" aria-label="搜索{escape(label, quote=True)}">{picker}{note}</div>')


def text_field(name, label, value="", size=2000, required=True):
    need = " required" if required else ""
    return f'<label>{label}<textarea name="{name}" maxlength="{size}" rows="4"{need}>{escape(value)}</textarea></label>'


def json_field(name, label, value, size=8000):
    return text_field(name, label, json.dumps(value, ensure_ascii=False), size)


def block(title, content):
    return f'<details class="action-details"><summary>{title}</summary>{content}</details>'


def project_options(projects):
    return [(p["id"], p["name"]) for p in projects]


def project_index(actor, projects, admin):
    rows = "".join(f'<li><a href="/projects/{quote(p["id"])}">{escape(p["name"])}</a> · '
                   f'{escape(p["owner"])} · {escape("、".join(p["roles"]))}</li>' for p in projects)
    create = ""
    if admin:
        create = block("登记项目", pages.form("project-save", "登记项目", {"version": 0},
                       input_field("project_id", "稳定项目编号") + input_field("name", "项目名称")))
    return panel(actor, "项目", f'<ul class="roster">{rows}</ul>{create}')


def project_page(actor, data, tasks):
    from . import workbench
    path = "/tasks/new?" + urlencode({"project": data["id"]})
    links = "".join(f'<li><a href="/tasks/{quote(t["task_id"])}">{escape(t["task_id"] + " " + t["title"])}</a>'
                    f' · {escape(pages.STAGES.get(t["stage"], t["stage"]))}</li>' for t in tasks)
    members = "".join(f'<li>{escape(m["identity"])} · {escape("、".join(m["roles"]))} · 版本 {m["version"]}</li>'
                      for m in data["members"])
    round_mode = data.get("automation") is not None
    manage = ""
    if "manager" in data["roles"]:
        manage = block("更新项目名称", pages.form("project-save", "保存项目", {"project_id": data["id"], "version": data["version"]},
                       input_field("name", "显示名称", data["name"])))
        if not round_mode:
            manage += block("登记或调整成员授权", pages.form("project-grant", "保存授权", {"project_id": data["id"]},
                            input_field("name", "人员或执行端") + input_field("roles", "角色（逗号分隔）", required=False)
                            + input_field("version", "授权版本（新成员填 0）", 0)
                            + json_field("resources", "资源授权数组", [])))
    new = f'<a class="primary" href="{escape(path, quote=True)}">登记任务</a>' if {"manager", "receiver"} & set(data["roles"]) else ""
    automation = data.get("automation")
    if automation is not None:
        href = "/collaboration?" + urlencode({"project": data["id"]})
        new += f' <a class="secondary" href="{escape(href, quote=True)}">关系与反馈</a>'
        if "manager" in data["roles"]:
            current = "yes" if automation["enabled"] else "no"
            manage += block("自动执行设置", pages.form("project-automation", "保存自动执行设置",
                            {"project_id": data["id"], "version": automation["version"]},
                            selection("enabled", "项目许可", [("no", "仅通知"), ("yes", "可按任务与窗口授权自动执行")], current)))
    return panel(actor, escape(data["name"]), f'<p class="muted">{escape(data["id"])}</p>{new}{manage}'
                 + (workbench.members_section(data) if round_mode else f'<section class="detail-group"><h2>项目成员</h2><ul>{members}</ul></section>') +
                 f'<section class="detail-group"><h2>项目任务</h2><ul>{links}</ul></section>')


def source_fields():
    return (selection("platform", "平台", [("codex", "Codex"), ("claude", "Claude"), ("gemini", "Gemini"), ("external", "其他")])
            + input_field("window_name", "窗口名称（当前聊天标题）", required=False)
            + input_field("session", "平台会话标识") + input_field("model", "模型")
            + input_field("environment", "环境标识") + input_field("device", "设备")
            + input_field("directory", "工作目录", size=400) + input_field("url", "原始会话链接", required=False, size=600)
            + input_field("parent", "父窗口编号（可选）", required=False))


def executor_index(actor, profile, sources, round_mode=False):
    from .workbench import window_text
    rows = "".join(f'<li><a href="/executors/{quote(item["executor_id"])}">{escape(window_text(item))}</a>'
                   f' · {escape(item["model"])} · {escape(item["owner"])} · {escape(item["status"])}</li>' for item in sources)
    register = ""
    if (profile["binding"] or {}).get("kind") == "human" and profile["projects"]:
        register = '<a class="primary" href="/invitations">邀请 AI 窗口</a>' if round_mode else block(
                         "登记新窗口", pages.form("executor-enroll", "登记窗口", contents=selection("project_id", "项目", project_options(profile["projects"]))
                         + input_field("roles", "角色（executor 或 receiver，可逗号分隔）", "executor") + source_fields()))
    return panel(actor, "窗口目录", f'<ul class="roster">{rows}</ul>{register}')


def executor_page(actor, item):
    from .workbench import window_label
    states = {"active": "进行中", "running": "执行中", "held": "占用中", "released": "已释放", "closed": "已结束",
              "cancelled": "已取消", "accepted": "已验收", "review": "待验收", "revision": "待返修", "idle": "空闲",
              "claimed": "待开始", "intent": "工作中", "started": "已开始", "working": "工作中", "waiting": "等待输入",
              "error": "出错", "finished": "已结束", "stopped": "已停止", "unknown": "待核实", "pending": "待确认",
              "not_started": "未开始", "ended": "已结束", "disabled": "已停用", "paused": "已暂停", "expired": "已过期"}

    def state(value):
        return escape(states.get(value, "待核实（" + str(value or "未回报") + "）"))
    link = f'<p><a href="{escape(item["url"], quote=True)}" rel="noreferrer noopener">打开对应窗口</a></p>' if item.get("url") else ""
    tasks = "".join(f'<li><a data-task-link href="/tasks/{quote(c["task_id"])}">{escape(c["task_id"])}</a> · 领取 {state(c["lifecycle"])}'
                    f' · 执行 {state(c["execution"]["state"])} · 代次 {c["epoch"]}'
                    f' · 回报 {state((c.get("run") or {}).get("state"))}</li>' for c in item["tasks"])
    summary = f'<p class="muted">{escape(item["executor_id"])} · {escape(item["platform"])} · {escape(item["model"])}</p>'
    metadata = "".join(f'<dt>{title}</dt><dd>{escape(str(item.get(key) or ("仅本人、责任人或管理员可见" if key in {"session", "device", "directory"} else "未登记")))}</dd>' for key, title in (
        ("window_name", "窗口名称"), ("window", "窗口编号"), ("owner", "责任人"), ("session", "平台会话"), ("device", "设备"), ("directory", "工作目录"),
        ("environment", "环境"), ("parent", "父窗口"),
    ))
    metadata += f'<dt>最后联系</dt><dd>{time_html(item.get("last_contact"))}</dd>'
    update = ""
    manage = bool(item.get("can_manage", actor in {item.get("owner"), "admin"}))
    management_url = f'/executors/{quote(item["executor_id"])}/manage'
    if item.get("round"):
        if not link:
            link = '<p>按窗口名称查找原聊天；重名时可核对窗口编号、平台会话和工作目录。</p>'
        if item.get("credential_expires"):
            update += f'<p>令牌到期 {time_html(item["credential_expires"])}{" · 请安排轮换" if item["credential_expiring"] else ""}</p>'
        if manage and item["status"] in {"active", "disabled", "disputed"}:
            path = "/tokens/rotate?" + urlencode({"identity": item["executor_id"]})
            update += f'<p><a href="{escape(path, quote=True)}">轮换令牌</a></p>'
        contact = {"stale": "联系异常，执行状态待核", "current": "近期有心跳", "unconfirmed": "心跳未确认"}
        update += f'<p>{contact.get(item["contact"], "心跳待核实")} · 并发上限 {item["concurrency"]}</p>'
    if item["executor_id"] == actor:
        update += block("更新窗口名称与会话资料", pages.form("executor-sync", "保存窗口资料", contents=input_field("window_name", "窗口名称（当前聊天标题）", item.get("window_name") or "", required=False)
                       + input_field("session", "平台会话标识", item["session"])
                       + input_field("model", "模型", item["model"]) + input_field("environment", "环境", item["environment"])))
    project_links = (f'<a class="secondary" href="/accounts/projects?{urlencode({"identity": item["executor_id"]})}">调整项目授权</a>'
                     if item.get("can_manage_projects") else "")
    controls = f'<a class="secondary" href="{management_url}">查看影响与管理窗口</a>' if manage else '<p class="muted-text">窗口管理由责任人或系统管理员操作。</p>'
    tabs = '<nav class="seg" aria-label="窗口详情">' + "".join(f'<a href="#{key}">{label}</a>' for key, label in (
        ("window-overview", "概览"), ("window-tasks", "任务"), ("window-permissions", "权限与委托"),
        ("window-capabilities", "能力"), ("window-credentials", "凭据"), ("window-admin", "停用与解绑"))) + '</nav>'
    body = (f'<div class="phead"><a href="/executors">← 窗口管理</a><h2>{escape(window_label(item))}</h2>'
            f'<a class="secondary" href="/executors/{quote(item["executor_id"])}/execution">执行配置、动作与资源</a></div>{tabs}'
            f'<section class="box" id="window-overview"><h3>概览</h3>{summary}<p>窗口编号 [{escape(item["window"])}]</p>{link}<dl>{metadata}</dl></section>'
            f'<section class="box" id="window-tasks"><h3>任务与领取</h3><ul>{tasks or "<li>暂无任务</li>"}</ul></section>'
            f'<section class="box" id="window-permissions"><h3>权限与委托</h3>{project_links}<a class="secondary" href="/assistants">查看助理与委托</a>{controls}</section>'
            f'<section class="box" id="window-capabilities"><h3>能力</h3><a class="secondary" href="/capabilities?{urlencode({"identity": item["executor_id"]})}">查看能力声明与核实记录</a></section>'
            f'<section class="box" id="window-credentials"><h3>凭据与联系</h3>{update or "<p>暂无凭据资料</p>"}</section>'
            f'<section class="box" id="window-admin"><h3>停用与解绑</h3><p class="muted-text">先核对当前任务、资源占用、项目授权与委托，再提交窗口管理操作。</p>{controls}</section>')
    return pages.workspace(actor, f'<section class="wb-page">{body}</section>')


def capability_page(actor, profile, data):
    rows = "".join(f'<li>{escape(row["project_id"])} · {escape(row["id"])} · {escape(row["value"])} · {escape(row["level"])} · 版本 {row["version"]}'
                   f'<small class="fingerprint">{escape(row["evidence"]["note"])} {escape(row["evidence"]["sha256"])}</small></li>'
                   for row in data["capabilities"])
    editor = ""
    writable = [project for project in profile["projects"] if {"manager", "executor", "receiver"} & set(project["roles"])]
    if writable:
        fields = (selection("project_id", "项目", project_options(writable))
                  + input_field("name", "执行身份", data["identity"]) + input_field("capability", "能力标识")
                  + selection("kind", "类别", [("skill", "业务"), ("environment", "环境")])
                  + input_field("value", "能力值") + input_field("environment", "环境标识", (profile["binding"] or {}).get("environment", "human"))
                  + selection("level", "证据等级", [("declared", "声明"), ("verified", "已验证")])
                  + text_field("evidence_note", "证据说明") + input_field("evidence_sha256", "证据 SHA256", required=False, size=64)
                  + input_field("valid_days", "有效天数", 30) + pages.hidden("issued", int(time.time()))
                  + input_field("version", "记录版本（新记录填 0）", 0))
        editor = block("声明或核对能力", pages.form("capability-save", "保存能力记录", contents=fields))
    lookup = '<form class="operation" action="/capabilities" method="get">' + input_field("identity", "查询身份", data["identity"]) + (
        '<button class="secondary" type="submit">查询</button></form>')
    return panel(actor, "能力与证据", f'{lookup}<ul class="roster">{rows}</ul>{editor}')


def contract_fields(project, spec=None, resources=None, dependencies=None, round_mode=False, actor=""):
    creating = spec is None
    spec = spec or {"iteration": {"goal": "", "previous": [], "next": []}, "delivery": "",
                    "requirements": [], "review_mode": "source", "user_basis": ""}
    lines = []
    for row in spec["requirements"]:
        necessity = "必需" if row["required"] else "优选"
        fields = ((row["id"], "catalog", "*", necessity, "catalog", str(row["definition_version"]))
                  if "definition_version" in row else (row["id"], row["kind"], row["value"], necessity, row["evidence"]))
        lines.append(" | ".join(fields))
    requirements = "\n".join(lines)
    routing = ""
    if round_mode:
        selection_data = spec.get("dispatch", {"mode": "open", "subjects": [], "capabilities": [],
                                               "automation": "notify", "owner": actor})
        routing = (selection("dispatch_mode", "领取模式", [("open", "项目内自主领取"), ("prefer", "优先通知"),
                                                          ("only", "限定领取")], selection_data["mode"])
                   + input_field("dispatch_owner", "任务负责人", selection_data["owner"], required=False)
                   + input_field("dispatch_subjects", "指定人员或窗口身份（逗号分隔）", ",".join(selection_data["subjects"]),
                                 required=False, size=2700)
                   + json_field("dispatch_capabilities", "指定能力组，无则填 []", selection_data["capabilities"])
                   + selection("dispatch_automation", "执行方式", [("notify", "仅通知"), ("auto", "按授权自动领取并执行")],
                               selection_data["automation"]))
    completion = (selection("completion_policy", "完成策略（创建后不可变更）", [
        ("review-required", "需要验收"), ("executor-direct", "执行者直接完成（不代表独立验收）")]) if creating else
        '<p class="muted">完成策略（不可变更）：' + ("执行者直接完成（不代表独立验收）" if spec.get("completion_policy") == "executor-direct" else "需要验收") + '</p>')
    return (completion + pages.hidden("project_id", project)
            + text_field("iteration_goal", "迭代目标", spec["iteration"]["goal"])
            + input_field("iteration_previous", "前序任务（逗号分隔）", ",".join(spec["iteration"]["previous"]), required=False)
            + input_field("iteration_next", "后续任务（逗号分隔）", ",".join(spec["iteration"]["next"]), required=False)
            + text_field("delivery", "交付物", spec["delivery"])
            + text_field("requirements", "领取能力，每行填写 编号 | 类别 | 值 | 必需或优选 | 等级，目录条目保留第六列版本",
                         requirements, 8000)
            + '<p class="muted">示例 markdown | skill | * | 必需 | declared</p>'
            + json_field("resources", "占用资源数组，无资源填 []", resources or [])
            + json_field("dependencies", "前置条件数组，无依赖填 []", dependencies or [])
            + selection("review_mode", "独立性策略", [("source", "不同执行主体"), ("account", "不同责任账号"),
                                                    ("user", "人工直接接受")], spec["review_mode"])
            + text_field("user_basis", "人工直接接受的明确授权依据", spec["user_basis"], required=False) + routing)


def task_form(actor, project, receivers, round_mode=False):
    choices = [(name, name) for name in receivers]
    fields = (input_field("title", "任务标题") + text_field("brief", "工作范围与冻结输入", size=40000)
              + text_field("criteria", "完成判据（每行一条）", size=3200)
              + selection("kind", "执行类型", [("documentation", "资料")])
              + selection("receiver", "验收人", choices) + contract_fields(project["id"], round_mode=round_mode, actor=actor))
    return panel(actor, "登记资料任务", '<p class="muted">填写完整合同后保存为待启动。</p>' + pages.form("register", "登记任务", contents=fields))


def task_contract(view):
    task, claim = view["task"], view["active"]
    spec = task.get("contract")
    if not spec:
        return ""
    requirements = "".join(f'<li>{escape(r["id"])} · {escape(r["value"])} · {"必需" if r["required"] else "优选"}'
                           f' · {escape(r["evidence"])}</li>' for r in spec["requirements"])
    dependencies = "".join(f'<li>{escape(dep["task"])} · {escape(dep["output"])} · {escape(dep["criterion"])}</li>'
                           for dep in task["dependencies"])
    missing = "".join(f'<li>{escape(reason)}</li>' for reason in view["qualification"]["missing"])
    preferred = "".join(f'<li>{escape(reason)}</li>' for reason in view["qualification"]["preferred"])
    controls = ""
    admin = "manager" in view["roles"]
    values = {key: task[key] for key in ("task_id", "version", "scope_version")}
    if admin and task["status"] in {"available", "running"}:
        op, label = ("task-hold", "设为待启动") if spec["open"] else ("task-publish", "开放领取")
        controls += block(label, pages.form(op, label, values, text_field("reason", "操作依据")))
        edit = contract_fields(spec["project_id"], spec, task["resources"], task["dependencies"], view.get("round"))
        controls += block("变更任务范围", pages.form("task-scope", "保存范围并待启动", values,
                                                   text_field("reason", "变更依据") + edit))
    if claim and (admin or claim["origin"] == view.get("viewer")):
        claim_fields = {"task_id": task["task_id"], "version": task["version"], "claim_id": claim["claim_id"], "epoch": claim["epoch"]}
        if claim.get("recovery", {}).get("status") == "pending":
            if admin:
                controls += block("处置恢复待核", pages.form("task-recover", "记录处置并核对释放", claim_fields,
                              text_field("reason", "处置决定") + text_field("evidence", "实际停止与资源依据")
                              + text_field("notes", "接续材料", size=16000) + text_field("unresolved", "外部效果待核项", required=False)))
        else:
            controls += block("登记中断", pages.form("task-interrupt", "进入恢复待核", claim_fields, text_field("reason", "中断事实")))
    tid = quote(task["task_id"])
    window = (f'<p>当前窗口 <a href="/executors/{quote(view["window_id"])}">{escape(view["window"])}</a></p>'
              if view["window"] and view.get("window_id") else "")
    routing = ""
    if view.get("round"):
        config = spec.get("dispatch", {})
        mode = {"open": "项目内自主领取", "prefer": "优先通知，其他合格主体仍可领取", "only": "限定领取"}
        routing = (f'<p>任务负责人 {escape(config.get("owner") or "待确认")} · {mode[config.get("mode", "open")]}'
                   f' · 验收人 {escape(task["receiver"])}</p>')
        if config.get("subjects"):
            routing += f'<p>指定范围 {escape("、".join(config["subjects"]))}</p>'
    return f"""<section class="detail-group">
  <h2>任务合同与领取条件</h2>
  <p>{escape(spec["iteration"]["goal"])}</p><p>交付物 {escape(spec["delivery"])}</p>{window}{routing}
  <ul>{requirements}</ul>
  <h3>前置条件</h3>{f"<ul>{dependencies}</ul>" if dependencies else "<p>无外部任务依赖。</p>"}
  <h3>当前身份匹配</h3>{f"<ul>{missing}</ul>" if missing else "<p>必需条件满足。</p>"}{f"<ul>{preferred}</ul>" if preferred else ""}
  <p><a href="/audit?task={tid}">查看任务时间线</a></p>{controls}
</section>"""


def audit_search(query, result):
    search = '<form class="operation" action="/audit" method="get">' + "".join(
        input_field(key, title, query.get(key, ""), required=False)
        for key, title in (("task", "任务号"), ("actor", "执行身份"), ("request", "请求编号"))) + (
        '<button class="secondary" type="submit">查找</button></form>')
    rows = []
    for item in result.get("events", []):
        at = item.get("committed_utc") or item.get("received_utc") or "时间未知"
        event = item.get("operation") or item.get("command") or "请求"
        who = item.get("window") or item.get("actor") or "身份未知"
        status = {"applied": "已生效", "pending": "待裁定", "rejected": "已拒绝", "evidence-only": "仅留证据"}.get(item["result"], item["result"])
        state = {"事件": item.get("event_id"), "请求": item.get("request_id"), "责任账号": item.get("owner"),
                 "提交服务": item.get("committer"), "原因": item.get("reason"), "变更": item["changes"]}
        rows.append(block(f'{escape(at)} · {escape(who)} · {escape(event)} · {escape(status)}',
                          f'<pre class="audit-data">{escape(json.dumps(state, ensure_ascii=False, indent=2))}</pre>'))
    return search + "".join(rows)


def audit_page(actor, query, result):
    return panel(actor, "状态追溯", audit_search(query, result))


def release_page(actor, data):
    release, fmt = data["release"], data["format"]
    if not fmt:
        return panel(actor, "升级验收", "<p>待迁移数据合同。</p>")
    record = escape(json.dumps(release, ensure_ascii=False, indent=2))
    controls = ""
    if "receiver" in data["roles"] and release["status"] in {"pending", "invalid"}:
        controls += block("独立验收", pages.form("release-accept", "提交验收", contents=text_field("reason", "验收依据") + text_field("report", "验收报告 JSON", size=256000)))
    if "manager" in data["roles"] and release["status"] == "accepted":
        controls += pages.form("release-close", "关闭本次升级验收", {"acceptance": release["acceptance"]}, text_field("reason", "收口依据"))
    if "manager" in data["roles"] and release["status"] in {"accepted", "closed"}:
        controls += block("更正结论", pages.form("release-correct", "标记结论待复核", contents=text_field("reason", "更正依据")))
    return panel(actor, "升级验收", f'<p>{escape(fmt["upgrade"])} · 数据合同 {fmt["schema"]}</p><pre class="audit-data">{record}</pre>{controls}')


def operations_page(actor, data, show_migration=False):
    content = release_page(actor, data)
    migration = bool((data.get("format") or {}).get("maintenance")) or show_migration
    extra = (f'<section class="box"><h3>历史迁移与凭据运维</h3>{identity_controls()}</section>' if migration else
             '<p class="muted-text">日常窗口管理请进入窗口管理页。历史身份迁移工具已收起；仅在需要修复历史数据时，'
             '<a href="/upgrade?migration=1">展开历史运维工具</a>。</p>')
    before, after = content.rsplit('</main>', 1)
    return before + extra + '</main>' + after


def identity_controls():
    binding = (input_field("name", "原身份") + selection("kind", "类型", [("human", "人员"), ("executor", "窗口")])
               + input_field("owner", "责任人（人员填本人）", required=False)
               + text_field("reason", "确认依据") + json_field("source", "窗口会话资料，人员填 null", None))
    change = (input_field("name", "身份") + input_field("version", "当前凭据版本", 1)
              + selection("status", "凭据操作", [("active", "轮换并启用"), ("disabled", "停用")]) + text_field("reason", "处置依据"))
    return (block("确认既有身份", pages.form("identity-bind", "保存绑定", contents=binding))
            + block("轮换或停用凭据", pages.form("credential-change", "保存凭据决定", contents=change)))
