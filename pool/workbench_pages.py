"""Project, AI window, activity and account views of the v3 workspace."""

from html import escape as e
from urllib.parse import quote, urlencode

from . import task_pages as pages, upgrade_pages as ui, workbench as wb
from .display_time import time_html


REPORT = {"claimed": ("待开始", "mid"), "intent": ("工作中", "info"), "started": ("工作中", "info"), "working": ("工作中", "info"),
          "waiting": ("等待输入", "mid"), "error": ("出错", "warn"), "finished": ("已结束", "dec")}
STATUS = {"active": ("正常", "st-on"), "disabled": ("已停用", "st-off"), "expired": ("已过期", "st-off"),
          "pending": ("待激活", "st-mid"), "disputed": ("待核实", "st-mid"),
          "paused": ("已暂停", "st-mid"), "archived": ("已归档", "st-off")}
ROW_LIMIT = 300


def work(actor, content):
    return pages.workspace(actor, f'<section class="wb-page">{content}</section>')


def two(first, second):
    return f'<div class="two">{first}{second}</div>'


def stamp(epoch):
    return time_html(epoch, compact=True)


def live(tasks, project):
    return [t for t in tasks if wb.project_of(t) == project and t["stage"] not in wb.ARCHIVE]


def counts(tasks):
    return [(key, name, n) for key, name, _ in wb.COLUMNS if (n := sum(wb.column_of(t) == key for t in tasks))]


def stack(tasks):
    """A proportional bar. SVG geometry is used because the page policy forbids inline styles."""
    total, x, bars = len(tasks), 0.0, ""
    parts = counts(tasks)
    for key, name, n in parts:
        width = n / total * 100
        bars += (f'<rect class="f-{key}" x="{x:.3f}" y="0" width="{width:.3f}" height="8">'
                 f'<title>{name} {n}</title></rect>')
        x += width
    label = "、".join(f"{name} {n}" for _, name, n in parts) or "暂无任务"
    return (f'<svg class="stack" viewBox="0 0 100 8" preserveAspectRatio="none" role="img" '
            f'aria-label="{label}">{bars}</svg>')


def role_chip(roles):
    return f'<span class="chip on">我是{wb.tier_name(roles)}</span>' if roles else ""


def member_avatars(members):
    return "".join(wb.window_avatar(m, False) for m in members if m["roles"])


def project_index(actor, cards, tasks, admin):
    items = ""
    for project in cards:
        rows = live(tasks, project["id"])
        people = [m for m in project["members"] if m["roles"]]
        items += f"""<a class="proj" href="/projects/{quote(project["id"])}">
  <div class="phead"><h2>{e(project["name"])}</h2>{role_chip(project["roles"])}</div>
  {stack(rows)}
  <div class="muted-text">{len(rows)} 个任务 · {len(people)} 名成员 · 项目创建人 {e(project["owner"])}</div>
  <div class="avs">{member_avatars(people)}</div></a>"""
    create = ""
    if admin:
        create = ui.block("新建项目", pages.form("project-save", "登记项目", {"version": 0},
                          ui.input_field("project_id", "稳定项目编号") + ui.input_field("name", "项目名称")))
    return work(actor, f"""<div class="phead"><span class="muted-text">{len(cards)} 个项目</span></div>
  <div class="projgrid">{items or '<p class="empty">你还不属于任何项目。</p>'}</div>{create}""")


def overview_tab(project, tasks, activity):
    rows = live(tasks, project["id"])
    legend = "".join(f'<span><i class="f-{key}"></i>{name} {sum(wb.column_of(t) == key for t in rows)}</span>'
                     for key, name, _ in wb.COLUMNS)
    query = urlencode({"project": project["id"]})
    links = f'<a class="secondary" href="/board?{query}">在看板中查看</a><a class="secondary" href="/list?{query}">在列表中查看</a>'
    if {"manager", "receiver"} & set(project["roles"]):
        links += f'<a class="primary" data-new-task href="/tasks/new?{query}">新建任务</a>'
    links += f'<a class="secondary" href="/collaboration?{query}">反馈与决定</a>'
    recent = ""
    for item in [row for row in activity if row["project"] == project["id"]][:8]:
        who = wb.window_text(item)
        recent += (f'<li><a class="tid" data-task-link href="/tasks/{quote(item["task_id"])}">{e(item["task_id"])}</a>'
                   f'<b>{e(who)}</b>{e(wb.event_label(item) or "")}'
                   f'<span class="when">{stamp(item.get("committed_utc"))}</span></li>')
    return f"""<div class="ovgrid">
  <div class="box"><h3>任务进度</h3>{stack(rows)}<div class="legend">{legend}</div><div class="addrow">{links}</div></div>
  <div class="box"><h3>最近动态</h3><ul class="recent">{recent or '<li class="muted-text">暂无</li>'}</ul></div></div>"""


def settings_tab(project):
    if "manager" not in project["roles"]:
        return '<p class="empty">只有项目管理员可以修改设置。</p>'
    automation = project["automation"]
    return f"""<div class="box"><h3>项目名称</h3>{pages.form("project-save", "保存项目", {"project_id": project["id"], "version": project["version"]},
        ui.input_field("name", "显示名称", project["name"]))}</div>
  <div class="box"><h3>自动执行</h3>{pages.form("project-automation", "保存自动执行设置", {"project_id": project["id"], "version": automation["version"]},
        ui.selection("enabled", "项目许可", [("no", "仅通知"), ("yes", "可按任务与窗口授权自动执行")], "yes" if automation["enabled"] else "no"))}</div>"""


def project_page(actor, project, tasks, activity, tab):
    tab = tab if tab in {"members", "settings"} else "overview"
    names = (("overview", "概览"), ("members", "成员"), ("settings", "设置"))
    links = "".join(f'<a href="/projects/{quote(project["id"])}{"" if key == "overview" else "?tab=" + key}"'
                    f'{" aria-current=\"page\"" if key == tab else ""}>{name}</a>' for key, name in names)
    body = {"overview": lambda: overview_tab(project, tasks, activity), "members": lambda: wb.members_section(project),
            "settings": lambda: settings_tab(project)}[tab]()
    return work(actor, f"""<div class="phead"><a href="/projects">← 全部项目</a></div>
  <div class="phead"><h2>{e(project["name"])}</h2>{role_chip(project["roles"])}<nav class="seg right" aria-label="项目页面">{links}</nav></div>{body}""")


def report_of(item):
    current = [c for c in item["tasks"] if c["lifecycle"] == "active"]
    if not current:
        return "空闲", "dec", "当前没有进行中的任务", 0
    latest = max(current, key=lambda c: (c.get("run") or {}).get("time", 0))
    run = latest.get("run") or {}
    label, kind = REPORT.get(run.get("state"), ("工作中", "info"))
    return label, kind, run.get("evidence") or f'正在处理 {latest["task_id"]}', run.get("time", 0)


def online_of(item):
    if item["status"] == "disabled":
        return "已停用", "off"
    if item["status"] != "active":
        return STATUS.get(item["status"], (item["status"], ""))[0], "off"
    return {"current": ("● 在线", ""), "stale": ("○ 联系中断", "off"), "unconfirmed": ("○ 心跳未确认", "off")}[item["contact"]]


def capability_row(row):
    verified = row["level"] == "verified"
    return (f'<li><span>{e(row["id"])}</span>'
            f'<span class="badge {"ok" if verified else "dec"}">{"已核实" if verified else "已申报"}</span>'
            f'<span class="basis">{e(row["evidence"]["note"])} · 到期 {stamp(row["expires"])}</span></li>')


def task_line(task):
    pill = "archive" if task["stage"] in wb.ARCHIVE else wb.column_of(task)
    return (f'<li><a data-task-link href="/tasks/{quote(task["task_id"])}">{e(task["task_id"])} {e(task["title"])}</a> '
            f'<span class="pill c-{pill}">{wb.column_title(task)}</span></li>')


def window_card(item, tasks, manage_projects=False):
    claimed = {c["task_id"] for c in item["tasks"]}
    mine = [tasks[tid] for tid in sorted(claimed)
            if tid in tasks and any(c["task_id"] == tid and c["lifecycle"] == "active" for c in item["tasks"])]
    done = [tasks[tid] for tid in sorted(claimed)
            if tid in tasks and wb.column_of(tasks[tid]) == "done" and tasks[tid] not in mine]
    online, state = online_of(item)
    label, kind, note, at = report_of(item)
    where = " · ".join(e(str(v)) for v in (item.get("platform"), f'责任人 {item.get("owner")}', item.get("directory"))
                       if v)
    joined = "；".join(f'{e(m["name"])}（{wb.tier_name(m["roles"])}）' for m in item["memberships"]) or "无"
    caps = "".join(capability_row(row) for row in item["capabilities"]) or '<li class="muted-text">尚未申报</li>'
    project_link = (f'<a class="link-sm" href="/accounts/projects?{urlencode({"identity": item["executor_id"]})}">'
                    f'调整项目</a>'
                    if manage_projects else "")
    manage_link = (f'<a class="secondary" href="/executors/{quote(item["executor_id"])}/manage">查看影响与管理窗口</a>'
                   if item.get("can_manage") else "")
    return f"""<article class="win">
  <div class="head"><a class="plain" href="/executors/{quote(item["executor_id"])}">{wb.window_avatar(item)}</a><span class="online {state}">{online}</span></div>
  <div class="muted-text">{where} · 最近联系 {stamp(item.get("last_contact"))}</div>
  {'' if item.get("window_name") else '<div class="muted-text">窗口名称未登记，可由对应窗口同步当前聊天标题。</div>'}
  <div class="report"><span class="badge {kind}">{label}</span><span>{e(note)}</span><span class="muted-text when">{stamp(at) if at else ""}</span></div>
  <div class="muted-text">自动执行设置：<b>{"按授权自动领取并执行" if item["auto"] else "仅通知"}</b> · 实际执行还需窗口可用、项目允许、任务允许，且平台有可调用的执行接口</div>
  <div><h4>所在项目 {project_link}</h4><div class="muted-text">{joined}</div></div>
  <div><h4>能力声明 <a class="link-sm" href="/capabilities?{urlencode({"identity": item["executor_id"]})}">查看或申报</a></h4><ul class="caps">{caps}</ul></div>
  <div><h4>当前任务</h4><ul>{"".join(task_line(t) for t in mine) or '<li class="muted-text">无</li>'}</ul></div>
  <div><h4>已完成</h4><ul>{"".join(task_line(t) for t in done) or '<li class="muted-text">无</li>'}</ul></div>
  <div class="addrow">{manage_link}</div>
</article>"""


def windows_page(actor, profile, sources, tasks, show_archived=False):
    index = {t["task_id"]: t for t in tasks}
    invite = ""
    if (profile["binding"] or {}).get("kind") == "human" and profile["projects"]:
        invite = '<a class="primary right" href="/invitations">邀请 AI 窗口</a>'
    binding = profile["binding"] or {}
    manage_projects = (binding.get("kind") == "human" and binding.get("status") == "active"
                       and binding.get("admin") is True)
    archived = sum(item["status"] == "archived" for item in sources)
    shown = [item for item in sources if show_archived or item["status"] != "archived"]
    cards = "".join(window_card(item, index, manage_projects) for item in shown)
    archive_link = ('<a class="secondary" href="/executors">收起归档窗口</a>' if show_archived else
                    f'<a class="secondary" href="/executors?archived=1">查看归档窗口（{archived}）</a>')
    own_execution = f'<a class="secondary" href="/executors/{quote(actor)}/execution">我的执行配置与资源</a>'
    return work(actor, f"""<div class="phead"><span class="muted-text">{len(sources)} 个窗口</span>{own_execution}{invite}</div>
  <div class="addrow">{archive_link}</div>
  <div class="wins">{cards or ('<p class="empty">当前没有未归档窗口，可查看归档窗口。</p>' if archived and not show_archived else '<p class="empty">还没有登记 AI 窗口。</p>')}</div>""")


def feed_row(item):
    who = wb.window_text(item) or "未知"
    reason = f'<span class="muted-text">：{e(item["reason"])}</span>' if item.get("reason") else ""
    return (f'<tr><td class="tid">{stamp(item.get("committed_utc"))}</td>'
            f'<td>{wb.avatar(who, bool(item.get("window")))}</td>'
            f'<td><a class="tid" data-task-link href="/tasks/{quote(item["task_id"])}">{e(item["task_id"])}</a> '
            f'<span class="muted-text">{e(item["title"])}</span></td>'
            f'<td class="wide">{e(wb.event_label(item) or "")}{reason}</td></tr>')


def activity_page(actor, rows, who, query, result):
    names = sorted({row.get("window") or row.get("actor") or "" for row in rows} - {""})
    shown = [row for row in rows if not who or who in {row.get("window"), row.get("actor")}]
    options = [("", "全部")] + [(name, name) for name in names]
    picker = ui.selection("who", "按人员筛选", options, who).replace(" required", "")
    body = "".join(feed_row(row) for row in shown[:ROW_LIMIT])
    more = f'<p class="muted-text">只显示最近 {ROW_LIMIT} 条，更早的记录请按编号追溯。</p>' if len(shown) > ROW_LIMIT else ""
    trace = ui.audit_search(query, result)
    opened = " open" if query else ""
    return work(actor, f"""<div class="addrow">
    <form class="wb-inline" method="get" action="/audit" data-auto>{picker}<noscript><button class="secondary" type="submit">应用</button></noscript></form>
    <span class="muted-text">每条记录都来自账本，点编号查看任务和技术细节。时间为 Asia/Hong_Kong（UTC+8），悬停查看 UTC。</span>
    <a class="secondary right" href="/board.md" download>导出看板</a></div>
  <div class="table-wrap"><table><thead><tr><th>时间</th><th>人员</th><th>任务</th><th>操作</th></tr></thead>
    <tbody>{body or '<tr><td colspan="4" class="muted-text">没有记录。</td></tr>'}</tbody></table></div>{more}
  <details class="action-details"{opened}><summary>按任务、执行身份或请求编号追溯</summary>{trace}</details>""")


def accounts_page(actor, rows, invite, code, controls):
    body = ""
    for row in rows:
        ai = row["kind"] == "executor"
        status, kind = STATUS.get(row["status"], (row["status"] or "未确认", "st-mid"))
        projects = "；".join(f'{e(p["name"])}·{wb.tier_name(p["roles"])}' for p in row["projects"]) or "无"
        target = urlencode({"identity": row["name"]})
        action = ""
        if row["kind"] == "human":
            action = f'<a class="secondary" href="/accounts/reset?{target}">重置密码</a>'
        elif ai and row["status"] in {"active", "disabled", "disputed"}:
            action = f'<a class="secondary" href="/tokens/rotate?{target}">轮换令牌</a>'
        if row["kind"] in {"human", "executor"}:
            action += f'<a class="secondary" href="/accounts/projects?{target}">调整项目</a>'
        where = (f'AI 窗口 · {e(str(row.get("platform") or ""))} · 责任人 {e(str(row.get("owner") or ""))}' if ai else "人员"
                 if row["kind"] == "human" else "身份未确认")
        body += (f'<tr><td>{wb.window_avatar(row)}</td><td>{where}</td>'
                 f'<td>{"系统管理员" if row["admin"] else "普通成员"}</td><td class="wide muted-text">{projects}</td>'
                 f'<td><span class="{kind}">{status}</span></td><td><div class="ops">{action}</div></td></tr>')
    opened = " open" if code else ""
    restore = "".join(
        pages.form("credential-change", f'重新启用 {e(row["name"])}',
                   {"name": row["name"], "version": row["credential"], "status": "active"},
                   ui.text_field("reason", f'重新启用 {e(row["name"])} 的依据'), secondary=True)
        for row in rows if row["kind"] == "human" and row["status"] == "disabled" and not row["admin"])
    if restore:
        restore = ui.block("重新启用已停用的人员", '<p class="muted-text">重新启用后用原密码登录；停用前的登录会话和访问令牌不会恢复。'
                           '名下窗口随责任人恢复认证，已单独停用、暂停或归档的窗口保持原状。</p>' + restore)
    return work(actor, f"""<div class="table-wrap"><table><thead><tr><th>账号</th><th>类型</th><th>系统角色</th><th>所在项目</th><th>状态</th><th>操作</th></tr></thead>
    <tbody>{body}</tbody></table></div>
  <p class="muted-text">停用后不能登录或调用接口，历史记录保留。重置密码和轮换令牌的结果只显示一次。</p>
  <details class="action-details"{opened}><summary>生成人员邀请码</summary>{code}{invite}</details>{restore}{controls}""")


def permissions_page(actor):
    yes, no = '<span class="y">✓</span>', '<span class="n">—</span>'
    rows = (("查看项目内的任务、动态和反馈", yes, yes, yes, yes, yes),
            ("记录反馈（提需求）", no, yes, yes, yes, no),
            ("新建任务（贡献者登记的任务由自己验收，由项目管理员开放）", no, yes, yes, no, no),
            ("领取、交付、放回任务", no, yes, yes, no, no),
            ("被指定为验收人，验收或退回", no, yes, yes, no, no),
            ("开放、暂停、取消任务，处理任务关系", no, yes, no, no, no),
            ("评估反馈、登记决定、拆分与合并", no, yes, no, no, no),
            ("项目设置、成员与角色", no, yes, no, no, no),
            ("管理账号：重置密码、轮换令牌、人员邀请码", yes, no, no, no, no),
            ("新建项目", yes, no, no, no, no))
    fields = (("任务负责人", "跟进任务结果，首页「我负责跟进的」列出未完成的任务。新建任务时默认是创建人"),
              ("执行人", "领取后自动填上。可以交付、放回"),
              ("验收人", "新建任务时确定，只有项目管理员登记时能指定他人；验收人不能领取自己验收的任务"))
    matrix = "".join(f'<tr><td class="wide">{row[0]}</td>{"".join(f"<td>{cell}</td>" for cell in row[1:])}</tr>'
                     for row in rows)
    table = "".join(f'<tr><td><b>{name}</b></td><td class="wide">{text}</td></tr>' for name, text in fields)
    return work(actor, f"""<p class="muted-text">权限分两层。系统层只有「系统管理员」和「普通成员」。项目层有四档角色，只管权限：一个账号在不同项目里可以担任不同角色。谁执行、谁验收不是角色，而是每个任务上的字段。AI 窗口最高只能是贡献者。</p>
  <div class="table-wrap"><table class="matrix"><thead><tr><th>操作</th><th>系统管理员</th><th>项目管理员</th><th>贡献者</th><th>报告者</th><th>观察者</th></tr></thead><tbody>{matrix}</tbody></table></div>
  <h3>任务上的分工</h3>
  <div class="table-wrap"><table><thead><tr><th>字段</th><th>说明</th></tr></thead><tbody>{table}</tbody></table></div>
  <h3>窗口与人员</h3><p class="muted-text">窗口用于定位实际 AI 会话，包括窗口名称、平台会话和工作目录。责任人是窗口归属的人员，负责该窗口的授权与凭据管理；任务负责人跟进某个任务的结果，两者可不同。助理是人员与窗口之间的委托关系。项目角色（贡献者、报告者、观察者等）决定项目权限，执行人和验收人是任务上的分工。</p>
  <p class="muted-text">系统管理员可以查看所有项目，但不自动参与项目工作，要记录反馈、领取或验收需先加入项目。网页登录用账号密码，AI 窗口和自动化客户端用各自的令牌，两者分开验证。</p>""")


def self_page(actor, profile, capabilities, form, message, failed):
    binding = profile["binding"] or {}
    joined = ("".join(f'<div>{e(p["name"])} · <b>{wb.tier_name(p["roles"])}</b></div>' for p in profile["projects"])
              or '<span class="muted-text">还没有加入项目</span>')
    kind = "AI 窗口" if binding.get("kind") == "executor" else "人员"
    caps = "".join(capability_row(row) for row in capabilities) or '<li class="muted-text">尚未申报</li>'
    note = f'<p class="{"form-error" if failed else "muted-text"}" role="status">{e(message)}</p>' if message else ""
    return work(actor, f"""<div class="ovgrid">
  <div class="box"><h3>{wb.window_avatar({**binding, "name": actor})}</h3>
    <div class="muted-text">{kind} · {"系统管理员" if binding.get("admin") else "普通成员"}</div>
    <div><h4 class="muted-text">所在项目</h4>{joined}</div>
    <div><h4>修改密码</h4>{note}{form}</div></div>
  <div class="box"><h3>我的能力</h3><p class="muted-text">按项目申报，写明依据。项目管理员或验收人核实后会标为已核实。任务要求某项能力时，领取前会核对。</p>
    <ul class="caps">{caps}</ul><div class="addrow"><a class="secondary" href="/capabilities">申报或查看能力</a></div></div></div>""")
