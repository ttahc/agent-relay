"""Board, list, personal work and task sheet for the v3 workspace."""

import json
import hashlib
import re
from html import escape as e
from urllib.parse import parse_qs, quote, urlencode

from . import __version__, RELEASE_NAME, task_pages as pages, upgrade_pages as ui
from .packages import ClientError
from .display_time import local_text, time_html


COLUMNS = (
    ("draft", "草稿", {"waiting", "merge_pending"}),
    ("open", "可领取", {"available"}),
    ("doing", "进行中", {"claimed", "running", "paused", "recovery", "handoff_pending", "cancel_pending"}),
    ("review", "待验收", {"review"}),
    ("rework", "返修中", {"revision"}),
    ("done", "已完成", {"accepted", "pending_close", "pending_commit", "completed", "closed_missing", "closed_candidate"}),
)
ARCHIVE = {"cancelled": "已取消", "replaced": "已拆分", "merged": "已归并"}
COLUMN_OF = {stage: key for key, _, stages in COLUMNS for stage in stages}
COLUMN_NAME = {key: name for key, name, _ in COLUMNS}
FLAG_TEXT = {"claimed": "已领取", "paused": "已暂停", "recovery": "恢复待核", "handoff_pending": "交接中",
             "cancel_pending": "取消中，待确认停止", "accepted": "待结束", "pending_close": "待归档", "closed_missing": "证据缺失"}
DECLARE = "执行人声明本次执行已结束，相关占用已释放"
SEARCH = re.compile(r"^(状态|执行|验收|负责|项目|标签)[:：](.+)$")
EVENTS = {"propose": "提出任务", "register": "登记任务", "claim": "领取任务", "seal": "上传交付", "stopped": "确认已停止",
          "acquire": "开始返修", "resume": "继续执行", "review": "验收通过", "close": "归档", "cancel": "取消任务",
          "replace_claim": "放回任务池", "release": "释放占用", "withdraw_delivery": "撤回交付",
          "upgrade-migrate": "升级迁移", "round-migrate": "升级迁移", "task-relation": "登记任务关系",
          "change-open": "登记拆分合并", "change-finish": "完成拆分合并",
          "task-publish": "开放领取", "task-hold": "暂缓", "task-scope": "调整范围", "task-interrupt": "登记中断",
          "task-recover": "处置恢复", "run-report": "执行回报", "return": "退回修改"}
TIERS = (("manager,executor,receiver", "项目管理员"), ("executor,receiver", "贡献者"),
         ("reporter", "报告者"), ("observer", "观察者"))
NAV_GROUPS = (("工作", (("/", "我的工作"), ("/board", "看板"), ("/list", "列表"))),
              ("协作", (("/projects", "项目"), ("/collaboration", "反馈与决定"), ("/communication", "沟通与经验"), ("/audit", "动态"), ("/release-status", "版本复验"))),
              ("AI 助理", (("/executors", "窗口管理"),)))
TASK_VIEWS = {"/", "/board", "/list"}
ACCOUNT_PAGES = ("/accounts", "/invitations", "/permissions", "/password")
HEADER = re.compile(rb'<header class="workspace-top">.*?(<div class="account">.*?</div>)\s*</header>', re.S)
TITLE = re.compile(rb"<title>(.*?) \xc2\xb7 ")
FILTER_KEYS = ("project", "q", "lane", "mine", "sort", "stage", "window", "receiver", "owner", "matching")


def tier_name(roles):
    current = set(roles)
    for value, name in TIERS:
        if current == set(value.split(",")):
            return name
    if "manager" in current:
        return "项目管理员（不执行）"
    return {frozenset({"executor"}): "仅执行", frozenset({"receiver"}): "仅验收"}.get(frozenset(current), "无角色")


def tier_value(roles):
    return ",".join(sorted(roles, key=["manager", "executor", "receiver", "reporter", "observer"].index))


def avatar(name, ai=False, with_name=True, title=None):
    if not name:
        return '<span class="av">未领取</span>'
    initials = re.sub(r"^(worker|member)-", "", name)[:2].upper()
    tone = sum(map(ord, name)) % 8
    return (f'<span class="av" title="{e(title or name, quote=True)}"><b class="a{tone}{" ai" if ai else ""}">{e(initials)}</b>'
            f'{e(name) if with_name else ""}</span>')


def window_label(item):
    return item.get("window_name") or item.get("window") or item.get("holder") or item.get("identity") or item.get("name") or item.get("actor") or ""


def window_text(item):
    label = window_label(item)
    label = f'{label} · {item["window"]}' if item.get("window_name") and item.get("window") else label
    return f'{label}（{item["delegator"]}授权）' if item.get("delegator") else label


def window_avatar(item, with_name=True):
    label = window_label(item)
    result = avatar(label, bool(item.get("window")), with_name, window_text(item))
    if with_name and item.get("window_name") and item.get("window"):
        result += f' <small class="muted-text">{e(item["window"])}</small>'
    return result


def here(path, filters, **changes):
    """Link to a view with some filters changed; empty values are dropped."""
    values = {k: v for k, v in {**filters, **changes}.items() if v}
    return e(path + ("?" + urlencode(values) if values else ""), quote=True)


def current(flag):
    return ' aria-current="page"' if flag else ""


def rail(path, admin, due, feedback, account, actor, scope="全部有权项目"):
    def link(href, name, title="", count=0):
        badge = f'<span class="wb-count">{count}</span>' if count else ""
        tip = f' title="{title}"' if title else ""
        return f'<a href="{href}"{tip}{current(active(href, path))}>{name}{badge}</a>'
    links = "".join(f'<span class="wb-nav-group">{name}</span>' + "".join(
        link(href, label, title={"/": f"{scope}内待我处理的任务，按任务去重，不含反馈",
                                "/collaboration": f"{scope}内待评估或待效果复核的反馈，仅项目管理员，不含跟进中"}.get(href, ""),
             count={"/": due, "/collaboration": feedback}.get(href, 0))
        for href, label in items) for name, items in NAV_GROUPS)
    home = "/accounts" if admin else "/password"
    selected = path.startswith(ACCOUNT_PAGES)
    links += f'<span class="wb-nav-group">管理</span><a href="{home}"{current(selected)}>账号与权限</a>'
    if admin:
        links += link("/upgrade", "运维工具")
    return (f'<nav class="wb-rail" aria-label="主导航"><a class="wb-brand" href="/"><i aria-hidden="true">任</i>任务池</a>{links}'
            f'<div class="wb-who">{avatar(actor, False, False)}{account}<small>v{__version__} · {e(RELEASE_NAME)}</small></div></nav>')


def topbar(title, path, filters, projects):
    search = ""
    segment = '<span class="wb-spacer"></span>'
    if path in TASK_VIEWS:
        keep = "".join(pages.hidden(k, filters[k]) for k in FILTER_KEYS if k != "q" and filters.get(k))
        search = (f'<form class="wb-search" role="search" method="get" action="{path}">{keep}<input type="search" name="q" maxlength="200" '
                  f'value="{e(filters.get("q", ""), quote=True)}" aria-label="搜索任务" placeholder="搜索标题或编号，也可以写 状态:待验收 执行:CDX-0002"></form>')
        chosen = filters.get("project", "")
        items = [("", "全部")] + [(p["id"], p["name"]) for p in projects]
        segment = ('<nav class="seg" aria-label="项目">' + "".join(
            f'<a href="{here(path, filters, project=key)}"{current(key == chosen)}>{e(name)}</a>' for key, name in items) + "</nav>")
    allowed = [p["id"] for p in projects if {"manager", "receiver"} & set(p["roles"])]
    new = ""
    if allowed:
        target = filters.get("project") if filters.get("project") in allowed else ""
        new = f'<a class="primary" data-new-task href="{here("/tasks/new", {}, project=target)}">新建任务</a>'
    return f'<header class="wb-top"><h1>{title}</h1>{search}{segment}{new}</header>'


def account_tabs(path, admin):
    names = (("/accounts", "账号"), ("/invitations", "邀请"), ("/permissions", "权限说明"), ("/password", "我的账号")) if admin else (
        ("/password", "我的账号"), ("/permissions", "权限说明"))
    links = "".join(f'<a href="{href}"{current(path == href or href == "/accounts" and path.startswith("/accounts/"))}>{name}</a>' for href, name in names)
    return f'<nav class="seg wb-tabs" aria-label="账号页面">{links}</nav>'


def workspace_revision(data):
    """A stable revision of visible overview state, before browser search filters."""
    tasks = [{"id": task["task_id"], "version": task.get("version"), "scope": task.get("scope_version"),
              "title": task.get("title"), "stage": task.get("stage"), "holder": task.get("holder"),
              "window": task.get("window"), "window_name": task.get("window_name"), "receiver": task.get("receiver"),
              "owner": owner_of(task), "last_executor": task.get("last_executor"),
              "qualification": {key: (task.get("qualification") or {}).get(key) for key in ("eligible", "prioritized", "missing")}}
             for task in data.get("tasks", [])]
    projects = [{"id": project["id"], "name": project.get("name"), "version": project.get("version"),
                 "owner": project.get("owner"), "roles": sorted(project.get("roles", []))} for project in data.get("projects", [])]
    value = {"version": __version__, "tasks": sorted(tasks, key=lambda task: task["id"]),
             "projects": sorted(projects, key=lambda project: project["id"]), "feedback_due": data.get("feedback_due", 0)}
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def adopt(html, target, actor, service):
    """Give any signed-in page the shared rail and top bar."""
    marker = b'<main class="workspace">'
    if marker not in html:
        return html
    path = target.path
    query = {k: v[0] for k, v in parse_qs(target.query).items() if k in FILTER_KEYS}
    project = query.get("project")
    if path.startswith("/projects/"):
        project = path.split("/")[-1]
    filters = query if path in TASK_VIEWS else {}
    try:
        data = service.read(actor, "overview", project)
    except ClientError:
        data = {"tasks": [], "projects": [], "feedback_due": 0}
    roles = roles_by_project(data)
    counted = filtered_tasks(data["tasks"], actor, filters if path == "/" else {"project": project})
    due = sum(1 for task in live_tasks(counted) if todo_reason(task, actor, roles))
    found = HEADER.search(html)
    account = found[1].decode("utf-8") if found else ""
    title = (found_title[1] if (found_title := TITLE.search(html)) else b"").decode("utf-8")
    html = html.replace(f"<h1>{title}</h1>".encode("utf-8"), b"", 1)
    heading = "账号与权限" if path in ACCOUNT_PAGES else {"任务看板": "看板"}.get(title, title)
    top = topbar(heading, path, filters, data["projects"])
    if path.startswith(ACCOUNT_PAGES):
        top += account_tabs(path, service.is_admin(actor))
    if path.startswith(("/executors", "/assistants", "/capabilities")) or path == "/invitations":
        top += window_tabs(path)
    html = HEADER.sub(lambda _: top.encode("utf-8"), html, 1)
    scope = "当前筛选" if path == "/" else "当前项目" if project else "全部有权项目"
    side = rail(path, service.is_admin(actor), due, data["feedback_due"], account, actor, scope)
    context = (f'<div class="wb-context" data-view-actor="{e(actor, quote=True)}" '
               f'data-workspace-revision="{workspace_revision(data)}" data-workspace-project="{e(project or "", quote=True)}"></div>')
    html = html.replace(marker, marker + context.encode("utf-8"), 1)
    html = html.replace(marker, f'<div class="wb-app">{side}'.encode("utf-8") + marker, 1)
    head, tail = html.rsplit(b"</main>", 1)
    return head + b"</main></div>" + tail


def active(href, path):
    if href == "/executors" and path.startswith(("/assistants", "/capabilities", "/executors")):
        return True
    return path == href if href == "/" else path.startswith(href)


def window_tabs(path):
    items = (("/executors", "窗口"), ("/assistants", "我的助理与委托"), ("/capabilities", "能力"), ("/invitations", "邀请窗口"))
    return '<nav class="seg wb-tabs" aria-label="窗口管理">' + "".join(
        f'<a href="{href}"{current(active(href, path) if href != "/executors" else path.startswith("/executors"))}>{label}</a>'
        for href, label in items) + '</nav>'


def live_tasks(tasks):
    return [t for t in tasks if t["stage"] not in ARCHIVE and column_of(t) != "done" or t["stage"] in {"accepted", "pending_close"}]


def utc(item):
    return local_text(item.get("committed_utc"), compact=True)


def event_label(item):
    if item.get("result") != "applied" or item.get("command") in {"note", "propose"}:
        return None
    name = item.get("operation") if item.get("command") == "pilot" or item.get("operation") == "return" else item.get("command")
    return EVENTS.get(name, name or "操作")


def spec_of(task):
    return task.get("contract") or {}


def owner_of(task):
    return (spec_of(task).get("dispatch") or {}).get("owner") or ""


def project_of(task):
    return spec_of(task).get("project_id") or ""


def column_of(task):
    return COLUMN_OF.get(task["stage"], "draft")


def roles_by_project(data):
    return {p["id"]: set(p["roles"]) for p in data["projects"]}


def flags(task):
    out = []
    if text := FLAG_TEXT.get(task["stage"]):
        hint = ' title="执行回报待确认；不能据此判断外部是否已经开始"' if task["stage"] == "claimed" else ""
        out.append(f'<span class="flag warn"{hint}>{text}</span>')
    if task["stage"] == "waiting" and (reason := spec_of(task).get("hold_reason")):
        out.append(f'<span class="flag" title="{e(reason, quote=True)}">已暂缓</span>')
    dispatch = spec_of(task).get("dispatch") or {}
    if dispatch.get("mode") in {"prefer", "only"}:
        text = {"prefer": "优先", "only": "限定"}[dispatch["mode"]]
        out.append(f'<span class="flag">{text}：{e("、".join(dispatch["subjects"]) or "能力组")}</span>')
    if task.get("dependencies"):
        out.append(f'<span class="flag">依赖 {e("、".join(sorted({d["task"] for d in task["dependencies"]})))}</span>')
    return "".join(out)


def requirement_tags(task):
    return "".join(f'<span class="tag{" v" if r["evidence"] != "declared" else ""}">{e(r["id"])}'
                   f'{" · 需核实" if r["evidence"] != "declared" else ""}</span>'
                   for r in spec_of(task).get("requirements", []))


def hidden_form(move, action, values):
    return pages.form(action, "提交", values).replace("<form ", f'<form hidden data-move="{move}" ', 1)


def claim_block(task, actor):
    if task["receiver"] == actor and not pages.executor_direct(task) and not (spec_of(task).get("review_mode") == "user" and (spec_of(task).get("user_basis") or "").strip()):
        return "你是本任务的验收人，不能同时执行"
    quality = task.get("qualification") or {}
    if not quality.get("eligible"):
        return "；".join(quality.get("missing") or ["当前不能领取"])
    return ""


def worker_avatar(task):
    display = executor_item(task)
    if display is not task:
        return window_avatar(display) + ' <small class="muted-text">历史执行</small>'
    if not window_label(display) and ended(task):
        return '<span class="av">无执行记录</span>'
    return window_avatar(display)


def ended(task):
    return task["stage"] in ARCHIVE or column_of(task) == "done"


def executor_item(task):
    if not task.get("holder") and ended(task) and (last := task.get("last_executor")):
        return {"holder": last["id"], "identity": last["id"], "window": last.get("window"), "window_name": last.get("window_name")}
    return task


def executor_text(task):
    return window_text(executor_item(task)) or ("无执行记录" if ended(task) else "")


def card(actor, task, roles, drag=True):
    tid = task["task_id"]
    column = column_of(task)
    forms = ""
    attributes = ""
    if drag:
        attributes = f' draggable="true" data-task="{e(tid)}" data-column="{column}"'
        if task["stage"] == "waiting":
            if "manager" in roles.get(project_of(task), set()) and spec_of(task).get("gate") is None:
                forms += hidden_form("open", "task-publish", {key: task[key] for key in ("task_id", "version", "scope_version")}
                                     | {"reason": "看板开放领取"})
            else:
                attributes += ' data-why="只有项目管理员可以开放任务"'
        if task["stage"] == "available":
            if why := claim_block(task, actor):
                attributes += f' data-why="{e(why, quote=True)}"'
            else:
                forms += hidden_form("doing", "claim", {key: task[key] for key in ("task_id", "version", "scope_version")})
    project = f'<span class="muted-text">{e(task.get("project_name") or "")}</span>' if task.get("project_name") else ""
    revisions = f'修订 {task["revisions"]} · ' if task.get("revisions") else ""
    tags = requirement_tags(task)
    return f"""<div class="card"{attributes}>
  <div class="row"><span class="tid">{e(tid)}</span>{project}{flags(task)}</div>
  <a class="card-link" href="/tasks/{quote(tid)}">{e(task["title"])}</a>
  {f'<div class="row">{tags}</div>' if tags else ""}
  <div class="foot">{worker_avatar(task)}<span class="muted-text">{revisions}验收 {e(task["receiver"])}</span></div>
  {forms}
</div>"""


def field_text(task):
    return (column_title(task) + " " + task["stage"], executor_text(task) or "未领取", task["receiver"], owner_of(task),
            task.get("project_name") or "", " ".join(r["id"] for r in spec_of(task).get("requirements", [])))


def column_title(task):
    if task["stage"] == "review" and pages.executor_direct(task):
        return "待执行者确认完成"
    return ARCHIVE.get(task["stage"]) or COLUMN_NAME[column_of(task)]


def matches(task, actor, filters):
    if filters.get("project") and project_of(task) != filters["project"]:
        return False
    if filters.get("mine") == "1" and actor not in {task.get("holder"), task["receiver"], owner_of(task)}:
        return False
    if filters.get("window") and filters["window"].casefold() not in executor_text(task).casefold():
        return False
    if filters.get("stage") and task["stage"] != filters["stage"]:
        return False
    if filters.get("receiver") and task["receiver"] != filters["receiver"]:
        return False
    if filters.get("owner") and owner_of(task) != filters["owner"]:
        return False
    if filters.get("matching") == "1" and not (task.get("qualification") or {}).get("eligible"):
        return False
    values = dict(zip(("状态", "执行", "验收", "负责", "项目", "标签"), field_text(task)))
    for token in filters.get("q", "").split():
        if found := SEARCH.match(token):
            if found[2].casefold() not in values[found[1]].casefold():
                return False
        elif token.casefold() not in (task["task_id"] + " " + task["title"] + " " + executor_text(task)).casefold():
            return False
    return True


def filtered_tasks(tasks, actor, filters):
    unique = {}
    for task in tasks:
        if matches(task, actor, filters):
            unique.setdefault(task["task_id"], task)
    return list(unique.values())


def toolbar(view, filters, data=None):
    path = "/" + view
    chips = (f'<a class="chip" href="{here(path, filters, mine="")}"{current(filters.get("mine") != "1")}>全部</a>'
             f'<a class="chip" href="{here(path, filters, mine="1")}"{current(filters.get("mine") == "1")}>我的</a>')
    saved = ('<div class="saved-views" data-saved-views><label>已保存视图<select data-view-picker aria-label="已保存视图"><option value="">选择视图</option></select></label><button class="secondary btn-sm" type="button" data-view-open>打开视图</button>'
             '<input data-view-name maxlength="60" placeholder="视图名称" aria-label="视图名称"><button class="secondary btn-sm" type="button" data-view-save>保存当前筛选</button>'
             '<button class="secondary btn-sm" type="button" data-view-delete>删除所选视图</button><span class="muted-text" data-view-status role="status">仅保存在本浏览器，按账号和项目区分。</span></div>')
    if view == "list":
        tasks = (data or {}).get("tasks", [])
        controls = "".join(pages.hidden(k, filters[k]) for k in ("project", "q", "mine", "sort") if filters.get(k))
        stages = [("", "全部状态")] + [(key, "已领取（执行回报待确认）" if key == "claimed" else pages.STAGES.get(key, column_title({"stage": key}))) for key in sorted({t["stage"] for t in tasks})]
        controls += ui.selection("stage", "状态", stages, filters.get("stage", "")).replace(" required", "")
        for key, label, values in (("window", "执行窗口", sorted({executor_text(t) for t in tasks if executor_text(t)})),
                                    ("receiver", "验收人", sorted({t["receiver"] for t in tasks})),
                                    ("owner", "任务负责人", sorted({owner_of(t) for t in tasks if owner_of(t)}))):
            controls += ui.selection(key, label, [("", "全部")] + [(name, name) for name in values], filters.get(key, "")).replace(" required", "")
        controls += '<button class="secondary btn-sm" type="submit">应用筛选</button>'
        return f'<div class="wb-bar">{chips}<span class="hint">点表头排序</span></div><form class="wb-filters" method="get" action="/list">{controls}</form>{saved}'
    keep = "".join(pages.hidden(k, filters[k]) for k in FILTER_KEYS if k != "lane" and filters.get(k))
    options = "".join(f'<option value="{value}"{" selected" if filters.get("lane", "") == value else ""}>{name}</option>'
                      for value, name in (("", "无"), ("project", "项目"), ("holder", "执行窗口"), ("receiver", "验收人"), ("owner", "任务负责人")))
    lane = (f'<form class="wb-inline" method="get" action="/board" data-auto>{keep}<label>分组 <select name="lane">{options}</select></label>'
            '<noscript><button class="secondary" type="submit">应用</button></noscript></form>')
    return (f'<div class="wb-bar">{lane}{chips}<a class="secondary btn-sm" href="/board.md" download>导出看板</a>'
            '<span class="hint">拖动卡片改状态，需要填写内容时会打开任务 · 已取消的任务在列表里</span></div>' + saved)


def board(actor, data, filters):
    tasks = [t for t in data["tasks"] if t["stage"] not in ARCHIVE and matches(t, actor, filters)]
    roles = roles_by_project(data)
    lanes = [("", tasks)]
    if filters.get("lane") == "project":
        names = sorted({t.get("project_name") or "未归属项目" for t in tasks})
        lanes = [(name, [t for t in tasks if (t.get("project_name") or "未归属项目") == name]) for name in names]
    elif filters.get("lane") == "holder":
        groups = {}
        for task in tasks:
            display = executor_item(task)
            groups.setdefault(display.get("holder") or display.get("window") or "", []).append(task)
        lanes = sorted(((executor_text(rows[0]) or "未领取", rows) for rows in groups.values()), key=lambda lane: lane[0])
    elif filters.get("lane") in {"receiver", "owner"}:
        getter = (lambda task: task["receiver"]) if filters["lane"] == "receiver" else owner_of
        names = sorted({getter(t) or "未指定" for t in tasks})
        lanes = [(name, [t for t in tasks if (getter(t) or "未指定") == name]) for name in names]
    head = "".join(f'<div class="colhead c-{key}"><i></i>{name}<span>{sum(column_of(t) == key for t in tasks)}</span></div>'
                   for key, name, _ in COLUMNS)
    body = ""
    for name, rows in lanes:
        if name:
            body += f'<div class="lane">{e(name)}<span>{len(rows)} 项</span></div>'
        for key, _, _ in COLUMNS:
            cards = "".join(card(actor, t, roles) for t in rows if column_of(t) == key)
            body += f'<div class="col" data-col="{key}">{cards}</div>'
    return pages.workspace(actor, f"""<section class="wb-page">{toolbar("board", filters, data)}
  <div class="board-wrap"><div class="board">{head}{body}</div></div></section>""")


SORTS = {"id": lambda t: t["created_seq"], "title": lambda t: t["title"], "status": lambda t: column_title(t),
         "holder": executor_text, "receiver": lambda t: t["receiver"],
         "owner": owner_of, "project": lambda t: t.get("project_name") or ""}


def list_page(actor, data, filters, activity):
    key = filters.get("sort", "id")
    tasks = sorted((t for t in data["tasks"] if matches(t, actor, filters)), key=SORTS.get(key, SORTS["id"]))

    def header(name, title):
        query = {k: v for k, v in filters.items() if k != "sort"} | {"sort": name}
        return f'<th><a href="/list?{e(urlencode(query), quote=True)}">{title}{" ↓" if key == name else ""}</a></th>'
    latest = {}
    for item in activity:
        latest.setdefault(item["task_id"], item)

    def recent(task):
        item = latest.get(task["task_id"])
        if not item:
            return "—"
        return f'{e(window_text(item))} {e(event_label(item) or "")} · {time_html(item.get("committed_utc"), compact=True)}'
    rows = "".join(f"""<tr data-task-row><td><span class="tid">{e(t["task_id"])}</span></td>
  <td class="wide"><a class="card-link" href="/tasks/{quote(t["task_id"])}">{e(t["title"])}</a> {flags(t)}</td>
  <td><span class="pill c-{column_of(t) if t["stage"] not in ARCHIVE else "archive"}">{column_title(t)}</span></td>
  <td>{worker_avatar(t)}</td><td>{e(t["receiver"])}</td><td>{e(owner_of(t) or "未指定")}</td>
  <td>{e(t.get("project_name") or "—")}</td><td class="muted-text">{recent(t)}</td></tr>""" for t in tasks)
    table = (f'<div class="table-wrap"><table><thead><tr>{header("id", "编号")}{header("title", "标题")}{header("status", "状态")}'
             f'{header("holder", "执行窗口")}{header("receiver", "验收人")}{header("owner", "任务负责人")}{header("project", "项目")}<th>最近动态</th></tr></thead>'
             f'<tbody>{rows or "<tr><td colspan=8>没有符合条件的任务。</td></tr>"}</tbody></table></div>')
    return pages.workspace(actor, f'<section class="wb-page">{toolbar("list", filters, data)}{table}</section>')


def todo_reason(task, actor, roles):
    stage = task["stage"]
    if stage == "review" and pages.executor_direct(task):
        return "待你凭交付证据确认完成" if task.get("holder") == actor else ""
    if stage == "review" and task["receiver"] == actor and (task.get("holder") != actor or
            spec_of(task).get("review_mode") == "user" and (spec_of(task).get("user_basis") or "").strip()):
        return "待你提交验收结论"
    if stage == "revision" and task.get("holder") == actor:
        return "被退回，等你修改"
    if stage == "waiting" and "manager" in roles.get(project_of(task), set()):
        return "等你开放"
    if stage == "pending_close" and pages.executor_direct(task) and task.get("direct_close_allowed"):
        return "等你收口并归档"
    if stage == "pending_close" and task["receiver"] == actor:
        return "等你归档"
    if stage in {"cancel_pending", "paused"} and task.get("holder") == actor:
        return "请确认已停止或继续"
    if stage == "accepted" and task.get("holder") == actor:
        if task.get("completion_kind") == "executor-direct":
            return "执行者已确认完成，未做独立审查；请确认执行已停止"
        if pages.executor_direct(task) and task.get("completion_kind") != "review":
            return "已确认完成，请确认执行已停止"
        return "已验收，请确认执行已停止"
    if stage == "recovery" and "manager" in roles.get(project_of(task), set()):
        return "恢复待核，等你处置"
    return ""


def section(title, rows, empty):
    body = "".join(f'<div>{f"""<p class="why">{e(reason)}</p>""" if reason else ""}{markup}</div>' for reason, markup in rows)
    return f'<section class="stack-list"><h2>{title}<small>{len(rows)} 项</small></h2>{body or f"""<p class="empty">{empty}</p>"""}</section>'


def home_groups(actor, data, filters):
    """Show each filtered task once, keeping the most immediate responsibility."""
    roles = roles_by_project(data)
    groups = {name: [] for name in ("todo", "doing", "owned", "can", "cannot")}
    for task in filtered_tasks(data["tasks"], actor, filters):
        live = bool(live_tasks([task]))
        if live and (reason := todo_reason(task, actor, roles)):
            groups["todo"].append((reason, task))
        elif live and task.get("holder") == actor and task["stage"] in {"claimed", "running"}:
            groups["doing"].append(("", task))
        elif live and owner_of(task) == actor:
            groups["owned"].append((column_title(task), task))
        elif task["stage"] == "available" and "executor" in roles.get(project_of(task), set()) and (task["receiver"] != actor or pages.executor_direct(task)):
            quality = task.get("qualification") or {}
            if quality.get("eligible"):
                groups["can"].append(("", task))
            elif quality:
                groups["cannot"].append(("；".join(quality["missing"][:2]), task))
    return groups


def mine_page(actor, data, filters):
    roles = roles_by_project(data)
    groups = home_groups(actor, data, filters)
    todo, doing, owned, can, cannot = ([(reason, card(actor, task, roles, False)) for reason, task in groups[key]]
                                     for key in ("todo", "doing", "owned", "can", "cannot"))
    blocked = section("暂时领不了", cannot, "") if cannot else ""
    return pages.workspace(actor, f"""<section class="wb-page">
  <div class="mine">{section("待我处理", todo, "没有等你处理的事。")}
    <div>{section("我在做的", doing, "你手上没有进行中的任务。")}{section("我负责跟进的", owned, "没有你负责跟进的未完成任务。")}</div>
    <div>{section("可以领的", can, "暂时没有你能领的任务。")}{blocked}</div></div></section>""")


def check_box(name, value, text, required=True):
    return (f'<label class="check"><input type="checkbox" name="{name}" value="{e(value, quote=True)}"'
            f'{" required" if required else ""}> {text}</label>')


def handoff_form(values):
    return ui.block("放回任务池", pages.form("handoff", "放回任务池", values,
                    pages.textarea("notes", "交接说明：已完成哪些、还剩什么、有没有外部影响", 16000)
                    + check_box("stop_evidence", DECLARE, "本次执行已结束，相关占用已释放"), secondary=True))


def worker_box(actor, view):
    task, claim = view["task"], view["active"]
    if task["status"] == "available":
        if "executor" not in view["roles"]:
            return ""
        contexts = view.get("execution_contexts", [])
        receiver_blocks = task["receiver"] == actor and not pages.executor_direct(task) and not (spec_of(task).get("review_mode") == "user" and (spec_of(task).get("user_basis") or "").strip())
        block = "你是本任务的验收人，不能同时执行" if receiver_blocks else "；".join(view["qualification"]["missing"])
        if block and (receiver_blocks or not contexts):
            return f'<p class="muted-text">暂时不能领取：{e(block)}</p>'
        config = ""
        if contexts:
            choices = [("", "使用当前默认配置")] + [(row["context_id"] + ":" + str(row["version"]),
                       f'{row.get("config", {}).get("model", "未知模型")} · v{row["version"]} · {row["context_id"]}') for row in contexts]
            config = ui.selection("context_ref", "本次领取使用的配置", choices, "").replace(" required", "")
        note = f'<p class="muted-text">默认配置当前不能领取：{e(block)}。可选择其它合法配置，由服务器核对资格。</p>' if block else ""
        return note + pages.form("claim", "领取任务", {key: task[key] for key in ("task_id", "version", "scope_version")}, config)
    if not claim or claim["origin"] != actor:
        return ""
    values = {"claim_id": claim["claim_id"], "epoch": claim["epoch"], "scope_version": claim["W"]["scope"]}
    work, execution = claim["W"]["state"], claim["E"]["state"]
    direct = "executor" in view.get("direct_roles", view["roles"])
    allowed = set(view.get("delegated_actions", []))
    begin = ""
    if view.get("execution_protocol") == 5:
        begin = f'<p><a href="/executors/{quote(actor)}/execution">到执行段与资源页核对实际动作和回报</a></p>'
    elif (direct or "run-report" in allowed) and claim.get("run", {}).get("state") == "claimed" and execution == "running":
        begin = ui.block("记录实际开始", pages.form("run-report", "记录实际开始", {**values, "state": "started"},
                         pages.textarea("evidence", "开工事实或依据"), secondary=True))
    withdraw = ""
    if direct and spec_of(task) and work == "review":
        withdraw = ui.block("撤回本次交付", pages.form("withdraw", "撤回待验修订", {**values, "revision": claim["W"]["revision"]},
                            pages.textarea("reason", "撤回原因"), secondary=True))
    if work == "draft" and execution == "running":
        if not direct and "deliver-files" not in allowed:
            return '<p class="muted-text">当前没有交付权限，可记录实际停止或交接。</p>' + handoff_form(values)
        upload = ('<label>交付文件（最多 10 个，合计约 8 MiB）<input type="file" name="artifact" multiple required></label>'
                  + check_box("stop_evidence", DECLARE, "本次执行已结束，相关占用已释放"))
        return pages.form("deliver-files", "提交交付", values, upload, upload=True) + begin + handoff_form(values)
    if execution == "requested" or execution == "running" and work in {"review", "complete", "revision"}:
        prompt = {"cancel": "任务正在取消", "pause": "任务已暂停", "replace": "任务正在交接"}.get(claim["E"].get("reason"), "交付已提交")
        return (f'<p class="muted-text">{prompt}，请在工作实际停止后确认。</p>'
                + f'<p><a href="/executors/{quote(actor)}/execution">先核对执行段与资源</a>；存在实际状态未知的动作时，须登记依据并核对原授权，旧停止操作不能抹掉占用。</p>'
                + pages.form("stop", "确认已停止", values, pages.textarea("stop_evidence", "停止情况")) + withdraw)
    if work == "revision" and claim["E"] == {"state": "stopped", "reason": "complete"}:
        return (pages.form("resume", "开始返修", values) if direct or "resume" in allowed else '<p>继续返修需要人员授权。</p>') + handoff_form(values)
    if spec_of(task) and work in {"draft", "revision"} and claim["E"] == {"state": "stopped", "reason": "pause"}:
        return (pages.form("resume", "继续执行", values) if direct or "resume" in allowed else '<p>继续执行需要人员授权。</p>') + handoff_form(values)
    return ('<p class="muted-text">本次执行已结束，等待完成确认。</p>' if work == "review" and pages.executor_direct(task) else '<p class="muted-text">本次执行已结束，等待验收。</p>' if work == "review" else "") + withdraw


def review_forms(claim, bundle, direct=False, finish=True):
    revision = bundle["revision"]
    values = {"claim_id": claim["claim_id"], "revision": revision["revision"], "manifest_sha256": revision["manifest_sha256"]}
    criteria = revision["criteria"]
    artifacts = [ref for ref in bundle["outputs"] if not ref["path"].endswith("/delivery.json")]
    if not artifacts:
        return '<p class="form-error" role="status">交付文件未通过复核，当前无法确认完成。</p>' if direct else '<p class="form-error" role="status">交付文件未通过复核，当前无法验收。</p>'
    single = len(artifacts) == 1
    options = "".join(f'<option value="{e(json.dumps(ref, ensure_ascii=False), quote=True)}"{" selected" if single else ""}>'
                      f'{e(ref["path"].rsplit("/", 1)[-1])}</option>' for ref in artifacts)
    prompt = "" if single else '<option value="">选择已核对的文件</option>'
    checks = "".join(f"""<fieldset><legend>{e(c)}</legend>{pages.hidden(f"criterion-{i}", c)}
  <label>核对的文件<select name="artifact-{i}" required>{prompt}{options}</select></label>
  {pages.textarea(f"note-{i}", "核对情况")}</fieldset>""" for i, c in enumerate(criteria))
    if direct:
        values.update(epoch=claim["epoch"], scope_version=claim["W"]["scope"])
        if finish:
            values["finish"] = "1"
        return ui.block('执行者确认完成', '<p class="muted-text">执行者完成，未做独立审查。请逐项记录实际完成依据。</p>'
                        + pages.form("executor-complete", "确认完成并尝试归档" if finish else "确认完成", {**values, "check_count": len(criteria)}, checks))
    accept = pages.form("review", "验收通过并归档", {**values, "check_count": len(criteria), "finish": "1"}, checks)
    failed = "".join(check_box(f"failed-{i}", c, e(c), False) for i, c in enumerate(criteria))
    back = pages.form("return", "退回修改", {**values, "criteria_form": "1"},
                      f'<fieldset><legend>未通过的判据</legend>{failed}</fieldset>' + pages.textarea("reason", "需要怎样修改"), secondary=True)
    return ui.block(f'验收 {e(revision["revision"])}', accept) + ui.block("退回修改", back)


def receiver_box(actor, view):
    task, claim = view["task"], view["active"]
    if pages.executor_direct(task) and (task["receiver"] != actor or claim and claim["origin"] == actor):
        return ""
    if task["receiver"] != actor:
        return f'<p class="muted-text">等待 {e(task["receiver"])} 验收。</p>' if view["stage"] == "review" else ""
    if task["status"] == "pending_close":
        return pages.form("close", "归档", {"task_id": task["task_id"]})
    if view["stage"] == "accepted":
        return '<p class="muted-text">已确认完成，等执行人确认工作已停止后归档。</p>' if pages.executor_direct(task) else '<p class="muted-text">已验收，等执行人确认工作已停止后归档。</p>'
    if not task.get("cancel_requested") and not task.get("accepted") and claim and claim["W"]["state"] == "review":
        latest = next((b for b in view["deliveries"] if b["claim_id"] == claim["claim_id"]
                       and b["revision"]["revision"] == claim["W"]["revision"]), None)
        if latest:
            return review_forms(claim, latest)
    return ""


def manage_box(view):
    task, claim = view["task"], view["active"]
    spec = spec_of(task)
    manager = "manager" in view["roles"]
    delegated = set(view.get("delegated_actions", []))
    assigned = task["receiver"] == view.get("viewer")
    controls = ""
    if not (manager or assigned or "admin" in view["roles"] or delegated & {"task-hold", "task-publish"}):
        return ""
    if spec and (manager or delegated & {"task-hold", "task-publish"}) and task["status"] in {"available", "running"} and not task.get("cancel_requested") and not task.get("accepted"):
        values = {key: task[key] for key in ("task_id", "version", "scope_version")}
        if spec["open"] and (manager or "task-hold" in delegated):
            controls += ui.block("暂缓任务" if task["status"] == "available" else "暂停任务",
                                 pages.form("task-hold", "确认", values, pages.textarea("reason", "原因"), secondary=True))
        elif not spec["open"] and (manager or "task-publish" in delegated):
            controls += pages.form("task-publish", "开放领取", values, pages.textarea("reason", "开放说明"))
        if manager:
            controls += ui.block("调整领取条件", pages.form("task-scope", "保存并暂缓", values, pages.textarea("reason", "调整原因")
                                 + ui.contract_fields(spec["project_id"], spec, task["resources"], task["dependencies"], view.get("round"))))
    if (manager or assigned or "admin" in view["roles"]) and task["status"] in {"available", "running"} and not task.get("cancel_requested") and not task.get("accepted"):
        controls += ui.block("取消任务", pages.form("cancel", "提交取消", {"task_id": task["task_id"], "version": task["version"]},
                             pages.textarea("reason", "取消原因"), secondary=True))
    if spec and claim and manager:
        values = {"task_id": task["task_id"], "version": task["version"], "claim_id": claim["claim_id"], "epoch": claim["epoch"]}
        if claim.get("recovery", {}).get("status") == "pending":
            controls += ui.block("处置恢复待核", pages.form("task-recover", "记录处置", values, ui.text_field("reason", "处置决定")
                                 + ui.text_field("evidence", "实际停止与占用情况") + ui.text_field("notes", "接续材料", size=16000)
                                 + ui.text_field("unresolved", "待核实的外部影响", required=False)))
        else:
            controls += ui.block("登记中断", pages.form("task-interrupt", "进入恢复待核", values, ui.text_field("reason", "中断情况")))
    return f'<section class="sheet-part"><h3>管理</h3>{controls}</section>' if controls else ""


def links(refs):
    return "".join(f'<div class="file"><a href="{e("/download?" + urlencode({"path": ref["path"]}), quote=True)}" download>'
                   f'{e(ref["path"].rsplit("/", 1)[-1])}</a></div>' for ref in refs)


def timeline(events):
    rows = []
    for item in events:
        label = event_label(item)
        if label is None:
            continue
        at = time_html(item.get("committed_utc"))
        who = window_text(item)
        reason = f'<span class="muted-text">{e(item["reason"])}</span>' if item.get("reason") else ""
        rows.append(f'<li><b>{e(who)}</b> {e(label)} {reason}<div class="muted-text">{at}</div></li>')
    return "".join(reversed(rows))


def sheet(actor, view, brief, events):
    task = view["task"]
    spec = spec_of(task)
    dispatch = spec.get("dispatch") or {}
    stage = view["stage"]
    column = column_title({**task, "stage": stage})
    view = {**view, "viewer": actor}
    actions = ""
    if not (stage in ARCHIVE or stage in {"completed", "closed_missing", "closed_candidate"}):
        actions = worker_box(actor, view) + pages.executor_completion(actor, view) + receiver_box(actor, view)
        if stage == "waiting":
            actions += f'<p class="muted-text">{e(spec.get("hold_reason") or "任务开放后才能领取。")}</p>'
    if stage == "available" and not actions:
        actions = '<p class="muted-text">等待执行者领取。</p>'
    action_box = f'<section class="actions"><h3>当前可办操作</h3>{actions or "<p class=muted-text>当前没有可办操作，历史记录保留供追溯。</p>"}</section>'
    if view["cancel_note"]:
        action_box = f'<p class="muted-text">取消原因：{e(view["cancel_note"]["text"])}</p>' + action_box
    done = stage in {"completed", "closed_missing", "accepted", "pending_close"}
    criteria = "".join(f'<li class="{"ok" if done else ""}">{e(item)}</li>' for item in task["completes_on"])
    inputs = [{"path": path, "sha256": sha} for path, sha in task["inputs"].items()]
    revisions = ""
    for bundle in reversed(view["deliveries"]):
        rev = bundle["revision"]
        state = {"review": "待验收", "revision": "已退回", "accepted": "已通过", "withdrawn": "已撤回"}.get(rev["status"], rev["status"])
        if (bundle.get("review") or {}).get("completion_kind") == "executor-direct":
            state = "执行者完成，未做独立审查"
        elif rev["status"] == "review" and pages.executor_direct(task):
            state = "待完成确认"
        revisions += (f'<div class="rev"><b>{e(rev["revision"].replace("revision-", "修订 "))}</b> <span class="muted-text">{state}</span>'
                      f'{links([ref for ref in bundle["outputs"] if not ref["path"].endswith("/delivery.json")])}</div>')
    rework = pages.rework_sections(view, "sheet-part", "h3")
    handoffs = links(view["handoffs"])
    claim = view["active"]
    technical = "".join(f"<dt>{k}</dt><dd>{e(str(v))}</dd>" for k, v in (
        ("任务版本", task["version"]), ("范围版本", task["scope_version"]),
        *((("执行回报", "执行回报待确认；不能据此判断外部是否已经开始"),) if stage == "claimed" else ()),
        ("领取编号", claim["claim_id"] if claim else "—"), ("执行代次", claim["epoch"] if claim else "—"),
        *((f"输入 {path.rsplit('/', 1)[-1]}", sha) for path, sha in task["inputs"].items())))
    tags = requirement_tags(task) or '<span class="muted-text">不限</span>'
    deps = "".join(f'<a class="tid" href="/tasks/{quote(t)}">{e(t)}</a> ' for t in sorted({d["task"] for d in task["dependencies"]})) or '<span class="muted-text">无</span>'
    mode = {"open": "项目内的贡献者", "prefer": "优先通知 ", "only": "只给 "}[dispatch.get("mode", "open")] + "、".join(dispatch.get("subjects", []))
    project = f'<a href="/projects/{quote(project_of(task))}">{e(task.get("project_name") or project_of(task))}</a>' if spec else "未归属项目"
    missing = ""
    if stage != "available" and view["qualification"] and stage == "waiting" and spec.get("gate"):
        missing = f'<p class="muted-text">{e("；".join(view["qualification"]["missing"]))}</p>'
    pill = "archive" if stage in ARCHIVE else COLUMN_OF.get(stage, "draft")
    return f"""<article class="sheet" id="task-sheet">
  <header class="sheet-head"><span class="tid">{e(task["task_id"])}</span><span class="pill c-{pill}">{column}</span>
    {f'<span class="flag warn">{FLAG_TEXT[stage]}</span>' if stage in FLAG_TEXT else ""}<a class="sheet-back" href="/board">返回看板</a></header>
  <div class="sheet-body"><div class="sheet-main">
    <h1>{e(task["title"])}</h1>{pages.collaboration_links(view)}{pages.completion_notice(view)}{action_box}{pages.execution_runtime(view)}{missing}
    <section class="sheet-part"><h3>说明</h3><p class="brief">{e(brief or "")}</p></section>
    <section class="sheet-part"><h3>完成判据</h3><ul class="crit">{criteria}</ul></section>
    {f'<section class="sheet-part"><h3>输入资料</h3>{links(inputs)}</section>' if inputs else ""}
    {f'<section class="sheet-part"><h3>接续材料</h3>{handoffs}</section>' if handoffs else ""}
    {f'<section class="sheet-part"><h3>交付与验收记录</h3>{revisions}</section>' if revisions else ""}
    {rework}
    {manage_box(view)}
    <section class="sheet-part"><h3>动态</h3><ul class="timeline">{timeline(events) or "<li>暂无记录</li>"}</ul></section>
    <details class="tech"><summary>技术细节</summary><dl>{technical}</dl></details>
  </div>
  <aside class="sheet-side">
    <div><span>项目</span>{project}</div>
    <div><span>任务负责人</span>{e(owner_of(task) or "未指定")}</div>
    <div><span>执行人</span>{e(window_text(view) or (claim["origin"] if claim else "未领取"))}</div>
    <div><span>{"可选验收人" if pages.executor_direct(task) else "验收人"}</span>{e(task["receiver"])}</div>
    <div><span>谁可以领</span>{e(mode)}</div>
    <div><span>能力要求</span><p class="row">{tags}</p></div>
    <div><span>前置任务</span><p class="row">{deps}</p></div>
  </aside></div>
</article>"""


def detail(actor, view, brief, events):
    return pages.workspace(actor, f'<section class="wb-page">{sheet(actor, view, brief, events)}</section>')


def new_task(actor, projects, project, receivers, capabilities, members, tasks):
    manager = "manager" in project["roles"]
    tabs = ('<nav class="seg" aria-label="项目">' + "".join(f'<a data-new-task href="/tasks/new?{e(urlencode({"project": p["id"]}), quote=True)}"{current(p["id"] == project["id"])}>{e(p["name"])}</a>'
                                                          for p in projects) + "</nav>") if len(projects) > 1 else ""
    receiver_candidates = [next((m for m in members if m["identity"] == name), {"identity": name, "name": name}) for name in receivers]
    receiver = ui.identity_picker("receiver", "验收人（直接完成任务中为可选验收责任人）", receiver_candidates, receivers[0] if receivers else "") if manager else pages.hidden("receiver", actor)
    people = [m["identity"] for m in members if m.get("kind") == "human" and m["roles"]]
    owner = actor if actor in people else ""
    owner_field = ui.identity_picker("dispatch_owner", "任务负责人", [m for m in members if m["identity"] in people], owner, optional=True)
    executors = [m for m in members if "executor" in m["roles"]]
    target = ui.identity_picker("dispatch_subjects", "指定对象", executors, optional=True)
    caps = "".join(f"""<label>{e(cap)}<select name="cap-{e(cap, quote=True)}"><option value="">不要求</option>
  {f'<option value="skill:declared">需要</option>' if kind == "skill" else ""}<option value="{e(kind)}:verified">需核实</option></select></label>""" for cap, kind in capabilities)
    deps = "".join(f'<option value="{e(json.dumps([{"task": t["task_id"], "output": "delivery", "criterion": c} for c in t["completes_on"]], ensure_ascii=False), quote=True)}">'
                   f'{e(t["task_id"])} {e(t["title"])}</option>' for t in tasks
                   if project_of(t) == project["id"] and t["stage"] not in ARCHIVE and len(t["completes_on"]) <= 30)
    open_now = check_box("open_now", "1", "创建后立即开放领取", False) if manager else ""
    who = ("" if manager else '<p class="muted-text">你登记的任务由你验收，创建后由项目管理员开放。</p>')
    more = ('<details class="more"><summary>更多选项：领取方式、前置任务</summary>'
            + ui.selection("dispatch_mode", "谁可以领", [("open", "项目内的贡献者"), ("prefer", "优先通知指定对象"), ("only", "只给指定对象")])
            + target + f'<label>前置任务（可多选）<select name="depends_on" multiple size="5">{deps}</select></label>'
            '<p class="muted-text">可按 Ctrl / Command 多选；不选表示无依赖，前置判据合计最多 30 条。只有所选任务的交付判据实际通过后才满足前置条件。</p></details>')
    controls = (pages.hidden("quick", "1") + pages.hidden("project_id", project["id"])
                + ui.input_field("title", "标题") + ui.text_field("brief", "说明", size=40000)
                + ui.text_field("criteria", "完成判据（每行一条）", size=3200)
                + f'<div class="two">{owner_field}{receiver}</div>'
                + f'<fieldset><legend>需要的能力（当前版本至少选一项）</legend><div class="two">{caps}</div>'
                + ui.input_field("cap_new", "新增能力编号（小写英文，例如 markdown）", required=False, size=48) + '</fieldset>'
                + more + open_now + who)
    return pages.workspace(actor, f'<section class="wb-page"><div class="wb-newtask" id="new-task"><h2>新建任务</h2>{tabs}'
                           f'<p class="muted-text">项目：{e(project["name"])}</p>{pages.form("register", "创建", contents=controls + ui.selection("completion_policy", "完成方式（创建后不可变更）", [("review-required", "独立验收后完成"), ("executor-direct", "执行者凭证据直接完成")], "review-required"))}</div></section>')


def members_section(data):
    manager = "manager" in data["roles"]
    rows = ""
    for member in data["members"]:
        tiers = [t for t in TIERS if member.get("kind") == "human" or "manager" not in t[0]]
        current = tier_value(member["roles"]) if member["roles"] else ""
        label = tier_name(member["roles"])
        control = e(label)
        if manager:
            options = [t for t in tiers]
            if current not in {value for value, _ in options}:
                options = [(current, label)] + options
            control = pages.form("project-grant", "保存", {"project_id": data["id"], "name": member["identity"],
                                 "version": member["version"], "resources": json.dumps(member["resources"], ensure_ascii=False)},
                                 ui.selection("roles", "项目角色", options, current), secondary=True)
        ai = member.get("kind") != "human"
        rows += f'<tr><td>{window_avatar(member)}</td><td>{"人员" if not ai else "AI 窗口"}</td><td>{control}</td></tr>'
    add = ""
    if manager:
        add = ui.block("添加成员", pages.form("project-grant", "添加成员", {"project_id": data["id"], "version": 0, "resources": "[]"},
                       ui.identity_picker("name", "账号或窗口", data.get("identity_choices", []))
                       + ui.selection("roles", "项目角色", list(TIERS), "executor,receiver")))
    return (f'<section class="detail-group"><h2>项目成员</h2><div class="table-wrap"><table><thead><tr><th>成员</th><th>类型</th>'
            f'<th>项目角色</th></tr></thead><tbody>{rows}</tbody></table></div>{add}'
            '<p class="muted-text">项目角色只决定权限。谁执行、谁验收写在每个任务上。AI 窗口最高只能是贡献者，且不能超出责任人的项目角色。</p></section>')
