"""HTML for the trial workflow, rendered from ledger projections."""

import json
from html import escape
import secrets
from . import __version__, RELEASE_NAME
from urllib.parse import quote, urlencode


STAGES = {
    "available": "可领取", "running": "执行中", "review": "待验收", "revision": "待返修",
    "accepted": "已验收 · 待停止", "pending_close": "待收口", "cancel_pending": "取消中 · 待停止",
    "completed": "已完成", "closed_missing": "已收口 · 证据缺失", "cancelled": "已取消",
    "waiting": "待启动", "recovery": "恢复待核", "paused": "待恢复执行", "handoff_pending": "交接中",
    "claimed": "已领取 · 执行回报待确认", "replaced": "已拆分", "merged": "已归并",
}
ARCHIVED = {"completed", "closed_missing", "cancelled", "replaced", "merged"}


def workspace(actor, contents):
    return f"""<main class="workspace">
  <header class="workspace-top">
    <a class="wordmark" href="/"><span class="mark" aria-hidden="true">任务</span><span>内网任务服务<small class="release-label">v{__version__} · {escape(RELEASE_NAME)}</small></span></a>
    <div class="account"><span>{escape(actor)}</span>
      <form method="post" action="/logout"><button class="secondary" type="submit">退出</button></form>
    </div>
  </header>
  {contents}
</main>"""


def project_label(task):
    relation = task.get("related")
    project = task.get("project_name") or (relation.get("project") if isinstance(relation, dict) else None)
    if isinstance(project, str) and project:
        return f'<small class="project-label muted">所属项目　{escape(project)}</small>'
    return ""


def overview(actor, data):
    tasks = data["tasks"]
    filters = data.get("filters", {})
    if data.get("round"):
        tasks = [t for t in tasks if (not filters.get("stage") or t["stage"] == filters["stage"])
                 and (not filters.get("window") or filters["window"].casefold() in (t.get("window") or "").casefold())
                 and (filters.get("mine") != "1" or mine(t, actor))
                 and (filters.get("matching") != "1" or (t.get("qualification") or {}).get("eligible"))]
        tasks.sort(key=lambda task: (not (task.get("qualification") or {}).get("prioritized"), task["created_seq"]))
    groups = (
        ("可领任务", [t for t in tasks if t["stage"] == "available"]),
        ("待启动", [t for t in tasks if t["stage"] == "waiting"]),
        ("进行中的任务", [t for t in tasks if t["stage"] not in {"available", "waiting"} and t["stage"] not in ARCHIVED]),
        ("归档记录", [t for t in tasks if t["stage"] in ARCHIVED]),
    )
    sections = []
    for title, rows in groups:
        links = "".join(f"""<li><a class="task-row" href="/tasks/{escape(t['task_id'])}">
  <span class="task-id">{escape(t['task_id'])}</span><span><strong>{escape(t['title'])}</strong>{project_label(t)}
  {f'<small class="project-label muted">{escape(t["window"])}</small>' if t.get("window") else ""}
  {f'<small class="project-label muted">{escape("、".join(t["qualification"]["missing"]))}</small>'
   if data.get("round") and t["stage"] == "available" and t.get("qualification") and t["qualification"]["missing"] else ""}</span>
  <span class="status">{escape(STAGES.get(t['stage'], t['stage']))}</span>
</a></li>""" for t in rows)
        listing = f'<ul class="task-list">{links}</ul>' if links else '<p class="muted">暂无任务。</p>'
        sections.append(f'<section class="overview-group"><h2>{title} <span class="count">{len(rows)}</span></h2>{listing}</section>')
    role = data["roles"]
    new = '<a class="primary" href="/tasks/new">登记任务</a>' if {"receiver", "admin"} & set(role) else ""
    accounts = '<a class="secondary" href="/accounts">账号管理</a>' if "admin" in role else ""
    navigation = ('<nav class="buttons"><a class="secondary" href="/projects">项目</a>'
                  '<a class="secondary" href="/executors">窗口目录</a><a class="secondary" href="/capabilities">能力与证据</a>'
                  '<a class="secondary" href="/audit">状态追溯</a><a class="secondary" href="/upgrade">升级验收</a></nav>') if data.get("upgraded") else ""
    if data.get("round"):
        from .upgrade_pages import input_field, selection
        options = [("", "全部项目")] + [(p["id"], p["name"]) for p in data["projects"]]
        navigation += ('<nav class="buttons round-nav" aria-label="我的工作"><a class="secondary" href="/?mine=1">待我处理</a>'
                       '<a class="secondary" href="/?matching=1">符合领取条件</a>'
                       '<a class="secondary" href="/collaboration">反馈与决定</a><a class="secondary" href="/password">账号密码</a></nav>')
        navigation += ('<form class="operation filter-grid" method="get" action="/">'
                       + selection("project", "项目", options, filters.get("project", "")).replace(" required", "")
                       + selection("stage", "状态", [("", "全部状态"), *STAGES.items()], filters.get("stage", "")).replace(" required", "")
                       + input_field("window", "窗口名称或编号", filters.get("window", ""), required=False, size=200)
                       + '<button class="secondary" type="submit">筛选任务</button></form>')
    return workspace(actor, f"""<section class="task-panel">
  <div class="section-title">
    <div><h1>任务看板</h1><p class="muted">查看领取、执行、验收和归档进度。</p></div>
    <div class="buttons">{new}{accounts}<a class="secondary" href="/board.md" download>下载完整看板</a></div>
  </div>
  {navigation}{"".join(sections)}
</section>""")


def mine(task, actor):
    owner = ((task.get("contract") or {}).get("dispatch") or {}).get("owner")
    return task["stage"] not in ARCHIVED and (task.get("holder") == actor or owner == actor or
            task["receiver"] == actor and task["stage"] in {"review", "pending_close"})


def hidden(name, value):
    return f'<input type="hidden" name="{escape(name)}" value="{escape(str(value), quote=True)}">'


def form(action, label, values=None, contents="", upload=False, secondary=False):
    encoding = ' enctype="multipart/form-data"' if upload else ""
    controls = hidden("request_id", "web-" + secrets.token_hex(16))
    controls += "".join(hidden(name, value) for name, value in (values or {}).items())
    style = "secondary" if secondary else "primary"
    return (f'<form class="operation" method="post" action="/actions/{action}"{encoding}>'
            f'{controls}{contents}<button class="{style}" type="submit">{label}</button></form>')


def textarea(name, label, limit=2000, rows=3):
    return (f'<label>{label}<textarea name="{name}" required maxlength="{limit}" '
            f'rows="{rows}"></textarea></label>')


def new_task(actor, receivers=None):
    controls = ('<label>任务标题<input name="title" required maxlength="200"></label>'
                '<label>所属项目（选填）<input name="project" maxlength="100"></label>'
                + textarea("brief", "任务说明（作为冻结输入）", 40000, 7)
                + textarea("criteria", "完成判据（每行一条）", 3200, 4))
    if receivers is not None:
        options = "".join(f'<option value="{escape(name, quote=True)}">{escape(name)}</option>' for name in receivers)
        controls += ('<label>指定接收者<select name="receiver" required>'
                     f'<option value="">选择接收者</option>{options}</select></label>')
    receiver_text = "由指定接收者独立验收。" if receivers is not None else "你将成为该任务的指定接收者。"
    return workspace(actor, f"""<section class="task-panel">
  <h1>登记资料任务</h1>
  <p class="muted intro">登记后，任务进入可领列表。{receiver_text}</p>
  {form("register", "登记并开放领取", contents=controls)}
</section>""")


def download(ref):
    name = ref["path"].rsplit("/", 1)[-1]
    url = "/download?" + urlencode({"path": ref["path"]})
    return (f'<a href="{escape(url, quote=True)}" download>{escape(name)}</a>'
            f'<small class="fingerprint" title="SHA256">{escape(ref["sha256"])}</small>')


def file_list(title, refs, record=""):
    if not refs:
        return ""
    rows = "".join(f"<li>{download(ref)}</li>" for ref in refs)
    return f'<section class="detail-group"><h2>{title}</h2>{record}<ul class="file-list">{rows}</ul></section>'


def collaboration_links(view):
    if not view.get("round"):
        return ""
    task = view["task"]
    project = (task.get("contract") or {}).get("project_id", "")
    query = {"task_id": task["task_id"]}
    if project:
        query["project"] = project
    links = (f'<a class="secondary" href="{escape("/communication?" + urlencode(query), quote=True)}">任务沟通与经验</a>')
    if task["status"] in {"completed", "closed_missing"} or view["stage"] in {"completed", "closed_missing"}:
        links += f'<a class="secondary" href="{escape("/post-completion?" + urlencode({"task_id": task["task_id"]}), quote=True)}">完成后复查</a>'
    return f'<nav class="buttons" aria-label="任务协作">{links}</nav>'


def executor_direct(task):
    return (task.get("contract") or {}).get("completion_policy", task.get("completion_policy", "review-required")) == "executor-direct"


def completion_notice(view):
    if not executor_direct(view["task"]):
        return ""
    accepted = view["task"].get("accepted")
    completed = any((bundle.get("review") or {}).get("completion_kind") == "executor-direct"
                    and (not accepted or (bundle.get("review") or {}).get("acceptance_id") == accepted)
                    for bundle in view.get("deliveries", []))
    text = "执行者完成，未做独立审查" if completed else "完成方式：执行者可凭交付证据直接完成；独立验收可选。"
    return f'<p class="muted-text" role="status">{text}</p>'


def executor_completion(actor, view):
    task, claim = view["task"], view["active"]
    if not executor_direct(task):
        return ""
    if task["status"] == "pending_close" and view.get("direct_close_allowed"):
        return form("close", "完成收口并归档", {"task_id": task["task_id"]})
    if (not claim or claim["origin"] != actor or claim["W"]["state"] != "review"
            or task.get("cancel_requested") or task.get("accepted")
            or "executor" not in view.get("direct_roles", view["roles"])):
        return ""
    latest = next((b for b in view["deliveries"] if b["claim_id"] == claim["claim_id"]
                   and b["revision"]["revision"] == claim["W"]["revision"]), None)
    if latest:
        from .workbench import review_forms
        return review_forms(claim, latest, direct=True, finish=bool(view.get("round")))
    return '<p class="muted-text">交付证据尚不可核对，暂不能直接完成。</p>'


def worker_actions(actor, task, claim, qualification=None, execution_protocol=None):
    if task["status"] == "available":
        if qualification and not qualification["eligible"]:
            return ""
        return form("claim", "领取任务", {key: task[key] for key in ("task_id", "version", "scope_version")})
    if not claim or claim["origin"] != actor:
        return ""
    values = {"claim_id": claim["claim_id"], "epoch": claim["epoch"], "scope_version": claim["W"]["scope"]}
    work, execution = claim["W"]["state"], claim["E"]["state"]
    begin = ""
    if execution_protocol == 5:
        begin = f'<p><a href="/executors/{quote(actor)}/execution">到执行段与资源页核对实际动作和回报</a></p>'
    elif claim.get("run", {}).get("state") == "claimed" and execution == "running":
        begin = form("run-report", "记录实际开始", {**values, "state": "started"},
                     textarea("evidence", "开工事实或依据"), secondary=True)
    handoff = ('<details class="action-details"><summary>交接任务</summary>'
               + form("handoff", "提交交接", values, textarea("notes", "接续说明", 16000)
                      + textarea("stop_evidence", "实际停止与资源释放依据"), secondary=True) + '</details>')
    if work == "draft" and execution == "running":
        upload = ('<label>交付文件（最多 10 个，合计不超过约 8 MiB）'
                  '<input type="file" name="artifact" multiple required></label>')
        return begin + form("deliver-files", "上传并封存", values, upload, upload=True) + handoff
    withdrawal = ""
    if task.get("contract") and work == "review":
        withdrawal = form("withdraw", "撤回待验修订", {**values, "revision": claim["W"]["revision"]},
                          textarea("reason", "撤回依据"), secondary=True)
    if execution == "requested" or execution == "running" and work in {"review", "complete", "revision"}:
        return form("stop", "确认停止并释放占用", values, textarea("stop_evidence", "实际停止与资源释放依据")) + withdrawal
    if work == "revision" and claim["E"] == {"state": "stopped", "reason": "complete"}:
        return form("resume", "开始返修", values) + handoff
    if task.get("contract") and work in {"draft", "revision"} and claim["E"] == {"state": "stopped", "reason": "pause"}:
        return form("resume", "确认范围并恢复", values) + handoff
    return withdrawal


def review_forms(claim, bundle):
    revision = bundle["revision"]
    values = {"claim_id": claim["claim_id"], "revision": revision["revision"],
              "manifest_sha256": revision["manifest_sha256"]}
    criteria = revision["criteria"]
    artifacts = [ref for ref in bundle["outputs"] if not ref["path"].endswith("/delivery.json")]
    if not artifacts:
        return '<p class="form-error" role="status">交付文件未通过复核，当前无法验收。</p>'
    options = "".join(
        f'<option value="{escape(json.dumps(ref, ensure_ascii=False), quote=True)}">'
        f'{escape(ref["path"].rsplit("/", 1)[-1])}</option>' for ref in artifacts
    )
    checks = []
    for i, criterion in enumerate(criteria):
        checks.append(f"""<fieldset><legend>{escape(criterion)}</legend>{hidden(f"criterion-{i}", criterion)}
  <label>核验文件<select name="artifact-{i}" required>
    <option value="">选择已核验的文件</option>{options}</select></label>
  {textarea(f"note-{i}", "通过依据")}
</fieldset>""")
    failed_options = "".join(f'<option value="{escape(c, quote=True)}">{escape(c)}</option>' for c in criteria)
    accept = form("review", "接受本修订", {**values, "check_count": len(criteria)}, "".join(checks))
    send_back = form("return", "退回返修", values,
                     '<label>未通过的判据<select name="criterion" required>'
                     f'<option value="">请选择</option>{failed_options}</select></label>'
                     + textarea("reason", "返修要求"), secondary=True)
    return (f'<details class="action-details"><summary>验收 {escape(revision["revision"])}</summary>{accept}</details>'
            f'<details class="action-details"><summary>退回返修</summary>{send_back}</details>')


def receiver_actions(actor, task, claim, bundles, admin):
    assigned = task["receiver"] == actor
    if not (assigned or admin):
        return ""
    if assigned and task["status"] == "pending_close":
        return form("close", "收口并归档", {"task_id": task["task_id"]})
    if task.get("cancel_requested") or task.get("accepted"):
        return ""
    actions = ""
    if assigned and claim and claim["W"]["state"] == "review" and not (executor_direct(task) and claim["origin"] == actor):
        latest = next((b for b in bundles if b["claim_id"] == claim["claim_id"]
                       and b["revision"]["revision"] == claim["W"]["revision"]), None)
        if latest:
            actions += review_forms(claim, latest)
    if task["status"] in {"available", "running"}:
        actions += ('<details class="action-details"><summary>取消任务</summary>'
                    + form("cancel", "提交取消", {"task_id": task["task_id"], "version": task["version"]},
                           textarea("reason", "取消原因"), secondary=True) + "</details>")
    return actions


def execution_runtime(view):
    if view.get("execution_protocol") != 5:
        return ""
    status = view.get("execution_status") or {}
    status = {**status, "start-authorized": status.get("start-authorized", status.get("start_authorized", status.get("awaiting_start", 0)))}
    actions = status.get("actions", [])
    count = status.get("count", len(actions) if isinstance(actions, list) else actions if isinstance(actions, int) else 0)
    labels = (("running", "实际执行中"), ("start-authorized", "许可已发，实际开工待回报"),
              ("unconfirmed", "执行事实待确认"), ("unknown", "物理占用待确认"), ("finished", "已登记结束事实"),
              ("stopped", "已回报停止"), ("error", "已回报错误"), ("not-started", "已确认未启动"),
              ("prepared", "已准备"), ("queued", "资源排队中"), ("granted", "资源已授予"))
    facts = "；".join(f'{label} {number}' for key, label in labels
                     if isinstance((number := status.get(key, status.get(key.replace("-", "_"), 0))), int) and number > 0)
    text = f'本回合动作 {count} 项；{facts}' if facts else f'本回合动作 {count} 项，尚无本回合的实际开工回报；旧执行事实单独保留。'
    historical = (("historical_live", "历史未收口动作"), ("historical_unconfirmed", "历史占用待确认"))
    old = "；".join(f'{label} {number}' for key, label in historical
                   if isinstance((number := status.get(key, 0)), int) and number > 0)
    if old:
        text += f' 历史单独核对：{old}；不计入本回合开工或结束，原占用不自动释放。'
    return f'<p role="status">{escape(text)}</p>'


def rework_sections(view, css="detail-group", heading="h2"):
    """Separate actionable local items from retained evidence, without mutating it."""
    current, history = [], []
    closed = view["stage"] in ARCHIVED | {"closed_candidate"}
    for item in view["items"]:
        active = (not closed and item["status"] == "unresolved"
                  and item.get("holder") in {None, view["task"]["task_id"]})
        label = "待处理" if active else {"resolved": "已解决", "unresolved": "历史未结项（非当前操作）"}.get(item["status"], "已结束")
        row = (f'<li><strong>{escape(item["criterion"] or "返修项")}</strong> '
               f'{escape(item["description"])} <span class="muted">{label}</span></li>')
        (current if active else history).append(row)
    output = ""
    for key, title, rows in (("current", "当前返修项", current), ("history", "历史返修记录", history)):
        if rows:
            output += f'<section class="{css}" data-rework="{key}"><{heading}>{title}</{heading}><ul>{"".join(rows)}</ul></section>'
    return output


def detail(actor, view):
    from .upgrade_pages import task_contract

    task, claim = view["task"], view["active"]
    inputs = file_list("冻结输入", [{"path": path, "sha256": sha} for path, sha in task["inputs"].items()])
    handoffs = file_list("接续材料", view["handoffs"])
    criteria = "".join(f"<li>{escape(item)}</li>" for item in task["completes_on"])
    actions = worker_actions(actor, task, claim, view.get("qualification"), view.get("execution_protocol")) if "executor" in view["roles"] else ""
    actions += executor_completion(actor, view)
    actions += receiver_actions(actor, task, claim, view["deliveries"], bool({"admin", "manager"} & set(view["roles"])))
    controls = f'<section class="detail-group"><h2>当前可办操作</h2>{actions or "<p class=muted>当前没有可办操作，历史记录保留供追溯。</p>"}</section>'
    revisions = []
    for bundle in view["deliveries"]:
        rev = bundle["revision"]
        label = {"review": "待完成确认" if executor_direct(task) else "待验收", "revision": "退回返修", "accepted": "已接受"}.get(rev["status"], rev["status"])
        if (bundle.get("review") or {}).get("completion_kind") == "executor-direct":
            label = "执行者完成，未做独立审查"
        review = bundle["review"]
        record = (f'<p class="muted">接收者 {escape(review["origin"])} · 账本位置 {review["seq"]}</p>' if review else "")
        revisions.append(file_list(f'{escape(rev["revision"])} · {escape(label)}',
                                   [rev["manifest"], *bundle["outputs"]], record))
    rework = rework_sections(view)
    close = file_list("归档证据", [view["close"]["summary"]]) if view["close"] else ""
    cancel = view["cancel_note"]
    note = f'<p class="muted intro">取消原因　{escape(cancel["text"])}</p>' if cancel else ""
    runtime = execution_runtime(view)
    if view.get("execution_protocol") != 5 and claim and claim.get("run"):
        run = claim["run"]
        labels = {"claimed": "已领取，执行回报待确认", "intent": "开工请求已登记", "started": "已回报开始", "waiting": "等待输入",
                  "working": "继续执行", "finished": "执行回报结束", "error": "执行异常"}
        runtime = f'<p role="status">当前代次 {claim["epoch"]} · {labels[run["state"]]} {escape(run.get("evidence", ""))}</p>'
    stage_label = STAGES.get(view["stage"], view["stage"])
    if executor_direct(task):
        stage_label = {"review": "待完成确认", "accepted": "已确认完成 · 待停止"}.get(view["stage"], stage_label)
    return workspace(actor, f"""<article class="task-panel">
  <div class="section-title">
    <div><span class="task-id">{escape(task['task_id'])}</span><h1>{escape(task['title'])}</h1>{project_label(task)}</div>
    <span class="status">{escape(stage_label)}</span>
  </div>
  {collaboration_links(view)}{note}{completion_notice(view)}{runtime}
  <section class="detail-group"><h2>完成判据</h2><ul>{criteria}</ul></section>
  {controls}{task_contract({**view, "viewer": actor})}{inputs}{handoffs}{rework}{"".join(revisions)}{close}
</article>""")
