"""Project feedback and change pages."""
from datetime import datetime, timezone
from html import escape
from urllib.parse import urlencode

from . import round_web, task_pages as pages, upgrade_pages as ui, workbench
from .packages import ClientError, strict_json

KINDS = {"issue": "问题", "feedback": "使用反馈", "hypothesis": "待验证推测"}
BADGES = {"triage": "mid", "evidence": "mid", "accepted": "info", "working": "info", "review": "mid",
          "verified": "ok", "deferred": "dec", "duplicate": "dec", "declined": "dec"}
LABELS = {"triage": "待评估", "evidence": "待补证", "accepted": "已纳入", "working": "处理中",
          "review": "待效果复核", "verified": "已验证关闭", "deferred": "延期", "duplicate": "重复关联", "declined": "不采纳"}


def operation(project, action, text, controls, values=None):
    values = {"project_id": project, "operation": action, **(values or {})}
    return round_web.password_form(
        "/collaboration", "".join(pages.hidden(k, v) for k, v in values.items()) + controls, text)


def impact_fields(record=None):
    record = record or {}
    return "".join(ui.text_field(key, label, record.get(key, "")) for key, label in (
        ("reason", "依据"), ("benefit", "预期收益"), ("cost", "实施、学习与维护成本"), ("risk", "影响与风险"), ("rollback", "复核与回退条件"),
    ))


def decision_form(project, record=None, tasks=None):
    record = record or {}
    values = {"version": record.get("version", 0)}
    controls = (ui.input_field("id", "决定编号", record.get("id", ""))
                + ui.input_field("area", "事项", record.get("area", ""), size=160)
                + ui.input_field("scope", "适用范围", record.get("scope", ""), size=500)
                + ui.selection("status", "状态", [("proposed", "提议"), ("effective", "有效"), ("withdrawn", "撤回")],
                               record.get("status"))
                + ui.input_field("replaces", "明确替代的同范围决定（选填）", required=False)
                + ui.input_field("replaces_version", "被替代决定版本", 0)
                + ui.json_field("tasks", "仅受影响任务及当前版本，例如 {\"T12\": 3}", tasks or {}) + impact_fields(record))
    return operation(project, "decision-save", "保存决定", controls, values)


def editing(project, data, versions):
    rows = "<p class='muted'>任务当前版本 " + escape("、".join(f"{t} v{v}" for t, v in versions.items())) + "</p>"
    relation = (ui.selection("kind", "关系",
                             [("related", "相关"), ("depends", "依赖"), ("duplicate", "完全重复"), ("overlap", "局部重合")])
                + ui.input_field("source", "来源任务") + ui.input_field("target", "目标任务")
                + ui.input_field("output", "依赖产出（依赖时必填）", required=False)
                + ui.input_field("criterion", "产出判据（依赖时必填）", required=False)
                + ui.json_field("versions", "来源与目标的版本对象", {}) + ui.text_field("reason", "关系与要求依据"))
    change = (ui.selection("kind", "变更", [("split", "拆分"), ("merge", "合并")])
              + ui.json_field("sources", "来源任务数组", []) + ui.json_field("targets", "承接任务数组", [])
              + ui.json_field("mapping", "逐项承接原判据（source、criterion、target、target_criterion）", [])
              + ui.json_field("versions", "全部受影响任务的版本对象", {}) + impact_fields())
    return (rows + ui.block("登记决定", decision_form(project))
            + ui.block("登记任务关系", operation(project, "task-relation", "保存关系", relation))
            + ui.block("准备拆分或合并", operation(project, "change-open", "登记变更并暂缓受影响任务", change)))


def feedback_form(projects, selected):
    kinds = "".join('<label><input type="radio" name="kind" '
                    f'value="{value}"{" checked" if not index else ""}> {label}</label>'
                    for index, (value, label) in enumerate(KINDS.items()))
    fields = (pages.hidden("operation", "feedback-save")
              + pages.hidden("observed", datetime.now(timezone.utc).isoformat(timespec="seconds"))
              + f'<div class="radios">{kinds}</div><div class="two">{ui.input_field("title", "标题")}'
              + ui.selection("project_id", "项目", [(p["id"], p["name"]) for p in projects], selected) + "</div>"
              + '<div class="two">' + ui.text_field("details", "现象或目标", size=4000).replace(' rows="4"', ' rows="2"')
              + ui.text_field("impact", "实际影响").replace(' rows="4"', ' rows="2"') + "</div>"
              + f'<div class="two">{ui.input_field("task_id", "关联任务（选填）", required=False)}'
              + ui.selection("visibility", "可见范围", [("project", "项目内"), ("restricted", "提交者与管理员")]) + "</div>"
              + ui.input_field("evidence", "证据引用或待补内容（选填）", size=4000, required=False))
    return round_web.password_form("/collaboration", fields, "提交")


def render(actor, project, data, versions, projects):
    from 协作关系 import TRANSITIONS
    names = {p["id"]: p["name"] for p in projects}
    feedback = []
    for item in reversed(data["feedback"]):
        update = ""
        if project and (data["managed"] or item["author"] == actor):
            allowed = (TRANSITIONS[item["status"]] | {item["status"]}) if data["managed"] else {item["status"]}
            inputs = (ui.selection("status", "状态",
                                   [(key, val) for key, val in LABELS.items() if key in allowed], item["status"])
                      + ui.input_field("linked_task", "跟踪任务", required=False)
                      + ui.input_field("duplicate", "主反馈编号", required=False)
                      + ui.text_field("reason", "处理依据") + ui.text_field("evidence", "补充证据", required=False)
                      + ui.json_field("metrics", "实测指标（metric、before、after、unit、samples、direction）", [])
                      + ui.text_field("lesson", "可复用经验", required=False)
                      + ui.text_field("limits", "适用条件和失效情形", required=False))
            update = ui.block("处理或补证", operation(project, "feedback-update", "保存反馈处理", inputs,
                                                         {"id": item["id"], "version": item["version"]}))
        trail = "".join(f'<li>{escape(log["by"])} · {escape(LABELS[log["status"]])} · {escape(log["reason"])}'
                        f'<p>{escape(log["evidence"])}</p><p>{escape(log["lesson"])} {escape(log["limits"])}</p></li>'
                        for log in item["updates"])
        managers = set(data.get("managed_projects", []))
        destinations = [(p["id"], p["name"]) for p in projects if p["id"] in managers and p["id"] != item["project_id"]]
        if item["project_id"] in managers and destinations:
            update += ui.block("调整所属项目", operation(item["project_id"], "feedback-move", "保存项目归属",
                ui.selection("target_project_id", "目标项目", destinations) + ui.text_field("reason", "调整依据"),
                {"id": item["id"], "version": item["version"]}))
        trail += "".join(f'<li>调整项目：{escape(names.get(move["from"], move["from"]))} → '
                         f'{escape(names.get(move["to"], move["to"]))} · {escape(move["reason"])} · '
                         f'{escape(move["by"])}</li>'
                         for move in item.get("project_history", []))
        related = " ".join(f'<a class="tid" data-task-link href="/tasks/{escape(tid, quote=True)}">{escape(tid)}</a>'
                           for tid in (item.get("task_id"), item.get("linked_task")) if tid)
        follow = "待累计样本复看" if item.get("follow_up") == "pending" else ""
        place = (f'<div class="muted-text">{escape(names.get(item["project_id"], item["project_id"]))}</div>'
                 if not project else "")
        link = ""
        if not project:
            href = "/collaboration?" + urlencode({"project": item["project_id"]})
            link = f'<a class="secondary btn-sm" href="{escape(href, quote=True)}">进入项目处理</a>'
        history = f'<details class="tech"><summary>处理记录</summary><ul>{trail}</ul></details>' if trail else ""
        feedback.append(
            f'<tr id="{escape(item["id"], quote=True)}"><td class="tid">{escape(item["id"][:11])}</td>'
            f'<td>{KINDS[item["kind"]]}</td>'
            f'<td class="wide"><b>{escape(item["title"])}</b>{place}'
            f'<div class="muted-text">{escape(item["details"])}</div>'
            f'<div class="muted-text">影响：{escape(item["impact"])}'
            f'{" · 证据：" + escape(item["evidence"]) if item["evidence"] else ""}</div>{history}</td>'
            f'<td>{workbench.avatar(item["author"])}<div class="muted-text">{escape(item["observed"][:10])}</div></td>'
            f'<td class="muted-text">{related or "—"}</td>'
            f'<td><span class="badge {BADGES[item["status"]]}">{LABELS[item["status"]]}</span>'
            f'<div class="muted-text">{follow}</div></td><td>{link}</td></tr>'
            + (f'<tr class="fb-ops"><td colspan="7">{update}</td></tr>' if update else ""))
    decisions, relations, changes = [], [], []
    for record in data["decision"]:
        controls = ""
        if data["managed"] and record["status"] in {"proposed", "effective"}:
            controls = ui.block("更新决定", decision_form(
                project, record, {tid: versions[tid] for tid in record["held"] if tid in versions}))
        decisions.append(
            f'<li>{escape(record["id"])} v{record["version"]} · {escape(record["area"])} · {escape(record["scope"])}'
            f' · {escape(record["status"])}<p>{escape(record["reason"])}</p>{controls}</li>')
    for record in data["relation"]:
        label = {"related": "相关", "depends": "依赖", "duplicate": "完全重复", "overlap": "局部重合"}[record["kind"]]
        relations.append(
            f'<li>{escape(record["source"])} → {escape(record["target"])} · {label} · {escape(record["reason"])}</li>')
    for record in data["change"]:
        controls = ""
        if data["managed"] and record["status"] == "pending":
            ids = record["sources"] + record["targets"]
            controls = ui.block("核对停止与生效", operation(project, "change-finish", "提交处置",
                                ui.json_field("versions", "当前任务版本", {tid: versions[tid] for tid in ids})
                                + ui.selection("outcome", "结果", [("apply", "正式承接"), ("abort", "撤回变更")])
                                + ui.text_field("reason", "实际停止及处置依据"), {"id": record["id"]}))
        changes.append(
            f'<li>{escape(record["id"])} · {escape(record["status"])} · {escape(record["reason"])}{controls}</li>')

    def tab(key, name):
        href = "/collaboration" + ("?" + urlencode({"project": key}) if key else "")
        return (f'<a href="{escape(href, quote=True)}"'
                f'{' aria-current="page"' if (key or None) == project else ""}>{escape(name)}</a>')
    tabs = ""
    if len(projects) > 1:
        tabs = ('<div class="phead"><nav class="seg" aria-label="项目">' + tab("", "全部")
                + "".join(tab(p["id"], p["name"]) for p in projects) + "</nav></div>")
    writable = [p for p in projects if set(p["roles"]) - {"observer"}]
    form = (f'<div class="box"><h3>记录反馈</h3>{feedback_form(writable, project)}</div>' if writable
            else '<p class="empty">你在所属项目里没有记录反馈的权限，只能查看。</p>')
    records = "".join(decisions + relations + changes)
    guide = (editing(project, data, versions) if data["managed"]
             else ('<p class="muted-text">选择具体项目后可以登记决定、任务关系和拆分合并。</p>' if not project and len(projects) > 1 else ""))
    return (
        tabs + '<p class="muted-text">报告者以上的成员（包括 AI 窗口）都可以记录问题和建议，观察者只能查看。项目管理员评估后，可以转入处理、标记重复或不采纳。'
        '完成后回到这里写下实际改善了什么，作为下一轮的依据。</p>' + form
        + '<div class="table-wrap"><table><thead><tr><th>编号</th><th>类型</th><th>标题</th><th>提出</th><th>关联</th><th>状态</th>'
          '<th>处理</th></tr></thead><tbody>'
        + ("".join(feedback) or '<tr><td colspan="7" class="muted-text">暂无反馈。</td></tr>') + "</tbody></table></div>"
        + f'<div class="box"><h3>决定、关系与拆合</h3>{guide}<ul class="roster">{records}</ul></div>'
    )


def dispatch(handler, method, target, actor):
    from .httpd import parse_query
    from .web import parse_form, redirect
    service = handler.server.service
    if method == "POST":
        data = parse_form(handler, 256 * 1024, 35)
        action = data.pop("operation", "")
        if action not in {"feedback-save", "feedback-update", "feedback-move", "decision-save", "task-relation",
                          "change-open", "change-finish"}:
            raise ClientError("协作操作无效")
        for name in ("tasks", "versions", "sources", "targets", "mapping", "metrics", "version", "replaces_version"):
            if name in data:
                data[name] = strict_json(data[name].encode("utf-8"))
        with service.lock:
            status, value = service.submit(actor, action, data.get("request_id"), data)
        if status != 200:
            return round_web.page("协作操作待核",
                                  value.get("message") or (value.get("steps") or [{}])[-1].get("reason", "请重送原表单"),
                                  status, actor=actor)
        return redirect("/collaboration?" + urlencode({"project": data.get("target_project_id", data["project_id"])}))
    project = parse_query(target.query, {"project"}).get("project")
    projects = service.read(actor, "projects")["projects"]
    if not project and len(projects) == 1:
        project = projects[0]["id"]
    data = service.read(actor, "collaboration", project)
    versions = ({t["task_id"]: t["version"] for t in service.read(actor, "overview", project)["tasks"]}
                if project else {})
    return round_web.work_page("反馈与决定", render(actor, project, data, versions, projects), actor)
