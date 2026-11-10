"""The invitation page's part for platform entry points and the applications waiting at them."""
from html import escape
import json

from . import task_pages, upgrade_pages, window_entries
from .display_time import time_html
from .packages import ClientError, fields
import 协作升级 as rules

OPERATIONS = {"entry-create", "entry-show", "entry-revoke", "apply-approve", "apply-reject"}
PLATFORM_NAMES = [("codex", "Codex"), ("claude", "Claude"), ("gemini", "Gemini"), ("external", "其他平台")]
ROLE_CHOICES = [("executor", "仅任务执行权限"), ("executor,receiver", "贡献者（执行和验收）"), ("receiver", "仅任务验收权限")]
STAGES = {"pending": "待处理", "approved": "已同意", "rejected": "已拒绝", "expired": "已过期", "revoked": "已作废"}


def bundle(handler, entry):
    """What a window needs to ask at this entry point. Presenting it changes nothing."""
    value = handler.invitation_bundle({"id": entry["id"], "code": window_entries.code(handler.server.service, entry),
                                       "project": entry["project"], "owner": entry["owner"], "platform": entry["platform"]})
    value.pop("invitation_url", None)
    value.update(kind="ai-window-entry", instructions=[
        "这是平台接入点的申请资料，只用于客户端 enroll --apply。提交申请不会直接登记窗口，须由负责人在网页同意。",
        "按 connect_host 连接实际地址，按 url 的主机名和 certificate_sha256 核对服务证书；下载 client.url 后核对 client.sha256，再解压。",
        "将整段 JSON 保存为 entry.json。每个窗口使用各自的凭据文件，将 window-one 换成当前窗口独有的文件名。",
        "Windows PowerShell: & .\\ops\\round-client.ps1 --state \"$env:USERPROFILE\\.taskpool\\window-one.credential\" enroll --apply .\\entry.json --window-name \"实际聊天标题\" --wait 600",
        "Linux/macOS: python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential enroll --apply ./entry.json --window-name '实际聊天标题' --wait 600",
        "命令会显示 6 位配对码。把配对码告诉负责人，由负责人在「邀请窗口」页核对后同意。",
        "未加 --wait 或等待超时后，用相同凭据文件再次运行 enroll（不带 --apply）查询结果；同意后自动完成登记和激活。",
        "申请资料可供同一平台的多个窗口使用。不要将其中的 code 或执行令牌写入反馈、日志或交付物。",
    ])
    return value


def present(handler, entry):
    text = json.dumps(bundle(handler, entry), indent=2, ensure_ascii=False)
    return ('<h2>平台接入点的申请资料</h2><p>把这份资料交给该平台的窗口。窗口提交申请后，须由负责人在本页同意才会登记。</p>'
            f'<textarea rows="10" readonly aria-label="平台接入点申请资料">{escape(text)}</textarea>')


def handle(handler, actor, operation, data, authorize):
    """One form submission of this part. Returns the HTML to show above the page."""
    service = handler.server.service
    if operation == "entry-create":
        fields(data, "request_id project_id platform owner")
        return present(handler, window_entries.create(service, actor, data["request_id"], data["project_id"],
                                                      data["platform"], data["owner"]))
    if operation == "entry-show":
        fields(data, "request_id entry_id")
        entry = next((row for row in window_entries.overview(service, actor) if row["id"] == data["entry_id"]), None)
        if not entry:
            raise ClientError("接入点不存在或当前人员无权查看", 404)
        if not entry["usable"]:
            raise ClientError("接入点已撤销或授权已失效，请重新建立", 409)
        return present(handler, entry)
    if operation == "entry-revoke":
        fields(data, "request_id entry_id reason")
        window_entries.revoke(service, actor, data["entry_id"], data["reason"])
        return '<p role="status">接入点已撤销，尚未处理的申请一并作废。已登记的窗口不受影响。</p>'
    if operation == "apply-approve":
        fields(data, "request_id application_id roles")
        roles = [role.strip() for role in data["roles"].split(",") if role.strip()]
        status, value = window_entries.decide(service, actor, data["application_id"], True, roles, authorize=authorize)
        handler.web_action_result = value
        if status != 200:
            raise ClientError(value.get("message") or (value.get("steps") or [{}])[-1].get("reason", "请求待确认"), status)
        return '<p role="status">已同意。窗口下次查询时完成登记和激活，须在 72 小时内完成。</p>'
    fields(data, "request_id application_id reason")
    window_entries.decide(service, actor, data["application_id"], False, reason=data["reason"])
    return '<p role="status">已拒绝这项申请。</p>'


def source_lines(source):
    rows = (("窗口名称", source.get("window_name")), ("模型", source.get("model")), ("环境", source.get("environment")),
            ("设备", source.get("device")), ("目录", source.get("directory")), ("会话", source.get("session")))
    return "".join(f'<li>{label}：{escape(str(value))}</li>' for label, value in rows if value)


def waiting(entry, application, form):
    # Only what this person may give to windows of this owner; with nothing to give, the full list and the rules decide.
    choices = [row for row in ROLE_CHOICES if set(row[0].split(",")) <= set(entry["roles"])] or ROLE_CHOICES
    return (f'<li><strong>配对码 {escape(application["pairing"])}</strong> · {escape(entry["platform"])} · 项目 {escape(entry["project"])}'
            f' · 负责人 {escape(entry["owner"])} · 申请于 {time_html(application["created"])}'
            f'<p class="muted-text">以下资料由窗口自行填报，未经服务核实。请先与窗口显示的配对码核对一致，再决定。</p>'
            f'<ul>{source_lines(application["source"])}</ul>'
            + form("/invitations", task_pages.hidden("operation", "apply-approve") + task_pages.hidden("application_id", application["id"])
                   + upgrade_pages.selection("roles", "同意后的窗口项目权限", choices, choices[0][0]), "同意登记")
            + upgrade_pages.block("拒绝这项申请", form("/invitations", task_pages.hidden("operation", "apply-reject")
                                                 + task_pages.hidden("application_id", application["id"])
                                                 + upgrade_pages.input_field("reason", "拒绝原因", size=400), "拒绝申请"))
            + '</li>')


def section(service, actor, form, selected=None, owners=()):
    """Two parts of the page: the applications awaiting a decision, which go on top, and below the
    invitation form the form for a new entry point followed by the entry points themselves."""
    entries = window_entries.overview(service, actor)
    pending = "".join(waiting(entry, row, form) for entry in entries for row in entry["applications"] if row["stage"] == "pending")
    pending = f'<h2>待处理的窗口申请</h2><ul class="roster">{pending}</ul>' if pending else ""
    result = ""
    if selected:
        result += upgrade_pages.block("建立平台接入点（窗口申请，负责人同意）", (
            '<p class="muted-text">平台的窗口凭申请资料自行提交申请，每项申请须由负责人或项目管理员在本页同意后才登记。'
            '申请不占用窗口编号，也不产生任何权限。</p>'
            + form("/invitations", task_pages.hidden("operation", "entry-create") + task_pages.hidden("project_id", selected)
                   + upgrade_pages.selection("platform", "平台", PLATFORM_NAMES, "codex")
                   + upgrade_pages.identity_picker("owner", "负责人（窗口归属人员）", owners, actor), "建立接入点")))
    items = []
    for entry in entries:
        state = "已撤销" if entry["revoked"] else "可用" if entry["usable"] else "授权已失效"
        history = "".join(
            f'<li>配对码 {escape(row["pairing"])} · {escape(str(row["source"].get("window_name") or row["source"].get("session") or ""))}'
            f' · {STAGES.get(row["stage"], row["stage"])}'
            + (f' · {escape(row["decided_by"])} · {time_html(row["decided"])}' if row["decided_by"] else "")
            + (f' · {escape(row["reason"])}' if row["reason"] else "") + '</li>'
            for row in entry["applications"] if row["stage"] != "pending")
        controls = ""
        if entry["usable"]:
            controls += form("/invitations", task_pages.hidden("operation", "entry-show") + task_pages.hidden("entry_id", entry["id"]),
                             "显示申请资料")
        if not entry["revoked"]:
            controls += form("/invitations", task_pages.hidden("operation", "entry-revoke") + task_pages.hidden("entry_id", entry["id"])
                             + upgrade_pages.input_field("reason", "撤销依据", size=400), "撤销接入点")
        items.append(f'<li><strong>{escape(entry["id"])}</strong> · {escape(entry["platform"])} · {escape(entry["project"])}'
                     f' · 负责人 {escape(entry["owner"])} · {state} · 待处理 {entry["pending"]}'
                     + (f'<details><summary>已处理的申请</summary><ul>{history}</ul></details>' if history else "")
                     + (f'<details><summary>接入点操作</summary>{controls}</details>' if controls else "") + '</li>')
    if items:
        result += '<h2>平台接入点</h2><ul class="roster">' + "".join(items) + '</ul>'
    return pending, result


def banner(service, actor):
    """A line on the window page for the person whose decision is awaited."""
    if not hasattr(service, "db"):
        return ""
    state = service.snapshot()["state"]
    count = sum(entry["pending"] for entry in window_entries.overview(service, actor)
                if actor == entry["owner"] or rules.manager(state, entry["project"], actor))
    return f'<p role="status"><a href="/invitations">有 {count} 项窗口申请等待你处理</a></p>' if count else ""
