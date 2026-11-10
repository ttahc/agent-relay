"""Ordinary forms for immutable execution configurations and dynamic resources."""
import json
import re
from html import escape as e
from urllib.parse import quote

from . import task_pages as pages, upgrade_pages as ui
from .packages import ClientError, strict_json

PATH = re.compile(r"/executors/([A-Za-z0-9][A-Za-z0-9_-]{0,79})/execution")
ACTIONS = {"context-save", "segment-open", "action-prepare", "resource-request", "resource-cancel", "action-start",
           "execution-fact", "resource-release"}
DIMENSIONS = (("platform", "调用平台"), ("adapter", "执行方式"), ("model", "模型"), ("reasoning", "推理配置"),
              ("tools_version", "工具集合版本"), ("permissions_version", "权限范围版本"), ("environment", "环境标识"))
STATES = {"prepared": "已准备", "queued": "排队等待", "granted": "资源已授予", "start-authorized": "已有开始许可，实际开工待回报",
          "running": "实际执行中", "finished": "已回报完成", "error": "已回报错误", "stopped": "已回报停止", "not-started": "已确认未启动",
          "unconfirmed": "执行事实待确认", "unknown": "物理占用未知，继续阻挡冲突", "released": "逻辑预约已归还", "cancelled": "等待已取消",
          "blocked": "条件不满足", "in-use": "实际使用中", "end-confirmed": "安全结束已确认", "pending-review": "材料待核"}


def fixed(values):
    return "".join(pages.hidden(key, value if value is not None else "") for key, value in values.items())


def evidence():
    return ui.text_field("evidence_note", "可核对的事实、停止或隔离依据") + ui.input_field("evidence_sha256", "证据 SHA256", size=64)


def resource_text(resources):
    return "、".join(
        f'{row.get("id", "未标明资源")}（{"只读" if row.get("mode") == "read" else "写入"} · {row.get("domain", "原记录未标明域")}）'
        for row in resources) or "无资源申请"


def config_form(row=None):
    row = row or {}
    config = row.get("config", {})
    fields = fixed({"context_id": row.get("context_id"), "version": row.get("version", 0)})
    for key, title in DIMENSIONS:
        value = config.get(key, "manual" if key == "adapter" else "unknown")
        editor = (ui.selection(key, title, [("manual", "人工确认"), ("local-files", "本地文件适配器"),
                                            ("isolated-worktree", "隔离工作树适配器")], value)
                  if key == "adapter" else ui.input_field(key, title, value, size=160))
        source = (config.get("sources") or {}).get(key, "reported" if key == "adapter" else "unknown")
        fields += ('<div class="two">' + editor
                   + ui.selection("source-" + key, "信息来源", [("unknown", "未知"), ("reported", "本窗口申报")], source)
                   + '</div>')
    fields += ui.selection("make_default", "用于新的动作", [("no", "保留为可选配置"), ("yes", "设为新动作默认配置")], "no")
    return pages.form("context-save", "保存新配置版本", contents=fields)


def fact_form(row):
    kinds = [("unconfirmed", "尚不能确认"), ("finished", "实际工作已完成"), ("error", "实际发生错误"),
             ("stopped", "已实际停止"), ("not-started", "已确认没有启动")]
    if row.get("permit_id"):
        kinds.append(("started", "已实际开始（已有开始许可）"))
    values = {key: row.get(key) for key in ("task_id", "claim_id", "scope_version", "epoch", "permit_id")}
    values.update(action_id=row.get("action_id") or (row.get("id") if row.get("segment_id") else None),
                  reporter_kind=row.get("reporter_kind", "owner"))
    fields = fixed(values) + ui.selection("kind", "实际发生的事实", kinds, "unconfirmed") + evidence()
    if not row.get("segment_id") and row.get("id") and row.get("reporter_kind") in {"human", "adapter"}:
        fields += fixed({"blocker_ref": row["id"]})
        fields += '<p class="muted-text">选择已停止或未启动时，将以所填证据请求确认这一条旧未知占用；按钮本身不能证明外部实际结束。</p>'
    fields += ui.text_field("reporter_note", "报告依据与本人知情范围")
    return pages.form("execution-fact", "登记事实（不新授执行权限）", contents=fields)


def render(actor, name, data, features, tasks, claims, domains):
    enabled = features.get("execution_protocol") == 5 and data.get("schema") == 5
    own = data.get("can_write") is True
    by_task = {task["task_id"]: task for task in tasks}
    contexts = data.get("contexts", [])
    configs = {(row["context_id"], row["version"]): row for row in contexts}
    body = (f'<div class="phead"><a href="/executors/{quote(name)}">← 窗口详情</a><h2>执行配置、动作与资源</h2></div>'
            '<p>稳定窗口身份保留。配置描述本次条件，不增加项目、工具或目录权限；改变默认配置不会覆盖已有执行段。</p>')
    if not enabled:
        body += '<p role="status">当前服务尚未启用完整执行协议；保留旧记录，不能在此降级申请新的执行权限。</p>'
    if not own:
        body += '<p class="muted-text">当前查看其他窗口；配置与新动作只由对应执行身份登记，有权人员仅办理允许的事实收尾。</p>'
    default = data.get("default_context") or {}
    body += '<section class="box"><h3>多个执行配置</h3>'
    if enabled and own:
        body += ui.block("新建可选配置", config_form())
    latest = {}
    for row in contexts:
        if row["version"] > latest.get(row["context_id"], {}).get("version", -1):
            latest[row["context_id"]] = row
    for row in contexts:
        config = row["config"]
        chosen = default.get("context_id") == row["context_id"] and default.get("version") == row["version"]
        body += (
            f'<article><h4>{e(config.get("model", "未知"))} · 配置版本 {row["version"]}{" · 当前默认" if chosen else ""}</h4>'
            '<dl>' + "".join(
                f'<dt>{title}</dt><dd>{e(str(config.get(key, "未知")))} · '
                f'{"本窗口申报" if config.get("sources", {}).get(key) == "reported" else "未知"}</dd>'
                for key, title in DIMENSIONS) + '</dl>')
        if enabled and row.get("can_write") and latest[row["context_id"]]["version"] == row["version"]:
            body += ui.block("基于此配置创建新版本", config_form(row))
        body += '</article>'
    if not contexts:
        body += '<p>暂无执行配置。</p>'
    body += '</section><section class="box"><h3>执行段（固定领取、范围和配置版本）</h3>'
    choices = [(row["context_id"] + ":" + str(row["version"]),
                f'{row["config"].get("model", "未知")} · v{row["version"]} · {row["context_id"]}') for row in contexts]
    if enabled and own and choices:
        for claim in claims:
            fields = fixed({"task_id": claim["task_id"], "claim_id": claim["claim_id"],
                            "scope_version": claim["W"]["scope"], "epoch": claim["epoch"]})
            fields += ui.selection("context_ref", "本段使用的配置", choices)
            body += ui.block("为 " + claim["task_id"] + " 新建执行段", pages.form("segment-open", "创建执行段", contents=fields))
    for segment in data.get("segments", []):
        body += f'<article><h4>{e(segment["task_id"])} · 执行段 {e(segment["id"])} · 第 {segment["epoch"]} 代</h4>'
        body += f'<p>范围 {segment["scope_version"]} · 配置 v{segment["context_version"]}</p>'
        context = configs.get((segment["context_id"], segment["context_version"]))
        if enabled and own and context:
            fields = fixed({"segment_id": segment["id"], "version": segment["version"],
                            "adapter_id": context["config"]["adapter"]})
            fields += ui.text_field("description", "本次实际动作及预期结果")
            resources = by_task.get(segment["task_id"], {}).get("resources", [])
            for index, row in enumerate(resources):
                fields += (f'<label class="check"><input type="checkbox" name="pick-{index}" '
                           f'value="{e(json.dumps({"id": row["id"], "mode": row["mode"]}), quote=True)}">'
                           f'{e(row["id"])} · {"只读" if row["mode"] == "read" else "写入"}</label>')
            fields += ui.selection("domain", "资源环境", [(key, key) for key in domains])
            fields += '<p class="muted-text">只选择本动作完整需要的资源。未受信解析的环境按保守域处理，不表示已隔离外部写入。</p>'
            body += ui.block("准备一个新动作", pages.form("action-prepare", "准备动作（尚不可开工）", contents=fields))
        body += '</article>'
    body += '</section><section class="box"><h3>动作、资源许可与实际事实</h3><p>开始许可不会启动外部程序；只有实际回报才表示开工。unknown 不等于已结束。</p>'
    grants = {row["id"]: row for row in data.get("grants", [])}
    for row in data.get("actions", []):
        body += (f'<article><h4>{e(row["task_id"])} · {e(row.get("description", row["id"]))}</h4>'
                 f'<p>{e(STATES.get(row["state"], row["state"]))}</p>'
                 f'<p>{e(resource_text(row.get("resources", [])))}</p>')
        if enabled and row.get("can_request"):
            body += pages.form("resource-request", "申请本动作完整资源集合",
                               {"action_id": row["id"], "version": row["version"],
                                "resources": json.dumps(row["resources"])})
        grant = grants.get(row.get("grant_id"))
        if enabled and row.get("can_start") and grant:
            body += pages.form("action-start", "申请本动作开始许可",
                               {"action_id": row["id"], "version": row["version"], "grant_id": grant["id"],
                                "generation": grant["generation"]})
        if row.get("can_report"):
            body += ui.block("登记实际事实或结束依据", fact_form(row))
        if row.get("can_release") and grant:
            fields = fixed({"action_id": row["id"], "grant_id": grant["id"], "generation": grant["generation"],
                            "version": grant["version"]}) + evidence()
            fields += ui.selection("basis", "归还依据", [
                ("unconfirmed", "尚不能确认物理结束（继续阻挡）"), ("human-isolation", "有权人员已核对停止或隔离证据"),
                ("adapter-confirmed", "受信适配器已证明安全结束")], "unconfirmed")
            body += ui.block("归还逻辑预约与核对物理占用", pages.form("resource-release", "按所述依据归还", contents=fields))
        body += '</article>'
    body += '</section><section class="box"><h3>资源队列</h3>'
    for row in data.get("resource_requests", []):
        body += (f'<p>顺序 {row.get("sequence", "—")} · {e(STATES.get(row["state"], row["state"]))} · '
                 f'{e(resource_text(row.get("resources", [])))}</p>')
        if enabled and own and row["state"] == "queued":
            body += pages.form("resource-cancel", "取消此次等待（不停止程序）",
                               {"resource_request_id": row["id"], "version": row["version"]})
    body += '</section><section class="box"><h3>实际占用、旧领取与 unknown 阻挡</h3>'
    for row in [*data.get("grants", []), *data.get("legacy", []), *data.get("blockers", []),
                *data.get("physical_blockers", [])]:
        body += (f'<p>{e(str(row.get("task_id") or row.get("claim_id") or row["id"]))} · '
                 f'{e(STATES.get(row.get("physical"), str(row.get("physical") or "待核")))} · '
                 f'{e(resource_text(row.get("resources", [])))}</p>')
        if row.get("binding_notice"):
            body += f'<p class="muted-text">{e(row["binding_notice"])}</p>'
        if row.get("can_report") and row.get("claim_id"):
            body += ui.block("登记原领取的真实收尾事实", fact_form(row))
    body += '</section><p>事实记录与材料暂存不自动构成交付接受或验收通过。外部程序自动结束检测及自动解除占用尚未支持。</p>'
    return pages.workspace(actor, '<section class="wb-page">' + body + '</section>')


def _body(action, values):
    data = dict(values)
    for key in ("version", "scope_version", "epoch", "generation"):
        if key in data:
            try:
                data[key] = int(data[key])
            except (ValueError, TypeError) as error:
                raise ClientError("页面记录版本无效，请重新读取后修正") from error
    if action == "context-save":
        config = {key: data.pop(key) for key, _ in DIMENSIONS}
        config["sources"] = {key: data.pop("source-" + key) for key, _ in DIMENSIONS}
        data.update(config=config, context_id=data["context_id"] or None,
                    make_default=data.pop("make_default") == "yes")
    elif action == "segment-open":
        try:
            context, version = data.pop("context_ref").rsplit(":", 1)
            data.update(context_id=context, context_version=int(version))
        except (ValueError, KeyError) as error:
            raise ClientError("请选择本段使用的合法配置版本") from error
    elif action == "action-prepare":
        resources = []
        for key in sorted(list(data)):
            if key.startswith("pick-"):
                row = strict_json(data.pop(key).encode())
                resources.append({**row, "domain": data["domain"]})
        data.pop("domain")
        data["resources"] = resources
    elif action == "resource-request":
        data["resources"] = strict_json(data["resources"].encode())
    elif action in {"execution-fact", "resource-release"}:
        data["evidence"] = {"note": data.pop("evidence_note"), "sha256": data.pop("evidence_sha256")}
        if action == "execution-fact":
            blocker = data.pop("blocker_ref", None)
            if blocker and data.get("kind") in {"stopped", "not-started"}:
                data["blocker_ids"] = [blocker]
            data["action_id"], data["permit_id"] = data.get("action_id") or None, data.get("permit_id") or None
            data["reporter_basis"] = {"kind": data.pop("reporter_kind"), "note": data.pop("reporter_note")}
    return data


def body(action, values):
    try:
        return _body(action, values)
    except (KeyError, TypeError, ValueError) as error:
        raise ClientError("执行表单信息缺失或无效，当前输入保留；请核对后重新读取对应记录。", 400) from error


def dispatch(handler, method, target, actor):
    if method != "GET":
        raise ClientError("此页仅供读取，写入请使用对应操作表单", 405)
    name = PATH.fullmatch(target.path)[1]
    service = handler.server.service
    data = service.read(actor, "execution", {"executor_id": name})
    features = service.read(actor, "features")
    tasks = service.read(actor, "overview")["tasks"]
    claims = []
    if data.get("can_write"):
        for task in tasks:
            if task.get("holder") == name:
                claims.extend(claim for claim in service.read(actor, "task", task["task_id"])["claims"]
                              if claim["origin"] == name and claim["L"] == "active")
    domains = sorted(getattr(service, "execution_roots", {})) or ["manual-unverified"]
    from .web import html_page
    return html_page("执行配置与资源 · 任务协作平台", render(actor, name, data, features, tasks, claims, domains))
