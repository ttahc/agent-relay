#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rebuildable, versioned views; no manually edited business board is overwritten."""
from pathlib import Path
import os
import re
import uuid
from urllib.parse import unquote, urlsplit, urlunsplit

from 协作存储 import digest, encoded, publish, read_json, safe
from 协作账本 import cursor, public_status


LABELS = {"available": "可领取", "running": "进行中", "pending_integration": "待集成",
          "pending_commit": "待提交", "pending_close": "待收口", "completed": "已完成", "closed_candidate": "候选已收口（业务进度见父项或原业务记录）",
          "closed_missing": "已收口·证据缺失", "cancelled": "已取消", "replaced": "已替代", "merged": "已合并",
          "merge_pending": "待合并", "migration_review": "迁移待核"}
EXEC = {"running": "执行中", "requested": "停止已请求", "stopped": "已停止"}
WORK = {"draft": "草稿", "review": "待审", "revision": "待返修", "complete": "已完成", "terminated": "已终止"}


def cell(value):
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ").replace("\r", "")


def table(headers, rows):
    return ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"] + [
        "| " + " | ".join(cell(x) for x in row) + " |" for row in rows]


def literal(value):
    """Free text is not Markdown relative to the generated board's directory."""
    return str(value).replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")


def item_source_link(desk, state, item, destination):
    source = item.get("source_record", "")
    target = None
    try:
        if source.startswith(("TestResults/", "docs/")):
            target = safe(Path(__file__).resolve().parents[2], source.split(" SHA256=", 1)[0])
        elif source in state["acceptances"]:
            references = state["acceptances"][source].get("tested_artifacts", [])
            if references:
                target = safe(desk.store, references[0]["path"])
        else:
            for c in state["claims"].values():
                prefix = c["claim_id"] + "/"
                if source.startswith(prefix):
                    record = c["deliveries"].get(source[len(prefix):])
                    if record and record.get("manifest"):
                        target = safe(desk.store, record["manifest"]["path"])
                    break
    except (OSError, ValueError, KeyError, TypeError):
        target = None
    if not target or not target.exists():
        return "原件/引用待核"
    if destination is None:
        return str(target)
    relative = os.path.relpath(target, Path(destination).parent).replace("\\", "/")
    return "[原件](<" + relative + ">)"


def readable_legacy(desk, reference, source_path):
    original = safe(desk.store, reference["path"])
    raw = original.read_bytes()
    if digest(raw) != reference["sha256"]:
        raise ValueError("原业务看板冻结指纹已变化")
    folder = safe(desk.store, "legacy-views")
    target = folder / (reference["sha256"][:16] + "-readable.md")
    workspace = Path(__file__).resolve().parents[2]
    source = safe(workspace, source_path)
    def rebase(match):
        value = match.group(2)
        url = urlsplit(value[1:-1] if value.startswith("<") and value.endswith(">") else value)
        if url.scheme or url.netloc or not url.path or url.path.startswith("/"):
            return match.group(0)
        destination = (source.parent / unquote(url.path)).resolve()
        link = os.path.relpath(destination, folder).replace("\\", "/")
        return match.group(1) + "<" + urlunsplit(("", "", link, url.query, url.fragment)) + ">" + match.group(3)
    text = raw.decode("utf-8-sig").replace("\r\n", "\n")
    text = re.sub(r"(!?\[[^\]\n]*\]\()(<[^>\n]+>|[^)\n]+)(\))", rebase, text)
    original_link = os.path.relpath(original, folder).replace("\\", "/")
    header = ("# 迁移前业务看板（只读展示）\n\n"
              "本页仅重新定位相对链接，不重判业务状态；实时任务以新账本为准。"
              "[原始冻结字节](<" + original_link + ">)，SHA256：`" + reference["sha256"] + "`。\n\n")
    display = (header + text).encode("utf-8")
    if not publish(target, display) and target.read_bytes() != display:
        raise ValueError("业务看板展示副本存在不同内容，保留差异")
    return target


def render_details(desk, snap, destination=None):
    state = snap["state"]
    business = max((e["ledger_seq"] for e in snap["entries"] if e.get("effects") and e.get("result") == "applied"), default=0)
    lines = ["# 协作账本看板", "", f"读取head：{snap['head']}；最后业务变更：{business}；协调代次：{state['generation']}。", "",
             "本视图可从账本重建；人工结论通过命令追加。", ""]
    legacy = state["migration"].get("legacy_board")
    if legacy:
        target = readable_legacy(desk, legacy, state["migration"].get("legacy_source_path", state["migration"].get("board_path", "docs/AI协作/制图与模型分析-20261024-任务看板.md")))
        if destination:
            link = os.path.relpath(target, Path(destination).parent).replace("\\", "/")
            lines += ["[迁移前业务状态、暂停边界与现场证据](<" + link + ">)。该冻结原件保留，未登记为新执行任务的业务不自动恢复。", ""]
    if snap["halted"]:
        lines += [f"**协作账本停写（技术故障），有效head为{snap['head']}。占用保留，只收件；恢复需另行设计。**", ""]
    sections = {"需要我处理": [], "进行中": [], "待提交": [], "未开始": [], "已完成": []}
    dependents = {tid: sum(any(d["task"] == tid for d in t["dependencies"]) for t in state["tasks"].values()) for tid in state["tasks"]}
    tasks = sorted(state["tasks"].values(), key=lambda t: (-t.get("priority", 0), -dependents[t["task_id"]], t.get("created_seq", 0), t["task_id"]))
    for task in tasks:
        status = task["status"]
        section = ("需要我处理" if task.get("user_needed") else "待提交" if status == "pending_commit" else
                   "进行中" if status in {"running", "pending_integration", "pending_close"} else
                   "未开始" if status in {"available", "merge_pending", "migration_review"} else "已完成")
        deps = [d["task"] + "/" + d["output"] + "/" + d["criterion"] for d in task["dependencies"]
                if d["criterion"] not in state["tasks"].get(d["task"], {}).get("provided", {}).get(d["output"], [])]
        task_id = ('<a id="task-' + task["task_id"].lower() + '"></a>' if state["migration"].get("board_layout") == "compact-v1" else "") + task["task_id"]
        sections[section].append([task_id, task["title"], LABELS.get(status, status),
                                  "; ".join("依赖未就绪：" + d for d in deps) or task.get("close_id", "")])
    for title, rows in sections.items():
        lines += ["## " + title, ""] + (table(["任务", "工作", "状态", "依据/下一步"], rows) if rows else ["暂无。看板不自动派发。"])+ [""]
    lines += ["## 未终结提议", ""] + table(["提议", "来源", "内容", "用户依据"], [
        [p["proposal_id"], p["origin"], p["title"], ", ".join(p["authorities"])]
        for p in state["proposals"].values() if p["status"] == "proposed"]) + [""]
    lines += ["## 领取与实际活动", ""] + table(["领取", "执行态E", "当前工作W", "占用", "生命周期/标记"], [
        [c["claim_id"], EXEC[c["E"]["state"]] + " " + str(c["E"].get("reason") or ""),
         "v" + str(c["W"]["scope"]) + " " + WORK[c["W"]["state"]] + " " + str(c["W"]["revision"]), len(c["R"]),
         c["L"] + (" · 范围待确认" if c.get("scope_ack_pending") else "") + (" · 活动未知待回执" if c.get("owner_ack_pending") else "")]
        for c in state["claims"].values()]) + [""]
    lines += ["## 遗留项台账（待定去向单列）", ""] + table(["条目", "内容", "状态", "当前去向/承接", "转交历史", "来源"], [
        [i["item_id"], literal(i["description"]), i["status"], i["disposition"] + " / " + str(i["holder"] or "无"),
         " → ".join(str(x.get("to") or "无") for x in i["history"]), item_source_link(desk, state, i, destination)]
        for i in sorted(state["items"].values(), key=lambda i: (i["disposition"] != "pending", i["item_id"]))]) + [""]
    lines += ["## 各范围交付与载荷", ""] + table(["领取/修订", "范围", "封存位置", "审核态", "载荷"], [
        [c["claim_id"] + "/" + revision, d["scope_version"], d["seal_seq"], d["status"], d.get("payload_status", "旧记录待核")]
        for c in state["claims"].values() for revision, d in c["deliveries"].items()]) + [""]
    copies = desk.copies()
    pending = {}
    for record in copies:
        env = record["envelope"]
        key = env["origin_id"] + "/" + env["event_id"]
        if key not in snap["control"]["terminal"]:
            pending.setdefault(key, set()).add(record["sha256"])
    lines += ["## 来源与待回执", ""] + table(["来源", "最后连续终局序号", "待处理/冲突"], [
        [oid, cursor(snap, oid), "; ".join(key + ("（冲突待裁）" if len(values) > 1 else "（同步待补/待处理）")
                                          for key, values in pending.items() if key.startswith(oid + "/"))]
        for oid in sorted(set(state["origins"]) | {r["envelope"]["origin_id"] for r in copies})]) + [""]
    lines += ["## 人工备注", ""] + ["- " + cell(n["text"]) for n in state["notes"].values()] + [""]
    return "\n".join(lines).encode("utf-8")


def task_summary(state, task):
    """Presentation only; never grants execution or infers completion from release."""
    status = task["status"]
    section = ("需要我处理" if task.get("user_needed") else "待提交" if status == "pending_commit" else
               "进行中" if status in {"running", "pending_integration", "pending_close"} else
               "未开始" if status in {"available", "merge_pending", "migration_review"} else "已完成")
    label = LABELS.get(status, status)
    if task.get("user_needed"):
        return section, label, "确认已列出的业务选择或授权"
    active = [state["claims"][cid] for cid in task["claims"] if state["claims"][cid]["L"] == "active"]
    if active:
        claim = active[-1]
        if claim.get("owner_ack_pending"):
            return section, "待持有者回执", "补确认及有依据的实际停止回执"
        if claim.get("scope_ack_pending"):
            return section, "待范围确认", "持有者确认当前范围并补封交付"
        if claim["E"]["state"] == "requested":
            return section, "等待实际停止", "停止新动作，回报真实结束；占用保留"
        pending = sum(i["status"] == "unresolved" and i["holder"] == task["task_id"] for i in state["items"].values())
        if claim["W"]["state"] == "review":
            return section, "待补证" if pending else "待审", "处理" + str(pending) + "项未解记录后复核" if pending else "指定接收者核证据并登记结论"
        if claim["W"]["state"] == "revision":
            return section, "待返修", "依据原审阅修订，重新核资源并封存"
        return section, "外平台进行中" if not state["origins"][claim["origin"]]["local"] else "进行中", "完成本卡工作、封存并报告真实停止"
    actions = {"available": "核固定输入与资源后领取",
               "merge_pending": "核对重复提议后决定合并或独立登记", "migration_review": "核迁入记录与原证据",
               "pending_commit": "按用户授权提交已接受内容", "pending_close": "复核强制证据并收口",
               "pending_integration": "登记集成任务并保留候选验收边界", "closed_missing": "补回原缺失证据后更正结论"}
    return section, label, actions.get(status, "按原边界接续反馈" if status in {"completed", "closed_candidate"} else "查明原决定后接续")


def render_compact(desk, snap, destination=None, detail_destination=None):
    state = snap["state"]
    destination = Path(destination) if destination else Path(state["migration"]["board_path"])
    detail_destination = Path(detail_destination) if detail_destination else destination.parent / "任务明细.md"
    detail_link = os.path.relpath(detail_destination, destination.parent).replace("\\", "/")
    lines = ["# 任务看板", "", f"账本head：{snap['head']}；协调代次：{state['generation']}。",
             "[完整台账、提议与历史证据](<" + detail_link + ">)。本页由账本生成，人工结论通过命令登记。", ""]
    if snap["halted"]:
        lines += ["**账本停写：保留占用，只收件；先处理损坏，不继续调度。**", ""]
    sections = {name: [] for name in ("需要我处理", "进行中", "待提交", "未开始", "已完成")}
    for task in sorted(state["tasks"].values(), key=lambda t: (-t.get("priority", 0), t.get("created_seq", 0), t["task_id"])):
        section, label, action = task_summary(state, task)
        evidence = "[详情](<" + detail_link + "#task-" + task["task_id"].lower() + ">)"
        sections[section].append([literal(task["task_id"] + " · " + task["title"]), label, action, evidence])
    for title, rows in sections.items():
        lines += ["## " + title, ""] + (table(["任务", "状态", "下一动作", "证据"], rows) if rows else ["暂无。"])+ [""]
    return "\n".join(lines).encode("utf-8")


def render(desk, snap, destination=None):
    if snap["state"]["migration"].get("board_layout") == "compact-v1":
        return render_compact(desk, snap, destination)
    return render_details(desk, snap, destination)


def write_views(desk, output):
    snap = desk.read()
    folder = Path(output).absolute()
    folder.mkdir(parents=True, exist_ok=True)
    board = render(desk, snap)
    prefix = f"head-{snap['head']:012d}-{snap['sha256'][:8]}-{digest(board)[:8]}"
    files = {"看板.md": render(desk, snap, folder / prefix / "看板.md"), "state.json": encoded(public_status(snap))}
    if snap["state"]["migration"].get("board_layout") == "compact-v1":
        files["任务明细.md"] = render_details(desk, snap, folder / prefix / "任务明细.md")
    for name, raw in files.items():
        path = safe(folder, prefix + "/" + name)
        if not publish(path, raw) and path.read_bytes() != raw:
            raise ValueError("派生视图发生冲突，保留差异")
    manifest = {"head": snap["head"], "ledger_sha256": snap["sha256"], "files": [
        {"path": n, "sha256": digest(b), "bytes": len(b)} for n, b in files.items()]}
    publish(safe(folder, prefix + "/manifest.json"), encoded(manifest))
    return {"head": snap["head"], "directory": str(folder / prefix), "halted": snap["halted"]}


def read_cached(directory):
    """Fast display only. Never used to issue a claim, permission or any decision."""
    folder = Path(directory).absolute()
    manifest = read_json(safe(folder, "manifest.json"))
    for item in manifest["files"]:
        raw = safe(folder, item["path"]).read_bytes()
        if digest(raw) != item["sha256"] or len(raw) != item["bytes"]:
            raise ValueError("快照视图损坏，须从账本重建")
    value = read_json(safe(folder, "state.json"))
    if value["head"] != manifest["head"] or value["sha256"] != manifest["ledger_sha256"]:
        raise ValueError("快照视图head不一致")
    return {"read_mode": "derived-snapshot-display-only", "facts_at_head": value["head"], "authoritative": False, "snapshot": value}


def prepare_board_layout(desk, payload, state):
    """Read-only guard for a coordinator's explicitly authorized path change."""
    migration = state["migration"]
    old = payload.get("expected_board_path")
    if old != migration.get("board_path") or migration["phase"] != "active":
        raise ValueError("看板路径已变化或未启用")
    workspace = Path(__file__).resolve().parents[2]
    paths = [old, payload["board_path"], payload["detail_path"]]
    if len({p.casefold() for p in paths}) != 3 or any(not p.startswith("docs/") or not p.endswith(".md") for p in paths):
        raise ValueError("主看板、详情和旧入口须为不同的文档路径")
    raw = safe(workspace, old).read_bytes()
    snapshot = payload["previous_board"]
    if digest(raw) != snapshot["sha256"] or safe(desk.store, snapshot["path"]).read_bytes() != raw:
        raise ValueError("切换前看板快照不符")
    for path in paths[1:]:
        if safe(workspace, path).exists():
            raise ValueError("新看板目标已存在，须先核定原件，不能覆盖")
    return {"board_layout_verified": True}


def publish_board(desk, relative_path, snap=None):
    """Replace only the frozen or our previously generated board; preserve every version."""
    snap = snap or desk.read()
    migration = snap["state"]["migration"]
    if migration["phase"] != "active" or relative_path != migration.get("board_path"):
        raise ValueError("只有已切换、已登记的看板可发布")
    if migration.get("board_layout") == "compact-v1":
        return publish_compact(desk, snap)
    workspace = Path(__file__).resolve().parents[2]
    target = safe(workspace, relative_path)
    raw = render(desk, snap, target)
    checksum = digest(raw)
    prior = target.read_bytes()
    originals = {migration["legacy_board"]["sha256"], checksum}
    folder = safe(desk.store, "projections")
    records = sorted(folder.glob("*.json")) if folder.exists() else []
    for path in records:
        record = read_json(safe(desk.store, "projections/" + path.name))
        if record["path"] == relative_path:
            originals.add(record["sha256"])
            if record["head"] > snap["head"]:
                return {"head": record["head"], "path": str(target), "skipped_older_projection": True}
    if digest(prior) not in originals:
        raise ValueError("看板在迁移快照外有新改动；先收录差异，不覆盖")
    publish(safe(desk.store, "board-history/" + digest(prior) + ".md"), prior)
    if prior != raw:
        pending = target.parent / (".board-" + uuid.uuid4().hex + ".tmp")
        try:
            publish(pending, raw)
            os.replace(pending, target)
        finally:
            pending.unlink(missing_ok=True)
    receipt = {"head": snap["head"], "path": relative_path, "sha256": checksum, "ledger_sha256": snap["sha256"]}
    publish(safe(desk.store, f"projections/{snap['head']:012d}-{checksum[:8]}.json"), encoded(receipt))
    return {**receipt, "path": str(target)}


def publish_compact(desk, snap):
    from 协作流水存储 import index_mutex, replace_projection
    migration = snap["state"]["migration"]
    workspace = Path(__file__).resolve().parents[2]
    board, detail = migration["board_path"], migration["detail_path"]
    board_target, detail_target = safe(workspace, board), safe(workspace, detail)
    files = {board: render_compact(desk, snap, board_target, detail_target),
             detail: render_details(desk, snap, detail_target)}
    for alias in migration.get("board_aliases", []):
        relative = os.path.relpath(board_target, safe(workspace, alias).parent).replace("\\", "/")
        files[alias] = ("# 任务看板入口已更名\n\n[打开当前任务看板](<" + relative + ">)。旧记录和详细台账从新入口查阅。\n").encode("utf-8")
    with index_mutex(desk.store):
        folder = safe(desk.store, "projections")
        records = [read_json(path) for path in sorted(folder.glob("*.json"))] if folder.exists() else []
        if any(r["path"] in files and r["head"] > snap["head"] for r in records):
            return {"head": max(r["head"] for r in records if r["path"] in files), "skipped_older_projection": True}
        # Check every destination before publishing any member of this rebuildable set.
        for path, raw in files.items():
            target = safe(workspace, path)
            if target.exists():
                allowed = {r["sha256"] for r in records if r["path"] == path} | {digest(raw)}
                if path in migration.get("board_aliases", []):
                    allowed.add(migration["previous_board"]["sha256"])
                if digest(target.read_bytes()) not in allowed:
                    raise ValueError("派生看板存在人工差异，保留原件，不覆盖：" + path)
        for path, raw in files.items():
            target = safe(workspace, path)
            if target.exists():
                prior = target.read_bytes()
                publish(safe(desk.store, "board-history/" + digest(prior) + ".md"), prior)
            replace_projection(target, raw)
            receipt = {"head": snap["head"], "path": path, "sha256": digest(raw), "ledger_sha256": snap["sha256"]}
            publish(safe(desk.store, f"projections/{snap['head']:012d}-{digest(path.encode())[:8]}-{digest(raw)[:8]}.json"), encoded(receipt))
    return {"head": snap["head"], "path": str(board_target), "detail_path": str(detail_target), "aliases": migration.get("board_aliases", [])}


def restore_legacy_board(desk, snap):
    migration = snap["state"]["migration"]
    if not migration.get("board_path"):
        return
    target = safe(Path(__file__).resolve().parents[2], migration["board_path"])
    original = safe(desk.store, migration["legacy_board"]["path"]).read_bytes()
    if digest(original) != migration["legacy_board"]["sha256"]:
        raise ValueError("旧看板快照已变化，不能回退")
    current = target.read_bytes()
    known = {digest(original)}
    folder = safe(desk.store, "projections")
    if folder.exists():
        known.update(read_json(path)["sha256"] for path in folder.glob("*.json"))
    if digest(current) not in known:
        raise ValueError("回退看板存在未登记改动，保留差异")
    publish(safe(desk.store, "board-history/" + digest(current) + ".md"), current)
    if current != original:
        pending = target.parent / (".board-rollback-" + uuid.uuid4().hex + ".tmp")
        try:
            publish(pending, original)
            os.replace(pending, target)
        finally:
            pending.unlink(missing_ok=True)
