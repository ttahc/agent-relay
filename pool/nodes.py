"""Node overview: which environments, platforms and windows take part, and what each is doing.

Read-only. It adds no permission: a caller sees the windows the window directory already
shows them, and an environment only where they may read that window's configuration
(the window itself, its responsible person, a system administrator).
"""
from html import escape as e
from urllib.parse import quote

import 协作升级 as rules

KINDS = {"local": "本机", "cloud": "云端", "container": "容器", "remote": "远端", "unknown": "未说明"}
CONTACT = {"current": "● 在线", "stale": "○ 联系中断", "unconfirmed": "○ 心跳未确认"}


def presence(item):
    """One of online, silent, unconfirmed, off; only a current heartbeat counts as online."""
    if item.get("status") != "active":
        return "off"
    return {"current": "online", "stale": "silent"}.get(item.get("contact"), "unconfirmed")


def overview(state, actor, sources):
    from . import window_admin
    from .execution import can_profile
    data = state.get("security", {}).get("execution", {})
    admin = rules.system_admin(state, actor)
    shown = [item for item in sources if item.get("status") != "archived"]
    names = {item["executor_id"] for item in shown}
    mappings = {}
    for row in data.get("resource_mappings", {}).values():
        if row.get("active"):
            mappings[row["environment_id"]] = mappings.get(row["environment_id"], 0) + 1
    environments, placed = [], {name: [] for name in names}
    for row in sorted(data.get("environments", {}).values(), key=lambda row: row["id"]):
        members = [name for name in row["executors"] if name in names and (admin or can_profile(state, actor, name))]
        if not members and not admin:
            continue
        environments.append({"id": row["id"], "label": row["label"], "kind": row["kind"], "active": row["active"],
                             "version": row["version"], "mappings": mappings.get(row["id"], 0), "windows": members})
        if row["active"]:
            for name in members:
                placed[name].append(row["id"])
    windows, platforms = [], {}
    for item in shown:
        name = item["executor_id"]
        detail = admin or actor == name or item.get("can_manage")
        state_of = presence(item)
        platform = item.get("platform") or "未登记"
        count = platforms.setdefault(platform, {"windows": 0, "online": 0})
        count["windows"] += 1
        count["online"] += state_of == "online"
        windows.append({"executor_id": name, "window": item.get("window"), "window_name": item.get("window_name"),
                        "platform": platform, "owner": item.get("owner"), "status": item.get("status"),
                        "presence": state_of, "last_contact": item.get("last_contact"),
                        "environments": placed[name],
                        "active_tasks": sorted({task["task_id"] for task in item.get("tasks", []) if task["lifecycle"] == "active"}),
                        "occupancies": len(window_admin._execution_occupancies(state, name)) if detail else None})
    return {"summary": {"windows": len(windows), "online": sum(row["presence"] == "online" for row in windows),
                        "working": sum(bool(row["active_tasks"]) for row in windows),
                        "environments": sum(row["active"] for row in environments), "platforms": platforms},
            "environments": environments, "windows": windows,
            "unplaced": [row["executor_id"] for row in windows if not row["environments"]]}


def _window_row(row):
    from .workbench_pages import stamp
    label = row.get("window_name") or row.get("window") or row["executor_id"]
    number = f' <small>{e(str(row["window"]))}</small>' if row.get("window") and row.get("window_name") else ""
    status = CONTACT.get({"online": "current", "silent": "stale", "unconfirmed": "unconfirmed"}.get(row["presence"]), "已停用或未启用")
    tasks = "、".join(f'<a data-task-link href="/tasks/{quote(task)}">{e(task)}</a>' for task in row["active_tasks"]) or "空闲"
    held = "—" if row["occupancies"] is None else str(row["occupancies"])
    return (f'<tr><td><a href="/executors/{quote(row["executor_id"])}">{e(str(label))}</a>{number}</td>'
            f'<td>{e(row["platform"])}</td><td>{e(str(row.get("owner") or ""))}</td>'
            f'<td><span class="online{"" if row["presence"] == "online" else " off"}">{status}</span></td>'
            f'<td>{stamp(row.get("last_contact"))}</td><td>{tasks}</td><td>{held}</td></tr>')


def _table(rows):
    if not rows:
        return '<p class="muted-text">没有你可以查看的窗口。</p>'
    return ('<table><thead><tr><th>窗口</th><th>平台</th><th>责任人</th><th>联系</th><th>最近联系</th>'
            '<th>当前任务</th><th>资源占用</th></tr></thead><tbody>' + "".join(_window_row(row) for row in rows) + '</tbody></table>')


def page(actor, data, banner=""):
    from .workbench_pages import work
    summary, index = data["summary"], {row["executor_id"]: row for row in data["windows"]}
    platforms = "".join(f'<span class="badge info">{e(name)} {count["online"]}/{count["windows"]}</span> '
                        for name, count in sorted(summary["platforms"].items()))
    head = (f'<div class="phead"><span class="muted-text">{summary["environments"]} 个启用的执行环境 · {summary["windows"]} 个窗口 · '
            f'{summary["online"]} 个在线 · {summary["working"]} 个有任务在手</span></div>'
            f'<p class="muted-text">各平台在线数／窗口数：{platforms or "暂无窗口"}</p>'
            '<p class="muted-text">「在线」只表示开启心跳的窗口在最近 3 分钟内联系过服务，不证明外部程序正在运行或已经停止。'
            '执行环境由系统管理员登记，只向窗口本人、责任人和系统管理员显示；资源占用数只向有权管理该窗口的人显示。</p>')
    sections = "".join(
        f'<section class="box"><h3>{e(env["label"])} <small>{e(env["id"])} · {KINDS.get(env["kind"], e(env["kind"]))}'
        f'{"" if env["active"] else " · 已停用"} · {env["mappings"]} 项目录映射</small></h3>'
        + _table([index[name] for name in env["windows"]]) + '</section>' for env in data["environments"])
    rest = [index[name] for name in data["unplaced"]]
    if rest:
        sections += ('<section class="box"><h3>未登记执行环境的窗口</h3>'
                     '<p class="muted-text">这些窗口没有绑定启用的执行环境，或其环境不在你的可见范围内。它们的资源冲突按保守规则判断。</p>'
                     + _table(rest) + '</section>')
    return work(actor, banner + head + (sections or '<p class="empty">还没有登记 AI 窗口。</p>'))
