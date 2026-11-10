"""Read routes of the service: one function per route, answered from one ledger snapshot.

``read`` is entered by ``Service.read`` with the service lock held.  A route that is
unknown, unavailable in the current mode, or declines the request falls through to
the stored-file lookup, which is also what answers the ``artifact`` route.
"""

from collections import Counter
from functools import cached_property
import json

from . import delegation, execution, input_packages, release_views, round_projects, round_service, upgrade, wakeups, window_admin
from .constants import ID
from .packages import ClientError
from .privacy import public, window_source
from .task_state import active_claim, execution_status, security_schema, stage
from 协作存储 import digest, encoded
from 协作本轮 import execution_settings
from 协作视图 import render
import 协作升级 as rules


class Reading:
    """What every route of one read shares: the caller, the snapshot and values derived from it."""

    def __init__(self, service, snap, actor, route, argument):
        self.service, self.snap, self.actor, self.route = service, snap, actor, route
        self.state = state = snap["state"]
        self.list_full = security_schema(state) < 5
        if route in {'tasks', 'task-options'} and isinstance(argument, dict):
            self.list_full = argument.get('full') == '1'
            argument = argument.get('project')
        self.argument = argument
        self.tasks = state["tasks"]
        self.upgraded = rules.enabled(state)
        self.round_enabled = round_service.enabled(state)

    @cached_property
    def visible_tasks(self):
        return [task for task in self.tasks.values() if self.service.visible(self.state, task, self.actor)]


DECLINED = object()  # returned by a route that leaves the request to the stored-file lookup


def features(r, argument):
    result = execution.features(r.state)
    result.update(api_protocol=1, input_download=dict(input_packages.BUDGET))
    result.setdefault('features', {})['input-package'] = True
    result['features']['list-summary'] = True
    if r.round_enabled:
        result['features']['wait'] = True
        result['wait'] = {'max_seconds': wakeups.MAX_HOLD}
    return result


def execution_view(r, argument):
    return execution.read(r.state, r.actor, argument)


def window_impact(r, argument):
    return window_admin.view(r.state, r.actor, argument)


def capability_requests(r, argument):
    return window_admin.requests_view(r.state, r.actor)


def cleanup(r, argument):
    actor = r.actor
    return {"claims": [{"claim_id": c["claim_id"], "task_id": c["task_id"], "epoch": c["epoch"],
                        "W": {"scope": c["W"]["scope"]}, "origin": actor, "L": c["L"]}
                       for c in r.state["claims"].values() if c["origin"] == actor and c["L"] == "active"]}


def invitations(r, argument):
    return round_service.invitations(r.state, r.actor)


def runner(r, argument):
    state, actor = r.state, r.actor
    contacts = r.service.notices.contacts()
    return {"settings": round_service.execution_settings(state, actor), "last_contact": contacts.get(actor),
            "load": rules.execution_load(state, actor),
            "automation": {p["id"]: state["round"].get("automation:" + p["id"], {"enabled": False, "version": 0})
                           for p in upgrade.projects(state, actor)}}


def notices(r, argument):
    service, state, actor, tasks = r.service, r.state, r.actor, r.tasks
    rows = service.db.execute("SELECT event_id,task,attempts,sent,ack FROM round_notices WHERE actor=? ORDER BY seq DESC LIMIT 100",
                              (actor,))
    return {"notices": [{"event_id": event, "task_id": task, "attempts": attempts, "sent": sent,
                         "acknowledged": ack} for event, task, attempts, sent, ack in rows
                        if task in tasks and service.visible(state, tasks[task], actor)]}


def collaboration(r, argument):
    return round_projects.view(r.state, r.actor, argument)


def sheet(r, argument):
    service, tasks = r.service, r.tasks
    if argument not in tasks:
        raise ClientError("任务不存在", 404)
    task = tasks[argument]
    view = service.detail(r.state, task, r.actor)
    brief = next((service.checked_file({"path": path, "sha256": sha}).decode("utf-8")
                  for path, sha in task["inputs"].items() if path.endswith("/brief.md")), "")
    return {"view": view, "brief": brief, "events": upgrade.audit_rows(service, r.snap, r.actor, {"task": argument})}


def tasks(r, argument):
    service, state, actor = r.service, r.state, r.actor
    available = []
    for task in r.visible_tasks:
        if task["status"] != "available" or argument and rules.task_project(task) != argument:
            continue
        if r.upgraded:
            qualified = service.qualification(state, task, actor)
            if not qualified["eligible"]:
                continue
            task = {**task, "qualification": qualified}
        available.append(task)
    if r.round_enabled:
        available.sort(key=lambda task: (not task["qualification"]["prioritized"], -task["priority"], task["created_seq"]))
    if not r.list_full:
        available = [service.task_summary(task) for task in available]
    return {"repo_id": service.desk.meta["repo_id"], "head": r.snap["head"], "tasks": available, 'summary': not r.list_full}


def task_options(r, argument):
    service, state, actor = r.service, r.state, r.actor
    overview = service.read(actor, "overview", argument)
    rows = overview["tasks"]
    reasons = Counter(reason for task in rows for reason in task["qualification"]["missing"])
    hints = {}
    for task in rows:
        spec = rules.contract(task) or {}
        for requirement in spec.get("requirements", []):
            hint = {"project_id": rules.task_project(task), **requirement}
            hints[encoded(hint)] = hint
    return {"tasks": rows if r.list_full else [service.task_summary(task) for task in rows], 'summary': not r.list_full,
            "counts": {"visible": len(rows),
            "claimable": sum(task["qualification"]["eligible"] for task in rows)},
            "missing_summary": [{"reason": reason, "count": count} for reason, count in sorted(reasons.items())],
            "capability_hints": sorted(hints.values(), key=lambda row: (row["project_id"], row["id"])),
            "load": rules.execution_load(state, actor)}


def overview(r, argument):
    service, state, actor = r.service, r.state, r.actor
    shown = []
    for task in r.visible_tasks:
        if argument and rules.task_project(task) != argument:
            continue
        current = active_claim(state, task)
        project = rules.project_record(state, rules.task_project(task))
        last = next((state["claims"][cid] for cid in reversed(task["claims"])
                     if cid in state["claims"] and state["claims"][cid].get("task_id") == task["task_id"]), None)
        last_identity = (rules.identity(state, last["origin"]) or {}) if last else {}
        shown.append({**task, "stage": stage(task, current, state),
                      'execution_status': execution_status(state, current),
                      "project_name": project["name"] if project else None,
                      "window": (rules.identity(state, current["origin"]) or {}).get("window") if current else None,
                      "window_name": (rules.identity(state, current["origin"]) or {}).get("window_name") if current else None,
                      "holder": current["origin"] if current else None,
                      "last_executor": {"id": last["origin"], "window": last_identity.get("window"),
                                        "window_name": last_identity.get("window_name")} if last else None,
                      "last_claim_id": last["claim_id"] if last else None,
                      "revisions": len(current["deliveries"]) if current else 0,
                      "qualification": service.qualification(state, task, actor)})
    return {"roles": service.roles(state, actor), "upgraded": r.upgraded,
            "projects": upgrade.projects(state, actor), "tasks": shown, "round": r.round_enabled,
            "feedback_due": service.feedback_due(state, actor, argument) if r.round_enabled else 0}


def activity(r, argument):
    return upgrade.activity_rows(r.service, r.snap, r.actor)


def project_cards(r, argument):
    return [{**project, "members": r.service.members(r.state, project["id"])} for project in upgrade.projects(r.state, r.actor)]


def project(r, argument):
    state, actor = r.state, r.actor
    project = next((p for p in upgrade.projects(state, actor) if p["id"] == argument), None)
    if not project:
        raise ClientError("项目不存在或无权查看", 404)
    return {**project, "members": r.service.members(state, argument), "identity_choices": release_views.identities(state, actor),
            "automation": state["round"].get("automation:" + argument, {"enabled": False, "version": 0}) if r.round_enabled else None}


def projects(r, argument):
    return {"projects": upgrade.projects(r.state, r.actor)}


def input_package(r, argument):
    return input_packages.package(r.service, r.actor, r.state, argument)


def invitation_owners(r, argument):
    return {"owners": release_views.invitation_owners(r.state, r.actor, argument)}


def release_readiness(r, argument):
    return public(release_views.readiness(r.state, r.actor))


def project_capabilities(r, argument):
    state = r.state
    if not any(p["id"] == argument for p in upgrade.projects(state, r.actor)):
        raise ClientError("项目不存在或无权查看", 404)
    found = {}
    for key, record in state["pilot"].items():
        if key.startswith(f"cap:{argument}:"):
            found.setdefault(key.rsplit(":", 1)[1], record["kind"])
    return sorted(found.items())


def executors(r, argument):
    service, state, actor = r.service, r.state, r.actor
    sources = upgrade.sources(state, actor)
    if r.round_enabled:
        round_service.annotate_sources(service, state, sources)
    sources = [window_source(state, actor, source) for source in sources]
    for source in sources:
        source['can_manage'] = window_admin.allowed(state, actor, source['executor_id'])
        source['can_manage_projects'] = rules.system_admin(state, actor)
    if r.route == "window-cards":
        joined = upgrade.projects(state, actor)
        for source in sources:
            name = source["executor_id"]
            source.update(auto=execution_settings(state, name)["auto"], capabilities=service.capability_rows(state, actor, name)[1],
                          memberships=[{"name": p["name"], "roles": sorted(rules.grant(state, p["id"], name)["roles"])}
                                       for p in joined if rules.grant(state, p["id"], name)["roles"]])
    return {"executors": sources}


def identity(r, argument):
    state, actor = r.state, r.actor
    data = state.get('security', {}).get('execution', {})
    return {"identity": actor, "binding": rules.identity(state, actor), "projects": upgrade.projects(state, actor),
            'default_context': data.get('defaults', {}).get(actor),
            'active_task_contexts': [{'segment_id': key, **{k: row.get(k) for k in ('task_id', 'claim_id', 'context_id', 'context_version')}}
                for key, row in data.get('segments', {}).items() if row.get('executor_id') == actor and
                state['claims'].get(row.get('claim_id'), {}).get('L') == 'active']}


def delegations(r, argument):
    return {"delegations": delegation.view(r.state, r.actor)}


def capabilities(r, argument):
    name = argument or r.actor
    permitted, capabilities = r.service.capability_rows(r.state, r.actor, name)
    if not permitted:
        raise ClientError("无权查看能力证据", 403)
    return {"identity": name, "capabilities": capabilities}


def audit(r, argument):
    return {"head": r.snap["head"], "events": upgrade.audit_rows(r.service, r.snap, r.actor, argument)}


def receipt(r, argument):
    service, actor = r.service, r.actor
    if not isinstance(argument, str) or not ID.fullmatch(argument):
        raise ClientError("请求编号无效")
    key = digest(encoded([actor, argument]))
    row = service.db.execute("SELECT status,response FROM requests WHERE key=?", (key,)).fetchone()
    if not row:
        raise ClientError("没有该身份的请求记录", 404)
    access = service.receipt_authorization(actor, key, r.state)
    response = json.loads(row[1]) if row[1] else {"status": "pending", "request_id": argument}
    return service.cleanup_receipt(response) if access == "cleanup" else response


def upgrade_status(r, argument):
    state = r.state
    fmt = state["pilot"].get("format")
    return {"format": fmt, "release": state["pilot"].get("release:" + fmt["upgrade"]) if fmt else None,
            "roles": sorted(rules.roles(state, rules.PROJECT, r.actor)), "head": r.snap["head"]}


def receivers(r, argument):
    state = r.state
    if argument:
        return sorted(name for name in state["origins"] if "receiver" in rules.roles(state, argument, name))
    return sorted(name for name, origin in state["origins"].items() if "receiver" in origin["roles"])


def account_table(r, argument):
    service, state, actor = r.service, r.state, r.actor
    if not service.is_admin(actor):
        raise ClientError("仅管理员可查看账号", 403)
    joined = upgrade.projects(state, actor)
    rows, seen = [], set()
    for key, subject in state["pilot"].items():
        if not key.startswith("identity:"):
            continue
        name = key.removeprefix("identity:")
        seen.add(name)
        if subject["kind"] not in {"human", "executor"}:
            continue
        rows.append({"name": name, "kind": subject["kind"], "status": subject["status"], "owner": subject.get("owner"),
                     "credential": subject.get("credential"),
                     "platform": subject.get("platform"), "window": subject.get("window"), "admin": rules.system_admin(state, name),
                     "window_name": subject.get("window_name"),
                     "projects": [{"name": p["name"], "roles": sorted(rules.grant(state, p["id"], name)["roles"])}
                                  for p in joined if rules.grant(state, p["id"], name)["roles"]]})
    rows.sort(key=lambda row: (row["kind"] != "human", row["name"]))
    return rows + [{"name": name, "kind": None, "status": None, "owner": None, "platform": None, "window": None, "admin": False, "projects": []}
                   for name, _ in service.accounts.list() if name not in seen]


def accounts(r, argument):
    service = r.service
    if not service.is_admin(r.actor):
        raise ClientError("仅管理员可查看账号", 403)
    roster = {name: role for name, role in service.accounts.list()}
    for name, origin in r.state["origins"].items():
        role = origin["roles"][0]
        if role in {"receiver", "executor"}:
            roster.setdefault(name, role)
    return sorted(roster.items())


def detail(r, argument):
    if argument not in r.tasks:
        raise ClientError("任务不存在", 404)
    return r.service.detail(r.state, r.tasks[argument], r.actor)


def task(r, argument):
    if argument not in r.tasks:
        raise ClientError("任务不存在", 404)
    return r.service.task_view(r.state, r.tasks[argument], r.actor)


def board(r, argument):
    state, snap = r.state, r.snap
    if r.upgraded:
        lines = ["# 内网任务看板", "", f"账本序号 {snap['head']}", ""]
        for task in r.visible_tasks:
            project = rules.project_record(state, rules.task_project(task))
            name = project["name"] if project else "原有任务"
            current = active_claim(state, task)
            subject = (rules.identity(state, current["origin"]) or {}) if current else {}
            window = subject.get("window_name") or subject.get("window")
            if subject.get("window_name") and subject.get("window"):
                window += " · " + subject["window"]
            lines.append(f"- {task['task_id']} {task['title']} · {name} · {stage(task, current, state)}"
                         + (f" · {window}" if window else ""))
        return ("\n".join(lines) + "\n").encode("utf-8")
    return render(r.service.desk, snap)


def stash_artifact(r, argument):
    state = r.state
    if not execution.stash_reference_allowed(state, r.actor, argument):
        return DECLINED
    row = next(row for row in state['security']['execution']['stashes'].values()
             if row.get('bundle', {}).get('path') == argument)
    return r.service.checked_file(row['bundle'])


def stored_file(r, argument):
    """A file the actor may read through one of its visible tasks; every unanswered read ends here."""
    service, state, actor = r.service, r.state, r.actor
    for task in r.visible_tasks:
        view = service.task_view(state, task, actor)
        refs = [{"path": p, "sha256": sha} for p, sha in task["inputs"].items()] + view["handoffs"]
        close = state["closings"].get(task.get("close_id"))
        if close and (view["claims"] or actor == task["receiver"]):
            refs.append(close["summary"])
        for claim in view["claims"]:
            refs += [{'path': p, 'sha256': sha} for p, sha in claim.get('inputs', {}).items()]
            for delivery in claim["deliveries"].values():
                ref = delivery["manifest"]
                if argument == ref["path"]:
                    refs.append(ref)
                elif argument.startswith(ref["path"].rsplit("/", 1)[0] + "/"):
                    refs += service.delivery_refs(ref)
        for ref in refs:
            if argument == ref["path"]:
                return service.checked_file(ref)
    raise ClientError("文件不存在或当前身份无权读取", 404)


ROUTES = {
    "features": features, "execution": execution_view, "window-impact": window_impact,
    "capability-requests": capability_requests, "cleanup": cleanup, "invitations": invitations, "runner": runner,
    "notices": notices, "collaboration": collaboration, "sheet": sheet, "tasks": tasks, "task-options": task_options,
    "overview": overview, "activity": activity, "project-cards": project_cards, "project": project,
    "projects": projects, "input-package": input_package, "invitation-owners": invitation_owners,
    "release-readiness": release_readiness, "project-capabilities": project_capabilities, "executors": executors,
    "window-cards": executors, "identity": identity, "delegations": delegations, "capabilities": capabilities,
    "audit": audit, "receipt": receipt, "upgrade": upgrade_status, "receivers": receivers,
    "account-table": account_table, "accounts": accounts, "detail": detail, "task": task, "board": board,
    "artifact": stash_artifact,
}
ROUND_ONLY = {"invitations", "runner", "notices", "collaboration"}


def read(service, snap, actor, route, argument=None):
    r = Reading(service, snap, actor, route, argument)
    handler = ROUTES.get(route)
    if handler is not None and (r.round_enabled or route not in ROUND_ONLY):
        result = handler(r, r.argument)
        if result is not DECLINED:
            return result
    return stored_file(r, r.argument)
