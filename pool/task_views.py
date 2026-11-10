"""Per-actor views of tasks, deliveries and capability records built from one ledger state.

Every function takes the Service first and reaches its other views and permission
checks through that object, so a caller that replaces one on the instance is honoured.
"""

from copy import deepcopy
import json
import time

from . import round_service, upgrade
from .packages import ClientError
from .task_state import active_claim, execution_status, security_schema, stage
from 协作取证 import manifest
from 协作存储 import Rejected
from 协作本轮 import policy, target_match
import 协作升级 as rules


def delivery_refs(service, ref):
    _, data = manifest(service.desk, ref)
    parent = ref["path"].rsplit("/", 1)[0]
    return [{"path": parent + "/" + item["path"], "sha256": item["sha256"].lower()} for item in data["outputs"]]


def delivery_reviews(service, state, task, claims, entries=None):
    """Project exact sealed-revision acceptance facts without changing stored records."""
    result = []
    for claim in claims:
        for name, delivery in claim.get("deliveries", {}).items():
            acceptance_id = delivery.get("acceptance_id")
            review = state.get("acceptances", {}).get(acceptance_id)
            if (not review or review.get("acceptance_id") != acceptance_id or review.get("task_id") != task["task_id"] or
                    review.get("claim_id") != claim["claim_id"] or review.get("revision") != name or
                    delivery.get("revision", name) != name or review.get("manifest_sha256") != delivery.get("manifest_sha256") or
                    review.get("scope_version") != delivery.get("scope_version") or
                    review.get("manifest") is not None and review["manifest"] != delivery.get("manifest")):
                continue
            if entries is None:
                entries = service.snapshot().get("entries", [])
            event = next((entry for entry in entries if entry.get("type") == "decision" and entry.get("result") == "applied" and
                          entry.get("command") == "review" and entry.get("key") == str(review.get("origin")) + "/" + str(acceptance_id) and
                          entry.get("origin_id") == review.get("origin") and
                          (review.get("seq") is None or entry.get("ledger_seq") == review["seq"]) and
                          any(effect.get("path") == ["acceptances", acceptance_id] and effect.get("value") == review
                              for effect in entry.get("effects", []))), None)
            failed = [check["id"] for check in review.get("checks", []) if check.get("status") in {"failed", "not-run"}]
            notes = list(dict.fromkeys(check.get("evidence", {}).get("note") for check in review.get("checks", [])
                                       if check.get("id") in failed and isinstance(check.get("evidence"), dict) and
                                       isinstance(check["evidence"].get("note"), str) and check["evidence"]["note"]))
            request = (event or {}).get("request", {})
            reason = request.get("reason") if isinstance(request.get("reason"), str) and request["reason"] else "\n".join(notes)
            metadata = {"acceptance_id": acceptance_id, "failed_criteria": failed, "reason": reason,
                        "reviewer": request.get("actor") or review.get("origin"),
                        "at": (event or {}).get("committed_utc"), "source_event": (event or {}).get("key")}
            result.append({"claim_id": claim["claim_id"], "revision": name, "manifest": deepcopy(delivery.get("manifest")),
                           "manifest_sha256": delivery.get("manifest_sha256"), **metadata,
                           "review": {**deepcopy(review), **metadata}})
    return result


def task_view(service, state, task, actor):
    if not service.visible(state, task, actor):
        raise ClientError("任务不存在或无权查看", 404)
    claims = [state["claims"][cid] for cid in task["claims"]]
    admin = service.is_admin(actor) or round_service.enabled(state) and rules.manager(state, rules.task_project(task), actor)
    permitted = [c for c in claims if admin or actor in {c["origin"], task["receiver"]}]
    spec = rules.contract(task)
    project = rules.project_record(state, spec["project_id"]) if spec else None
    return {"task": {**task, "project_name": project["name"]} if project else task,
            "stage": stage(task, active_claim(state, task), state),
            'execution_status': execution_status(state, active_claim(state, task)),
            "claims": deepcopy(permitted),
            'execution_protocol': 5 if security_schema(state) == 5 else None,
            'default_context': state.get('security', {}).get('execution', {}).get('defaults', {}).get(actor),
            'execution_contexts': [deepcopy(row) for row in state.get('security', {}).get('execution', {}).get('contexts', {}).values()
                                  if row.get('executor_id') == actor],
            "delivery_reviews": service._delivery_reviews(state, task, [c for c in permitted if
                actor in {c["origin"], task["receiver"]} or service.is_admin(actor) or rules.system_admin(state, actor)]),
            "handoffs": service.handoffs(state, task) if any(c["origin"] == actor and c["L"] == "active"
                                                      for c in claims) or actor == task["receiver"] or admin else [],
            "qualification": service.qualification(state, task, actor)}


def qualification(service, state, task, actor):
    if not rules.enabled(state):
        return None
    missing, preferred = rules.eligible(state, task, actor, time.time())
    gate = (rules.contract(task) or {}).get("gate")
    if state["pilot"]["format"]["maintenance"]:
        missing.append("服务维护中")
    if gate:
        release = state["pilot"].get("release:" + gate, {})
        if release.get("status") == "closed":
            try:
                rules.verify_report(state, json.loads(service.checked_file(release["evidence"])), gate)
            except (KeyError, ValueError, OSError, Rejected):
                missing.append("升级收口证据待复核")
    result = {"eligible": not missing, "missing": missing, "preferred": preferred}
    if round_service.enabled(state):
        mode = policy(task)["mode"]
        result.update(mode=mode, prioritized=mode == "prefer" and target_match(state, task, actor, time.time()))
    return result


def detail(service, state, task, actor):
    view = service.task_view(state, task, actor)
    current = active_claim(state, task)
    participant = view["claims"] or actor == task["receiver"] or service.is_admin(actor)
    deliveries = []
    for claim in view["claims"]:
        for revision in claim["deliveries"].values():
            ref = revision["manifest"]
            try:
                outputs = service.delivery_refs(ref)
            except (OSError, ValueError, KeyError, TypeError):
                outputs = []
            review = state["acceptances"].get(revision.get("acceptance_id"))
            deliveries.append({"claim_id": claim["claim_id"], "revision": revision, "outputs": outputs,
                               "review": review})
    return {**view, "active": current if current in view["claims"] else None,
            "roles": service.task_roles(state, task, actor) if rules.contract(task) else service.roles(state, actor),
            "direct_roles": service.independent_roles(state, task, actor) if rules.contract(task) else service.roles(state, actor),
            "delegated_actions": service.delegated_actions(state, task, actor),
            "deliveries": deliveries,
            "window": (rules.identity(state, current["origin"]) or {}).get("window") if current else None,
            "window_name": (rules.identity(state, current["origin"]) or {}).get("window_name") if current else None,
            "window_id": current["origin"] if current else None,
            "round": round_service.enabled(state),
            "items": [item for item in state["items"].values()
                      if participant and item["source_task"] == task["task_id"]],
            "close": state["closings"].get(task.get("close_id")) if participant else None,
            "cancel_note": next((note for note in state["notes"].values() if participant and
                                 note["related"] == {"task_id": task["task_id"], "kind": "cancel"}), None)}


def members(service, state, project):
    return [{"identity": key.rsplit(":", 1)[1], **record,
             "kind": (rules.identity(state, key.rsplit(":", 1)[1]) or {}).get("kind"),
             "window_name": (rules.identity(state, key.rsplit(":", 1)[1]) or {}).get("window_name"),
             "window": (rules.identity(state, key.rsplit(":", 1)[1]) or {}).get("window")}
            for key, record in state["pilot"].items() if key.startswith(f"grant:{project}:")]


def capability_rows(service, state, actor, name):
    """Return whether the actor may look at a subject's capability records, and the records it may see."""
    owner = rules.responsible(state, name)
    allowed_projects = {p["id"] for p in upgrade.projects(state, actor)
                        if {"manager", "receiver"} & set(p["roles"]) and rules.grant(state, p["id"], name)["roles"]}
    permitted = actor in {name, owner} or service.is_admin(actor)
    rows = []
    for key, record in state["pilot"].items():
        if key.startswith("cap:"):
            _, project, subject, cap_id = key.split(":")
            if subject == name and (permitted or project in allowed_projects):
                rows.append({"id": cap_id, "project_id": project, **record})
    return permitted or bool(allowed_projects), rows


def feedback_due(service, state, actor, project=None):
    return sum(1 for key, record in state["round"].items()
               if key.partition(":")[0] == "feedback" and record["status"] in {"triage", "review"}
               and (not project or record["project_id"] == project)
               and rules.manager(state, record["project_id"], actor))


def task_summary(task):
    result = {k: task[k] for k in ('task_id', 'title', 'status', 'stage', 'version', 'scope_version', 'priority',
                'project_name', 'qualification', 'holder', 'holder_window', 'holder_window_name', 'receiver') if k in task}
    result['project_id'] = rules.task_project(task)
    return result
