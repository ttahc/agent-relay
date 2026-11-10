"""Read-only projections of a task and its claims from one ledger state."""

from .packages import SHA
import 协作升级 as rules


def security_schema(state, default=0):
    """Version of the security data contract recorded in the state."""
    return state.get("security", {}).get("schema", default)


def handoff_reference(claim):
    path = claim.get("replacement", "")
    name = path.rsplit("/", 1)[-1]
    if path.startswith("handoffs/" + claim["claim_id"] + "/") and name.endswith(".json") and SHA.fullmatch(name[:-5]):
        return {"path": path, "sha256": name[:-5]}
    return None


def active_claim(state, task):
    return next((state["claims"][cid] for cid in reversed(task["claims"])
                 if state["claims"][cid]["L"] == "active"), None)


def execution_status(state, claim):
    if not state or not claim or security_schema(state) < 5:
        return None
    data = state['security'].get('execution', {})
    all_rows = [row for row in data.get('actions', {}).values() if row.get('claim_id') == claim['claim_id']]
    rows = [row for row in all_rows if row.get('epoch') == claim['epoch'] and row.get('scope_version') == claim['W']['scope']]
    historical = [row for row in all_rows if row not in rows]
    if not all_rows and claim['claim_id'] not in data.get('claim_bindings', {}):
        return None
    unknown = sum(row.get('state') == 'unconfirmed' or row.get('state') in {'finished', 'error', 'stopped'} and
                data.get('grants', {}).get(row.get('grant_id'), {}).get('physical') in {'in-use', 'unknown'} for row in rows)
    return {'actions': len(rows), 'running': sum(row['state'] == 'running' for row in rows),
            'awaiting_start': sum(row['state'] == 'start-authorized' for row in rows),
            'unconfirmed': unknown, 'finished': sum(row['state'] in {'finished', 'error', 'stopped', 'not-started'} for row in rows),
            'historical_live': sum(row['state'] in {'running', 'start-authorized', 'unconfirmed'} for row in historical),
            'historical_unconfirmed': sum(row['state'] == 'unconfirmed' or data.get('grants', {}).get(row.get('grant_id'), {}).get('physical') in {'in-use', 'unknown'} for row in historical)}


def stage(task, claim, state=None):
    if claim and claim.get("recovery", {}).get("status") == "pending":
        return "recovery"
    if task["status"] == "running" and claim:
        if task.get("cancel_requested"):
            return "cancel_pending"
        if claim["E"].get("reason") == "replace":
            return "handoff_pending"
        if claim["E"].get("reason") == "pause" and claim["W"]["state"] in {"draft", "revision"}:
            return "paused"
        current = execution_status(state, claim)
        if current is not None and claim['W']['state'] not in {'review', 'revision', 'complete'}:
            if current['unconfirmed']:
                return 'recovery'
            if current['running'] or current['finished']:
                return 'running'
            return 'claimed'
        return {"review": "review", "revision": "revision", "complete": "accepted"}.get(
            claim["W"]["state"], "claimed" if claim.get("run", {}).get("state") == "claimed" else "running")
    if task["status"] == "available" and (spec := rules.contract(task)):
        gate = spec.get("gate")
        if not spec["open"] or state is not None and gate and state["pilot"].get("release:" + gate, {}).get("status") != "closed":
            return "waiting"
    return task["status"]
