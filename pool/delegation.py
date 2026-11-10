"""Explicit human-to-window delegation scoped to one operation at a time."""
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
import time

from .packages import ClientError, fields, string
from .constants import COORDINATOR, step
from 协作本轮 import (DELEGATION_ACTIONS, DELEGATION_EXECUTION, DELEGATION_MANAGEMENT,
                  DELEGATION_MAX_SECONDS, DELEGATION_PRESETS, delegable, delegation_action,
                  delegation_id, usable_delegation)
import 协作升级 as rules


ACTIONS = {"delegate-grant", "delegate-revoke"}
_CURRENT = ContextVar("taskpool_delegation", default=None)
AUDIT_KEYS = {"delegator", "delegation_id", "delegation_version"}
ACTION_LABELS = {"read": "读取", "claim": "领取任务", "deliver": "上传交付包", "deliver-files": "上传交付文件",
                 "stop": "登记实际停止", "handoff": "交接", "run-report": "执行回报", "resume": "继续执行或返修", "feedback-save": "提交反馈",
                 "capability-save": "申报自身技能",
                 "register": "创建任务", "task-publish": "开放任务", "task-hold": "暂缓任务", "feedback-update": "处理反馈"}
COMMANDS = {"claim": {"claim"}, "deliver": {"seal"}, "deliver-files": {"seal", "stopped"},
            "stop": {"stopped"}, "handoff": {"replace_claim", "stopped", "release"}, "register": {"propose", "register"},
            "resume": {"acquire", "resume", "ack_scope"}}
PILOT_OPS = {"task-publish": "publish", "task-hold": "hold", "feedback-save": "feedback-save",
             "feedback-update": "feedback-update", "run-report": "run-report", "capability-save": "capability"}


def target(state, operation, body):
    """Resolve a real target; a feedback's task association cannot be supplied as a scope override."""
    task_id = body.get("task_id")
    claim_id = body.get("claim_id")
    claim = state.get("claims", {}).get(claim_id) if isinstance(claim_id, str) else None
    if claim:
        task_id = claim["task_id"]
    spec = body.get("contract")
    project = body.get("project_id") or (spec.get("project_id") if isinstance(spec, dict) else None)
    if not isinstance(project, str):
        project = None
    if operation == "capability-resolve":
        verification = state.get("round", {}).get("verification:" + str(body.get("verification_id") or body.get("id"))) or {}
        project = verification.get("project_id")
    if operation == "feedback-update":
        record = state.get("round", {}).get("feedback:" + str(body.get("id"))) or {}
        project = record.get("project_id") or project
        linked = {value for value in (record.get("task_id"), record.get("linked_task"))
                  if isinstance(value, str) and value}
        # A new association cannot create authority over unrelated feedback.
        proposed = body.get("linked_task")
        task_id = next(iter(linked)) if len(linked) == 1 and (not proposed or proposed in linked) else None
    task = state.get("tasks", {}).get(task_id) if isinstance(task_id, str) else None
    return task_id if task else None, rules.task_project(task) or project


def records(state, actor):
    subject = rules.identity(state, actor) or {}
    return [record for key, record in state.get("round", {}).items() if key.startswith("delegation:") and
            (record["delegator"] == actor and subject.get("kind") == "human" or record["executor_id"] == actor)]


def _find(state, actor, operation, project, task_id, now):
    candidates = [record for record in records(state, actor)
                  if usable_delegation(state, record, actor, operation, project, task_id, now)]
    return min(candidates, key=lambda row: row["id"]) if candidates else None


@contextmanager
def operation_context(state, actor, operation, project_id=None, task_id=None, now=None, audit=None):
    """Planning selects a current grant; replay only accepts the originally recorded grant."""
    when = time.time() if now is None else now
    if task_id and not project_id:
        project_id = rules.task_project(state.get("tasks", {}).get(task_id))
    record = None
    if audit is not None:
        if audit.get("delegation_id"):
            record = state.get("round", {}).get("delegation:" + str(audit["delegation_id"]))
            rules.require(record and record["version"] == audit.get("delegation_version") and
                          record["delegator"] == audit.get("delegator") and
                          usable_delegation(state, record, actor, operation, project_id, task_id, when),
                          "委托已过期、撤销、变更或超出人员当前权限与任务范围", "intent-final")
        else:
            rules.require(not any(audit.get(key) for key in AUDIT_KEYS), "委托审计信息不完整", "intent-final")
    else:
        record = _find(state, actor, operation, project_id, task_id, when)
    value = {"actor": actor, "operation": operation, "project_id": project_id, "task_id": task_id,
             "now": when, "record_id": record["id"] if record else None,
             "version": record["version"] if record else None}
    token = _CURRENT.set(value)
    try:
        yield stamp(state, actor, project_id)
    finally:
        _CURRENT.reset(token)


def _current_record(state, actor, project):
    context = _CURRENT.get()
    if not context or context["actor"] != actor or context["project_id"] != project or not context["record_id"]:
        return None
    record = state.get("round", {}).get("delegation:" + context["record_id"])
    if not record or record["version"] != context["version"] or not usable_delegation(
            state, record, actor, context["operation"], project, context["task_id"], context["now"]):
        return None
    return record


def stamp(state, actor, project):
    record = _current_record(state, actor, project)
    return {"delegator": record["delegator"], "delegation_id": record["id"],
            "delegation_version": record["version"]} if record else {}


def effective_roles(state, project, actor, base_roles):
    """Called by rules.roles; read grants never become project-wide management roles."""
    record = _current_record(state, actor, project)
    if not record:
        return set(base_roles)
    operation = _CURRENT.get()["operation"]
    extra = {"manager"} if operation in DELEGATION_MANAGEMENT else (
        {"executor"} if operation in DELEGATION_EXECUTION or operation == "capability-save" else {"reporter"} if operation == "feedback-save" else {"observer"})
    return set(base_roles) | extra


def enforce_capability_self(actor, body):
    record = body.get("record") or body
    rules.require(isinstance(record, dict) and body.get("name") == actor and record.get("kind") == "skill" and record.get("level") == "declared",
                  "受托能力申报仅限 AI 自身的已声明技能", "intent-final")


def enforce_audit(state, env, now):
    """Recheck persisted request metadata against the actual envelope before a ledger decision."""
    p = env["payload"]
    audit = p.get("_audit") or {}
    if not audit.get("delegation_id"):
        rules.require(not any(audit.get(key) for key in AUDIT_KEYS), "委托审计信息不完整", "intent-final")
        return
    actor, operation, command = audit.get("actor"), audit.get("operation"), env["command"]
    valid_command = (command == "pilot" and PILOT_OPS.get(operation) == p.get("op") or
                     command in COMMANDS.get(operation, set()))
    rules.require(valid_command, "委托操作与实际账本命令不符", "intent-final")
    if operation == "capability-save":
        enforce_capability_self(actor, p)
    task_id, project = target(state, operation, p)
    if command == "propose" and operation == "register":
        project = audit.get("project_id")
    rules.require(not audit.get("project_id") or audit["project_id"] == project,
                  "委托审计项目与实际操作不符", "intent-final")
    rules.require(not audit.get("task_id") or audit["task_id"] == task_id,
                  "委托审计任务与实际操作不符", "intent-final")
    with operation_context(state, actor, operation, project, task_id, now, audit):
        rules.require(bool(stamp(state, actor, project)), "未找到有效人员委托", "intent-final")


def plan(service, actor, action, key, body, state):
    if action not in ACTIONS:
        return None
    from .upgrade import identifier, version
    if state["pilot"].get("format", {}).get("schema") not in {3, 4, 5}:
        raise ClientError("须先迁移人员与 AI 委托数据合同", 409)
    subject = rules.identity(state, actor) or {}
    if subject.get("kind") != "human" or not rules.active(state, actor):
        raise ClientError("委托须由人员本人办理", 403)
    if action == "delegate-grant":
        duration = "duration_seconds" in body
        fields(body, "request_id executor_id project_id actions task_ids version reason " + ("duration_seconds" if duration else "expires"))
        executor = identifier(body["executor_id"], "AI 窗口")
        project = identifier(body["project_id"], "项目")
        if duration:
            seconds = body["duration_seconds"]
            if type(seconds) is not int or not 1 <= seconds <= DELEGATION_MAX_SECONDS:
                raise ClientError("委托有效时长须为 1 秒至 30 天")
            expires = int(time.time()) + seconds
        else:
            expires = body["expires"]
        p = {"op": action, "executor_id": executor, "project_id": project,
             "delegation_id": delegation_id(actor, executor, project), "actions": body["actions"],
             "task_ids": body["task_ids"], "expires": expires, "version": version(body["version"]),
             "reason": string(body["reason"], "授权依据")}
    else:
        fields(body, "request_id delegation_id version reason")
        p = {"op": action, "delegation_id": identifier(body["delegation_id"], "委托编号"),
             "version": version(body["version"]), "reason": string(body["reason"], "撤销依据")}
    candidate = {**state, "round": deepcopy(state["round"])}
    delegation_action(candidate, p, actor, time.time(), "transport-validation")
    return {"round_result": {"delegation_id": p["delegation_id"]},
            "steps": [step(COORDINATOR, "pilot", p, {"generation": state["generation"]})]}


def view(state, actor, now=None):
    when = time.time() if now is None else now
    result = []
    for record in records(state, actor):
        status = "revoked" if record["revoked"] else "expired" if record["expires"] <= when else "active"
        if status == "active" and not all(delegable(state, record["delegator"], record["project_id"], action) for action in record["actions"]):
            status = "restricted"
        subject = rules.identity(state, record["executor_id"]) or {}
        if status == "active" and (not rules.active(state, record["executor_id"]) or subject.get("owner") != record["delegator"]):
            status = "restricted"
        result.append({**record, "status": status, "window": subject.get("window"), "window_name": subject.get("window_name")})
    return sorted(result, key=lambda row: (row["executor_id"], row["project_id"]))
