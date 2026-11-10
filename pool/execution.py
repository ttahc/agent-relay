"""Typed HTTP plans and authorized projections for the security-5 execution protocol."""
import base64
import binascii
from copy import deepcopy
from io import BytesIO
from pathlib import Path
import time
import zipfile

from .packages import ClientError, MAX_EXPANDED, MAX_FILES, MAX_PACKAGE, artifact_name, fields, string
from .constants import COORDINATOR, step
from .task_state import security_schema
from .upgrade import identifier, version
from . import delegation
import 协作执行 as engine
import 协作升级 as rules
from 协作存储 import digest


ACTIONS = engine.OPS
READS = {"features", "execution"}
FIELDS = {
    "context-save": "context_id version config make_default",
    "segment-open": "task_id claim_id scope_version epoch context_id context_version",
    "action-prepare": "segment_id version description resources adapter_id",
    "resource-request": "action_id version resources",
    "resource-cancel": "resource_request_id version",
    "action-start": "action_id version grant_id generation",
    "execution-fact": "task_id claim_id scope_version epoch action_id kind evidence permit_id reporter_basis",
    "evidence-stash": "task_id claim_id scope_version epoch action_id files reporter_basis",
    "resource-release": "action_id grant_id generation version evidence basis",
}
PREFIXES = {"context-save": "ctx-", "segment-open": "seg-", "action-prepare": "act-", "resource-request": "rq-",
            "execution-fact": "fact-", "evidence-stash": "stash-"}
IDENTIFIERS = ("task_id", "claim_id", "context_id", "segment_id", "action_id", "resource_request_id",
               "grant_id", "permit_id")


def _row(state, table, key):
    """A stored execution record, or {} when the key is absent or is not text."""
    rows = state.get("security", {}).get("execution", {}).get(table, {})
    return rows.get(key) or {} if isinstance(key, str) else {}


def _binding(state, action, p):
    """The record a request is bound to. Also used for rejected requests, so any body shape is accepted."""
    if action == "action-prepare":
        return _row(state, "segments", p.get("segment_id"))
    if action == "resource-cancel":
        return _row(state, "actions", _row(state, "resource_requests", p.get("resource_request_id")).get("action_id"))
    if isinstance(p.get("action_id"), str) and p["action_id"]:
        return state.get("security", {}).get("execution", {}).get("actions", {}).get(p["action_id"], p)
    return p


def _stash(p):
    values = p["files"]
    if not isinstance(values, list) or not 0 < len(values) <= MAX_FILES:
        raise ClientError("暂存文件数量须在原交付预算内")
    files, names, size = [], set(), 0
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for item in values:
            fields(item, "name sha256 content_base64")
            name = artifact_name(item["name"])
            if name.casefold() in names:
                raise ClientError("暂存文件名称重复或大小写冲突")
            names.add(name.casefold())
            try:
                raw = base64.b64decode(item["content_base64"], validate=True)
            except (ValueError, TypeError, binascii.Error) as error:
                raise ClientError("暂存文件编码无效") from error
            if digest(raw) != item["sha256"]:
                raise ClientError("暂存文件摘要不匹配，保留原文件后重试")
            size += len(raw)
            if size > MAX_EXPANDED:
                raise ClientError("暂存展开内容超出原交付24MiB预算", 413)
            entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, raw)
            files.append({"name": name, "sha256": item["sha256"], "bytes": len(raw)})
    raw = stream.getvalue()
    if len(raw) > MAX_PACKAGE:
        raise ClientError("暂存包超出原交付8MiB预算，请拆分提交", 413)
    sha = digest(raw)
    path = "evidence-stash/" + identifier(p["claim_id"], "原领取") + "/" + sha + "/stash.zip"
    p["files"], p["bundle"] = files, {"path": path, "sha256": sha, "bytes": len(raw)}
    return [path, base64.b64encode(raw).decode("ascii")]


def _proofs(service, resources):
    """Resolve only explicitly configured server-local roots; all other domains stay conservative."""
    roots = getattr(service, "execution_roots", {})
    proofs = {}
    for row in resources:
        if not row["id"].startswith("path:") or row["domain"] not in roots:
            continue
        root = Path(roots[row["domain"]]).resolve(strict=True)
        logical = row["id"][5:]
        target = root.joinpath(*logical.split("/"))
        for current in (target, *target.parents):
            if current == root.parent:
                break
            if current.is_symlink() or getattr(current, "is_junction", lambda: False)():
                raise ClientError("资源路径包含链接或重解析点，请改用隔离副本")
        target.resolve().relative_to(root)
        ancestor = target
        while not ancestor.exists():
            ancestor = ancestor.parent
        info = ancestor.stat()
        suffix = target.relative_to(ancestor).as_posix()
        identity = f"{info.st_dev}:{info.st_ino}" + ("/" + suffix if suffix != "." else "")
        proofs[row["domain"] + "|" + row["id"]] = {"identity": identity, "resolved": True,
            "canonical_path": target.resolve().as_posix().casefold(), "filesystem": str(info.st_dev)}
    return proofs


def plan(service, actor, action, key, body, state):
    if action not in ACTIONS:
        return None
    extra = " supersedes_request_id" if "supersedes_request_id" in body else ""
    if action == "execution-fact" and "blocker_ids" in body:
        extra += " blocker_ids"
    fields(body, "request_id " + FIELDS[action] + extra)
    if any(body.get(name) and not isinstance(body[name], str) for name in IDENTIFIERS) or not (
            isinstance(body.get("blocker_ids", []), list)
            and all(isinstance(key, str) for key in body.get("blocker_ids", []))):
        raise ClientError("编号字段须为文本")
    p = {name: deepcopy(value) for name, value in body.items() if name != "request_id"}
    p["op"] = action
    if "supersedes_request_id" in p:
        identifier(p["supersedes_request_id"], "被修正请求")
    if action in PREFIXES:
        p["id"] = PREFIXES[action] + key[:32]
    if action == "action-start":
        p["permit_id"] = "permit-" + key[:40]
    if action == "context-save":
        p["context_id"] = identifier(p["context_id"], "配置") if p["context_id"] else p["id"]
    for name in ("version", "scope_version", "epoch", "context_version", "generation"):
        if name in p:
            p[name] = version(p[name])
    binding = _binding(state, action, p)
    if action not in engine.FACT_OPS | {"context-save", "resource-release", "resource-cancel"}:
        task = state.get("tasks", {}).get(binding.get("task_id"))
        if task:
            project = rules.task_project(task)
            authorization_operation = binding.get("authorization_operation", "claim")
            if action == "segment-open":
                authorization_operation = "claim"
            if authorization_operation not in {"claim", "resume"}:
                raise ClientError("原执行段的授权操作类别无效", 409)
            with delegation.operation_context(state, actor, authorization_operation, project, task["task_id"]) as audit:
                p["authority"] = {**audit, "authorization": rules.auth_stamp(state, actor, project),
                                  "delegated_operation": authorization_operation}
    file = _stash(p) if action == "evidence-stash" else None
    if action == "action-prepare":
        p["resource_proofs"] = _proofs(service, engine.normalize_resources(state, p["resources"]))
    elif action == "action-start":
        previous = _binding(state, action, p)
        current = _proofs(service, previous.get("resources", []))
        if previous.get("resource_proofs", {}) != current:
            raise ClientError("资源文件身份或父目录已变化，请重新建立动作并核对", 409)
    now = time.time()
    audit = {"actor": actor, "credential_version": (rules.identity(state, actor) or {}).get("credential")}
    candidate = {**state, "security": deepcopy(state.get("security", {}))}
    phase = service.lifecycle.status()["phase"] if hasattr(service, "lifecycle") else "running"
    engine.action(candidate, {"payload": {**p, "_audit": audit}, "event_id": "validation-" + key[:24]},
                  {"now": now, "phase": phase})
    operation = step(COORDINATOR, "pilot", p, {"generation": state["generation"]})
    if file:
        operation["file"] = file
    data = candidate["security"]["execution"]
    result = {"execution_protocol": 5, "operation": action}

    def public_record(record):
        # Stable deterministic result fields only; actual ledger event/time come from GET execution.
        return _public({name: value for name, value in record.items() if name not in {"event", "at"}})
    table = {"context-save": "contexts", "segment-open": "segments", "action-prepare": "actions",
             "resource-request": "resource_requests",
             "resource-cancel": "resource_requests", "execution-fact": "facts", "evidence-stash": "stashes"}.get(action)
    if table == "contexts":
        result["context"] = public_record(data[table][p["context_id"] + ":" + str(p["version"] + 1)])
    elif table:
        record = data[table].get(p.get("id") or p.get("resource_request_id"))
        if record is None and action == "resource-request":
            record = next((row for row in data[table].values()
                           if row["action_id"] == p["action_id"] and row["state"] in {"queued", "granted"}), None)
        if record:
            result[{"resource_requests": "resource_request", "segments": "segment", "actions": "action",
                    "facts": "fact", "stashes": "stash"}[table]] = public_record(record)
    if p.get("action_id") in data["actions"]:
        target = data["actions"][p["action_id"]]
        result["action"] = public_record(target)
        if target.get("grant_id"):
            result["grant"] = public_record(data["grants"][target["grant_id"]])
    return {"round_result": result, "steps": [operation]}


def features(state):
    schema = security_schema(state, 3)
    ready = state.get("security", {}).get("phase", "ready") == "ready"
    operations = ACTIONS if schema == 5 and ready else engine.FACT_OPS if schema == 4 and ready else []
    return {"api_protocol": 1, "security_schema": schema, "execution_protocol": 5 if schema == 5 and ready else None,
            "features": {op: op in operations for op in ACTIONS},
            "input_download": {"json_bytes": 8388608, "zip_bytes": 150994944, "total_bytes": 134217728,
                               "file_bytes": 67108864, "files": 500, "manifest_bytes": 1048576},
            "operations": sorted(ACTIONS if schema == 5 and ready
                                 else engine.FACT_OPS if schema == 4 and ready else []),
            "adapters": ["manual", "local-files", "isolated-worktree"], "automatic_release": False,
            "automatic_end_confirmation": False,
            "trusted_adapter_ids": sorted(state.get("security", {}).get("execution", {}).get("adapters", {})),
            "budgets": {"evidence_stash_package": MAX_PACKAGE, "evidence_stash_expanded": MAX_EXPANDED,
                        "evidence_stash_files": MAX_FILES},
            "resource_policy": "atomic-set/conflict-fifo/unknown-blocks", "unknown_is_release": False}


def can_profile(state, actor, executor):
    """Who reads a window's saved configurations: the window, its responsible person, an administrator."""
    return actor == executor or rules.system_admin(state, actor) or actor == rules.responsible(state, executor)


def reporter_kind(state, actor, row):
    """How actor may report on an action or segment: as its owner, a managing person, a trusted adapter, or not at all."""
    if row["executor_id"] == actor:
        return "owner"
    task = state.get("tasks", {}).get(row["task_id"], {})
    if ((rules.identity(state, actor) or {}).get("kind") == "human"
        and rules.manager(state, rules.task_project(task), actor)):
        return "human"
    adapters = state.get("security", {}).get("execution", {}).get("adapters", {})
    if any(item.get("trusted") and item.get("actor") == actor and
           (row["claim_id"] in item.get("claims", []) or item.get("executor_id") == row["executor_id"])
           for item in adapters.values()):
        return "adapter"
    return None


def audit_context(state, actor, body):
    """The saved configuration a request's audit record may carry; None means the requester's own default.

    A request can name any configuration, directly or through a segment or an action, and rejected
    requests are recorded too. Only a configuration the requester may read is kept, or the one of an
    action or segment the requester may report on.
    """
    action = _row(state, "actions", body.get("action_id"))
    segment = _row(state, "segments", body.get("segment_id") or action.get("segment_id"))
    direct = body.get("context_id") or body.get("context_version")
    context_id = body.get("context_id") or segment.get("context_id")
    context_version = body.get("context_version") or segment.get("context_version")
    named = (_row(state, "contexts", str(context_id) + ":" + str(context_version))
             if context_id and context_version else {})
    if not named:
        return None
    if can_profile(state, actor, named["executor_id"]):
        return named
    source = action or segment
    if not direct and source and source["executor_id"] == named["executor_id"] and reporter_kind(state, actor, source):
        return named
    return None


def _can_view(state, actor, record):
    claim = state.get("claims", {}).get(record.get("claim_id"), {})
    if actor == record.get("executor_id", claim.get("origin")) or rules.system_admin(state, actor):
        return True
    task = state.get("tasks", {}).get(record.get("task_id"))
    return bool(task and rules.visible(state, task, actor))


def _public(value):
    private = {"authority", "resource_proofs", "canonical_path", "filesystem", "identity", "resolved"}
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items() if key not in private}
    if isinstance(value, list):
        return [_public(item) for item in value]
    return deepcopy(value)


def read(state, actor, query=None):
    query = query or {}
    if not isinstance(query, dict) or not set(query) <= {"executor_id", "task_id", "claim_id", "action_id"}:
        raise ClientError("执行查询条件无效")
    data = state.get("security", {}).get("execution", {})
    target = query.get("executor_id", actor)
    profile = can_profile(state, actor, target)
    contexts = [deepcopy(row) for row in data.get("contexts", {}).values() if row["executor_id"] == target and profile]
    selected_action = data.get("actions", {}).get(query.get("action_id"), {})

    def selected(row):
        return _can_view(state, actor, row) and (
                not query.get("executor_id") or row.get("executor_id") == target) and all(
            not query.get(key) or
            row.get(key if key != "action_id" else "action_id",
                    row.get("id") if key == "action_id" else None) == query[key] or
            key == "action_id" and row.get("id") == selected_action.get("segment_id")
            for key in ("task_id", "claim_id", "action_id")) and (bool(query) or
                row.get("executor_id", state.get("claims", {}).get(row.get("claim_id"), {}).get("origin")) == actor)
    result = {"schema": security_schema(state, 3), "actor": actor, "executor_id": target,
              "can_write": actor == target,
              "default_context": deepcopy(data.get("defaults", {}).get(target)) if profile else None,
              "contexts": [{**row, "can_write": actor == row["executor_id"]} for row in contexts]}
    result["resource_domains"] = sorted(getattr(query, "resource_domains", []))
    for table in ("segments", "actions", "resource_requests", "grants", "facts", "stashes", "legacy", "blockers"):
        result[table] = [_public(row) for row in data.get(table, {}).values() if selected(row)]
    result["physical_blockers"] = [deepcopy(row)
                                   for row in state.get("security", {}).get("physical_blockers", {}).values()
                                   if selected(row)]
    for row in result["actions"]:
        reporter = reporter_kind(state, actor, row)
        own = reporter == "owner"
        row.update(can_prepare=own, can_request=own and row["state"] == "prepared",
                   can_start=own and row["state"] == "granted",
                   can_report=bool(reporter), can_release=bool(reporter) and bool(row.get("grant_id")),
                   reporter_kind=reporter)
    for row in result["legacy"] + result["physical_blockers"]:
        claim = state.get("claims", {}).get(row.get("claim_id"), {})
        task = state.get("tasks", {}).get(claim.get("task_id"), {})
        own = claim.get("origin") == actor
        human = ((rules.identity(state, actor) or {}).get("kind") == "human"
                 and rules.manager(state, rules.task_project(task), actor))
        row.setdefault("task_id", claim.get("task_id"))
        if row.get("epoch") == claim.get("epoch"):
            row.setdefault("scope_version", claim.get("W", {}).get("scope"))
        row.update(can_report=own or human, reporter_kind="owner" if own else "human" if human else None)
        if row.get("epoch") is None or row.get("scope_version") is None:
            row.update(can_report=False, binding_notice="原范围或代次需先核实，不能套用当前代次解除历史阻挡")
    return result


def stash_reference_allowed(state, actor, path):
    return any(row.get("bundle", {}).get("path") == path and _can_view(state, actor, row)
               for row in state.get("security", {}).get("execution", {}).get("stashes", {}).values())
