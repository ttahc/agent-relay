"""Security-5 execution contexts, immutable segments and atomic resource arbitration."""
from copy import deepcopy
from pool import environments
import re

from 协作存储 import digest, encoded
import 协作升级 as rules
from 协作命令 import resource as old_resource, grants as covers_permission, conflicts as old_conflicts


OPS = {"context-save", "segment-open", "action-prepare", "resource-request", "resource-cancel",
       "action-start", "execution-fact", "evidence-stash", "resource-release"} | environments.OPS
FACT_OPS = {"execution-fact", "evidence-stash"}
DIMENSIONS = ("platform", "adapter", "model", "reasoning", "tools_version", "permissions_version", "environment")
TABLES = ("contexts", "defaults", "segments", "actions", "resource_requests", "grants", "facts", "stashes",
          "legacy", "blockers", "adapters", "capability_definitions", "evidence_bindings", "claim_bindings") + environments.TABLES
TERMINAL = {"finished", "error", "stopped", "not-started"}


def ensure(state):
    data = state["security"].setdefault("execution", {})
    for key in TABLES:
        data.setdefault(key, {})
    data.setdefault("sequence", 0)
    return data


def identifier(value, label="编号"):
    rules.require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", value), label + "无效")
    return value


def version(value, expected):
    rules.require(type(value) is int and value == expected, "记录版本已变化，请重新读取后使用新请求")


def evidence(value):
    rules.require(isinstance(value, dict) and set(value) == {"note", "sha256"} and
                  isinstance(value["note"], str) and 0 < len(value["note"].strip()) <= 2000 and
                  isinstance(value["sha256"], str) and rules.SHA.fullmatch(value["sha256"]), "须提供可核对的证据说明和 SHA256")
    return deepcopy(value)


def context_record(state, actor, context):
    data = state.get("security", {}).get("execution", {})
    if context is None:
        context = data.get("defaults", {}).get(actor)
    if isinstance(context, dict) and "config" in context:
        row = context
    else:
        rules.require(isinstance(context, dict), "请选择本次执行配置")
        row = data.get("contexts", {}).get(str(context.get("context_id")) + ":" + str(context.get("version")))
    rules.require(row and row["executor_id"] == actor, "执行配置不存在或不属于本窗口")
    return row


def capability_check(state, actor, record, context, requirement=None):
    """Match evidence against the selected segment context, never a window-global model."""
    requirement = requirement or {}
    context = context or default_context(state, actor)
    config = context.get("config", context)
    cap_id = requirement.get("id") or record.get("id")
    project = requirement.get("project_id") or record.get("project_id")
    definitions = state.get("security", {}).get("execution", {}).get("capability_definitions", {})
    definition = definitions.get(str(project) + ":" + str(cap_id), definitions.get(cap_id, {}))
    technical = set(definition.get("dimensions", [])) | set(requirement.get("dimensions", []))
    required_level = requirement.get("evidence", record.get("level", "declared"))
    allow_unknown = set(definition.get("allow_unknown", [])) | set(requirement.get("allow_unknown", []))
    independently_known = set(definition.get("verified_dimensions", [])) | set(requirement.get("verified_dimensions", []))
    binding = record.get("applicability")
    if not binding:
        if required_level == "declared" and not independently_known and not technical and not record.get("execution_context"):
            return {"matches": True, "status": "legacy-declared", "reason": "旧声明按允许自报的合同兼容；未补造模型核实范围"}
        scope = record.get("execution_context")
        dims = record.get("context_dimensions")
        if not isinstance(scope, dict) or not isinstance(dims, list):
            return {"matches": False, "status": "scope-unknown", "reason": "核实证据适用范围未知，需要补证"}
        binding = {"rule_version": 1, "dependencies": {key: scope.get(key, "unknown") for key in dims}, "verified_dimensions": []}
    dependencies = binding.get("dependencies", {})
    if not technical <= set(dependencies):
        return {"matches": False, "status": "missing-dependencies", "reason": "证据未覆盖能力定义要求的技术依赖"}
    if binding.get("rule_version") != definition.get("rule_version", 1):
        return {"matches": False, "status": "rule-changed", "reason": "能力适用规则版本已变化"}
    for key, expected in dependencies.items():
        actual = config.get(key, "unknown")
        unknown = actual in (None, "", "unknown") or expected in (None, "", "unknown")
        if unknown and (key in independently_known or required_level != "declared" or key not in allow_unknown):
            return {"matches": False, "status": "unknown-dependency", "reason": "相关配置维度未知，不能当作独立核实：" + key}
        if not unknown and expected != actual:
            return {"matches": False, "status": "context-mismatch", "reason": "证据不适用于所选配置：" + key}
    if not independently_known <= set(binding.get("verified_dimensions", [])):
        return {"matches": False, "status": "unverified-dimensions", "reason": "任务要求的相关维度尚无独立核实依据"}
    return {"matches": True, "status": "applicable", "reason": "按证据依赖与所选配置匹配，不根据模型名称授权"}


def match_context(state, actor, record, context, requirement=None):
    return capability_check(state, actor, record, context, requirement)["matches"]


def bind_evidence(state, actor, record, context=None, project_id=None, capability_id=None, requested_dimensions=None, verified=False):
    selected = context_record(state, actor, context) if context is not None else default_context(state, actor)
    definitions = state.get("security", {}).get("execution", {}).get("capability_definitions", {})
    definition = definitions.get(str(project_id) + ":" + str(capability_id), definitions.get(capability_id, {}))
    default = ["platform", "tools_version", "permissions_version", "environment"] if record.get("kind") == "environment" else (
        ["platform"] if (rules.identity(state, actor) or {}).get("kind") == "executor" else [])
    technical = set(definition.get("dimensions", default))
    requested = list(technical) if requested_dimensions is None else requested_dimensions
    rules.require(isinstance(requested, list) and all(isinstance(key, str) and key in DIMENSIONS for key in requested) and
                  len(set(requested)) == len(requested), "证据依赖维度无效")
    rules.require(technical <= set(requested), "不能删除能力定义规定的真实技术依赖")
    dependencies = {key: selected["config"][key] for key in sorted(requested)}
    known = [key for key, value in dependencies.items() if value not in {"unknown", ""}]
    return {"context_id": selected["context_id"], "context_version": selected["version"],
            "applicability": {"rule_version": definition.get("rule_version", 1), "dependencies": dependencies,
                              "verified_dimensions": known if verified else [], "origin": "independent-evidence" if verified else "declared"}}


def eligible(state, task, actor, context, now):
    missing, refs = [], []
    project = rules.task_project(task)
    for requirement in (rules.contract(task) or {}).get("requirements", []):
        key = f"cap:{project}:{actor}:{requirement['id']}"
        record = state["pilot"].get(key)
        suitable = bool(record and record.get("kind") == requirement["kind"] and
                        (requirement["value"] == "*" or record.get("value") == requirement["value"]) and
                        rules.LEVEL.get(record.get("level"), 0) >= rules.LEVEL[requirement["evidence"]] and
                        record.get("expires", 0) > now and match_context(state, actor, record, context, {**requirement, "project_id": project}))
        if not suitable and requirement["required"]:
            missing.append("能力证据不满足所选配置：" + requirement["id"])
        if suitable:
            refs.append({"key": key, "version": record.get("version", 0), "sha256": record.get("evidence", {}).get("sha256"),
                         "level": record["level"], "applicability": deepcopy(record.get("applicability"))})
    return {"eligible": not missing, "missing": missing, "capability_refs": refs}


def legacy_new_work_allowed(state, claim=None):
    return state.get("security", {}).get("schema", 3) < 5


def default_context(state, actor, create=False, now=0, event_id="legacy-profile"):
    data = ensure(state) if create else state.get("security", {}).get("execution", {})
    selected = data.get("defaults", {}).get(actor)
    if selected:
        return context_record(state, actor, selected)
    subject = rules.identity(state, actor) or {}
    config = {key: subject.get(key) or ("manual" if key == "adapter" else "unknown") for key in DIMENSIONS}
    if subject.get('kind')=='human':
        config.update(platform=subject.get('platform') or 'human', model=subject.get('model') or 'not-applicable',
                      reasoning='not-applicable', environment=subject.get('environment') or 'human')
    config["sources"] = {key: "unknown" if config[key] == "unknown" else "reported" for key in DIMENSIONS}
    context_id = "ctx-legacy-" + digest(actor.encode("utf-8"))[:24]
    row = {"id": context_id, "context_id": context_id, "version": 1, "executor_id": actor, "config": config,
           "at": now, "event": event_id, "origin": "legacy-reported-unknown"}
    if create:
        data["contexts"].setdefault(context_id + ":1", row)
        data["defaults"][actor] = {"context_id": context_id, "version": 1}
    return row


def freeze_claim(state, task, actor, claim, now, p=None):
    data = ensure(state)
    p = p or {}
    selected = context_record(state, actor, {"context_id": p["context_id"], "version": p["context_version"]}) if p.get("context_id") else default_context(state, actor, True, now)
    checked = eligible(state, task, actor, selected, now)
    rules.require(checked["eligible"], "；".join(checked["missing"]))
    row = {"claim_id": claim["claim_id"], "task_id": task["task_id"], "executor_id": actor,
           "scope_version": claim["W"]["scope"], "epoch": claim["epoch"], "context_id": selected["context_id"],
           "context_version": selected["version"], "capability_refs": deepcopy(checked["capability_refs"]), "at": now}
    data["claim_bindings"].setdefault(claim["claim_id"], row)
    return deepcopy(data["claim_bindings"][claim["claim_id"]])


def actor_contexts(state, actor):
    data = state.get("security", {}).get("execution", {})
    return {"default_context": deepcopy(data.get("defaults", {}).get(actor)),
            "active_task_contexts": [deepcopy(row) for row in data.get("segments", {}).values() if row["executor_id"] == actor and
                state.get("claims", {}).get(row["claim_id"], {}).get("L") == "active"] +
                [deepcopy(row) for row in data.get("claim_bindings", {}).values() if row["executor_id"] == actor and
                 state.get("claims", {}).get(row["claim_id"], {}).get("L") == "active"]}


def execution_load(state, actor, exclude_claim=None, exclude_action=None):
    from 协作本轮 import execution_settings
    data = state.get("security", {}).get("execution", {})
    active = [row for row in data.get("actions", {}).values() if row["executor_id"] == actor and row["id"] != exclude_action and
              row["claim_id"] != exclude_claim and (row["state"] in {"start-authorized", "running", "unconfirmed"} or
              data.get("grants", {}).get(row.get("grant_id"), {}).get("physical") in {"in-use", "unknown"})]
    legacy = {row["claim_id"] for row in data.get("legacy", {}).values() if row["executor_id"] == actor and row["claim_id"] != exclude_claim and
              row.get("active") and row.get("physical") in {"in-use", "unknown"}}
    claims = [row for row in state.get("claims", {}).values() if row["origin"] == actor and row["L"] == "active"]
    count = len(active) + len(legacy)
    limit = execution_settings(state, actor)["limit"] if (rules.identity(state,actor) or {}).get('kind')=='executor' else None
    return {"active_claims": len(claims), "executing": count, "running": sum(row["state"] == "running" for row in active),
            "awaiting_review": sum(row["W"]["state"] == "review" for row in claims), "limit_exempt": max(0, len(claims)-count),
            "limit": limit, "available": max(0, limit-count) if limit is not None else None}


def normalize_resources(state, values):
    rules.require(isinstance(values, list) and len(values) <= 30, "资源集合须为最多30项的完整数组")
    result = []
    for value in values:
        rules.require(isinstance(value, dict) and set(value) == {"id", "mode", "domain"}, "资源须包含 id、mode、domain")
        rules.require(isinstance(value["id"], str) and isinstance(value["mode"], str), "资源标识与模式须为文本")
        row = old_resource({"id": value["id"], "mode": value["mode"]})
        domain = value["domain"]
        rules.require(isinstance(domain, str) and 0 < len(domain) <= 160 and not any(ord(ch) < 32 for ch in domain), "须声明明确资源域")
        result.append({**row, "domain": domain})
    rules.require(len({(row["domain"], row["id"]) for row in result}) == len(result), "同一资源不能重复或同时申请读写升级")
    return sorted(result, key=lambda row: (row["domain"], row["id"], row["mode"]))


def conflict(state, left, right):
    if left.get("identity") and right.get("identity") and left["identity"] == right["identity"]:
        return left["mode"] != "read" or right["mode"] != "read"
    if (left.get("identity") in right.get("ancestor_identities", []) or
            right.get("identity") in left.get("ancestor_identities", [])):
        return left["mode"] != "read" or right["mode"] != "read"
    left_members = set(left.get("descendant_identities", [])) | set(left.get("domain_identities", []))
    right_members = set(right.get("descendant_identities", [])) | set(right.get("domain_identities", []))
    if (left_members & (right_members | set(right.get("ancestor_identities", [])) | {right.get("identity")}) or
            right_members & (set(left.get("ancestor_identities", [])) | {left.get("identity")})):
        return left["mode"] != "read" or right["mode"] != "read"
    for a_root, a_suffix in [*left.get("physical_paths", []), *left.get("domain_paths", [])]:
        for b_root, b_suffix in [*right.get("physical_paths", []), *right.get("domain_paths", [])]:
            if a_root == b_root and (a_suffix == b_suffix or a_suffix == "." or b_suffix == "." or
                    a_suffix.startswith(b_suffix + "/") or b_suffix.startswith(a_suffix + "/")):
                return left["mode"] != "read" or right["mode"] != "read"
    if left.get("resolved") and right.get("resolved") and left["id"].startswith("path:") and right["id"].startswith("path:"):
        a, b = left.get("canonical_path", ""), right.get("canonical_path", "")
        related = a == b or a.startswith(b.rstrip("/") + "/") or b.startswith(a.rstrip("/") + "/")
        if a and b and related:
            return left["mode"] != "read" or right["mode"] != "read"
    # Only server-mapped, administrator-attested domains can prove remote isolation.
    # Never use the caller's resource.domain label for this decision. Local alias
    # evidence above overrides even an administrator's mistaken distinct labels.
    if left["id"].startswith("path:") and right["id"].startswith("path:"):
        if left.get("scope_uncertain") or right.get("scope_uncertain"):
            return left["mode"] != "read" or right["mode"] != "read"
        left_domain, right_domain = left.get("storage_domain_id"), right.get("storage_domain_id")
        if left_domain and right_domain:
            return (environments.canonical_domain(state, left_domain) == environments.canonical_domain(state, right_domain) and
                    (left["mode"] != "read" or right["mode"] != "read"))
        if left_domain or right_domain or not left.get("resolved") or not right.get("resolved"):
            return left["mode"] != "read" or right["mode"] != "read"
        # Both local complete proofs were checked above and establish disjoint paths.
        if left.get("canonical_path") and right.get("canonical_path"):
            return False
    return old_conflicts(state, left, right)


def _sets_conflict(state, left, right):
    return any(conflict(state, a, b) for a in left for b in right)


def blocking_records(state):
    data = state.get("security", {}).get("execution", {})
    rows = [row for row in data.get("grants", {}).values() if row["state"] == "granted" or row.get("physical") in {"in-use", "unknown"}]
    rows += [row for table in ("legacy", "blockers") for row in data.get(table, {}).values() if row.get("active", True)]
    rows += [row for row in state.get("security", {}).get("physical_blockers", {}).values() if row.get("active", True)]
    return rows


def migrate_legacy(state, now, event_id):
    """Index old occupancies without changing claim state, epoch, resources or reservations."""
    data = ensure(state)
    for claim in state.get("claims", {}).values():
        reservations = [row for row in state.get("reservations", {}).values() if row.get("active") and row.get("claim_id") == claim["claim_id"]]
        if claim["L"] != "active" and not reservations and not claim.get("R"):
            continue
        key = "legacy-" + claim["claim_id"]
        resources = [{"id": row["id"], "mode": row["mode"]} for row in reservations]
        if claim.get("R") and not resources:
            resources = deepcopy(state["tasks"][claim["task_id"]].get("resources", []))
        uncertain = claim["E"]["state"] != "stopped" or not claim.get("stop_evidence")
        data["legacy"].setdefault(key, {"id": key, "kind": "legacy-claim", "claim_id": claim["claim_id"],
            "task_id": claim["task_id"], "executor_id": claim["origin"], "scope_version": claim["W"]["scope"], "epoch": claim["epoch"],
            "original_R": deepcopy(claim.get("R", [])), "original_E": deepcopy(claim["E"]), "resources": resources,
            "physical": "unknown" if uncertain or resources else "end-confirmed", "active": bool(resources) or uncertain, "at": now, "event": event_id})


def _claim(state, p):
    claim = state.get("claims", {}).get(p.get("claim_id"))
    rules.require(claim and claim["task_id"] == p.get("task_id"), "原任务与领取绑定不存在")
    return claim, state["tasks"][claim["task_id"]]


def _new_permission(state, actor, claim, task, context, now, authority=None, authorization_operation="claim"):
    from pool.delegation import operation_context
    environments.check_context(state, actor, context)
    project = rules.task_project(task)
    rules.require(claim["origin"] == actor and claim["L"] == "active" and rules.active(state, actor), "须为原领取的有效执行者", "intent-final")
    rules.require(claim.get('E',{}).get('state')=='running' and not claim.get('E',{}).get('reason') and
                  claim.get('W',{}).get('state')=='draft' and not claim.get('scope_ack_pending') and
                  claim.get('recovery',{}).get('status')!='pending',
                  '任务已暂停、待返修续行或范围待确认；须先明确继续本工作回合')
    rules.require(task.get("scope_version") == claim["W"]["scope"] and not task.get("cancel_requested") and not task.get("accepted"), "任务范围或阶段已变化")
    rules.require((rules.contract(task) or {}).get("open") is True and not task.get("change_pending") and not task.get("decision_holds"), "任务已暂缓或待处理变更")
    rules.require(authorization_operation in {"claim", "resume"} and
                  (not authority or authority.get("delegated_operation", "claim") == authorization_operation),
                  "授权操作类别与原执行段不符", "intent-final")
    with operation_context(state, actor, authorization_operation, project, task["task_id"], now, authority):
        rules.require("executor" in rules.roles(state, project, actor), "当前项目执行授权或原委托已失效", "intent-final")
        if authority and authority.get("authorization"):
            rules.require(rules.auth_stamp(state, actor, project) == authority["authorization"], "原执行授权依据已变化", "intent-final")
        result = eligible(state, task, actor, context, now)
        rules.require(result["eligible"], "；".join(result["missing"]))
        gate = (rules.contract(task) or {}).get("gate")
        rules.require(not gate or rules.release_current(state, gate), "任务升级前置仍未满足")
        for dep in task.get("dependencies", []):
            rules.require(dep["criterion"] in state["tasks"].get(dep["task"], {}).get("provided", {}).get(dep["output"], []), "前置产出待满足")
    return result["capability_refs"]


def open_resume_segment(state, task, actor, claim, now, event_id, p):
    """Called only after an authorized business resume, never as a new-claim shortcut."""
    audit = p.get("_audit", {})
    current = state.get("claims", {}).get(claim.get("claim_id"))
    rules.require(state.get("security", {}).get("schema") == 5 and state["security"].get("phase") == "ready", "返修执行段须在安全版本5就绪后建立")
    rules.require(current and current["origin"] == actor and current["task_id"] == task["task_id"] and current["L"] == "active" and
                  current["epoch"] == claim["epoch"] and current["W"]["scope"] == task["scope_version"] == claim["W"]["scope"] and
                  current["W"]["state"] == "draft" and current["E"]["state"] == "running" and
                  type(current["epoch"]) is int and current["epoch"] > 0, "须先完成原任务当前范围与代次的显式业务返修授权")
    rules.require(audit.get("actor") == actor and audit.get("operation") == "resume" and
                  audit.get("task_id") == task["task_id"] and audit.get("project_id") == rules.task_project(task) and
                  type(audit.get("credential_version")) is int and audit["credential_version"] == (rules.identity(state, actor) or {}).get("credential") and
                  isinstance(audit.get("authorization"), str), "返修执行段缺少原业务授权审计", "intent-final")
    if "resumed_epoch" in p:
        version(p["resumed_epoch"], current["epoch"])
    if "scope_version" in p:
        version(p["scope_version"], current["W"]["scope"])
    authority = {key: deepcopy(audit[key]) for key in ("delegator", "delegation_id", "delegation_version", "authorization") if key in audit}
    authority["delegated_operation"] = "resume"
    candidate = {**state, "security": deepcopy(state["security"])}
    data = ensure(candidate)
    identifier(event_id, "返修事件")
    segment_id = "seg-resume-" + digest(event_id.encode("utf-8"))[:40]
    previous = data["segments"].get(segment_id)
    rules.require(not previous or previous["claim_id"] == current["claim_id"] and previous["epoch"] == current["epoch"] and
                  previous["scope_version"] == current["W"]["scope"] and previous.get("authorization_operation") == "resume",
                  "原返修事件已绑定其他代次，不得覆盖历史段")
    if previous:
        selected = context_record(candidate, actor, {"context_id": previous["context_id"], "version": previous["context_version"]})
    else:
        selected = context_record(candidate, actor, {"context_id": p["context_id"], "version": p["context_version"]}) if p.get("context_id") else default_context(candidate, actor, True, now, event_id)
    refs = _new_permission(candidate, actor, current, task, selected, now, authority, "resume")
    rules.require(not any(row.get("active") and row.get("claim_id") == current["claim_id"] for row in data["legacy"].values()),
                  "原领取的未知占用仍未确认归还，不能借返修清除")
    if previous:
        return deepcopy(previous)
    record = {"id": segment_id, "version": 1, "task_id": task["task_id"], "claim_id": current["claim_id"], "executor_id": actor,
              "scope_version": current["W"]["scope"], "epoch": current["epoch"], "context_id": selected["context_id"],
              "context_version": selected["version"], "capability_refs": deepcopy(refs), "authorization_operation": "resume", "at": now, "event": event_id}
    data["segments"][segment_id] = record
    state["security"] = candidate["security"]
    return deepcopy(record)


def _within(state, task, resources):
    bounds = task.get("resources", [])
    for row in resources:
        rules.require(any(covers_permission(state, upper["id"], row["id"]) and
                          (row["mode"] == "read" or upper["mode"] != "read") for upper in bounds), "动作资源超出任务合同上界")


def _resource_permission(state, actor, task, resources):
    project = rules.task_project(task)
    assigned = rules.grant(state, project, actor)["resources"]
    subject = rules.identity(state, actor) or {}
    parent = rules.grant(state, project, subject.get("owner"))
    limits = [assigned] if subject.get("kind") != "executor" or "manager" in parent["roles"] else [assigned, parent["resources"]]
    for resource in resources:
        rules.require(all(any(covers_permission(state, held["id"], resource["id"]) and
                              (resource["mode"] == "read" or held["mode"] != "read") for held in limit) for limit in limits), "本动作资源权限不足")


def _actor_basis(state, actor, claim, task, basis):
    rules.require(isinstance(basis, dict) and set(basis) == {"kind", "note"} and isinstance(basis["note"], str) and
                  0 < len(basis["note"].strip()) <= 2000, "须说明原执行来源和事实报告依据")
    if actor == claim["origin"] and basis["kind"] == "owner":
        return "owner"
    if basis["kind"] == "human" and (rules.identity(state, actor) or {}).get("kind") == "human" and rules.manager(state, rules.task_project(task), actor):
        return "human"
    data = state["security"].get("execution", {})
    if basis["kind"] == "adapter" and any(row.get("actor") == actor and row.get("trusted") is True and
            (claim["claim_id"] in row.get("claims", []) or row.get("executor_id") == claim["origin"]) for row in data.get("adapters", {}).values()):
        return "adapter"
    rules.require(False, "只能由原执行者、有项目权限的人类管理者或已登记受信执行适配器补报", "intent-final")


def _arbitrate(state, now, event_id):
    data = ensure(state)
    waiting = []
    for request in sorted(data["resource_requests"].values(), key=lambda row: row["sequence"]):
        if request["state"] != "queued":
            continue
        action = data["actions"][request["action_id"]]
        segment = data["segments"][action["segment_id"]]
        claim, task = _claim(state, action)
        try:
            rules.require(claim["epoch"] == action["epoch"] == segment["epoch"] and
                          claim["W"]["scope"] == action["scope_version"] == segment["scope_version"], "旧执行段的等待申请不能取得新代次授权")
            context = context_record(state, action["executor_id"], {"context_id": segment["context_id"], "version": segment["context_version"]})
            operation = segment.get("authorization_operation", "claim")
            rules.require(action.get("authorization_operation", "claim") == operation, "动作与执行段的授权类别不符")
            _new_permission(state, action["executor_id"], claim, task, context, now, request.get("authority"), operation)
            environments.check_mappings(state, action)
            _within(state, task, request["resources"])
            _resource_permission(state, action["executor_id"], task, request["resources"])
        except Exception as error:
            from 协作存储 import Rejected
            if not isinstance(error, Rejected):
                raise
            request.update(state="blocked", reason=str(error), version=request["version"] + 1)
            action.update(state="prepared", version=action["version"] + 1)
            continue
        if any(_sets_conflict(state, request["resources"], row["resources"]) for row in blocking_records(state)) or any(
                _sets_conflict(state, request["resources"], earlier["resources"]) for earlier in waiting):
            waiting.append(request)
            continue
        generation = action.get("generation", 0) + 1
        grant_id = "g-" + request["id"][2:]
        data["grants"][grant_id] = {"id": grant_id, "action_id": action["id"], "claim_id": action["claim_id"], "task_id": action["task_id"],
            "segment_id": action["segment_id"], "executor_id": action["executor_id"], "generation": generation, "version": 1,
            "state": "granted", "physical": "not-started", "resources": deepcopy(request["resources"]), "at": now, "event": event_id}
        request.update(state="granted", grant_id=grant_id, generation=generation, version=request["version"] + 1)
        action.update(state="granted", grant_id=grant_id, generation=generation, version=action["version"] + 1)


def action(state, env, context):
    p, now = env["payload"], context["now"]
    op, audit = p.get("op"), p.get("_audit", {})
    actor = audit.get("actor")
    subject = rules.identity(state, actor) or {}
    schema = state.get("security", {}).get("schema", 3)
    rules.require(op in OPS and (schema == 5 or schema == 4 and op in FACT_OPS), "此操作需要对应安全语义版本4或5")
    rules.require(state["security"].get("phase", "ready") == "ready", "安全迁移尚未完成")
    rules.require(rules.active(state, actor) and subject.get("kind") in {"human", "executor"} and
                  type(audit.get("credential_version")) is int and audit["credential_version"] == subject.get("credential"),
                  "执行身份或凭据版本已失效", "intent-final")
    if subject.get("kind") == "executor":
        rules.require(rules.active(state, subject.get("owner")) and subject.get("token_expires", now + 1) > now, "责任账号或执行凭据已失效", "intent-final")
    if op in {"segment-open", "action-start"}:
        rules.require(context.get("phase", "running") == "running", "服务排空中，暂停新段和开始许可")
    candidate = {**state, "security": deepcopy(state["security"])}
    _apply(candidate, p, actor, now, env["event_id"])
    state["security"] = candidate["security"]
    if op in environments.OPS or (op == "action-prepare" and any(
            "physical_paths" in proof or "descendant_identities" in proof for proof in p.get("resource_proofs", {}).values())):
        # Persist a reader floor: older binaries replay stored effects but do not
        # understand these collision proofs, so they must refuse this store.
        state["pilot"] = {**state["pilot"], "format": {**state["pilot"]["format"], "min_reader": 6}}


def _apply(state, p, actor, now, event_id):
    data = ensure(state)
    op = p["op"]
    if op in environments.OPS:
        environments.apply(state, p, actor, now, event_id)
        _arbitrate(state, now, event_id)
        return
    if op == "context-save":
        context_id = p["context_id"]
        rows = [row for row in data["contexts"].values() if row["context_id"] == context_id]
        latest = max((row["version"] for row in rows), default=0)
        version(p["version"], latest)
        rules.require(not rows or all(row["executor_id"] == actor for row in rows), "执行配置属于其他窗口")
        config = p["config"]
        rules.require(isinstance(config, dict) and set(config) == set(DIMENSIONS) | {"sources"} and
                      all(isinstance(config[key], str) and 0 < len(config[key]) <= 160 for key in DIMENSIONS), "执行配置字段不完整")
        rules.require(isinstance(config["sources"], dict) and set(config["sources"]) == set(DIMENSIONS) and
                      all(isinstance(source, str) and source in {"reported", "unknown"} for source in config["sources"].values()), "本窗口只能申报配置或标记未知，不能自证受信探测")
        rules.require(type(p["make_default"]) is bool, "须明确是否作为新动作默认配置")
        record = {"id": context_id, "context_id": context_id, "version": latest + 1, "executor_id": actor,
                  "config": deepcopy(config), "at": now, "event": event_id}
        previous = max(rows, key=lambda row: row["version"]) if rows else {}
        environment_id = p.get("environment_id", previous.get("environment_id", ""))
        rules.require(isinstance(environment_id, str), "执行环境编号须为文本")
        if environment_id:
            instance = environments.selected(state, actor, identifier(environment_id, "执行环境编号"))
            record.update(environment_id=instance["id"], environment_version=instance["version"])
        data["contexts"][context_id + ":" + str(latest + 1)] = record
        if p["make_default"]:
            data["defaults"][actor] = {"context_id": context_id, "version": latest + 1}
        return
    if op == "segment-open":
        claim, task = _claim(state, p)
        rules.require(claim["epoch"] == p["epoch"] and claim["W"]["scope"] == p["scope_version"], "当前领取代次或范围已变化")
        rules.require(not any(row.get("active") and row.get("claim_id") == claim["claim_id"] for row in data["legacy"].values()), "须先核对归还原领取占用，再建立新执行段")
        selected = context_record(state, actor, {"context_id": p["context_id"], "version": p["context_version"]})
        refs = _new_permission(state, actor, claim, task, selected, now, p.get("authority"))
        data["segments"][p["id"]] = {"id": p["id"], "version": 1, "task_id": task["task_id"], "claim_id": claim["claim_id"],
            "executor_id": actor, "scope_version": p["scope_version"], "epoch": p["epoch"], "context_id": selected["context_id"],
            "context_version": selected["version"], "capability_refs": deepcopy(refs), "authorization_operation": "claim", "at": now, "event": event_id}
        return
    if op == "action-prepare":
        segment = data["segments"].get(p["segment_id"])
        rules.require(segment and segment["executor_id"] == actor, "执行段不存在或不属于本人")
        version(p["version"], segment["version"])
        claim, task = _claim(state, segment)
        rules.require(claim["epoch"] == segment["epoch"] and claim["W"]["scope"] == segment["scope_version"], "执行段已不属于当前代次或范围")
        selected = context_record(state, actor, {"context_id": segment["context_id"], "version": segment["context_version"]})
        authorization_operation = segment.get("authorization_operation", "claim")
        _new_permission(state, actor, claim, task, selected, now, p.get("authority"), authorization_operation)
        resources = normalize_resources(state, p["resources"])
        _within(state, task, resources)
        _resource_permission(state, actor, task, resources)
        rules.require(isinstance(p["description"], str) and 0 < len(p["description"].strip()) <= 2000, "请说明本次实际动作")
        rules.require(isinstance(p["adapter_id"], str) and p["adapter_id"] in {"manual", "local-files", "isolated-worktree"} and p["adapter_id"] == selected["config"]["adapter"], "适配器须与所选配置相符；CATIA自动执行尚未启用")
        data["actions"][p["id"]] = {"id": p["id"], "version": 1, "state": "prepared", "segment_id": segment["id"],
            "task_id": segment["task_id"], "claim_id": segment["claim_id"], "scope_version": segment["scope_version"], "epoch": segment["epoch"],
            "executor_id": actor, "description": p["description"], "resources": resources, "resource_proofs": deepcopy(p.get("resource_proofs", {})),
            "adapter_id": p["adapter_id"], "authorization_operation": authorization_operation, "at": now, "event": event_id}
        segment["version"] += 1
        return
    if op in {"execution-fact", "evidence-stash"}:
        claim, task = _claim(state, p)
        basis = _actor_basis(state, actor, claim, task, p["reporter_basis"])
        rules.require(type(p["epoch"]) is int and 0 < p["epoch"] <= claim["epoch"] and type(p["scope_version"]) is int and
                      0 < p["scope_version"] <= task["scope_version"], "事实来源代次或范围无效")
        target = data["actions"].get(p.get("action_id")) if p.get("action_id") else None
        if p.get("action_id"):
            rules.require(target and target["claim_id"] == claim["claim_id"] and target["epoch"] == p["epoch"] and target["scope_version"] == p["scope_version"], "动作与原执行来源不符")
        historical = p["epoch"] != claim["epoch"] or p["scope_version"] != claim["W"]["scope"]
        common = {"id": p["id"], "task_id": task["task_id"], "claim_id": claim["claim_id"], "scope_version": p["scope_version"], "epoch": p["epoch"],
                  "action_id": p.get("action_id"), "executor_id": claim["origin"], "reporter": actor, "reporter_basis": deepcopy(p["reporter_basis"]),
                  "historical": historical, "at": now, "event": event_id}
        if op == "evidence-stash":
            rules.require(isinstance(p["files"], list) and 0 < len(p["files"]) <= 100 and sum(row["bytes"] for row in p["files"]) <= 24 * 1024 * 1024, "产物暂存超出原交付预算")
            rules.require(p["bundle"]["path"].startswith("evidence-stash/") and rules.SHA.fullmatch(p["bundle"]["sha256"]), "暂存对象引用无效")
            data["stashes"][p["id"]] = {**common, "files": deepcopy(p["files"]), "bundle": deepcopy(p["bundle"]), "state": "pending-review"}
            return
        kind = p["kind"]
        rules.require(isinstance(kind, str) and kind in {"started", "finished", "error", "stopped", "not-started", "unconfirmed"}, "收尾事实种类无效")
        proof = evidence(p["evidence"])
        if kind == "started":
            rules.require(target and p.get("permit_id") == target.get("permit_id") and target.get("permit_id"), "started须绑定已有开始许可，不能通过事实入口创建许可")
        data["facts"][p["id"]] = {**common, "kind": kind, "evidence": proof, "permit_id": p.get("permit_id")}
        if target and not historical:
            if kind == "started":
                rules.require(target["state"] in {"start-authorized", "running", "unconfirmed"}, "动作不处于已获许可状态")
                grant = data["grants"].get(target.get("grant_id"))
                # A delayed receipt cannot revive a permit whose physical end was confirmed.
                rules.require(grant and grant.get("physical") != "end-confirmed", "资源已确认安全结束或原授权不存在，不能再次登记实际开始")
                target["state"] = "running"
            elif kind in TERMINAL:
                target["state"] = kind
            else:
                target["state"] = "unconfirmed"
            target["version"] += 1
            if target.get("grant_id"):
                grant = data["grants"][target["grant_id"]]
                if grant.get("physical") != "end-confirmed":
                    grant["physical"] = "in-use" if kind == "started" else "unknown" if target.get("permit_id") else "not-started"
        blocker_ids = p.get("blocker_ids", [])
        rules.require(isinstance(blocker_ids, list) and len(blocker_ids) <= 30 and len(set(blocker_ids)) == len(blocker_ids), "占用确认清单无效")
        if blocker_ids:
            rules.require(kind in {"stopped", "not-started"} and basis in {"human", "adapter"}, "解除未知占用须由有权人或受信适配器提供停止或隔离依据")
            for key in blocker_ids:
                blocker = state["security"].get("physical_blockers", {}).get(key) or data["legacy"].get(key) or data["blockers"].get(key)
                rules.require(blocker and blocker.get("claim_id") == claim["claim_id"] and blocker.get("epoch") == p["epoch"], "阻挡与原领取或授权代次不符，缺失旧代次需先补核")
                blocker.update(active=False, physical="end-confirmed", end_evidence=proof, end_reporter=actor, end_event=event_id)
                if key in data["grants"]:
                    data["grants"][key].update(physical="end-confirmed", version=data["grants"][key]["version"] + 1)
        _arbitrate(state, now, event_id)
        return
    target = data["actions"].get(p.get("action_id"))
    if op == "resource-cancel":
        request = data["resource_requests"].get(p["resource_request_id"])
        rules.require(request and request["executor_id"] == actor, "资源申请不存在或不属于本人")
        version(p["version"], request["version"])
        if request["state"] == "queued":
            request.update(state="cancelled", version=request["version"] + 1, event=event_id)
            target = data["actions"][request["action_id"]]
            target.update(state="prepared", version=target["version"] + 1)
            _arbitrate(state, now, event_id)
        return
    rules.require(target is not None, "动作不存在")
    claim, task = _claim(state, target)
    if op == "resource-release":
        grant = data["grants"].get(p["grant_id"])
        rules.require(grant and grant["action_id"] == target["id"] and grant["generation"] == p["generation"], "授权ID、动作或代次不符，不能释放其他授权")
        version(p["version"], grant["version"])
        proof = evidence(p["evidence"])
        basis = p["basis"]
        human = (rules.identity(state, actor) or {}).get("kind") == "human" and rules.manager(state, rules.task_project(task), actor)
        trusted = any(row.get("trusted") and row.get("actor") == actor and (claim["claim_id"] in row.get("claims", []) or row.get("executor_id") == claim["origin"])
                      for row in data["adapters"].values())
        if any(row["id"].startswith("app:") for row in grant["resources"]):
            trusted = False  # No automatic external-application physical-end confirmation in this release.
        rules.require(actor == target["executor_id"] or human or trusted, "无权归还此动作资源", "intent-final")
        safe = not target.get("permit_id") or basis == "human-isolation" and human or basis == "adapter-confirmed" and trusted
        rules.require(basis in {"unconfirmed", "human-isolation", "adapter-confirmed"}, "归还依据类型无效")
        # Physical end confirmation is final; repeated releases retain its evidence.
        if grant.get("physical") == "end-confirmed":
            return
        grant.update(state="released", physical="end-confirmed" if safe else "unknown", version=grant["version"] + 1,
                     release_evidence=proof, released_by=actor, release_event=event_id)
        for request in data["resource_requests"].values():
            if request.get("grant_id") == grant["id"]:
                request.update(state="released", version=request["version"] + 1)
        if not safe:
            data["blockers"][grant["id"]] = {"id": grant["id"], "claim_id": claim["claim_id"], "epoch": target["epoch"],
                "action_id": target["id"], "resources": deepcopy(grant["resources"]), "physical": "unknown", "active": True, "evidence": proof}
            target.update(state="unconfirmed", version=target["version"] + 1)
        elif grant["id"] in data["blockers"]:
            data["blockers"][grant["id"]].update(active=False, physical="end-confirmed", end_evidence=proof)
        _arbitrate(state, now, event_id)
        return
    rules.require(target["executor_id"] == actor, "动作不属于本人", "intent-final")
    version(p["version"], target["version"])
    segment = data["segments"][target["segment_id"]]
    rules.require(claim["epoch"] == target["epoch"] and claim["W"]["scope"] == target["scope_version"], "旧段只能留事实，不能取得新授权")
    selected = context_record(state, actor, {"context_id": segment["context_id"], "version": segment["context_version"]})
    authorization_operation = segment.get("authorization_operation", "claim")
    rules.require(target.get("authorization_operation", "claim") == authorization_operation, "动作与原段的授权操作类别不符")
    _new_permission(state, actor, claim, task, selected, now, p.get("authority"), authorization_operation)
    environments.check_mappings(state, target)
    if op == "resource-request":
        resources = normalize_resources(state, p["resources"])
        rules.require(resources == target["resources"], "请以新动作申请完整资源集合；不支持持锁追加或读写升级")
        rules.require(target["state"] in {"prepared", "queued"}, "动作已有授权或开始状态；不能持锁追加等待")
        _within(state, task, resources)
        _resource_permission(state, actor, task, resources)
        existing = next((row for row in data["resource_requests"].values() if row["action_id"] == target["id"] and row["state"] in {"queued", "granted"}), None)
        if existing:
            return
        data["sequence"] += 1
        resources = [{**row, **target.get("resource_proofs", {}).get(row["domain"] + "|" + row["id"], {})} for row in resources]
        data["resource_requests"][p["id"]] = {"id": p["id"], "action_id": target["id"], "version": 1, "sequence": data["sequence"],
            "executor_id": actor, "task_id": target["task_id"], "claim_id": target["claim_id"], "segment_id": target["segment_id"],
            "scope_version": target["scope_version"], "epoch": target["epoch"],
            "state": "queued", "resources": resources, "authority": deepcopy(p.get("authority")), "at": now, "event": event_id}
        target.update(state="queued", version=target["version"] + 1)
        _arbitrate(state, now, event_id)
        return
    if op == "action-start":
        grant = data["grants"].get(p["grant_id"])
        rules.require(grant and grant["action_id"] == target["id"] and grant["generation"] == p["generation"] and grant["state"] == "granted", "授权已变化或不属于此动作")
        rules.require(target["state"] in {"granted", "start-authorized"}, "启动结果不明或已执行，不能重新发出开始许可")
        rules.require(not any(row.get("id") != grant["id"] and row.get("action_id") != target["id"] and
                              _sets_conflict(state, grant["resources"], row["resources"]) for row in blocking_records(state)),
                      "资源等价关系或保护范围已变化；须先核实其他占用，不能按旧授权开始")
        _within(state, task, target["resources"])
        _resource_permission(state, actor, task, target["resources"])
        load = execution_load(state, actor, exclude_action=target["id"])
        rules.require(load["limit"] is None or load["executing"] < load["limit"], "实际动作并发名额已满，保留原资源申请等待核对")
        if not target.get("permit_id"):
            target.update(permit_id=p["permit_id"], state="start-authorized", version=target["version"] + 1)
            grant.update(physical="unknown", version=grant["version"] + 1)
        return
    rules.require(False, "未知执行操作")
