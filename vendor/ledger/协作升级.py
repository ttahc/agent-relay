"""Task-pool contract v2. All decisions are replayed through the existing ledger."""

from datetime import datetime, timezone
import re

from 协作存储 import Rejected, digest, encoded


VERSION = 2
ROUND_VERSION = 3
PROJECT = "intranet-task-system"
PLATFORMS = {"codex": "CDX", "claude": "CLD", "gemini": "GEM", "external": "EXT"}
ROLES = {"manager", "executor", "receiver"}
MODES = {"source", "account", "user"}
CAP_ID = re.compile(r"[a-z][a-z0-9_-]{0,47}")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}")
SHA = re.compile(r"[0-9a-f]{64}")
LEVEL = {"declared": 1, "probed": 2, "verified": 3}
CASES = {f"A{i:02d}" for i in range(1, 35)}


def require(condition, message, category="retryable"):
    if not condition:
        raise Rejected(message, category)


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def enabled(state):
    return "format" in state["pilot"]


def identity(state, actor):
    return state["pilot"].get("identity:" + str(actor))


def active(state, actor):
    person = identity(state, actor)
    return person is not None and person["status"] == "active"


def responsible(state, actor):
    person = identity(state, actor)
    if person and person["kind"] != "legacy":
        return person["owner"]
    return None


def grant(state, project, actor):
    return state["pilot"].get(f"grant:{project}:{actor}", {"roles": [], "resources": []})


def project_record(state, project):
    return state["pilot"].get("project:" + str(project))


def roles(state, project, actor):
    subject = identity(state, actor)
    if not subject or subject["status"] != "active" or not project_record(state, project):
        return set()
    own = set(grant(state, project, actor)["roles"])
    if subject["kind"] == "human":
        return own
    if subject["kind"] == "executor" and active(state, subject["owner"]):
        parent = set(grant(state, project, subject["owner"])["roles"])
        from pool.delegation import effective_roles
        return effective_roles(state, project, actor, own if "manager" in parent else own & parent)
    return set()


def manager(state, project, actor):
    return "manager" in roles(state, project, actor)


def system_admin(state, actor):
    subject = identity(state, actor)
    return active(state, actor) and subject["kind"] == "human" and subject.get("admin") is True


def auth_stamp(state, actor, project):
    subject = identity(state, actor) or {}
    owner = identity(state, subject.get("owner")) or {}
    values = [subject.get("kind"), subject.get("owner"), subject.get("status"),
                           subject.get("credential", 0), owner.get("status"),
                           grant(state, project, actor), grant(state, project, subject.get("owner"))]
    from pool.delegation import stamp
    if delegated := stamp(state, actor, project):
        values.append(delegated)
    return digest(encoded(values))


def contract(task):
    return (task or {}).get("contract")


def visible(state, task, actor):
    spec = contract(task)
    return not spec or system_admin(state, actor) or bool(roles(state, spec["project_id"], actor))


def active_claims(state, task_id=None):
    return [claim for claim in state["claims"].values()
            if claim["L"] == "active" and (task_id is None or claim["task_id"] == task_id)]


def execution_limit_exempt(state, claim):
    """Only sealed, actually stopped work with no reservations can free a slot."""
    if claim.get("L") != "active" or claim.get("E", {}).get("state") != "stopped" or claim.get("R") != []:
        return False
    evidence = claim.get("stop_evidence")
    if not isinstance(evidence, str) or not evidence.strip():
        return False
    recovery = claim.get("recovery") or {}
    if not isinstance(recovery, dict) or recovery.get("status") not in {None, "resolved"}:
        return False
    claim_id = claim.get("claim_id")
    if not claim_id or any(r.get("active") and r.get("claim_id") == claim_id
                           for r in state.get("reservations", {}).values()):
        return False
    work = claim.get("W") or {}
    expected = {"review": "review", "complete": "accepted"}.get(work.get("state"))
    delivery = (claim.get("deliveries") or {}).get(work.get("revision"))
    if expected is None or not isinstance(delivery, dict) or delivery.get("status") != expected:
        return False
    manifest = delivery.get("manifest")
    return bool(isinstance(manifest, dict) and isinstance(manifest.get("path"), str) and manifest["path"].strip()
                and isinstance(manifest.get("sha256"), str) and SHA.fullmatch(manifest["sha256"])
                and delivery.get("manifest_sha256", manifest["sha256"]) == manifest["sha256"])


def execution_load(state, actor, exclude_claim=None):
    """Report held execution slots separately from active business claims.

    Stopped drafts, paused work and uncertain work keep their slots. Excluding
    the current claim is only for checking a restart; it never changes state.
    """
    if state.get('security',{}).get('schema',0)>=5:
        from 协作执行 import execution_load as action_load
        return action_load(state,actor,exclude_claim)
    from 协作本轮 import execution_settings
    claims = [c for c in active_claims(state) if c["origin"] == actor and c.get("claim_id") != exclude_claim]
    exempt = sum(execution_limit_exempt(state, c) for c in claims)
    executor = (identity(state, actor) or {}).get("kind") == "executor"
    limit = execution_settings(state, actor)["limit"] if executor else None
    occupying = len(claims) - exempt
    return {"active_claims": len(claims), "executing": occupying,
            "running": sum(c.get("E", {}).get("state") == "running" for c in claims),
            "awaiting_review": sum(c.get("W", {}).get("state") == "review" for c in claims),
            "limit_exempt": exempt, "limit": limit,
            "available": max(0, limit - occupying) if limit is not None else None}


def stop_if_running(claim, reason):
    from 协作命令 import stop
    if claim["E"]["state"] == "running":
        stop(claim, "pause")
        claim["control_reason"] = reason


def requirement_rows(rows, contextual=False):
    require(isinstance(rows, list) and 1 <= len(rows) <= 24, "领取能力要求须填写 1 至 24 项")
    output = []
    for row in rows:
        core={'id','kind','value','required','evidence'}
        require(isinstance(row, dict) and core <= set(row) <= core | ({'dimensions','verified_dimensions','allow_unknown'} if contextual else set()),
                "能力要求须填写标识、类别、值、必需性与证据级别")
        require(isinstance(row["id"], str) and CAP_ID.fullmatch(row["id"]) and
                isinstance(row["kind"], str) and row["kind"] in {"skill", "environment"} and type(row["required"]) is bool and
                isinstance(row["value"], str) and 0 < len(row["value"].strip()) <= 100 and
                isinstance(row["evidence"], str) and row["evidence"] in LEVEL,
                "能力要求格式无效")
        require(row["kind"] == "skill" or row["evidence"] in {"probed", "verified"}, "环境要求须有探测或验证证据")
        if contextual:
            from 协作执行 import DIMENSIONS
            for key in ('dimensions','verified_dimensions','allow_unknown'):
                values=row.get(key,[])
                require(isinstance(values,list) and all(isinstance(v,str) and v in DIMENSIONS for v in values)
                        and len(values)==len(set(values)), '能力依赖维度无效或重复')
            require(set(row.get('verified_dimensions',[]))<=set(row.get('dimensions',[])) and
                    set(row.get('allow_unknown',[]))<=set(row.get('dimensions',[])) and
                    not set(row.get('verified_dimensions',[])) & set(row.get('allow_unknown',[])),
                    '核实及允许未知的维度须属于依赖维度，二者不能重叠')
        output.append({**row, "value": row["value"].strip()})
    require(any(r["required"] for r in output) and len({r["id"] for r in output}) == len(output),
            "至少填写一项必需能力，能力标识须唯一")
    return output


def resources(rows):
    from 协作命令 import resource
    require(isinstance(rows, list) and len(rows) <= 30, "须明确声明资源数组")
    return [resource(row) for row in rows]


def iteration(state, data, project, task_id=None):
    require(isinstance(data, dict) and set(data) == {"goal", "previous", "next"},
            "迭代须声明目标和前后任务")
    require(isinstance(data["goal"], str) and 0 < len(data["goal"].strip()) <= 2000, "迭代目标无效")
    for key in ("previous", "next"):
        require(isinstance(data[key], list) and len(data[key]) <= 30, "迭代关联须为任务编号数组")
        require(all(isinstance(ref, str) and ref in state["tasks"] and ref != task_id and
                    task_project(state["tasks"][ref]) == project for ref in data[key]),
                "迭代关联须引用本项目的其他任务")
        require(len(set(data[key])) == len(data[key]), "迭代关联任务重复")
    return data


def task_project(task):
    return (contract(task) or {}).get("project_id")


def execution_context(state, actor):
    subject = identity(state, actor) or {}
    human = subject.get("kind") == "human"
    return {key: subject.get(key) or ("human" if human else "unknown")
            for key in ("platform", "model", "environment")}


def capability_dimensions(state, actor, kind, requested=None):
    executor = (identity(state, actor) or {}).get("kind") == "executor"
    defaults = ["platform", "environment"] if kind == "environment" else ["platform", "model", "environment"]
    if not executor:
        defaults = ["environment"] if kind == "environment" else []
    result = defaults if requested is None else requested
    require(isinstance(result, list) and len(result) <= 3 and
            all(isinstance(key, str) and key in {"platform", "model", "environment"} for key in result) and
            len(set(result)) == len(result), "能力适用维度须从 platform、model、environment 选择且不能重复")
    minimum = ({"platform", "environment"} if kind == "environment" else {"platform", "model"}) if executor else set()
    require(minimum <= set(result), "AI 技能须明确平台与模型；环境能力须明确平台与环境")
    return sorted(result)


def capability_record_context(state, actor, record, requested=None):
    """New records capture evidence scope; replay never relabels an old profile."""
    supplied = "execution_context" in record or "context_dimensions" in record
    if supplied:
        require("execution_context" in record and "context_dimensions" in record, "能力配置与适用维度须同时提供")
        scope = record["execution_context"]
        require(isinstance(scope, dict) and set(scope) == {"platform", "model", "environment"} and
                all(isinstance(value, str) and 0 < len(value) <= 160 for value in scope.values()), "能力执行配置无效")
        dimensions = capability_dimensions(state, actor, record["kind"], record["context_dimensions"])
        current = execution_context(state, actor)
        require(all(scope[key] == current[key] for key in dimensions), "能力证据适用配置已变化，请重新声明或申请核实")
    else:
        scope = execution_context(state, actor)
        dimensions = capability_dimensions(state, actor, record["kind"], requested)
    require("environment" not in dimensions or record.get("environment") == scope["environment"],
            "证据环境与所选执行配置不一致")
    return {"execution_context": dict(scope), "context_dimensions": dimensions}


def capability_context_status(state, actor, record):
    current = execution_context(state, actor)
    scope, dimensions = record.get("execution_context"), record.get("context_dimensions")
    if not isinstance(scope, dict) or not isinstance(dimensions, list):
        relevant = {"platform", "environment"} if record.get("kind") == "environment" else {"platform", "model", "environment"}
        recorded = record.get("recorded", record.get("at", 0))
        changes = (identity(state, actor) or {}).get("context_changes", [])
        changed = any(row.get("at", 0) >= recorded and relevant & set(row.get("dimensions", [])) for row in changes)
        return {"status": "legacy-review-required" if changed else "legacy-unknown", "applicable": not changed,
                "execution_context": None, "context_dimensions": None, "current_context": current,
                "reason": "旧证据未记录配置范围；配置变化后须重新声明或核实" if changed else "旧证据适用配置未知，暂按原合同兼容；未补造当前模型适用范围"}
    mismatched = [key for key in dimensions if scope.get(key) != current.get(key)]
    return {"status": "context-mismatch" if mismatched else "applicable", "applicable": not mismatched,
            "execution_context": dict(scope), "context_dimensions": list(dimensions), "current_context": current,
            "mismatched_dimensions": mismatched, "unknown_model": current["model"] == "unknown",
            "reason": "证据不适用于当前配置：" + "、".join(mismatched) if mismatched else "证据按明确适用维度匹配；不由模型名称推断能力"}


def claim_execution_context(state, task, actor, now):
    project = task_project(task)
    refs = []
    for requirement in (contract(task) or {}).get("requirements", []):
        key = f"cap:{project}:{actor}:{requirement['id']}"
        record = state["pilot"].get(key)
        if record and capability_matches(state, project, actor, requirement, now):
            refs.append({"key": key, "id": requirement["id"], "version": record.get("version", 0), "level": record["level"],
                         "context_status": capability_context_status(state, actor, record)["status"],
                         "execution_context": dict(record["execution_context"]) if record.get("execution_context") is not None else None,
                         "context_dimensions": list(record["context_dimensions"]) if record.get("context_dimensions") is not None else None})
    return {"execution_context": execution_context(state, actor), "capability_refs": refs}


def capability_matches(state, project, actor, requirement, now, execution_context=None):
    record = state["pilot"].get(f"cap:{project}:{actor}:{requirement['id']}")
    if state.get('security',{}).get('schema',0)>=5:
        from 协作执行 import match_context
        return bool(record and record['kind']==requirement['kind'] and
                    (requirement['value']=='*' or record['value']==requirement['value']) and
                    LEVEL[record['level']]>=LEVEL[requirement['evidence']] and record['expires']>now and
                    match_context(state,actor,record,execution_context,{**requirement,'project_id':project}))
    subject = identity(state, actor) or {}
    return bool(record and record["kind"] == requirement["kind"] and
                (requirement["value"] == "*" or record["value"] == requirement["value"]) and
                LEVEL[record["level"]] >= LEVEL[requirement["evidence"]] and record["expires"] > now and
                (requirement["kind"] != "environment" or record["environment"] == subject.get("environment", "human")) and
                (state.get('security',{}).get('schema',0)<5 or capability_context_status(state, actor, record)["applicable"]))


def release_current(state, gate):
    data = state["pilot"]
    release = data.get("release:" + gate, {})
    return release.get("status") == "closed" and (
        gate != data["format"]["upgrade"] and data["format"]["schema"] >= ROUND_VERSION or
        release.get("image") == data["format"]["image"]
    )


def dependency_rows(state, data, project, task_id=None):
    require(isinstance(data, list) and len(data) <= 30, "须明确声明前置条件数组")
    for row in data:
        require(isinstance(row, dict) and set(row) == {"task", "output", "criterion"} and
                all(isinstance(v, str) and 0 < len(v.strip()) <= 100 for v in row.values()), "前置条件须为任务、产出及判据")
        require(row["task"] in state["tasks"] and row["task"] != task_id and
                task_project(state["tasks"][row["task"]]) == project, "依赖须引用本项目的其他任务")
    return data


def eligible(state, task, actor, now, include_status=True, check_resources=True, execution_context=None):
    from 协作命令 import conflicts, expanded, grants
    spec = contract(task)
    if not spec:
        if enabled(state):
            subject = identity(state, actor) or {}
            if "executor" not in subject.get("legacy_roles", []):
                return ["旧任务需要迁移到获授权项目"], []
        return ([] if task["status"] == "available" or not include_status else ["任务已有领取或已结束"]), []
    project = spec["project_id"]
    missing, preferred = [], []
    if include_status and task["status"] != "available":
        missing.append("任务已有领取或已结束")
    if "executor" not in roles(state, project, actor):
        missing.append("缺少明确身份绑定或项目执行授权")
    if not spec["open"]:
        missing.append("任务待启动")
    gate = spec.get("gate")
    if gate and not release_current(state, gate):
        missing.append("升级验收尚无当前有效收口")
    if state["pilot"]["format"]["schema"] >= ROUND_VERSION:
        from 协作本轮 import blocked
        missing.extend(blocked(state, task, actor, now))
        subject = identity(state, actor) or {}
        if subject.get("token_expires", now + 1) <= now:
            missing.append("执行端凭据已到期")
        load = execution_load(state, actor)
        if include_status and state.get('security',{}).get('schema',0)<5 and subject.get("kind") == "executor" and load["executing"] >= load["limit"]:
            missing.append("窗口并发上限已满")
    for dep in task["dependencies"]:
        other = state["tasks"].get(dep["task"], {})
        if dep["criterion"] not in other.get("provided", {}).get(dep["output"], []):
            missing.append("前置产出待满足 " + dep["task"])
    subject = identity(state, actor) or {}
    for requirement in spec["requirements"]:
        if not capability_matches(state, project, actor, requirement, now, execution_context):
            (missing if requirement["required"] else preferred).append("能力缺项 " + requirement["id"])
    assigned = grant(state, project, actor)["resources"]
    if subject.get("kind") == "executor":
        owner_grant = grant(state, project, subject["owner"])
        limits = [assigned] if "manager" in owner_grant["roles"] else [assigned, owner_grant["resources"]]
    else:
        limits = [assigned]
    for requested in expanded(state, task["resources"]):
        if any(not any(grants(state, held["id"], requested["id"]) and
                       (requested["mode"] == "read" or held["mode"] != "read") for held in limit) for limit in limits):
            missing.append("缺少资源授权 " + requested["id"])
        if check_resources and state.get('security',{}).get('schema',0)<5 and any(r["active"] and conflicts(state, requested, r)
                                   for r in state["reservations"].values()):
            missing.append("资源占用冲突 " + requested["id"])
    return missing, preferred


def reviewer(state, task, actor):
    spec = contract(task)
    require(task["receiver"] == actor and "receiver" in roles(state, spec["project_id"], actor),
            "须为当前获授权的指定接收者", "intent-final")
    authors = {state["claims"][cid]["origin"] for cid in task["claims"]}
    if spec["review_mode"] == "user":
        require(identity(state, actor)["kind"] == "human" and spec.get("user_basis"), "须为已明确授权的人工确认")
    else:
        require(actor not in authors, "接收者参与了该任务交付链的制作", "intent-final")
        if spec["review_mode"] == "account":
            owner = responsible(state, actor)
            owners = {responsible(state, author) for author in authors}
            require(owner and None not in owners and owner not in owners, "须核对不同责任账号", "intent-final")


def completion_policy(task):
    return (contract(task) or {}).get("completion_policy", "review-required")


def direct_closer(state, task, actor):
    record = state.get("acceptances", {}).get((task or {}).get("accepted"), {})
    claim = state.get("claims", {}).get(record.get("claim_id"), {})
    return bool(completion_policy(task) == "executor-direct" and
                record.get("completion_kind") == "executor-direct" and record.get("independent") is False and
                record.get("origin") == actor == claim.get("origin") and record.get("scope_version") == task["scope_version"] and
                active(state, actor) and "executor" in roles(state, task_project(task), actor))


def task_spec(state, data, task_id=None):
    core = {"project_id", "iteration", "delivery", "requirements", "review_mode", "user_basis"}
    require(isinstance(data, dict) and (set(data) - {"completion_policy"} == core or set(data) - {"completion_policy"} == core | {"dispatch"} and
            state["pilot"].get("format", {}).get("schema", 0) >= ROUND_VERSION), "任务合同字段不完整")
    policy = data.get("completion_policy", completion_policy(state["tasks"][task_id]) if task_id else "review-required")
    require(isinstance(policy, str) and policy in {"review-required", "executor-direct"}, "完成策略无效")
    if task_id is not None:
        require(policy == completion_policy(state["tasks"][task_id]), "创建时的完成策略不可变更")
    project = data["project_id"]
    require(isinstance(project, str) and project_record(state, project), "须选择已登记项目")
    require(isinstance(data["delivery"], str) and 0 < len(data["delivery"].strip()) <= 2000, "须声明交付物")
    require(isinstance(data["review_mode"], str) and data["review_mode"] in MODES and isinstance(data["user_basis"], str) and
            (data["review_mode"] != "user" or 0 < len(data["user_basis"].strip()) <= 2000), "验收策略缺少明确依据")
    spec = {**data, **({"completion_policy": policy} if "completion_policy" in data or task_id and policy == "executor-direct" else {}), "requirements": requirement_rows(data["requirements"],state.get('security',{}).get('schema',0)>=5),
            "iteration": iteration(state, data["iteration"], project, task_id)}
    if "dispatch" in spec:
        from 协作本轮 import task_policy
        spec["dispatch"] = task_policy(state, project, spec["dispatch"])
    return spec


def guard(state, env, context):
    command, p = env["command"], env["payload"]
    if not enabled(state):
        return
    audit = p.get("_audit")
    require(isinstance(audit, dict) and audit.get("schema") == state["pilot"]["format"]["schema"], "该账本需要升级后的单写服务")
    if command == "pilot":
        return
    if state["pilot"]["format"]["maintenance"]:
        raise Rejected("服务处于维护窗口", "retryable")
    actor = audit["actor"]
    require(active(state, actor) or command in {"stopped", "release"}, "操作身份已停用或待确认", "intent-final")
    claim = state["claims"].get(p.get("claim_id"))
    task = state["tasks"].get(p.get("task_id")) or (state["tasks"][claim["task_id"]] if claim else None)
    spec = p.get("contract") if command == "register" else contract(task)
    if state.get('security',{}).get('schema',0)>=5 and task and command in {'stopped','close'}:
        from 协作执行 import blocking_records
        require(not any(row.get('claim_id') in task.get('claims',[]) and
                        (command=='close' or row.get('kind')!='legacy-claim' and
                         not str(row.get('id','')).startswith('legacy:')) for row in blocking_records(state)),
                '动作或物理占用尚未安全结束；先回报事实并核对具体资源归还')
    if command == "register":
        require(spec, "新任务须填写完整的项目与能力合同")
        spec = task_spec(state, spec)
        project = spec["project_id"]
        require(manager(state, project, actor) or ("receiver" in roles(state, project, actor) and actor == p["receiver"]),
                "无项目登记授权", "intent-final")
        require("receiver" in roles(state, project, p["receiver"]), "接收者须有本项目授权")
        if spec["review_mode"] == "user":
            require(manager(state, project, actor) and identity(state, p["receiver"])["kind"] == "human", "人工直接接受须由项目管理员明确授权")
        dependency_rows(state, p["dependencies"], project)
    if not spec:
        if task and command == "claim":
            missing, _ = eligible(state, task, actor, context["now"])
            require(not missing, "；".join(missing))
        return
    project = spec["project_id"]
    if command in {"claim", "acquire", "resume", "seal", "ack_scope", "register", "review", "executor_complete", "close"}:
        require(audit.get("authorization") == auth_stamp(state, actor, project), "授权已变更，须重新核对")
    if command in {"claim", "acquire", "resume", "seal", "ack_scope"}:
        require(actor == (claim["origin"] if claim else env["origin_id"]), "执行身份与领取不符", "intent-final")
        selected_context=None
        if state.get('security',{}).get('schema',0)>=5 and command in {'claim','resume','acquire'}:
            require(p.get('execution_protocol')==5,'新领取须明确执行协议5，旧客户端不能降级领取')
            if p.get('context_id'):
                from 协作执行 import context_record
                selected_context=context_record(state,actor,{'context_id':p['context_id'],'version':p.get('context_version')})
        if state.get('security',{}).get('schema',0)>=5 and command in {'acquire','resume'}:
            require(audit.get('operation')=='resume','新工作回合须明确继续任务；资源按动作申请')
        if command == 'seal':
            require('executor' in roles(state, project, actor), '正式交付需要当前项目授权；已有产物可走受限暂存')
            missing = []
        else:
            missing, _ = eligible(state, task, actor, context["now"], command == "claim", command == "claim",selected_context)
        require(not missing, "；".join(missing))
        if command in {"acquire", "resume"}:
            if state["pilot"]["format"]["schema"] >= ROUND_VERSION:
                require(claim and env["expects"].get("epoch:" + claim["claim_id"]) == claim["epoch"],
                        "须声明当前执行代次")
                load = execution_load(state, actor, exclude_claim=claim["claim_id"])
                require(load["limit"] is None or load["executing"] < load["limit"], "窗口并发上限已满")
        require(not spec.get("gate") or context.get("release_verified"), "升级收口证据需重新核对")
    if command == "claim" and p.get("notice"):
        from 协作本轮 import automation_allowed, ready_key
        require(state["pilot"]["format"]["schema"] >= ROUND_VERSION and p["notice"] == ready_key(task, actor) and
                automation_allowed(state, task, actor), "通知已过期或自动执行授权不足")
    if command == "executor_complete":
        require(claim and actor == claim["origin"] == env["origin_id"] and
                completion_policy(task) == "executor-direct" and "executor" in roles(state, project, actor),
                "直接完成需要创建时授权及当前执行权限", "intent-final")
    if command in {"review", "close"}:
        if command != "close" or not direct_closer(state, task, actor):
            reviewer(state, task, actor)
    if command == "withdraw_delivery" and state["pilot"]["format"]["schema"] >= ROUND_VERSION:
        require("executor" in roles(state, project, actor), "撤回交付需要当前项目执行权限", "intent-final")
        require(audit.get("authorization") == auth_stamp(state, actor, project), "授权已变更，须重新核对")
    if command == "cancel":
        require(manager(state, project, actor) or (actor == task["receiver"] and "receiver" in roles(state, project, actor)),
                "无项目取消授权", "intent-final")


def user_acceptance(state, task, actor):
    spec = contract(task)
    return bool(spec and spec["review_mode"] == "user" and actor == task["receiver"])


def action(state, env, context):
    from 协作命令 import finish, no_cycles, release_one, stop, TERMINAL
    p = env["payload"]
    op = p["op"]
    actor = p["_audit"]["actor"]
    data = state["pilot"]
    if op == "migrate":
        require(not enabled(state) and "admin" in state["origins"], "须有初始管理员和旧版数据")
        task = state["tasks"].get(p["task_id"])
        require(task and task["status"] == "available" and not active_claims(state, p["task_id"]),
                "T02 已有活动或状态变更，先办理真实停止及处置")
        data["format"] = {"schema": VERSION, "min_reader": VERSION, "maintenance": True,
                          "image": p["image"], "upgrade": p["upgrade"]}
        data["serial"] = 0
        data["project:" + PROJECT] = {"id": PROJECT, "name": "任务协作平台", "owner": "admin", "previous_names": [], "version": 1}
        for name in state["origins"]:
            kind = "service" if name in {state["coordinator"], "pilot-committer"} else "legacy"
            data["identity:" + name] = {"kind": kind, "owner": name, "status": "active", "credential": 1,
                                       "legacy_roles": state["origins"][name]["roles"] if kind == "legacy" else []}
        data["identity:admin"].update(kind="human", admin=True)
        data[f"grant:{PROJECT}:admin"] = {"roles": ["manager"], "resources": [], "version": 1}
        data["release:" + p["upgrade"]] = {"status": "pending", "image": p["image"], "by": actor}
        spec = task_spec(state, p["contract"], task["task_id"])
        task["contract"] = {**spec, "open": False, "gate": p["upgrade"]}
        task["scope_version"] += 1
        return
    require(enabled(state), "请先完成数据合同迁移")
    fmt = data["format"]
    from 协作本轮 import OPS, action as round_action
    if op in OPS:
        return round_action(state, env, context)
    task = state["tasks"].get(p.get("task_id"))
    project = p.get("project_id") or task_project(task)
    if fmt["maintenance"]:
        require(op in {"maintenance", "bind", "project", "grant"}, "服务处于维护窗口")
    if op == "maintenance":
        require(system_admin(state, actor), "仅管理员可调整维护模式", "intent-final")
        fmt["maintenance"] = p["enabled"]
    elif op == "project":
        existing = project_record(state, project)
        require(manager(state, project, actor) if existing else system_admin(state, actor), "无项目管理授权", "intent-final")
        require((existing or {}).get("version", 0) == p["version"], "项目版本已变化")
        require(not any(k.startswith("project:") and v["id"] != project and v["name"].casefold() == p["name"].casefold()
                        for k, v in data.items()), "项目名称已使用")
        previous = existing["previous_names"] + [existing["name"]] if existing and existing["name"] != p["name"] else (
            existing or {}).get("previous_names", [])
        data["project:" + project] = {"id": project, "name": p["name"], "owner": (existing or {}).get("owner", actor),
                                      "previous_names": previous, "version": p["version"] + 1}
        if not existing:
            data[f"grant:{project}:{actor}"] = {"roles": ["manager"], "resources": [], "version": 1}
    elif op == "bind":
        require(system_admin(state, actor), "仅管理员可确认原身份绑定", "intent-final")
        subject = identity(state, p["name"])
        require(subject and subject["kind"] == "legacy" and p["name"] in state["origins"], "仅可绑定待确认的原账号")
        if p["kind"] == "human":
            subject.update(kind="human", owner=p["name"], binding_reason=p["reason"])
        else:
            require(active(state, p["owner"]) and identity(state, p["owner"])["kind"] == "human", "须指定已确认的人员账号")
            assign_window(state, p["name"], p["owner"], p["source"])
            identity(state, p["name"])["legacy_roles"] = subject["legacy_roles"]
        for claim in active_claims(state):
            if claim["origin"] == p["name"]:
                stop_if_running(claim, "身份绑定变更")
    elif op == "grant":
        require(manager(state, project, actor), "无项目授权管理权限", "intent-final")
        subject = identity(state, p["name"])
        require(subject and subject["kind"] in {"human", "executor"}, "须先确认人员或执行端身份")
        current = grant(state, project, p["name"])
        require(current.get("version", 0) == p["version"], "授权版本已变化")
        require(subject["kind"] == "human" or "manager" not in p["roles"], "项目管理须由人员账号承担")
        require(project_record(state, project)["owner"] != p["name"] or "manager" in p["roles"], "项目负责人须保有管理授权")
        base = state["origins"][p["name"]]
        base["roles"] = sorted(set(base["roles"]) | (set(p["roles"]) - {"manager"}))
        data[f"grant:{project}:{p['name']}"] = {"roles": p["roles"], "resources": resources(p["resources"]), "version": p["version"] + 1}
        fence(state, context["now"], project=project)
    elif op == "enroll":
        require(active(state, actor) and identity(state, actor)["kind"] == "human", "须由已绑定人员登记执行端")
        allowed = roles(state, project, actor)
        require("manager" in allowed or set(p["roles"]) <= allowed, "执行端角色须在责任账号授权内")
        require(project_record(state, project) and not identity(state, p["name"]) and p["name"] not in state["origins"],
                "项目或新执行端身份有冲突")
        assign_window(state, p["name"], actor, p["source"])
        identity(state, p["name"])["last_contact"] = context["now"]
        if fmt["schema"] >= ROUND_VERSION:
            from 协作本轮 import TOKEN_SECONDS
            identity(state, p["name"])["token_expires"] = int(context["now"]) + TOKEN_SECONDS
        state["origins"][p["name"]] = {"roles": ["executor", "receiver"], "local": False, "version": 0}
        data[f"grant:{project}:{p['name']}"] = {"roles": p["roles"], "resources": grant(state, project, actor)["resources"], "version": 1}
    elif op == "sync":
        subject = identity(state, actor)
        require(active(state, actor) and subject["kind"] == "executor", "执行端不可续接")
        if p["session"] != subject["session"]:
            subject.update(status="disputed", conflict_session=p["session"])
            for claim in active_claims(state):
                if claim["origin"] == actor:
                    stop_if_running(claim, "窗口来源冲突")
        else:
            before = execution_context(state, actor)
            platform = p.get("platform", before["platform"])
            require(platform == before['platform'], '来源平台不能通过配置同步更改；请办理身份来源更正')
            require(isinstance(platform, str) and platform in PLATFORMS and not any(key != "identity:" + actor and key.startswith("identity:") and
                    row.get("platform") == platform and row.get("session") == subject["session"] for key, row in data.items()),
                    "平台无效或该平台会话已由其他窗口登记")
            after = {"platform": platform, "model": p["model"], "environment": p["environment"]}
            dimensions = sorted(key for key in before if before[key] != after[key])
            if dimensions:
                subject.setdefault("context_changes", []).append({"before": before, "after": dict(after),
                    "dimensions": dimensions, "at": context["now"], "event": env["event_id"]})
                subject["context_version"] = subject.get("context_version", 0) + 1
            subject.update(**after, last_contact=context["now"])
            if "window_name" in p:
                subject["window_name"] = p["window_name"]
            # Profile edits are not stop acknowledgements and do not alter E/L/R/epoch.
    elif op == "credential":
        subject = identity(state, p["name"])
        require(subject and subject["kind"] in {"human", "executor"} and not subject.get("admin"), "此身份不在普通凭据处置范围")
        require(system_admin(state, actor) or (subject["kind"] == "executor" and subject["owner"] == actor and active(state, actor)),
                "须为责任账号或管理员", "intent-final")
        require(subject["credential"] == p["version"], "凭据版本已变化")
        if subject["kind"] == "executor" and fmt["schema"] >= ROUND_VERSION:
            require(p["status"] == "disabled", "重新启用须通过新令牌激活流程")
            from pool.window_admin import apply
            apply(state, {"op": "window-admin", "operation": "disable", "name": p["name"],
                          "version": p["version"], "reason": p["reason"]}, actor, context["now"], env["event_id"])
            return
        subject.update(credential=p["version"] + 1, status=p["status"], credential_reason=p["reason"])
        fence(state, context["now"])
    elif op == "capability":
        subject = identity(state, p["name"])
        require(active(state, p["name"]) and subject["kind"] != "service" and
                roles(state, project, p["name"]), "能力须绑定本项目已确认的执行身份")
        if p["record"]["level"] in {"probed", "verified"}:
            require(state.get('security',{}).get('schema',0)<5 or (identity(state,actor) or {}).get('kind')=='human',
                    '探测或核实等级须由有项目授权的人类办理，不能由AI相互核实','intent-final')
            require((manager(state, project, actor) or "receiver" in roles(state, project, actor)) and
                    actor != p["name"], "验证须由另一项目管理者或接收者办理")
        else:
            require(actor == p["name"] or responsible(state, p["name"]) == actor, "能力声明须由本人或责任账号办理")
        key = f"cap:{project}:{p['name']}:{p['id']}"
        version = data.get(key, {}).get("version", 0)
        require(version == p["version"], "能力记录版本已变化")
        record = {**p["record"], "by": actor, "recorded": context["now"], "version": version + 1}
        if state.get('security',{}).get('schema',0)>=5:
            from 协作执行 import bind_evidence, context_record, default_context
            if record.get('context_id'):
                context_key=str(record['context_id'])+':'+str(record['context_version'])
                if context_key not in state.get('security',{}).get('execution',{}).get('contexts',{}):
                    initial=default_context(state,p['name'])
                    require(initial['context_id']==record['context_id'] and initial['version']==record['context_version'],
                            '证据绑定的配置不存在，不能自动替换为其他配置')
                    default_context(state,p['name'],True,context['now'],env['event_id'])
            selected=context_record(state,p['name'],{'context_id':record['context_id'],'version':record['context_version']}) if record.get('context_id') else None
            record.update(bind_evidence(state,p['name'],record,selected,project,p['id'],
                                       list(record.get('applicability',{}).get('dependencies',{})),record['level'] in {'verified','probed'}))
        require(record["expires"] > context["now"], "能力证据已到期")
        data[key] = record
        # Existing claims retain their facts; later operations recheck applicable evidence.
    elif op in {"publish", "hold", "scope"}:
        require(task and task["status"] not in TERMINAL and manager(state, project, actor), "须为项目管理员且任务尚未终结")
        spec = contract(task)
        require(spec and task["scope_version"] == p["scope_version"], "范围版本已变化")
        require(not task.get("cancel_requested") and not task.get("accepted"), "任务处于取消或已接受阶段")
        if op == "publish":
            gate = spec.get("gate")
            require(not gate or (release_current(state, gate) and context.get("release_verified")), "缺少与本版本相符的有效升级收口")
            require(not task.get("change_pending") and not task.get("decision_holds"), "先处理任务关系或决定待核")
            require("receiver" in roles(state, project, task["receiver"]), "须先确认接收者身份与项目授权")
            spec.pop("hold_reason", None)
            spec.update(open=True, publication=env["event_id"], publication_reason=p["reason"])
        else:
            spec.update(open=False, hold_reason=p["reason"])
            if op == "scope":
                require(all(c["W"]["state"] in {"draft", "revision"} for c in active_claims(state, task["task_id"])),
                        "须先处理已封存修订再调整执行范围")
                change = task_spec(state, p["contract"], task["task_id"])
                require(change["project_id"] == project, "范围调整须保留任务项目")
                if change.get("dispatch") != spec.get("dispatch") and "dispatch" in change:
                    require(not active_claims(state, task["task_id"]), "先核对停止并结束活动领取，再改预指定")
                require(change["review_mode"] != "user" or identity(state, task["receiver"])["kind"] == "human", "人工确认须指定人员账号")
                spec.update(change)
                task["dependencies"] = dependency_rows(state, p["dependencies"], project, task["task_id"])
                no_cycles(state)
                task["resources"] = resources(p["resources"])
                task["scope_version"] += 1
            for claim in active_claims(state, task["task_id"]):
                stop_if_running(claim, p["reason"])
                if op == "scope":
                    claim["W"] = {"scope": task["scope_version"], "state": "draft",
                                  "revision": len(claim["deliveries"]) + 1}
                    claim["scope_ack_pending"] = True
    elif op in {"interrupt", "resolve"}:
        require(task and contract(task), "任务未纳入项目")
        claim = state["claims"].get(p["claim_id"])
        require(claim in active_claims(state, task["task_id"]) and claim["epoch"] == p["epoch"], "领取或代次已变化")
        if op == "interrupt":
            require(manager(state, project, actor) or claim["origin"] == actor, "仅管理员或持有者可记录中断")
            require(not claim.get("recovery") or claim["recovery"]["status"] != "pending", "已有恢复待核记录")
            stop_if_running(claim, p["reason"])
            claim["recovery"] = {"status": "pending", "reason": p["reason"], "by": actor, "event": env["event_id"]}
        else:
            require(manager(state, project, actor) and claim.get("recovery", {}).get("status") == "pending", "仅项目管理员可处置恢复待核")
            if p["unresolved"]:
                claim["recovery"].update(by=actor, evidence=p["evidence"], decision=p["reason"],
                                         unresolved=p["unresolved"], material=p["replacement"])
                task["contract"].update(open=False, hold_reason="外部效果待核：" + p["unresolved"])
                return
            claim["recovery"].update(status="resolved", by=actor, evidence=p["evidence"],
                                     decision=p["reason"], unresolved=p["unresolved"])
            work = claim["W"]["state"]
            if work in {"draft", "revision"} and not task.get("cancel_requested"):
                stop(claim, "replace")
                claim["replacement"] = p["replacement"]
            require(claim["E"]["state"] in {"requested", "stopped"}, "须先记录中断")
            claim["E"] = {"state": "stopped", "reason": claim["E"]["reason"]}
            claim["stop_evidence"] = p["evidence"]
            for rid in list(claim["R"]):
                release_one(state, claim, rid, p["evidence"])
            finish(state, claim)
    elif op in {"release-accept", "release-close", "release-correct"}:
        release = data["release:" + fmt["upgrade"]]
        if op == "release-accept":
            require("receiver" in roles(state, PROJECT, actor) and responsible(state, actor) != responsible(state, release["by"]),
                    "升级验收须由另一责任账号的接收者办理", "intent-final")
            require(release["status"] in {"pending", "invalid"} and context.get("release_verified"),
                    "升级证据未通过校验")
            release.update(status="accepted", acceptance=env["event_id"], evidence=p["evidence"], receiver=actor, reason=p["reason"])
        elif op == "release-close":
            require(manager(state, PROJECT, actor) and release["status"] == "accepted" and
                    release["acceptance"] == p["acceptance"] and context.get("release_verified"), "须复核本次独立验收及证据")
            release.update(status="closed", closing=env["event_id"], closed_by=actor, reason=p["reason"])
        else:
            require(manager(state, PROJECT, actor) and release["status"] in {"accepted", "closed"}, "没有可更正的升级结论")
            release.update(status="invalid", correction=env["event_id"], reason=p["reason"])
            fence(state, context["now"])
    else:
        raise Rejected("未知升级命令")


def assign_window(state, name, owner, source):
    data = state["pilot"]
    require(not any(v.get("platform") == source["platform"] and v.get("session") == source["session"]
                    for k, v in data.items() if k.startswith("identity:")), "该平台会话已登记，请沿用其执行端")
    data["serial"] += 1
    data["identity:" + name] = {"kind": "executor", "owner": owner, "status": "active", "credential": 1,
                                **source, "window": f"{PLATFORMS[source['platform']]}-{data['serial']:04d}",
                                "number": data["serial"]}


def fence(state, now, project=None, executor=None):
    for claim in active_claims(state):
        task = state["tasks"][claim["task_id"]]
        if not contract(task) or (project and task_project(task) != project) or (executor and claim["origin"] != executor):
            continue
        missing, _ = eligible(state, task, claim["origin"], now, include_status=False, check_resources=False)
        if missing:
            stop_if_running(claim, "；".join(missing))


def verify_report(state, report, release_id=None):
    fmt = state["pilot"]["format"]
    release_id = release_id or fmt["upgrade"]
    release = state["pilot"].get("release:" + release_id, {})
    image = fmt["image"] if release_id == fmt["upgrade"] else release.get("image")
    require(isinstance(report, dict) and report.get("upgrade") == release_id and report.get("image") == image,
            "验收报告与当前发布版本不一致")
    baseline, cases = report.get("baseline", {}), report.get("cases")
    needed = {f"N{i:02d}" for i in range(1, 55)} if release.get("schema", 0) >= ROUND_VERSION else CASES
    require(isinstance(baseline, dict) and type(baseline.get("passed")) is int and baseline["passed"] >= 110 and
            baseline.get("failed") == 0 and baseline.get("ext4") == 33 and
            isinstance(cases, dict) and set(cases) == needed and all(
                isinstance(result, dict) and result.get("status") == "passed" and
                isinstance(result.get("evidence"), str) and bool(result["evidence"].strip()) for result in cases.values()),
            "须提供基线及本版所有必过场景的通过证据")
