"""Versioned execution instances and administrator-confirmed global storage mappings.

These records select collision proofs only. They never grant task/resource permission.
Filesystem observations are made in the HTTP planner and frozen in ledger payloads;
replay never probes the machine replaying the ledger.
"""
from copy import deepcopy
from pathlib import Path

from .packages import ClientError
import 协作升级 as rules
from 协作存储 import digest, encoded

OPS = {"environment-save", "resource-map-save", "storage-domain-register", "storage-domain-merge"}
TABLES = ("environments", "environment_history", "resource_mappings", "resource_mapping_history", "storage_domains", "storage_domain_parents", "storage_domain_merges")


def mapping_id(environment_id, domain):
    return "map-" + digest(encoded([environment_id, domain]))[:40]


def canonical_domain(state, domain_id):
    """Append-only equivalence also applies to historical frozen resource proofs."""
    parents = state.get("security", {}).get("execution", {}).get("storage_domain_parents", {})
    seen = set()
    while domain_id in parents and parents[domain_id] != domain_id:
        if domain_id in seen:
            raise ValueError("存储域等价关系损坏")
        seen.add(domain_id)
        domain_id = parents[domain_id]
    return domain_id


def require_domain(state, domain_id):
    rules.require(isinstance(domain_id, str) and domain_id in state["security"]["execution"].get("storage_domains", {}),
                  "物理存储域尚未由管理员确认")
    return canonical_domain(state, domain_id)


def local_mappings(state):
    """Current views plus historical views that still back a physical protection."""
    from 协作执行 import blocking_records
    data = state["security"]["execution"]
    protected = {(resource.get("mapping_id"), resource.get("mapping_version"))
                 for blocker in blocking_records(state) for resource in blocker["resources"]}
    candidates = {row["id"] + ":" + str(row["version"]): row for row in data["resource_mappings"].values() if row["active"]}
    candidates.update({key: row for key, row in data["resource_mapping_history"].items() if (row["id"], row["version"]) in protected})
    return [row for row in candidates.values() if row.get("mapping_kind", "server-local") == "server-local"]


def check_local_domain(state, observation, domain_id):
    """Do not export known local aliases as independent global domains via remote views."""
    from 协作执行 import conflict
    scope = {"id": "path:", "domain": "registry", "mode": "write", **observation.get("root_scope", {})}
    for row in local_mappings(state):
        other_domain = row.get("storage_domain_id")
        if row.get("mapping_kind", "server-local") != "server-local" or not other_domain or canonical_domain(state, other_domain) == canonical_domain(state, domain_id):
            continue
        other = {"id": "path:", "domain": "registry", "mode": "write", **row.get("root_scope", {})}
        rules.require(not conflict(state, scope, other),
                      "全局存储域与已知本地目录重叠或无法证明独立；须先核实并合并等价域，不能导出为独立远端映射")


def require_admin(state, actor):
    rules.require(rules.system_admin(state, actor), "环境和物理映射须由系统管理员确认", "intent-final")


def selected(state, actor, environment_id):
    row = state.get("security", {}).get("execution", {}).get("environments", {}).get(environment_id)
    rules.require(row and row["active"] and actor in row["executors"], "执行环境不存在、已停用或未绑定本窗口", "intent-final")
    return row


def check_context(state, actor, context):
    if context.get("environment_id"):
        selected(state, actor, context["environment_id"])


def check_mappings(state, action):
    """Revocation/remapping prevents new starts/grants, never clears old occupancy."""
    mappings = state.get("security", {}).get("execution", {}).get("resource_mappings", {})
    for proof in action.get("resource_proofs", {}).values():
        if proof.get("mapping_id"):
            current = mappings.get(proof["mapping_id"], {})
            rules.require(current.get("active") and current.get("version") == proof["mapping_version"],
                          "资源映射已变化或停用，请重新建立动作；原占用仍须确认归还")


def observe_root(value):
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        raise ClientError("映射根目录须为服务端可核实的绝对目录")
    try:
        root = Path(value).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("not a directory")
        info = root.stat()
        return {"root": str(root), "root_identity": f"{info.st_dev}:{info.st_ino}"}
    except (OSError, ValueError, RuntimeError) as error:
        raise ClientError("无法核实映射根目录；远端目录须先提供受信挂载，不能以环境名称推断") from error


def apply(state, p, actor, now, event_id):
    from 协作执行 import identifier, version, evidence
    require_admin(state, actor)
    data = state["security"]["execution"]
    if p["op"] == "storage-domain-register":
        sid = identifier(p["storage_domain_id"], "物理存储域编号")
        rules.require(sid not in data["storage_domains"], "物理存储域编号不可复用或改写；共享存储应沿用原域或合并")
        rules.require(p["independent"] is True, "新域须明确确认与现有其他存储域物理独立；共享目录请沿用已有域")
        rules.require(isinstance(p["label"], str) and 0 < len(p["label"].strip()) <= 160, "存储域名称无效")
        row = {"id": sid, "label": p["label"], "evidence": evidence(p["evidence"]), "independent": True,
               "confirmed_by": actor, "at": now, "event": event_id}
        data["storage_domains"][sid] = row
        data["storage_domain_parents"][sid] = sid
        return row
    if p["op"] == "storage-domain-merge":
        a, b = require_domain(state, p["storage_domain_id"]), require_domain(state, p["other_domain_id"])
        version(p["version"], len(data["storage_domain_merges"]))
        rules.require(a != b, "两个存储域已经等价，不得拆分")
        parent, child = sorted((a, b))
        mid = "merge-" + str(p["version"] + 1)
        row = {"id": mid, "version": p["version"] + 1, "storage_domain_id": p["storage_domain_id"],
               "other_domain_id": p["other_domain_id"], "canonical_domain": parent, "evidence": evidence(p["evidence"]),
               "confirmed_by": actor, "at": now, "event": event_id}
        data["storage_domain_parents"][child] = parent
        data["storage_domain_merges"][mid] = row
        return row
    eid = identifier(p["environment_id"], "执行环境编号")
    if p["op"] == "environment-save":
        previous = data["environments"].get(eid, {})
        version(p["version"], previous.get("version", 0))
        rules.require(isinstance(p["label"], str) and 0 < len(p["label"].strip()) <= 160, "环境名称无效")
        rules.require(isinstance(p["kind"], str) and p["kind"] in {"local", "cloud", "container", "remote", "unknown"}, "环境种类无效")
        executors = p["executors"]
        rules.require(isinstance(executors, list) and 0 < len(executors) <= 100 and
                      all(isinstance(x, str) for x in executors) and len(set(executors)) == len(executors), "环境须绑定明确窗口清单")
        rules.require(all((rules.identity(state, x) or {}).get("kind") == "executor" and (p["active"] is False or rules.active(state, x)) for x in executors), "环境只能绑定有效窗口")
        rules.require(type(p["active"]) is bool, "须明确环境是否启用")
        row = {"id": eid, "version": p["version"] + 1, "label": p["label"], "kind": p["kind"],
               "executors": sorted(executors), "active": p["active"], "confirmed_by": actor, "at": now, "event": event_id}
        data["environments"][eid] = row
        data["environment_history"][eid + ":" + str(row["version"])] = deepcopy(row)
        return row
    rules.require(eid in data["environments"], "请先登记执行环境")
    domain = p["domain"]
    rules.require(isinstance(domain, str) and 0 < len(domain) <= 160 and not any(ord(c) < 32 for c in domain), "资源域无效")
    mid = mapping_id(eid, domain)
    previous = data["resource_mappings"].get(mid, {})
    version(p["version"], previous.get("version", 0))
    rules.require(type(p["active"]) is bool, "须明确映射是否启用")
    storage_domain = p.get("storage_domain_id", "")
    if storage_domain:
        require_domain(state, storage_domain)
    if previous.get("storage_domain_id"):
        rules.require(storage_domain and canonical_domain(state, storage_domain) == canonical_domain(state, previous["storage_domain_id"]),
                      "既有映射不能切换到独立存储域以绕过旧占用；请核实并合并等价域")
    kind = p.get("mapping_kind", "server-local")
    rules.require(isinstance(kind, str) and kind in {"server-local", "attested-domain"}, "映射种类无效")
    if kind == "attested-domain":
        rules.require(bool(storage_domain), "远端映射须绑定管理员确认的全局存储域")
        observation = {"mapping_evidence": evidence(p.get("evidence"))}
    else:
        observation = p.get("root_observation")
        rules.require(isinstance(observation, dict) and {"root", "root_identity"} <= set(observation) <= {"root", "root_identity", "root_scope"} and
                      all(isinstance(observation[x], str) and observation[x] for x in ("root", "root_identity")), "映射缺少服务端目录核实")
        if storage_domain and p["active"]:
            rules.require(isinstance(observation.get("root_scope"), dict), "全局域绑定缺少本地目录范围证明")
            scope = observation["root_scope"]
            rules.require(not scope.get("resolved") or scope.get("identity") == observation["root_identity"], "目录扫描期间根身份已变化")
            check_local_domain(state, observation, storage_domain)
    row = {"id": mid, "environment_id": eid, "domain": domain, "version": p["version"] + 1,
           "active": p["active"], "mapping_kind": kind, "storage_domain_id": storage_domain, **deepcopy(observation), "confirmed_by": actor, "at": now, "event": event_id}
    data["resource_mappings"][mid] = row
    data["resource_mapping_history"][mid + ":" + str(row["version"])] = deepcopy(row)
    return row


def roots(state, actor, context):
    eid = context.get("environment_id")
    if not eid:
        return None
    selected(state, actor, eid)
    return {row["domain"]: row for row in state["security"]["execution"].get("resource_mappings", {}).values()
            if row["environment_id"] == eid and row["active"]}


def visible(state, actor, target):
    """Expose only the caller's (or authorized target's) instance labels, not local paths."""
    from .execution import can_profile
    data = state.get("security", {}).get("execution", {})
    admin = rules.system_admin(state, actor)
    rows = [deepcopy(row) for row in data.get("environments", {}).values()
            if admin or can_profile(state, actor, target) and target in row["executors"]]
    ids = {row["id"] for row in rows}
    if not admin:
        for row in rows:
            row["executors"] = [target]
    maps = [{key: deepcopy(value) for key, value in row.items() if key not in {"root", "root_identity", "root_scope", "mapping_evidence"}}
            for row in data.get("resource_mappings", {}).values() if row["environment_id"] in ids]
    domain_ids = set(data.get("storage_domains", {})) if admin else {row["storage_domain_id"] for row in maps if row.get("storage_domain_id")}
    domains = [{"id": sid, "label": data["storage_domains"][sid]["label"], "canonical_domain": canonical_domain(state, sid)}
               for sid in sorted(domain_ids)]
    return {"environments": rows, "resource_mappings": maps, "storage_domains": domains,
            "storage_domain_revision": len(data.get("storage_domain_merges", {})) if admin else None}
