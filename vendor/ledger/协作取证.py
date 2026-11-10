#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Read-only artifact/Git checks and immutable close preparation, outside pure decisions."""
import json
from pathlib import Path
import re
import subprocess

from 协作存储 import Rejected, digest, encoded, publish, read_json, safe


def checked_file(root, reference):
    if not isinstance(reference, dict) or not isinstance(reference.get("path"), str) or not re.fullmatch(r"[0-9a-f]{64}", reference.get("sha256", "")):
        raise Rejected("文件引用须有相对路径与SHA256")
    path = safe(root, reference["path"])
    raw = path.read_bytes()
    if digest(raw) != reference["sha256"]:
        raise Rejected("文件指纹已变化：" + reference["path"])
    return raw


def manifest(desk, reference):
    raw = checked_file(desk.store, reference)
    data = json.loads(raw)
    outputs = output_contract(data)
    parent = Path(reference["path"]).parent.as_posix()
    seen = set()
    for item in outputs:
        name = item["path"]
        normalized = name.casefold()
        if normalized in seen or normalized == "manifest.json":
            raise Rejected("manifest输出重名或引用自身")
        seen.add(normalized)
        target = safe(desk.store, parent + "/" + name)
        content = target.read_bytes()
        if digest(content) != item["sha256"].lower() or len(content) != item["bytes"]:
            raise Rejected("manifest负载指纹不匹配：" + name)
    return digest(raw), data


def output_contract(data):
    outputs = data.get("outputs")
    if not isinstance(outputs, list) or not outputs:
        raise Rejected("manifest缺少输出清单")
    seen = set()
    for row in outputs:
        if (not isinstance(row, dict) or not isinstance(row.get("path"), str) or
                not isinstance(row.get("sha256"), str) or not re.fullmatch(r"[0-9a-fA-F]{64}", row["sha256"]) or
                type(row.get("bytes")) is not int or row["bytes"] < 0):
            raise Rejected("manifest输出路径/SHA/长度格式错误")
        key = row["path"].casefold()
        if key in seen or key == "manifest.json":
            raise Rejected("manifest输出重名或引用自身")
        seen.add(key)
    if sum(row["path"] == "delivery.json" for row in outputs) != 1:
        raise Rejected("manifest必须唯一包含受SHA和长度约束的delivery.json")
    return outputs


def repository_outputs(data):
    mapping = data.get("repository_outputs", {})
    if not isinstance(mapping, dict):
        raise Rejected("仓库路径映射须为对象")
    outputs = {row["path"]: row for row in output_contract(data)}
    result = {}
    for path, output in mapping.items():
        safe(Path(__file__).resolve().parents[2], path)
        if not isinstance(output, str) or output not in outputs:
            raise Rejected("仓库路径必须绑定已封存输出")
        result[path] = {"output": output, "sha256": outputs[output]["sha256"].lower()}
    return result


def accepted_bundle(state, task_id):
    task = state["tasks"].get(task_id)
    accepted = task and state["acceptances"].get(task.get("accepted"))
    c = accepted and state["claims"].get(accepted["claim_id"])
    rev = c and c["deliveries"].get(accepted["revision"])
    if not accepted or accepted["verdict"] != "accept" or accepted["scope_version"] != task["scope_version"] or not rev or rev["status"] != "accepted":
        raise Rejected("缺少当前范围有效接受记录", "retryable")
    reference = accepted.get("manifest") or rev.get("manifest")
    if not reference or reference["sha256"] != accepted["manifest_sha256"]:
        raise Rejected("接受记录未绑定manifest路径和SHA")
    return task, accepted, rev, reference


def typed_references(value):
    if isinstance(value, dict):
        if "path" in value and "sha256" in value:
            yield value
        else:
            for child in value.values():
                yield from typed_references(child)
    elif isinstance(value, list):
        for child in value:
            yield from typed_references(child)


def accepted_references(state, accepted):
    yield from typed_references(accepted.get("tested_artifacts", []))
    seen = set()
    def check_refs(check, acceptance_id):
        marker = (acceptance_id, check.get("id"))
        if marker in seen:
            return
        seen.add(marker)
        yield from typed_references(check.get("evidence"))
        reuse = check.get("reuse")
        if reuse:
            ref, name = reuse.split("/", 1)
            prior = state["acceptances"].get(ref)
            match = prior and next((x for x in prior["checks"] if x["id"] == name and x["status"] == "passed"), None)
            if not match:
                raise Rejected("复用的接受分项已不可追溯")
            yield from check_refs(match, ref)
    for check in accepted.get("checks", []):
        yield from check_refs(check, accepted["acceptance_id"])


def prepare_close(desk, env, state):
    p = env["payload"]
    task_id = p.get("task_id")
    if task_id is None:
        old = state["closings"].get(p.get("target")) or state["acceptances"].get(p.get("target"))
        task_id = old and old["task_id"]
    task, accepted, rev, accepted_manifest = accepted_bundle(state, task_id)
    required = [accepted_manifest]
    missing, observations = [], []
    try:
        data = json.loads(checked_file(desk.store, accepted_manifest))
        rows = output_contract(data)
        parent = Path(accepted_manifest["path"]).parent.as_posix()
        required += [{"path": parent + "/" + row["path"], "sha256": row["sha256"].lower()} for row in rows]
    except (OSError, ValueError, KeyError, TypeError) as error:
        missing.append({"reference": accepted_manifest, "reason": "接受清单不可复核：" + str(error)})
    required += list(accepted_references(state, accepted))
    # Explicit additions never replace the accepted manifest/output contract.
    required += p.get("evidence", [])
    unique = {encoded(reference): reference for reference in required}
    for reference in unique.values():
        try:
            checked_file(desk.store, reference)
            observations.append({"reference": reference, "status": "matched"})
        except (OSError, ValueError, KeyError, TypeError) as error:
            missing.append({"reference": reference, "reason": str(error)})
    # Include identifiers and conclusions; never copy raw diagnostic contents into the view.
    summary = {"task_id": task_id, "close_id": env["event_id"], "proven": p.get("proven", []),
               "acceptance_id": accepted["acceptance_id"], "accepted_manifest": accepted_manifest,
               "checked": observations, "missing": missing, "remaining": p.get("remaining", []), "result": "missing" if missing else "complete"}
    raw = ("# 收口摘要\n\n```json\n" + json.dumps(summary, ensure_ascii=False, indent=2) + "\n```\n").encode("utf-8")
    target = "summaries/" + str(task_id) + "/" + env["event_id"] + "-" + digest(raw)[:8] + ".md"
    path = safe(desk.store, target)
    if not publish(path, raw) and path.read_bytes() != raw:
        raise Rejected("摘要路径冲突")
    return {"summary": {"path": target, "sha256": digest(raw)}, "missing": missing,
            "acceptance_id": accepted["acceptance_id"], "accepted_manifest": accepted_manifest}


def inspect(desk, env, state):
    p, command = env["payload"], env["command"]
    result = {}
    if command.startswith("flow_"):
        from 协作流水 import inspect_flow
        return inspect_flow(desk, env, state)
    if command == 'pilot' and p.get('op') == 'task-issue-review' and p.get('verdict') == 'resolved':
        from 协作复查 import source
        checked = p.get('checked_source') or {}
        target = state.get('tasks', {}).get(checked.get('task_id'))
        if checked != source(state, target):
            raise Rejected('复核所指交付已变化')
        checksum, _ = manifest(desk, checked['manifest'])
        result['verified_manifests'] = {checksum}
    if command == 'pilot' and p.get('op') == 'task-repair-open' and p.get('include_original_delivery') is True:
        from 协作复查 import source
        baseline = p.get('baseline_source') or {}
        original = state.get('tasks', {}).get(baseline.get('task_id'))
        if baseline != source(state, original):
            raise Rejected('返修基线的原收口已变化')
        ref = baseline['manifest']
        _, data = manifest(desk, ref)
        prefix = ref['path'].rsplit('/', 1)[0]
        result['repair_baseline'] = {ref['path']: ref['sha256'],
            **{prefix + '/' + row['path']: row['sha256'].lower() for row in data['outputs']}}
    requested = p.get("resources", [])
    if command == "claim" and p.get("task_id") in state["tasks"]:
        requested = state["tasks"][p["task_id"]]["resources"]
    elif command in {"acquire", "resume"} and p.get("claim_id") in state["claims"] and "resources" not in p:
        requested = state["tasks"][state["claims"][p["claim_id"]]["task_id"]]["resources"]
    for raw in requested:
        if isinstance(raw, dict) and isinstance(raw.get("id"), str) and raw["id"].startswith("path:"):
            safe(Path(__file__).resolve().parents[2], raw["id"][5:])
    if command in {"seal", "review", "executor_complete"}:
        reference = p.get("manifest")
        if not reference:
            raise Rejected("须引用本机已收到的manifest载荷")
        inline = command == "seal" and "manifest_inline" in p
        if inline:
            if state["origins"].get(env["origin_id"], {}).get("local", True):
                raise Rejected("本地封存须核本机载荷，外平台回执才允许载荷待收")
            data = p["manifest_inline"]
            output_contract(data)
            checksum = digest(encoded(data))
            receipt = p.get("receipt_inline")
            if not isinstance(receipt, dict) or not isinstance(data.get("outputs"), list):
                raise Rejected("外平台封存须内附完整manifest与delivery合同")
            receipt_raw = encoded(receipt)
            outputs = data["outputs"]
            seen = set()
            for output in outputs:
                safe(desk.store, "unreceived-payload/" + output["path"])
                key = output["path"].casefold()
                if key in seen or key == "manifest.json" or not re.fullmatch(r"[0-9a-f]{64}", output.get("sha256", "")) or type(output.get("bytes")) is not int or output["bytes"] < 0:
                    raise Rejected("外平台manifest输出清单无效")
                seen.add(key)
            if not any(o["path"] == "delivery.json" and o["sha256"] == digest(receipt_raw) and o["bytes"] == len(receipt_raw) for o in outputs):
                raise Rejected("内附delivery不在manifest内或SHA不符")
            result["payload_status"] = "pending"
        else:
            checksum, data = manifest(desk, reference)
            receipt_path = Path(reference["path"]).parent.as_posix() + "/delivery.json"
            receipt = read_json(safe(desk.store, receipt_path))
            result["payload_status"] = "verified"
        if checksum != p.get("manifest_sha256"):
            raise Rejected("信封与manifest的SHA不同")
        if reference.get("sha256") != checksum:
            raise Rejected("载荷引用与manifest指纹不同")
        if data.get("claim_id", data.get("claimId")) != p.get("claim_id") or data.get("revision") != p.get("revision"):
            raise Rejected("manifest领取/修订归属不匹配")
        if command == "seal" and (data.get("inputs") != p.get("inputs") or data.get("scope_version") != p.get("scope_version")):
            raise Rejected("manifest输入/范围不匹配")
        c = state["claims"].get(p.get("claim_id"))
        if c and data.get("task_id", data.get("task")) != c["task_id"]:
            raise Rejected("manifest任务归属不匹配")
        safe(desk.store, reference["path"])
        if c and command == "seal" and not reference["path"].startswith("deliveries/" + c["task_id"] + "/" + c["claim_id"] + "/"):
            raise Rejected("封存只能引用本领取交付目录")
        if command == "seal" and any(receipt.get(key) != p.get(key, [] if key in {"remaining", "claimed_resolved"} else None)
                                     for key in ("claim_id", "revision", "inputs", "execution", "remaining", "claimed_resolved", "scope_version")):
            raise Rejected("封存信封与delivery.json合同不一致")
        result["verified_manifests"] = {checksum}
        result["manifest_data"] = data
        result["repository_outputs"] = repository_outputs(data)
        if command == "seal" and (receipt.get("repository_outputs", {}) != data.get("repository_outputs", {}) or
                                   p.get("repository_outputs", {}) != data.get("repository_outputs", {})):
            raise Rejected("仓库产物映射必须同时冻结在manifest、delivery与信封中")
        if state.get("flow_records"):
            from 协作流水 import included_records, verify_record
            if command == "seal":
                result["included_flow_records"] = included_records(state, p["claim_id"], p["revision"],
                                                                  {x["sha256"].lower() for x in data["outputs"]})
            else:
                c = state["claims"].get(p["claim_id"])
                rev = c and c["deliveries"].get(p["revision"])
                for key in rev.get("flow_record_ids", []) if rev else []:
                    verify_record(state["flow_records"][key]["reference"], state["flow_config"])
        for reference in p.get("tested_artifacts", []):
            checked_file(desk.store, reference)
        if command in {"review", "executor_complete"}:
            for reference in typed_references(p.get("checks", [])):
                checked_file(desk.store, reference)
    if command in {"close", "correction"} and (command == "close" or p.get("verdict") == "complete"):
        result["close_prepared"] = prepare_close(desk, env, state)
    if command == "commit_record":
        if type(p.get("pending_verification", False)) is not bool:
            raise Rejected("待验安全节点标记须为布尔值")
        accepted = None
        mapping = {}
        if not p.get("pending_verification", False):
            _, accepted, accepted_rev, accepted_manifest = accepted_bundle(state, p.get("task_id"))
            _, accepted_data = manifest(desk, accepted_manifest)
            mapping = repository_outputs(accepted_data)
            if mapping != accepted_rev.get("repository_outputs", {}):
                raise Rejected("接受产物映射与封存事实不一致")
        commit = p.get("commit", "")
        if not re.fullmatch(r"[0-9a-f]{40,64}", commit) or not p.get("paths"):
            raise Rejected("须有提交对象与逐路径清单")
        workspace = Path(__file__).resolve().parents[2]
        for item in p["paths"]:
            safe(workspace, item["path"])
            blob = subprocess.check_output(["git", "rev-parse", commit + ":" + item["path"]], cwd=workspace).decode().strip()
            if blob != item["blob_sha"]:
                raise Rejected("Git blob身份不符")
            content = subprocess.check_output(["git", "cat-file", "blob", blob], cwd=workspace)
            if digest(content) != item["sha256"]:
                raise Rejected("Git blob内容SHA不符")
            if accepted and (item["path"] not in mapping or mapping[item["path"]]["sha256"] != digest(content)):
                raise Rejected("Git内容与本任务当前已接受产物不符，继续待提交")
        result["git_verified"] = True
        result["accepted_commit_id"] = accepted["acceptance_id"] if accepted else None
    if command == "migration_import":
        reference = p.get("inventory")
        raw = checked_file(desk.store, reference)
        data = json.loads(raw)
        for file in data["files"]:
            checked_file(desk.store, file)
        result["migration_inventory"] = data
        result["legacy_payload_integrity"] = {}
        for cid, reference in data.get("manifests", {}).items():
            try:
                manifest(desk, reference)
                result["legacy_payload_integrity"][cid] = "verified"
            except (OSError, ValueError, KeyError, TypeError):
                result["legacy_payload_integrity"][cid] = "pending"
    return result
