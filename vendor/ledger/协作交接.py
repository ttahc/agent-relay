#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Frozen claim ZIPs and payload-first imports. Never extracts into product sources."""
import io
import json
from pathlib import Path
import stat
import uuid
import zipfile

from 协作存储 import digest, encoded, publish, safe
from 协作取证 import checked_file
from 协作账本 import cursor


def export_claim(desk, claim_id, output):
    snap = desk.read()
    if snap["halted"]:
        raise ValueError("账本停写期间不重新发放领取包")
    c = snap["state"]["claims"][claim_id]
    task = snap["state"]["tasks"][c["task_id"]]
    if c["L"] != "active" or c["scope_ack_pending"]:
        raise ValueError("领取已结束或范围待确认")
    header = {"schema": 1, "repo_id": desk.meta["repo_id"], "task_id": c["task_id"], "claim_id": claim_id,
              "origin_id": c["origin"], "origin_seq_next": cursor(snap, c["origin"]) + 1, "exec_epoch": c["epoch"],
              "scope_version": c["W"]["scope"], "head": snap["head"], "head_sha256": snap["sha256"],
              "inputs": c["inputs"], "execution": c["execution"], "completes_on": task["completes_on"]}
    payload = {"CLAIM.json": encoded(header), "inputs.json": encoded(c["inputs"]),
               "START.md": ("# 单项领取包\n\n先读CLAIM.json与本卡固定输入。保留origin_id、event_id及递增origin_seq；导入批次不改变来源。\n"
                            "新的共享副作用前核对领取E、epoch、scope及资源；暂停/取消先停止新动作，再报告实际结束。\n"
                            "旧范围载荷只匹配既有封存记录，不恢复写资格。交付按新revision追加，不覆盖旧交付。\n"
                            "执行权限只看CLAIM.json；不会因本包恢复其它任务、启用其它模型或允许部署/提交。\n").encode("utf-8")}
    for path, sha in c["inputs"].items():
        payload["frozen/" + path] = checked_file(desk.store, {"path": path, "sha256": sha})
    manifest = {"files": [{"path": path, "bytes": len(raw), "sha256": digest(raw)} for path, raw in sorted(payload.items())]}
    payload["manifest.json"] = encoded(manifest)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, raw in sorted(payload.items()):
            archive.writestr(path, raw)
    raw = stream.getvalue()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if set(archive.namelist()) != set(payload) or any(archive.read(path) != data for path, data in payload.items()):
            raise ValueError("领取ZIP逐字节回验失败")
    target = safe(desk.store, output)
    if not publish(target, raw):
        raise ValueError("不覆盖旧领取包")
    return {"path": str(target), "sha256": digest(raw), "head": snap["head"], "origin_id": c["origin"]}


def import_package(desk, package, expected_sha256, importer):
    raw = Path(package).read_bytes()
    if digest(raw) != expected_sha256:
        raise ValueError("外部ZIP的SHA不符")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        names = [entry.filename for entry in members]
        if (len(members) > 5000 or len({x.casefold() for x in names}) != len(names) or
                sum(entry.file_size for entry in members) > 200 * 1024 * 1024):
            raise ValueError("ZIP重名或超出文件/解压大小上限")
        for entry in members:
            safe(desk.store, "import-staging/" + entry.filename)
            if entry.is_dir() or stat.S_ISLNK(entry.external_attr >> 16):
                raise ValueError("交付ZIP只接受普通文件")
        header = json.loads(archive.read("PACKAGE.json"))
        if header["repo_id"] != desk.meta["repo_id"] or header["kind"] not in {"proposal", "delivery"}:
            raise ValueError("外包协调仓库或类型不符；包内T号不能自行登记")
        declared = header["files"]
        if set(names) != {x["path"] for x in declared} | {"PACKAGE.json"}:
            raise ValueError("ZIP与文件清单不一致")
        data = {}
        for ref in declared:
            content = archive.read(ref["path"])
            if len(content) != ref["bytes"] or digest(content) != ref["sha256"]:
                raise ValueError("ZIP负载指纹不符")
            data[ref["path"]] = content
    state = desk.read()["state"]
    if header["kind"] == "delivery":
        c = state["claims"].get(header.get("claim_id"))
        if not c or c["origin"] != header["origin_id"]:
            raise ValueError("交付来源不是领取包分配的origin_id")
        prefix = "payload/deliveries/" + c["task_id"] + "/" + c["claim_id"] + "/"
    else:
        prefix = None
    envelopes = []
    payloads = []
    for path, content in data.items():
        if path.startswith("envelopes/"):
            env = json.loads(content)
            if env.get("origin_id") != header["origin_id"] or env.get("repo_id") != header["repo_id"]:
                raise ValueError("包头与信封来源不符")
            if header["kind"] == "proposal" and env.get("command") not in {"propose", "feedback"}:
                raise ValueError("外平台提议包不能获得调度或执行权限")
            if header["kind"] == "delivery" and (env.get("payload", {}).get("claim_id") != c["claim_id"] or
                                                    env.get("command") not in {"seal", "stopped", "release", "ack_scope", "withdraw_delivery", "note"}):
                raise ValueError("交付包命令不属于该领取")
            envelopes.append(env)
        elif prefix and path.startswith(prefix):
            payloads.append((path[8:], content))
        else:
            raise ValueError("ZIP不能写产品、账本、其它领取或未知目录")
    if not envelopes:
        raise ValueError("外包没有信封")
    original = safe(desk.store, "received-packages/" + expected_sha256 + ".zip")
    if not publish(original, raw) and original.read_bytes() != raw:
        raise ValueError("原始外包指纹冲突")
    # Publish all payloads before any envelope becomes visible to a committer.
    # Partial import is safe to retry: immutable equal bytes are reused.
    for path, content in payloads:
        target = safe(desk.store, path)
        if not publish(target, content) and target.read_bytes() != content:
            raise ValueError("已存在不同载荷，保留冲突，不覆盖")
    batch = uuid.uuid4().hex
    received = [desk.receive(env, importer, batch, expected_sha256) for env in envelopes]
    return {"import_batch_id": batch, "package_sha256": expected_sha256, "received": received, "payload_files": len(payloads)}
