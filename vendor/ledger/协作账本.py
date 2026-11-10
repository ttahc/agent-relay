#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""T15 revision-7 protocol. Explicit --store; does not enable or migrate the old desk."""
import argparse
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import uuid

from 协作存储 import Rejected, digest, encoded, ntfs_identity, publish, read_json, safe


TIGHTENING = {"pause", "cancel", "revoke", "replace_claim", "stopped", "release", "contact", "note"}
SYNCHRONIZATION = {"gap_close", "resolve_conflict"}  # Authorized controls grant no execution resource themselves.
TOKEN = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")


def initial(meta):
    actor = meta["coordinator"]
    return {"repo_id": meta["repo_id"], "coordinator": actor, "generation": 1,
            "storage_prefix": meta.get("storage_prefix", "TestResults/TaskIntake/coordination"),
            "origins": {actor: {"roles": ["coordinator"], "local": True, "version": 1}},
            "authorities": {"bootstrap": meta["authority_ref"]}, "standing": {}, "coverage": {},
            "tasks": {}, "proposals": {}, "claims": {}, "reservations": {}, "items": {},
            "acceptances": {}, "closings": {}, "corrections": {}, "commits": {},
            "contacts": {}, "intents": {}, "notes": {}, "next_task": 1, "pilot": {}, "round": {}, "security": {},
            "flow_records": {}, "flow_superseded": {}, "flow_config": {},
            "migration": {"phase": "frozen" if meta.get("migration") else "standalone", "business_changed": False}}


def effects_between(before, after):
    """Changed top-level records only; replay does not retain whole-state snapshots."""
    changes = []
    for key in sorted(after):
        if before.get(key) == after[key]:
            continue
        if isinstance(before.get(key), dict) and isinstance(after[key], dict):
            if set(before[key]) - set(after[key]):
                raise ValueError("记录不能删除，须保留终态")
            for record in sorted(after[key]):
                if before[key].get(record) != after[key][record]:
                    changes.append({"path": [key, record], "value": after[key][record]})
        else:
            changes.append({"path": [key], "value": after[key]})
    return changes


def apply_entry(snap, entry):
    if entry.get("type") not in {"import", "gap-observed", "decision"} or not isinstance(entry.get("effects"), list):
        raise ValueError("账本条目结构无效")
    for effect in entry["effects"]:
        path = effect.get("path")
        if (not isinstance(path, list) or len(path) not in {1, 2} or path[0] not in snap["state"] or
                "value" not in effect or len(path) == 2 and not isinstance(snap["state"][path[0]], dict)):
            raise ValueError("账本effects结构无效")
    if entry["type"] == "decision" and (not all(k in entry for k in ("key", "origin_id", "origin_seq")) or entry.get("result") not in {"applied", "rejected", "evidence-only"}):
        raise ValueError("终局条目结构无效")
    if entry["type"] == "import" and not all(k in entry for k in ("copy_id", "result")):
        raise ValueError("导入条目结构无效")
    if entry["type"] == "gap-observed" and len(entry.get("gap", [])) != 3:
        raise ValueError("缺口条目结构无效")
    for effect in entry["effects"]:
        path = effect["path"]
        if len(path) == 1:
            snap["state"][path[0]] = copy.deepcopy(effect["value"])
        elif len(path) == 2 and path[0] in snap["state"]:
            snap["state"][path[0]][path[1]] = copy.deepcopy(effect["value"])
        else:
            raise ValueError("账本effects路径无效")
    control = snap["control"]
    if entry["type"] == "import":
        control["imports"][entry["copy_id"]] = entry["result"]
    elif entry["type"] == "gap-observed":
        control["gaps"].add(tuple(entry["gap"]))
    elif entry["type"] == "decision":
        control["terminal"][entry["key"]] = entry
        if entry["result"] == "applied":
            control["last_applied"][entry["origin_id"]] = entry["ledger_seq"]
    for closed in entry.get("closed", []):
        control["closed"].setdefault(closed["origin_id"], []).append((closed["a"], closed["b"]))
    for resolution in entry.get("resolutions", []):
        control["selected"][resolution["key"]] = resolution["sha256"]
    for resolution in entry.get("sequence_resolutions", []):
        control["sequence_selected"][(resolution["origin_id"], resolution["origin_seq"])] = resolution["key"]
        control["selected"][resolution["key"]] = resolution["sha256"]
    snap["head"] = entry["ledger_seq"]
    snap["sha256"] = entry["sha256"]
    snap["entries"].append(entry)


def cursor(snap, origin):
    seqs = {e["origin_seq"] for e in snap["control"]["terminal"].values() if e["origin_id"] == origin}
    closed = snap["control"]["closed"].get(origin, [])
    current = 0
    while True:
        match = next((b for a, b in closed if a <= current + 1 <= b), None)
        if match is not None:
            current = match
        elif current + 1 in seqs:
            current += 1
        else:
            return current


def envelope(repo_id, origin_id, origin_seq, command, payload=None, expects=None, event_id=None):
    return {"repo_id": repo_id, "origin_id": origin_id, "origin_seq": origin_seq,
            "event_id": event_id or uuid.uuid4().hex, "command": command,
            "payload": payload or {}, "expects": expects or {}}


class Ledger:
    def __init__(self, store):
        self.store = Path(store).absolute()
        self.meta = read_json(safe(self.store, "repo.json"))

    @classmethod
    def create(cls, store, coordinator, authority_ref, qualification, migration=False):
        if not TOKEN.fullmatch(coordinator) or not authority_ref.strip():
            raise ValueError("初始化须有稳定来源和可追溯授权")
        path = Path(store).absolute()
        path.mkdir(parents=True, exist_ok=True)
        safe(path, "repo.json")
        proof = read_json(Path(qualification))
        cls.check_qualification(path, proof)
        storage_prefix = path.relative_to(Path(__file__).resolve().parents[2]).as_posix()
        meta = {"schema": 1, "repo_id": uuid.uuid4().hex, "coordinator": coordinator,
                "authority_ref": authority_ref, "qualification": proof,
                "qualification_sha256": digest(encoded(proof)), "created_utc": datetime.now(timezone.utc).isoformat(),
                "migration": migration, "storage_prefix": storage_prefix}
        if not publish(safe(path, "repo.json"), encoded(meta)):
            raise ValueError("协调仓库已存在，不覆盖身份")
        return cls(path)

    @staticmethod
    def check_qualification(path, proof):
        if proof.get("failed") != 0 or any(proof.get(v) != "passed" for v in ("V1", "V3", "V4")):
            raise ValueError("P/V1/V3/V4未通过，不能提交")
        actual = ntfs_identity(path)
        expected = proof["identity"]
        if any(actual[k] != expected[k] for k in ("machine", "volume", "serial", "filesystem")):
            raise ValueError("验证环境已变化，只允许投递")
        Path(actual["store"]).relative_to(Path(expected["store"]))
        probe = Path(path) / (".permission-probe-" + uuid.uuid4().hex)
        try:
            if not publish(probe, b"qualified publication probe\n"):
                raise ValueError("提交权限探测冲突")
            probe.unlink()
        except OSError as error:
            raise ValueError("当前目录权限未验证，只允许投递信封") from error

    def read(self):
        snap = {"state": initial(self.meta), "head": 0, "sha256": digest(encoded(self.meta)), "halted": None,
                "entries": [], "control": {"imports": {}, "terminal": {}, "selected": {},
                                           "closed": {}, "gaps": set(), "last_applied": {}, "sequence_selected": {}}}
        folder = safe(self.store, "ledger")
        if not folder.exists():
            return snap
        paths = sorted(folder.glob("*.json"))
        for path in paths:
            try:
                expected_name = f"{snap['head'] + 1:012d}.json"
                if path.name != expected_name:
                    raise ValueError("账本位置缺失或文件名无效")
                entry = read_json(safe(self.store, "ledger/" + path.name))
                checksum = entry.pop("sha256")
                if (type(entry["ledger_seq"]) is not int or entry["ledger_seq"] != snap["head"] + 1 or
                        entry["prev_sha256"] != snap["sha256"] or digest(encoded(entry)) != checksum):
                    raise ValueError("账本SHA或前链不匹配")
                entry["sha256"] = checksum
                apply_entry(snap, entry)
                from 协作安全 import check as check_security
                check_security(snap['state'])
            except (OSError, ValueError, KeyError, TypeError) as error:
                snap["halted"] = {"position": snap["head"] + 1, "reason": str(error)}
                break
        return snap

    def receive(self, env, importer, import_batch_id=None, package_sha256=None):
        required = {"repo_id", "origin_id", "origin_seq", "event_id", "command", "payload", "expects"}
        if not isinstance(env, dict) or set(env) != required:
            raise ValueError("信封字段不完整或有未知字段")
        if (env["repo_id"] != self.meta["repo_id"] or
                any(not isinstance(env[k], str) or not TOKEN.fullmatch(env[k]) for k in ("origin_id", "event_id", "command")) or
                type(env["origin_seq"]) is not int or not 0 < env["origin_seq"] <= 10**9 or
                not isinstance(env["payload"], dict) or not isinstance(env["expects"], dict) or not importer.strip()):
            raise ValueError("信封身份、序号或载荷格式无效")
        raw = encoded(env)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("信封超出4MiB；大载荷按SHA引用")
        copy_id = uuid.uuid4().hex
        record = {"envelope": env, "sha256": digest(raw), "importer": importer,
                  "import_batch_id": import_batch_id or uuid.uuid4().hex, "copy_id": copy_id,
                  "package_sha256": package_sha256}
        publish(safe(self.store, "inbox/" + copy_id + ".json"), encoded(record))
        return {"copy_id": copy_id, "key": env["origin_id"] + "/" + env["event_id"], "sha256": record["sha256"]}

    def copies(self):
        folder = safe(self.store, "inbox")
        result = []
        if folder.exists():
            for path in sorted(folder.glob("*.json")):
                record = read_json(safe(self.store, "inbox/" + path.name))
                if digest(encoded(record["envelope"])) != record["sha256"] or path.stem != record["copy_id"]:
                    raise ValueError("收件箱副本已变化，保留现场")
                result.append(record)
        return result

    def append(self, snap, fields, committer):
        if snap["halted"]:
            raise ValueError("协作账本停写")
        entry = {"ledger_seq": snap["head"] + 1, "prev_sha256": snap["sha256"],
                 "committer": committer, "coordinator_generation": snap["state"]["generation"],
                 "effects": [], "reason": "", **fields}
        if "format" in snap["state"]["pilot"] or fields.get("command") == "pilot":
            entry["committed_utc"] = datetime.now(timezone.utc).isoformat()
        entry["sha256"] = digest(encoded(entry))
        if not publish(safe(self.store, f"ledger/{entry['ledger_seq']:012d}.json"), encoded(entry)):
            return False
        apply_entry(snap, entry)
        return True

    def evidence_context(self, env, state):
        if env["command"] == "board_layout":
            from 协作视图 import prepare_board_layout
            return prepare_board_layout(self, env["payload"], state)
        from 协作取证 import checked_file, inspect
        from 协作升级 import contract, enabled, verify_report
        result = inspect(self, env, state)
        if enabled(state):
            p = env["payload"]
            claim = state["claims"].get(p.get("claim_id"), {})
            task = state["tasks"].get(p.get("task_id") or claim.get("task_id"))
            gate = (contract(task) or {}).get("gate")
            evidence = None
            release_id = None
            if env["command"] == "pilot" and p.get("op") == "release-accept":
                evidence = p.get("evidence")
            elif env["command"] == "pilot" and p.get("op") == "release-close":
                evidence = state["pilot"]["release:" + state["pilot"]["format"]["upgrade"]].get("evidence")
            elif gate and (env["command"] in {"claim", "acquire", "resume", "seal", "ack_scope"} or
                           env["command"] == "pilot" and p.get("op") == "publish"):
                evidence = state["pilot"].get("release:" + gate, {}).get("evidence")
                release_id = gate
            if evidence:
                verify_report(state, json.loads(checked_file(self.store, evidence)), release_id)
                result["release_verified"] = True
        return result

    def process(self, committer, handler=None, max_steps=10000):
        self.check_qualification(self.store, self.meta["qualification"])
        if handler is None:
            from 协作命令 import decide
            handler = decide
        snap = self.read()
        if not snap["state"]["origins"].get(committer, {}).get("local"):
            raise ValueError("只有已登记且通过本地验证的来源可提交")
        for _ in range(max_steps):
            if snap["halted"]:
                break
            copies = self.copies()
            grouped = {}
            seq_keys = {}
            for record in copies:
                env = record["envelope"]
                key = env["origin_id"] + "/" + env["event_id"]
                grouped.setdefault(key, {})[record["sha256"]] = record
                seq_keys.setdefault((env["origin_id"], env["origin_seq"]), set()).add(key)
            fields = None
            for record in copies:
                if record["copy_id"] in snap["control"]["imports"]:
                    continue
                env = record["envelope"]
                key = env["origin_id"] + "/" + env["event_id"]
                terminal = snap["control"]["terminal"].get(key)
                result = ("duplicate" if terminal["content_sha256"] == record["sha256"] else "conflict-copy") if terminal else "received"
                fields = {"type": "import", "copy_id": record["copy_id"], "import_batch_id": record["import_batch_id"],
                          "importer": record["importer"], "key": key, "content_sha256": record["sha256"], "result": result,
                          "package_sha256": record.get("package_sha256")}
                break
            if fields is None:
                candidates = []
                for key, variants in grouped.items():
                    if key in snap["control"]["terminal"]:
                        continue
                    chosen = snap["control"]["selected"].get(key)
                    if chosen:
                        record = variants.get(chosen)
                        if record is None:
                            continue
                    else:
                        record = next(iter(variants.values()))
                    env = record["envelope"]
                    origin, seq = env["origin_id"], env["origin_seq"]
                    is_closed = any(a <= seq <= b for a, b in snap["control"]["closed"].get(origin, []))
                    selected_key = snap["control"]["sequence_selected"].get((origin, seq))
                    prior_keys = {k for k, e in snap["control"]["terminal"].items() if e["origin_id"] == origin and e["origin_seq"] == seq}
                    excluded = selected_key is not None and selected_key != key or bool(prior_keys - {key}) and selected_key != key
                    conflict = len(variants) > 1 and not chosen or len(seq_keys[(origin, seq)]) > 1 and not selected_key and not prior_keys
                    if conflict and not is_closed and not excluded:
                        continue
                    cur = cursor(snap, origin)
                    if is_closed or excluded or seq <= cur + 1 or env["command"] in TIGHTENING | SYNCHRONIZATION:
                        candidates.append((origin, seq, key, record, is_closed or excluded))
                if candidates:
                    origin, seq, key, record, is_closed = sorted(candidates) [0]
                    env = record["envelope"]
                    fields = {"type": "decision", "key": key, "origin_id": origin, "origin_seq": seq,
                              "content_sha256": record["sha256"], "import_batch_id": record["import_batch_id"],
                              "command": env["command"], "result": "applied", "rejection": None}
                    if "_audit" in env["payload"]:
                        fields["request"] = env["payload"]["_audit"]
                    if is_closed:
                        fields.update(result="evidence-only", reason="来源序号已关闭或已有其他裁定/终局事件；本副本留证，不取消原任务要求")
                    else:
                        try:
                            context = {"seq": snap["head"] + 1, "control": snap["control"], "inbox": grouped,
                                       "now": datetime.now(timezone.utc).timestamp()}
                            if handler.__module__ == "协作命令":
                                context.update(self.evidence_context(env, snap["state"]))
                            after, extra = handler(copy.deepcopy(snap["state"]), env, context)
                            fields.update(effects=effects_between(snap["state"], after), **extra)
                        except Rejected as error:
                            fields.update(result="rejected", rejection=error.category, reason=str(error))
                            if (env["command"] in {"handoff", "takeover"} and env["payload"].get("intent_id") and
                                    env["payload"]["intent_id"] not in snap["state"]["intents"]):
                                after = copy.deepcopy(snap["state"])
                                after["intents"][env["payload"]["intent_id"]] = {"result": "rejected", "reason": str(error)}
                                fields["effects"] = effects_between(snap["state"], after)
                        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
                            fields.update(result="rejected", rejection="format", reason="载荷不符合合同：" + str(error))
                else:
                    for key, variants in sorted(grouped.items()):
                        if key in snap["control"]["terminal"]:
                            continue
                        env = next(iter(variants.values()))["envelope"]
                        gap = (env["origin_id"], cursor(snap, env["origin_id"]) + 1, env["origin_seq"] - 1)
                        if gap[1] <= gap[2] and gap not in snap["control"]["gaps"]:
                            fields = {"type": "gap-observed", "gap": list(gap), "result": "observed"}
                            break
            if fields is None:
                return self.refresh_projection(snap)
            if not self.append(snap, fields, committer):
                snap = self.read()  # Re-evaluate the same immutable envelope at the winning head.
        return self.refresh_projection(snap)

    def refresh_projection(self, snap):
        migration = snap["state"]["migration"]
        if migration.get("board_path") and migration["phase"] == "active":
            try:
                from 协作视图 import publish_board
                snap["projection"] = publish_board(self, migration["board_path"], snap)
            except (OSError, ValueError, KeyError, TypeError) as error:
                snap["view_error"] = str(error)  # Decisions already committed; never replay their effects.
        if snap["state"].get("flow_config", {}).get("phase") == "active":
            try:
                from 协作流水索引 import rebuild
                snap["flow_projection"] = rebuild(self)
            except (OSError, ValueError, KeyError, TypeError) as error:
                snap["flow_view_error"] = str(error)
        return snap


def public_status(snap):
    origins = {key: {"cursor": cursor(snap, key), "last_applied": snap["control"]["last_applied"].get(key)}
               for key in snap["state"]["origins"]}
    decisions = {key: {field: entry.get(field) for field in ("ledger_seq", "command", "result", "rejection", "reason")}
                 for key, entry in snap["control"]["terminal"].items()}
    return {"head": snap["head"], "sha256": snap["sha256"], "halted": snap["halted"],
            "origins": origins, "decisions": decisions, "state": snap["state"], "view_error": snap.get("view_error"),
            "flow_view_error": snap.get("flow_view_error")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--origin", required=True)
    init.add_argument("--authority", required=True)
    init.add_argument("--qualification", required=True)
    init.add_argument("--migration", action="store_true")
    receive = sub.add_parser("receive")
    receive.add_argument("--file", required=True)
    receive.add_argument("--importer", required=True)
    receive.add_argument("--batch")
    process = sub.add_parser("process")
    process.add_argument("--committer", required=True)
    sub.add_parser("list")
    view = sub.add_parser("view")
    view.add_argument("--output", required=True)
    cached = sub.add_parser("cached-view")
    cached.add_argument("--directory", required=True)
    board = sub.add_parser("publish-board")
    board.add_argument("--path", required=True)
    pack = sub.add_parser("pack")
    pack.add_argument("--claim-id", required=True)
    pack.add_argument("--output", required=True)
    package = sub.add_parser("import")
    package.add_argument("--file", required=True)
    package.add_argument("--sha256", required=True)
    package.add_argument("--importer", required=True)
    check = sub.add_parser("check-write")
    for field in ("claim-id", "origin", "resource"):
        check.add_argument("--" + field, required=True)
    check.add_argument("--epoch", type=int, required=True)
    check.add_argument("--scope", type=int, required=True)
    args = parser.parse_args()
    try:
        if args.command == "init":
            desk = Ledger.create(args.store, args.origin, args.authority, args.qualification, args.migration)
            result = {"repo_id": desk.meta["repo_id"], "enabled": "explicit-store-only"}
        else:
            desk = Ledger(args.store)
            if args.command == "receive":
                result = desk.receive(read_json(Path(args.file)), args.importer, args.batch)
            elif args.command == "process":
                result = public_status(desk.process(args.committer))
            elif args.command == "view":
                from 协作视图 import write_views
                result = write_views(desk, Path(args.output))
            elif args.command == "cached-view":
                from 协作视图 import read_cached
                result = read_cached(args.directory)
            elif args.command == "publish-board":
                from 协作视图 import publish_board
                result = publish_board(desk, args.path)
            elif args.command == "pack":
                from 协作交接 import export_claim
                result = export_claim(desk, args.claim_id, args.output)
            elif args.command == "import":
                from 协作交接 import import_package
                result = import_package(desk, args.file, args.sha256, args.importer)
            elif args.command == "check-write":
                from 协作命令 import writable
                snap = desk.read()
                if args.resource.startswith("path:"):
                    safe(Path(__file__).resolve().parents[2], args.resource[5:])
                result = {"allowed": writable(snap["state"], args.claim_id, args.origin,
                                               args.epoch, args.scope, args.resource), "head": snap["head"],
                          "halted": snap["halted"]}
            else:
                result = public_status(desk.read())
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 3 if args.command == "check-write" and not result["allowed"] else 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("协作账本：" + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
