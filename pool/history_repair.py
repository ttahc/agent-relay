"""Find records written before the v0.4.2 fixes that those fixes do not reach, and repair them.

Report only unless --apply. Two kinds of record are examined:

Resource end confirmation. Once a grant's physical end is confirmed it is final. Older code let a
later release downgrade it or replace its evidence, and let a delayed "started" receipt put the
action back to running. The ledger is walked from its first entry, each such grant and its action
are followed, and the values the current rules would have kept are worked out. The repair is one
new ledger event that sets them; no existing ledger file is changed.

Request audit. Older code copied a configuration named by a request into the requester's audit
record even when it belonged to another window. Those records are listed. Only with --redact-audit
are the ones held in the request journal alone replaced by the requester's own default; copies that
entered the ledger are part of its hash chain and are never changed.
"""
import argparse
from contextlib import ExitStack, closing
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys
import time

from . import execution
from .backup import snapshot
from .constants import COMMITTER, COORDINATOR
from .service import exclusive
from .storage import LedgerBackend
import 协作执行 as engine
from 协作存储 import Rejected, digest, encoded, safe
from 协作账本 import cursor, envelope, initial

COMMAND = "history-repair"
CONFIRMED = "end-confirmed"
RELEASE_FIELDS = ("physical", "release_evidence", "released_by", "release_event")
CONTEXT_FIELDS = ("execution_context", "reporter_context")
JOURNAL = "http-journal.sqlite3"


class RepairError(ValueError):
    pass


def _execution(state):
    return state.get("security", {}).get("execution", {})


def _advance(state, entry):
    """Apply one entry's effects without touching objects an earlier state still refers to."""
    for effect in entry["effects"]:
        path = effect["path"]
        if len(path) == 1:
            state[path[0]] = effect["value"]
        else:
            state[path[0]] = {**state[path[0]], path[1]: effect["value"]}


def _moment(value):
    try:
        moment = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return moment if moment.tzinfo else None


def _follow(track, seq, before, after, repaired=False):
    """Follow end-confirmed grants and their actions across one ledger entry."""
    old, new = _execution(before), _execution(after)
    if old is new:
        return
    if repaired:
        # An earlier run of this tool: what it set is what stays.
        for key, item in track["grants"].items():
            row = new["grants"][key]
            item.update(final={field: row[field] for field in RELEASE_FIELDS if field in row},
                        blocker=new.get("blockers", {}).get(key))
        for key, item in track["actions"].items():
            if not item["manual"] and new["actions"][key].get("grant_id") == item["grant_id"]:
                item["state"] = new["actions"][key]["state"]
        return
    old_grants, old_actions = old.get("grants", {}), old.get("actions", {})
    facts = [row for key, row in new.get("facts", {}).items() if key not in old.get("facts", {})]
    released = set()
    for key, row in new.get("grants", {}).items():
        prior = old_grants.get(key) or {}
        if any(row.get(field) != prior.get(field) for field in RELEASE_FIELDS):
            released.add(key)
        if row.get("physical") == CONFIRMED and prior.get("physical") != CONFIRMED:
            # A confirmation, or a new one after a downgrade, is the value that stays.
            track["grants"][key] = {"seq": seq, "final": {field: row[field] for field in RELEASE_FIELDS if field in row},
                                    "blocker": new.get("blockers", {}).get(key), "changed": []}
            action = new.get("actions", {}).get(row.get("action_id"))
            if action and track["actions"].get(action["id"], {}).get("grant_id") != key:
                track["actions"][action["id"]] = {"grant_id": key, "seq": seq, "state": action["state"],
                                                  "changed": [], "manual": None}
        elif key in track["grants"] and key in released:
            track["grants"][key]["changed"].append(seq)
    for key, item in track["actions"].items():
        row, prior = new.get("actions", {}).get(key), old_actions.get(key)
        if item["manual"] or row is None or prior is None or row == prior or item["seq"] == seq:
            continue
        if row.get("grant_id") != item["grant_id"]:
            item["manual"] = "动作之后取得了新的资源授权"
            continue
        reported = [fact for fact in facts if fact.get("action_id") == key and not fact.get("historical")]
        for fact in reported:
            if fact["kind"] == "started":
                item["changed"].append(seq)  # Refused by the current rules: the end was already confirmed.
            else:
                item["state"] = fact["kind"] if fact["kind"] in engine.TERMINAL else "unconfirmed"
        if not reported and row["state"] != prior["state"]:
            if item["grant_id"] in released:
                item["changed"].append(seq)  # A repeated release; the current rules change nothing.
            else:
                item["manual"] = f"账本第 {seq} 条以本工具不认识的方式改变了动作状态"


def _change(table, key, row, values, clear=(), **notes):
    return {"table": table, "id": key, "expect_sha256": digest(encoded(row)),
            "set": {name: value for name, value in values.items() if row.get(name) != value},
            "unset": sorted(name for name in clear if name in row), **notes}


def _resource_findings(track, state):
    """Changes that bring the current rows to what the current rules would have kept."""
    data, repairs, manual = _execution(state), [], []
    for key, item in track["grants"].items():
        row, final = data["grants"][key], item["final"]
        wrong = any(row.get(field) != final.get(field) for field in RELEASE_FIELDS)
        if wrong:
            repairs.append(_change("grants", key, row, final, clear=[f for f in RELEASE_FIELDS if f not in final],
                                   confirmed_seq=item["seq"], changed_seq=item["changed"], action_id=row.get("action_id"),
                                   summary=f"授权 {key} 在账本第 {item['seq']} 条已确认安全结束，之后被改为 "
                                           f"{row.get('physical')} 或证据被替换；恢复为确认时的状态和证据"))
        blocker, kept = data.get("blockers", {}).get(key), item["blocker"]
        if blocker and kept and blocker != kept and not kept.get("active"):
            repairs.append(_change("blockers", key, blocker, kept, clear=[name for name in blocker if name not in kept],
                                   confirmed_seq=item["seq"], summary=f"授权 {key} 的占用阻挡恢复为确认结束时的记录"))
        elif blocker and not kept and blocker.get("active") and wrong:
            repairs.append(_change("blockers", key, blocker, {"active": False, "physical": CONFIRMED,
                                                              "end_evidence": final.get("release_evidence")},
                                   confirmed_seq=item["seq"], summary=f"授权 {key} 确认结束后才出现的占用阻挡改为已解除"))
    for key, item in track["actions"].items():
        row = data["actions"][key]
        if item["manual"]:
            if item["changed"]:
                manual.append({"table": "actions", "id": key, "state": row["state"], "reason": item["manual"],
                               "changed_seq": item["changed"]})
        elif row.get("grant_id") == item["grant_id"] and row["state"] != item["state"]:
            repairs.append(_change("actions", key, row, {"state": item["state"]}, confirmed_seq=item["seq"],
                                   changed_seq=item["changed"],
                                   summary=f"动作 {key} 在资源确认结束后被改为 {row['state']}；"
                                           f"恢复为按现行规则应有的 {item['state']}"))
    return repairs, manual


def apply_repairs(state, repairs, now, event_id):
    """Apply listed changes to rows that are still exactly as scanned, then let waiting requests proceed."""
    data = engine.ensure(state)
    for item in repairs:
        row = data.get(item["table"], {}).get(item["id"]) if item["table"] in {"grants", "blockers", "actions"} else None
        if row is None or digest(encoded(row)) != item["expect_sha256"]:
            raise RepairError(f"{item['table']} {item['id']} 在检查之后已变化，未作任何修复")
        for name in item["unset"]:
            row.pop(name, None)
        row.update(deepcopy(item["set"]))
        if "version" in row:
            row["version"] += 1
    engine._arbitrate(state, now, event_id)
    return state


def decide(state, env, context):
    if env["command"] != COMMAND:
        raise RuntimeError("修复期间出现了其他待处理请求；已停止，未写入")
    repairs = env["payload"]["repairs"]
    apply_repairs(state, repairs, context["now"], env["event_id"])
    return state, {"reason": f"历史记录修复：{len(repairs)} 项"}


def _foreign(record):
    for field in CONTEXT_FIELDS:
        context = record.get(field)
        if isinstance(context, dict) and context.get("executor_id") not in (None, record.get("actor")):
            return field, context
    return None, None


def _may_carry(state, record, context):
    """Whether the current rules let this requester's audit record carry this configuration."""
    actor, owner = record.get("actor"), context["executor_id"]
    if execution.can_profile(state, actor, owner):
        return True
    data = _execution(state)
    sources = [data.get("actions", {}).get(record.get("action_id"))] if isinstance(record.get("action_id"), str) else []
    sources += [row for row in data.get("segments", {}).values()
                if (row.get("context_id"), row.get("context_version")) == (context.get("context_id"), context.get("version"))]
    return any(row and row.get("executor_id") == owner and execution.reporter_kind(state, actor, row) for row in sources)


def _audit_finding(state, record):
    """None when the record is in order; otherwise what it carries and what it should carry instead."""
    field, context = _foreign(record)
    if not field:
        return None
    try:
        if _may_carry(state, record, context):
            return None
        own = deepcopy(engine.default_context(state, record.get("actor")))
    except (Rejected, KeyError, TypeError, AttributeError):
        return {"field": field, "owner": context.get("executor_id"), "context_id": context.get("context_id"),
                "uncertain": True, "replacement": None}
    return {"field": field, "owner": context.get("executor_id"), "context_id": context.get("context_id"),
            "uncertain": False, "replacement": own}


def _journal_rows(store):
    path = safe(store, JOURNAL)
    if not path.exists():
        return [], 0
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"requests", "request_context", "steps"} <= tables:
            return [], 0
        rows = db.execute("SELECT c.request_key, c.details, EXISTS(SELECT 1 FROM steps s WHERE s.request_key=c.request_key) "
                          "FROM request_context c ORDER BY c.rowid").fetchall()
        pending = db.execute("SELECT count(*) FROM requests WHERE status IS NULL").fetchone()[0]
    return rows, pending


def scan(store, now=None):
    """Read-only examination. Returns the report and the private plan an apply would use."""
    store = Path(store)
    ledger = LedgerBackend(store)
    snap = ledger.read()
    if snap["halted"]:
        raise RepairError("账本已停写，须先按原流程恢复：" + str(snap["halted"]["reason"]))
    rows, pending = _journal_rows(store)
    waiting = []
    for key, raw, stepped in rows:
        record = json.loads(raw)
        if isinstance(record, dict) and _foreign(record)[0]:
            waiting.append((_moment(record.get("received_utc")), key, raw, record, bool(stepped)))
    waiting.sort(key=lambda item: (item[0] is None, item[0] or datetime.min.replace(tzinfo=timezone.utc)))
    state, track = initial(ledger.meta), {"grants": {}, "actions": {}}
    journal, in_ledger, position = [], [], 0

    def settle(until):
        nonlocal position
        while position < len(waiting) and (until is None or (waiting[position][0] is not None and waiting[position][0] < until)):
            _, key, raw, record, stepped = waiting[position]
            position += 1
            found = _audit_finding(state, record)
            if found:
                journal.append({**found, "request_key": key, "raw": raw, "entered_ledger": stepped,
                                "request_id": record.get("request_id"), "actor": record.get("actor"),
                                "operation": record.get("operation"), "received_utc": record.get("received_utc")})

    for entry in snap["entries"]:
        committed = _moment(entry.get("committed_utc"))
        if committed:
            settle(committed)
        if entry["type"] == "decision" and isinstance(entry.get("request"), dict):
            found = _audit_finding(state, entry["request"])
            if found:
                in_ledger.append({"seq": entry["ledger_seq"], "request_id": entry["request"].get("request_id"),
                                  "actor": entry["request"].get("actor"), "operation": entry["request"].get("operation"),
                                  "owner": found["owner"], "context_id": found["context_id"], "result": entry["result"]})
        before = dict(state)
        _advance(state, entry)
        _follow(track, entry["ledger_seq"], before, state,
                entry["type"] == "decision" and entry.get("command") == COMMAND and entry["result"] == "applied")
    settle(None)
    repairs, manual = _resource_findings(track, state)
    preview = {"granted": [], "blocked": []}
    if repairs:
        trial = apply_repairs(deepcopy(state), repairs, now or time.time(), "history-repair-preview")
        requests = _execution(state).get("resource_requests", {})
        for key, row in _execution(trial)["resource_requests"].items():
            if row["state"] != requests[key]["state"] and row["state"] in preview:
                preview[row["state"]].append(key)
    replaceable = [item for item in journal if not item["entered_ledger"] and not item["uncertain"]]

    def public(item):
        return {name: item[name] for name in ("request_id", "actor", "operation", "received_utc", "owner", "context_id")}
    report = {
        "ledger_head": snap["head"], "ledger_sha256": snap["sha256"],
        "resource_end": {"repairs": [{name: value for name, value in item.items() if name != "expect_sha256"} for item in repairs],
                         "needs_review": manual, "requests_after_repair": preview},
        "audit": {"replaceable": [public(item) for item in replaceable],
                  "uncertain": [public(item) for item in journal if item["uncertain"] and not item["entered_ledger"]],
                  "in_ledger": in_ledger + [{**public(item), "seq": None} for item in journal if item["entered_ledger"]]},
        "pending_requests": pending,
    }
    report["findings"] = (len(repairs) + len(manual) + len(journal) + len(in_ledger))
    return report, {"repairs": repairs, "replaceable": replaceable, "snap": snap, "ledger": ledger}


def _commit_event(plan, tag):
    ledger, snap, repairs = plan["ledger"], plan["snap"], plan["repairs"]
    terminal = snap["control"]["terminal"]
    for record in ledger.copies():
        env = record["envelope"]
        if env["origin_id"] + "/" + env["event_id"] not in terminal or record["copy_id"] not in snap["control"]["imports"]:
            raise RepairError("账本收件箱里还有未处理完的请求；请先让服务处理完再停止服务，未作任何修复")
    committer = COMMITTER if COMMITTER in snap["state"]["origins"] else COORDINATOR
    audit = {"actor": committer, "operation": COMMAND, "request_id": "history-repair-" + tag,
             "received_utc": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
             "reason": "恢复 v0.4.2 之前已确认结束却被改动的资源记录",
             "repairs": [{"table": item["table"], "id": item["id"], "set": sorted(item["set"]) + item["unset"]} for item in repairs]}
    env = envelope(ledger.meta["repo_id"], committer, cursor(snap, committer) + 1, COMMAND,
                   {"op": COMMAND, "repairs": repairs, "_audit": audit},
                   event_id=digest(encoded([COMMAND, snap["head"], snap["sha256"]])))
    ledger.receive(env, committer)
    after = ledger.process(committer, handler=decide)
    decision = after["control"]["terminal"].get(committer + "/" + env["event_id"])
    if after["halted"] or not decision or decision["result"] != "applied":
        raise RepairError("修复事件未被账本接受：" + str((decision or {}).get("reason") or after["halted"]))
    return {"ledger_seq": decision["ledger_seq"], "sha256": decision["sha256"], "head": after["head"]}


def _redact(store, items):
    done = []
    with closing(sqlite3.connect(safe(store, JOURNAL))) as db:
        db.execute("PRAGMA synchronous=EXTRA")
        with db:
            for item in items:
                record, own = json.loads(item["raw"]), item["replacement"]
                record[item["field"]] = own
                if "model" in record or "platform" in record:
                    record.update(model=own.get("config", {}).get("model"), platform=own.get("config", {}).get("platform"))
                original = digest(item["raw"] if isinstance(item["raw"], bytes) else str(item["raw"]).encode("utf-8"))
                record["history_repair"] = {"replaced": item["field"], "original_sha256": original,
                                            "at": datetime.now(timezone.utc).isoformat(timespec="microseconds")}
                changed = db.execute("UPDATE request_context SET details=? WHERE request_key=? AND details=?",
                                     (encoded(record), item["request_key"], item["raw"])).rowcount
                if changed != 1:
                    raise RepairError("审计记录在检查之后已变化，未替换任何审计记录")
                done.append({"request_id": item["request_id"], "actor": item["actor"], "original_sha256": original})
    return done


def repair(store, archive, tag, redact_audit=False):
    """Back up, then repair under the service's own locks. The service must be stopped."""
    store = Path(store).resolve(strict=True)
    backup = snapshot(store, archive, tag)
    with ExitStack() as stack:
        stack.enter_context(exclusive(store))
        stack.enter_context(exclusive(store, "service-writer.lock"))
        report, plan = scan(store)
        if plan["snap"]["head"] != backup["head"]:
            raise RepairError("备份之后账本发生了变化，未作任何修复")
        if report["pending_requests"] and (plan["repairs"] or (redact_audit and plan["replaceable"])):
            raise RepairError("请求日志里还有未完成的请求；请先让服务处理完再停止服务，未作任何修复")
        result = {"backup": {"manifest": backup["manifest"], "head": backup["head"]}, "event": None, "audit_replaced": []}
        if plan["repairs"]:
            result["event"] = _commit_event(plan, tag)
        if redact_audit and plan["replaceable"]:
            result["audit_replaced"] = _redact(store, plan["replaceable"])
        remaining, _ = scan(store)
    receipt = {"mode": "applied", "before": report, **result, "remaining_findings": remaining["findings"],
               "remaining": {"resource_end": remaining["resource_end"], "audit": remaining["audit"]}}
    path = Path(archive) / (tag + ".history-repair.json")
    with path.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    return {**receipt, "receipt": str(path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--apply", action="store_true", help="写入修复；须同时给出 --archive 和 --tag，并先停止服务")
    parser.add_argument("--archive", type=Path, help="--apply：修复前完整备份所用的私有绝对目录")
    parser.add_argument("--tag", help="--apply：未使用过的备份名称")
    parser.add_argument("--redact-audit", action="store_true",
                        help="--apply：同时把仅存于请求日志的审计记录中其他窗口的配置替换为请求者自己的默认配置")
    args = parser.parse_args()
    try:
        if os.name == "posix":
            os.umask(0o077)
        if args.apply:
            if not args.archive or not args.tag:
                raise RepairError("--apply 需要 --archive 私有绝对目录和 --tag 唯一名称")
            result = repair(args.store, args.archive, args.tag, args.redact_audit)
        else:
            if args.archive or args.tag or args.redact_audit:
                raise RepairError("--archive、--tag 和 --redact-audit 只与 --apply 一起使用")
            result = {"mode": "dry-run", **scan(args.store)[0]}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (ValueError, OSError, RuntimeError, sqlite3.Error) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
