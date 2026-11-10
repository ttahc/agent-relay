"""History repair: records written before the v0.4.2 fixes are found, and repaired without rewriting the ledger."""
from contextlib import closing, contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

from pool import history_repair
from pool.constants import COORDINATOR, Unavailable
from pool.service import Service, exclusive
import 协作执行 as engine
from 协作存储 import digest, encoded
from 协作账本 import Ledger, cursor, envelope
from verify_delegation import ASSISTANT, OTHER, PERSON
import verify_r2_execution
from verify_support import ROOT, scratch

FOREIGN, FOREIGN_OWNER = "foreign-window", "other-person"
MARKERS = ("foreign-model-marker", "foreign-environment-marker")
CONFIRMED = "end-confirmed"
OTHER_EVIDENCE = {"note": "a later and different statement", "sha256": "c" * 64}


class DiskLedger(Ledger):
    """The real ledger on disk; only the filesystem qualification of the deployed volume is skipped."""

    @staticmethod
    def check_qualification(path, proof):
        pass


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class Store:
    """A real on-disk store whose history is produced by the execution engine, one ledger entry per commit."""

    def __init__(self, root):
        self.path = root / "store"
        self.path.mkdir()
        self.archive = root / "archive"
        meta = {"schema": 1, "repo_id": "f" * 32, "coordinator": COORDINATOR, "authority_ref": "fixture",
                "qualification": {}, "migration": False, "storage_prefix": "fixture"}
        (self.path / "repo.json").write_bytes(encoded(meta))
        self.ledger = DiskLedger(self.path)
        self.case = verify_r2_execution.ExecutionTests()
        self.case.setUp()
        state = self.case.state
        state["origins"][COORDINATOR] = {"roles": ["coordinator"], "local": True, "version": 1}
        state["pilot"]["format"].update(schema=5, min_reader=5)
        with self.journal() as db:
            db.executescript("""
                CREATE TABLE requests(key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, actor TEXT NOT NULL,
                    action TEXT NOT NULL, body BLOB NOT NULL, plan BLOB, status INTEGER, response BLOB);
                CREATE TABLE steps(request_key TEXT NOT NULL, position INTEGER NOT NULL, envelope BLOB NOT NULL,
                    PRIMARY KEY(request_key, position));
                CREATE TABLE request_context(request_key TEXT PRIMARY KEY, details BLOB NOT NULL);
            """)
        self.commit()

    @property
    def data(self):
        return self.case.data

    @contextmanager
    def journal(self):
        with closing(sqlite3.connect(self.path / "http-journal.sqlite3")) as db, db:
            yield db

    def commit(self):
        snap = self.ledger.read()
        env = envelope(self.ledger.meta["repo_id"], COORDINATOR, cursor(snap, COORDINATOR) + 1, "fixture")
        self.ledger.receive(env, COORDINATOR)
        current = deepcopy(self.case.state)
        snap = self.ledger.process(COORDINATOR, handler=lambda state, env, context: ({**state, **current}, {}))
        assert not snap["halted"] and snap["control"]["terminal"][COORDINATOR + "/" + env["event_id"]]["result"] == "applied"
        return snap

    def grant(self, aid):
        return self.data["grants"][self.data["actions"][aid]["grant_id"]]

    def held_until_confirmed(self, confirm="human-isolation"):
        """Window one holds the path, returns it unconfirmed, and the person confirms the physical end."""
        case = self.case
        a, b = case.prepare(), case.prepare(OTHER)
        case.request(a)
        case.start(a)
        case.release(a)
        self.commit()
        if confirm == "blocker-fact":
            case.call("execution-fact", PERSON, task_id="T01", claim_id="ca", scope_version=1, epoch=1, action_id=None,
                      kind="stopped", evidence={"note": "original process isolated", "sha256": "a" * 64}, permit_id=None,
                      reporter_basis={"kind": "human", "note": "project manager checked evidence"},
                      blocker_ids=[self.data["actions"][a]["grant_id"]])
        else:
            case.release(a, PERSON, confirm)
        self.commit()
        return a, b

    def before_fix(self, aid, step, late_start=False):
        """Run one engine step the way it behaved before PR #14, when a confirmed end was not final.

        The old code ran the same statements without looking at the confirmation. Hiding the
        confirmation for the duration of the step reproduces that with the real engine.
        """
        assert self.grant(aid)["physical"] == CONFIRMED
        self.grant(aid)["physical"] = "unknown"
        step()
        if late_start:
            self.grant(aid)["physical"] = CONFIRMED  # The old code already kept this field on a fact.
            engine._arbitrate(self.case.state, 0, "fixture")
        self.commit()

    def old_release(self, aid, actor=None, basis="unconfirmed", evidence=None):
        grant, action = self.grant(aid), self.data["actions"][aid]
        self.before_fix(aid, lambda: self.case.call(
            "resource-release", actor or action["executor_id"], action_id=aid, grant_id=grant["id"],
            generation=grant["generation"], version=grant["version"], basis=basis,
            evidence=evidence or {"note": "checked physical isolation evidence", "sha256": "a" * 64}))

    def old_late_start(self, aid):
        self.before_fix(aid, lambda: self.case.started_fact(aid), late_start=True)

    def record(self, actor, request_id, context, field="execution_context", stepped=False, status=400, **more):
        key = digest(encoded([actor, request_id]))
        details = {"actor": actor, "request_id": request_id, "operation": "context-save", "received_utc": now(),
                   field: context, "model": context["config"]["model"], "platform": context["config"]["platform"], **more}
        with self.journal() as db:
            db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)", (key, "f", actor, "context-save", b"{}", None, status, b"{}"))
            db.execute("INSERT INTO request_context VALUES(?,?)", (key, encoded(details)))
            if stepped:
                db.execute("INSERT INTO steps VALUES(?,?,?)", (key, 0, b"{}"))
        return key

    def details(self, key):
        with self.journal() as db:
            return db.execute("SELECT details FROM request_context WHERE request_key=?", (key,)).fetchone()[0]

    def files(self):
        return {path.relative_to(self.path).as_posix(): path.read_bytes() for path in sorted(self.path.rglob("*"))
                if path.is_file() and not path.name.endswith(".lock")}

    def scan(self):
        return history_repair.scan(self.path)[0]

    def repair(self, tag="repair-one"):
        return history_repair.repair(self.path, self.archive, tag)

    def state(self):
        snap = self.ledger.read()
        assert not snap["halted"], snap["halted"]
        return snap["state"]["security"]["execution"], snap


class RepairCase(unittest.TestCase):
    def setUp(self):
        folder = scratch("history-repair-")
        self.addCleanup(folder.cleanup)
        for target in ("pool.history_repair.LedgerBackend", "pool.backup.LedgerBackend"):
            patcher = patch(target, DiskLedger)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.store = Store(Path(folder.name))


class ResourceEnd(RepairCase):
    def test_history_without_the_old_faults_reports_nothing_and_adds_no_event(self):
        store = self.store
        a, b = store.held_until_confirmed()
        store.case.request(b)
        store.commit()
        report = store.scan()
        self.assertEqual(report["findings"], 0)
        head = report["ledger_head"]
        result = store.repair()
        self.assertIsNone(result["event"])
        self.assertEqual(store.state()[1]["head"], head)
        self.assertTrue(Path(result["backup"]["manifest"]).is_file())

    def test_downgraded_end_is_restored_by_one_new_event_and_the_waiting_request_proceeds(self):
        for confirm in ("human-isolation", "blocker-fact"):
            with self.subTest(confirm=confirm):
                self.setUp()
                store = self.store
                a, b = store.held_until_confirmed(confirm)
                kept = deepcopy(store.grant(a))
                kept_blocker = deepcopy(store.data["blockers"][kept["id"]])
                kept_state = store.data["actions"][a]["state"]
                store.old_release(a, evidence=OTHER_EVIDENCE)
                self.assertEqual(store.grant(a)["physical"], "unknown")
                self.assertTrue(store.data["blockers"][kept["id"]]["active"])
                waiting = store.case.request(b)
                store.commit()
                self.assertEqual(store.data["resource_requests"][waiting]["state"], "queued")

                before = store.files()
                report = store.scan()
                self.assertEqual(store.files(), before, "a dry run writes nothing")
                self.assertEqual({(item["table"], item["id"]) for item in report["resource_end"]["repairs"]},
                                 {("grants", kept["id"]), ("blockers", kept["id"])})
                self.assertEqual(report["resource_end"]["requests_after_repair"]["granted"], [waiting])

                result = store.repair()
                after = store.files()
                for name, raw in before.items():
                    if name.startswith(("ledger/", "inbox/")) or name == "repo.json":
                        self.assertEqual(after[name], raw, name + " must not be rewritten")
                data, snap = store.state()
                entry = snap["entries"][-1]
                self.assertEqual((entry["type"], entry["command"], entry["result"]), ("decision", "history-repair", "applied"))
                self.assertEqual(entry["ledger_seq"], result["event"]["ledger_seq"])
                self.assertEqual(snap["head"], report["ledger_head"] + 2, "one received copy and one decision")
                self.assertEqual(entry["request"]["operation"], "history-repair")
                grant = data["grants"][kept["id"]]
                for field in history_repair.RELEASE_FIELDS:
                    self.assertEqual(grant.get(field), kept.get(field), field)
                self.assertEqual(grant["state"], "released")
                self.assertGreater(grant["version"], kept["version"])
                self.assertEqual(data["blockers"][kept["id"]], kept_blocker)
                self.assertEqual(data["actions"][a]["state"], kept_state)
                self.assertEqual(data["resource_requests"][waiting]["state"], "granted")
                self.assertEqual(result["remaining_findings"], 0)
                self.assertEqual(store.scan()["findings"], 0)
                manifest = json.loads(Path(result["backup"]["manifest"]).read_text(encoding="utf-8"))
                self.assertEqual(manifest["ledger_head"], report["ledger_head"])
                self.assertTrue(Path(result["receipt"]).is_file())

    def test_action_revived_by_a_late_start_is_put_back(self):
        store = self.store
        a, _ = store.held_until_confirmed("blocker-fact")
        self.assertEqual(store.data["actions"][a]["state"], "unconfirmed")
        store.old_late_start(a)
        revived = deepcopy(store.data["actions"][a])
        self.assertEqual((revived["state"], store.grant(a)["physical"]), ("running", CONFIRMED))
        facts = len(store.data["facts"])
        report = store.scan()
        self.assertEqual([(item["table"], item["id"], item["set"]) for item in report["resource_end"]["repairs"]],
                         [("actions", a, {"state": "unconfirmed"})])
        store.repair()
        data, _ = store.state()
        self.assertEqual(data["actions"][a]["state"], "unconfirmed")
        self.assertEqual(data["actions"][a]["version"], revived["version"] + 1)
        self.assertEqual(len(data["facts"]), facts, "the late receipt stays on record")
        self.assertEqual(store.scan()["findings"], 0)

    def test_action_that_reported_its_end_after_the_late_start_is_left_alone(self):
        store = self.store
        a, _ = store.held_until_confirmed()
        store.old_late_start(a)
        action = store.data["actions"][a]
        store.case.call("execution-fact", task_id="T01", claim_id="ca", scope_version=1, epoch=1, action_id=a, kind="finished",
                        evidence={"note": "work finished", "sha256": "d" * 64}, permit_id=action["permit_id"],
                        reporter_basis={"kind": "owner", "note": "original executor"})
        store.commit()
        self.assertEqual(store.scan()["findings"], 0)

    def test_replaced_evidence_of_a_confirmed_end_is_restored(self):
        store = self.store
        a, _ = store.held_until_confirmed()
        kept = deepcopy(store.grant(a))
        store.old_release(a, PERSON, "human-isolation", OTHER_EVIDENCE)
        self.assertEqual((store.grant(a)["physical"], store.grant(a)["release_evidence"]), (CONFIRMED, OTHER_EVIDENCE))
        store.repair()
        data, _ = store.state()
        self.assertEqual(data["grants"][kept["id"]]["release_evidence"], kept["release_evidence"])
        self.assertEqual(data["grants"][kept["id"]]["release_event"], kept["release_event"])
        self.assertEqual(data["blockers"][kept["id"]]["end_evidence"], kept["release_evidence"])
        self.assertEqual(store.scan()["findings"], 0)

    def test_a_later_confirmation_by_a_person_is_kept_as_it_is(self):
        store = self.store
        a, _ = store.held_until_confirmed()
        store.old_release(a)
        store.case.release(a, PERSON, "human-isolation")
        store.commit()
        self.assertEqual(store.grant(a)["physical"], CONFIRMED)
        self.assertEqual(store.scan()["findings"], 0)

    def test_service_starts_on_the_repaired_store_and_shows_the_repair_in_audit(self):
        store = self.store
        a, _ = store.held_until_confirmed()
        grant_id = store.grant(a)["id"]
        store.old_release(a)
        store.repair("shown-in-audit")
        with patch("pool.service.LedgerBackend", DiskLedger):
            service = Service(store.path)
        try:
            view = service.read(ASSISTANT, "execution", {})
            self.assertEqual([(row["id"], row["physical"]) for row in view["grants"]], [(grant_id, CONFIRMED)])
            events = service.read(COORDINATOR, "audit", {"request": "history-repair-shown-in-audit"})["events"]
            self.assertEqual([(row["command"], row["result"]) for row in events], [("history-repair", "applied")])
            self.assertEqual({row["id"] for row in events[0]["repairs"]}, {grant_id})
        finally:
            service.close()

    def test_rows_changed_after_the_scan_are_not_touched(self):
        store = self.store
        a, _ = store.held_until_confirmed()
        store.old_release(a)
        _, plan = history_repair.scan(store.path)
        state = deepcopy(store.case.state)
        state["security"]["execution"]["grants"][store.grant(a)["id"]]["version"] += 1
        before = deepcopy(state)
        with self.assertRaises(history_repair.RepairError):
            history_repair.apply_repairs(state, plan["repairs"], 0, "fixture")
        self.assertEqual(state, before)

    def test_apply_refuses_a_running_service_and_unfinished_requests(self):
        store = self.store
        a, _ = store.held_until_confirmed()
        store.old_release(a)
        before = store.files()
        with exclusive(store.path, "service-writer.lock"):
            with self.assertRaises(Unavailable):
                store.repair("while-running")
        self.assertEqual(store.files(), before)
        with store.journal() as db:
            db.execute("INSERT INTO requests VALUES('k','f',?,'claim',?,?,NULL,NULL)", (ASSISTANT, b"{}", b"{}"))
        before = store.files()
        with self.assertRaises(history_repair.RepairError):
            store.repair("with-pending")
        self.assertEqual(store.files(), before)
        self.assertEqual(store.scan()["pending_requests"], 1)


class RequestAudit(RepairCase):
    def setUp(self):
        super().setUp()
        store = self.store
        values = {"platform": "codex", "adapter": "manual", "model": MARKERS[0], "reasoning": "high",
                  "tools_version": "unknown", "permissions_version": "unknown", "environment": MARKERS[1]}
        config = {**values, "sources": {key: "unknown" if value == "unknown" else "reported" for key, value in values.items()}}
        self.foreign = {"id": "ctx-foreign", "context_id": "ctx-foreign", "version": 1, "executor_id": FOREIGN,
                        "config": config, "at": 0, "event": "fixture"}
        store.data["contexts"]["ctx-foreign:1"] = deepcopy(self.foreign)
        store.data["defaults"][FOREIGN] = {"context_id": "ctx-foreign", "version": 1}
        store.commit()
        self.own = engine.default_context(store.case.state, ASSISTANT)
        self.leaked = store.record(ASSISTANT, "leaked", self.foreign)
        self.untouched = {
            "own": store.record(ASSISTANT, "own", self.own),
            "responsible person": store.record(FOREIGN_OWNER, "responsible", self.foreign),
            "in ledger": store.record(ASSISTANT, "stepped", self.foreign, stepped=True, status=409),
            "fact without action": store.record(FOREIGN_OWNER, "fact", self.foreign, field="reporter_context"),
        }

    def test_report_names_the_requests_without_repeating_the_configuration(self):
        report = self.store.scan()
        self.assertEqual([item["request_id"] for item in report["audit"]["journal_only"]], ["leaked"])
        self.assertEqual([item["request_id"] for item in report["audit"]["in_ledger"]], ["stepped"])
        self.assertEqual(report["audit"]["journal_only"][0]["owner"], FOREIGN)
        self.assertEqual(report["resource_end"]["repairs"], [])
        for marker in MARKERS:
            self.assertNotIn(marker, json.dumps(report, ensure_ascii=False))

    def test_rights_are_judged_as_they_stood_when_the_request_arrived(self):
        store = self.store
        store.case.state["pilot"]["identity:" + FOREIGN]["owner"] = PERSON
        store.commit()
        late = store.record(FOREIGN_OWNER, "after-transfer", self.foreign)
        report = store.scan()
        self.assertEqual(sorted(item["request_id"] for item in report["audit"]["journal_only"]), ["after-transfer", "leaked"])
        self.assertNotEqual(late, self.untouched["responsible person"])

    def test_apply_never_changes_an_audit_record(self):
        store = self.store
        before = store.files()
        result = store.repair()
        self.assertIsNone(result["event"])
        self.assertEqual(store.files(), before)
        self.assertEqual(result["remaining_findings"], 2)
        for marker in MARKERS:
            self.assertNotIn(marker, Path(result["receipt"]).read_text(encoding="utf-8"))


class CommandLine(RepairCase):
    def run_tool(self, *arguments):
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
        return subprocess.run([sys.executable, "-B", "-X", "utf8", str(ROOT / "ops" / "repair-history.py"),
                               "--store", str(self.store.path), *arguments],
                              capture_output=True, text=True, encoding="utf-8", env=environment, check=False)

    def test_default_run_is_a_report_and_apply_needs_a_backup_target(self):
        store = self.store
        a, _ = store.held_until_confirmed()
        store.old_release(a)
        before = store.files()
        done = self.run_tool()
        self.assertEqual(done.returncode, 0, done.stderr)
        report = json.loads(done.stdout)
        self.assertEqual(report["mode"], "dry-run")
        self.assertEqual(len(report["resource_end"]["repairs"]), 2)
        for arguments in (("--apply",), ("--tag", "x"), ("--archive", "/tmp/x")):
            refused = self.run_tool(*arguments)
            self.assertEqual(refused.returncode, 1, arguments)
            self.assertEqual(refused.stdout, "")
        self.assertEqual(store.files(), before)


if __name__ == "__main__":
    unittest.main()
