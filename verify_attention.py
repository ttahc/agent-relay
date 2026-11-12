"""Timeout and lost-contact reminders: who is told, when, and that nothing is ever released by them.

The first class derives reminders from a synthetic ledger state and synthetic entry times. The
second runs the packaged service on a disposable store and reads the reminders over HTTP and through
the client. No production store is read.
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
import zipfile

from pool import attention, wakeups, workbench
from verify import ROOT, call, server as running_service
from verify_delegation import ASSISTANT, OTHER, PERSON
from verify_round import activate, ai_prepare, auth_checks, invitation, setup
from verify_support import scratch
from 协作存储 import digest, encoded
import verify_v030_review_read as review_fixture

MANAGER = "manager-only"
START = datetime(2026, 11, 1, tzinfo=timezone.utc).timestamp()
HOUR = 3600


def stamp(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


class Reminders(unittest.TestCase):
    def setUp(self):
        self.service, self.state, self.task, self.claim, _ = review_fixture.fixture_service()
        self.contacts = {}
        self.service.notices = SimpleNamespace(contacts=lambda: dict(self.contacts))
        self.entries = []
        self.claim["W"]["state"] = "draft"
        self.claim["deliveries"] = {}
        self.record(START, task=self.task, claim=self.claim)

    def record(self, when, task=None, claim=None, request_task=None):
        effects = []
        if task is not None:
            effects.append({"path": ["tasks", task["task_id"]], "value": deepcopy(task)})
        if claim is not None:
            effects.append({"path": ["claims", claim["claim_id"]], "value": deepcopy(claim)})
        entry = {"type": "decision", "result": "applied", "ledger_seq": len(self.entries) + 1,
                 "prev_sha256": self.entries[-1]["sha256"] if self.entries else "0" * 64,
                 "committed_utc": stamp(when), "request": {"task_id": request_task} if request_task else {}, "effects": effects}
        entry["sha256"] = digest(encoded(entry))  # chained, as the ledger's own entries are
        self.entries.append(entry)

    def reminders(self, actor, now):
        return attention.reminders(self.service, self.state, self.entries, actor, now)

    def kinds(self, actor, now, task_id=None):
        return [(row["type"], row["task_id"]) for row in self.reminders(actor, now) if task_id in (None, row["task_id"])]

    def open_task(self, when, task_id="T09"):
        task = {"task_id": task_id, "contract": {"project_id": "project-one", "open": True, "requirements": []},
                "status": "available", "version": 1, "scope_version": 1, "receiver": PERSON, "claims": []}
        self.state["tasks"][task_id] = task
        self.record(when, task=task)
        return task

    def heartbeat(self, on=True):
        self.state["round"]["runner:" + ASSISTANT] = {"auto": False, "limit": 1, "heartbeat": on, "adapter": ""}

    def test_a_task_open_a_day_without_a_claim_is_shown_to_the_projects_human_managers_only(self):
        task = self.open_task(START)
        self.assertEqual(self.kinds(MANAGER, START + 23 * HOUR, "T09"), [])
        self.assertEqual(self.kinds(MANAGER, START + 24 * HOUR, "T09"), [("task-unclaimed", "T09")])
        for other in (ASSISTANT, OTHER):  # windows: not human managers
            self.assertNotIn(("task-unclaimed", "T09"), self.kinds(other, START + 48 * HOUR), other)
        row = next(r for r in self.reminders(MANAGER, START + 30 * HOUR) if r["task_id"] == "T09")
        self.assertEqual((row["since"], row["seconds"], row["project_id"]), (int(START), 30 * HOUR, "project-one"))
        self.assertIn("30 小时", attention.describe(row))
        task["status"] = "running"
        self.assertEqual(self.kinds(MANAGER, START + 48 * HOUR, "T09"), [], "taken: nothing to remind")

    def test_the_clock_restarts_when_a_task_becomes_claimable_again(self):
        task = self.open_task(START)
        held = {**task, "status": "running"}
        self.record(START + 10 * HOUR, task=held)
        self.record(START + 20 * HOUR, task=task)  # handed back
        self.assertEqual(self.kinds(MANAGER, START + 40 * HOUR, "T09"), [])
        self.assertEqual(self.kinds(MANAGER, START + 44 * HOUR, "T09"), [("task-unclaimed", "T09")])
        self.assertEqual(next(r for r in self.reminders(MANAGER, START + 44 * HOUR) if r["task_id"] == "T09")["since"], int(START + 20 * HOUR))

    def test_a_held_task_is_not_reported_as_unclaimed_and_closed_contracts_are_ignored(self):
        task = self.open_task(START)
        task["contract"]["open"] = False
        self.entries.pop()
        self.record(START, task=task)
        self.assertEqual(self.kinds(MANAGER, START + 48 * HOUR, "T09"), [])

    def test_a_silent_window_holding_a_claim_is_shown_to_its_owner_and_managers(self):
        self.heartbeat()
        self.contacts[ASSISTANT] = START + 100
        now = START + 100 + attention.SILENT_SECONDS
        self.assertEqual(self.kinds(PERSON, now - 1), [])
        self.assertIn(("claim-silent", "T01"), self.kinds(PERSON, now))
        self.assertIn(("claim-silent", "T01"), self.kinds(MANAGER, now))
        self.assertEqual(self.kinds(OTHER, now), [])
        self.assertEqual(self.kinds(ASSISTANT, now), [], "the window itself is not reminded of its own silence")
        row = next(r for r in self.reminders(PERSON, now) if r["type"] == "claim-silent")
        self.assertEqual((row["claim_id"], row["holder"], row["since"]), ("claim-one", ASSISTANT, int(START + 100)))
        first = row["key"]
        self.contacts[ASSISTANT] = now
        self.assertNotIn(("claim-silent", "T01"), self.kinds(PERSON, now + 1), "heard from again")
        self.contacts[ASSISTANT] = now - 5000
        self.assertNotEqual(next(r for r in self.reminders(PERSON, now) if r["type"] == "claim-silent")["key"], first)

    def test_without_heartbeats_or_any_contact_silence_is_not_inferred(self):
        self.heartbeat(False)
        self.contacts[ASSISTANT] = START
        self.assertNotIn("claim-silent", [k for k, _ in self.kinds(PERSON, START + 10 * HOUR)])
        self.heartbeat()
        del self.contacts[ASSISTANT]
        self.assertNotIn("claim-silent", [k for k, _ in self.kinds(PERSON, START + 10 * HOUR)])

    def test_a_claim_with_nothing_recorded_for_a_day_is_stalled_and_any_record_restarts_the_clock(self):
        self.assertEqual(self.kinds(PERSON, START + 23 * HOUR), [])
        self.assertEqual(self.kinds(PERSON, START + 24 * HOUR), [("claim-stalled", "T01")])
        self.record(START + 20 * HOUR, request_task="T01")  # e.g. an execution fact naming the task
        self.assertEqual(self.kinds(PERSON, START + 30 * HOUR), [])
        self.assertEqual(self.kinds(MANAGER, START + 44 * HOUR), [("claim-stalled", "T01")])
        self.claim["L"] = "ended"
        self.assertEqual(self.kinds(MANAGER, START + 44 * HOUR), [])

    def test_reminders_change_nothing_and_never_release(self):
        self.heartbeat()
        self.contacts[ASSISTANT] = START
        self.open_task(START)
        before = deepcopy(self.state)
        found = self.reminders(MANAGER, START + 50 * HOUR)
        self.assertEqual({row["type"] for row in found}, set(attention.KINDS))
        self.assertEqual(self.state, before)
        self.assertEqual(found, self.reminders(MANAGER, START + 50 * HOUR))
        self.assertEqual(self.claim["L"], "active")

    def test_entries_are_read_once_and_a_rewritten_ledger_is_read_again(self):
        self.open_task(START)
        self.assertEqual(attention.times(self.entries)["T09"], (START, START))
        changed = deepcopy(self.entries)
        changed[-1]["sha256"] = "f" * 64
        changed[-1]["committed_utc"] = stamp(START + 5)
        self.assertEqual(attention.times(changed)["T09"], (START + 5, START + 5))
        self.assertEqual(attention.times([]), {})

    def test_token_mode_and_states_without_entry_times_raise_nothing(self):
        del self.service.notices
        self.assertEqual(self.reminders(MANAGER, START + 99 * HOUR), [])
        self.service.notices = SimpleNamespace(contacts=dict)
        untimed = []
        for entry in deepcopy(self.entries):  # an older ledger: entries written before times were kept
            entry.pop("committed_utc")
            entry["sha256"] = digest(encoded({k: v for k, v in entry.items() if k != "sha256"}))
            untimed.append(entry)
        self.assertEqual(attention.reminders(self.service, self.state, untimed, MANAGER, START + 99 * HOUR), [])

    def test_wait_events_carry_the_reminders(self):
        self.service.snapshot = lambda: {"state": self.state, "entries": self.entries}
        self.open_task(START - 30 * HOUR)
        rows = [row for row in wakeups.events(self.service, self.state, MANAGER) if row["type"] in attention.KINDS]
        self.assertEqual(sorted((row["type"], row["task_id"]) for row in rows), [("claim-stalled", "T01"), ("task-unclaimed", "T09")])
        self.assertTrue(all(wakeups.CURSOR.fullmatch(row["key"]) for row in rows))

    def test_the_workbench_puts_a_reminded_task_first_with_its_message(self):
        task = {"stage": "available", "reminders": [{"type": "task-unclaimed", "key": "k", "message": "已开放 30 小时，仍无人领取"}]}
        self.assertEqual(workbench.todo_reason(task, MANAGER, {}), "提醒：已开放 30 小时，仍无人领取")
        base = {"tasks": [{"task_id": "T09", "reminders": []}], "projects": []}
        reminded = {"tasks": [{"task_id": "T09", "reminders": [{"key": "k"}]}], "projects": []}
        self.assertNotEqual(workbench.workspace_revision(base), workbench.workspace_revision(reminded))


class Served(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = scratch("attention-")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.project = project = Path(cls.scratch.name)
        with zipfile.ZipFile(ROOT / "dist" / "task-pool-local.zip") as package:
            package.extractall(project)
        _, tokens, password = setup(project)
        cls.running = running_service(project)
        _, cls.url = cls.running.__enter__()
        cls.addClassCleanup(cls.running.__exit__, None, None, None)
        admin, _, _ = auth_checks(project, cls.url, tokens, password)
        _, (status, issued) = ai_prepare(cls.url, invitation(admin, "worker-a"), session="attention-session")
        assert status == 200, (status, issued)
        activate(cls.url, issued)
        cls.token = issued["token"]

    def test_the_route_answers_with_limits_and_is_announced(self):
        status, value = call(self.url + "/attention", self.token)
        self.assertEqual(status, 200)
        self.assertEqual(value["reminders"], [])
        self.assertEqual(value["limits"], {"unclaimed_seconds": 86400, "silent_seconds": 600, "stalled_seconds": 86400})
        self.assertIs(value["releases"], False)
        self.assertEqual(call(self.url + "/attention")[0], 401)
        self.assertIs(call(self.url + "/features", self.token)[1]["features"]["attention"], True)

    def test_the_client_command_reads_the_same_view(self):
        state = self.project / "attention.credential"
        state.write_text(json.dumps({"url": self.url.removesuffix("/v1"), "token": self.token}), encoding="utf-8")
        state.chmod(0o600)
        done = subprocess.run([sys.executable, "-B", "-X", "utf8", str(ROOT / "ops/round-client.py"), "--state", str(state),
                               "--allow-loopback", "attention"], capture_output=True, cwd=self.project, timeout=120,
                              env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        self.assertEqual(done.returncode, 0, done.stderr.decode("utf-8", "replace")[-800:])
        self.assertEqual(json.loads(done.stdout)["limits"]["silent_seconds"], 600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
