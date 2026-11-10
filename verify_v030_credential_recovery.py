"""Fail-closed executor issuance after ledger commit and interrupted private SQL sync."""
from copy import deepcopy
import json
from pathlib import Path
import secrets
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from pool import round_service
from pool.httpd import Server
from pool.service import COORDINATOR, Service
import 协作本轮 as round_rules
import 协作升级 as rules
from 协作存储 import digest, encoded
from verify_delegation import ASSISTANT, PERSON, fixture


ROOT = Path(__file__).resolve().parent


class MemoryLedger:
    stores = {}

    def __init__(self, store):
        self.store = Path(store)
        self.meta = {"qualification": {}, "migration": False, "coordinator": COORDINATOR, "repo_id": "credential-fixture"}
        self.data = self.stores[str(self.store)]

    def check_qualification(self, *_):
        pass

    def read(self):
        return {"state": deepcopy(self.data["state"]), "head": len(self.data["terminal"]), "sha256": "a" * 64,
                "halted": None, "entries": deepcopy(self.data["entries"]),
                "control": {"terminal": deepcopy(self.data["terminal"]), "closed": {}}}

    def copies(self):
        return self.data["copies"]

    def receive(self, env, *_):
        self.data["copies"].append({"envelope": deepcopy(env), "sha256": digest(encoded(env))})

    def process(self, *_, **kwargs):
        for record in self.data["copies"]:
            env = record["envelope"]
            key = env["origin_id"] + "/" + env["event_id"]
            if key in self.data["terminal"]:
                continue
            before = deepcopy(self.data["state"])
            round_rules.action(self.data["state"], env, {"now": time.time()})
            row = {"origin_id": env["origin_id"], "origin_seq": env["origin_seq"], "key": key,
                   "type": "decision", "command": env["command"], "result": "applied", "reason": "",
                   "content_sha256": record["sha256"], "ledger_seq": len(self.data["terminal"]) + 1, "sha256": "b" * 64}
            from 协作账本 import effects_between
            row["effects"] = effects_between(before, self.data["state"])
            self.data["terminal"][key] = row
            self.data["entries"].append(row)
        return self.read()


class CredentialRecovery(unittest.TestCase):
    def setUp(self):
        (ROOT / ".state").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="credential-recovery-", dir=ROOT / ".state")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        state = fixture()
        state["pilot"]["format"]["min_reader"] = 3
        rules.identity(state, ASSISTANT).update(credential=1, token_expires=int(time.time()) + 86400, last_contact=time.time())
        self.state = state
        MemoryLedger.stores[str(self.root)] = {"state": state, "terminal": {}, "entries": [], "copies": []}
        self.reader = patch("pool.service.LedgerBackend", MemoryLedger)
        self.reader.start()
        self.addCleanup(self.reader.stop)
        self.service = Service(self.root)
        self.addCleanup(lambda: self.service.close())
        self.server = object.__new__(Server)
        self.server.service, self.server.tokens = self.service, {}
        self.old = secrets.token_urlsafe(32)
        with self.service.db:
            self.service.accounts.issue_executor(ASSISTANT, self.old, int(time.time()) + 86400, 1)

    def restart(self):
        self.service.close()
        self.service = Service(self.root)
        self.server.service = self.service

    def submit(self, action, actor=PERSON, **body):
        body = {"request_id": "fixture-" + secrets.token_hex(8), **body}
        status, value = self.service.submit(actor, action, body["request_id"], body)
        self.assertEqual(status, 200)
        return value

    def prepare(self, operation="pause"):
        self.submit("window-admin", name=ASSISTANT, version=1, operation=operation, reason="isolated lifecycle",
                    **({"owner": "other-person"} if operation == "transfer" else {}))
        actor = "other-person" if operation == "transfer" else PERSON
        value = self.submit("token-prepare", actor=actor, name=ASSISTANT, version=2,
                            reason="fresh isolated activation", proof_sha="a" * 64)
        record = self.state["round"]["enrollment:" + value["registration_id"]]
        return actor, record, round_service.token_for(self.service, record)

    def fail_activation(self, actor, record):
        body = {"request_id": "activation-fault", "registration_id": record["id"]}
        original = self.service.accounts.issue_executor
        def fail_after_sql(*args, **kwargs):
            original(*args, **kwargs)
            raise sqlite3.OperationalError("synthetic private issuance transaction failure")
        with patch.object(self.service.accounts, "issue_executor", side_effect=fail_after_sql):
            with self.assertRaises(sqlite3.OperationalError):
                self.service.submit(actor, "ai-activate", body["request_id"], body)
        self.assertEqual(self.state["pilot"]["identity:" + ASSISTANT]["credential"], 3)
        self.assertEqual(self.state["pilot"]["identity:" + ASSISTANT]["status"], "active")
        self.assertIsNone(self.service.db.execute("SELECT status FROM requests WHERE action='ai-activate'").fetchone()[0])
        self.assertEqual(self.service.db.execute("SELECT credential FROM executor_credential_versions WHERE name=?", (ASSISTANT,)).fetchone()[0], 1)

    def test_ledger_active_sql_failure_keeps_old_and_new_tokens_invalid_until_exact_recovery(self):
        self.assertEqual(self.server.actor_for_token(self.old), ASSISTANT)
        actor, record, new = self.prepare()
        self.assertIsNone(self.server.actor_for_token(self.old))
        self.fail_activation(actor, record)
        self.assertIsNone(self.server.actor_for_token(self.old))
        self.assertIsNone(self.server.actor_for_token(new))
        self.assertIsNone(self.service.credential_version(ASSISTANT))
        self.restart()
        self.assertIsNone(self.server.actor_for_token(self.old))
        self.assertIsNone(self.server.actor_for_token(new))
        self.assertTrue(self.service.recover())
        self.assertEqual(self.server.actor_for_token(new), ASSISTANT)
        self.assertIsNone(self.server.actor_for_token(self.old))
        self.assertEqual(self.service.credential_version(ASSISTANT), 3)
        self.restart()
        self.assertEqual(self.server.actor_for_token(new), ASSISTANT)
        self.assertIsNone(self.server.actor_for_token(self.old))

    def test_migration_cannot_stamp_old_hash_at_new_version_with_unfinished_activation(self):
        actor, record, new = self.prepare()
        self.fail_activation(actor, record)
        with self.service.db:
            self.service.db.execute("DELETE FROM executor_credential_versions")
        before = self.service.db.execute("SELECT * FROM enrolled_accounts").fetchall()
        self.restart()
        self.assertEqual(self.service.db.execute("SELECT * FROM executor_credential_versions").fetchall(), [])
        self.assertEqual(self.service.db.execute("SELECT * FROM enrolled_accounts").fetchall(), before)
        self.assertIsNone(self.server.actor_for_token(self.old))
        self.assertTrue(self.service.recover())
        self.assertEqual(self.server.actor_for_token(new), ASSISTANT)

    def test_existing_v2_and_v020_version_one_tokens_gain_safe_mapping_without_changing_old_rows(self):
        for schema in (2, 3):
            with self.subTest(schema=schema):
                self.state["pilot"]["format"].update(schema=schema, min_reader=schema)
                with self.service.db:
                    self.service.db.execute("DELETE FROM executor_credential_versions")
                before = self.service.db.execute("SELECT * FROM enrolled_accounts").fetchall()
                self.restart()
                self.assertEqual(self.server.actor_for_token(self.old), ASSISTANT)
                self.assertEqual(self.service.db.execute("SELECT * FROM enrolled_accounts").fetchall(), before)
                self.assertTrue(self.service.accounts.executor_current(ASSISTANT, 1, self.old))

    def test_existing_current_active_enrollment_requires_matching_derived_hash(self):
        self.state["round"]["enrollment:existing"] = {"id": "existing", "name": ASSISTANT, "version": 4, "state": "active"}
        rules.identity(self.state, ASSISTANT).update(credential=4)
        current = round_service.token_for(self.service, self.state["round"]["enrollment:existing"])
        with self.service.db:
            self.service.db.execute("DELETE FROM executor_credential_versions")
        self.restart()
        self.assertIsNone(self.server.actor_for_token(self.old))
        self.assertEqual(self.service.db.execute("SELECT * FROM executor_credential_versions").fetchall(), [])
        with self.service.db:
            self.service.db.execute("UPDATE enrolled_accounts SET token_sha=? WHERE name=?", (digest(current.encode("ascii")), ASSISTANT))
        self.restart()
        self.assertEqual(self.server.actor_for_token(current), ASSISTANT)

    def test_unknown_unfinished_executor_change_prevents_baseline_inference(self):
        with self.service.db:
            self.service.db.execute("DELETE FROM executor_credential_versions")
            self.service.db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)",
                ("ambiguous", "a" * 64, PERSON, "ai-activate", b"{}", b"{}", None, None))
        self.restart()
        self.assertIsNone(self.server.actor_for_token(self.old))
        self.assertEqual(self.service.db.execute("SELECT * FROM executor_credential_versions").fetchall(), [])

    def test_disable_archive_and_owner_transfer_restore_only_fresh_token(self):
        for operation in ("disable", "archive", "transfer"):
            with self.subTest(operation=operation):
                # Each transition advances from its actual current generation.
                credential = rules.identity(self.state, ASSISTANT)["credential"]
                owner = rules.identity(self.state, ASSISTANT)["owner"]
                self.submit("window-admin", actor=owner, name=ASSISTANT, version=credential, operation=operation, reason="isolated lifecycle",
                            **({"owner": "other-person" if owner == PERSON else PERSON} if operation == "transfer" else {}))
                self.assertIsNone(self.server.actor_for_token(self.old))
                actor = rules.identity(self.state, ASSISTANT)["owner"]
                pending = self.submit("token-prepare", actor=actor, name=ASSISTANT, version=credential+1,
                                      reason="restore with new identity proof", proof_sha="b" * 64)
                record = self.state["round"]["enrollment:" + pending["registration_id"]]
                new = round_service.token_for(self.service, record)
                self.submit("ai-activate", actor=actor, registration_id=record["id"])
                self.assertEqual(self.server.actor_for_token(new), ASSISTANT)
                self.assertIsNone(self.server.actor_for_token(self.old))
                self.restart()
                self.assertEqual(self.server.actor_for_token(new), ASSISTANT)
                self.old = new

    def test_static_legacy_bootstrap_remains_version_one_only_and_cannot_bypass_new_mapping(self):
        self.server.tokens = {ASSISTANT: self.old}
        self.assertEqual(self.server.actor_for_token(self.old), ASSISTANT)
        actor, record, _ = self.prepare()
        self.fail_activation(actor, record)
        self.assertIsNone(self.server.actor_for_token(self.old))

    def test_static_version_one_without_private_account_row_survives_until_an_unfinished_change(self):
        self.server.tokens = {ASSISTANT: self.old}
        with self.service.db:
            self.service.db.execute("DELETE FROM executor_credential_versions")
            self.service.db.execute("DELETE FROM enrolled_accounts WHERE name=?", (ASSISTANT,))
        self.restart()
        self.assertEqual(self.server.actor_for_token(self.old), ASSISTANT)
        with self.service.db:
            self.service.db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)",
                ("unknown-activation", "a" * 64, PERSON, "ai-activate", b"{}", b"{}", None, None))
        self.restart()
        self.assertIsNone(self.server.actor_for_token(self.old))

    def test_static_hash_cannot_bypass_current_private_hash_even_at_version_one(self):
        self.server.tokens = {ASSISTANT: self.old}
        current = secrets.token_urlsafe(32)
        with self.service.db:
            self.service.accounts.issue_executor(ASSISTANT, current, int(time.time()) + 86400, 1)
        self.assertIsNone(self.server.actor_for_token(self.old))
        self.assertEqual(self.server.actor_for_token(current), ASSISTANT)

    def test_v2_higher_version_baseline_needs_terminal_issuance_and_corresponding_ledger_effect(self):
        self.state["pilot"]["format"].update(schema=2, min_reader=2)
        rules.identity(self.state, ASSISTANT)["credential"] = 4
        key, event = "old-v2-issuance", "old-v2-event"
        token = self.service.accounts.token("account", key, ASSISTANT)
        response = {"issued_to": ASSISTANT, "steps": [{"event_id": event, "result": "applied"}]}
        with self.service.db:
            self.service.db.execute("DELETE FROM executor_credential_versions")
            self.service.db.execute("UPDATE enrolled_accounts SET token_sha=? WHERE name=?", (digest(token.encode("ascii")), ASSISTANT))
            self.service.db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)",
                (key, "a" * 64, PERSON, "credential-change", b"{}", None, 200, encoded(response)))
        self.restart()
        self.assertIsNone(self.server.actor_for_token(token))
        MemoryLedger.stores[str(self.root)]["entries"].append({"key": COORDINATOR + "/" + event, "result": "applied",
            "effects": [{"path": ["pilot", "identity:" + ASSISTANT], "value": deepcopy(rules.identity(self.state, ASSISTANT))}]})
        self.restart()
        self.assertEqual(self.server.actor_for_token(token), ASSISTANT)
        self.assertTrue(self.service.accounts.executor_current(ASSISTANT, 4, token))


if __name__ == "__main__":
    unittest.main()
