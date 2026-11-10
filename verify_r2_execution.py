"""Isolated security-5 actions, atomic resources, context scope and fact recovery."""
import base64
from copy import deepcopy
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pool import execution
import 协作执行 as engine
import 协作升级 as rules
from 协作存储 import Rejected, digest
from verify_delegation import fixture, ASSISTANT, OTHER, PERSON


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.state = fixture()
        self.state.update(reservations={}, security={"schema": 5, "phase": "ready", "physical_blockers": {}})
        self.state["tasks"] = {"T01": {"task_id": "T01", "scope_version": 1, "version": 1, "status": "running", "receiver": PERSON,
            "claims": ["ca", "cb"], "dependencies": [], "resources": [{"id": "path:work", "mode": "write"}],
            "contract": {"project_id": "project-one", "open": True, "requirements": []}}}
        for actor, cid in ((ASSISTANT, "ca"), (OTHER, "cb")):
            rules.identity(self.state, actor).update(platform="codex", model="unknown", environment="env", token_expires=time.time()+99999)
            self.state["pilot"][f"grant:project-one:{actor}"] = {"roles": ["executor"], "resources": [{"id": "path:work", "mode": "write"}], "version": 1}
            self.state["claims"][cid] = {"claim_id": cid, "task_id": "T01", "origin": actor, "L": "active", "epoch": 1,
                "W": {"scope": 1, "state": "draft"}, "E": {"state": "running"}, "R": [], "deliveries": {}}
            self.state["round"]["runner:"+actor] = {"limit": 4}
        self.counter = 0
        engine.ensure(self.state)
        self.context(ASSISTANT)
        self.context(OTHER)

    @property
    def data(self):
        return self.state["security"]["execution"]

    def call(self, op, actor=ASSISTANT, **body):
        self.counter += 1
        key = "id-"+str(self.counter)
        p = {"op": op, "id": key, **body, "_audit": {"actor": actor, "credential_version": rules.identity(self.state, actor)["credential"]}}
        if op == "action-start":
            p.setdefault("permit_id", "permit-"+key)
        engine.action(self.state, {"payload": p, "event_id": key}, {"now": time.time(), "phase": "running"})
        return p["id"]

    def context(self, actor, **changes):
        config = {key: "unknown" for key in engine.DIMENSIONS}
        config.update(platform="codex", adapter="manual", environment="env", **changes)
        config["sources"] = {key: "unknown" if config[key] == "unknown" else "reported" for key in engine.DIMENSIONS}
        context_id = "ctx-"+actor
        prior = max((row["version"] for row in self.data["contexts"].values() if row["context_id"] == context_id), default=0)
        self.call("context-save", actor, context_id=context_id, version=prior, config=config, make_default=True)
        return context_id, prior+1

    def prepare(self, actor=ASSISTANT, mode="write", path="path:work/item", domain="manual-unverified"):
        selected = self.data["defaults"][actor]
        segment = self.call("segment-open", actor, task_id="T01", claim_id="ca" if actor == ASSISTANT else "cb", scope_version=1,
                            epoch=1, context_id=selected["context_id"], context_version=selected["version"])
        resources = [{"id": path, "mode": mode, "domain": domain}]
        return self.call("action-prepare", actor, segment_id=segment, version=1, description="synthetic work", resources=resources, adapter_id="manual")

    def request(self, aid):
        action = self.data["actions"][aid]
        return self.call("resource-request", action["executor_id"], action_id=aid, version=action["version"], resources=action["resources"])

    def start(self, aid):
        action = self.data["actions"][aid]
        self.call("action-start", action["executor_id"], action_id=aid, version=action["version"], grant_id=action["grant_id"], generation=action["generation"])

    def release(self, aid, actor=None, basis="unconfirmed"):
        action = self.data["actions"][aid]
        grant = self.data["grants"][action["grant_id"]]
        self.call("resource-release", actor or action["executor_id"], action_id=aid, grant_id=grant["id"], generation=grant["generation"],
                  version=grant["version"], basis=basis, evidence={"note": "checked physical isolation evidence", "sha256": "a"*64})

    def test_default_switch_does_not_rewrite_segments_claims_or_resources(self):
        aid = self.prepare()
        segment = deepcopy(self.data["segments"][self.data["actions"][aid]["segment_id"]])
        claims = deepcopy(self.state["claims"])
        self.context(ASSISTANT, model="different-model")
        self.assertEqual(self.data["segments"][segment["id"]], segment)
        self.assertEqual(self.state["claims"], claims)

    def test_untrusted_domain_spelling_cannot_bypass_same_physical_resource(self):
        a, b = self.prepare(domain="invented-a"), self.prepare(OTHER, domain="invented-b")
        self.request(a)
        request = self.request(b)
        self.assertEqual(self.data["resource_requests"][request]["state"], "queued")
        self.assertEqual(len(self.data["grants"]), 1)

    def test_fifo_writer_is_not_overtaken_by_later_shared_reader(self):
        a, b, c = self.prepare(mode="read"), self.prepare(OTHER), self.prepare(mode="read")
        self.request(a)
        rb, rc = self.request(b), self.request(c)
        self.assertEqual(self.data["resource_requests"][rb]["state"], "queued")
        self.assertEqual(self.data["resource_requests"][rc]["state"], "queued")
        self.release(a)
        self.assertEqual(self.data["resource_requests"][rb]["state"], "granted")
        self.assertEqual(self.data["resource_requests"][rc]["state"], "queued")

    def test_complete_resource_set_grants_atomically_and_holding_cannot_append(self):
        a = self.prepare()
        self.request(a)
        before = deepcopy(self.state)
        with self.assertRaises(Rejected):
            self.call("resource-request", action_id=a, version=self.data["actions"][a]["version"], resources=[
                {"id": "path:work/new", "mode": "write", "domain": "manual-unverified"}])
        self.assertEqual(self.state, before)

    def test_start_permission_makes_physical_unknown_and_owner_report_never_frees_it(self):
        a, b = self.prepare(), self.prepare(OTHER)
        self.request(a)
        self.start(a)
        self.release(a)
        self.assertEqual(self.data["grants"][self.data["actions"][a]["grant_id"]]["physical"], "unknown")
        request = self.request(b)
        self.assertEqual(self.data["resource_requests"][request]["state"], "queued")
        self.release(a, actor=PERSON, basis="human-isolation")
        self.assertEqual(self.data["resource_requests"][request]["state"], "granted")

    def test_unconfirmed_action_cannot_get_second_start_and_old_grant_cannot_free_new(self):
        a, b = self.prepare(), self.prepare(OTHER)
        self.request(a); self.start(a)
        self.release(a)
        with self.assertRaises(Rejected):
            self.start(a)
        self.request(b)
        self.release(a, PERSON, "human-isolation")
        new_grant = deepcopy(self.data["grants"][self.data["actions"][b]["grant_id"]])
        old = self.data["grants"][self.data["actions"][a]["grant_id"]]
        with self.assertRaises(Rejected):
            self.call("resource-release", action_id=a, grant_id=new_grant["id"], generation=old["generation"], version=new_grant["version"],
                      basis="human-isolation", evidence={"note": "wrong grant", "sha256": "a"*64})
        self.assertEqual(self.data["grants"][new_grant["id"]], new_grant)

    def test_cancel_granted_request_does_not_guess_program_stop(self):
        a = self.prepare(); request = self.request(a)
        before = deepcopy(self.data["grants"])
        row = self.data["resource_requests"][request]
        self.call("resource-cancel", resource_request_id=request, version=row["version"])
        self.assertEqual(self.data["grants"], before)

    def test_fact_after_project_revoke_is_narrow_and_old_epoch_does_not_change_current_action(self):
        a = self.prepare(); self.request(a); self.start(a)
        action = deepcopy(self.data["actions"][a])
        self.state["pilot"][f"grant:project-one:{ASSISTANT}"]["roles"] = []
        self.state["claims"]["ca"]["epoch"] = 2
        self.call("execution-fact", task_id="T01", claim_id="ca", scope_version=1, epoch=1, action_id=a, kind="finished",
                  evidence={"note": "old operation ended", "sha256": "b"*64}, permit_id=action["permit_id"], reporter_basis={"kind": "owner", "note": "original executor"})
        self.assertEqual(self.data["actions"][a], action)
        self.assertEqual(len(execution.read(self.state, ASSISTANT)["facts"]), 1)
        self.assertEqual(execution.read(self.state, OTHER)["facts"], [])

    def test_legacy_migration_preserves_exact_business_facts_and_blocks_same_claim_new_segment(self):
        self.state["claims"]["ca"]["R"] = ["legacy-r"]
        self.state["reservations"]["legacy-r"] = {"claim_id": "ca", "active": True, "id": "path:work", "mode": "write"}
        claims = deepcopy(self.state["claims"])
        engine.migrate_legacy(self.state, time.time(), "migration")
        self.assertEqual(self.state["claims"], claims)
        with self.assertRaises(Rejected):
            self.prepare()

    def test_generic_skill_not_forced_to_model_and_unknown_verified_dependency_does_not_match(self):
        context = engine.default_context(self.state, ASSISTANT)
        record = {"kind": "skill", "level": "declared"}
        record.update(engine.bind_evidence(self.state, ASSISTANT, record, project_id="project-one", capability_id="language"))
        self.assertEqual(record["applicability"]["dependencies"], {"platform": "codex"})

        self.assertTrue(engine.match_context(self.state, ASSISTANT, record, context, {"id": "language", "evidence": "declared"}))
        record["applicability"]["dependencies"] = {"model": "unknown"}
        self.assertFalse(engine.match_context(self.state, ASSISTANT, record, context, {"id": "language", "evidence": "verified"}))

    def test_capability_definition_dependencies_cannot_be_removed_and_unrelated_changes_survive(self):
        self.data["capability_definitions"]["project-one:file-read"] = {"dimensions": ["platform", "environment"], "rule_version": 1}
        record = {"kind": "environment", "level": "verified"}
        with self.assertRaises(Rejected):
            engine.bind_evidence(self.state, ASSISTANT, record, project_id="project-one", capability_id="file-read", requested_dimensions=[])
        record.update(engine.bind_evidence(self.state, ASSISTANT, record, project_id="project-one", capability_id="file-read", verified=True))
        changed = deepcopy(engine.default_context(self.state, ASSISTANT)); changed["config"]["model"] = "another"
        req = {"id": "file-read", "project_id": "project-one", "evidence": "verified"}
        self.assertTrue(engine.match_context(self.state, ASSISTANT, record, changed, req))
        changed["config"]["platform"] = "claude"
        self.assertFalse(engine.match_context(self.state, ASSISTANT, record, changed, req))

    def test_prepared_and_queued_do_not_fill_execution_limit_but_start_does(self):
        a = self.prepare(); self.request(a)
        self.assertEqual(engine.execution_load(self.state, ASSISTANT)["executing"], 0)
        self.start(a)
        self.assertEqual(engine.execution_load(self.state, ASSISTANT)["executing"], 1)

    def test_schema_and_credential_checks_are_mandatory(self):
        self.state["security"]["schema"] = 4
        with self.assertRaises(Rejected):
            self.prepare()
        self.state["security"]["schema"] = 5
        with self.assertRaises(Rejected):
            engine.action(self.state, {"payload": {"op": "context-save", "_audit": {"actor": ASSISTANT, "credential_version": 1}}, "event_id": "bad"}, {"now": time.time()})

    def test_pool_plan_stash_checks_hash_immutable_reference_and_stable_permit(self):
        service = SimpleNamespace(lifecycle=SimpleNamespace(status=lambda: {"phase": "running"}))
        raw = b"preserved prior result"
        body = {"request_id": "stash", "task_id": "T01", "claim_id": "ca", "scope_version": 1, "epoch": 1, "action_id": None,
                "files": [{"name": "result.txt", "sha256": digest(raw), "content_base64": base64.b64encode(raw).decode()}],
                "reporter_basis": {"kind": "owner", "note": "prior result"}}
        result = execution.plan(service, ASSISTANT, "evidence-stash", "a"*64, body, self.state)
        instruction = result["steps"][0]
        self.assertTrue(instruction["file"][0].startswith("evidence-stash/ca/"))
        self.assertNotIn("content_base64", str(instruction["payload"]))
        a = self.prepare(); self.request(a)
        action = self.data["actions"][a]
        result = execution.plan(service, ASSISTANT, "action-start", "b"*64, {"request_id": "start", "action_id": a,
            "version": action["version"], "grant_id": action["grant_id"], "generation": action["generation"]}, self.state)
        self.assertEqual(result["steps"][0]["payload"]["permit_id"], result["round_result"]["action"]["permit_id"])

    def test_trusted_alias_identity_and_directory_ancestry_block_writes_but_independent_files_parallel(self):
        left = {"id": "path:work/a", "mode": "write", "domain": "one", "resolved": True, "identity": "dev:1", "canonical_path": "/tmp/work/a"}
        alias = {**left, "id": "path:work/alias", "domain": "two", "canonical_path": "/tmp/other/alias"}
        self.assertTrue(engine.conflict(self.state, left, alias))
        directory = {**left, "identity": "dev:2", "canonical_path": "/tmp/work"}
        self.assertTrue(engine.conflict(self.state, left, directory))
        other = {**left, "identity": "dev:3", "canonical_path": "/tmp/work/b"}
        self.assertFalse(engine.conflict(self.state, left, other))

    def test_human_fact_only_clears_explicit_original_blocker_and_retains_claim_facts(self):
        self.state["security"]["physical_blockers"] = {key: {"id": key, "claim_id": "ca", "epoch": epoch, "active": True,
            "physical": "unknown", "resources": [{"id": "path:work", "mode": "write"}]} for key, epoch in (("old", 1), ("new", 2))}
        claims = deepcopy(self.state["claims"])
        self.call("execution-fact", PERSON, task_id="T01", claim_id="ca", scope_version=1, epoch=1, action_id=None, kind="stopped",
                  evidence={"note": "physical isolation checked", "sha256": "a"*64}, permit_id=None,
                  reporter_basis={"kind": "human", "note": "project manager checked evidence"}, blocker_ids=["old"])
        self.assertFalse(self.state["security"]["physical_blockers"]["old"]["active"])
        self.assertTrue(self.state["security"]["physical_blockers"]["new"]["active"])
        self.assertEqual(self.state["claims"], claims)

    def test_started_fact_with_prior_permit_is_allowed_during_drain_but_new_start_is_not(self):
        a = self.prepare(); self.request(a); self.start(a)
        action = self.data["actions"][a]
        fact = {"op": "execution-fact", "id": "late-started", "task_id": "T01", "claim_id": "ca", "scope_version": 1, "epoch": 1,
                "action_id": a, "kind": "started", "evidence": {"note": "prior permission process receipt", "sha256": "a"*64},
                "permit_id": action["permit_id"], "reporter_basis": {"kind": "owner", "note": "original process receipt"},
                "_audit": {"actor": ASSISTANT, "credential_version": 7}}
        engine.action(self.state, {"payload": fact, "event_id": "late-started"}, {"now": time.time(), "phase": "draining"})
        self.assertEqual(self.data["actions"][a]["state"], "running")

    def test_freeze_claim_preserves_claim_and_copies_capability_reference(self):
        claim = self.state["claims"]["ca"]
        before = deepcopy(claim)
        row = engine.freeze_claim(self.state, self.state["tasks"]["T01"], ASSISTANT, claim, time.time())
        self.assertEqual(claim, before)
        self.assertEqual(row["context_id"], self.data["defaults"][ASSISTANT]["context_id"])

    def test_task_filtered_view_keeps_queued_request_and_human_can_report(self):
        a, b = self.prepare(), self.prepare(OTHER)
        self.request(a); queued = self.request(b)
        view = execution.read(self.state, OTHER, {"task_id": "T01"})
        self.assertIn(queued, {row["id"] for row in view["resource_requests"]})
        manager = execution.read(self.state, PERSON, {"task_id": "T01"})
        self.assertTrue(all(row["can_report"] and row["reporter_kind"] == "human" for row in manager["actions"]))

    def test_v5_capability_request_keeps_selected_context_when_default_changes(self):
        from pool import window_admin
        self.context(ASSISTANT, model="model-one")
        body = {"request_id": "cap-req", "project_id": "project-one", "capability": "language", "kind": "skill", "value": "yes",
                "evidence": {"note": "independent reproducible language evidence", "sha256": "a"*64}, "environment": "env", "expires": int(time.time())+3600}
        p = window_admin.payload(self.state, ASSISTANT, "capability-request", body, "c"*64)
        window_admin.capability_action(self.state, p, ASSISTANT, time.time(), "request")
        first_context = p["record"]["context_version"]
        self.context(ASSISTANT, model="model-two")
        window_admin.capability_action(self.state, {"op": "capability-resolve", "id": p["id"], "version": 1, "decision": "approve",
            "level": "verified", "reason": "human checked evidence against selected configuration"}, PERSON, time.time(), "resolved")
        record = self.state["pilot"][f"cap:project-one:{ASSISTANT}:language"]
        self.assertEqual(record["context_version"], first_context)
        self.assertEqual(record["applicability"]["dependencies"], {"platform": "codex"})


class ServiceIntegration(unittest.TestCase):
    def test_standard_service_plan_ledger_dispatch_receipt_and_replay_share_real_permit(self):
        from pool.service import Service
        from pool.httpd import Server
        from verify_v030_credential_recovery import MemoryLedger
        from 协作账本 import effects_between
        from 协作存储 import encoded
        class IntegratedLedger(MemoryLedger):
            def evidence_context(self, env, state):
                return {}
            def process(self, *args, handler=None, **kwargs):
                for record in self.data["copies"]:
                    env = record["envelope"]
                    key = env["origin_id"] + "/" + env["event_id"]
                    if key in self.data["terminal"]:
                        continue
                    before = deepcopy(self.data["state"])
                    updated, _ = handler(self.data["state"], env, {"now": time.time(), "seq": len(self.data["terminal"])+1})
                    self.data["state"] = updated
                    row = {"origin_id": env["origin_id"], "origin_seq": env["origin_seq"], "key": key,
                        "type": "decision", "command": env["command"], "result": "applied", "reason": "",
                        "content_sha256": record["sha256"], "ledger_seq": len(self.data["terminal"])+1,
                        "sha256": digest(encoded(updated)), "effects": effects_between(before, updated)}
                    self.data["terminal"][key] = row
                    self.data["entries"].append(row)
                return self.read()
        fixture_case = ExecutionTests()
        fixture_case.setUp()
        state = fixture_case.state
        state["pilot"]["format"].update(schema=5, min_reader=5)
        root = Path(__file__).resolve().parent / ".state"
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="r2-service-execution-", dir=root) as directory:
            IntegratedLedger.stores[directory] = {"state": state, "terminal": {}, "entries": [], "copies": []}
            with patch("pool.service.LedgerBackend", IntegratedLedger):
                service = Service(Path(directory))
            try:
                server = object.__new__(Server)
                server.service, server.tokens = service, {}
                token = "synthetic-execution-token-" + "x"*24
                with service.db:
                    service.accounts.issue_executor(ASSISTANT, token, int(time.time())+3600, 7)
                def post(op, rid, **body):
                    payload = {"request_id": rid, **body}
                    status, result = service.submit(ASSISTANT, op, rid, payload, authorize=lambda: server.actor_for_token(token))
                    self.assertEqual(status, 200, result)
                    return result, payload
                config = deepcopy(engine.default_context(state, ASSISTANT)["config"])
                created, _ = post("context-save", "integrated-context", context_id=None, version=0, config=config, make_default=True)
                ctx = created["context"]
                opened, _ = post("segment-open", "integrated-segment", task_id="T01", claim_id="ca", scope_version=1, epoch=1,
                                  context_id=ctx["context_id"], context_version=ctx["version"])
                prepared, _ = post("action-prepare", "integrated-action", segment_id=opened["segment"]["id"], version=1,
                                   description="isolated service path", resources=[{"id":"path:work/a","mode":"write","domain":"unverified"}], adapter_id="manual")
                aid = prepared["action"]["id"]
                granted, _ = post("resource-request", "integrated-resources", action_id=aid, version=1, resources=prepared["action"]["resources"])
                grant, action = granted["grant"], granted["action"]
                started, payload = post("action-start", "integrated-start", action_id=aid, version=action["version"],
                                        grant_id=grant["id"], generation=grant["generation"])
                snapshot = service.snapshot()
                actual = snapshot["state"]["security"]["execution"]["actions"][aid]
                self.assertEqual(started["action"]["permit_id"], actual["permit_id"])
                self.assertNotIn("validation-", str(started))
                status, replay = service.submit(ASSISTANT, "action-start", "integrated-start", payload,
                                                authorize=lambda: server.actor_for_token(token))
                self.assertEqual((status, replay), (200, started))
                self.assertEqual(len(service.read(ASSISTANT, "execution", {"action_id": aid})["actions"]), 1)
                self.assertEqual(service.read(ASSISTANT, "features")["security_schema"], 5)
                self.assertTrue(all(row[0] == 200 for row in service.db.execute("SELECT status FROM requests")))
            finally:
                service.close()

if __name__ == "__main__":
    unittest.main()
