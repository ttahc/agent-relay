"""Real-directory proofs and replayable registry/lock policy; no production store required."""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pool import environments, execution
from pool.packages import ClientError
from pool.service import PUBLIC_ACTIONS
import 协作执行 as engine
import 协作升级 as rules
from 协作存储 import Rejected
import verify_r2_execution as r2
from verify_delegation import ASSISTANT, OTHER, PERSON


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.fixture = r2.ExecutionTests()
        self.fixture.setUp()
        self.state = self.fixture.state
        rules.identity(self.state, PERSON)["admin"] = True
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.service = SimpleNamespace()
        self.counter = 0

    @property
    def data(self):
        return self.state["security"]["execution"]

    def call(self, op, actor=ASSISTANT, **body):
        self.counter += 1
        key = __import__("hashlib").sha256(str(self.counter).encode()).hexdigest()
        plan = execution.plan(self.service, actor, op, key, {"request_id": key, **body}, self.state)
        p = json.loads(json.dumps(plan["steps"][0]["payload"]))  # Match journal/envelope persistence.
        p["_audit"] = {"actor": actor, "credential_version": rules.identity(self.state, actor)["credential"]}
        engine.action(self.state, {"payload": p, "event_id": "event-" + str(self.counter)}, {"now": time.time(), "phase": "running"})
        return plan["round_result"], p

    def register(self, eid, actors, kind="local", **changes):
        return self.call("environment-save", PERSON, environment_id=eid, version=self.data["environments"].get(eid, {}).get("version", 0),
                         **{"label": "Same platform label", "kind": kind, "executors": actors, "active": True, **changes})

    def mapping(self, eid, root, domain="files", **changes):
        mid = environments.mapping_id(eid, domain)
        root.mkdir(parents=True, exist_ok=True)
        return self.call("resource-map-save", PERSON, environment_id=eid, domain=domain,
                         version=self.data["resource_mappings"].get(mid, {}).get("version", 0), root=str(root), **{"active": True, **changes})

    def bind(self, actor, eid, platform="codex"):
        previous = self.data["defaults"][actor]
        config = deepcopy(self.data["contexts"][previous["context_id"] + ":" + str(previous["version"])] ["config"])
        config["platform"] = platform
        self.call("context-save", actor, context_id=previous["context_id"], version=previous["version"], config=config,
                  make_default=True, environment_id=eid)

    def action(self, actor=ASSISTANT, path="path:work/item", domain="files", mode="write"):
        selected = self.data["defaults"][actor]
        segment, _ = self.call("segment-open", actor, task_id="T01", claim_id="ca" if actor == ASSISTANT else "cb", scope_version=1,
                               epoch=1, context_id=selected["context_id"], context_version=selected["version"])
        result, _ = self.call("action-prepare", actor, segment_id=segment["segment"]["id"], version=1, description="test work",
                              resources=[{"id": path, "domain": domain, "mode": mode}], adapter_id="manual")
        return result["action"]["id"]

    def request(self, aid):
        row = self.data["actions"][aid]
        result, _ = self.call("resource-request", row["executor_id"], action_id=aid, version=row["version"], resources=row["resources"])
        return result["resource_request"]

    def start(self, aid):
        row = self.data["actions"][aid]
        return self.call("action-start", row["executor_id"], action_id=aid, version=row["version"], grant_id=row["grant_id"], generation=row["generation"])

    def pair(self, shared=False, kinds=("local", "cloud")):
        for actor, eid, kind in ((ASSISTANT, "local-instance", kinds[0]), (OTHER, "cloud-instance", kinds[1])):
            self.register(eid, [actor], kind=kind)
            self.mapping(eid, self.root / ("shared" if shared else eid))
            self.bind(actor, eid)

    def test_independent_directories_same_owner_and_platform_run_concurrently(self):
        self.pair()
        self.assertEqual(rules.responsible(self.state, ASSISTANT), rules.responsible(self.state, OTHER))
        a, b = self.action(), self.action(OTHER)
        self.assertEqual(self.request(a)["state"], "granted")
        self.assertEqual(self.request(b)["state"], "granted")
        self.start(a); self.start(b)
        self.assertEqual(len([x for x in self.data["actions"].values() if x["state"] == "start-authorized"]), 2)

    def test_different_platforms_sharing_directory_are_mutually_exclusive(self):
        self.pair(shared=True)
        self.bind(OTHER, "cloud-instance", platform="claude")
        a, b = self.action(), self.action(OTHER)
        self.request(a); self.start(a)
        self.assertEqual(self.request(b)["state"], "queued")

    def test_same_instance_can_be_used_by_two_platforms(self):
        self.register("shared-instance", [ASSISTANT, OTHER])
        self.mapping("shared-instance", self.root / "shared")
        self.bind(ASSISTANT, "shared-instance"); self.bind(OTHER, "shared-instance", platform="claude")
        self.request(self.action())
        self.assertEqual(self.request(self.action(OTHER))["state"], "queued")

    def test_labels_and_unmapped_domain_never_prove_isolation(self):
        self.pair()
        a, b = self.action(domain="invented-a"), self.action(OTHER, domain="invented-b")
        self.request(a)
        self.assertEqual(self.request(b)["state"], "queued")

    def test_existing_unverified_occupancy_still_blocks_new_verified_mapping(self):
        a = self.action(domain="legacy-name")
        self.request(a); self.start(a)
        old = deepcopy(self.data["grants"])
        self.pair()
        self.assertEqual(self.request(self.action(OTHER))["state"], "queued")
        self.assertEqual(self.data["grants"], old)

    def test_legacy_physical_blocker_is_never_reinterpreted(self):
        self.state["security"]["physical_blockers"]["old"] = {"active": True, "resources": [{"id": "path:elsewhere", "mode": "write"}]}
        before = deepcopy(self.state["security"]["physical_blockers"])
        self.pair()
        self.assertEqual(self.request(self.action())["state"], "queued")
        self.assertEqual(self.state["security"]["physical_blockers"], before)

    def test_symlink_root_alias_shares_physical_lock(self):
        real = self.root / "real"; real.mkdir()
        alias = self.root / "alias"; alias.symlink_to(real, target_is_directory=True)
        for actor, eid, root in ((ASSISTANT, "one", real), (OTHER, "two", alias)):
            self.register(eid, [actor]); self.mapping(eid, root); self.bind(actor, eid)
        self.request(self.action())
        self.assertEqual(self.request(self.action(OTHER))["state"], "queued")

    def test_hardlink_files_across_mappings_conflict(self):
        self.pair()
        first = self.root / "local-instance/work"; first.mkdir()
        second = self.root / "cloud-instance/work"; second.mkdir()
        (first / "item").write_text("fixture")
        os.link(first / "item", second / "item")
        self.request(self.action())
        self.assertEqual(self.request(self.action(OTHER))["state"], "queued")

    def test_directory_ancestor_proof_catches_alias_descendant(self):
        left = {"id": "path:work", "mode": "write", "domain": "a", "resolved": True, "identity": "1:2", "canonical_path": "/mount/a"}
        right = {"id": "path:work/item", "mode": "write", "domain": "b", "resolved": True, "identity": "1:3",
                 "canonical_path": "/other/item", "ancestor_identities": ["1:2"]}
        self.assertTrue(engine.conflict(self.state, left, right))
        self.assertTrue(engine.conflict(self.state, right, left))

    def test_hardlinked_descendant_cannot_bypass_directory_lock(self):
        for other_path in ("path:work/item", "path:work"):
            with self.subTest(other_path=other_path):
                self.setUp()
                self.pair()
                first = self.root / "local-instance/work"; first.mkdir()
                second = self.root / "cloud-instance/work"; second.mkdir()
                (first / "item").write_text("fixture")
                os.link(first / "item", second / "item")
                a = self.action(path="path:work")
                self.request(a); self.start(a)
                b = self.action(OTHER, path=other_path)
                self.assertEqual(self.request(b)["state"], "queued")
                self.assertNotIn("grant_id", self.data["actions"][b])

    def test_nonexistent_ancestor_suffixes_under_mount_alias_conflict(self):
        left = {"id": "path:work", "mode": "write", "domain": "a", "resolved": True, "identity": "1:2/work",
                "canonical_path": "/mount-a/work", "physical_paths": [["1:2", "work"]]}
        right = {"id": "path:work/item", "mode": "write", "domain": "b", "resolved": True, "identity": "1:2/work/item",
                 "canonical_path": "/mount-b/work/item", "physical_paths": [["1:2", "work/item"]]}
        self.assertTrue(engine.conflict(self.state, left, right))
        self.assertTrue(engine.conflict(self.state, right, left))
        right["physical_paths"] = [["1:2", "other/item"]]
        self.assertFalse(engine.conflict(self.state, left, right))

    def test_directory_scan_budget_falls_back_to_conservative_conflict(self):
        self.pair()
        path = self.root / "local-instance/work"; path.mkdir()
        (path / "one").write_text("fixture")
        with patch.object(execution, "MAX_PROOF_ENTRIES", 0):
            a = self.action(path="path:work")
            self.assertFalse(next(iter(self.data["actions"][a]["resource_proofs"].values())).get("resolved"))
            self.request(a)
            self.assertEqual(self.request(self.action(OTHER))["state"], "queued")

    def test_alias_added_before_start_invalidates_directory_snapshot(self):
        self.pair()
        first = self.root / "local-instance/work"; first.mkdir()
        second = self.root / "cloud-instance/work"; second.mkdir()
        (second / "item").write_text("fixture")
        a = self.action(path="path:work"); self.request(a)
        os.link(second / "item", first / "alias")
        with self.assertRaises(ClientError):
            self.start(a)

    def test_symlink_inside_mapping_is_rejected_instead_of_bypassed(self):
        self.pair()
        path = self.root / "local-instance/work"; path.mkdir()
        (path / "item").symlink_to(self.root / "cloud-instance")
        with self.assertRaisesRegex(ClientError, "链接"):
            self.action()

    def test_executor_cannot_register_or_forge_mapping_proofs(self):
        before = deepcopy(self.state)
        with self.assertRaises(Rejected):
            self.call("environment-save", ASSISTANT, environment_id="fake", version=0, label="fake", kind="local", executors=[ASSISTANT], active=True)
        self.assertEqual(self.state, before)
        with self.assertRaises(ClientError):
            self.call("resource-map-save", PERSON, environment_id="fake", domain="files", version=0, root=str(self.root), active=True,
                      root_observation={"root": "/fake", "root_identity": "fake"})

    def test_foreign_or_forged_environment_cannot_bind(self):
        self.register("mine", [ASSISTANT])
        for actor, eid in ((OTHER, "mine"), (ASSISTANT, "forged")):
            with self.subTest(actor=actor, eid=eid), self.assertRaises(Rejected):
                self.bind(actor, eid)

    def test_remapping_does_not_release_old_occupancy_and_blocks_old_start(self):
        self.pair(shared=True)
        a, b = self.action(), self.action(OTHER)
        self.request(a); self.request(b)
        grants = deepcopy(self.data["grants"])
        old_context = deepcopy(self.data["contexts"])
        self.mapping("local-instance", self.root / "different")
        self.assertEqual(self.data["grants"], grants)
        self.assertEqual(self.data["contexts"], old_context)
        self.assertEqual(self.request(self.action(OTHER))["state"], "queued")
        with self.assertRaises((Rejected, ClientError)):
            self.start(a)
        self.assertEqual(len(self.data["resource_mapping_history"]), 3)

    def test_mapping_revocation_blocks_waiters_but_preserves_unknown_grants(self):
        self.pair(shared=True)
        a, b = self.action(), self.action(OTHER)
        self.request(a); self.start(a)
        request = self.request(b)
        grants = deepcopy(self.data["grants"])
        self.mapping("cloud-instance", self.root / "shared", active=False)
        self.assertEqual(self.data["resource_requests"][request["id"]]["state"], "blocked")
        self.assertEqual(self.data["grants"], grants)

    def test_environment_revocation_does_not_prevent_stop_facts(self):
        self.pair()
        a = self.action(); self.request(a); self.start(a)
        self.register("local-instance", [ASSISTANT], active=False)
        row = self.data["actions"][a]
        self.call("execution-fact", action_id=a, task_id="T01", claim_id="ca", scope_version=1, epoch=1, kind="stopped",
                  evidence={"note": "actual exit", "sha256": "a"*64}, permit_id=row["permit_id"], reporter_basis={"kind": "owner", "note": "original executor"})
        self.assertEqual(self.data["grants"][row["grant_id"]]["physical"], "unknown")
        with self.assertRaises(Rejected):
            self.action()

    def test_root_replacement_blocks_start_without_releasing_grant(self):
        self.pair()
        a = self.action(); self.request(a)
        prior = deepcopy(self.data["grants"])
        root = self.root / "local-instance"
        root.rename(self.root / "moved")
        with self.assertRaises(ClientError):
            self.start(a)
        root.mkdir()
        with self.assertRaises(ClientError):
            self.start(a)
        self.assertEqual(self.data["grants"], prior)

    def test_disabling_unavailable_mapping_does_not_probe_old_root(self):
        self.pair()
        (self.root / "local-instance").rmdir()
        self.call("resource-map-save", PERSON, environment_id="local-instance", domain="files", version=1, root="", active=False)
        self.assertFalse(self.data["resource_mappings"][environments.mapping_id("local-instance", "files")]["active"])

    def test_stale_mapping_update_is_atomic_and_rejected(self):
        self.pair()
        before = deepcopy(self.state)
        with self.assertRaises(Rejected):
            self.call("resource-map-save", PERSON, environment_id="local-instance", domain="files", version=0,
                      root=str(self.root / "cloud-instance"), active=True)
        self.assertEqual(self.state, before)

    def test_resource_permissions_remain_independent_of_mapping(self):
        self.pair()
        self.state["pilot"][f"grant:project-one:{ASSISTANT}"]["resources"] = []
        with self.assertRaisesRegex(Rejected, "资源权限"):
            self.action()

    def test_mapping_replay_does_not_touch_filesystem(self):
        self.register("one", [ASSISTANT])
        before = deepcopy(self.state)
        _, p = self.mapping("one", self.root / "mapped")
        with patch.object(Path, "resolve", side_effect=AssertionError("replay must not probe")):
            engine.action(before, {"payload": p, "event_id": "replay"}, {"now": time.time(), "phase": "running"})
        self.assertEqual(before["security"]["execution"]["resource_mappings"].keys(), self.data["resource_mappings"].keys())

    def test_environment_and_mapping_views_hide_paths_and_foreign_owners(self):
        self.register("shared", [ASSISTANT, "foreign-window"])
        self.mapping("shared", self.root / "private-device-path")
        view = execution.read(self.state, ASSISTANT)
        self.assertNotIn(str(self.root), json.dumps(view))
        self.assertEqual(view["environments"][0]["executors"], [ASSISTANT])
        self.assertEqual(execution.read(self.state, OTHER)["environments"], [])
        self.assertEqual(execution.read(self.state, OTHER, {"executor_id": ASSISTANT})["environments"], [])

    def storage(self, sid, actor=PERSON, **changes):
        return self.call("storage-domain-register", actor, storage_domain_id=sid, label="confirmed storage " + sid,
                         **{"independent": True, "evidence": {"note": "Administrator verified physical separation from registered domains", "sha256": "d"*64}, **changes})

    def remote_map(self, eid, sid, domain="files", **changes):
        mid = environments.mapping_id(eid, domain)
        return self.call("resource-map-save", PERSON, environment_id=eid, domain=domain,
                         version=self.data["resource_mappings"].get(mid, {}).get("version", 0), root="",
                         **{"active": True, "mapping_kind": "attested-domain", "storage_domain_id": sid,
                            "evidence": {"note": "Verified node mount belongs to this global storage domain", "sha256": "e"*64}, **changes})

    def remote_pair(self, shared=False):
        self.storage("storage-a")
        if not shared:
            self.storage("storage-b")
        for actor, eid, sid in ((ASSISTANT, "node-a", "storage-a"), (OTHER, "node-b", "storage-a" if shared else "storage-b")):
            self.register(eid, [actor], kind="remote")
            self.remote_map(eid, sid)
            self.bind(actor, eid)

    def merge(self, left, right):
        return self.call("storage-domain-merge", PERSON, storage_domain_id=left, other_domain_id=right,
                         version=len(self.data["storage_domain_merges"]), evidence={"note": "Verified domains are shared physical storage", "sha256": "f"*64})

    def test_remote_independent_nodes_parallel_without_service_filesystem_access(self):
        with patch.object(Path, "resolve", side_effect=AssertionError("remote mapping must not probe relay filesystem")):
            self.remote_pair()
            a, b = self.action(), self.action(OTHER)
            self.assertEqual(self.request(a)["state"], "granted")
            self.assertEqual(self.request(b)["state"], "granted")
            self.start(a); self.start(b)
        proof = next(iter(self.data["actions"][a]["resource_proofs"].values()))
        self.assertEqual(proof["proof_source"], "administrator-attested")
        self.assertNotIn("identity", proof)
        self.assertNotIn("resolved", proof)

    def test_remote_shared_domain_serializes_even_differently_spelled_aliases(self):
        self.remote_pair(shared=True)
        a = self.action(path="path:work/alias-one")
        b = self.action(OTHER, path="path:work/alias-two")
        self.request(a); self.start(a)
        self.assertEqual(self.request(b)["state"], "queued")

    def test_remote_shared_domain_allows_concurrent_reads(self):
        self.remote_pair(shared=True)
        a, b = self.action(mode="read"), self.action(OTHER, mode="read")
        self.assertEqual(self.request(a)["state"], "granted")
        self.assertEqual(self.request(b)["state"], "granted")

    def test_remote_domains_never_bypass_legacy_unscoped_occupancy(self):
        a = self.action(domain="legacy-unverified"); self.request(a); self.start(a)
        old = deepcopy(self.data["grants"])
        self.remote_pair()
        self.assertEqual(self.request(self.action(OTHER))["state"], "queued")
        self.assertEqual(self.data["grants"], old)

    def test_storage_domains_need_explicit_administrator_attestation(self):
        for actor, values in ((ASSISTANT, {}), (PERSON, {"independent": False}), (PERSON, {"evidence": {"note": "unverified", "sha256": ""}})):
            with self.subTest(actor=actor, values=values), self.assertRaises(Rejected):
                self.storage("fake", actor, **values)
        self.assertEqual(self.data["storage_domains"], {})

    def test_remote_mapping_requires_registered_domain_and_binding_evidence(self):
        self.register("remote", [ASSISTANT], kind="cloud")
        with self.assertRaises(Rejected):
            self.remote_map("remote", "unregistered")
        self.storage("known")
        with self.assertRaises(Rejected):
            self.remote_map("remote", "known", evidence={"note": "", "sha256": "e"*64})

    def test_raw_resource_global_domain_cannot_be_forged(self):
        with self.assertRaises(Rejected):
            engine.normalize_resources(self.state, [{"id": "path:work", "mode": "write", "domain": "fake", "storage_domain_id": "fake"}])

    def test_existing_remote_mapping_cannot_silently_split_or_drop_domain(self):
        self.remote_pair()
        a = self.action(); self.request(a); self.start(a)
        before = deepcopy(self.state)
        for sid in ("storage-b", ""):
            with self.subTest(sid=sid), self.assertRaises(Rejected):
                self.remote_map("node-a", sid)
            self.assertEqual(self.state, before)
        with self.assertRaises(Rejected):
            self.storage("storage-a")

    def test_domain_merge_rechecks_preexisting_grants_and_preserves_snapshots(self):
        self.remote_pair()
        a, b = self.action(), self.action(OTHER)
        self.request(a); self.request(b)
        grants = deepcopy(self.data["grants"])
        result, _ = self.merge("storage-a", "storage-b")
        self.assertEqual(set(result["affected_grants"]), set(grants))
        self.assertEqual(self.data["grants"], grants)
        for aid in (a, b):
            with self.assertRaisesRegex(Rejected, "等价关系"):
                self.start(aid)
        self.assertEqual(self.request(self.action(OTHER))["state"], "queued")

    def test_domain_merge_is_transitive_and_has_no_split_operation(self):
        self.remote_pair()
        self.storage("storage-c")
        self.merge("storage-b", "storage-c")
        self.merge("storage-a", "storage-b")
        self.assertEqual({environments.canonical_domain(self.state, sid) for sid in ("storage-a", "storage-b", "storage-c")}, {"storage-a"})
        with self.assertRaises(Rejected):
            self.merge("storage-c", "storage-a")
        self.assertNotIn("storage-domain-split", PUBLIC_ACTIONS)
        # Rebinding to a different spelling in the same equivalence class is safe.
        self.remote_map("node-a", "storage-c")

    def test_known_local_alias_cannot_be_exported_as_independent_remote_domain(self):
        self.pair(shared=True)
        self.storage("storage-a"); self.storage("storage-b")
        self.mapping("local-instance", self.root / "shared", storage_domain_id="storage-a")
        with self.assertRaisesRegex(Rejected, "重叠"):
            self.mapping("cloud-instance", self.root / "shared", storage_domain_id="storage-b")
        self.merge("storage-a", "storage-b")
        self.mapping("cloud-instance", self.root / "shared", storage_domain_id="storage-b")
        self.register("remote-alias", [OTHER], kind="remote")
        self.remote_map("remote-alias", "storage-b"); self.bind(OTHER, "remote-alias")
        a = self.action(); self.request(a); self.start(a)
        self.assertEqual(self.request(self.action(OTHER))["state"], "queued")

    def test_local_alias_proof_overrides_distinct_domain_labels_in_old_records(self):
        self.storage("storage-a"); self.storage("storage-b")
        left = {"id": "path:work", "mode": "write", "domain": "a", "identity": "same-local-file", "storage_domain_id": "storage-a"}
        right = {"id": "path:work", "mode": "write", "domain": "b", "identity": "same-local-file", "storage_domain_id": "storage-b"}
        self.assertTrue(engine.conflict(self.state, left, right))

    def test_hardlinked_subtrees_cannot_be_registered_as_independent_global_domains(self):
        self.pair()
        first = self.root / "local-instance/item"; first.write_text("fixture")
        os.link(first, self.root / "cloud-instance/item")
        self.storage("storage-a"); self.storage("storage-b")
        self.mapping("local-instance", self.root / "local-instance", storage_domain_id="storage-a")
        with self.assertRaisesRegex(Rejected, "重叠"):
            self.mapping("cloud-instance", self.root / "cloud-instance", storage_domain_id="storage-b")

    def test_inactive_mapping_with_unfinished_grant_still_protects_global_root_identity(self):
        self.pair(shared=True)
        self.storage("storage-a"); self.storage("storage-b")
        self.mapping("local-instance", self.root / "shared", storage_domain_id="storage-a")
        a = self.action(); self.request(a); self.start(a)
        self.mapping("local-instance", self.root / "shared", active=False, storage_domain_id="storage-a")
        with self.assertRaisesRegex(Rejected, "重叠"):
            self.mapping("cloud-instance", self.root / "shared", storage_domain_id="storage-b")

    def test_new_hardlink_in_known_local_view_is_carried_by_remote_domain_proof(self):
        self.pair()
        self.storage("storage-a"); self.storage("storage-b")
        for eid, sid in (("local-instance", "storage-a"), ("cloud-instance", "storage-b")):
            self.mapping(eid, self.root / eid, storage_domain_id=sid)
        first = self.root / "local-instance/work"; first.mkdir(); (first / "item").write_text("fixture")
        a = self.action(); self.request(a); self.start(a)
        second = self.root / "cloud-instance/work"; second.mkdir()
        os.link(first / "item", second / "alias")
        self.register("remote-alias", [OTHER], kind="remote")
        self.remote_map("remote-alias", "storage-b"); self.bind(OTHER, "remote-alias")
        b = self.action(OTHER, path="path:work/unrelated-spelling")
        proof = next(iter(self.data["actions"][b]["resource_proofs"].values()))
        self.assertTrue(proof["domain_identities"])
        self.assertEqual(self.request(b)["state"], "queued")
        self.assertNotIn("domain_identities", json.dumps(execution.read(self.state, OTHER)))

    def test_local_view_added_after_remote_prepare_cannot_be_stripped_as_legacy(self):
        self.remote_pair()
        b = self.action(OTHER); self.request(b)
        self.register("new-local-view", [OTHER])
        self.mapping("new-local-view", self.root / "new-local-view", storage_domain_id="storage-b")
        with self.assertRaises(ClientError):
            self.start(b)

    def test_remote_start_rechecks_known_local_view_topology(self):
        self.remote_pair()
        # Attach a server-visible view to B without probing any remote filesystem.
        self.register("local-b", [OTHER])
        self.mapping("local-b", self.root / "local-b", storage_domain_id="storage-b")
        b = self.action(OTHER); self.request(b)
        (self.root / "local-b/new-file").write_text("changed after permit preparation")
        with self.assertRaises(ClientError):
            self.start(b)

    def test_local_and_remote_can_share_or_separate_attested_domain(self):
        for shared in (True, False):
            with self.subTest(shared=shared):
                self.setUp()
                self.storage("storage-a"); self.storage("storage-b")
                self.register("local", [ASSISTANT]); self.mapping("local", self.root / "local", storage_domain_id="storage-a")
                self.bind(ASSISTANT, "local")
                self.register("remote", [OTHER], kind="cloud")
                self.remote_map("remote", "storage-a" if shared else "storage-b"); self.bind(OTHER, "remote")
                self.request(self.action())
                self.assertEqual(self.request(self.action(OTHER))["state"], "queued" if shared else "granted")

    def test_incomplete_local_subtree_proof_cannot_claim_domain_isolation(self):
        self.storage("storage-a"); self.storage("storage-b")
        self.register("local", [ASSISTANT]); self.mapping("local", self.root / "local", storage_domain_id="storage-a")
        self.bind(ASSISTANT, "local")
        path = self.root / "local/work"; path.mkdir(); (path / "one").write_text("fixture")
        self.register("remote", [OTHER], kind="remote"); self.remote_map("remote", "storage-b"); self.bind(OTHER, "remote")
        with patch.object(execution, "MAX_PROOF_ENTRIES", 0):
            self.request(self.action(path="path:work"))
            self.assertEqual(self.request(self.action(OTHER))["state"], "queued")

    def test_environment_can_be_disabled_after_its_window_is_disabled(self):
        self.register("one", [ASSISTANT])
        rules.identity(self.state, ASSISTANT)["status"] = "disabled"
        self.register("one", [ASSISTANT], active=False)
        self.assertFalse(self.data["environments"]["one"]["active"])

    def test_remote_mapping_revocation_retains_prior_attestation(self):
        self.remote_pair()
        self.call("resource-map-save", PERSON, environment_id="node-a", domain="files", version=1, root="", active=False)
        row = self.data["resource_mappings"][environments.mapping_id("node-a", "files")]
        self.assertFalse(row["active"])
        self.assertEqual(row["storage_domain_id"], "storage-a")
        self.assertEqual(row["mapping_kind"], "attested-domain")

    def test_older_context_editor_preserves_binding_unless_explicitly_cleared(self):
        self.remote_pair()
        selected = self.data["defaults"][ASSISTANT]
        previous = deepcopy(self.data["contexts"][selected["context_id"] + ":" + str(selected["version"])])
        result, _ = self.call("context-save", context_id=previous["context_id"], version=previous["version"],
                              config=previous["config"], make_default=True)
        self.assertEqual(result["context"]["environment_id"], "node-a")
        result, _ = self.call("context-save", context_id=previous["context_id"], version=previous["version"]+1,
                              config=previous["config"], make_default=True, environment_id="")
        self.assertNotIn("environment_id", result["context"])
        self.assertEqual(self.data["contexts"][previous["context_id"] + ":" + str(previous["version"])], previous)

    def test_full_ledger_json_roundtrip_preserves_global_domain_start(self):
        self.remote_pair()
        for eid, sid, actor in (("local-view-a", "storage-a", ASSISTANT), ("local-view-b", "storage-b", OTHER)):
            self.register(eid, [actor])
            self.mapping(eid, self.root / eid, storage_domain_id=sid)
        a, b = self.action(), self.action(OTHER)
        self.request(a); self.request(b)
        self.state = json.loads(json.dumps(self.state))  # Snapshot replay, not only the request payload.
        self.start(a); self.start(b)
        self.assertEqual(self.data["actions"][a]["state"], "start-authorized")
        self.assertEqual(self.data["actions"][b]["state"], "start-authorized")

    def test_registry_persists_reader_floor_without_changing_execution_schema(self):
        from 协作安全 import check
        before = deepcopy(self.state)
        self.counter += 1
        body = {"request_id": "register-plan", "environment_id": "one", "version": 0, "label": "one", "kind": "local",
                "executors": [ASSISTANT], "active": True}
        execution.plan(self.service, PERSON, "environment-save", "a" * 64, body, self.state)
        self.assertEqual(self.state, before)  # Validation does not mutate the live format.
        self.register("one", [ASSISTANT])
        self.assertEqual(self.state["pilot"]["format"]["min_reader"], 6)
        self.assertEqual(check(self.state), 5)
        with self.assertRaises(ValueError):
            check(self.state, reader=5)

    def test_api_and_cli_are_exposed_without_new_credentials(self):
        import taskpool
        self.assertTrue(environments.OPS <= PUBLIC_ACTIONS)
        args = taskpool.build_parser().parse_args(["environment-save", "--request-id", "stable", "--config", "environment.json"])
        self.assertEqual(args.action, "environment-save")
        spec = importlib.util.spec_from_file_location("client_environment_test", Path(__file__).parent / "ops/round-client.py")
        client = importlib.util.module_from_spec(spec); spec.loader.exec_module(client)
        args = client.build_parser().parse_args(["--state", "synthetic.json", "context", "save", "--environment-id", "local-instance"])
        self.assertEqual(args.environment_id, "local-instance")


if __name__ == "__main__":
    unittest.main()
