"""Delegation decisions, replay constraints and human-only consent UI regression."""
from copy import deepcopy
from email.message import Message
import time
from threading import RLock
from types import SimpleNamespace
import unittest
from urllib.parse import urlencode, urlsplit

from pool import delegation, delegation_pages
from pool.packages import ClientError
import 协作本轮 as round_rules
import 协作升级 as rules
from 协作存储 import Rejected


PERSON, ASSISTANT, OTHER = "person", "window-one", "window-two"


def fixture():
    state = {"generation": 1, "tasks": {}, "claims": {}, "origins": {}, "round": {},
             "pilot": {"format": {"schema": 3, "maintenance": False}}}
    for actor, kind, owner in ((PERSON, "human", PERSON), ("other-person", "human", "other-person"),
                               (ASSISTANT, "executor", PERSON), (OTHER, "executor", PERSON),
                               ("foreign-window", "executor", "other-person")):
        state["pilot"]["identity:" + actor] = {"kind": kind, "owner": owner, "status": "active", "credential": 7,
            "window": "CDX-0001" if actor == ASSISTANT else "CLD-0002", "number": len(state["origins"]),
            "window_name": '<test "window">' if actor == ASSISTANT else actor}
        state["origins"][actor] = {"roles": []}
    for project in ("project-one", "project-two"):
        state["pilot"]["project:" + project] = {"id": project, "name": project, "owner": PERSON, "version": 1}
        state["pilot"][f"grant:{project}:{PERSON}"] = {"roles": ["manager", "executor", "receiver"], "resources": [], "version": 1}
        state["pilot"][f"grant:{project}:other-person"] = {"roles": ["manager", "executor"], "resources": [], "version": 1}
    for tid, project in (("T01", "project-one"), ("T02", "project-one"), ("T03", "project-two")):
        state["tasks"][tid] = {"task_id": tid, "contract": {"project_id": project}, "completes_on": ["ready"], "claims": []}
    return state


def grant_payload(state, actions=None, task_ids=None, version=0, **changes):
    payload = {"op": "delegate-grant", "executor_id": ASSISTANT, "project_id": "project-one",
               "actions": list(actions or ["read", "claim", "deliver-files", "stop", "task-publish"]),
               "task_ids": task_ids or [], "expires": int(time.time()) + 3600, "version": version,
               "delegation_id": delegation.delegation_id(PERSON, ASSISTANT, "project-one"), "reason": "fixture human consent"}
    payload.update(changes)
    return payload


def decide(state, payload, actor=PERSON):
    env = {"command": "pilot", "event_id": "fixture-event", "payload": {**payload, "_audit": {"actor": actor}}}
    round_rules.action(state, env, {"now": time.time()})


def audited_publish(state, task="T01"):
    with delegation.operation_context(state, ASSISTANT, "task-publish", "project-one", task) as metadata:
        audit = {"actor": ASSISTANT, "operation": "task-publish", "project_id": "project-one", "task_id": task, **metadata}
    return {"command": "pilot", "payload": {"op": "publish", "task_id": task, "_audit": audit}}


class DelegationTest(unittest.TestCase):
    def setUp(self):
        self.state = fixture()

    def grant(self, *args, **kwargs):
        payload = grant_payload(self.state, *args, **kwargs)
        decide(self.state, payload)
        return self.state["round"]["delegation:" + payload["delegation_id"]]

    def test_real_ledger_creates_versioned_human_bound_record_without_changing_identities(self):
        identities = deepcopy(self.state["pilot"])
        origins = deepcopy(self.state["origins"])
        record = self.grant()
        self.assertEqual(record["version"], 1)
        self.assertEqual(record["delegator"], PERSON)
        self.assertEqual(record["executor_id"], ASSISTANT)
        self.assertEqual(self.state["pilot"], identities)
        self.assertEqual(self.state["origins"], origins)

    def test_ai_cannot_grant_to_itself(self):
        with self.assertRaises(Rejected):
            decide(self.state, grant_payload(self.state), ASSISTANT)
        self.assertFalse(self.state["round"])

    def test_person_cannot_grant_to_another_person_window(self):
        with self.assertRaises(Rejected):
            self.grant(executor_id="foreign-window")

    def test_new_window_does_not_inherit_a_sibling_grant(self):
        self.grant()
        with delegation.operation_context(self.state, OTHER, "task-publish", "project-one", "T01"):
            self.assertEqual(delegation.effective_roles(self.state, "project-one", OTHER, set()), set())

    def test_rejects_cross_project_task_and_unknown_sensitive_actions(self):
        for changes in ({"task_ids": ["T03"]}, {"actions": ["project-grant"]}, {"actions": ["review"]},
                        {"actions": ["credential-change"]}, {"actions": ["delegate-grant"]}):
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                self.grant(**changes)

    def test_rejects_expired_and_unbounded_grants(self):
        for expires in (int(time.time()) - 1, int(time.time()) + 31 * 86400, True):
            with self.subTest(expires=expires), self.assertRaises(Rejected):
                self.grant(expires=expires)

    def test_grant_cannot_exceed_person_current_permissions(self):
        self.state["pilot"][f"grant:project-one:{PERSON}"]["roles"] = ["executor"]
        with self.assertRaises(Rejected):
            self.grant(actions=["task-publish"])

    def test_scoped_manager_exists_only_for_matching_operation_and_task(self):
        self.grant(task_ids=["T01"])
        self.assertEqual(delegation.effective_roles(self.state, "project-one", ASSISTANT, set()), set())
        with delegation.operation_context(self.state, ASSISTANT, "task-publish", "project-one", "T01") as audit:
            self.assertEqual(audit["delegator"], PERSON)
            self.assertIn("manager", delegation.effective_roles(self.state, "project-one", ASSISTANT, set()))
            self.assertEqual(delegation.effective_roles(self.state, "project-two", ASSISTANT, set()), set())
        for task in (None, "T02", "T03"):
            with self.subTest(task=task), delegation.operation_context(self.state, ASSISTANT, "task-publish", "project-one", task):
                self.assertEqual(delegation.effective_roles(self.state, "project-one", ASSISTANT, set()), set())
        with delegation.operation_context(self.state, ASSISTANT, "read", "project-one", "T01"):
            self.assertEqual(delegation.effective_roles(self.state, "project-one", ASSISTANT, set()), {"observer"})
        self.assertEqual(delegation.stamp(self.state, ASSISTANT, "project-one"), {})

    def test_task_scope_cannot_authorize_creation_of_new_tasks(self):
        with self.assertRaises(Rejected):
            self.grant(actions=["register"], task_ids=["T01"])

    def test_persisted_request_rechecked_after_expiry_revoke_downgrade_or_disabling(self):
        self.grant(task_ids=["T01"])
        env = audited_publish(self.state)
        delegation.enforce_audit(self.state, env, time.time())
        key = "delegation:" + env["payload"]["_audit"]["delegation_id"]
        mutations = [lambda s: s["round"][key].update(expires=1), lambda s: s["round"][key].update(revoked=True),
                     lambda s: s["pilot"][f"grant:project-one:{PERSON}"].update(roles=["executor"]),
                     lambda s: s["pilot"]["identity:" + PERSON].update(status="disabled"),
                     lambda s: s["pilot"]["identity:" + ASSISTANT].update(owner="other-person"),
                     lambda s: s["pilot"]["identity:" + ASSISTANT].update(status="disabled")]
        for mutation in mutations:
            state = deepcopy(self.state)
            mutation(state)
            with self.subTest(mutation=mutation), self.assertRaises(Rejected):
                delegation.enforce_audit(state, env, time.time())

    def test_changed_grant_version_rejects_old_queued_request(self):
        self.grant()
        env = audited_publish(self.state)
        self.grant(version=1, actions=["read", "task-publish"])
        with self.assertRaises(Rejected):
            delegation.enforce_audit(self.state, env, time.time())

    def test_task_and_actual_command_cannot_be_relabelled_by_audit(self):
        self.grant()
        env = audited_publish(self.state)
        altered = deepcopy(env)
        altered["payload"]["task_id"] = "T02"
        with self.assertRaises(Rejected):
            delegation.enforce_audit(self.state, altered, time.time())
        altered = deepcopy(env)
        altered["payload"]["op"] = "grant"
        with self.assertRaises(Rejected):
            delegation.enforce_audit(self.state, altered, time.time())

    def test_replay_does_not_adopt_new_grants_when_original_request_had_none(self):
        self.grant()
        with delegation.operation_context(self.state, ASSISTANT, "task-publish", "project-one", "T01", audit={}):
            self.assertEqual(delegation.stamp(self.state, ASSISTANT, "project-one"), {})

    def test_only_delegator_can_revoke_and_stale_version_rejected(self):
        record = self.grant()
        p = {"op": "delegate-revoke", "delegation_id": record["id"], "version": 1, "reason": "withdraw fixture"}
        for actor in (ASSISTANT, "other-person"):
            with self.subTest(actor=actor), self.assertRaises(Rejected):
                decide(self.state, p, actor)
        decide(self.state, p)
        self.assertTrue(record["revoked"])
        self.assertEqual(record["version"], 2)
        with self.assertRaises(Rejected):
            decide(self.state, p)

    def test_acceptance_and_capability_identities_are_never_added(self):
        self.grant()
        for operation in ("review", "return", "close", "capability-save"):
            with self.subTest(operation=operation), delegation.operation_context(self.state, ASSISTANT, operation, "project-one", "T01"):
                self.assertEqual(delegation.effective_roles(self.state, "project-one", ASSISTANT, set()), set())

    def test_task_delegate_may_declare_only_its_own_skill_without_own_project_membership(self):
        self.grant(actions=["capability-save"], task_ids=["T01"])
        with delegation.operation_context(self.state, ASSISTANT, "capability-save", "project-one") as metadata:
            self.assertIn("executor", delegation.effective_roles(self.state, "project-one", ASSISTANT, set()))
            audit = {"actor": ASSISTANT, "operation": "capability-save", "project_id": "project-one", **metadata}
        p = {"op": "capability", "project_id": "project-one", "name": ASSISTANT,
             "record": {"kind": "skill", "level": "declared"}, "_audit": audit}
        delegation.enforce_audit(self.state, {"command": "pilot", "payload": p}, time.time())
        for change in ({"name": OTHER}, {"record": {"kind": "environment", "level": "declared"}},
                       {"record": {"kind": "skill", "level": "verified"}}, {"record": {"kind": "skill", "level": "probed"}}):
            with self.subTest(change=change), self.assertRaises(Rejected):
                delegation.enforce_audit(self.state, {"command": "pilot", "payload": {**p, **change}}, time.time())


class FixtureService:
    def __init__(self):
        self.lock = RLock()
        self.state = fixture()
        self.calls = []

    def snapshot(self):
        return {"state": self.state}

    def submit(self, actor, action, request_id, body):
        self.calls.append((actor, action, request_id, deepcopy(body)))
        prepared = delegation.plan(self, actor, action, request_id, body, self.state)
        candidate = deepcopy(self.state)
        decide(candidate, prepared["steps"][0]["payload"], actor)
        self.state = candidate
        return 200, {"status": "applied"}


class DelegationPageTest(unittest.TestCase):
    def setUp(self):
        self.service = FixtureService()

    def send(self, actor=PERSON, changes=None, csrf=True, origin="http://localhost:8765"):
        data = {"request_id": "fixture-ui", "operation": "grant", "executor_id": ASSISTANT,
                "project_id": "project-one", "preset": "project", "task_ids": "T01", "hours": "24", "issued": str(int(time.time())), "version": "0", "reason": "human consent"}
        data.update(changes or {})
        if csrf:
            data["csrf"] = "a" * 64
        headers = Message()
        headers["Host"], headers["Origin"] = "localhost:8765", origin
        handler = SimpleNamespace(server=SimpleNamespace(service=self.service, is_round=True, tls=None),
                                  form_token="a" * 64, headers=headers,
                                  request_body=lambda kind, limit: urlencode(data).encode())
        return delegation_pages.dispatch(handler, "POST", urlsplit("/assistants"), actor)

    def test_human_confirmation_records_task_scope_and_only_available_preset_actions(self):
        status, html, *_ = self.send()
        self.assertEqual(status, 200)
        self.assertIn("委托已更新".encode(), html)
        p = self.service.calls[0][3]
        self.assertEqual(p["task_ids"], ["T01"])
        self.assertIn("task-publish", p["actions"])
        self.assertNotIn("register", p["actions"])
        self.assertNotIn("review", p["actions"])

    def test_ai_and_cross_origin_cannot_confirm(self):
        for actor, origin in ((ASSISTANT, "http://localhost:8765"), (PERSON, "http://other.invalid")):
            with self.subTest(actor=actor), self.assertRaises(ClientError):
                self.send(actor=actor, origin=origin)
        self.assertFalse(self.service.state["round"])

    def test_missing_csrf_and_foreign_window_are_refused(self):
        status, *_ = self.send(csrf=False)
        self.assertEqual(status, 403)
        status, *_ = self.send(changes={"executor_id": "foreign-window"})
        self.assertEqual(status, 409)
        self.assertFalse(self.service.state["round"])

    def test_window_names_are_escaped_and_existing_version_is_preserved_in_editor(self):
        decide(self.service.state, grant_payload(self.service.state))
        _, html, *_ = delegation_pages.render(PERSON, self.service.state)
        self.assertIn(b'&lt;test &quot;window&quot;&gt;', html)
        self.assertNotIn(b'<test "window">', html)
        self.assertIn(b'name="version" value="1"', html)


if __name__ == "__main__":
    unittest.main()
