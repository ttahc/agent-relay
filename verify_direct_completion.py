"""Direct completion keeps the sealed evidence and never impersonates independent review."""
from copy import deepcopy
import unittest
import pool
from 协作账本 import initial
from 协作命令 import decide
from 协作存储 import Rejected
import 协作升级 as rules

SHA = 'a' * 64
ART = {'path': 'deliveries/T1/c/r/output.md', 'sha256': 'b' * 64}
MANIFEST = {'path': 'deliveries/T1/c/r/manifest.json', 'sha256': SHA}


def fixture(policy='executor-direct'):
    state = initial({'coordinator': 'coord', 'repo_id': 'fixture', 'authority_ref': 'fixture'})
    state['pilot']['format'] = {'schema': 3, 'min_reader': 7, 'maintenance': False}
    state['pilot']['project:p'] = {'id': 'p', 'owner': 'reviewer'}
    for actor, roles in [('worker', ['executor']), ('peer', ['executor']), ('reviewer', ['receiver'])]:
        state['origins'][actor] = {'roles': roles, 'version': 1}
        state['pilot']['identity:' + actor] = {'kind': 'human', 'owner': actor, 'status': 'active'}
        state['pilot']['grant:p:' + actor] = {'roles': roles, 'resources': [], 'version': 1}
    state['tasks']['T1'] = {'task_id': 'T1', 'receiver': 'reviewer', 'scope_version': 1, 'version': 1,
        'status': 'running', 'kind': 'documentation', 'claims': ['c'], 'completes_on': ['ready'], 'requires_commit': False,
        'inputs': {}, 'dependencies': [], 'contract': {'project_id': 'p', 'review_mode': 'source', 'completion_policy': policy}}
    state['claims']['c'] = {'claim_id': 'c', 'task_id': 'T1', 'origin': 'worker', 'version': 1,
        'L': 'active', 'epoch': 1, 'W': {'state': 'review', 'scope': 1, 'revision': 'r'},
        'E': {'state': 'stopped', 'reason': 'complete'}, 'R': [], 'inputs': {},
        'deliveries': {'r': {'status': 'review', 'scope_version': 1, 'manifest': MANIFEST,
            'manifest_sha256': SHA, 'criteria': ['ready'], 'remaining': []}}}
    return state


def event(state, actor='worker', command='executor_complete'):
    return {'origin_id': actor, 'command': command, 'event_id': 'done',
        'expects': {'epoch:c': 1, 'scope:T1': 1}, 'payload': {'claim_id': 'c', 'revision': 'r',
        'manifest': MANIFEST, 'manifest_sha256': SHA, 'verdict': 'accept',
        'checks': [{'id': 'ready', 'status': 'passed', 'level': 'static', 'evidence': {'artifact': ART}}],
        '_audit': {'schema': 3, 'actor': actor, 'authorization': rules.auth_stamp(state, actor, 'p')}}}


def context():
    return {'seq': 1, 'now': 1, 'verified_manifests': {SHA},
            'manifest_data': {'outputs': [{'path': 'output.md', 'sha256': ART['sha256']}]}}


class DirectCompletion(unittest.TestCase):
    def test_reader_seven_does_not_claim_future_security_schema(self):
        from 协作安全 import check
        for version in (6, 7):
            state = fixture()
            state['pilot']['format'].update(schema=version)
            state['security'] = {'schema': version, 'phase': 'ready'}
            with self.assertRaises(ValueError): check(state)

    def test_parallel_domain_reader_requires_actual_execution_capability(self):
        from unittest.mock import patch
        from 协作安全 import check
        import 协作执行 as execution
        state = fixture(); state['pilot']['format']['min_reader'] = 6
        # This safety regression remains valid in a later combined build.
        with patch.object(execution, 'OPS', execution.OPS - {'environment-save'}):
            with self.assertRaises(ValueError): check(state)

    def test_parallel_domain_shapes_cannot_hide_under_reader_seven(self):
        from unittest.mock import patch
        from 协作安全 import check, DOMAIN_TABLES, DOMAIN_PROOF_KEYS
        import 协作执行 as execution
        candidates = [{'execution': {key: {}}} for key in DOMAIN_TABLES]
        candidates += [{'execution': {'contexts': {'c': {'environment_id': 'env'}}}}]
        for key in DOMAIN_PROOF_KEYS:
            candidates.append({'execution': {'actions': {'a': {'resource_proofs': {'p': {key: []}}}}}})
            for table in ('actions', 'resource_requests', 'grants', 'legacy', 'blockers'):
                candidates.append({'execution': {table: {'r': {'resources': [{key: []}]}}}})
            candidates.append({'physical_blockers': {'r': {'resources': [{key: []}]}}})
        with patch.object(execution, 'OPS', execution.OPS - {'environment-save'}):
            for security in candidates:
                with self.subTest(security=security):
                    state = fixture(); state['security'] = {'schema': 3, **security}
                    with self.assertRaises(ValueError): check(state)

    def test_legacy_proofs_and_user_evidence_remain_compatible(self):
        from 协作安全 import check
        state = fixture()
        state['security'] = {'schema': 3, 'execution': {'actions': {'a': {
            'resource_proofs': {'p': {'identity': '1:2', 'resolved': True, 'canonical_path': '/tmp/a'}},
            'resources': [{'id': 'path:a', 'domain': 'local', 'mode': 'read'}],
            'evidence': {'environment_id': 'ordinary evidence, not an execution context'}}}}}
        self.assertEqual(check(state), 3)

    def test_completion_records_non_independent_provenance_and_ends_safe_claim(self):
        state = fixture(); decide(state, event(state), context())
        self.assertEqual(state['tasks']['T1']['status'], 'pending_close')
        self.assertEqual(state['claims']['c']['L'], 'ended')
        record = state['acceptances']['done']
        self.assertEqual(record['completion_kind'], 'executor-direct')
        self.assertFalse(record['independent'])
        self.assertTrue(rules.direct_closer(state, state['tasks']['T1'], 'worker'))
        self.assertFalse(rules.direct_closer(state, state['tasks']['T1'], 'peer'))
        state['pilot']['grant:p:worker']['roles'] = []
        self.assertFalse(rules.direct_closer(state, state['tasks']['T1'], 'worker'))

    def test_running_execution_and_resources_do_not_end_claim(self):
        for change in ({'E': {'state': 'running'}}, {'R': ['resource']}):
            state = fixture(); state['claims']['c'].update(change)
            decide(state, event(state), context())
            self.assertEqual(state['tasks']['T1']['status'], 'running')
            self.assertEqual(state['claims']['c']['L'], 'active')

    def test_review_required_and_legacy_tasks_reject_direct_completion(self):
        for remove in (False, True):
            state = fixture('review-required')
            if remove: state['tasks']['T1']['contract'].pop('completion_policy')
            with self.assertRaises(Rejected): decide(state, event(state), context())

    def test_other_executor_and_self_review_are_rejected(self):
        for actor, command in [('peer', 'executor_complete'), ('worker', 'review')]:
            state = fixture()
            with self.assertRaises(Rejected): decide(state, event(state, actor, command), context())

    def test_stale_scope_epoch_and_ended_claim_are_rejected(self):
        for key, value in [('epoch', 2), ('L', 'ended')]:
            state = fixture(); state['claims']['c'][key] = value
            with self.assertRaises(Rejected): decide(state, event(state), context())
        state = fixture(); state['tasks']['T1']['scope_version'] = 2
        with self.assertRaises(Rejected): decide(state, event(state), context())

    def test_manifest_and_actual_artifact_checks_are_mandatory(self):
        for change in ('manifest', 'artifact', 'criteria', 'verified'):
            state = fixture(); env = event(state); ctx = context()
            if change == 'manifest': env['payload']['manifest'] = {**MANIFEST, 'path': 'other'}
            if change == 'artifact': env['payload']['checks'][0]['evidence'] = {'note': 'assertion only'}
            if change == 'criteria': env['payload']['checks'] = []
            if change == 'verified': ctx['verified_manifests'] = set()
            with self.assertRaises(Rejected): decide(state, env, ctx)

    def test_current_authorization_rechecked(self):
        state = fixture(); env = event(state)
        state['pilot']['grant:p:worker']['roles'] = []
        with self.assertRaises(Rejected): decide(state, env, context())

    def test_authorized_executor_close_preserves_provenance(self):
        state = fixture(); decide(state, event(state), context())
        env = {'origin_id': 'coord', 'command': 'close', 'event_id': 'closed',
            'expects': {'generation': 1}, 'payload': {'task_id': 'T1',
            '_audit': {'schema': 3, 'actor': 'worker', 'authorization': rules.auth_stamp(state, 'worker', 'p')}}}
        ctx = {**context(), 'close_prepared': {'missing': [], 'summary': 'verified',
            'acceptance_id': 'done', 'accepted_manifest': MANIFEST}}
        decide(state, env, ctx)
        self.assertEqual(state['tasks']['T1']['status'], 'completed')
        self.assertFalse(state['closings']['closed']['independent'])
        self.assertEqual(state['closings']['closed']['completion_kind'], 'executor-direct')

    def test_close_rejects_live_claim_even_with_acceptance(self):
        state = fixture(); state['claims']['c']['E'] = {'state': 'running'}
        decide(state, event(state), context())
        env = {'origin_id': 'coord', 'command': 'close', 'event_id': 'closed',
            'expects': {'generation': 1}, 'payload': {'task_id': 'T1',
            '_audit': {'schema': 3, 'actor': 'worker', 'authorization': rules.auth_stamp(state, 'worker', 'p')}}}
        with self.assertRaises(Rejected): decide(state, env, context())

    def test_direct_registration_sets_reader_floor_without_rewriting_old_tasks(self):
        from 协作命令 import new_task
        from 协作安全 import check
        state = fixture(); before = deepcopy(state['tasks']['T1'])
        proposal = {'proposal_id': 'proposal', 'title': 'new direct task', 'authorities': []}
        spec = {'project_id': 'p', 'iteration': {'goal': 'test', 'previous': [], 'next': []},
                'delivery': 'output', 'requirements': [{'id': 'markdown', 'kind': 'skill', 'value': '*', 'required': True, 'evidence': 'declared'}],
                'review_mode': 'source', 'user_basis': '', 'completion_policy': 'executor-direct'}
        state['pilot']['format']['min_reader'] = 3
        new_task(state, proposal, {'kind': 'documentation', 'completes_on': ['ready'],
            'requires_commit': False, 'receiver': 'reviewer', 'inputs': {'input.md': SHA}, 'contract': spec}, 1)
        self.assertEqual(state['pilot']['format']['min_reader'], 7)
        self.assertEqual(state['tasks']['T1'], before)
        with self.assertRaises(ValueError): check(state, reader=5)

    def test_scope_cannot_change_frozen_policy_and_omission_preserves_it(self):
        for policy in ('executor-direct', 'review-required'):
            state = fixture(policy)
            spec = {'project_id': 'p', 'iteration': {'goal': 'test', 'previous': [], 'next': []},
                'delivery': 'output', 'requirements': [{'id': 'markdown', 'kind': 'skill', 'value': '*', 'required': True, 'evidence': 'declared'}], 'review_mode': 'source', 'user_basis': ''}
            self.assertEqual(rules.task_spec(state, spec, 'T1').get('completion_policy', 'review-required'), policy)
            spec['completion_policy'] = 'review-required' if policy == 'executor-direct' else 'executor-direct'
            with self.assertRaises(Rejected): rules.task_spec(state, spec, 'T1')


if __name__ == '__main__': unittest.main()
