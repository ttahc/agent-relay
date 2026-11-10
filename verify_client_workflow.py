"""Isolated AI-client workflow regression; production data and tokens are not used."""
from copy import deepcopy
from contextlib import redirect_stdout
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
from io import StringIO
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('workflow_client', ROOT / 'ops/round-client.py')
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


def temporary():
    folder = ROOT / '.state'
    folder.mkdir(exist_ok=True)
    return tempfile.TemporaryDirectory(prefix='client-workflow-', dir=folder)


class MemoryAPI:
    def __init__(self):
        self.calls, self.receipts, self.applied = [], {}, 0
        self.drop_once, self.pending_once = False, False
        self.view = {'task': {'task_id': 'T1', 'version': 4, 'scope_version': 3, 'inputs': {}},
                     'claims': [{'claim_id': 'c-fixture', 'origin': 'fixture-window', 'L': 'active',
                                 'epoch': 8, 'W': {'scope': 3}, 'inputs': {}, 'deliveries': {}}]}
        self.files = {}

    def call(self, route, token=None, body=None, response_format='json', **kwargs):
        self.calls.append((route, deepcopy(body), response_format))
        if route == 'features':
            return {'api_protocol': 1, 'security_schema': 3, 'features': {'input-package': False}}
        if route.startswith('tasks/'):
            return deepcopy(self.view)
        if route == 'identity':
            return {'identity': 'fixture-window', 'binding': {'environment': 'fixture-env'}}
        if route == 'capabilities':
            return {'identity': 'fixture-window', 'capabilities': []}
        if route.startswith('artifact?'):
            path = parse_qs(urlsplit(route).query)['path'][0]
            return self.files[path]
        if body is not None:
            rid = body['request_id']
            if self.pending_once:
                self.pending_once = False
                raise client.RequestError(202, {'status': 'pending', 'request_id': rid})
            if rid not in self.receipts:
                self.applied += 1
                self.receipts[rid] = {'status': 'applied', 'request_id': rid, 'claim': deepcopy(self.view['claims'][0])}
            if self.drop_once:
                self.drop_once = False
                raise ConnectionResetError('fixture dropped reply after apply')
            return deepcopy(self.receipts[rid])
        raise AssertionError(route)


def saved_state(root):
    state = client.State(root / 'private/window.credential')
    state.data = {'token': 'fixture-private-token', 'executor_id': 'fixture-window'}
    state.save()
    return state


class ClientWorkflow(unittest.TestCase):
    def test_empty_claimable_list_explains_visible_tasks_and_skill_gaps(self):
        result = {'tasks': [{'task_id': 'T1', 'qualification': {'eligible': False, 'missing': ['能力缺项 source-review']}}],
                  'counts': {'visible': 1, 'claimable': 0}, 'missing_summary': [{'reason': '能力缺项 source-review', 'count': 1}],
                  'capability_hints': [{'project_id': 'fixture-project', 'id': 'source-review', 'kind': 'skill', 'evidence': 'declared'}]}
        api = SimpleNamespace(call=lambda *args: deepcopy(result))
        actual = client.visible_tasks(SimpleNamespace(data={'token': 'private'}), api, SimpleNamespace(project=None, claimable=True))
        self.assertEqual(actual['tasks'], [])
        self.assertEqual(actual['counts'], {'visible': 1, 'claimable': 0})
        self.assertIn('source-review', actual['missing_summary'][0]['reason'])
        self.assertIn('declare', actual['next'])

    def test_lost_claim_reply_reloads_and_replays_exact_request_once(self):
        with temporary() as folder:
            root = Path(folder)
            state, api = saved_state(root), MemoryAPI()
            api.drop_once = True
            args = SimpleNamespace(task='T1')
            with self.assertRaises(ConnectionResetError):
                client.claim_task(state, api, args)
            original = deepcopy(state.data['pending_write']['body'])
            api.view['task']['version'] = 99
            reread = client.State(state.path)
            with reread.exclusive():
                reply = client.claim_task(reread, api, args)
            writes = [body for route, body, _ in api.calls if route == 'claim']
            self.assertEqual(writes, [original, original])
            self.assertEqual(api.applied, 1)
            self.assertEqual(reply['request_id'], original['request_id'])
            self.assertEqual(sum(route.startswith('tasks/') for route, _, _ in api.calls), 1)
            self.assertNotIn('pending_write', reread.data)

    def test_pending_write_blocks_different_mutation_and_retry_keeps_id(self):
        with temporary() as folder:
            state, api = saved_state(Path(folder)), MemoryAPI()
            api.pending_once = True
            with self.assertRaises(client.RequestError):
                client.claim_task(state, api, SimpleNamespace(task='T1'))
            pending = deepcopy(state.data['pending_write'])
            with self.assertRaisesRegex(ValueError, '待确认'):
                client.claim_task(state, api, SimpleNamespace(task='T2'))
            result = client.durable_write(state, api)
            self.assertEqual(result['request_id'], pending['body']['request_id'])
            self.assertEqual(api.applied, 1)

    def test_lost_delivery_reply_keeps_file_bytes_epoch_and_scope(self):
        with temporary() as folder:
            root = Path(folder)
            state, api = saved_state(root), MemoryAPI()
            artifact = root / 'result.md'
            artifact.write_bytes(b'original fixture')
            args = SimpleNamespace(task='T1', claim_id=None, file=[artifact], stop_evidence='fixture process exited')
            api.drop_once = True
            with self.assertRaises(ConnectionResetError):
                client.deliver_task(state, api, args)
            original = deepcopy(state.data['pending_write']['body'])
            artifact.write_bytes(b'changed after lost reply')
            client.deliver_task(state, api, args)
            writes = [body for route, body, _ in api.calls if route == 'deliver-files']
            self.assertEqual(writes, [original, original])
            self.assertEqual(original['epoch'], 8)
            self.assertEqual(original['scope_version'], 3)
            self.assertEqual(original['claim_id'], 'c-fixture')
            self.assertEqual(api.applied, 1)

    def test_bad_download_hash_preserves_existing_file(self):
        with temporary() as folder:
            root = Path(folder)
            target = root / 'download/inputs/fixture.txt'
            target.parent.mkdir(parents=True)
            target.write_bytes(b'existing file')
            api = MemoryAPI()
            api.view['task']['inputs'] = {'inputs/fixture.txt': hashlib.sha256(b'expected').hexdigest()}
            api.files['inputs/fixture.txt'] = b'tampered'
            args = SimpleNamespace(task='T1', output=root / 'download', artifact=None, sha256=None)
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                client.download_task(SimpleNamespace(data={'token': 'private'}), api, args)
            self.assertEqual(target.read_bytes(), b'existing file')
            self.assertFalse(list(target.parent.glob('.download-*')))

    def test_download_rejects_escaping_and_reserved_paths(self):
        with temporary() as folder:
            for path in ('../outside', '/absolute', 'C:/escape', r'folder\escape', 'safe/../outside', 'CON.txt', 'file:stream', 'x\n.txt'):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    client.checked_target(Path(folder), path)

    def test_download_verifies_manifest_and_output_files(self):
        with temporary() as folder:
            api = MemoryAPI()
            prefix = 'deliveries/T1/c-fixture/revision-1/frozen'
            output = b'actual output fixture'
            manifest = json.dumps({'outputs': [{'path': 'output.md', 'sha256': hashlib.sha256(output).hexdigest()}]}).encode()
            ref = {'path': prefix + '/manifest.json', 'sha256': hashlib.sha256(manifest).hexdigest()}
            api.view['claims'][0]['deliveries'] = {'revision-1': {'manifest': ref}}
            api.files = {ref['path']: manifest, prefix + '/output.md': output}
            args = SimpleNamespace(task='T1', output=Path(folder) / 'download', artifact=None, sha256=None)
            result = client.download_task(SimpleNamespace(data={'token': 'private'}), api, args)
            self.assertEqual(result['verified_files'], 2)
            self.assertEqual((args.output / prefix / 'output.md').read_bytes(), output)

    def test_declare_only_declared_skill_and_current_environment(self):
        with temporary() as folder:
            state, api = saved_state(Path(folder)), MemoryAPI()
            args = SimpleNamespace(project='fixture-project', capability='source-review', value='ok', environment=None,
                                   evidence='read fixture source', evidence_sha256=None, days=7)
            client.declared_capability(state, api, args)
            body = next(body for route, body, _ in api.calls if route == 'capability-save')
            self.assertEqual((body['kind'], body['level'], body['name'], body['environment']),
                             ('skill', 'declared', 'fixture-window', 'fixture-env'))
            self.assertEqual(body['version'], 0)

    def test_public_output_redacts_nested_access_credentials(self):
        value = client.public_value({'status': 'ok', 'token': 'private-token', 'nested': [{'code': 'private-invite', 'task': 'T1'}]})
        rendered = json.dumps(value)
        self.assertNotIn('private-token', rendered)
        self.assertNotIn('private-invite', rendered)
        self.assertIn('T1', rendered)

    def test_create_contract_is_frozen_across_lost_reply_and_file_change(self):
        with temporary() as folder:
            root = Path(folder)
            state, api = saved_state(root), MemoryAPI()
            contract = root / 'contract.json'
            contract.write_text(json.dumps({'title': 'original contract', 'project_id': 'fixture-project'}), encoding='utf-8')
            api.drop_once = True
            args = SimpleNamespace(contract=contract)
            with self.assertRaises(ConnectionResetError):
                client.create_task(state, api, args)
            first = deepcopy(state.data['pending_write']['body'])
            contract.write_text(json.dumps({'title': 'changed contract'}), encoding='utf-8')
            client.create_task(state, api, args)
            self.assertEqual([body for route, body, _ in api.calls if route == 'register'], [first, first])
            self.assertEqual(api.applied, 1)

    def test_publish_and_hold_use_task_version_scope_and_explicit_reason(self):
        with temporary() as folder:
            state, api = saved_state(Path(folder)), MemoryAPI()
            for action, route in (('publish', 'task-publish'), ('hold', 'task-hold')):
                client.task_publication(state, api, SimpleNamespace(action=action, task='T1', reason='fixture user instruction'))
                body = next(body for selected, body, _ in reversed(api.calls) if selected == route)
                self.assertEqual({key: body[key] for key in ('task_id', 'version', 'scope_version', 'reason')},
                                 {'task_id': 'T1', 'version': 4, 'scope_version': 3, 'reason': 'fixture user instruction'})

    def test_feedback_update_retains_existing_tracking_and_evidence_fields(self):
        with temporary() as folder:
            state, api = saved_state(Path(folder)), MemoryAPI()
            original_call = api.call
            prior = {'id': 'fb-fixture', 'version': 6, 'status': 'triage', 'linked_task': 'T1', 'evidence': 'original observation',
                     'updates': [{'duplicate': 'fb-main', 'evidence': 'existing evidence', 'metrics': [{'metric': 'steps'}],
                                  'lesson': 'existing lesson', 'limits': 'existing limits'}]}
            def call(route, *args, **kwargs):
                if route.startswith('collaboration?'):
                    return {'feedback': [deepcopy(prior)]}
                return original_call(route, *args, **kwargs)
            api.call = call
            args = SimpleNamespace(project='fixture-project', feedback_id='fb-fixture', status='triage', reason='candidate follow-up',
                                   linked_task=None, duplicate=None, evidence=None, metrics=None, lesson=None, limits=None)
            client.update_feedback(state, api, args)
            body = next(body for route, body, _ in api.calls if route == 'feedback-update')
            self.assertEqual(body['version'], 6)
            self.assertEqual(body['linked_task'], 'T1')
            for key in ('duplicate', 'evidence', 'metrics', 'lesson', 'limits'):
                self.assertEqual(body[key], prior['updates'][-1][key])
            self.assertEqual(body['status'], 'triage')

    def test_revoked_delegation_can_only_use_cleanup_for_stop_or_handoff(self):
        with temporary() as folder:
            state, api = saved_state(Path(folder)), MemoryAPI()
            original_call, reads = api.call, []
            def call(route, *args, **kwargs):
                reads.append(route)
                if route.startswith('tasks/'):
                    raise client.RequestError(404, {'message': 'fixture withdrawn project access'})
                if route == 'cleanup':
                    return {'claims': [{'claim_id': 'c-fixture', 'task_id': 'T1', 'epoch': 8, 'W': {'scope': 3},
                                        'origin': 'fixture-window', 'L': 'active'}]}
                return original_call(route, *args, **kwargs)
            api.call = call
            args = SimpleNamespace(action='stop', task='T1', claim_id=None, evidence='actual fixture process exited')
            client.stop_or_handoff(state, api, args)
            body = next(body for route, body, _ in api.calls if route == 'stop')
            self.assertEqual(set(body), {'request_id', 'claim_id', 'epoch', 'scope_version', 'stop_evidence'})
            self.assertIn('cleanup', reads)
            reads.clear()
            with self.assertRaises(client.RequestError):
                client.own_claim(state, api, 'T1')
            self.assertNotIn('cleanup', reads)

    def test_cleanup_does_not_select_other_tasks_or_other_windows(self):
        state = SimpleNamespace(data={'token': 'private', 'executor_id': 'fixture-window'})
        def call(route, *args, **kwargs):
            if route.startswith('tasks/'):
                raise client.RequestError(403, {'message': 'fixture revoked'})
            return {'claims': [{'claim_id': 'c-other', 'task_id': 'T1', 'epoch': 1, 'W': {'scope': 1}, 'origin': 'another-window', 'L': 'active'},
                               {'claim_id': 'c-different-task', 'task_id': 'T2', 'epoch': 1, 'W': {'scope': 1}, 'origin': 'fixture-window', 'L': 'active'}]}
        with self.assertRaisesRegex(ValueError, '唯一活动领取'):
            client.own_claim(state, SimpleNamespace(call=call), 'T1', allow_cleanup=True)

    def test_pending_command_can_be_inspected_offline_without_network(self):
        with temporary() as folder:
            state = saved_state(Path(folder))
            state.data['pending_write'] = {'operation': {'name': 'claim'}, 'route': 'claim',
                                           'body': {'request_id': 'fixture-request'}, 'local_update': {}}
            state.save()
            output = StringIO()
            with patch.object(client.sys, 'argv', ['round-client.py', '--state', str(state.path), 'pending']), \
                    patch.object(client, 'endpoint', side_effect=AssertionError('pending must work offline')), redirect_stdout(output):
                self.assertEqual(client.main(), 0)
            value = json.loads(output.getvalue())
            self.assertEqual(value['request_id'], 'fixture-request')
            self.assertNotIn('fixture-private-token', output.getvalue())

    def test_board_reads_markdown_without_json_decoder(self):
        class Markdown(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                raw = '# fixture board\n\n- T1 ready\n'.encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/markdown; charset=utf-8')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = ThreadingHTTPServer(('127.0.0.1', 0), Markdown)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            api = client.Pool('http://127.0.0.1:' + str(server.server_address[1]), None, allow_loopback=True)
            self.assertEqual(api.call('board', response_format='text'), '# fixture board\n\n- T1 ready\n')
        finally:
            server.shutdown()
            thread.join()
            server.server_close()


class LinkInvitations(unittest.TestCase):
    identifier = 'i-' + '1' * 32
    proof = 'k' * 43
    pin = 'a' * 64

    def link(self, *, scheme='https', host='taskpool-host', fragment=None):
        values = {'key': self.proof, 'sha256': self.pin, 'tls': 'taskpool.test'} if fragment is None else fragment
        return f'{scheme}://{host}:18443/ai/join/{self.identifier}#' + urlencode(values)

    def information(self, **changes):
        return {'id': self.identifier, 'code': 'c' * 43, 'protocol': 1, 'url': 'https://taskpool.test:18443',
                'certificate_sha256': self.pin, 'connect_host': 'taskpool.test',
                'client': {'connect_host': 'taskpool.test'}, 'invitation_url': self.link(), **changes}

    def args(self, value=None):
        return SimpleNamespace(invite=None, invite_url=value or self.link(), allow_loopback=False, platform='external',
                               session='fixture-invite-link-session', model='fixture', environment='fixture-env', link=None,
                               window_name='fixture window')

    def test_https_link_keeps_secret_in_fragment_and_route_is_canonical(self):
        value = client.invitation_link(self.link())
        self.assertEqual(value['base'], 'https://taskpool.test:18443')
        self.assertEqual(value['actual_host'], 'taskpool-host')
        self.assertEqual(value['id'], self.identifier)

    def test_link_rejects_ambiguous_fields_and_credentials_without_echo(self):
        invalid = [self.link() + '&key=' + self.proof, self.link().replace('/ai/join/', '/other/'),
                   self.link().replace('taskpool-host:', 'user:password@taskpool-host:'), self.link().replace('#', '?x=1#'),
                   self.link(fragment={'key': 'short', 'sha256': self.pin, 'tls': 'taskpool.test'}),
                   self.link(fragment={'key': self.proof, 'sha256': self.pin}),
                   self.link(fragment={'key': self.proof, 'sha256': self.pin, 'tls': 'https://taskpool.test'})]
        for link in invalid:
            with self.subTest(case=invalid.index(link)), self.assertRaises(ValueError) as caught:
                client.invitation_link(link)
            self.assertNotIn(self.proof, str(caught.exception))

    def test_plaintext_only_allows_explicit_loopback_with_empty_tls_fields(self):
        link = self.link(scheme='http', host='127.0.0.1', fragment={'key': self.proof})
        with self.assertRaises(ValueError):
            client.invitation_link(link)
        self.assertEqual(client.invitation_link(link, True)['base'], 'http://127.0.0.1:18443')
        with self.assertRaises(ValueError):
            client.invitation_link(self.link(scheme='http', fragment={'key': self.proof}), True)
        with self.assertRaises(ValueError):
            client.invitation_link(self.link(scheme='http', host='localhost'), True)

    def test_information_rebinds_canonical_route_to_trusted_original_host(self):
        api = SimpleNamespace(call=lambda *args, **kwargs: self.information())
        with patch.object(client, 'Pool', return_value=api) as factory:
            value = client.load_invitation(self.args())
        factory.assert_called_once_with('https://taskpool.test:18443', self.pin, False, 'taskpool-host')
        self.assertEqual(value['connect_host'], 'taskpool-host')
        self.assertEqual(value['client']['connect_host'], 'taskpool-host')
        self.assertNotIn('invitation_url', value)

    def test_bad_pin_fails_before_the_proof_is_sent(self):
        calls = []
        def rejected_pool(*args, **kwargs):
            calls.append('certificate probe only')
            raise ValueError('fixture pin mismatch')
        with patch.object(client, 'Pool', side_effect=rejected_pool), self.assertRaises(ValueError) as caught:
            client.load_invitation(self.args())
        self.assertEqual(calls, ['certificate probe only'])
        self.assertNotIn(self.proof, str(caught.exception))

    def test_information_cannot_change_identity_pin_authority_or_route(self):
        changes = [{'id': 'i-' + '2' * 32}, {'certificate_sha256': 'b' * 64}, {'url': 'https://other.test:18443'},
                   {'url': 'https://taskpool.test:9443'}, {'connect_host': 'third-host'},
                   {'url': 'https://taskpool.test:18443/redirect'}, {'code': 'invalid'}]
        for change in changes:
            api = SimpleNamespace(call=lambda *args, **kwargs: self.information(**change))
            with self.subTest(change=list(change)), patch.object(client, 'Pool', return_value=api), self.assertRaises(ValueError) as caught:
                client.load_invitation(self.args())
            self.assertNotIn(self.proof, str(caught.exception))

    def test_failed_information_read_does_not_redeem_or_persist_a_registration(self):
        calls = []
        def failed(route, **kwargs):
            calls.append(route)
            raise client.RequestError(410, {'message': 'fixture expired'})
        with temporary() as folder:
            state = client.State(Path(folder) / 'private/window.credential')
            with patch.object(client, 'Pool', return_value=SimpleNamespace(call=failed)), self.assertRaises(ValueError):
                client.enroll(state, self.args())
            self.assertEqual(state.data, {})
            self.assertFalse(state.path.exists())
        self.assertEqual(calls, ['ai-invite-info?' + urlencode({'invite_id': self.identifier})])

    def test_lost_prepare_reply_resumes_without_refetching_exhausted_link(self):
        owner = self
        class Flow:
            def __init__(self):
                self.reads, self.used, self.requests, self.drop = 0, 0, [], True

            def call(self, route, token=None, body=None, **kwargs):
                if route.startswith('ai-invite-info?'):
                    self.reads += 1
                    if self.used:
                        raise client.RequestError(409, {'message': 'fixture quota used'})
                    owner.assertEqual(token, owner.proof)
                    return owner.information()
                if route == 'ai-prepare':
                    self.requests.append(deepcopy(body))
                    if not self.used:
                        self.used = 1
                    if self.drop:
                        self.drop = False
                        raise ConnectionResetError('fixture reply lost')
                    return {'token': 'fixture-execution-token', 'registration_id': 'fixture-registration'}
                if route == 'ai-activate':
                    return {'executor_id': 'fixture-window', 'window': 'EXT-0010', 'expires': 1999999999}
                if route == 'identity':
                    return {'identity': 'fixture-window', 'binding': {'window_name': 'fixture window'}, 'projects': []}
                if route == 'task-options':
                    return {'counts': {'visible': 0, 'claimable': 0}, 'capability_hints': []}
                raise AssertionError(route)
        flow = Flow()
        with temporary() as folder, patch.object(client, 'Pool', return_value=flow):
            state = client.State(Path(folder) / 'private/window.credential')
            with self.assertRaises(ConnectionResetError):
                client.enroll(state, self.args())
            reread = client.State(state.path)
            with reread.exclusive():
                value = client.enroll(reread, self.args())
            self.assertEqual(value['status'], 'active')
            self.assertEqual(flow.reads, 1)
            self.assertEqual(flow.used, 1)
            self.assertEqual(flow.requests[0], flow.requests[1])
            self.assertEqual(reread.data['connect_host'], 'taskpool-host')
            self.assertNotIn(self.proof, json.dumps(reread.data))


if __name__ == '__main__':
    unittest.main()
