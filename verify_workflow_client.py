"""Portable explicit workflow commands retain original requests and never auto-act."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from urllib.parse import parse_qs, urlsplit
from verify_client_workflow import client, MemoryAPI, saved_state, temporary


class WorkflowAPI(MemoryAPI):
    def __init__(self, supported=True):
        super().__init__()
        self.supported = supported

    def call(self, route, token=None, body=None, response_format='json', **kwargs):
        if route == 'features':
            self.calls.append((route, deepcopy(body), response_format))
            return {'api_protocol': 1, 'security_schema': 5,
                    'features': {key: self.supported for key in set(client.WORKFLOW_FEATURES.values())}}
        if route.startswith(('communication', 'post-completion')):
            self.calls.append((route, deepcopy(body), response_format))
            return {'messages': [], 'experiences': [], 'issues': []}
        return super().call(route, token, body, response_format, **kwargs)


class WorkflowClient(unittest.TestCase):
    def test_parser_and_dispatch_allowlist(self):
        parser = client.build_parser()
        for operation in client.WORKFLOW_FEATURES:
            args = parser.parse_args(['--state', 'private/credential', 'workflow', operation, '--file', 'request.json'])
            self.assertEqual(args.operation, operation)
            self.assertEqual(client.SERVICE_COMMANDS['workflow'], client.workflow_command)
        for command in ('communication', 'post-issues'):
            self.assertEqual(client.SERVICE_COMMANDS[command], client.workflow_read)

    def test_workflow_allowlist_matches_server_actions(self):
        import pool
        from pool.post_completion import ACTIONS as post_actions
        from pool.task_communication import ACTIONS as communication_actions
        self.assertEqual(set(client.WORKFLOW_FEATURES), post_actions | communication_actions | {'executor-complete', 'close'})

    def test_empty_search_omitted_and_all_read_queries_parse(self):
        from pool.httpd import parse_query
        with temporary() as folder:
            state = saved_state(Path(folder)); api = WorkflowAPI()
            for project, task, q in ((None, None, ''), ('P1', None, ''), ('P1', 'T1', ''), ('P1', 'T1', '证据')):
                client.workflow_read(state, api, SimpleNamespace(action='communication', project=project, task=task, q=q))
                route = api.calls[-1][0]
                actual = parse_query(urlsplit(route).query, {'project', 'task_id', 'q'})
                self.assertEqual(actual, {k: v for k, v in {'project': project, 'task_id': task, 'q': q}.items() if v})

    def test_drop_retry_preserves_original_file_and_request(self):
        with temporary() as folder:
            root = Path(folder); state = saved_state(root); api = WorkflowAPI()
            path = root / 'request.json'; path.write_text(json.dumps({'task_id': 'T1'}))
            args = SimpleNamespace(operation='close', file=path)
            api.drop_once = True
            with self.assertRaises(ConnectionResetError): client.workflow_command(state, api, args)
            original = deepcopy(state.data['pending_write']['body'])
            path.write_text('{"task_id":"T2"}')
            with state.exclusive():
                client.workflow_command(state, api, args)
            posts = [body for route, body, _ in api.calls if body is not None]
            self.assertEqual(posts, [original, original]); self.assertEqual(api.applied, 1)
            self.assertNotIn('pending_write', state.data)
            self.assertEqual(sum(route == 'features' for route, _, _ in api.calls), 1)

    def test_no_unsupported_writes_or_pending_state(self):
        with temporary() as folder:
            root = Path(folder); state = saved_state(root); api = WorkflowAPI(False)
            path = root / 'request.json'; path.write_text('{"task_id":"T1"}')
            for operation in client.WORKFLOW_FEATURES:
                with self.assertRaises(ValueError):
                    client.workflow_command(state, api, SimpleNamespace(operation=operation, file=path))
            self.assertNotIn('pending_write', state.data)
            self.assertFalse(any(body for _, body, _ in api.calls))

    def test_malformed_and_reserved_payloads_never_post(self):
        with temporary() as folder:
            root = Path(folder); state = saved_state(root); api = WorkflowAPI()
            path = root / 'request.json'
            for value in ('[]', '{"task_id":"T1","task_id":"T2"}', '{"request_id":"override"}',
                          '{"token":"secret"}', '{"_audit":{}}', '{"op":"anything"}', '{"x":NaN}'):
                path.write_text(value)
                with self.assertRaises(ValueError):
                    client.workflow_command(state, api, SimpleNamespace(operation='task-message', file=path))
            self.assertFalse(any(body for _, body, _ in api.calls))
            with self.assertRaises(ValueError):
                client.workflow_command(state, api, SimpleNamespace(operation='anything', file=path))

    def test_explicit_completion_checks_not_synthesized(self):
        with temporary() as folder:
            root = Path(folder); state = saved_state(root); api = WorkflowAPI(); path = root / 'request.json'
            for data in ({}, {'checks': []}, {'checks': 'pass'}):
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    client.workflow_command(state, api, SimpleNamespace(operation='executor-complete', file=path))
            body = {'claim_id': 'claim-1', 'epoch': 2, 'scope_version': 1, 'revision': 'revision-1',
                    'manifest_sha256': 'f' * 64, 'checks': [{'id': 'C1', 'path': 'out/a.txt', 'sha256': 'a' * 64, 'note': 'Measured'}],
                    'finish': True}
            path.write_text(json.dumps(body))
            client.workflow_command(state, api, SimpleNamespace(operation='executor-complete', file=path))
            sent = next(value for route, value, _ in api.calls if route == 'executor-complete')
            self.assertEqual({k: v for k, v in sent.items() if k != 'request_id'}, body)
            self.assertFalse(any(route.startswith('tasks/') for route, _, _ in api.calls))

    def test_pending_blocks_different_workflow_without_reading_file(self):
        with temporary() as folder:
            root = Path(folder); state = saved_state(root); api = WorkflowAPI(); path = root / 'request.json'
            path.write_text('{"task_id":"T1"}'); api.pending_once = True
            with self.assertRaises(client.RequestError):
                client.workflow_command(state, api, SimpleNamespace(operation='close', file=path))
            with self.assertRaises(ValueError):
                client.workflow_command(state, api, SimpleNamespace(operation='experience-save', file=path))
            client.durable_write(state, api)
            self.assertEqual(api.applied, 1)

    def test_reads_encode_filters_without_ack_or_write(self):
        with temporary() as folder:
            state = saved_state(Path(folder)); api = WorkflowAPI()
            client.workflow_read(state, api, SimpleNamespace(action='communication', project='P1', task='T1', q='证据 & a'))
            client.workflow_read(state, api, SimpleNamespace(action='post-issues', task='T1'))
            routes = [route for route, _, _ in api.calls if route != 'features']
            self.assertEqual(parse_qs(urlsplit(routes[0]).query), {'project': ['P1'], 'task_id': ['T1'], 'q': ['证据 & a']})
            self.assertEqual(routes[1], 'post-completion?task_id=T1')
            self.assertTrue(all(body is None for _, body, _ in api.calls))
            self.assertNotIn('pending_write', state.data)


if __name__ == '__main__': unittest.main()
