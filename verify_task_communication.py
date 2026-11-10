"""Communication is evidence, never implicit execution or authority."""
from copy import deepcopy
import unittest
import json
from html.parser import HTMLParser
from types import SimpleNamespace
from urllib.parse import urlencode
import pool
from pool.task_communication import payload, view
from pool.task_communication_pages import render
from pool.packages import ClientError
from 协作沟通 import action, validate
from 协作存储 import Rejected


def fixture():
    pilot = {'format': {'schema': 3, 'min_reader': 3}}
    for name, kind, owner in [('manager', 'human', 'manager'), ('writer', 'human', 'writer'),
                              ('peer', 'human', 'peer'), ('observer', 'human', 'observer'),
                              ('bot', 'executor', 'manager'), ('outsider', 'human', 'outsider')]:
        pilot['identity:' + name] = {'kind': kind, 'owner': owner, 'status': 'active'}
    for project in ('P1', 'P2'):
        pilot['project:' + project] = {'id': project}
        for name, roles in [('manager', ['manager']), ('writer', ['executor']), ('peer', ['reporter']),
                            ('observer', ['observer']), ('bot', ['manager'])]:
            pilot[f'grant:{project}:{name}'] = {'roles': roles, 'resources': []}
    return {'pilot': pilot, 'round': {'feedback:fb-1': {'id': 'fb-1', 'project_id': 'P1', 'task_id': 'T1',
                'visibility': 'restricted', 'author': 'writer', 'version': 1}},
            'tasks': {'T1': {'task_id': 'T1', 'version': 1, 'status': 'completed', 'contract': {'project_id': 'P1'}},
                      'T2': {'task_id': 'T2', 'version': 1, 'status': 'available', 'contract': {'project_id': 'P2'}}},
            'claims': {}, 'generation': 3}


def message(**changes):
    return dict({'request_id': 'req-1', 'project_id': 'P1', 'task_id': 'T1', 'task_version': 1,
                 'kind': 'question', 'recipient': 'manager', 'reply_to': '', 'content': '<script>sample</script>'}, **changes)


def experience(**changes):
    return dict({'request_id': 'exp-1', 'project_id': 'P1', 'id': 'exp-1', 'version': 0,
                 'source_task': 'T1', 'source_task_version': 1, 'source_feedback': 'fb-1', 'source_feedback_version': 1,
                 'title': 'Secret lesson', 'conditions': 'Applicable only in test', 'method': 'Hidden procedure',
                 'evidence': 'private receipt', 'limits': 'Not an authorization'}, **changes)


def apply(state, op, data, actor='writer', key='abc'):
    p = {'op': op, **payload(state, actor, op, data, key)}
    action(state, p, actor, 1700000000, 'event-' + key)
    return p


class Communication(unittest.TestCase):
    def test_no_task_lifecycle_or_authority_changes(self):
        state = fixture(); before = deepcopy(state['tasks']); claims = deepcopy(state['claims'])
        apply(state, 'task-message', message())
        self.assertEqual(state['round']['message:msg-abc']['status'], '')
        for n, status in enumerate(('received', 'replied', 'executed', 'completed'), 1):
            apply(state, 'task-message-status', {'request_id': 'status-' + str(n), 'project_id': 'P1',
                'id': 'msg-abc', 'version': n, 'status': status, 'evidence': 'Explicit marking'}, actor='manager')
        self.assertEqual(state['tasks'], before); self.assertEqual(state['claims'], claims)
        self.assertEqual(state['pilot']['format']['min_reader'], 7)
        self.assertEqual(len(state['round']['message:msg-abc']['history']), 4)

    def test_read_does_not_acknowledge_message(self):
        state = fixture(); apply(state, 'task-message', message()); before = deepcopy(state)
        view(state, 'manager', 'P1', 'T1'); self.assertEqual(state, before)

    def test_recipient_and_reply_boundaries(self):
        for changes in ({'recipient': 'outsider'}, {'reply_to': 'unknown'}, {'task_id': 'T2'}, {'task_version': 2}):
            with self.assertRaises(ClientError): apply(fixture(), 'task-message', message(**changes))
        state = fixture(); apply(state, 'task-message', message())
        apply(state, 'task-message', message(reply_to='msg-abc'), actor='manager', key='reply')
        self.assertEqual(state['round']['message:msg-abc']['status'], '')

    def test_exact_schema_and_replay_auth(self):
        state = fixture(); p = {'op': 'task-message', **payload(state, 'writer', 'task-message', message(), 'abc')}
        for field, value in [('task_version', True), ('kind', []), ('content', ''), ('recipient', []), ('unexpected', 1)]:
            with self.assertRaises(Rejected): validate(state, {**p, field: value}, 'writer')
        state['pilot']['identity:writer']['status'] = 'disabled'
        with self.assertRaises(Rejected): action(state, p, 'writer', 1, 'event')
        self.assertNotIn('message:msg-abc', state['round'])

    def test_observer_cannot_write_or_unrelated_user_mark(self):
        with self.assertRaises(ClientError): apply(fixture(), 'task-message', message(), actor='observer')
        state = fixture(); apply(state, 'task-message', message())
        with self.assertRaises(ClientError): apply(state, 'task-message-status', {'request_id': 'x', 'project_id': 'P1',
            'id': 'msg-abc', 'version': 1, 'status': 'received', 'evidence': 'x'}, actor='peer')

    def test_restricted_source_never_leaks_through_task_or_search(self):
        state = fixture(); apply(state, 'experience-save', experience())
        for actor in ('peer', 'observer', 'bot', 'outsider'):
            for query in ('', 'Secret', 'Hidden', 'private'):
                result = view(state, actor, query=query)
                self.assertEqual(result['experiences'], [])
                self.assertNotIn('Secret lesson', render(actor, result))
        self.assertEqual(len(view(state, 'manager', 'P1', 'T1')['experiences']), 1)
        self.assertEqual(len(view(state, 'writer', query='Hidden')['experiences']), 1)
        state['round']['feedback:fb-1']['project_id'] = 'P2'
        self.assertEqual(view(state, 'manager', 'P1')['experiences'], [])

    def test_human_manager_confirmation_only_and_source_freshness(self):
        state = fixture(); apply(state, 'experience-save', experience(source_feedback='', source_feedback_version=0))
        body = {'request_id': 'confirm-1', 'project_id': 'P1', 'id': 'exp-1', 'version': 1, 'state': 'confirmed', 'reason': 'Reviewed evidence'}
        for actor in ('writer', 'bot', 'observer'):
            with self.assertRaises(ClientError): apply(state, 'experience-state', body, actor=actor)
        state['tasks']['T1']['version'] = 2
        with self.assertRaises(ClientError): apply(state, 'experience-state', body, actor='manager')
        apply(state, 'experience-save', experience(version=1, source_task_version=2, source_feedback='', source_feedback_version=0))
        body['version'] = 2; apply(state, 'experience-state', body, actor='manager')
        self.assertEqual(state['round']['experience:exp-1']['state'], 'confirmed')
        with self.assertRaises(ClientError): apply(state, 'experience-save', experience(version=3, source_task_version=2, source_feedback='', source_feedback_version=0))
        apply(state, 'experience-state', {**body, 'version': 3, 'state': 'retired'}, actor='manager')
        self.assertEqual(state['round']['experience:exp-1']['state'], 'retired')

    def test_sources_immutable_and_history_retained(self):
        state = fixture(); apply(state, 'experience-save', experience())
        with self.assertRaises(ClientError): apply(state, 'experience-save', experience(version=1, source_feedback='', source_feedback_version=0))
        apply(state, 'experience-save', experience(version=1, method='Changed method'))
        entry = view(state, 'writer')['experiences'][0]
        self.assertEqual(entry['history'][0]['method'], 'Hidden procedure')
        entry['history'].clear(); self.assertEqual(len(state['round']['experience:exp-1']['history']), 1)

    def test_delegation_is_not_authority(self):
        state = fixture(); p = {'op': 'task-message', **payload(state, 'writer', 'task-message', message(), 'abc')}
        p['_audit'] = {'actor': 'writer', 'delegation_id': 'd-x', 'delegator': 'manager', 'delegation_version': 1}
        with self.assertRaises(Rejected): action(state, p, 'writer', 1, 'event')

    def test_search_scope_roundtrip_uses_real_query_parser(self):
        from pool.httpd import parse_query
        class SearchForm(HTMLParser):
            def __init__(self):
                super().__init__(); self.search = False; self.inputs = []
            def handle_starttag(self, tag, pairs):
                attrs = dict(pairs)
                if tag == 'form':
                    self.search = attrs.get('method') == 'get'
                if tag == 'input' and self.search:
                    self.inputs.append(attrs)
            def handle_endtag(self, tag):
                if tag == 'form':
                    self.search = False
        for project, task_id in ((None, None), ('P1', None), ('P1', 'T1')):
            data = view(fixture(), 'writer', project, task_id)
            form = SearchForm(); form.feed(render('writer', data, 1 if task_id else None))
            values = {row['name']: row.get('value', '') for row in form.inputs}
            self.assertEqual({k: v for k, v in values.items() if k != 'q'},
                             {k: v for k, v in {'project': project, 'task_id': task_id}.items() if v})
            self.assertIn('required', next(row for row in form.inputs if row['name'] == 'q'))
            values['q'] = '证据 & 条件'
            self.assertEqual(parse_query(urlencode(values), {'project', 'task_id', 'q'}), values)
            from pool.task_communication_pages import url
            self.assertEqual(parse_query(url(project, task_id).partition('?')[2], {'project', 'task_id', 'q'}),
                             {k: v for k, v in values.items() if k != 'q'})

    def test_activity_and_audit_recheck_restricted_source(self):
        from pool.upgrade import collaboration_event_visible, activity_rows, audit_rows
        state = fixture(); state['tasks']['T1']['title'] = 'Task one'
        apply(state, 'experience-save', experience())
        row = deepcopy(state['round']['experience:exp-1'])
        request = {'actor': 'writer', 'task_id': 'T1', 'project_id': 'P1', 'request_id': 'exp-request',
                   'operation': 'experience-save', 'reason': None}
        entry = {'type': 'decision', 'result': 'applied', 'request': request, 'origin_id': 'writer',
                 'effects': [{'path': ['round', 'experience:exp-1'], 'value': row}],
                 'command': 'pilot', 'reason': '', 'ledger_seq': 1, 'sha256': 'f' * 64,
                 'key': 'decision/experience-event', 'committer': 'coordinator'}
        snap = {'state': state, 'entries': [entry]}
        service = SimpleNamespace(is_admin=lambda actor: False, visible=lambda *args: True,
                                  db=SimpleNamespace(execute=lambda *args: []))
        for actor in ('peer', 'observer', 'bot'):
            self.assertFalse(collaboration_event_visible(state, actor, entry))
            self.assertEqual(activity_rows(service, snap, actor), [])
            self.assertEqual(audit_rows(service, snap, actor, {'task': 'T1'}), [])
        service.is_admin = lambda actor: True
        self.assertEqual(activity_rows(service, snap, 'peer'), [])
        self.assertEqual(audit_rows(service, snap, 'peer', {'task': 'T1'}), [])
        service.is_admin = lambda actor: False
        self.assertTrue(collaboration_event_visible(state, 'manager', entry))
        self.assertEqual(len(activity_rows(service, snap, 'manager')), 1)
        self.assertEqual(len(audit_rows(service, snap, 'manager', {'task': 'T1'})), 1)
        state['round']['feedback:fb-1']['project_id'] = 'P2'
        self.assertFalse(collaboration_event_visible(state, 'manager', entry))
        self.assertEqual(activity_rows(service, snap, 'manager'), [])
        self.assertEqual(audit_rows(service, snap, 'manager', {'task': 'T1'}), [])
        # Broad task visibility must not revive a hidden ledger decision through the request journal fallback.
        service.db = SimpleNamespace(execute=lambda *args: [(json.dumps(request), 200,
                         json.dumps({'status': 'applied', 'request_id': 'exp-request'}))])
        self.assertEqual(audit_rows(service, snap, 'peer', {'task': 'T1'}), [])
        service.db = SimpleNamespace(execute=lambda *args: [(json.dumps(request), None, None)])
        self.assertEqual(audit_rows(service, {'state': state, 'entries': []}, 'peer', {'task': 'T1'}), [])

    def test_xss_and_source_links(self):
        state = fixture(); apply(state, 'task-message', message()); apply(state, 'experience-save', experience())
        html = render('writer', view(state, 'writer', 'P1', 'T1'), 1)
        self.assertNotIn('<script>sample</script>', html)
        self.assertIn('&lt;script&gt;', html); self.assertIn('/tasks/T1', html)
        self.assertIn('来源反馈 fb-1 v1', html); self.assertIn('不完成任务', html)


if __name__ == '__main__': unittest.main()
