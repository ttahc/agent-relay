"""Direct completion forms preserve evidence, actor, scope and policy distinctions."""
import json
import unittest
from unittest.mock import patch
from pool import task_pages as pages, workbench, web
from verify_v030_execution_projection_ui import view


def direct_view():
    data = view('review', {})
    data['round'] = True
    data['task']['contract'] = {'completion_policy': 'executor-direct'}
    data['active']['W'].update(state='review', revision='revision-1')
    data['active']['E'] = {'state': 'stopped', 'reason': 'complete'}
    data['deliveries'] = [{'claim_id': 'c1', 'revision': {'revision': 'revision-1', 'status': 'review',
                           'manifest_sha256': 'a' * 64, 'criteria': ['done']},
                           'outputs': [{'path': 'result.txt', 'sha256': 'b' * 64}], 'review': None}]
    return data


class DirectCompletionUI(unittest.TestCase):
    def test_direct_holder_has_completion_with_scope_and_evidence(self):
        data = direct_view()
        html = pages.executor_completion('worker', data)
        for value in ('/actions/executor-complete', 'name="epoch"', 'name="scope_version"',
                      'name="manifest_sha256"', 'name="criterion-0"', 'name="artifact-0"', 'name="note-0"',
                      'name="finish"', '未做独立审查'):
            self.assertIn(value, html)
        self.assertNotIn('/actions/review', html)
        self.assertEqual(pages.executor_completion('someone', data), '')
        data['task']['contract'] = {}
        self.assertEqual(pages.executor_completion('worker', data), '')

    def test_same_receiver_can_claim_direct_but_not_default(self):
        data = direct_view(); data['task'].update(status='available', receiver='worker')
        self.assertIn('/actions/claim', workbench.worker_box('worker', data))
        task = {**data['task'], 'qualification': {'eligible': True}}
        self.assertEqual(workbench.claim_block(task, 'worker'), '')
        data['task']['contract'] = {}
        self.assertNotIn('/actions/claim', workbench.worker_box('worker', data))

    def test_receiver_holder_does_not_self_review(self):
        data = direct_view(); data['task']['receiver'] = 'worker'
        self.assertEqual(workbench.receiver_box('worker', data), '')
        self.assertNotIn('/actions/review', pages.receiver_actions('worker', data['task'], data['active'], data['deliveries'], False))

    def test_direct_close_requires_authorized_projection(self):
        data = direct_view(); data['task']['status'] = 'pending_close'
        data['task']['accepted'] = 'a1'
        self.assertEqual(pages.executor_completion('worker', data), '')
        data['direct_close_allowed'] = True
        self.assertIn('/actions/close', pages.executor_completion('worker', data))

    def test_web_parses_completion_evidence_without_losing_scope(self):
        data = dict(request_id='r', claim_id='c', epoch='2', scope_version='3', revision='revision-1',
                    manifest_sha256='a' * 64, check_count='1', finish='1')
        data.update({'criterion-0': 'done', 'artifact-0': json.dumps({'path': 'result.txt', 'sha256': 'b'*64}),
                     'note-0': 'checked'})
        with patch('pool.web.parse_form', return_value=data):
            body = web.action_body(None, 'executor-complete')
        self.assertEqual((body['epoch'], body['scope_version'], body['finish']), (2, 3, True))
        self.assertEqual(body['checks'][0]['note'], 'checked')
        self.assertNotIn('check_count', body)

    def test_direct_todo_targets_holder_and_avoids_false_review(self):
        task = {**direct_view()['task'], 'stage': 'review', 'holder': 'worker'}
        self.assertEqual(workbench.column_title(task), '待执行者确认完成')
        self.assertIn('确认完成', workbench.todo_reason(task, 'worker', {}))
        self.assertEqual(workbench.todo_reason(task, 'reviewer', {}), '')
        task.update(stage='accepted', completion_kind='executor-direct')
        self.assertIn('未做独立审查', workbench.todo_reason(task, 'worker', {}))
        self.assertNotIn('已验收', workbench.todo_reason(task, 'worker', {}))
        task['completion_kind'] = 'review'
        self.assertIn('已验收', workbench.todo_reason(task, 'worker', {}))
        task.update(stage='pending_close', direct_close_allowed=True)
        self.assertIn('归档', workbench.todo_reason(task, 'worker', {}))

    def test_legacy_todo_and_compact_policy_remain_correct(self):
        task = {**direct_view()['task'], 'contract': {}, 'stage': 'review', 'holder': 'worker'}
        self.assertEqual(workbench.column_title(task), '待验收')
        self.assertIn('验收结论', workbench.todo_reason(task, 'reviewer', {}))
        task['completion_policy'] = 'executor-direct'
        self.assertEqual(workbench.column_title(task), '待执行者确认完成')

    def test_completion_notice_distinguishes_policy_from_record(self):
        data = direct_view()
        self.assertIn('独立验收可选', pages.completion_notice(data))
        data['deliveries'][0]['review'] = {'completion_kind': 'executor-direct', 'independent': False}
        self.assertIn('执行者完成，未做独立审查', pages.completion_notice(data))


if __name__ == '__main__': unittest.main()
