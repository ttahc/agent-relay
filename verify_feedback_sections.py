"""Feedback groups and task history are presentation-only projections."""
from copy import deepcopy
from threading import RLock
from types import SimpleNamespace
from urllib.parse import urlsplit
from unittest.mock import patch
import unittest

from pool import round_projects_web as web, task_pages, workbench
from verify_v030_execution_projection_ui import view


def record(status):
    return dict(id='fb-' + status, project_id='p', author='writer', kind='issue',
                status=status, title='<script>unsafe</script>', details='original details',
                impact='impact', evidence='original evidence', observed='2026-11-10',
                updates=[dict(by='writer', status=status, reason='original reason',
                              evidence='historical evidence', lesson='saved lesson', limits='limits')],
                version=1, task_id='closed-task', linked_task='closed-task')


def fixture():
    return dict(feedback=[record(s) for s in ('triage', 'deferred', 'verified', 'resolved', 'duplicate', 'declined', 'withdrawn')],
                managed=False, managed_projects=[], decision=[], relation=[], change=[])


PROJECTS = [dict(id='p', name='Project <one>', roles=['observer']), dict(id='q', name='Two', roles=['observer'])]


class FeedbackSections(unittest.TestCase):
    def test_groups_preserve_closed_evidence_without_mutation(self):
        data = fixture(); before = deepcopy(data)
        html = web.render('reader', 'p', data, {}, PROJECTS)
        current, deferred, history = (html.split('id="feedback-' + key + '"')[1].split('</section>')[0]
                                      for key in ('current', 'deferred', 'history'))
        self.assertIn('fb-triage', current); self.assertIn('fb-deferred', deferred)
        for status in ('verified', 'resolved', 'duplicate', 'declined', 'withdrawn'):
            self.assertIn('fb-' + status, history)
            self.assertNotIn('fb-' + status, current)
        self.assertIn('original evidence', history); self.assertIn('historical evidence', history)
        self.assertIn('saved lesson', history); self.assertNotIn('<script>', html)
        self.assertEqual(data, before)

    def test_filter_keeps_project_and_project_tabs_keep_section(self):
        html = web.render('reader', 'p', fixture(), {}, PROJECTS, 'history')
        self.assertIn('section=history&amp;project=q', html)
        self.assertIn('section=current&amp;project=p', html)
        self.assertNotIn('id="feedback-current"', html)
        self.assertNotIn('id="feedback-deferred"', html)

    def test_empty_sections_are_explicit(self):
        data = fixture(); data['feedback'] = []
        html = web.render('reader', None, data, {}, PROJECTS)
        for text in ('暂无需要处理的反馈', '暂无延期反馈', '暂无已关闭的历史反馈'):
            self.assertIn(text, html)

    def test_dispatch_preserves_section_in_post_forms_and_redirect(self):
        service = SimpleNamespace(read=lambda actor, kind, *args: {'projects': PROJECTS} if kind == 'projects'
                                  else {'tasks': []} if kind == 'overview' else fixture())
        handler = SimpleNamespace(server=SimpleNamespace(service=service))
        with patch.object(web.round_web, 'work_page', side_effect=lambda title, html, actor: html):
            html = web.dispatch(handler, 'GET', urlsplit('/collaboration?project=p&section=history'), 'writer')
        self.assertIn('action="/collaboration?section=history&amp;project=p"', html)
        service.lock = RLock()
        service.submit = lambda *args: (200, {})
        body = dict(operation='feedback-update', project_id='p', request_id='test')
        with patch('pool.web.parse_form', return_value=body), patch('pool.web.redirect', side_effect=lambda url: url):
            result = web.dispatch(handler, 'POST', urlsplit('/collaboration?project=p&section=history'), 'writer')
        self.assertEqual(result, '/collaboration?section=history&project=p')

    def test_closed_task_unresolved_items_stay_history(self):
        data = view('completed', {})
        data['items'] = [dict(criterion='check', description='<old repair>', status='unresolved', holder='T01')]
        before = deepcopy(data)
        html = task_pages.rework_sections(data)
        self.assertNotIn('data-rework="current"', html)
        self.assertIn('data-rework="history"', html)
        self.assertIn('历史未结项（非当前操作）', html)
        self.assertIn('&lt;old repair&gt;', html)
        self.assertEqual(data, before)
        with patch.object(workbench, 'manage_box', return_value=''):
            html = workbench.sheet('reader', data, '', [])
        self.assertIn('当前没有可办操作', html)
        self.assertNotIn('data-rework="current"', html)

    def test_task_collaboration_links_preserve_context(self):
        data = view('completed', {})
        data['round'] = True
        data['task']['contract'] = {'project_id': 'p&one'}
        html = task_pages.collaboration_links(data)
        self.assertIn('/communication?task_id=T01&amp;project=p%26one', html)
        self.assertIn('/post-completion?task_id=T01', html)
        data['stage'] = 'running'
        self.assertNotIn('/post-completion', task_pages.collaboration_links(data))
        self.assertIn('/communication', task_pages.collaboration_links(data))
        data['round'] = False
        self.assertEqual(task_pages.collaboration_links(data), '')

    def test_feedback_search_filters_after_visibility_and_preserves_history(self):
        from pool.round_projects import view as feedback_view
        from verify_feedback_move import fixture as search_fixture
        from pool.packages import ClientError
        state = search_fixture()
        item = state['round']['feedback:fb-1']
        item['updates'] = [{'reason': 'Unique repair reason', 'lesson': 'Reusable needle', 'evidence': 'proof'}]
        item['status'] = 'verified'
        for query in ('evidence title', 'original evidence', 'REUSABLE NEEDLE', 'unique repair'):
            self.assertEqual(len(feedback_view(state, 'writer', 'source', query)['feedback']), 1)
        state['pilot']['identity:outsider'] = {'kind': 'human', 'owner': 'outsider', 'status': 'active', 'admin': False}
        state['pilot']['grant:source:outsider'] = {'roles': ['observer'], 'resources': [], 'version': 1}
        self.assertEqual(feedback_view(state, 'outsider', 'source', 'Reusable needle')['feedback'], [])
        self.assertEqual(feedback_view(state, 'writer', 'target', 'Reusable needle')['feedback'], [])
        self.assertEqual(feedback_view(state, 'writer', 'source', 'absent')['feedback'], [])
        with self.assertRaises(ClientError):
            feedback_view(state, 'writer', 'source', 'x' * 201)

    def test_search_tabs_preserve_query_and_clear_link_removes_it(self):
        html = web.render('reader', 'p', fixture(), {}, PROJECTS, 'history', 'evidence <one>')
        self.assertIn('section=history&amp;project=q&amp;q=evidence+%3Cone%3E', html)
        self.assertIn('section=current&amp;project=p&amp;q=evidence+%3Cone%3E', html)
        self.assertIn('value="evidence &lt;one&gt;"', html)
        self.assertIn('href="/collaboration?section=history&amp;project=p">清除搜索', html)
        html = web.render('reader', None, fixture(), {}, PROJECTS)
        self.assertNotIn('name="project" value=""', html)

    def test_resolved_or_transferred_repair_is_historical(self):
        data = view('revision', {})
        data['items'] = [dict(criterion='', description=status, status=status, holder=holder)
                         for status, holder in [('unresolved', 'T01'), ('resolved', 'T01'), ('unresolved', 'other')]]
        html = task_pages.rework_sections(data)
        self.assertIn('data-rework="current"', html)
        self.assertIn('data-rework="history"', html)
        self.assertEqual(html.count('历史未结项（非当前操作）'), 1)


if __name__ == '__main__':
    unittest.main()
