"""Permission-scoped selectors and explicit outstanding acceptance work."""
from . import __version__, upgrade
import 协作升级 as rules


def identities(state, actor):
    admin = rules.system_admin(state, actor)
    projects = {p['id'] for p in upgrade.projects(state, actor)}
    visible = {actor}
    for key, row in state['pilot'].items():
        if key.startswith('grant:') and row['roles']:
            _, project, name = key.split(':', 2)
            if project in projects:
                visible.add(name)
    rows = []
    for key, subject in state['pilot'].items():
        if (not key.startswith('identity:') or subject.get('kind') not in {'human', 'executor'}
            or subject.get('status') != 'active'):
            continue
        name = key.partition(':')[2]
        if not (admin or name in visible or subject.get('owner') == actor):
            continue
        rows.append({'id': name, 'identity': name, 'name': subject.get('window_name') or subject.get('window') or name,
            'kind': subject['kind'], 'window_name': subject.get('window_name'), 'window': subject.get('window'),
            'owner': subject.get('owner'), 'status': subject['status']})
    return sorted(rows, key=lambda row: (row['kind'] != 'human', row['name'], row['id']))


def invitation_owners(state, actor, project):
    from 协作本轮 import invite_allowed
    if not project or not rules.project_record(state, project):
        return []
    return [row for row in identities(state, actor) if row['kind'] == 'human' and (
        invite_allowed(state, actor, project, row['id'], {'executor'}) or
        invite_allowed(state, actor, project, row['id'], {'receiver'}))]


def readiness(state, actor):
    from .round_projects import view
    from .task_state import stage, active_claim
    visible = [t for t in state['tasks'].values() if rules.visible(state, t, actor)]
    waiting = [{'id': t['task_id'], 'title': t['title'], 'status': stage(t, active_claim(state, t), state)}
               for t in visible
             if t['title'].startswith(('AI 接入修复', 'v0.')) and t['status'] not in {'completed', 'cancelled'}]
    feedback = view(state, actor)['feedback']
    pending = [{'id': f['id'], 'title': f['title'], 'status': f['status'], 'task': f.get('linked_task')}
             for f in feedback if f['status'] in {'accepted', 'working', 'review', 'evidence'}]
    return {'application_version': __version__, 'follow_up_tasks': waiting, 'pending_feedback': pending,
            'notice': '实现、隔离检查、原窗口实测与独立验收分别记录；待复验事项不会自动标为通过。'}
