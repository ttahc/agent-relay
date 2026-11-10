"""Source scopes for request receipts and broad metadata projections."""
from copy import deepcopy
from 协作沟通 import ACTIONS as COMMUNICATION, record_visible
from 协作复查 import OPS as RECHECK, visible as issue_visible

ACTIONS = COMMUNICATION | RECHECK


def request_scope(state, actor, action, body, plan=None):
    if action not in ACTIONS:
        return None
    from 协作升级 import ID
    for name in ('id', 'task_id', 'project_id', 'source_task', 'source_feedback'):
        value = body.get(name)
        if value is not None and (not isinstance(value, str) or value and not ID.fullmatch(value)):
            return {'invalid': True, 'author': actor}
    if 'visibility' in body and (not isinstance(body['visibility'], str) or body['visibility'] not in {'project', 'restricted'}):
        return {'invalid': True, 'author': actor}
    plan = plan or {}
    record_id = body.get('id') or plan.get('round_result', {}).get('issue_id') or plan.get('round_result', {}).get('record_id')
    if action in RECHECK:
        namespace = 'task-issue:'
        fallback = {'task_id': body.get('task_id'), 'project_id': None,
                    'visibility': body.get('visibility', 'restricted'), 'author': actor}
        from 协作升级 import task_project
        fallback['project_id'] = task_project(state.get('tasks', {}).get(body.get('task_id')))
    elif action.startswith('experience-'):
        namespace = 'experience:'
        fallback = {k: body.get(k) for k in ('project_id','source_task','source_feedback')}
    else:
        namespace = 'message:'
        fallback = {k: body.get(k) for k in ('project_id','task_id')}
    key = namespace + str(record_id or '')
    old = state.get('round', {}).get(key)
    selected = old or fallback
    keys = ('project_id','task_id','source_task','source_feedback','visibility','author')
    return {'key': key, 'record': deepcopy({k: selected[k] for k in keys if k in selected})}


def request_visible(state, actor, request):
    if request.get('operation') not in ACTIONS:
        return True
    scope = request.get('collaboration_scope')
    if not isinstance(scope, dict):
        # Old or incomplete metadata has no safe source-specific disclosure basis.
        return False
    if scope.get('invalid'):
        from 协作升级 import active
        return scope.get('author') == actor and active(state, actor)
    key = scope.get('key', '')
    row = state.get('round', {}).get(key) or scope.get('record', {})
    if key.startswith('task-issue:'):
        return issue_visible(state, row, actor)
    return record_visible(state, row, actor)
