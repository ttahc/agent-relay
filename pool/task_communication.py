"""Request planning and privacy-preserving task discussion / experience search."""
from copy import deepcopy
from .packages import ClientError, fields
from .constants import COORDINATOR, step
from .privacy import public
from 协作存储 import Rejected
from 协作沟通 import ACTIONS, FIELDS, curator, direct_roles, record_visible, validate


def payload(state, actor, action, body, key):
    if action not in ACTIONS:
        raise ClientError('未知沟通操作')
    expected = set(FIELDS[action].split())
    if action == 'task-message':
        expected.remove('id')
    fields(body, ' '.join(sorted(expected | {'request_id'})))
    out = {k: deepcopy(v) for k, v in body.items() if k != 'request_id'}
    if action == 'task-message':
        out['id'] = 'msg-' + key[:24]
    try:
        validate(state, {'op': action, **out}, actor)
    except Rejected as error:
        raise ClientError(str(error), 409) from error
    return out


def plan(service, actor, action, key, body, state):
    if action not in ACTIONS:
        return None
    from 协作本轮 import enabled
    if not enabled(state):
        raise ClientError('须先迁移本轮数据合同', 409)
    p = {'op': action, **payload(state, actor, action, body, key)}
    return {'round_result': {'record_id': p['id']},
            'steps': [step(COORDINATOR, 'pilot', p, {'generation': state['generation']})]}


def view(state, actor, project=None, task_id=None, query=''):
    if not isinstance(query, str) or len(query) > 200:
        raise ClientError('搜索词须为不超过 200 字符的文本')
    if project and not direct_roles(state, project, actor):
        raise ClientError('项目不存在或无权查看', 404)
    if task_id:
        task = state.get('tasks', {}).get(task_id)
        from 协作升级 import task_project
        if not task or not direct_roles(state, task_project(task), actor) or project and task_project(task) != project:
            raise ClientError('任务不存在或无权查看', 404)
        project = task_project(task)
    groups = {'messages': [], 'experiences': []}
    for key, item in state.get('round', {}).items():
        kind = 'messages' if key.startswith('message:') else 'experiences' if key.startswith('experience:') else None
        if not kind or project and item['project_id'] != project or not record_visible(state, item, actor):
            continue
        if task_id and (item.get('task_id') if kind == 'messages' else item.get('source_task')) != task_id:
            continue
        # Filter visibility BEFORE matching. Counts, excerpts and historical versions cannot leak sources.
        if query and query.casefold() not in ' '.join(str(item.get(k, '')) for k in
                ('title', 'conditions', 'method', 'evidence', 'limits', 'content')).casefold():
            continue
        groups[kind].append(public(deepcopy(item)))
    for rows in groups.values():
        rows.sort(key=lambda item: (item.get('at', 0), item['id']), reverse=True)
    return {'project': project, 'task_id': task_id, 'query': query,
            'managed': bool(project and curator(state, project, actor)),
            'can_write': bool(project and direct_roles(state, project, actor) - {'observer'}), **groups}
