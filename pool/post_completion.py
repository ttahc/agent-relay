"""Transport and projections for completed-task rechecks and linked repairs."""
import base64
from copy import deepcopy
import time

from .constants import COORDINATOR, step
from .packages import ClientError, fields, string
from .upgrade import identifier, version
from 协作存储 import digest, encoded, Rejected
from 协作复查 import OPS as ACTIONS, action as apply, may_review, source, visible
import 协作升级 as rules


def plan(service, actor, action, key, body, state):
    if action not in ACTIONS:
        return None
    if state['pilot'].get('format', {}).get('schema', 0) < 3:
        raise ClientError('须先迁移本轮数据合同', 409)
    task_id = identifier(body.get('task_id'), '任务编号')
    task = state['tasks'].get(task_id)
    if not task or not rules.visible(state, task, actor):
        raise ClientError('任务不存在或无权办理', 404)
    p = {'op': action, 'task_id': task_id, 'project_id': rules.task_project(task),
         'task_version': version(body.get('task_version'))}
    file = None
    try:
        p['source'] = source(state, task)
        if action == 'task-issue-open':
            fields(body, 'request_id task_id task_version title details evidence visibility')
            p.update(id='issue-' + key[:24], title=string(body['title'], '问题标题', 200),
                     details=string(body['details'], '问题说明', 4000), evidence=string(body['evidence'], '证据', 4000),
                     visibility=body['visibility'])
        else:
            p.update(id=identifier(body.get('id'), '问题编号'), version=version(body.get('version')),
                     reason=string(body.get('reason'), '处理依据', 4000))
            issue = state.get('round', {}).get('task-issue:' + p['id'])
            if not issue or not visible(state, issue, actor):
                raise ClientError('问题不存在或无权办理', 404)
            if action == 'task-issue-review':
                fields(body, 'request_id task_id task_version id version verdict reason evidence')
                p.update(verdict=body['verdict'], evidence=string(body['evidence'], '复核证据', 4000), checked_source=None)
                if p['verdict'] == 'resolved':
                    checked = state['tasks'].get(issue.get('repair_task') or task_id)
                    p['checked_source'] = source(state, checked)
            else:
                fields(body, 'request_id task_id task_version id version reason title brief criteria receiver completion_policy' + (' include_original_delivery' if 'include_original_delivery' in body else ''))
                criteria = body['criteria']
                if not isinstance(criteria, list) or not 1 <= len(criteria) <= 30 or any(not isinstance(x, str) for x in criteria) or len(set(criteria)) != len(criteria):
                    raise ClientError('须填写 1 至 30 条不重复完成判据')
                criteria = [string(x, '完成判据', 100) for x in criteria]
                raw = string(body['brief'], '返修说明', 40000).encode('utf-8')
                path = 'inputs/' + digest(raw) + '/repair.md'
                spec = {k: deepcopy(task['contract'][k]) for k in
                        ('project_id', 'iteration', 'delivery', 'requirements', 'review_mode', 'user_basis')}
                spec['iteration'] = {'goal': body['title'], 'previous': [task_id], 'next': []}
                spec['completion_policy'] = body['completion_policy']
                # Fresh open dispatch, explicit notification only; old invitations/targets never become a new grant.
                from 协作本轮 import DEFAULT_POLICY
                spec['dispatch'] = {**deepcopy(DEFAULT_POLICY), 'owner': rules.responsible(state, actor) or ''}
                include = body.get('include_original_delivery', False)
                if type(include) is not bool:
                    raise ClientError('须明确是否将原交付分享为项目可见返修输入')
                baseline = {}
                baseline_source = None
                if include:
                    prior_repair = state['tasks'].get(issue.get('repair_task'))
                    baseline_source = source(state, prior_repair) if prior_repair else p['source']
                    ref = baseline_source['manifest']
                    baseline = {r['path']: r['sha256'] for r in [ref, *service.delivery_refs(ref)]}
                p.update(include_original_delivery=include, baseline=baseline, baseline_source=baseline_source, title=string(body['title'], '返修标题', 200), repair={
                    'kind': 'repair', 'receiver': identifier(body['receiver'], '接收者'), 'completes_on': criteria,
                    'contract': spec, 'inputs': {**task['inputs'], **baseline, path: digest(raw)},
                    'primary_brief': {'path': path, 'sha256': digest(raw)},
                    'execution': deepcopy(task['execution']), 'resources': deepcopy(task['resources']),
                    'requires_commit': task['requires_commit'], 'required_paths': task.get('required_paths', []),
                    'dependencies': [], 'parent': task.get('parent')})
                file = path, base64.b64encode(raw).decode('ascii')
        validation = {'verified_manifests': {p['checked_source']['manifest']['sha256']}} if p.get('checked_source') else {}
        if action == 'task-repair-open':
            validation['repair_baseline'] = p['baseline']
        apply(deepcopy(state), p, actor, time.time(), 'validation-' + key, 1, validation)
    except Rejected as error:
        raise ClientError(str(error), 409) from error
    instruction = step(COORDINATOR, 'pilot', p, {'generation': state['generation']})
    if file:
        instruction['file'] = file
    return {'task_id': task_id, 'round_result': {'issue_id': p['id']}, 'steps': [instruction]}


def view(state, actor, task_id):
    task = state['tasks'].get(task_id)
    if not task or not rules.visible(state, task, actor):
        raise ClientError('任务不存在或无权查看', 404)
    rows = [deepcopy(row) for key, row in state.get('round', {}).items()
            if key.startswith('task-issue:') and row['task_id'] == task_id and visible(state, row, actor)]
    related = [deepcopy(row) for key, row in state.get('round', {}).items()
               if key.startswith('task-issue:') and row.get('repair_task') == task_id and visible(state, row, actor)]
    for row in rows:
        previous = state['tasks'].get(row.get('repair_task'))
        row['can_start_repair'] = not previous or previous['status'] in {'completed', 'closed_missing'}
    return {'task_id': task_id, 'issues': rows, 'repair_of': related,
            'can_review': may_review(state, task, actor),
            'can_repair': rules.manager(state, rules.task_project(task), actor)}

