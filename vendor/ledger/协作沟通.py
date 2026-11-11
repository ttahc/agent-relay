"""Task discussion and optional, source-bound experience. Never execution authority."""
from copy import deepcopy
from 协作升级 import ID, active, grant, identity, project_record, require, task_project

ACTIONS = {'task-message', 'task-message-status', 'experience-save', 'experience-state'}
KINDS = {'question', 'note', 'blocker', 'conclusion', 'request-review'}
STATUSES = {'received', 'replied', 'executed', 'completed'}
STATES = {'candidate', 'confirmed', 'retired'}
FIELDS = {
    'task-message': 'project_id task_id task_version id kind recipient reply_to content',
    'task-message-status': 'project_id id version status evidence',
    'experience-save': 'project_id id version source_task source_task_version source_feedback source_feedback_version title conditions method evidence limits',
    'experience-state': 'project_id id version state reason',
}


def direct_roles(state, project, actor):
    """Do not inherit an operation-context delegation, even for read/search."""
    subject = identity(state, actor) or {}
    if not active(state, actor) or not project_record(state, project):
        return set()
    own = set(grant(state, project, actor)['roles'])
    if subject.get('kind') == 'human':
        return own
    if subject.get('kind') == 'executor' and active(state, subject.get('owner')):
        parent = set(grant(state, project, subject['owner'])['roles'])
        return own if 'manager' in parent else own & parent
    return set()


def curator(state, project, actor):
    return (identity(state, actor) or {}).get('kind') == 'human' and 'manager' in direct_roles(state, project, actor)


def task_visible(state, project, tid, actor):
    task = state.get('tasks', {}).get(tid)
    return bool(task and task_project(task) == project and direct_roles(state, project, actor))


def feedback_visible(state, project, fid, actor):
    item = state.get('round', {}).get('feedback:' + fid)
    return bool(item and item['project_id'] == project and direct_roles(state, project, actor) and
                (item['visibility'] != 'restricted' or item['author'] == actor or curator(state, project, actor)))


def source_visible(state, item, actor):
    project = item['project_id']
    return bool(direct_roles(state, project, actor) and
                (not item.get('source_task') or task_visible(state, project, item['source_task'], actor)) and
                (not item.get('source_feedback') or feedback_visible(state, project, item['source_feedback'], actor)))


def record_visible(state, item, actor):
    if 'source_task' in item:
        return source_visible(state, item, actor)
    return task_visible(state, item['project_id'], item['task_id'], actor)


def text(value, limit=4000, optional=False):
    return isinstance(value, str) and len(value) <= limit and (optional and value == '' or bool(value.strip()))


def identifier(value, optional=False):
    return isinstance(value, str) and (optional and value == '' or bool(ID.fullmatch(value)))


def version(value):
    return type(value) is int and 0 <= value <= 10**9


def validate(state, p, actor):
    """Exact replay validation, with all authorization checked at ledger commit time."""
    op = p.get('op')
    require(isinstance(op, str) and op in ACTIONS, '未知沟通操作')
    require(set(p) - {'_audit'} == set(FIELDS[op].split()) | {'op'}, '沟通字段不完整或包含未知字段')
    require(not any((p.get('_audit') or {}).get(k) for k in ('delegator', 'delegation_id', 'delegation_version')),
            '沟通和经验不接受委托权限', 'intent-final')
    project = p['project_id']
    require(identifier(project) and identifier(p['id']), '项目或记录编号无效')
    own = direct_roles(state, project, actor)
    require(bool(own - {'observer'}), '无当前项目沟通权限', 'intent-final')
    data = state['round']
    if op == 'task-message':
        require(identifier(p['task_id']) and version(p['task_version']) and
                task_visible(state, project, p['task_id'], actor), '任务不存在或无权查看', 'intent-final')
        require(state['tasks'][p['task_id']]['version'] == p['task_version'], '任务版本已变化')
        require(isinstance(p['kind'], str) and p['kind'] in KINDS and text(p['content']), '沟通类型或正文无效')
        require(identifier(p['recipient'], True) and identifier(p['reply_to'], True), '接收人或回复编号无效')
        require(not p['recipient'] or task_visible(state, project, p['task_id'], p['recipient']), '接收人无当前任务查看权限')
        parent = data.get('message:' + p['reply_to']) if p['reply_to'] else None
        require(not p['reply_to'] or parent and parent['project_id'] == project and parent['task_id'] == p['task_id'], '只能回复当前任务的沟通')
        require('message:' + p['id'] not in data, '沟通编号已使用')
    elif op == 'task-message-status':
        old = data.get('message:' + p['id'])
        require(old and old['project_id'] == project and record_visible(state, old, actor), '沟通不存在或无权查看', 'intent-final')
        require(version(p['version']) and old['version'] == p['version'], '沟通版本已变化')
        require(actor in {old['author'], old['recipient']} or curator(state, project, actor), '仅沟通参与者或项目管理员可明确标记', 'intent-final')
        require(isinstance(p['status'], str) and p['status'] in STATUSES and text(p['evidence']), '须明确选择沟通状态并填写依据')
    elif op == 'experience-save':
        require(version(p['version']) and identifier(p['source_task'], True) and identifier(p['source_feedback'], True), '经验版本或来源无效')
        require(bool(p['source_task'] or p['source_feedback']) and source_visible(state, p, actor), '须提供当前可见的来源任务或反馈', 'intent-final')
        require(version(p['source_task_version']) and version(p['source_feedback_version']), '来源版本无效')
        require((state['tasks'][p['source_task']]['version'] if p['source_task'] else 0) == p['source_task_version'], '来源任务版本已变化')
        require((data['feedback:' + p['source_feedback']]['version'] if p['source_feedback'] else 0) == p['source_feedback_version'], '来源反馈版本已变化')
        require(text(p['title'], 200) and all(text(p[k]) for k in ('conditions', 'method', 'evidence', 'limits')), '须填写适用条件、方法、证据和局限')
        old = data.get('experience:' + p['id'])
        require((old or {}).get('version', 0) == p['version'], '经验版本已变化')
        if old:
            require(old['project_id'] == project and source_visible(state, old, actor), '经验不可见', 'intent-final')
            require(old['state'] == 'candidate' and (old['author'] == actor or curator(state, project, actor)), '只能修订本人或管理范围内的候选经验', 'intent-final')
            require(all(old[k] == p[k] for k in ('source_task', 'source_feedback')), '经验来源不可更换；请新建关联来源记录')
    else:
        old = data.get('experience:' + p['id'])
        require(old and old['project_id'] == project and source_visible(state, old, actor), '经验不存在或来源不可见', 'intent-final')
        require(curator(state, project, actor), '经验确认或退役须由当前项目管理人员本人办理', 'intent-final')
        require(version(p['version']) and old['version'] == p['version'], '经验版本已变化')
        require(isinstance(p['state'], str) and p['state'] in {'confirmed', 'retired'} and
                (old['state'], p['state']) in {('candidate', 'confirmed'), ('candidate', 'retired'), ('confirmed', 'retired')}, '经验状态不允许此变更')
        require(text(p['reason']), '须填写人工确认或退役依据')
        if p['state'] == 'confirmed':
            require((state['tasks'][old['source_task']]['version'] if old['source_task'] else 0) == old['source_task_version'] and
                    (data['feedback:' + old['source_feedback']]['version'] if old['source_feedback'] else 0) == old['source_feedback_version'],
                    '经验来源已变化，请先修订候选经验并复核新版本')


def action(state, p, actor, now, event_id):
    validate(state, p, actor)
    data, op = state['round'], p['op']
    namespace = 'message:' if op.startswith('task-message') else 'experience:'
    key = namespace + p['id']
    old = data.get(key)
    audit = {'by': actor, 'at': now, 'event': event_id}
    if op in {'task-message', 'experience-save'}:
        item = {k: deepcopy(v) for k, v in p.items() if k not in {'op', '_audit'}}
        item.update(author=old['author'] if old else actor, version=(old or {}).get('version', 0) + 1, **audit)
        item['status' if op == 'task-message' else 'state'] = '' if op == 'task-message' else 'candidate'
        item['history'] = deepcopy(old.get('history', [])) + [{k: deepcopy(v) for k, v in old.items() if k != 'history'}] if old else []
        data[key] = item
    else:
        old.setdefault('history', []).append({k: deepcopy(v) for k, v in old.items() if k != 'history'})
        old.update(version=old['version'] + 1, **audit)
        if op == 'task-message-status':
            old.update(status=p['status'], status_evidence=p['evidence'])
        else:
            old.update(state=p['state'], state_reason=p['reason'])
    fmt = state['pilot']['format']
    fmt['min_reader'] = max(fmt.get('min_reader', 0), 7)
