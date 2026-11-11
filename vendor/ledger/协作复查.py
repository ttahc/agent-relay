"""Post-completion issues and fresh repair tasks, without reviving historical work."""
from copy import deepcopy

import 协作升级 as rules
from 协作命令 import add_proposal, new_task
from 协作取证 import accepted_bundle
from 协作存储 import Rejected

OPS = {'task-issue-open', 'task-issue-review', 'task-repair-open'}
TERMINAL = {'completed', 'closed_missing'}
STATES = {'open', 'evidence', 'repair-required', 'repairing', 'resolved', 'declined'}


def require(value, message):
    rules.require(value, message, 'intent-final')


def text(value, limit):
    return isinstance(value, str) and 0 < len(value.strip()) <= limit


def source(state, task):
    require(task and task.get('status') in TERMINAL, '仅已完成或缺证收口的任务可申请复查')
    _, accepted, revision, manifest = accepted_bundle(state, task['task_id'])
    closing = state.get('closings', {}).get(task.get('close_id'))
    require(closing and closing.get('acceptance_id') == task.get('accepted') and
            closing.get('accepted_manifest') == manifest, '原收口与交付绑定不完整')
    return {'task_id': task['task_id'], 'scope_version': task['scope_version'],
            'close_id': task['close_id'], 'acceptance_id': task['accepted'],
            'claim_id': accepted['claim_id'], 'revision': accepted['revision'],
            'manifest': deepcopy(manifest)}


def visible(state, row, actor):
    task = state.get('tasks', {}).get(row.get('task_id'))
    project = row.get('project_id')
    return bool(task and rules.active(state, actor) and rules.visible(state, task, actor) and
                (row.get('visibility') != 'restricted' or row.get('author') == actor or
                 rules.manager(state, project, actor) or rules.system_admin(state, actor)))


def may_review(state, task, actor):
    project = rules.task_project(task)
    return bool(rules.active(state, actor) and
                (rules.manager(state, project, actor) or
                 actor == task.get('receiver') and 'receiver' in rules.roles(state, project, actor)))


def action(state, p, actor, now, event_id, seq, context=None):
    context = context or {}
    task = state.get('tasks', {}).get(p.get('task_id'))
    project = rules.task_project(task)
    require(task and project == p.get('project_id') and rules.active(state, actor) and
            rules.visible(state, task, actor), '任务不存在或无权办理')
    require(type(p.get('task_version')) is int and task['version'] == p['task_version'], '原任务版本已变化')
    frozen = source(state, task)
    require(p.get('source') == frozen, '须核对原收口、接受记录及具体修订')
    data = state['round']
    op = p['op']
    require(isinstance(p.get('id'), str) and rules.ID.fullmatch(p['id']), '问题编号无效')
    key = 'task-issue:' + p['id']
    if op == 'task-issue-open':
        require(rules.roles(state, project, actor) - {'observer'}, '观察者只能查看复查问题')
        require(key not in data and text(p.get('title'), 200) and text(p.get('details'), 4000) and
                text(p.get('evidence'), 4000), '问题需要标题、现象和证据或明确待补内容')
        require(isinstance(p.get('visibility'), str) and p['visibility'] in {'project', 'restricted'}, '问题可见范围无效')
        row = {k: deepcopy(p[k]) for k in ('id', 'project_id', 'task_id', 'source', 'title', 'details', 'evidence', 'visibility')}
        row.update(author=actor, at=now, event=event_id, version=1, status='open', reviews=[])
        data[key] = row
    else:
        row = data.get(key)
        require(row and visible(state, row, actor) and row['task_id'] == task['task_id'] and
                row['source'] == frozen and type(p.get('version')) is int and row['version'] == p['version'],
                '问题不存在、不可见或版本已变化')
        require(may_review(state, task, actor), '复查须由当前项目管理员或指定接收者办理')
        require(text(p.get('reason'), 4000), '须记录本次处理依据')
        if op == 'task-issue-review':
            verdict = p.get('verdict')
            require(isinstance(verdict, str) and verdict in {'evidence', 'repair-required', 'resolved', 'declined'}, '复查结论无效')
            require(row['status'] not in {'resolved', 'declined'} or verdict == 'evidence', '关闭问题须先以新增证据重新申请复查')
            require(text(p.get('evidence'), 4000), '复查须有证据或明确待补内容')
            checked = row.get('repair_task') if verdict == 'resolved' and row.get('repair_task') else task['task_id']
            target = state['tasks'].get(checked)
            checked_source = source(state, target) if verdict == 'resolved' else None
            require(p.get('checked_source') == checked_source, '须明确本次复核的原交付或已完成返修交付')
            if verdict == 'resolved':
                require(checked_source['manifest']['sha256'] in context.get('verified_manifests', set()),
                        '解决问题须重新核对所指交付及负载')
            review = {k: deepcopy(p[k]) for k in ('verdict', 'reason', 'evidence', 'checked_source')}
            authors = {state['claims'][cid]['origin'] for cid in target.get('claims', [])} if target else set()
            review.update(by=actor, at=now, event=event_id, independent=actor not in authors,
                          kind='post-completion-recheck')
            row['reviews'].append(review)
            row.update(status=verdict, version=row['version'] + 1)
        elif op == 'task-repair-open':
            require(rules.manager(state, project, actor), '新返修任务须由项目管理员登记')
            require(row['visibility'] == 'project', '受限问题不能直接转为项目可见返修；请先提供可公开的独立问题')
            prior_repair = state['tasks'].get(row.get('repair_task'))
            require(row['status'] == 'repair-required' and (not prior_repair or prior_repair['status'] in TERMINAL),
                    '须先确认需要修改并结束上一返修；同一回合不能重复建立任务')
            # All authorizations and task contract checks happen before any mutation.
            payload = deepcopy(p['repair'])
            require(payload.get('receiver') in state['origins'] and
                    rules.active(state, payload['receiver']) and
                    'receiver' in rules.roles(state, project, payload['receiver']), '须指定当前获授权接收者')
            require(payload.get('kind') == 'repair' and payload.get('resources') == task['resources'] and
                    payload.get('execution') == task['execution'] and
                    payload.get('requires_commit') == task['requires_commit'] and
                    payload.get('required_paths') == task.get('required_paths', []) and
                    payload.get('dependencies') == [] and payload.get('parent') == task.get('parent'),
                    '返修继承资源和执行边界，不复用原依赖或领取')
            brief = payload.get('primary_brief')
            baseline = p.get('baseline')
            require(type(p.get('include_original_delivery')) is bool and isinstance(baseline, dict), '须明确原交付分享选择')
            expected_baseline = source(state, prior_repair) if prior_repair else frozen
            require(p.get('baseline_source') == (expected_baseline if p['include_original_delivery'] else None),
                    '返修基线须明确绑定最近完成返修；首轮绑定原已接受交付')
            require(not baseline if not p['include_original_delivery'] else
                    baseline == context.get('repair_baseline') and bool(baseline), '原交付基线须重验并明确授权分享')
            require(isinstance(brief, dict) and set(brief) == {'path', 'sha256'} and
                    isinstance(brief['path'], str) and brief['path'].startswith('inputs/') and brief['path'].endswith('/repair.md') and
                    isinstance(brief['sha256'], str) and rules.SHA.fullmatch(brief['sha256']), '返修主说明引用无效')
            require(payload.get('inputs') == {**task['inputs'], **baseline, brief['path']: brief['sha256']},
                    '返修只能纳入原输入、新说明及明确分享的原交付')
            spec = rules.task_spec(state, payload.get('contract'))
            require(spec['project_id'] == project and text(p.get('title'), 200), '返修须在原项目')
            if spec['review_mode'] == 'user':
                require(rules.identity(state, payload['receiver']).get('kind') == 'human', '人工确认须指定人员')
            # new_task is atomic within the ledger candidate; failures are discarded by its caller.
            add_proposal(state, event_id, actor, {'title': p['title'], 'related': task['task_id']}, task['authorities'])
            new_task(state, state['proposals'][event_id], payload, seq,
                     {'task': task['task_id'], 'issue': row['id'], 'correction': event_id})
            repair_id = state['proposals'][event_id]['task_id']
            state['tasks'][repair_id]['primary_brief'] = deepcopy(brief)
            state['corrections'][event_id] = {'target': task['close_id'], 'task_id': task['task_id'],
                'verdict': 'revision', 'reason': p['reason'], 'erratum': False, 'issue_id': row['id'],
                'repair_task': repair_id, 'by': actor, 'source': frozen}
            if prior_repair:
                row.setdefault('repair_history', []).append({'task_id': prior_repair['task_id'],
                    'source': source(state, prior_repair), 'replaced_by': repair_id, 'event': event_id})
            row.update(status='repairing', repair_task=repair_id, correction_id=event_id, version=row['version'] + 1)
            row['reviews'].append({'verdict': 'repairing', 'reason': p['reason'], 'by': actor, 'at': now,
                                   'event': event_id, 'repair_task': repair_id,
                                   'included_original_delivery': p['include_original_delivery'],
                                   'baseline_source': deepcopy(p.get('baseline_source'))})
        else:
            raise Rejected('未知复查操作')
    fmt = state['pilot']['format']
    fmt['min_reader'] = max(fmt.get('min_reader', 1), 7)
