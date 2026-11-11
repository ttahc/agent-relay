"""Small standalone task communication and optional experience workspace."""
from html import escape
from urllib.parse import urlencode, quote
from . import round_web, task_pages as pages, upgrade_pages as ui
from .packages import ClientError, strict_json
from .task_communication import ACTIONS, view

KINDS = {'question': '提问', 'note': '说明', 'blocker': '阻塞', 'conclusion': '结论', 'request-review': '请求复查'}
STATUSES = {'received': '已收到', 'replied': '已回复', 'executed': '已执行（沟通事项）', 'completed': '已办结（沟通事项）'}
STATES = {'candidate': '候选', 'confirmed': '人工确认', 'retired': '已退役'}
NOTICE = '沟通标记只记录沟通事项，不完成任务、不代表验收，也不授予执行权限。经验沉淀自愿选择，引用前仍须核对适用条件和当前授权。'


def url(project=None, task_id=None):
    return '/communication?' + urlencode({k: v for k, v in {'project': project, 'task_id': task_id}.items() if v})


def operation(action, values, controls, label):
    fields = ''.join(pages.hidden(k, v) for k, v in {'operation': action, **values}.items())
    return round_web.password_form(escape(url(values.get('project_id'), values.get('task_id')), quote=True), fields + controls, label)


def sources(item):
    links = []
    if item.get('source_task'):
        tid = item['source_task']
        links.append(f'<a href="/tasks/{quote(tid, safe="")}">来源任务 {escape(tid)} v{item["source_task_version"]}</a>')
    if item.get('source_feedback'):
        href = '/collaboration?' + urlencode({'project': item['project_id']})
        links.append(f'<a href="{escape(href, quote=True)}">来源反馈 {escape(item["source_feedback"])} v{item["source_feedback_version"]}</a>')
    return ' · '.join(links)


def history(item):
    rows = []
    for prior in item.get('history', []):
        label = STATUSES.get(prior.get('status'), '尚未标记') if 'status' in prior else STATES.get(prior.get('state'), '')
        details = prior.get('content') or prior.get('method') or ''
        rows.append(f'<li>v{prior["version"]} · {escape(label)} · {escape(prior.get("by", ""))}<p>{escape(details)}</p></li>')
    return '<details><summary>历史版本</summary><ul>' + ''.join(rows) + '</ul></details>' if rows else ''


def experience_form(project, task_id='', task_version=0, item=None):
    item = item or {}
    controls = ui.input_field('id', '经验编号', item.get('id', ''), size=80)
    controls += ui.input_field('source_task', '来源任务（任务或反馈至少填一项）', item.get('source_task', task_id), required=False)
    controls += ui.input_field('source_task_version', '来源任务当前版本，无来源填 0', item.get('source_task_version', task_version))
    controls += ui.input_field('source_feedback', '来源反馈（选填，保持原可见范围）', item.get('source_feedback', ''), required=False)
    controls += ui.input_field('source_feedback_version', '来源反馈当前版本，无来源填 0', item.get('source_feedback_version', 0))
    for field, label in (('title', '经验标题'), ('conditions', '适用条件'), ('method', '处理方法'), ('evidence', '可核验证据'), ('limits', '局限与失效条件')):
        controls += ui.text_field(field, label, item.get(field, ''), size=200 if field == 'title' else 4000)
    return operation('experience-save', {'project_id': project, 'version': item.get('version', 0)}, controls, '保存候选经验')


def render(actor, data, task_version=None):
    project, task_id = data.get('project'), data.get('task_id')
    scope = ''.join(pages.hidden(key, value) for key, value in {'project': project, 'task_id': task_id}.items() if value)
    search = ('<form method="get" action="/communication">' + scope +
              ui.input_field('q', '检索可见沟通和经验', data.get('query', ''), required=True) +
              '<button type="submit">检索</button></form>' +
              '<a href="' + escape(url(project, task_id), quote=True) + '">清除检索条件</a>')
    messages = []
    for item in data['messages']:
        status = STATUSES.get(item['status'], '尚未标记')
        controls = ''
        if data['can_write'] and (actor in {item['author'], item['recipient']} or data['managed']):
            controls = operation('task-message-status', {'project_id': item['project_id'], 'id': item['id'], 'version': item['version']},
                ui.selection('status', '明确标记沟通事项', list(STATUSES.items())) + ui.text_field('evidence', '标记依据'), '保存沟通标记')
        messages.append(f'<li id="{escape(item["id"], quote=True)}"><strong>{escape(KINDS[item["kind"]])}</strong> · '
            f'{escape(item["author"])} → {escape(item["recipient"] or "项目成员")} · {escape(status)} · v{item["version"]}'
            f'<p>{escape(item["content"])}</p><p class="muted">回复 {escape(item["reply_to"] or "无")} · 编号 {escape(item["id"])}</p>'
            + history(item) + controls + '</li>')
    create = ''
    if task_id and task_version is not None and data['can_write']:
        create = operation('task-message', {'project_id': project, 'task_id': task_id, 'task_version': task_version},
            ui.selection('kind', '沟通类别', list(KINDS.items())) + ui.input_field('recipient', '指名接收人（选填）', required=False) +
            ui.input_field('reply_to', '回复沟通编号（选填）', required=False) + ui.text_field('content', '内容', size=4000), '发送任务沟通')
    experiences = []
    for item in data['experiences']:
        controls = ''
        if data['managed'] and item['state'] != 'retired':
            options = [('retired', '退役')] if item['state'] == 'confirmed' else [('confirmed', '人工确认'), ('retired', '退役')]
            controls = operation('experience-state', {'project_id': item['project_id'], 'id': item['id'], 'version': item['version']},
                ui.selection('state', '人工处置', options) + ui.text_field('reason', '复核依据'), '保存人工处置')
        if data['can_write'] and item['state'] == 'candidate' and (item['author'] == actor or data['managed']):
            controls += '<details><summary>修订候选经验</summary>' + experience_form(item['project_id'], item=item) + '</details>'
        details = ''.join(f'<p><strong>{label}</strong> {escape(item[field])}</p>' for field, label in
                          [('conditions', '适用条件'), ('method', '方法'), ('evidence', '证据'), ('limits', '局限')])
        experiences.append(f'<li><strong>{escape(item["title"])}</strong> · {STATES[item["state"]]} · v{item["version"]}'
                           f'<p>{sources(item)}</p>' + details + history(item) + controls + '</li>')
    optional = ('<details><summary>自愿沉淀一条候选经验</summary>' + experience_form(project, task_id or '', task_version or 0) + '</details>') if data['can_write'] else ''
    return (f'<p class="muted">{NOTICE}</p>' + search + '<h2>任务沟通</h2><ul class="roster">' + ''.join(messages) +
            '</ul>' + create + '<h2>经验检索与沉淀</h2><ul class="roster">' + ''.join(experiences) + '</ul>' + optional)


def dispatch(handler, method, target, actor):
    from .httpd import parse_query
    from .web import parse_form, redirect
    from 协作本轮 import enabled
    service = handler.server.service
    if not actor:
        return redirect('/login')
    filters = parse_query(target.query, {'project', 'task_id', 'q'})
    if method == 'POST':
        data = parse_form(handler, 64 * 1024, 20)
        action = data.pop('operation', '')
        if action not in ACTIONS:
            raise ClientError('沟通操作无效')
        for name in ('version', 'task_version', 'source_task_version', 'source_feedback_version'):
            if name in data:
                data[name] = strict_json(data[name].encode('utf-8'))
        with service.lock:
            status, result = service.submit(actor, action, data.get('request_id'), data)
        if status != 200:
            return round_web.page('沟通操作待核', result.get('message') or (result.get('steps') or [{}])[-1].get('reason', '请重送原表单'), status, actor=actor)
        return redirect(url(data.get('project_id'), data.get('task_id') or filters.get('task_id')))
    if method != 'GET':
        raise ClientError('仅支持查看或提交', 405)
    with service.lock:
        state = service.snapshot()['state']
        if not enabled(state):
            raise ClientError('须先迁移本轮数据合同', 409)
        data = view(state, actor, filters.get('project') or None, filters.get('task_id') or None, filters.get('q', ''))
        version = state['tasks'][data['task_id']]['version'] if data['task_id'] else None
    return round_web.work_page('任务沟通与经验', render(actor, data, version), actor)
