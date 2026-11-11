"""Completed-task issues, explicit rechecks, and linked fresh repairs."""
from html import escape
from urllib.parse import quote, urlencode
from . import round_web, task_pages as pages, upgrade_pages as ui
from .post_completion import ACTIONS
from .packages import ClientError, strict_json

LABELS = {'open': '问题待核实', 'evidence': '待补证复查', 'repair-required': '确认需修改',
          'repairing': '关联返修中', 'resolved': '复查已解决', 'declined': '复查不成立'}


def url(task_id):
    return '/post-completion?' + urlencode({'task_id': task_id})


def operation(action, values, controls, label):
    hidden = ''.join(pages.hidden(k, v) for k, v in {'operation': action, **values}.items())
    return round_web.password_form(escape(url(values['task_id']), quote=True), hidden + controls, label)


def render(actor, data, task, receivers):
    tid = task['task_id']
    base = {'task_id': tid, 'task_version': task['version']}
    body = (f'<p><a href="/tasks/{quote(tid, safe="")}">{escape(tid)} · {escape(task["title"])}</a></p>'
        '<p>报告问题不等于推翻原结果。复查与返修保留原完成记录，返修使用新任务和新的执行许可。</p>')
    if task['status'] in {'completed', 'closed_missing'}:
        controls = ui.input_field('title', '问题标题') + ui.text_field('details', '现象、复现条件和影响', size=4000)
        controls += ui.text_field('evidence', '证据或明确待补内容', size=4000)
        controls += ui.selection('visibility', '可见范围', [('project', '项目内'), ('restricted', '提交者与管理员')])
        body += ui.block('报告问题／申请复查', operation('task-issue-open', base, controls, '登记问题'))
    rows = []
    for issue in data['issues']:
        values = {**base, 'id': issue['id'], 'version': issue['version']}
        controls = ''
        if data['can_review']:
            choices = [('evidence', '补证或重开复查')] if issue['status'] in {'resolved', 'declined'} else [
                ('evidence', '需要补证'), ('repair-required', '确认需要修改'), ('resolved', '证据证实已解决'), ('declined', '问题不成立')]
            controls = operation('task-issue-review', values, ui.selection('verdict', '本次结论', choices)
                + ui.text_field('reason', '处理依据', size=4000) + ui.text_field('evidence', '具体核对与结果证据', size=4000), '记录复查结论')
        if data['can_repair'] and issue['visibility'] == 'project' and issue['status'] == 'repair-required' and issue.get('can_start_repair', not issue.get('repair_task')):
            repair = ui.input_field('title', '返修标题', '返修：' + issue['title'])
            repair += ui.text_field('brief', '返修说明与新范围', issue['details'], size=40000)
            repair += ui.text_field('criteria', '返修完成判据（每行一条）', size=3200)
            repair += ui.selection('receiver', '当前接收者', [(x, x) for x in receivers], task['receiver'])
            repair += ui.selection('completion_policy', '返修完成方式', [('review-required', '审查后完成'), ('executor-direct', '执行者完成')])
            repair += '<label><input type="checkbox" name="include_original_delivery" value="1">将最近完成返修的交付（首轮为原已接受交付）加入新任务输入，允许本项目可查看任务的成员读取（不勾选时，新执行者可能无法读取旧交付）</label>'
            repair += ui.text_field('reason', '更正原结论并登记返修的依据', size=4000)
            controls += ui.block('创建关联返修任务', operation('task-repair-open', values, repair, '登记新返修任务'))
        if issue['visibility'] == 'restricted':
            controls += '<p class="muted">受限问题不会自动转为项目可见返修。需要返修时，请先登记不含受限内容的独立项目问题。</p>'
        linked = f'<p><a href="/tasks/{quote(issue["repair_task"], safe="")}">返修任务 {escape(issue["repair_task"])}</a> · 返修完成不自动关闭问题，须核对新交付。</p>' if issue.get('repair_task') else ''
        linked += ''.join(f'<p>历史返修 <a href="/tasks/{quote(r["task_id"], safe="")}">{escape(r["task_id"])}</a></p>' for r in issue.get('repair_history', []))
        trail = ''.join('<li>' + escape(LABELS.get(r['verdict'], r['verdict'])) + ' · ' + escape(r['by']) +
                       '<p>' + escape(r['reason']) + '</p><p>' + escape(r.get('evidence', '')) + '</p></li>' for r in issue['reviews'])
        rows.append(f'<section id="{escape(issue["id"], quote=True)}"><h2>{escape(issue["title"])}</h2>'
            f'<p>{escape(LABELS[issue["status"]])} · {escape(issue["author"])} · v{issue["version"]}</p>'
            f'<p>{escape(issue["details"])}</p><p>{escape(issue["evidence"])}</p>{linked}'
            f'<details><summary>原收口和复查记录</summary><p>收口 {escape(issue["source"]["close_id"])} · '
            f'修订 {escape(issue["source"]["revision"])}</p><ul>{trail}</ul></details>{controls}</section>')
    return body + ''.join(rows or ['<p class="muted">尚无可见的完成后问题。</p>'])


def dispatch(handler, method, target, actor):
    from .httpd import parse_query
    from .web import parse_form, redirect
    service = handler.server.service
    filters = parse_query(target.query, {'task_id'})
    if method == 'POST':
        data = parse_form(handler, 256 * 1024, 20)
        action = data.pop('operation', '')
        if action not in ACTIONS:
            raise ClientError('复查操作无效')
        for name in ('task_version', 'version'):
            if name in data:
                data[name] = strict_json(data[name].encode('utf-8'))
        if action == 'task-repair-open':
            data['include_original_delivery'] = data.get('include_original_delivery') == '1'
        if 'criteria' in data:
            data['criteria'] = [x.strip() for x in data['criteria'].splitlines() if x.strip()]
        status, value = service.submit(actor, action, data.get('request_id'), data)
        if status != 200:
            return round_web.page('复查操作待核', value.get('message') or (value.get('steps') or [{}])[-1].get('reason', '请核对原表单'), status, actor=actor)
        return redirect(url(data['task_id']))
    tid = filters.get('task_id')
    data = service.read(actor, 'post-completion', tid)
    task = service.read(actor, 'task', tid)['task']
    state = service.snapshot()['state']
    import 协作升级 as rules
    receivers = [name for name in state['origins'] if rules.active(state, name) and
                 'receiver' in rules.roles(state, rules.task_project(task), name)]
    return round_web.work_page('完成后复查', render(actor, data, task, receivers), actor)
