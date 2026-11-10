"""Current release evidence boundaries and outstanding real-user verification."""
from html import escape as e
from urllib.parse import quote
from .task_pages import STAGES


def page(service, actor):
    from .round_web import work_page
    data = service.read(actor, 'release-readiness')
    tasks = ''.join(f'<li><a href="/tasks/{quote(t["id"])}">{e(t["id"])} · {e(t["title"])}</a> · '
                  f'{e(STAGES.get(t["status"], t["status"]))}</li>' for t in data['follow_up_tasks'])
    feedback = ''.join(f'<li>{e(f["title"])} · {e(f["status"])}'
                     + (f' · <a href="/tasks/{quote(f["task"])}">{e(f["task"])}</a>' if f['task']
                        else ' · 待分配复验') + '</li>'
                     for f in data['pending_feedback'])
    return work_page('版本复验', f'<div class="phead"><h2>当前版本 {e(data["application_version"])}</h2></div>'
        f'<p>{e(data["notice"])}</p>'
        f'<div class="box"><h3>原窗口／人员复验任务</h3><ul>{tasks or "<li>当前权限范围内没有待复验任务。</li>"}</ul></div>'
        f'<div class="box"><h3>尚未完成业务复核的反馈（{len(data["pending_feedback"])}）</h3>'
        f'<ul>{feedback or "<li>无。</li>"}</ul></div>', actor)
