"""Read-only bootstrap information behind short-lived AI invitation links."""
from html import escape
import hmac
import json
import re
import time
from urllib.parse import urlencode

from .packages import ClientError

INVITE_PATH = re.compile(r"/ai/join/(i-[a-f0-9]{32})")


def link(handler, invitation):
    service = getattr(handler.server, "service", None)
    if not service or not hasattr(service, "accounts") or not invitation.get("issuer"):
        return None
    key = service.accounts.token("ai-invite-link", invitation["id"], invitation["issuer"])
    values = {"key": key}
    if handler.server.tls:
        values.update(sha256=handler.server.tls_fingerprint, tls=handler.server.lan_name)
    scheme = "https" if handler.server.tls else "http"
    return f'{scheme}://{handler.headers["Host"].lower()}/ai/join/{invitation["id"]}#{urlencode(values)}'


def remember(service, invitation_id):
    with service.db:
        service.db.execute("CREATE TABLE IF NOT EXISTS invite_presentations("
                           "id TEXT PRIMARY KEY, format INTEGER NOT NULL)")
        service.db.execute("INSERT OR IGNORE INTO invite_presentations VALUES(?,2)", (invitation_id,))


def is_current(service, invitation_id):
    exists = service.db.execute("SELECT 1 FROM sqlite_master "
                                "WHERE type='table' AND name='invite_presentations'").fetchone()
    return bool(exists
                and service.db.execute("SELECT 1 FROM invite_presentations WHERE id=?", (invitation_id,)).fetchone())


def information(handler, invitation_id, proof):
    from .round_service import usable_invite
    if not isinstance(invitation_id, str) or not re.fullmatch(r"i-[a-f0-9]{32}", invitation_id):
        raise ClientError("邀请编号无效", 400)
    service = handler.server.service
    with service.lock:
        state = service.snapshot()["state"]
        item = state["round"].get("invite:" + invitation_id)
        if not item or not isinstance(proof, str) or not proof.isascii() or not hmac.compare_digest(
                service.accounts.token("ai-invite-link", invitation_id, item["issuer"]), proof):
            raise ClientError("邀请链接无效，请向邀请人索取完整链接", 403)
        if item["revoked"] or item["expires"] <= time.time():
            raise ClientError("邀请已撤销或到期，请邀请人重新生成", 410)
        if item["used"] >= item["count"]:
            raise ClientError("邀请登记额度已用完；已登记窗口请用原凭据恢复", 409)
        if not usable_invite(state, item):
            raise ClientError("邀请人的当前授权已不满足接入条件", 403)
        code = service.accounts.token("ai-invite", invitation_id, item["issuer"])
        return handler.invitation_bundle({**item, "code": code})


def page(invitation_id):
    from .web import html_page
    return html_page("AI 邀请接入", f"""
<main class="login-shell"><section class="form-panel"><div data-ai-invite="{escape(invitation_id)}">
<h1>AI 窗口邀请</h1><p>本链接用于登记一个独立 AI 窗口。查看说明或下载客户端不会消耗登记额度。</p>
<p id="invite-status" role="status">正在读取接入信息……</p>
<div id="invite-content" hidden><p id="invite-project"></p>
<p><a href="/ai-client.zip">下载最小客户端包</a> · <a href="/ai">通用接入说明</a></p>
<p>将完整邀请链接交给可以访问本服务的 AI。客户端支持 enroll --invite-url，并在登记前核对链接中的证书指纹。</p>
<ol id="invite-steps"></ol><details><summary>给 AI 的接入资料</summary>
<textarea id="invite-json" rows="10" readonly aria-label="AI 接入资料"></textarea></details></div>
</div></section></main><script defer src="/assets/ai-invite.js"></script>""")


SCRIPT = """(() => {
const area = document.querySelector('[data-ai-invite]');
if (!area) return;
const status = document.getElementById('invite-status');
const key = new URLSearchParams(location.hash.slice(1)).get('key');
if (!key) { status.textContent = '缺少邀请凭据，请使用邀请人复制的完整链接（包括 # 后的部分）。'; return; }
fetch('/v1/ai-invite-info?' + new URLSearchParams({invite_id: area.dataset.aiInvite}), {
  headers: {Authorization: 'Bearer ' + key}, cache: 'no-store', referrerPolicy: 'no-referrer'
}).then(async response => {
  const value = await response.json();
  if (!response.ok) throw new Error(value.message || '邀请资料暂不可用');
  status.textContent = '邀请可用。正式登记时才兑换额度。';
  document.getElementById('invite-project').textContent = '项目：' + value.project + ' · 责任人：' + value.owner;
  document.getElementById('invite-json').value = JSON.stringify(value, null, 2);
  const steps = document.getElementById('invite-steps');
  for (const text of value.instructions) { const li = document.createElement('li'); li.textContent = text; steps.append(li); }
  document.getElementById('invite-content').hidden = false;
}).catch(error => { status.textContent = error.message; });
})();""".encode("utf-8")
