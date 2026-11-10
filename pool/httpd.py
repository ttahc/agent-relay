"""HTTP transport for loopback and explicitly enabled local LAN TLS."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime
import hashlib
import hmac
import secrets
from ipaddress import IPv4Address, IPv4Network
import logging
import re
import ssl
import time
from threading import BoundedSemaphore
from urllib.parse import parse_qs, urlsplit

from . import round_service, round_web, web
from . import __version__
from . import ROOT
from .packages import ClientError, MAX_JSON, strict_json
from .service import PUBLIC_ACTIONS, Unavailable
from .lifecycle import Maintenance
from .sessions import DurableSessions
from 协作存储 import encoded


PRIVATE_V4 = tuple(map(IPv4Network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))


JSON = "application/json; charset=utf-8"
ROUND_WRITES = frozenset({"person-invite", "token-prepare", "notices-poll", "notice-ack", "notice-retry", "runner-heartbeat"})


def whole_query(query):
    return query


def one_value(name):
    return lambda query: query.get(name)


def listing_query(query):
    if 'full' in query and query['full'] != '1':
        raise ClientError('full 只接受1')
    return query if 'full' in query else query.get('project')


# GET /v1/<action>: the query keys it accepts (None: it takes no query), how the parsed query
# becomes the argument of Service.read, the content type, and whether only round mode serves it.
READ_API = {
    "features": (None, None, JSON, False),
    "execution": ({'task_id', 'claim_id', 'action_id', 'executor_id'}, whole_query, JSON, False),
    "input-package": ({'task_id', 'scope_version', 'claim_id'}, whole_query, "application/zip", False),
    "release-readiness": (None, None, JSON, False),
    "window-impact": ({"name"}, one_value("name"), JSON, False),
    "capability-requests": (None, None, JSON, False),
    "tasks": ({"project", 'full'}, listing_query, JSON, False),
    "task-options": ({"project", 'full'}, listing_query, JSON, False),
    "board": (None, None, "text/markdown; charset=utf-8", False),
    "projects": (None, None, JSON, False),
    "executors": (None, None, JSON, False),
    "identity": (None, None, JSON, False),
    "upgrade": (None, None, JSON, False),
    "invitations": (None, None, JSON, True),
    "runner": (None, None, JSON, True),
    "notices": (None, None, JSON, True),
    "delegations": (None, None, JSON, True),
    "cleanup": (None, None, JSON, True),
    "collaboration": ({"project"}, one_value("project"), JSON, True),
    "capabilities": ({"identity"}, one_value("identity"), JSON, False),
    "audit": ({"task", "actor", "request"}, whole_query, JSON, False),
    "receipt": ({"request"}, one_value("request"), JSON, False),
}
READ_API_PREFIXES = (("tasks/", "task"), ("projects/", "project"))  # GET /v1/tasks/<id>, /v1/projects/<id>
READ_ACTIONS = frozenset(READ_API) | {"artifact"}


class Server(ThreadingHTTPServer):
    daemon_threads = False

    def __init__(self, port, service, tokens, tls=None, lan_name=None, lan_aliases=(), tls_fingerprint=None):
        self.service = service
        self.lifecycle = service.lifecycle
        self.tokens = tokens
        self.tls = tls
        self.tls_fingerprint = tls_fingerprint
        self.lan_name = lan_name
        archive = ROOT / "dist" / "task-pool-local.zip"
        archive = archive.with_name("taskpool-ai-client.zip")
        if archive.is_file():
            self.client_archive = archive.read_bytes()
        else:
            from build import client_bundle_bytes
            self.client_archive = client_bundle_bytes()
        self.is_round = service.round_enabled()
        self.lan_names = {lan_name, *lan_aliases}
        self.sessions = DurableSessions(service)
        self.csrf_key = self.sessions.csrf_key
        self.request_slots = BoundedSemaphore(24)
        super().__init__(("0.0.0.0" if tls else "127.0.0.1", port), Handler)

    def process_request(self, request, address):
        if not self.request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.request_slots.release()

    def finish_request(self, request, address):
        if not self.tls:
            return super().finish_request(request, address)
        request.settimeout(10)
        try:
            secured = self.tls.wrap_socket(request, server_side=True)
        except (OSError, ssl.SSLError):
            return
        with secured:
            return super().finish_request(secured, address)

    def allows_host(self, headers):
        if len(headers) != 1:
            return False
        host, sep, port = headers[0].lower().partition(":")
        if not sep or port != str(self.server_address[1]):
            return False
        if host in {"127.0.0.1", "localhost"} | self.lan_names:
            return True
        if not self.tls:
            return False
        try:
            address = IPv4Address(host)
        except ValueError:
            return False
        return any(address in network for network in PRIVATE_V4)

    def actor_for_token(self, token, identity=None):
        with self.service.lock:
            return self._actor_for_token(token, identity)

    def _actor_for_token(self, token, identity=None):
        if not token.isascii() or not 32 <= len(token) <= 100:
            return None
        if identity in self.tokens:
            if hmac.compare_digest(token, self.tokens[identity]) and self.service.credential_version(identity, bootstrap=True):
                return identity
        if identity is None:
            for actor, expected in self.tokens.items():
                if hmac.compare_digest(token, expected) and self.service.credential_version(actor, bootstrap=True):
                    return actor
        actor = self.service.account_actor(token)
        return actor if actor and (identity is None or actor == identity) and self.service.credential_version(actor) else None


class Handler(BaseHTTPRequestHandler):
    server_version = f"TaskPool/{__version__}"
    sys_version = ""
    timeout = 15

    def log_message(self, *_):
        pass

    def send(self, status, data, kind="application/json; charset=utf-8", headers=()):
        payload = encoded(data) if isinstance(data, dict) else data
        streaming = hasattr(payload, 'read') and hasattr(payload, 'seek')
        if streaming:
            payload.seek(0, 2)
            length = payload.tell()
            payload.seek(0)
        else:
            length = len(payload)
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-TaskPool-Version", __version__)
        if status == 401 and kind.startswith("application/json"):
            self.send_header("WWW-Authenticate", "Bearer")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        try:
            if self.command != "HEAD":
                if streaming:
                    while chunk := payload.read(1024 * 1024):
                        self.wfile.write(chunk)
                else:
                    self.wfile.write(payload)
        finally:
            if streaming:
                payload.close()

    def authenticate(self):
        headers = self.headers.get_all("Authorization", [])
        value = headers[0] if len(headers) == 1 else ""
        scheme, _, token = value.partition(" ")
        if scheme.lower() == "bearer" and (actor := self.server.actor_for_token(token)):
            return actor
        raise ClientError("需要已登记身份的 Bearer 令牌", 401)

    def request_body(self, content_type, limit):
        lengths = self.headers.get_all("Content-Length", [])
        if (self.headers.get("Transfer-Encoding") is not None or len(lengths) != 1 or
                not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0]) > 10):
            raise ClientError("需要单一有效的 Content-Length", 411)
        size = int(lengths[0])
        if not 0 < size <= limit:
            raise ClientError("请求体大小超出限制", 413)
        if self.headers.get_content_type() != content_type:
            raise ClientError("需要 " + content_type, 415)
        raw = self.rfile.read(size)
        if len(raw) != size:
            raise ClientError("请求体未完整到达")
        return raw

    def request_json(self, limit=MAX_JSON):
        data = strict_json(self.request_body("application/json", limit))
        if not isinstance(data, dict) or "request_id" not in data:
            raise ClientError("需要 JSON 对象和 request_id")
        return data

    def discard_unadmitted_body(self):
        """Bounded drain avoids resetting a TLS response over an unread small POST body."""
        lengths = self.headers.get_all('Content-Length', [])
        if (self.command != 'POST' or len(lengths) != 1 or not lengths[0].isascii() or
                not lengths[0].isdigit() or len(lengths[0]) > 10 or self.headers.get('Transfer-Encoding')):
            return
        remaining = int(lengths[0])
        if remaining > MAX_JSON:
            return
        previous = self.connection.gettimeout()
        deadline = time.monotonic() + 2
        try:
            while remaining and time.monotonic() < deadline:
                self.connection.settimeout(max(0.01, deadline - time.monotonic()))
                chunk = self.rfile.read1(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
        except (OSError, TimeoutError):
            pass
        finally:
            self.connection.settimeout(previous)

    def dispatch(self, method):
        if not self.server.allows_host(self.headers.get_all("Host", [])):
            raise ClientError("Host 与服务监听不匹配")
        service = self.server.service
        target = urlsplit(self.path)
        if method == "GET" and (response := entry_page(self, target)) is not None:
            return response
        if not (target.scheme or target.netloc or target.fragment) and web.matches(target):
            if method == "GET":
                with service.lock, service.one_snapshot():
                    return web.dispatch(self, method, target)
            with service.request_identity(lambda: self.server.sessions.actor(web.session_id(self), service),
                                          lambda: getattr(self, 'web_supersedes_request_id', None)):
                return web.dispatch(self, method, target)
        if self.server.tls and method == "GET" and self.path == "/healthz":
            with service.lock:
                service.snapshot()
            return 200, {"status": "ok", "service": "intranet-task-pool"}, JSON
        api_route = target.path[4:] if target.path.startswith("/v1/") and not (
            target.scheme or target.netloc or target.fragment or target.query
        ) else ""
        if self.server.is_round and method == "POST" and api_route in round_service.BOOTSTRAP:
            auth = self.headers.get_all("Authorization", [])
            scheme, _, token = auth[0].partition(" ") if len(auth) == 1 else ("", "", "")
            body = self.request_json(round_service.MAX_SECRET_BODY)
            status, data = round_service.bootstrap(service, api_route, body, token if scheme.lower() == "bearer" else "")
            return status, data, JSON
        if target.scheme or target.netloc or target.fragment or not target.path.startswith("/v1/"):
            raise ClientError("接口不存在", 404)
        action = target.path[4:]
        if not ((method == "GET" and (action in READ_ACTIONS or action.startswith("tasks/") or action.startswith("projects/"))) or
                (method == "POST" and (action in PUBLIC_ACTIONS or action in ROUND_WRITES))):
            raise ClientError("接口不存在，请从 /ai 查看接入说明", 404)
        actor = self.authenticate()
        if self.server.is_round and method == "POST" and api_route in ROUND_WRITES:
            return round_write(self, action)
        if method == "POST" and action in PUBLIC_ACTIONS and not target.query:
            return submit_write(self, action)
        if method == "GET":
            if action == 'input-package':
                return download_inputs(self, target)
            with service.lock, service.one_snapshot():
                actor = self.authenticate()
                return self.read_api(action, target, actor)
        raise ClientError("接口不存在", 404)

    def read_api(self, action, target, actor):
        service = self.server.service
        if action in READ_API:
            allowed, argument, kind, round_only = READ_API[action]
            if not round_only or self.server.is_round:
                if allowed is not None:
                    return 200, service.read(actor, action, argument(parse_query(target.query, allowed))), kind
                if not target.query:
                    return 200, service.read(actor, action), kind
        for prefix, route in READ_API_PREFIXES:
            if action.startswith(prefix) and not target.query:
                return 200, service.read(actor, route, action[len(prefix):]), JSON
        if action == "artifact":
            try:
                query = parse_qs(target.query, max_num_fields=1, keep_blank_values=True)
            except ValueError as error:
                raise ClientError("只能提供一个 path 参数") from error
            if set(query) != {"path"}:
                raise ClientError("需要 path 查询参数")
            return 200, service.read(actor, "artifact", query["path"][0]), "application/octet-stream"
        raise ClientError("接口不存在", 404)

    def invitation_bundle(self, invitation):
        scheme = "https" if self.server.tls else "http"
        authority = self.headers["Host"].lower()
        if self.server.tls:
            host, _, port = authority.partition(":")
            bundle = {**invitation, "protocol": 1, "url": f"https://{self.server.lan_name}:{port}",
                      "connect_host": host, "certificate_sha256": self.server.tls_fingerprint}
        else:
            bundle = {**invitation, "protocol": 1, "url": scheme + "://" + authority,
                      "certificate_sha256": self.server.tls_fingerprint}
        if "id" not in invitation or "code" not in invitation:
            return {**bundle, "kind": "ai-token-rotation"}
        archive = self.server.client_archive
        if archive is None:
            raise ClientError("客户端包尚未构建，请管理员检查发行包", 503)
        bundle.update(kind="ai-window", client={"url": bundle["url"] + "/ai-client.zip",
                      "sha256": hashlib.sha256(archive).hexdigest(), "version": __version__,
                      "connect_host": bundle.get("connect_host"), "help_url": bundle["url"] + "/ai",
                      "python": "3.11+", "entry": "ops/round-client.py", "windows_entry": "ops/round-client.ps1"},
                      instructions=[
                          "这是 AI 窗口邀请，只用于客户端 enroll。人员注册页面不使用这份 code。",
                          "读取 /ai 和下载客户端不消耗邀请码，也不需要登录或发送 code。",
                          "按 connect_host 连接实际地址，按 url 的主机名和 certificate_sha256 核对服务证书；下载 client.url 后核对 client.sha256，再解压。",
                          "将整段 JSON 保存为 invite.json。在解压目录运行下面的客户端命令。将 window-one 换成当前窗口独有的文件名，平台和名称填写实际值。",
                          "Windows PowerShell: & .\\ops\\round-client.ps1 --state \"$env:USERPROFILE\\.taskpool\\window-one.credential\" enroll --invite .\\invite.json --platform external --window-name \"实际聊天标题\"",
                          "Linux/macOS: python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential enroll --invite ./invite.json --platform external --window-name '实际聊天标题'",
                          "--platform 可选 codex、claude、gemini、external。Windows 无法找到 Python 时，将 TASKPOOL_PYTHON 设为实际 python.exe 完整路径。",
                          "网络中断后用相同凭据文件执行 enroll 恢复；收到 active、窗口编号和项目权限后再申报能力、查看任务。不要将 code 或执行令牌写入反馈、日志或交付物。",
                      ])
        from .invite_links import link
        if invitation_url := link(self, invitation):
            bundle["invitation_url"] = invitation_url
        return bundle

    def handle_api(self, method):
        try:
            try:
                if method == "GET" and self.path == "/readyz":
                    if not self.server.allows_host(self.headers.get_all("Host", [])):
                        raise ClientError("Host 与服务监听不匹配")
                    phase = self.server.lifecycle.status()["phase"]
                    ready = phase == "running"
                    self.send(200 if ready else 503, {"phase": phase, "ready": ready},
                              headers=() if ready else (("Retry-After", str(Maintenance.retry_after)),))
                    return
                with self.server.lifecycle.admit(method, urlsplit(self.path).path):
                    response = self.dispatch(method)
                    self.send(*response)
                    return
            except Maintenance as error:
                self.discard_unadmitted_body()
                if self.headers.get('X-TaskPool-Response') == 'json':
                    self.send(503, {'status': 503, 'state': 'pending', 'received': False, 'retryable': True,
                              'message': '服务正在维护，请保留原输入和请求编号稍后重试'},
                              headers=(('Retry-After', str(error.retry_after)),))
                    return
                if web.matches(urlsplit(self.path)):
                    status, payload, kind, headers = web.html_page("服务正在升级", "<main><h1>服务暂时重连</h1>"
                        "<p>正在排空或切换服务。已有任务与占用保留；请稍后使用原请求重试，避免重复领取或开工。</p>"
                        "<p>可返回原页面保留填写内容，服务恢复后再提交。</p></main>", 503)
                    self.send(status, payload, kind, headers + (("Retry-After", str(error.retry_after)),))
                    return
                self.send(503, {"status": "maintenance", "retryable": True, "message": str(error),
                                "retry_after": error.retry_after, "phase": self.server.lifecycle.status()["phase"]},
                          headers=(("Retry-After", str(error.retry_after)),))
                return
            except ClientError as error:
                from .privacy import text
                self.send(error.status, {"status": "rejected", "message": text(error), "help_url": "/ai", "client_url": "/ai-client.zip"})
                return
            except TimeoutError:
                self.send(408, {"status": "rejected", "message": "请求读取超时"})
                return
            except Unavailable as error:
                from .privacy import text
                self.send(503, {"status": "pending", "message": text(error)})
                return
            except Exception as error:
                from .privacy import log_exception
                incident = log_exception(error)
                self.send(503, {"status": "pending", "message": "操作状态待核，修复后重试同一请求", "incident": incident})
                return
        except (ConnectionError, TimeoutError):
            pass  # The request may already be durable; the client can retry the same id.

    def do_GET(self):
        self.handle_api("GET")

    def do_POST(self):
        self.handle_api("POST")

    def do_HEAD(self):
        self.handle_api("GET")


def entry_page(handler, target):
    """GET routes served before any page or API routing: status, AI invitations and the client package."""
    if handler.path == "/v1/service-status":
        handler.authenticate()
        return 200, handler.server.lifecycle.status(), JSON
    from . import invite_links
    if (match := invite_links.INVITE_PATH.fullmatch(target.path)) and not target.query:
        return invite_links.page(match[1])
    if handler.path == "/assets/ai-invite.js":
        return 200, invite_links.SCRIPT, "text/javascript; charset=utf-8"
    if target.path == "/v1/ai-invite-info":
        query = parse_query(target.query, {"invite_id"})
        headers = handler.headers.get_all("Authorization", [])
        scheme, _, proof = headers[0].partition(" ") if len(headers) == 1 else ("", "", "")
        if scheme.lower() != "bearer" or not re.fullmatch(r"[A-Za-z0-9_-]{43}", proof):
            raise ClientError("需要完整邀请链接中的凭据", 401)
        return 200, invite_links.information(handler, query.get("invite_id"), proof), JSON
    if handler.path == "/ai-client.zip":
        if handler.server.client_archive is None:
            raise ClientError("客户端包尚未构建，请管理员检查发行包", 503)
        return 200, handler.server.client_archive, "application/zip", (
            ("Content-Disposition", 'attachment; filename="taskpool-ai-client.zip"'),
        )
    if handler.path == "/ai":
        return round_web.ai_entry()
    return None


def round_write(handler, action):
    """Round-mode writes that bypass the request journal: invitations, tokens, notices and heartbeats."""
    service = handler.server.service
    body = handler.request_json(round_service.MAX_SECRET_BODY)
    with service.lock:
        actor = handler.authenticate()
        state = service.snapshot()["state"]
        if state["pilot"]["format"]["maintenance"]:
            raise ClientError("服务处于维护窗口", 503)
        if action == "person-invite":
            from .packages import fields
            fields(body, "request_id role")
            value = {"code": service.invite(actor, body["request_id"], body["role"])}
            return 200, value, JSON
        if action == "runner-heartbeat":
            from .packages import fields
            fields(body, "request_id")
            if not round_service.execution_settings(state, actor)["heartbeat"]:
                raise ClientError("执行端未启用心跳", 403)
            with service.db:
                service.notices.pulse(actor)
            return 200, {"status": "received"}, JSON
        if action == "token-prepare":
            status, value = round_service.prepare_token(service, actor, body)
            return status, value, JSON
        if action == "notices-poll":
            value = service.notices.poll(state, actor, body, service)
        elif action == "notice-ack":
            value = service.notices.acknowledge(actor, body)
        else:
            value = service.notices.retry(state, actor, body)
        return 200, value, JSON


def submit_write(handler, action):
    """A journaled write: POST /v1/<action> with a request_id."""
    service = handler.server.service
    body = handler.request_json()
    reported = handler.headers.get("X-TaskPool-Reported-At")
    if reported:
        try:
            if len(reported) > 40 or datetime.fromisoformat(reported).tzinfo is None:
                raise ValueError
        except ValueError as error:
            raise ClientError("客户端报告时间须为带时区的 ISO 时间") from error
    with service.lock:
        actor = handler.authenticate()
        status, response = service.submit(actor, action, body["request_id"], body, reported_utc=reported,
                                          authorize=handler.authenticate)
        if action == "ai-invite" and response.get("invitation"):
            response = {**response, "invitation": handler.invitation_bundle(response["invitation"])}
            from .invite_links import remember
            remember(service, response["invitation"]["id"])
    return status, response, JSON


def download_inputs(handler, target):
    """Stream the frozen inputs of a task; credentials and the selection are checked again after packing."""
    from .input_packages import select, generate
    service = handler.server.service
    query = parse_query(target.query, {'task_id', 'scope_version', 'claim_id'})
    with service.lock:
        actor = handler.authenticate()
        selected = select(service, actor, service.snapshot()['state'], query)
        version = service.credential_version(actor)
    stream, manifest_sha = generate(service, actor, selected)
    try:
        with service.lock:
            if handler.authenticate() != actor or service.credential_version(actor) != version:
                raise ClientError('下载期间凭据已变化，请重新核对', 401)
            if select(service, actor, service.snapshot()['state'], query) != selected:
                raise ClientError('下载期间冻结输入已变化，原文件保留', 409)
        return 200, stream, 'application/zip', (('X-TaskPool-Manifest-SHA256', manifest_sha),)
    except BaseException:
        stream.close()
        raise


def parse_query(raw, allowed):
    try:
        values = parse_qs(raw, max_num_fields=len(allowed), keep_blank_values=True, strict_parsing=True)
    except ValueError as error:
        raise ClientError("查询参数无效") from error
    if not values.keys() <= allowed or any(len(v) != 1 or not v[0] for v in values.values()):
        raise ClientError("查询参数无效")
    return {key: value[0] for key, value in values.items()}
