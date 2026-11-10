"""Connect one AI window to an intranet task pool."""
import argparse
import base64
from contextlib import contextmanager
from copy import deepcopy
import errno
import hashlib
from io import BytesIO
from http.client import HTTPConnection, HTTPSConnection, HTTPException
import json
import os
from pathlib import Path, PurePosixPath
import random
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from urllib.parse import parse_qs, quote, urlencode, urlsplit


MAX_TRANSFER = 8 * 1024 * 1024
DOWNLOAD_LIMITS = {"json_bytes": MAX_TRANSFER, "zip_bytes": 144 * 1024 * 1024,
                   "total_bytes": 128 * 1024 * 1024, "file_bytes": 64 * 1024 * 1024,
                   "files": 500, "manifest_bytes": 1024 * 1024}
SECRET_FIELDS = {"token", "tokens", "rotation_token", "access_token", "refresh_token", "api_key", "private_key",
                 "code", "recovery", "recovery_code", "reset_code", "password", "passwd", "secret", "proof_sha", "invitation_url", "invite_url"}


def private_bytes(raw, decrypt=False):
    if os.name != "nt":
        return raw
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("data", ctypes.c_void_p)]

    buffer = ctypes.create_string_buffer(raw)
    source = Blob(len(raw), ctypes.cast(buffer, ctypes.c_void_p))
    result = Blob()
    crypto = ctypes.WinDLL("crypt32.dll", use_last_error=True)
    name = "CryptUnprotectData" if decrypt else "CryptProtectData"
    transform = getattr(crypto, name)
    transform.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                          ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    transform.restype = wintypes.BOOL
    if not transform(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result)):
        raise ctypes.WinError(ctypes.get_last_error())
    release = ctypes.WinDLL("kernel32.dll").LocalFree
    release.argtypes = [ctypes.c_void_p]
    release.restype = ctypes.c_void_p
    try:
        return ctypes.string_at(result.data, result.size)
    finally:
        release(result.data)


class State:
    def __init__(self, path):
        self.path = path.expanduser().absolute()
        self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.path.is_symlink() or self.path.parent.is_symlink() or (
                os.name != "nt" and self.path.parent.stat().st_mode & 0o077):
            raise ValueError("凭据须存于当前用户的受限目录")
        self.data = {}

    @contextmanager
    def exclusive(self):
        lock = self.path.with_suffix(self.path.suffix + ".lock")
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "r+b") as stream:
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise ValueError("此窗口凭据已由另一个进程打开") from error
            if self.path.exists():
                if os.name != "nt" and self.path.stat().st_mode & 0o077:
                    raise ValueError("凭据文件权限须为仅当前用户可读写")
                self.data = json.loads(private_bytes(self.path.read_bytes(), decrypt=True))
            yield

    def save(self):
        data = private_bytes(json.dumps(self.data, ensure_ascii=False).encode("utf-8"))
        fd, temporary = tempfile.mkstemp(prefix=".window-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.replace(temporary, self.path)
            except OSError as error:
                if error.errno == errno.EXDEV or getattr(error, "winerror", None) == 17:
                    raise ValueError("凭据目录无法完成原子替换（跨设备错误）。请用当前用户目录下的 "
                                     "~/.taskpool/<窗口名>.credential，或选择其他当前用户私有目录；"
                                     "已有凭据文件请保留，恢复登记时继续使用原请求。") from error
                raise
            if os.name != "nt":
                folder = os.open(self.path.parent, os.O_DIRECTORY | os.O_RDONLY)
                try:
                    os.fsync(folder)
                finally:
                    os.close(folder)
        finally:
            Path(temporary).unlink(missing_ok=True)


class RequestError(RuntimeError):
    def __init__(self, status, value, retry_after=None, server_version=None):
        self.status, self.value = status, value
        self.retry_after = retry_after
        self.server_version = server_version
        detail = value.get("message") or (value.get("steps") or [{}])[-1].get("reason") or value.get("status", "")
        super().__init__(f"HTTP {status} {detail}")


class DownloadBudgetError(ValueError):
    def __init__(self, budget, message):
        self.budget = budget
        super().__init__(message)


class RoutedHTTPSConnection(HTTPSConnection):
    """Connect to the supplied address while verifying the certificate's service name."""

    def __init__(self, host, port, connect_host, context, timeout):
        super().__init__(host, port, context=context, timeout=timeout)
        self.connect_host, self.tls_context = connect_host, context

    def connect(self):
        raw = socket.create_connection((self.connect_host, self.port), timeout=self.timeout)
        try:
            self.sock = self.tls_context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class Pool:
    def __init__(self, base, fingerprint, allow_loopback=False, connect_host=None):
        address = urlsplit(base)
        if (address.scheme not in ("https", "http") or not address.hostname or not address.port or address.username or
                address.password or address.path not in ("", "/") or address.query or address.fragment):
            raise ValueError("接入地址须为包含端口的服务根地址")
        self.host, self.port = address.hostname, address.port
        if connect_host is not None and (not isinstance(connect_host, str) or
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", connect_host)):
            raise ValueError("连接地址须为单独的主机名或 IPv4 地址")
        self.connect_host = connect_host or self.host
        self.context = None
        self.pin = (fingerprint or "").lower().replace(":", "")
        if address.scheme == "http":
            if not allow_loopback or self.host not in ("127.0.0.1", "localhost") or self.connect_host != self.host:
                raise ValueError("接入需要经核验的 HTTPS")
            return
        if len(self.pin) != 64 or any(c not in "0123456789abcdef" for c in self.pin):
            raise ValueError("邀请缺少有效的服务证书 SHA-256")
        # The initial connection fetches only the public certificate. Its digest
        # must match before it can become the trust anchor for real requests.
        probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        probe.check_hostname = False
        probe.verify_mode = ssl.CERT_NONE
        probe.minimum_version = ssl.TLSVersion.TLSv1_2
        def certificate_probe():
            with socket.create_connection((self.connect_host, self.port), timeout=8) as tcp:
                with probe.wrap_socket(tcp, server_hostname=self.host) as connection:
                    return connection.getpeercert(binary_form=True)
        der = bounded_retry(certificate_probe)
        if hashlib.sha256(der).hexdigest() != self.pin:
            raise ValueError("当前地址的服务证书指纹不匹配")
        self.context = ssl.create_default_context(cadata=ssl.DER_cert_to_PEM_cert(der))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def call(self, route, token=None, body=None, response_format="json", response_limit=None, method=None):
        # Build once so retries of any POST retain the same request identity and bytes.
        if body is not None:
            body = {"request_id": "c-" + secrets.token_hex(16), **body}
        if response_limit is None and method is None:
            return bounded_retry(lambda: self._call_once(route, token, body, response_format))
        return bounded_retry(lambda: self._call_once(route, token, body, response_format, response_limit, method))

    def _call_once(self, route, token=None, body=None, response_format="json", response_limit=None, method=None):
        if response_format not in {"json", "text", "bytes", "file", "headers"}:
            raise ValueError("响应格式无效")
        control_limit = min(MAX_TRANSFER, getattr(self, "_taskpool_control_limit", MAX_TRANSFER))
        limit = control_limit if response_limit is None else response_limit
        if response_format == "json":
            limit = min(limit, control_limit)
        if type(limit) is not int or limit < 1:
            raise ValueError("响应预算须为正整数")
        method = method or ("GET" if body is None else "POST")
        if method not in {"GET", "HEAD", "POST"} or method != "POST" and body is not None:
            raise ValueError("请求方法或请求体无效")
        if self.context:
            connection = RoutedHTTPSConnection(self.host, self.port, self.connect_host, self.context, timeout=12)
        else:
            connection = HTTPConnection(self.host, self.port, timeout=12)
        try:
            connection.connect()
            if self.context and hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest() != self.pin:
                raise ValueError("请求连接的证书指纹已变化")
            headers = {"Authorization": "Bearer " + token} if token else {}
            if body is not None:
                headers["Content-Type"] = "application/json"
                body = json.dumps(body, ensure_ascii=False).encode("utf-8")
            connection.request(method, "/v1/" + route, body, headers)
            response = connection.getresponse()
            if response.status != 200:
                raw = response.read(control_limit + 1)
                if len(raw) > control_limit:
                    raise ValueError("服务错误回执超出控制响应预算")
                try:
                    value = json.loads(raw)
                except (ValueError, UnicodeError):
                    value = {"message": "服务返回了非 JSON 错误响应"}
                if not isinstance(value, dict):
                    value = {"message": "服务返回了无效错误回执"}
                retry_after = response.getheader("Retry-After", "")
                retry_after = int(retry_after) if retry_after.isascii() and retry_after.isdigit() else None
                raise RequestError(response.status, value, retry_after, response.getheader("X-TaskPool-Version"))
            if response_format == "headers":
                return {"status": response.status, "content_length": response.getheader("Content-Length"),
                        "content_type": response.getheader("Content-Type")}
            if response_format == "file":
                if response.getheader("Content-Type", "").partition(";")[0].strip().lower() != "application/zip":
                    raise ValueError("输入包响应类型不是 ZIP，未降级下载")
                stream = tempfile.TemporaryFile()
                try:
                    total = 0
                    while chunk := response.read(min(65536, limit - total + 1)):
                        total += len(chunk)
                        if total > limit:
                            raise DownloadBudgetError("zip_bytes", "输入包网络字节超出本机与服务共同预算；保留已核验结果")
                        stream.write(chunk)
                    stream.seek(0)
                    stream.manifest_sha256 = response.getheader("X-TaskPool-Manifest-SHA256")
                    return stream
                except BaseException:
                    stream.close()
                    raise
            raw = response.read(limit + 1)
            if len(raw) > limit:
                raise ValueError("服务回执超出本次响应预算")
            if response_format == "bytes":
                return raw
            if response_format == "text":
                return raw.decode("utf-8")
            try:
                return json.loads(raw)
            except (ValueError, UnicodeError) as error:
                raise ValueError("服务返回了非 JSON 内容；看板请使用 board 命令，文件请使用 download 命令") from error
        finally:
            connection.close()


def bounded_retry(operation):
    """One attempt budget shared by maintenance and transport failures."""
    for attempt in range(3):
        try:
            return operation()
        except ssl.SSLCertVerificationError:
            raise
        except (OSError, HTTPException, RequestError) as error:
            retryable = isinstance(error, (OSError, HTTPException)) or error.status in {408, 429, 502, 503, 504}
            if not retryable or attempt == 2:
                raise
            delay = getattr(error, "retry_after", None)
            seconds = min(5, max(1, delay if isinstance(delay, (int, float)) else 1 + attempt))
            print("服务暂时重连，稍后重试原请求；可按 Ctrl+C 取消等待。", file=sys.stderr, flush=True)
            time.sleep(min(5, seconds + random.uniform(0, .2)))


def unsupported_interface(error):
    if not isinstance(error, RequestError) or error.status != 404:
        return False
    code = error.value.get("code") or error.value.get("error")
    version = error.server_version or ""
    return code == "unsupported_interface" or bool(re.fullmatch(r"0\.[012]\.\d+", version))


def server_features(api, token):
    cached = getattr(api, "_taskpool_features", None)
    if cached is not None:
        return cached
    try:
        value = api.call("features", token)
    except RequestError as error:
        if not unsupported_interface(error):
            raise
        value = {"api_protocol": 0, "security_schema": 3, "features": {}, "legacy_confirmed": True}
    if (not isinstance(value, dict) or type(value.get("api_protocol")) is not int or value["api_protocol"] not in {0, 1} or
            type(value.get("security_schema")) is not int or not isinstance(value.get("features"), (dict, list))):
        raise ValueError("服务功能说明无效，未降级或发送新执行操作")
    remote = value.get("input_download", {})
    if not isinstance(remote, dict):
        raise ValueError("服务下载预算说明无效")
    advertised_json = remote.get("json_bytes", MAX_TRANSFER)
    if type(advertised_json) is not int or advertised_json < 1:
        raise ValueError("服务控制响应预算无效")
    api._taskpool_control_limit = min(MAX_TRANSFER, advertised_json)
    api._taskpool_features = value
    return value


def supported(features, name):
    values = features.get("features", {})
    return values.get(name) is True if isinstance(values, dict) else name in values


def require_feature(api, token, name):
    value = server_features(api, token)
    if value["api_protocol"] != 1 or not supported(value, name):
        raise ValueError("当前服务未声明支持 " + name + "；保留原请求，请核对服务与客户端版本")
    return value


def download_limits(features, args):
    remote = features.get("input_download", {})
    if not isinstance(remote, dict):
        raise ValueError("服务下载预算说明无效")
    result = {}
    for key, default in DOWNLOAD_LIMITS.items():
        local = getattr(args, key, None)
        local = default if local is None else local
        advertised = remote.get(key, default)
        if type(local) is not int or local < 1 or type(advertised) is not int or advertised < 1:
            raise ValueError("下载预算须为正整数；请核对本机参数与服务配置")
        result[key] = min(local, advertised)
    return result


def bundle(path):
    value = json.load(sys.stdin) if path == "-" else json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if value.get("protocol") != 1:
        raise ValueError("接入信息版本无效")
    return value


def invitation_link(value, allow_loopback=False):
    """Parse the trusted fragment without sending it in an HTTP request target."""
    invalid = "邀请链接格式无效，请使用邀请人复制的完整链接（包括 # 后的部分）"
    try:
        if not isinstance(value, str) or len(value) > 4096 or any(ord(char) < 33 for char in value):
            raise ValueError(invalid)
        address = urlsplit(value)
        host, port = address.hostname, address.port
        match = re.fullmatch(r"/ai/join/(i-[0-9a-f]{32})", address.path)
        if (address.scheme not in {"https", "http"} or not host or not port or not 1 <= port <= 65535
                or address.username or address.password or address.query or '?' in value.partition('#')[0]
                or not match or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host)):
            raise ValueError(invalid)
        values = parse_qs(address.fragment, keep_blank_values=True, strict_parsing=True, max_num_fields=3)
        if not values.keys() <= {"key", "sha256", "tls"} or any(len(items) != 1 for items in values.values()):
            raise ValueError(invalid)
        proof = values.get("key", [""])[0]
        pin, tls = values.get("sha256", [""])[0], values.get("tls", [""])[0]
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", proof):
            raise ValueError(invalid)
        if address.scheme == "https":
            if (set(values) != {"key", "sha256", "tls"} or not re.fullmatch(r"[a-fA-F0-9]{64}", pin)
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,120}", tls)):
                raise ValueError(invalid)
            tls = tls.lower()
        else:
            if not allow_loopback or host not in {"127.0.0.1", "localhost"} or pin or tls:
                raise ValueError(invalid)
            tls = host
        return {"id": match[1], "key": proof, "pin": pin.lower(), "tls": tls, "actual_host": host,
                "port": port, "scheme": address.scheme, "base": f"{address.scheme}://{tls}:{port}"}
    except (ValueError, TypeError):
        raise ValueError(invalid) from None


def load_invitation(args):
    link = getattr(args, "invite_url", None)
    if not link:
        return bundle(args.invite)
    source = invitation_link(link, getattr(args, "allow_loopback", False))
    try:
        api = Pool(source["base"], source["pin"] or None, getattr(args, "allow_loopback", False), source["actual_host"])
        value = api.call("ai-invite-info?" + urlencode({"invite_id": source["id"]}), token=source["key"])
        if not isinstance(value, dict) or value.get("id") != source["id"] or value.get("protocol") != 1:
            raise ValueError("binding mismatch")
        address = urlsplit(value.get("url", ""))
        pin = value.get("certificate_sha256") or ""
        response_route = value.get("connect_host", source["actual_host"] if source["scheme"] == "http" else None)
        if (not isinstance(pin, str) or pin.lower() != source["pin"] or address.scheme != source["scheme"]
                or address.hostname != source["tls"] or address.port != source["port"]
                or address.username or address.password or address.path not in {"", "/"} or address.query or address.fragment
                or response_route not in {source["actual_host"], source["tls"]}
                or not isinstance(value.get("code"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value["code"])):
            raise ValueError("binding mismatch")
        result = {**value, "connect_host": source["actual_host"]}
        # The original trusted link supplies the route; the response cannot redirect it.
        if isinstance(result.get("client"), dict):
            result["client"] = {**result["client"], "connect_host": source["actual_host"]}
        result.pop("invitation_url", None)
        return result
    except (OSError, ValueError, RuntimeError, KeyError, TypeError):
        raise ValueError("邀请链接读取或校验失败；未兑换登记额度，请核对链接是否完整、有效及服务证书，稍后重试或请邀请人重新生成") from None


def safe_error(value):
    text = str(value)
    text = re.sub(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
                  "[已隐藏]", text, flags=re.S)
    text = re.sub(r"\b(?:ghp_|github_pat_|sk-proj-|sk-ant-)[A-Za-z0-9_-]{24,}", "[已隐藏]", text)
    text = re.sub(r"(?i)(/ai/join/[A-Za-z0-9_-]+)#[^\s\"'<>]+", r"\1#[已隐藏]", text)
    text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [已隐藏]", text)
    return re.sub(r"(?i)((?:token|rotation_token|access_token|refresh_token|api[_-]?key|code|password|passwd|secret|密码|令牌)\s*[=:：]\s*)[\"']?[^\s,;\"'<>]+",
                  r"\1[已隐藏]", text)


def public_value(value):
    """Do not expose access credentials in CLI output or error summaries."""
    if isinstance(value, dict):
        return {key: ("[已隐藏]" if key.lower() in SECRET_FIELDS else public_value(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [public_value(item) for item in value]
    return safe_error(value) if isinstance(value, str) else value


def operation_key(name, parameters):
    return {"name": name, "parameters": json.loads(json.dumps(parameters, ensure_ascii=False, default=str))}


def durable_write(state, api, operation=None, route=None, prepare=None, local_update=None):
    """Persist the exact request, including file bytes, before any business write."""
    data = state.data
    pending = data.get("pending_write")
    if pending and getattr(state,'supersedes_request_id',None)==pending['body']['request_id']:
        archive=data.setdefault('superseded_writes',{})
        archive.setdefault(pending['body']['request_id'],deepcopy(pending))
        data.pop('pending_write')
        state.save()
        pending=None
    if pending:
        if operation is not None and pending["operation"] != operation:
            raise ValueError("此窗口有待确认写入，请先运行 pending 查看，再用 retry 重试原请求")
    else:
        if operation is None:
            raise ValueError("此窗口没有待确认写入")
        body = prepare()
        if getattr(state,'supersedes_request_id',None) and 'supersedes_request_id' not in body:
            body['supersedes_request_id']=state.supersedes_request_id
        body["request_id"] = "write-" + secrets.token_hex(16)
        pending = {"operation": operation, "route": route, "body": body, "local_update": local_update or {}}
        data["pending_write"] = pending
        state.save()
    try:
        value = api.call(pending["route"], data["token"], pending["body"])
    except RequestError as error:
        # Only a terminal receipt for this exact request resolves a failed write.
        if (error.value.get("request_id") == pending["body"]["request_id"] and error.value.get("status") == "rejected"
                and 400 <= error.status < 500 and error.status not in {408, 429}):
            data["last_write"] = {"operation": pending["operation"]["name"],
                                  "request_id": pending["body"]["request_id"], "status": "rejected"}
            data.pop("pending_write", None)
            state.save()
        raise
    if value.get("status") == "pending":
        raise RuntimeError("操作仍待确认；原请求已保留，请稍后运行 retry")
    data.update(pending.get("local_update") or {})
    data["last_write"] = {"operation": pending["operation"]["name"], "request_id": pending["body"]["request_id"],
                          "status": value.get("status", "applied"), "result": public_value(value)}
    data.pop("pending_write", None)
    state.save()
    return value


def pending_summary(state):
    pending = state.data.get("pending_write")
    if not pending:
        last = state.data.get("last_write") or {}
        return {"pending": False, "runner_reports": len(state.data.get("runner_reports", [])),
                "local_execution": public_value(state.data.get("attempt")),
                "last_request": {key: last.get(key) for key in ("operation", "request_id", "status")}}
    return {"pending": True, "operation": pending["operation"]["name"], "route": pending["route"],
            "request_id": pending["body"]["request_id"], "next": "运行 retry，重放已保存的原始请求"}


def task_options(api, token, project=None, full=False):
    query = {"project": project} if project else {}
    if full:
        query["full"] = "1"
    route = "task-options" + ("?" + urlencode(query) if query else "")
    return api.call(route, token)


def onboarding_summary(api, token):
    try:
        options = task_options(api, token)
        return {"task_counts": options.get("counts", {}), "capability_hints": options.get("capability_hints", []),
                "next_commands": ["whoami", "capabilities", "declare --project <项目> --capability <技能> --evidence <依据>",
                                  "tasks", "show <任务>", "claim <任务>"]}
    except (OSError, HTTPException, ValueError, RuntimeError):
        return {"next_commands": ["whoami", "capabilities", "tasks"], "notice": "窗口已激活；任务概要暂未取得，可运行 tasks 重试"}


def source(args):
    variable = {"codex": "CODEX_THREAD_ID", "claude": "CLAUDE_SESSION_ID", "gemini": "GEMINI_SESSION_ID"}.get(args.platform)
    session = args.session or (os.environ.get(variable) if variable else "")
    profile = {"platform": args.platform, "session": session or ("local-" + secrets.token_hex(16)),
            "session_source": "reported" if session else "local", "model": args.model or "unknown",
            "environment": args.environment or sys.platform, "device": socket.gethostname(),
            "directory": str(Path.cwd()), "url": args.link or "", "parent": None}
    if getattr(args, "window_name", None) is not None:
        profile["window_name"] = args.window_name
    return profile


def endpoint(state, args):
    return Pool(state.data["url"], state.data.get("certificate_sha256"), args.allow_loopback, state.data.get("connect_host"))


def whoami(state, api):
    """Read the platform registration; never inspect a host application's chat UI."""
    profile = api.call("identity", state.data["token"])
    if not isinstance(profile, dict) or not isinstance(profile.get("identity"), str) or not profile["identity"]:
        raise ValueError("服务身份回执不完整，请稍后运行 whoami")
    binding = profile.get("binding") or {}
    result = {"window_name": binding.get("window_name"), "window": binding.get("window") or state.data.get("window"),
            "executor_id": profile["identity"], "owner": binding.get("owner"), "projects": profile.get("projects", []),
            "name_source": "platform-registration", "chat_title_auto_detected": False}
    for key in ("default_context", "active_task_contexts"):
        if key in profile:
            result[key] = profile[key]
    return result


def active_identity_fields(state, api):
    """An optional read cannot undo a successful activation or metadata write."""
    try:
        current = whoami(state, api)
        return {"window_name": current["window_name"], "projects": current["projects"], "self": current}
    except (OSError, HTTPException, ValueError, RuntimeError, KeyError, TypeError):
        return {"window_name": None, "projects": None, "self": None,
                "identity_notice": "窗口身份摘要暂未取得；保留原凭据，稍后运行 whoami，不要重新登记或兑换邀请"}


def rename(state, api, name):
    if not isinstance(name, str) or not name.strip():
        raise ValueError("窗口名称不能为空")
    local_update = {}
    def prepare():
        binding = api.call("identity", state.data["token"])["binding"]
        body = {key: binding[key] for key in ("session", "model", "environment")}
        body["window_name"] = name
        local_update["source"] = {**state.data.get("source", {}), **body}
        return body
    result = durable_write(state, api, operation_key("rename", {"window_name": name}), "executor-sync", prepare, local_update)
    return {"status": result.get("status", "applied"),
            "request_id": result.get("request_id") or state.data["last_write"]["request_id"],
            **active_identity_fields(state, api)}


def trust_update(state, args):
    """Operator-supplied trust only; never learn a new pin from an untrusted endpoint."""
    data = state.data
    if not data.get("token") or not data.get("executor_id"):
        raise ValueError("请使用已激活窗口的原凭据文件更新指纹")
    api = Pool(data["url"], args.sha256, False, data.get("connect_host"))
    # Pool.call verifies chain, validity, hostname and pin before constructing Authorization.
    identity = api.call("identity", data["token"])
    if identity.get("identity") != data["executor_id"]:
        raise ValueError("新证书端点的身份回执与当前窗口不符，原信任保持")
    data["certificate_sha256"] = api.pin
    state.save()
    return {"status": "updated", "window": data.get("window"), "certificate_sha256": api.pin,
            "message": "服务身份已核验，沿用原窗口和原凭据；未重新登记"}


def finish_activation(state, api):
    data = state.data
    token = data.get("rotation_token", data.get("token"))
    data.setdefault("activation_request", "activate-" + secrets.token_hex(16))
    state.save()
    result = api.call("ai-activate", token, {"request_id": data["activation_request"], "registration_id": data["registration_id"]})
    data["token"] = token
    data.update({k: result[k] for k in ("executor_id", "window", "expires")})
    for key in ("request", "registration_id", "rotation_token", "activation_request"):
        data.pop(key, None)
    state.save()
    return {"status": "active", "window": data["window"], "executor_id": data["executor_id"],
            "credential_location": str(state.path), **active_identity_fields(state, api),
            "next": "先查看能力要求并申报实际具备的技能，再按授权领取", "source": data.get("source"),
            **onboarding_summary(api, data["token"])}


def enroll(state, args):
    data = state.data
    has_invitation = bool(args.invite or getattr(args, "invite_url", None))
    if data and has_invitation and "request" not in data:
        raise ValueError("此凭据文件已绑定窗口，新窗口请使用不同文件")
    if not data:
        if not has_invitation:
            raise ValueError("请提供 --invite 文件路径（或 -）或 --invite-url 完整邀请链接")
        value = load_invitation(args)
        profile = source(args)
        data.update(url=value["url"], certificate_sha256=value.get("certificate_sha256"), connect_host=value.get("connect_host"), source=profile,
                    request={"request_id": "enroll-" + secrets.token_hex(16), "invite_id": value["id"],
                             "code": value["code"], "recovery": secrets.token_urlsafe(32), "source": profile})
        state.save()
    api = endpoint(state, args)
    if "request" in data and "token" not in data:
        result = api.call("ai-prepare", body=data["request"])
        data.update(token=result["token"], registration_id=result["registration_id"])
        state.save()
    if "registration_id" in data:
        return finish_activation(state, api)
    return {"status": "active", "window": data["window"], "executor_id": data["executor_id"],
            "credential_location": str(state.path), **active_identity_fields(state, api), "source": data.get("source"),
            **onboarding_summary(api, data["token"])}


def sync(state, args):
    api = endpoint(state, args)
    if server_features(api, state.data["token"])["security_schema"] >= 5:
        renamed = rename(state, api, args.window_name) if args.window_name is not None else None
        if args.model is None and args.environment is None:
            return renamed or whoami(state, api)
        options = argparse.Namespace(action="context", operation="save", context_id=None, platform=None, adapter=None,
                                     model=args.model, environment=args.environment, reasoning=None, tools_version=None,
                                     permissions_version=None, make_default=True, supersedes_request_id=None)
        return execution_command(state, api, options)
    def prepare():
        binding = api.call("identity", state.data["token"])["binding"]
        body = {"session": binding["session"], "model": args.model or binding["model"],
                "environment": args.environment or binding["environment"]}
        if args.window_name is not None:
            body["window_name"] = args.window_name
        return body
    durable_write(state, api, operation_key("sync", {key: getattr(args, key) for key in ("window_name", "model", "environment")}),
                  "executor-sync", prepare)
    current = api.call("identity", state.data["token"])["binding"]
    state.data.setdefault("source", {}).update({key: current[key] for key in ("session", "model", "environment", "window_name") if key in current})
    state.save()
    return {"status": "active", "window": current["window"], "window_name": current.get("window_name"),
            "executor_id": state.data["executor_id"]}


def activate(state, args):
    if args.bundle:
        value = bundle(args.bundle)
        if state.data and state.data.get("executor_id") != value["executor_id"]:
            raise ValueError("轮换凭据与此窗口不符")
        state.data.update(url=value["url"], certificate_sha256=value.get("certificate_sha256"),
                          connect_host=value.get("connect_host"),
                          registration_id=value["registration_id"], rotation_token=value["token"])
        state.save()
    return finish_activation(state, endpoint(state, args))


def declared_capability(state, api, args):
    def prepare():
        profile = api.call("identity", state.data["token"])
        records = api.call("capabilities", state.data["token"])["capabilities"]
        old = next((row for row in records if row["project_id"] == args.project and row["id"] == args.capability), {})
        if old and (old.get("kind") != "skill" or old.get("level") != "declared"):
            raise ValueError("此能力已有环境或核实记录，请通过能力页面按证据流程维护；declare 只维护已申报技能")
        environment = args.environment or (profile.get("binding") or {}).get("environment")
        if not environment:
            raise ValueError("请用 --environment 填写实际能力所在环境")
        if not 1 <= args.days <= 365:
            raise ValueError("能力声明有效期须为 1 至 365 天")
        return {"project_id": args.project, "name": profile["identity"], "capability": args.capability,
                "kind": "skill", "value": args.value, "level": "declared", "environment": environment,
                "evidence": {"note": args.evidence, "sha256": args.evidence_sha256 or ""},
                "expires": int(time.time()) + args.days * 86400, "version": old.get("version", 0)}
    parameters = {key: getattr(args, key) for key in ("project", "capability", "value", "environment", "evidence", "evidence_sha256", "days")}
    return durable_write(state, api, operation_key("declare", parameters), "capability-save", prepare)


def visible_tasks(state, api, args):
    full = getattr(args, "full", False)
    wire_full = full and supported(server_features(api, state.data["token"]), "list-summary")
    data = task_options(api, state.data["token"], args.project, full=wire_full)
    if args.claimable:
        data = {**data, "tasks": [row for row in data.get("tasks", []) if (row.get("qualification") or {}).get("eligible")]}
    counts = data.get("counts") or {}
    data["message"] = f'可见 {counts.get("visible", len(data.get("tasks", [])))} 项，可领取 {counts.get("claimable", 0)} 项'
    if not counts.get("claimable") and counts.get("visible"):
        data["next"] = "查看 missing_summary；技能缺项可先运行 capabilities，再用 declare 申报实际能力"
    if getattr(args, "full", False):
        return data
    rows = []
    for row in data.get("tasks", []):
        qualification = row.get("qualification") or {}
        rows.append({**{key: row[key] for key in ("task_id", "title", "project_id", "stage") if key in row},
                     "claimable": bool(qualification.get("eligible")), "missing": qualification.get("missing", [])})
    current = active_identity_fields(state, api)
    identity = current["self"]
    self_fields = {key: identity[key] for key in ("window_name", "window", "executor_id")} if identity else None
    return {**{key: value for key, value in data.items() if key not in {"tasks", "capability_hints"}}, "tasks": rows,
            "self": self_fields, **({"self_notice": current["identity_notice"]} if not identity else {}),
            "details": "tasks --full 查看完整合同与能力要求；show <任务> 查看单项详情"}


def request_capability(state, api, args):
    parameters = {key: getattr(args, key) for key in ("project", "capability", "kind", "value", "environment",
                                                     "evidence", "evidence_sha256", "days")}
    def prepare():
        if not re.fullmatch(r"[a-fA-F0-9]{64}", args.evidence_sha256):
            raise ValueError("核实申请须提供实际证据文件的 SHA256（64 位十六进制）")
        if not 1 <= args.days <= 366:
            raise ValueError("能力核实有效期须为 1 至 366 天")
        identity = api.call("identity", state.data["token"])
        environment = args.environment or (identity.get("binding") or {}).get("environment") or "human"
        return {"project_id": args.project, "capability": args.capability, "kind": args.kind, "value": args.value,
                "evidence": {"note": args.evidence, "sha256": args.evidence_sha256.lower()},
                "environment": environment, "expires": int(time.time()) + args.days * 86400}
    return durable_write(state, api, operation_key("capability-request", parameters), "capability-request", prepare)


def resolve_capability(state, api, args):
    parameters = {key: getattr(args, key) for key in ("verification_id", "decision", "level", "reason")}
    def prepare():
        rows = api.call("capability-requests", state.data["token"])
        row = next((row for row in rows if row["id"] == args.verification_id), None)
        if not row:
            raise ValueError("未找到当前身份可查看的能力核实申请，请先运行 capabilities requests")
        return {"verification_id": row["id"], "version": row["version"], "decision": args.decision,
                "level": args.level, "reason": args.reason}
    return durable_write(state, api, operation_key("capability-resolve", parameters), "capability-resolve", prepare)


def own_claim(state, api, task_id, claim_id=None, allow_cleanup=False):
    from_cleanup = False
    try:
        view = api.call("tasks/" + quote(task_id, safe=""), state.data["token"])
    except RequestError as error:
        if not allow_cleanup or error.status not in {403, 404}:
            raise
        view = api.call("cleanup", state.data["token"])
        from_cleanup = True
    identity = state.data.get("executor_id") or api.call("identity", state.data["token"])["identity"]
    claims = [row for row in view["claims"] if row["origin"] == identity and row["L"] == "active"
              and (not claim_id or row["claim_id"] == claim_id) and (not from_cleanup or row.get("task_id") == task_id)]
    if len(claims) != 1:
        raise ValueError("未找到当前窗口的唯一活动领取；请先用 show 核对任务和 --claim-id")
    claim = claims[0]
    return {"claim_id": claim["claim_id"], "epoch": claim["epoch"], "scope_version": claim["W"]["scope"]}


def claim_task(state, api, args):
    def prepare():
        task = api.call("tasks/" + quote(args.task, safe=""), state.data["token"])["task"]
        body = {key: task[key] for key in ("task_id", "version", "scope_version")}
        features = server_features(api, state.data["token"])
        if features["security_schema"] >= 5:
            body["execution_protocol"] = 5
            context_id, context_version = getattr(args, "context_id", None), getattr(args, "context_version", None)
            if (context_id is None) != (context_version is None):
                raise ValueError("指定领取配置时须同时提供 --context-id 和 --context-version")
            if context_id is not None:
                body.update(context_id=context_id, context_version=context_version)
        elif getattr(args, "context_id", None) is not None:
            raise ValueError("旧服务不支持指定执行配置，未降级领取")
        return body
    parameters = {"task": args.task}
    for key in ("context_id", "context_version"):
        if getattr(args, key, None) is not None:
            parameters[key] = getattr(args, key)
    return durable_write(state, api, operation_key("claim", parameters), "claim", prepare)


def create_task(state, api, args):
    def prepare():
        path = args.contract.expanduser().absolute()
        if is_link(path) or not path.is_file() or path.resolve() == state.path.resolve() or path.stat().st_size > 1024 * 1024:
            raise ValueError("任务合同须为不超过 1 MiB 的普通 JSON 文件")
        body = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(body, dict) or "request_id" in body:
            raise ValueError("任务合同须为 JSON 对象，且不能包含 request_id")
        return body
    return durable_write(state, api, operation_key("create", {"contract": str(args.contract.expanduser().absolute())}),
                         "register", prepare)


def task_publication(state, api, args):
    def prepare():
        task = api.call("tasks/" + quote(args.task, safe=""), state.data["token"])["task"]
        return {**{key: task[key] for key in ("task_id", "version", "scope_version")}, "reason": args.reason}
    route = "task-publish" if args.action == "publish" else "task-hold"
    return durable_write(state, api, operation_key(args.action, {"task": args.task, "reason": args.reason}), route, prepare)


def update_feedback(state, api, args):
    def prepare():
        data = api.call("collaboration?" + urlencode({"project": args.project}), state.data["token"])
        current = next((row for row in data["feedback"] if row["id"] == args.feedback_id), None)
        if current is None:
            raise ValueError("当前项目中未找到可处理的反馈")
        latest = current.get("updates", [])[-1] if current.get("updates") else {}
        metrics = latest.get("metrics", [])
        if args.metrics:
            if not args.metrics.is_file() or args.metrics.stat().st_size > 128 * 1024:
                raise ValueError("指标须为不超过 128 KiB 的 JSON 数组文件")
            metrics = json.loads(args.metrics.read_text(encoding="utf-8-sig"))
            if not isinstance(metrics, list):
                raise ValueError("指标文件须为 JSON 数组")
        def chosen(name, default=""):
            provided = getattr(args, name)
            return provided if provided is not None else latest.get(name, current.get(name, default)) or default
        return {"project_id": args.project, "id": current["id"], "version": current["version"], "status": args.status,
                "linked_task": args.linked_task if args.linked_task is not None else current.get("linked_task") or "",
                "duplicate": chosen("duplicate"), "reason": args.reason, "evidence": chosen("evidence"),
                "metrics": metrics, "lesson": chosen("lesson"), "limits": chosen("limits")}
    parameters = {key: getattr(args, key) for key in ("project", "feedback_id", "status", "reason", "linked_task", "duplicate",
                                                     "evidence", "metrics", "lesson", "limits")}
    return durable_write(state, api, operation_key("feedback-update", parameters), "feedback-update", prepare)


def relative_artifact(path):
    if (not isinstance(path, str) or not path or len(path) > 700 or "\\" in path or ":" in path or "\0" in path
            or any(ord(char) < 32 or char in '<>"|?*' for char in path)
            or any(part in {"", ".", ".."} or part.endswith((" ", ".")) for part in path.split("/"))):
        raise ValueError("文件路径须为无越界片段的相对路径")
    # Block Windows device names even when the client runs on another OS.
    for part in path.split("/"):
        stem = part.split(".", 1)[0].upper()
        if stem in {"CON", "PRN", "AUX", "NUL"} or re.fullmatch(r"(?:COM|LPT)[1-9]", stem):
            raise ValueError("文件路径包含保留设备名称")
    return PurePosixPath(path)


def is_link(path):
    return path.is_symlink() or (path.exists() and bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400))


def checked_target(directory, remote_path):
    relative = relative_artifact(remote_path)
    root = directory.expanduser().absolute()
    for parent in (root, *root.parents):
        if is_link(parent):
            raise ValueError("下载目录不能经过符号链接或重解析点")
    root.mkdir(parents=True, exist_ok=True)
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        if is_link(current):
            raise ValueError("下载路径不能经过符号链接或重解析点")
        current.mkdir(exist_ok=True)
    target = current / relative.name
    if is_link(target) or target.exists() and not target.is_file():
        raise ValueError("下载目标须为普通文件")
    return target


def verified_bytes(api, token, ref, limit=None):
    relative_artifact(ref["path"])
    expected = ref.get("sha256", "")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
        raise ValueError("下载需要服务记录中的 SHA256，或明确提供 --sha256")
    route = "artifact"
    options = {"response_format": "bytes"}
    if limit is not None:
        options["response_limit"] = limit
    raw = api.call(route + "?" + urlencode({"path": ref["path"]}), token, **options)
    if limit is not None and len(raw) > limit:
        raise DownloadBudgetError("file_bytes", "文件超过本次下载预算，已核验文件保留")
    if hashlib.sha256(raw).hexdigest() != expected.lower():
        raise ValueError("下载文件 SHA256 不符，未保存文件")
    return raw


def save_artifact(directory, ref, raw):
    target = checked_target(directory, ref["path"])
    if target.exists():
        if target.read_bytes() != raw:
            raise ValueError("下载目标已有不同内容，请选择新目录：" + str(target))
        return str(target)
    fd, temporary = tempfile.mkstemp(prefix=".download-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        # Recheck the destination after the network read and before replacement.
        checked_target(directory, ref["path"])
        if target.exists():
            raise ValueError("下载目标在保存前已出现，请重试并核对现有文件")
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return str(target)


def frozen_inputs(state, view, args):
    task = view["task"]
    claims = view.get("claims", [])
    selected = getattr(args, "claim_id", None)
    if selected:
        matches = [row for row in claims if row["claim_id"] == selected]
        if len(matches) != 1:
            raise ValueError("指定领取未列在当前授权资料中，请先核对 show")
        claim = matches[0]
    else:
        own = [row for row in claims if row.get("origin") == state.data.get("executor_id") and row.get("L") == "active"]
        if len(own) > 1:
            raise ValueError("存在多份活动领取，请明确 --claim-id，避免混合冻结输入")
        claim = own[0] if own else None
    binding = {"task_id": task["task_id"], "scope_version": claim["W"]["scope"] if claim else task["scope_version"],
               "claim_id": claim["claim_id"] if claim else None}
    refs = [{"path": path, "sha256": sha.lower()} for path, sha in (claim["inputs"] if claim else task["inputs"]).items()]
    seen = set()
    for ref in refs:
        relative_artifact(ref["path"])
        if not re.fullmatch(r"[a-f0-9]{64}", ref["sha256"]) or ref["path"].casefold() in seen:
            raise ValueError("冻结输入清单包含无效摘要或大小写冲突路径")
        seen.add(ref["path"].casefold())
    return binding, sorted(refs, key=lambda ref: ref["path"])


def progress_target(directory, binding, checksum):
    key = hashlib.sha256(json.dumps({**binding, "manifest_sha256": checksum}, sort_keys=True).encode()).hexdigest()[:24]
    return checked_target(directory, ".taskpool-inputs-" + key + ".json")


def save_input_progress(directory, binding, checksum, records):
    target = progress_target(directory, binding, checksum)
    content = {**binding, "manifest_sha256": checksum, "verified": records}
    if target.exists():
        if target.stat().st_size > DOWNLOAD_LIMITS["manifest_bytes"]:
            raise ValueError("原续行记录过大，已保留；请检查或选择独立目录")
        previous = json.loads(target.read_text(encoding="utf-8"))
        if any(previous.get(key) != value for key, value in {**binding, "manifest_sha256": checksum}.items()):
            raise ValueError("原续行记录不属于本冻结清单，未覆盖")
        if not records:
            return  # A failed new attempt must not erase earlier verified progress.
    fd, temporary = tempfile.mkstemp(prefix=".inputs-progress-", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(content, stream, ensure_ascii=False, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        checked_target(directory, target.name)
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)


def existing_verified(directory, ref, limit):
    target = checked_target(directory, ref["path"])
    if not target.exists():
        return None
    if target.stat().st_size > limit:
        raise ValueError("已有文件超过预算，保留原文件；请核对下载目录")
    with target.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != ref["sha256"].lower():
        raise ValueError("已有文件 SHA256 与冻结摘要不同，保留原文件；请核对或选择新目录")
    return {**ref, "bytes": target.stat().st_size, "saved_to": str(target), "reused": True}


def validate_input_zip(stream, binding, refs, limits):
    archive = zipfile.ZipFile(stream)
    try:
        members, names = archive.infolist(), set()
        if len(members) > limits["files"] + 1:
            raise DownloadBudgetError("files", "输入包文件数量超过预算，未降级下载")
        by_name = {}
        for info in members:
            relative_artifact(info.filename)
            folded = info.filename.casefold()
            mode = (info.external_attr >> 16) & 0xFFFF
            if (folded in names or info.is_dir() or stat.S_IFMT(mode) not in {0, stat.S_IFREG} or
                    info.flag_bits & 1 or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}):
                raise ValueError("输入包含重复、链接、设备、加密或无效成员，未降级下载")
            names.add(folded)
            by_name[info.filename] = info
        manifest_info = by_name.get("manifest.json")
        if manifest_info is None or manifest_info.file_size > limits["manifest_bytes"]:
            raise ValueError("输入包需要且仅允许一份有界 manifest.json")
        raw = archive.read(manifest_info)
        if len(raw) > limits["manifest_bytes"]:
            raise ValueError("输入包清单超过预算")
        checksum = hashlib.sha256(raw).hexdigest()
        header_sha = getattr(stream, "manifest_sha256", None)
        if header_sha is not None and (not isinstance(header_sha, str) or not re.fullmatch(r"[A-Fa-f0-9]{64}", header_sha) or header_sha.lower() != checksum):
            raise ValueError("输入包清单与响应摘要不一致，未降级下载")
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("输入包清单含重复 JSON 字段")
                result[key] = value
            return result
        manifest = json.loads(raw, object_pairs_hook=unique_object)
        if (not isinstance(manifest, dict) or type(manifest.get("scope_version")) is not int or
                any(manifest.get(key) != value for key, value in binding.items())):
            raise ValueError("输入包任务、领取或范围与冻结清单不一致，未保存")
        rows = manifest.get("inputs")
        if not isinstance(rows, list) or len(rows) != len(refs) or len(rows) > limits["files"]:
            raise ValueError("输入包文件集合与冻结输入不一致")
        expected = {ref["path"]: ref["sha256"].lower() for ref in refs}
        seen, total, validated = set(), 0, []
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("输入包逐文件清单无效")
            path, size, sha = row.get("path"), row.get("bytes"), row.get("sha256")
            relative_artifact(path)
            member = "files/" + path
            if (path in seen or path not in expected or not isinstance(sha, str) or sha.lower() != expected[path] or
                    row.get("member") != member or member not in by_name or type(size) is not int or size < 0 or
                    by_name[member].file_size != size):
                raise ValueError("输入包成员、大小或摘要与冻结清单不一致")
            if size > limits["file_bytes"]:
                raise DownloadBudgetError("file_bytes", "单文件超过输入下载预算，未降级下载")
            total += size
            if total > limits["total_bytes"]:
                raise DownloadBudgetError("total_bytes", "输入展开总量超过预算，已核验结果保留")
            seen.add(path)
            validated.append({"path": path, "sha256": sha.lower(), "bytes": size, "member": member})
        if set(by_name) != {"manifest.json", *(row["member"] for row in validated)}:
            raise ValueError("输入包含未授权的额外成员")
        return archive, checksum, validated
    except BaseException:
        archive.close()
        raise


def download_inputs(state, api, args, view):
    token = state.data["token"]
    features = server_features(api, token)
    limits = download_limits(features, args)
    binding, refs = frozen_inputs(state, view, args)
    if len(refs) > limits["files"]:
        raise DownloadBudgetError("files", "冻结输入数量超过本机与服务共同预算；请配置预算或分批下载，领取保持")
    use_package = supported(features, "input-package")
    if not use_package and not (features.get("legacy_confirmed") or "input-package" in features.get("features", {})):
        raise ValueError("服务未明确声明输入包是否支持，未降级")
    output = []
    if use_package:
        query = {key: value for key, value in binding.items() if value is not None}
        try:
            stream = api.call("input-package?" + urlencode(query), token, response_format="file", response_limit=limits["zip_bytes"])
        except RequestError as error:
            if not (error.status == 404 and error.value.get("code") == "unsupported_interface" or error.status == 413):
                raise
            use_package = False
        except DownloadBudgetError as error:
            if error.budget != "zip_bytes":
                raise
            use_package = False
        if use_package:
            stream = BytesIO(stream) if isinstance(stream, bytes) else stream
            with stream:
                archive, checksum, rows = validate_input_zip(stream, binding, refs, limits)
                with archive:
                    save_input_progress(args.output, binding, checksum, output)
                    for row in rows:
                        ref = {key: row[key] for key in ("path", "sha256")}
                        record = existing_verified(args.output, ref, limits["file_bytes"])
                        if record is not None and record["bytes"] != row["bytes"]:
                            raise ValueError("已有核验文件长度与包清单不一致，未降级或覆盖")
                        if record is None:
                            with archive.open(row["member"]) as member:
                                raw = member.read(row["bytes"] + 1)
                            if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                                raise ValueError("输入文件长度或 SHA256 不符；保留已核验文件，未降级")
                            record = {**ref, "bytes": len(raw), "saved_to": save_artifact(args.output, ref, raw), "reused": False}
                        output.append(record)
                        save_input_progress(args.output, binding, checksum, output)
            return {**binding, "mode": "input-package", "manifest_sha256": checksum, "verified_files": len(output), "files": output}
    checksum = hashlib.sha256(json.dumps({**binding, "inputs": refs}, sort_keys=True).encode()).hexdigest()
    save_input_progress(args.output, binding, checksum, output)
    total = 0
    for ref in refs:
        record = existing_verified(args.output, ref, min(limits["file_bytes"], max(1, limits["total_bytes"] - total)))
        if record is None:
            raw = verified_bytes(api, token, ref, min(limits["file_bytes"], max(1, limits["total_bytes"] - total)))
            if total + len(raw) > limits["total_bytes"]:
                raise DownloadBudgetError("total_bytes", "逐项下载总量超过预算；已核验结果和领取保持")
            record = {**ref, "bytes": len(raw), "saved_to": save_artifact(args.output, ref, raw), "reused": False}
        total += record["bytes"]
        if total > limits["total_bytes"]:
            raise DownloadBudgetError("total_bytes", "逐项下载总量超过预算；已核验结果保留")
        output.append(record)
        save_input_progress(args.output, binding, checksum, output)
    return {**binding, "mode": "individual", "manifest_sha256": checksum, "verified_files": len(output), "files": output}


def download_task(state, api, args):
    token = state.data["token"]
    if getattr(args, "inputs", False) and args.sha256:
        raise ValueError("--inputs 使用冻结清单逐项摘要；单文件 --sha256 请配 --artifact")
    view = api.call("tasks/" + quote(args.task, safe=""), token)
    if getattr(args, "inputs", False):
        return download_inputs(state, api, args, view)
    limits = download_limits(server_features(api, token), args)
    if args.artifact and args.sha256:
        known = dict(view["task"]["inputs"])
        for claim in view.get("claims", []):
            known.update(claim.get("inputs", {}))
        if args.artifact in known and known[args.artifact].lower() != args.sha256.lower():
            raise ValueError("提供的 SHA256 与冻结输入不一致")
        ref = {"path": args.artifact, "sha256": args.sha256}
        raw = verified_bytes(api, token, ref, min(limits["file_bytes"], limits["total_bytes"]))
        return {"task_id": args.task, "verified_files": 1,
                "files": [{**ref, "saved_to": save_artifact(args.output, ref, raw)}]}
    refs = [{"path": path, "sha256": sha} for path, sha in view["task"]["inputs"].items()] + view.get("handoffs", [])
    for claim in view["claims"]:
        refs += [{"path": path, "sha256": sha} for path, sha in claim.get("inputs", {}).items()]
        for revision in claim.get("deliveries", {}).values():
            ref = revision["manifest"]
            refs.append(ref)
            raw = verified_bytes(api, token, ref, limits["json_bytes"])
            manifest = json.loads(raw)
            parent = ref["path"].rsplit("/", 1)[0]
            for item in manifest["outputs"]:
                relative_artifact(item["path"])
                refs.append({"path": parent + "/" + item["path"], "sha256": item["sha256"]})
    by_path = {}
    for ref in refs:
        prior = by_path.setdefault(ref["path"], ref)
        if prior["sha256"].lower() != ref["sha256"].lower():
            raise ValueError("服务返回同一路径的不同指纹，请先核对任务资料")
    if args.artifact:
        ref = by_path.get(args.artifact)
        if args.sha256:
            if ref and ref["sha256"].lower() != args.sha256.lower():
                raise ValueError("提供的 SHA256 与任务资料不一致")
            ref = {"path": args.artifact, "sha256": args.sha256}
        if ref is None:
            raise ValueError("该路径未列在任务资料中，请指定可核对的 --sha256")
        refs = [ref]
    else:
        if args.sha256:
            raise ValueError("--sha256 需要与 --artifact 一起使用")
        refs = list(by_path.values())
    if len(refs) > limits["files"]:
        raise DownloadBudgetError("files", "资料数量超过下载预算，请用 --inputs 或显式 --artifact 分批选择；领取保持")
    output, total = [], 0
    for ref in refs:
        remaining = min(limits["file_bytes"], max(1, limits["total_bytes"] - total))
        record = existing_verified(args.output, ref, remaining)
        if record is None:
            raw = verified_bytes(api, token, ref, remaining)
            record = {**ref, "bytes": len(raw), "saved_to": save_artifact(args.output, ref, raw)}
        total += record["bytes"]
        if total > limits["total_bytes"]:
            raise DownloadBudgetError("total_bytes", "资料总量超过预算；已核验文件与领取保持，请分批选择")
        output.append(record)
    return {"task_id": args.task, "verified_files": len(output), "files": output}


def deliver_task(state, api, args):
    def prepare():
        claim = own_claim(state, api, args.task, args.claim_id)
        files, seen, total = [], set(), 0
        if not 1 <= len(args.file) <= 98:
            raise ValueError("交付须选择 1 至 98 个文件")
        for selected in args.file:
            path = selected.expanduser().absolute()
            if is_link(path) or not path.is_file() or path.resolve() == state.path.resolve():
                raise ValueError("交付只接受普通产物文件，不能选择当前窗口凭据")
            name = path.name
            relative_artifact(name)
            if name.startswith(".") or name.casefold() in seen or name.casefold() in {"manifest.json", "delivery.json"}:
                raise ValueError("产物重名或使用了交付保留名称")
            if total + path.stat().st_size > MAX_TRANSFER - 65536:
                raise ValueError("交付文件总大小超过 8 MiB 预留元数据后的限制")
            raw = path.read_bytes()
            total += len(raw)
            if total > MAX_TRANSFER - 65536:
                raise ValueError("交付文件总大小超过 8 MiB 预留元数据后的限制")
            seen.add(name.casefold())
            files.append({"name": name, "content": base64.b64encode(raw).decode("ascii")})
        body = {**claim, "files": files}
        if args.stop_evidence:
            body["stop_evidence"] = args.stop_evidence
        return body
    parameters = {"task": args.task, "claim_id": args.claim_id, "files": [str(path.expanduser().absolute()) for path in args.file],
                  "stop_evidence": args.stop_evidence}
    return durable_write(state, api, operation_key("deliver", parameters), "deliver-files", prepare)


def stop_or_handoff(state, api, args):
    def prepare():
        body = {**own_claim(state, api, args.task, args.claim_id, allow_cleanup=True), "stop_evidence": args.evidence}
        if args.action == "handoff":
            body["notes"] = args.notes
        return body
    parameters = {"task": args.task, "claim_id": args.claim_id, "evidence": args.evidence}
    if args.action == "handoff":
        parameters["notes"] = args.notes
    return durable_write(state, api, operation_key(args.action, parameters), args.action, prepare)


def resume_task(state, api, args):
    def prepare():
        body=own_claim(state,api,args.task,args.claim_id)
        if server_features(api,state.data['token'])['security_schema']>=5:
            body['execution_protocol']=5
        return body
    return durable_write(state, api, operation_key("resume", {"task": args.task, "claim_id": args.claim_id}),
                         "resume", prepare)


def execution_view(state, api, **query):
    query = {key: value for key, value in query.items() if value is not None}
    value = api.call("execution" + ("?" + urlencode(query) if query else ""), state.data["token"])
    if not isinstance(value, dict):
        raise ValueError("执行查询回执无效")
    return value


def execution_row(view, collection, identifier, version=None):
    rows = [row for row in view.get(collection, []) if row.get("id", row.get("context_id")) == identifier and
            (version is None or row.get("version") == version)]
    if not rows:
        raise ValueError("未找到当前身份可查询的 " + collection + "；请先查看 execution")
    return max(rows, key=lambda row: row.get("version", 0))


def reported_evidence(args):
    note = args.note
    sha = getattr(args, "evidence_sha256", None) or hashlib.sha256(note.encode("utf-8")).hexdigest()
    if not re.fullmatch(r"[A-Fa-f0-9]{64}", sha):
        raise ValueError("证据摘要须为 64 位十六进制；省略时仅计算所填说明的摘要")
    return {"note": note, "sha256": sha.lower()}


def execution_origin(state, api, args):
    action_id = getattr(args, "action_id", None)
    if action_id:
        view = execution_view(state, api, action_id=action_id)
        action = execution_row(view, "actions", action_id)
        origin = {key: action[key] for key in ("task_id", "claim_id", "scope_version", "epoch")}
        supplied = {"task_id": getattr(args, "task", None), "claim_id": getattr(args, "claim_id", None),
                    "scope_version": getattr(args, "scope_version", None), "epoch": getattr(args, "epoch", None)}
        if any(value is not None and value != origin[key] for key, value in supplied.items()):
            raise ValueError("明确提供的任务或领取来源与动作不一致，未提交事实")
        return origin, action
    explicit = {"task_id": getattr(args, "task", None), "claim_id": getattr(args, "claim_id", None),
                "scope_version": getattr(args, "scope_version", None), "epoch": getattr(args, "epoch", None)}
    if all(value is not None for value in explicit.values()):
        return explicit, None
    view = execution_view(state, api, task_id=explicit["task_id"], claim_id=explicit["claim_id"])
    rows = [row for row in view.get("legacy", []) if row.get("claim_id") == explicit["claim_id"]]
    if len(rows) != 1:
        raise ValueError("请提供原领取的 --scope-version 与 --epoch；不会改用当前任务范围")
    row = rows[0]
    return {"task_id": row["task_id"], "claim_id": row["claim_id"],
            "scope_version": row.get("scope_version", row.get("scope")), "epoch": row["epoch"]}, None


def selected_resources(args):
    rows = []
    for key, mode in (("read", "read"), ("write", "write"), ("exclusive", "exclusive")):
        for identifier in getattr(args, key, None) or []:
            if not args.domain:
                raise ValueError("申请资源须明确 --domain（主机／共享存储资源域），不能按本机路径名猜测")
            rows.append({"id": identifier, "mode": mode, "domain": args.domain})
    if len({(row["domain"], row["id"]) for row in rows}) != len(rows):
        raise ValueError("同一资源只能选择一种模式，请一次提交完整集合")
    return rows


def execution_command(state, api, args):
    group, operation = args.action, getattr(args, "operation", None)
    route = {("context", "save"): "context-save", ("segment", "open"): "segment-open",
             ("action", "prepare"): "action-prepare", ("action", "start"): "action-start",
             ("resource", "request"): "resource-request", ("resource", "cancel"): "resource-cancel",
             ("resource", "release"): "resource-release", ("fact", None): "execution-fact",
             ("stash", None): "evidence-stash"}.get((group, operation))
    if route is None:
        return execution_view(state, api, task_id=getattr(args, "task", None), claim_id=getattr(args, "claim_id", None),
                              action_id=getattr(args, "action_id", None))
    require_feature(api, state.data["token"], route)
    parameters = {key: value for key, value in vars(args).items() if key not in {"state", "allow_loopback"}}
    def prepare():
        if route == "context-save":
            view = execution_view(state, api)
            previous = execution_row(view, "contexts", args.context_id) if args.context_id else None
            defaults = (view.get("default_context") or {})
            base = previous or (execution_row(view, "contexts", defaults["context_id"], defaults.get("version")) if defaults.get("context_id") else {})
            config = dict(base.get("config", {}))
            sources = dict(config.get("sources", {}))
            for field in ("platform", "adapter", "model", "reasoning", "tools_version", "permissions_version", "environment"):
                supplied = getattr(args, field, None)
                if supplied is not None:
                    config[field] = supplied
                    sources[field] = "unknown" if supplied in {"", "unknown"} else "reported"
                elif field not in config:
                    config[field], sources[field] = "unknown", "unknown"
            config["sources"] = sources
            config["sources"] = {field: "unknown" if config.get(field) is None or config.get(field) == "" or config.get(field) == "unknown" else "reported"
                                 for field in ("platform", "adapter", "model", "reasoning", "tools_version", "permissions_version", "environment")}
            body = {"context_id": args.context_id, "version": previous["version"] if previous else 0,
                    "config": config, "make_default": args.make_default}
        elif route == "segment-open":
            view = api.call("tasks/" + quote(args.task, safe=""), state.data["token"])
            binding = own_claim(state, api, args.task, args.claim_id)
            model = execution_view(state, api, claim_id=binding["claim_id"])
            default = model.get("default_context") or {}
            context_id = args.context_id or default.get("context_id")
            context = execution_row(model, "contexts", context_id, args.context_version or default.get("version"))
            body = {"task_id": view["task"]["task_id"], **binding, "context_id": context_id,
                    "context_version": context["version"]}
        elif route == "action-prepare":
            view = execution_view(state, api)
            segment = execution_row(view, "segments", args.segment_id)
            body = {"segment_id": segment["id"], "version": segment["version"], "description": args.description,
                    "resources": selected_resources(args), "adapter_id": args.adapter_id}
        elif route == "resource-cancel":
            view = execution_view(state, api)
            request = execution_row(view, "resource_requests", args.resource_request_id)
            body = {"resource_request_id": request["id"], "version": request["version"]}
        elif route in {"resource-request", "action-start", "resource-release"}:
            view = execution_view(state, api, action_id=args.action_id)
            action = execution_row(view, "actions", args.action_id)
            if route == "resource-request":
                body = {"action_id": action["id"], "version": action["version"], "resources": action["resources"]}
            else:
                grant_id = getattr(args, "grant_id", None) or action.get("grant_id")
                grant = execution_row(view, "grants", grant_id)
                body = {"action_id": action["id"], "grant_id": grant["id"], "generation": grant["generation"],
                        "version": action["version"] if route == "action-start" else grant["version"]}
                if route == "resource-release":
                    body.update(evidence=reported_evidence(args), basis=args.basis)
        else:
            origin, action = execution_origin(state, api, args)
            body = {**origin, "action_id": getattr(args, "action_id", None),
                    "reporter_basis": {"kind": args.reporter_kind, "note": args.note}}
            if route == "execution-fact":
                permit = getattr(args, "permit_id", None) or (action or {}).get("permit_id")
                if args.kind == "started" and (not action or not permit):
                    raise ValueError("started 只能回报已有开始许可的动作；此命令不能创建开始授权")
                body.update(kind=args.kind, evidence=reported_evidence(args), permit_id=permit)
                if getattr(args, "blocker_id", None):
                    if args.kind not in {"stopped", "not-started"}:
                        raise ValueError("物理未知占用的核对仅可关联真实停止或未启动确认")
                    body["blocker_ids"] = args.blocker_id
            else:
                files, seen, total = [], set(), 0
                if not 1 <= len(args.file) <= 100:
                    raise ValueError("暂存须选择 1 至 100 个文件")
                for selected in args.file:
                    path = selected.expanduser().absolute()
                    if is_link(path) or not path.is_file() or path.resolve() == state.path.resolve():
                        raise ValueError("暂存只接受普通产物，不能选择窗口凭据或链接")
                    relative_artifact(path.name)
                    if path.name.casefold() in seen:
                        raise ValueError("暂存文件名大小写冲突")
                    total += path.stat().st_size
                    if total > 24 * 1024 * 1024:
                        raise ValueError("暂存展开总量超过原 24 MiB 预算，请分批保留材料")
                    raw = path.read_bytes()
                    files.append({"name": path.name, "sha256": hashlib.sha256(raw).hexdigest(),
                                  "content_base64": base64.b64encode(raw).decode("ascii")})
                    seen.add(path.name.casefold())
                body["files"] = files
                if len(json.dumps(body, ensure_ascii=False).encode()) + 256 > MAX_TRANSFER:
                    raise ValueError("暂存请求超过原 8 MiB 传输预算，请分批暂存；原文件保持")
        if getattr(args, "supersedes_request_id", None):
            body["supersedes_request_id"] = args.supersedes_request_id
        return body
    return durable_write(state, api, operation_key(route, parameters), route, prepare)


def feedback(state, api, args):
    parameters = {key: getattr(args, key) for key in ("project", "task", "kind", "title", "details", "impact", "evidence", "visibility")}
    def prepare():
        return {"project_id": args.project, "task_id": args.task or "", "kind": args.kind, "title": args.title,
                "details": args.details, "impact": args.impact, "evidence": args.evidence or "", "visibility": args.visibility,
                "observed": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    return durable_write(state, api, operation_key("feedback", parameters), "feedback-save", prepare)


def poll(state, api):
    data = state.data
    rid = data.get("poll_request")
    if rid is None:
        rid = "poll-" + secrets.token_hex(16)
        data["poll_request"] = rid
        state.save()
    value = api.call("notices-poll", data["token"], {"request_id": rid, "cursor": data.get("cursor", 0)})
    data.update(cursor=value["cursor"])
    data.pop("poll_request", None)
    state.save()
    return value


def report(api, token, claim, phase, evidence, request):
    return api.call("run-report", token, {"request_id": request, "claim_id": claim["claim_id"], "epoch": claim["epoch"],
                                         "scope_version": claim["W"]["scope"], "state": phase, "evidence": evidence})


def queue_report(state, claim, phase, evidence, request):
    reports = state.data.setdefault("runner_reports", [])
    if not any(row["request_id"] == request for row in reports):
        reports.append({"request_id": request, "claim_id": claim["claim_id"], "epoch": claim["epoch"],
                        "scope_version": claim["W"]["scope"], "state": phase, "evidence": evidence})
        state.save()


def flush_reports(state, api):
    reports = state.data.setdefault("runner_reports", [])
    while reports:
        result = api.call("run-report", state.data["token"], reports[0])
        if result.get("status") in {"pending", "maintenance"}:
            raise RuntimeError("执行回报待确认；已保存原请求，任务不会重新启动")
        reports.pop(0)
        state.save()


def keep_running_reports(state, api):
    try:
        flush_reports(state, api)
        if state.data.get("heartbeat"):
            api.call("runner-heartbeat", state.data["token"], {})
    except (OSError, HTTPException, ValueError, RuntimeError) as error:
        print("服务暂时重连；本机执行继续，原回报已保存：" + safe_error(error), file=sys.stderr, flush=True)


def run_once(state, api):
    data = state.data
    attempt = data.get("attempt")
    if attempt and attempt.get("phase") == "completed":
        flush_reports(state, api)
        result = attempt["result"]
        data.pop("attempt")
        state.save()
        return result
    if attempt and attempt.get("phase") in {"starting", "running"}:
        raise ValueError("上次本机执行仍需核对；不会重复启动。请用 pending 查看进程/输出位置并核对任务页的停止与占用")
    cmd = data.get("command", [])
    if not cmd or not Path(cmd[0]).is_file() or not Path(data["workdir"]).is_dir():
        raise ValueError("请先登记可运行的本机执行入口")
    if attempt:
        event = attempt["notice"]
    else:
        events = poll(state, api)["events"]
        event = next((event for event in events if event["auto"]), None)
        if not event:
            return {"status": "idle", "notices": events}
        attempt = {"notice": event, "phase": "queued"}
        data["attempt"] = attempt
        state.save()
    if server_features(api, data["token"])["security_schema"] >= 5:
        raise ValueError("当前服务使用动作开始许可；请用 context/segment/action/resource 流程取得许可，旧 run 不会重复领取或直接启动程序")
    token = data["token"]
    event_id = event["event_id"]
    api.call("notice-ack", token, {"event_id": event_id, "request_id": "ack-" + event_id})
    attempt.setdefault("claim_request", {**{k: event[k] for k in ("task_id", "version", "scope_version")},
                                          "request_id": "auto-" + event_id, "notice": event_id})
    state.save()
    try:
        claim = api.call("claim", token, attempt["claim_request"])["claim"]
    except RequestError as error:
        if error.status in (403, 404, 409):
            data.pop("attempt")
            state.save()
        raise
    attempt.update(claim=claim["claim_id"], phase="claimed")
    state.save()
    report(api, token, claim, "intent", "本机客户端已持久记录启动意图", "intent-" + event_id)
    payload = json.dumps({"task_id": event["task_id"], "claim": claim, "notice": event_id},
                         ensure_ascii=False).encode("utf-8")
    output_path = state.path.parent / (state.path.name + ".run-" + hashlib.sha256(event_id.encode()).hexdigest()[:16] + ".output")
    attempt.update(phase="starting", output=str(output_path))
    state.save()
    fd = os.open(output_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    with os.fdopen(fd, "w+b") as output:
        # Do not use Popen's context manager: a client exception must not wait on or kill an external task.
        child = subprocess.Popen(cmd, cwd=data["workdir"], stdin=subprocess.PIPE, stdout=output, stderr=subprocess.DEVNULL)
        attempt.update(phase="running", pid=child.pid, started_at=time.time())
        state.save()
        queue_report(state, claim, "started", f"本机执行入口已启动，进程 {child.pid}", "start-" + event_id)
        keep_running_reports(state, api)
        while True:
            try:
                child.communicate(payload, timeout=60)
                break
            except subprocess.TimeoutExpired:
                payload = None
                keep_running_reports(state, api)
        output.seek(0)
        receipt = output.read(65537)
    phase = "finished" if child.returncode == 0 and len(receipt) <= 65536 else "error"
    evidence = f"执行入口退出码 {child.returncode}，输出 SHA256 {hashlib.sha256(receipt).hexdigest()}"
    result = {"status": phase, "task_id": event["task_id"], "claim_id": claim["claim_id"],
              "evidence": evidence, "output": str(output_path)}
    attempt.update(phase="completed", result=result)
    queue_report(state, claim, phase, evidence, "end-" + event_id)
    state.save()
    flush_reports(state, api)
    data.pop("attempt")
    state.save()
    return result


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True, help="此窗口的私有凭据文件")
    parser.add_argument("--allow-loopback", action="store_true", help="允许隔离测试的 HTTP 回环服务")
    parser.add_argument("--supersedes-request-id", help="修正已终局拒绝后的关联新请求；不会改写旧请求")
    commands = parser.add_subparsers(dest="action", required=True)
    create = commands.add_parser("enroll")
    invitation = create.add_mutually_exclusive_group()
    invitation.add_argument("--invite", help="邀请文件路径，- 代表标准输入")
    invitation.add_argument("--invite-url", help="邀请人提供的完整单链接，包括 # 后的校验片段")
    create.add_argument("--platform", default="external", choices=("codex", "claude", "gemini", "external"))
    create.add_argument("--session")
    create.add_argument("--model")
    create.add_argument("--environment")
    create.add_argument("--link")
    create.add_argument("--window-name", help="当前聊天窗口的实际名称或标题")
    update = commands.add_parser("sync", help="同步当前窗口名称、模型或环境")
    update.add_argument("--window-name", help="当前聊天窗口的实际名称或标题")
    update.add_argument("--model")
    update.add_argument("--environment")
    commands.add_parser("whoami", help="只读查看平台登记的窗口名称、编号、身份、责任人与项目")
    rename_parser = commands.add_parser("rename", help="仅修改当前窗口的平台登记名称，保留原会话、模型、环境及责任人")
    rename_parser.add_argument("name")
    rotate = commands.add_parser("activate")
    rotate.add_argument("--bundle")
    tasks = commands.add_parser("tasks", help="查看可见任务、领取资格及能力缺项")
    tasks.add_argument("--project")
    tasks.add_argument("--claimable", action="store_true", help="仅列出可领取任务，保留完整数量与缺项摘要")
    tasks.add_argument("--full", action="store_true", help="输出完整任务合同和能力要求")
    trust = commands.add_parser("trust-update", help="使用管理员独立提供且已核实的新证书 SHA256，沿用原窗口凭据")
    trust.add_argument("--sha256", required=True)
    caps = commands.add_parser("capabilities", help="查看当前窗口的能力记录")
    caps.add_argument("--project")
    cap_commands = caps.add_subparsers(dest="capability_action")
    cap_commands.add_parser("requests", help="查看能力核实申请和可核实身份")
    cap_request = cap_commands.add_parser("request", help="为自己的实际能力提交证据，等待独立核实")
    cap_request.add_argument("--project", required=True)
    cap_request.add_argument("--capability", required=True)
    cap_request.add_argument("--kind", choices=("skill", "environment"), default="skill")
    cap_request.add_argument("--value", default="ok")
    cap_request.add_argument("--environment")
    cap_request.add_argument("--evidence", required=True)
    cap_request.add_argument("--evidence-sha256", required=True)
    cap_request.add_argument("--days", type=int, default=7)
    cap_resolve = cap_commands.add_parser("resolve", help="由有权限的另一位项目管理者或验收人处理核实")
    cap_resolve.add_argument("verification_id")
    cap_resolve.add_argument("--decision", required=True, choices=("approve", "reject"))
    cap_resolve.add_argument("--level", required=True, choices=("probed", "verified"))
    cap_resolve.add_argument("--reason", required=True)
    declare = commands.add_parser("declare", help="申报当前窗口实际具备的技能（declared）")
    declare.add_argument("--project", required=True)
    declare.add_argument("--capability", required=True)
    declare.add_argument("--value", default="ok")
    declare.add_argument("--environment")
    declare.add_argument("--evidence", required=True)
    declare.add_argument("--evidence-sha256")
    declare.add_argument("--days", type=int, default=7)
    show = commands.add_parser("show", help="查看任务详情、领取和资料引用")
    show.add_argument("task")
    take = commands.add_parser("claim", help="按当前版本领取任务")
    take.add_argument("task")
    take.add_argument("--context-id")
    take.add_argument("--context-version", type=int)
    resume = commands.add_parser("resume", help="按当前代次继续执行或开始返修，重新核对权限、并发和资源")
    resume.add_argument("task")
    resume.add_argument("--claim-id")
    create_task_parser = commands.add_parser("create", help="按完整 JSON 合同创建任务，须具备相应权限或明确委托")
    create_task_parser.add_argument("--contract", type=Path, required=True)
    for action, help_text in (("publish", "按当前版本开放任务"), ("hold", "按当前版本暂缓任务")):
        publication = commands.add_parser(action, help=help_text)
        publication.add_argument("task")
        publication.add_argument("--reason", required=True)
    download = commands.add_parser("download", help="下载并校验任务输入、接续资料和交付文件")
    download.add_argument("task")
    download.add_argument("--output", type=Path, required=True)
    selection = download.add_mutually_exclusive_group()
    selection.add_argument("--artifact", help="仅下载指定的服务端相对路径；supplement/ 使用来源资料路由")
    selection.add_argument("--inputs", action="store_true", help="仅下载所选冻结输入，优先安全输入包并保留逐项续行")
    download.add_argument("--claim-id", help="--inputs 选择原领取；省略时优先当前窗口唯一活动领取")
    for flag, destination in (("zip", "zip_bytes"), ("total", "total_bytes"), ("file", "file_bytes")):
        download.add_argument("--max-input-" + flag + "-mib", type=lambda value: int(value) * 1024 * 1024, dest=destination,
                              help="本机下载预算 MiB；仍取与服务公布预算的较小值")
    download.add_argument("--max-input-files", type=int, dest="files")
    download.add_argument("--sha256", help="指定文件的预期 SHA256；默认采用任务记录")
    deliver = commands.add_parser("deliver", help="提交产物，服务端生成与当前领取匹配的交付清单")
    deliver.add_argument("task")
    deliver.add_argument("--file", type=Path, action="append", required=True)
    deliver.add_argument("--claim-id")
    deliver.add_argument("--stop-evidence", help="仅在实际已停止时填写，可与交付一起记录停止")
    for action, help_text in (("stop", "记录真实停止及资源释放依据"), ("handoff", "提交停止证据和接续材料后放回任务")):
        move = commands.add_parser(action, help=help_text)
        move.add_argument("task")
        move.add_argument("--claim-id")
        move.add_argument("--evidence", required=True)
        if action == "handoff":
            move.add_argument("--notes", required=True)
    note = commands.add_parser("feedback", help="记录问题、使用反馈或待验证推测")
    note.add_argument("--project", required=True)
    note.add_argument("--task")
    note.add_argument("--kind", choices=("issue", "feedback", "hypothesis"), default="feedback")
    note.add_argument("--title", required=True)
    note.add_argument("--details", required=True)
    note.add_argument("--impact", required=True)
    note.add_argument("--evidence")
    note.add_argument("--visibility", choices=("project", "restricted"), default="project")
    feedback_update = commands.add_parser("feedback-update", help="按现有记录及业务规则处理反馈")
    feedback_update.add_argument("feedback_id")
    feedback_update.add_argument("--project", required=True)
    feedback_update.add_argument("--status", required=True, choices=("triage", "evidence", "accepted", "working", "review", "verified", "deferred", "duplicate", "declined"))
    feedback_update.add_argument("--reason", required=True)
    feedback_update.add_argument("--linked-task")
    feedback_update.add_argument("--duplicate")
    feedback_update.add_argument("--evidence")
    feedback_update.add_argument("--metrics", type=Path, help="可选 JSON 指标数组文件；省略时保留现有指标")
    feedback_update.add_argument("--lesson")
    feedback_update.add_argument("--limits")
    delegates = commands.add_parser("delegations", help="查看当前窗口的委托范围、期限与状态")
    delegates.add_argument("--project")
    board = commands.add_parser("board", help="读取 Markdown 看板")
    board.add_argument("--output", type=Path)
    commands.add_parser("pending", help="查看待确认写入及原请求编号")
    commands.add_parser("retry", help="使用持久保存的原请求重试待确认写入")
    execution = commands.add_parser("execution", help="查看当前身份可见的配置、执行段、动作、资源和历史事实")
    execution.add_argument("--task")
    execution.add_argument("--claim-id")
    execution.add_argument("--action-id")
    context = commands.add_parser("context", help="执行配置版本；不更改窗口来源或增加权限")
    context_commands = context.add_subparsers(dest="operation", required=True)
    context_commands.add_parser("list")
    save_context = context_commands.add_parser("save")
    save_context.add_argument("--context-id", help="更新该配置的不可变下一版本；省略则创建新配置")
    for field in ("platform", "adapter", "model", "reasoning", "tools-version", "permissions-version", "environment"):
        save_context.add_argument("--" + field)
    save_context.add_argument("--make-default", action="store_true", help="仅供新动作选择，不覆盖旧执行段")
    segment = commands.add_parser("segment")
    segment_commands = segment.add_subparsers(dest="operation", required=True)
    open_segment = segment_commands.add_parser("open")
    open_segment.add_argument("task")
    open_segment.add_argument("--claim-id")
    open_segment.add_argument("--context-id")
    open_segment.add_argument("--context-version", type=int)
    action = commands.add_parser("action")
    action_commands = action.add_subparsers(dest="operation", required=True)
    prepare_action = action_commands.add_parser("prepare")
    prepare_action.add_argument("segment_id")
    prepare_action.add_argument("--description", required=True)
    prepare_action.add_argument("--adapter-id", default="manual")
    prepare_action.add_argument("--domain", help="明确资源域，不从同名路径推断设备身份")
    for mode in ("read", "write", "exclusive"):
        prepare_action.add_argument("--" + mode, action="append", help="合同上界内的资源ID；一次选完整集合")
    start_action = action_commands.add_parser("start", help="取得并持久保存原开始许可，不自动运行外部程序")
    start_action.add_argument("action_id")
    start_action.add_argument("--grant-id")
    resource = commands.add_parser("resource")
    resource_commands = resource.add_subparsers(dest="operation", required=True)
    request_resource = resource_commands.add_parser("request")
    request_resource.add_argument("action_id")
    cancel_resource = resource_commands.add_parser("cancel")
    cancel_resource.add_argument("resource_request_id")
    release_resource = resource_commands.add_parser("release")
    release_resource.add_argument("action_id")
    release_resource.add_argument("--grant-id")
    release_resource.add_argument("--note", required=True)
    release_resource.add_argument("--evidence-sha256")
    release_resource.add_argument("--basis", choices=("adapter-confirmed", "human-isolation", "unconfirmed"), default="unconfirmed")
    for name in ("fact", "stash"):
        command = commands.add_parser(name, help="绑定原执行来源保存事实或产物，不取得新执行权限")
        command.add_argument("task")
        command.add_argument("--claim-id")
        command.add_argument("--scope-version", type=int)
        command.add_argument("--epoch", type=int)
        command.add_argument("--action-id")
        command.add_argument("--note", required=True)
        command.add_argument("--reporter-kind", choices=("owner", "human", "adapter"), default="owner")
        if name == "fact":
            command.add_argument("--kind", choices=("started", "finished", "error", "stopped", "not-started", "unconfirmed"), required=True)
            command.add_argument("--permit-id")
            command.add_argument("--evidence-sha256")
            command.add_argument("--blocker-id", action="append", help="显式关联 execution 显示的旧物理未知记录，不自动推断已停止")
        else:
            command.add_argument("--file", type=Path, action="append", required=True)
    commands.add_parser("poll")
    configure = commands.add_parser("configure")
    configure.add_argument("--limit", type=int, default=1)
    configure.add_argument("--heartbeat", action="store_true")
    configure.add_argument("--workdir", type=Path, default=Path.cwd())
    configure.add_argument("--command", nargs=argparse.REMAINDER)
    run = commands.add_parser("run")
    run.add_argument("--once", action="store_true")
    return parser


def capability_records(state, api, args):
    token = state.data["token"]
    if args.capability_action == "request":
        return request_capability(state, api, args)
    if args.capability_action == "resolve":
        return resolve_capability(state, api, args)
    if args.capability_action == "requests":
        value = api.call("capability-requests", token)
        if args.project:
            value = [row for row in value if row["project_id"] == args.project]
        return value
    value = api.call("capabilities", token)
    if args.project:
        value = {**value, "capabilities": [row for row in value["capabilities"] if row["project_id"] == args.project]}
    return value


def delegation_records(state, api, args):
    value = api.call("delegations", state.data["token"])
    if args.project:
        value = {**value, "delegations": [row for row in value["delegations"] if row["project_id"] == args.project]}
    return value


def read_board(state, api, args):
    value = api.call("board", state.data["token"], response_format="text")
    if args.output:
        ref = {"path": args.output.name, "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest()}
        value = {"saved_to": save_artifact(args.output.parent, ref, value.encode("utf-8")), "sha256": ref["sha256"]}
    return value


def configure_runner(state, api, args):
    token = state.data["token"]
    command = args.command or []
    if command and (not Path(command[0]).is_absolute() or not Path(command[0]).is_file() or
                    Path(command[0]).suffix.lower() in (".bat", ".cmd") or not args.workdir.is_dir()):
        raise ValueError("本机入口须为绝对路径的可执行文件及已存在的工作目录")
    parameters = {"command": command, "workdir": str(args.workdir.resolve()), "limit": args.limit, "heartbeat": args.heartbeat}
    def prepare_configuration():
        settings = api.call("runner", token)["settings"]
        return {"version": settings.get("version", 0), "limit": args.limit, "auto": bool(command),
                "heartbeat": args.heartbeat, "adapter": "local-command" if command else ""}
    return durable_write(state, api, operation_key("configure", parameters), "runner-settings", prepare_configuration,
                         {"command": command, "workdir": str(args.workdir.resolve()), "heartbeat": args.heartbeat})


def run_loop(state, api, args):
    if state.data.get("pending_write"):
        raise ValueError("有待确认写入，请先运行 pending 和 retry，再启动自动执行")
    while True:
        value = run_once(state, api)
        if args.once:
            return value
        print(json.dumps(public_value(value), ensure_ascii=False), flush=True)
        time.sleep(random.uniform(24, 36))


# Commands answered from the credential file alone.  Each entry looks its function up
# when called, so a replaced module-level function is the one that runs.
LOCAL_COMMANDS = {
    "enroll": lambda state, args: enroll(state, args),
    "activate": lambda state, args: activate(state, args),
    "sync": lambda state, args: sync(state, args),
    "pending": lambda state, args: pending_summary(state),
    "trust-update": lambda state, args: trust_update(state, args),
}
EXECUTION_COMMANDS = ("execution", "context", "segment", "action", "resource", "fact", "stash")
# Commands that talk to the service with this window's token; "run" is every remaining one.
SERVICE_COMMANDS = {
    "whoami": lambda state, api, args: whoami(state, api),
    "rename": lambda state, api, args: rename(state, api, args.name),
    **{name: lambda state, api, args: execution_command(state, api, args) for name in EXECUTION_COMMANDS},
    "tasks": lambda state, api, args: visible_tasks(state, api, args),
    "capabilities": lambda state, api, args: capability_records(state, api, args),
    "declare": lambda state, api, args: declared_capability(state, api, args),
    "show": lambda state, api, args: api.call("tasks/" + quote(args.task, safe=""), state.data["token"]),
    "claim": lambda state, api, args: claim_task(state, api, args),
    "resume": lambda state, api, args: resume_task(state, api, args),
    "create": lambda state, api, args: create_task(state, api, args),
    "publish": lambda state, api, args: task_publication(state, api, args),
    "hold": lambda state, api, args: task_publication(state, api, args),
    "download": lambda state, api, args: download_task(state, api, args),
    "deliver": lambda state, api, args: deliver_task(state, api, args),
    "stop": lambda state, api, args: stop_or_handoff(state, api, args),
    "handoff": lambda state, api, args: stop_or_handoff(state, api, args),
    "feedback": lambda state, api, args: feedback(state, api, args),
    "feedback-update": lambda state, api, args: update_feedback(state, api, args),
    "delegations": lambda state, api, args: delegation_records(state, api, args),
    "board": lambda state, api, args: read_board(state, api, args),
    "retry": lambda state, api, args: durable_write(state, api),
    "poll": lambda state, api, args: poll(state, api),
    "configure": lambda state, api, args: configure_runner(state, api, args),
}


def run_command(state, args):
    if args.action in LOCAL_COMMANDS:
        return LOCAL_COMMANDS[args.action](state, args)
    api = endpoint(state, args)
    state.data["token"]  # a credential file without a token ends here, before any request
    return SERVICE_COMMANDS.get(args.action, run_loop)(state, api, args)


def main():
    args = build_parser().parse_args()
    state = None
    try:
        state = State(args.state)
        state.supersedes_request_id=getattr(args,'supersedes_request_id',None)
        with state.exclusive():
            value = run_command(state, args)
            print(value if isinstance(value, str) else json.dumps(public_value(value), ensure_ascii=False, indent=2), flush=True)
        return 0
    except (OSError, HTTPException, ValueError, RuntimeError, KeyError) as error:
        print(safe_error(error), file=sys.stderr)
        if state is not None and state.data.get("pending_write"):
            print("原写入请求和上传内容已保存；运行 pending 查看，再运行 retry 重放原请求。", file=sys.stderr)
        elif state is not None and state.data.get("runner_reports"):
            print("本机执行回报已保存；运行 pending 核对原进程与输出，run --once 仅补报已完成结果，不会再次启动同次执行。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
