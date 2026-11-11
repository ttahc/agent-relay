"""A machine-readable description of the HTTP interface, built from the tables the server routes by.

Every path here comes from the same sets and tables `pool/httpd.py` uses to accept a request, so a
route cannot be added or removed without this description changing. `docs/openapi.json` is the
committed copy; `verify_openapi.py` fails when the two differ.

Request bodies are described only as far as a single table states them: the field names of the
execution and communication writes. Every other write lists `request_id` alone and leaves
its remaining fields open; the AI client manual stays the reference for those. Field types and
response bodies are not described.
"""
import json

from . import __version__

MANUAL = "docs/AI客户端操作.md"
OPEN = "其余字段见 " + MANUAL + "；本说明未逐项列出。"
ERROR = {"$ref": "#/components/responses/Rejected"}


def _body(names=None, optional=(), note=""):
    """A JSON request body. `names` None: only request_id is known and other fields stay open."""
    if names is None:
        schema = {"type": "object", "required": ["request_id"], "properties": {"request_id": {"type": "string"}},
                  "description": OPEN}
    else:
        listed = sorted({*names, *optional})
        schema = {"type": "object", "required": sorted(names), "additionalProperties": False,
                  "properties": {name: ({"type": "string"} if name == "request_id" else {}) for name in listed}}
        if note:
            schema["description"] = note
    return {"required": True, "content": {"application/json": {"schema": schema}}}


def _operation(summary, security, kind="application/json", parameters=(), body=None, tags=(), extra=None):
    content = {kind: {"schema": {"type": "object"} if kind.startswith("application/json") else
                      {"type": "string"} if kind.startswith("text/") else {"type": "string", "format": "binary"}}}
    result = {"summary": summary, "tags": list(tags), "security": [{security: []}] if security else [],
              "responses": {"200": {"description": "成功", "content": content}, "default": ERROR}}
    if parameters:
        result["parameters"] = list(parameters)
    if body:
        result["requestBody"] = body
    result.update(extra or {})
    return result


def _query(name, required=False):
    return {"name": name, "in": "query", "required": required, "schema": {"type": "string"}}


def write_fields():
    """Write action -> (required field names, optional field names), where one table states them."""
    from . import execution
    from 协作沟通 import FIELDS as communication
    known = {}
    optional = {"execution-fact": ("blocker_ids",), "context-save": ("environment_id",),
                "resource-map-save": ("mapping_kind", "storage_domain_id", "evidence")}
    for action, names in execution.FIELDS.items():
        known[action] = ({"request_id", *names.split()}, ("supersedes_request_id", *optional.get(action, ())))
    for action, names in communication.items():
        known[action] = ({"request_id", *names.split()} - ({"id"} if action == "task-message" else set()), ())
    return known


def document():
    from . import httpd, project_capabilities, round_service
    from .service import PUBLIC_ACTIONS
    from .wakeups import MAX_HOLD
    paths = {}
    round_only = {"x-round-only": True}

    for name, (allowed, _, kind, only_round) in sorted(httpd.READ_API.items()):
        paths["/v1/" + name] = {"get": _operation(
            "读取 " + name, "windowToken", kind, [_query(key) for key in sorted(allowed or ())], tags=["read"],
            extra=round_only if only_round else None)}
    for prefix, route in httpd.READ_API_PREFIXES:
        key = route + "_id"
        paths["/v1/" + prefix + "{" + key + "}"] = {"get": _operation(
            "读取单个 " + route, "windowToken", tags=["read"],
            parameters=[{"name": key, "in": "path", "required": True, "schema": {"type": "string"}}])}
    for name in sorted(httpd.READ_ACTIONS - set(httpd.READ_API)):
        if name == "wait":
            paths["/v1/wait"] = {"get": _operation(
                f"保持请求直到本身份的待处理事件变化，最长 {MAX_HOLD} 秒", "windowToken", tags=["read"],
                parameters=[_query("cursor"), {"name": "timeout", "in": "query", "required": False,
                                               "schema": {"type": "integer", "minimum": 0, "maximum": MAX_HOLD}}],
                extra=round_only)}
        elif name == "artifact":
            paths["/v1/artifact"] = {"get": _operation("读取一个有权查看的文件", "windowToken", "application/octet-stream",
                                                      [_query("path", True)], tags=["read"])}
        else:
            paths["/v1/" + name] = {"get": _operation("读取 " + name, "windowToken", tags=["read"])}

    known = write_fields()
    reported = {"$ref": "#/components/parameters/ReportedAt"}
    for name in sorted(PUBLIC_ACTIONS):
        paths["/v1/" + name] = {"post": _operation(
            "写入 " + name + "（记入请求日志，可用原 request_id 与原请求体重试）", "windowToken", parameters=[reported],
            body=_body(*known[name]) if name in known else _body(), tags=["write"], extra={"x-journaled": True})}
    for name in sorted(httpd.ROUND_WRITES):
        paths["/v1/" + name] = {"post": _operation("写入 " + name + "（不记入请求日志）", "windowToken", body=_body(),
                                                  tags=["write"], extra={**round_only, "x-journaled": False})}
    for name in sorted(project_capabilities.PROBE_WRITES):
        paths["/v1/" + name] = {"post": _operation("独立探测端写入 " + name, "verifierToken", body=_body(), tags=["probe"],
                                                  extra={"x-journaled": True})}
    for name in sorted(round_service.BOOTSTRAP):
        paths["/v1/" + name] = {"post": _operation("窗口接入 " + name, "enrollmentToken" if name == "ai-activate" else None,
                                                  body=_body(), tags=["enrollment"], extra=round_only)}
    paths["/v1/window-apply"] = {"post": _operation("凭平台接入点的申请码提交申请或查询结果", None,
                                                    body={"required": True, "content": {"application/json": {"schema": {"type": "object", "description": OPEN}}}},
                                                    tags=["enrollment"], extra=round_only)}
    paths["/v1/ai-invite-info"] = {"get": _operation("凭邀请链接中的证明读取邀请", "inviteProof", parameters=[_query("invite_id", True)],
                                                     tags=["enrollment"])}
    paths["/v1/service-status"] = {"get": _operation("服务阶段", "windowToken", tags=["service"])}
    paths["/metrics"] = {"get": _operation("运行指标，Prometheus 文本格式；须为抓取令牌或系统管理员令牌", "metricsToken",
                                           "text/plain; version=0.0.4; charset=utf-8", tags=["service"])}
    paths["/readyz"] = {"get": _operation("是否可接收请求；维护阶段返回 503", None, tags=["service"])}
    paths["/healthz"] = {"get": _operation("存活检查，仅局域网 TLS 模式提供", None, tags=["service"])}

    bearer = lambda text: {"type": "http", "scheme": "bearer", "description": text}
    return {
        "openapi": "3.1.0",
        "info": {"title": "Agent Relay HTTP 接口", "version": __version__,
                 "description": "由服务端路由表生成。带 x-round-only 的接口仅在账号密码登录模式（round）下提供；"
                                "x-journaled 为 true 的写入有持久回执。请求体与响应体未逐项描述，以 " + MANUAL + " 为准。",
                 "license": {"name": "AGPL-3.0-only", "identifier": "AGPL-3.0-only"}},
        "paths": dict(sorted(paths.items())),
        "components": {
            "securitySchemes": {"windowToken": bearer("已登记窗口或人员的令牌"),
                                "verifierToken": bearer("管理员登记的独立探测凭据，格式 <verifier_id>.<secret>"),
                                "enrollmentToken": bearer("ai-prepare 回执中的待激活令牌"),
                                "inviteProof": bearer("邀请链接中的专用证明"),
                                "metricsToken": bearer("taskpool.py metrics-token 生成的抓取令牌，或系统管理员令牌")},
            "parameters": {"ReportedAt": {"name": "X-TaskPool-Reported-At", "in": "header", "required": False,
                                          "schema": {"type": "string", "maxLength": 40}, "description": "带时区的 ISO 时间"}},
            "responses": {"Rejected": {"description": "拒绝或错误：JSON 对象，含 status 与 message", "content": {"application/json": {
                "schema": {"type": "object", "properties": {"status": {"type": "string"}, "message": {"type": "string"}}}}}}},
        },
    }


def rendered():
    """The description as the bytes of docs/openapi.json."""
    return (json.dumps(document(), ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
