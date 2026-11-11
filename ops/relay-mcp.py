#!/usr/bin/env python3
"""MCP 接入层：把本窗口的任务操作作为 MCP 工具提供给 AI 平台（stdio 传输，仅用标准库）。

    python3 -B ops/relay-mcp.py --state ~/.taskpool/window-one.credential

本程序不保存凭据、不直接访问服务：每次工具调用都运行同目录的 round-client.py 的一条命令，
沿用它的证书核对、稳定请求编号、待确认写入与重试。工具只读取和登记，不启动任何程序，
也不自动领取。窗口须先按 AI 客户端手册完成接入（enroll／activate）。
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

MODERN = "2026-07-28"  # no handshake: every request carries its version in _meta
LEGACY = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")  # negotiated by initialize
VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
SERVER = {"name": "agent-relay", "version": "1.0.0"}
INSTRUCTIONS = (
    "Agent Relay 任务协作中心的窗口工具。常用顺序：relay_tasks 查看可领取任务，relay_show 读取合同，"
    "relay_claim 领取，relay_download 取输入，完成后 relay_deliver 交付；无法继续时用 relay_handoff 放回。"
    "relay_wait 返回的事件只是提示，仍须读取详情后再操作。写入响应不明确时先 relay_pending，再 relay_retry 重放原请求，"
    "不要改用新内容重发。工具不会启动程序，也不代表资源已获授权。")
MAX_WAIT = 50
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
TEXT, FLAG, NUMBER, LIST = {"type": "string"}, {"type": "boolean"}, {"type": "integer"}, {"type": "array", "items": {"type": "string"}}


def tool(description, properties=None, required=(), read_only=False):
    return {"description": description, "read_only": read_only,
            "schema": {"type": "object", "properties": properties or {}, "required": list(required), "additionalProperties": False}}


TOOLS = {
    "relay_whoami": tool("查看平台登记的本窗口名称、编号、身份、责任人与项目。", read_only=True),
    "relay_tasks": tool("查看可见任务、领取资格及能力缺项。默认只列可领取任务。",
                        {"project": TEXT, "all": {**FLAG, "description": "true 时列出全部可见任务，而不只是可领取的"},
                         "full": {**FLAG, "description": "输出完整任务合同和能力要求"}}, read_only=True),
    "relay_show": tool("查看一个任务的详情、领取和资料引用；返修要求也在这里读取。", {"task": TEXT}, ["task"], read_only=True),
    "relay_claim": tool("按当前版本领取任务。服务端仍核对任务状态、能力、前置条件和授权。",
                        {"task": TEXT, "context_id": TEXT, "context_version": NUMBER}, ["task"]),
    "relay_download": tool("下载并校验任务输入、接续资料和交付文件到本机目录。",
                           {"task": TEXT, "output": {**TEXT, "description": "本机目录"},
                            "inputs": {**FLAG, "description": "仅下载所选冻结输入"},
                            "artifact": {**TEXT, "description": "仅下载指定的服务端相对路径"}, "claim_id": TEXT},
                           ["task", "output"]),
    "relay_deliver": tool("提交本机产物文件作为交付。stop_evidence 仅在实际已停止时填写。",
                          {"task": TEXT, "files": {**LIST, "minItems": 1, "description": "本机文件路径"},
                           "claim_id": TEXT, "stop_evidence": TEXT}, ["task", "files"]),
    "relay_handoff": tool("提交真实停止证据和接续材料后把任务放回，供其他窗口接续。",
                          {"task": TEXT, "evidence": TEXT, "notes": TEXT, "claim_id": TEXT}, ["task", "evidence", "notes"]),
    "relay_wait": tool(f"等待服务端事件（新任务、返修、待验收、范围变更、中断、资源授权），最长 {MAX_WAIT} 秒；0 为只查看一次。"
                       "无事件时返回 idle，可再次调用。",
                       {"timeout": {**NUMBER, "minimum": 0, "maximum": MAX_WAIT}}, read_only=True),
    "relay_pending": tool("查看待确认写入及原请求编号。", read_only=True),
    "relay_retry": tool("使用持久保存的原请求重试待确认写入；不会生成新请求。"),
}


class Invalid(ValueError):
    pass


def identifier(value, label):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise Invalid(f"{label} 须为字母或数字开头的编号")
    return value


def text(value, label):
    if not isinstance(value, str) or not value.strip() or len(value) > 8000 or "\0" in value:
        raise Invalid(f"{label} 须为非空文本")
    return value


def command(name, arguments):
    """The round-client.py command line of one tool call. Free text only ever follows an '=' of its own option."""
    schema = TOOLS[name]["schema"]
    if not isinstance(arguments, dict) or not set(arguments) <= set(schema["properties"]):
        raise Invalid("参数应为 " + (" ".join(schema["properties"]) or "空对象"))
    missing = [key for key in schema["required"] if key not in arguments]
    if missing:
        raise Invalid("缺少参数 " + " ".join(missing))
    get = arguments.get
    for key, kind in schema["properties"].items():
        if key in arguments and kind["type"] in ("boolean", "integer") and type(get(key)) is not {"boolean": bool, "integer": int}[kind["type"]]:
            raise Invalid(f"{key} 类型不符")
    action = name.removeprefix("relay_")
    if action in ("whoami", "pending", "retry"):
        return [action]
    if action == "wait":
        seconds = get("timeout", 25)
        if not 0 <= seconds <= MAX_WAIT:
            raise Invalid(f"timeout 须为 0 至 {MAX_WAIT}")
        return ["wait", "--timeout", str(seconds)]
    if action == "tasks":
        argv = ["tasks"] + ([] if get("all") else ["--claimable"]) + (["--full"] if get("full") else [])
        return argv + (["--project=" + identifier(get("project"), "project")] if "project" in arguments else [])
    argv = [action, identifier(get("task"), "task")]
    if "claim_id" in arguments:
        argv.append("--claim-id=" + identifier(get("claim_id"), "claim_id"))
    if action == "claim":
        if "context_id" in arguments:
            argv.append("--context-id=" + identifier(get("context_id"), "context_id"))
        if "context_version" in arguments:
            argv.append("--context-version=" + str(get("context_version")))
    elif action == "download":
        if get("inputs") and "artifact" in arguments:
            raise Invalid("inputs 与 artifact 只能选一个")
        argv.append("--output=" + text(get("output"), "output"))
        if get("inputs"):
            argv.append("--inputs")
        if "artifact" in arguments:
            argv.append("--artifact=" + text(get("artifact"), "artifact"))
    elif action == "deliver":
        files = get("files")
        if not isinstance(files, list) or not files:
            raise Invalid("files 须为至少一个本机文件路径")
        argv += ["--file=" + text(path, "files") for path in files]
        if "stop_evidence" in arguments:
            argv.append("--stop-evidence=" + text(get("stop_evidence"), "stop_evidence"))
    elif action == "handoff":
        argv += ["--evidence=" + text(get("evidence"), "evidence"), "--notes=" + text(get("notes"), "notes")]
    return argv


def run_tool(settings, name, arguments):
    argv = command(name, arguments)
    base = [sys.executable, "-B", "-X", "utf8", str(settings.client), "--state", str(settings.state)]
    if settings.allow_loopback:
        base.append("--allow-loopback")
    limit = MAX_WAIT + 40 if argv[0] == "wait" else 900 if argv[0] in ("download", "deliver") else 180
    try:
        done = subprocess.run(base + argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=limit, check=False)
    except subprocess.TimeoutExpired:
        return {"content": [{"type": "text", "text": "命令超时；写入可能已送达，先用 relay_pending 查看，再用 relay_retry 重放原请求。"}],
                "isError": True}
    output = done.stdout.decode("utf-8", "replace").strip()
    if done.returncode != 0:
        message = done.stderr.decode("utf-8", "replace").strip() or output or f"命令退出码 {done.returncode}"
        return {"content": [{"type": "text", "text": message}], "isError": True}
    result = {"content": [{"type": "text", "text": output}], "isError": False}
    try:
        value = json.loads(output)
    except ValueError:
        return result
    if isinstance(value, dict):
        result["structuredContent"] = value
    return result


def listed_tools():
    return [{"name": name, "description": item["description"], "inputSchema": item["schema"],
             "annotations": {"readOnlyHint": item["read_only"], "destructiveHint": False, "openWorldHint": False}}
            for name, item in TOOLS.items()]


def handle(settings, message):
    """The response to one JSON-RPC message, or None for a notification."""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
        return {"jsonrpc": "2.0", "id": message.get("id") if isinstance(message, dict) else None,
                "error": {"code": -32600, "message": "Invalid Request"}}
    if "id" not in message:
        return None
    method, params = message["method"], message.get("params")
    params = params if isinstance(params, dict) else {}
    meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
    modern = VERSION_KEY in meta

    def reply(result):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {**({"resultType": "complete"} if modern else {}), **result}}

    def error(code, text_, data=None):
        return {"jsonrpc": "2.0", "id": message["id"], "error": {"code": code, "message": text_, **({"data": data} if data else {})}}

    if modern and meta[VERSION_KEY] not in (MODERN, *LEGACY):
        return error(-32022, "Unsupported protocol version", {"supported": [MODERN, *LEGACY], "requested": meta[VERSION_KEY]})
    if method == "initialize":
        asked = params.get("protocolVersion")
        return reply({"protocolVersion": asked if asked in LEGACY else LEGACY[0], "capabilities": {"tools": {}},
                      "serverInfo": SERVER, "instructions": INSTRUCTIONS})
    if method == "server/discover":
        modern = True
        return reply({"supportedVersions": [MODERN, *LEGACY], "capabilities": {"tools": {}},
                      "_meta": {"io.modelcontextprotocol/serverInfo": SERVER}, "instructions": INSTRUCTIONS})
    if method == "ping":
        return reply({})
    if method == "tools/list":
        return reply({"tools": listed_tools()})
    if method == "tools/call":
        name = params.get("name")
        if name not in TOOLS:
            return error(-32602, f"Unknown tool: {name}")
        try:
            return reply(run_tool(settings, name, params.get("arguments") or {}))
        except Invalid as problem:
            return reply({"content": [{"type": "text", "text": str(problem)}], "isError": True})
    return error(-32601, "Method not found")


def serve(settings, source, target):
    for raw in source:
        if not raw.strip():
            continue
        try:
            message = json.loads(raw.decode("utf-8"))
        except ValueError:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        else:
            response = handle(settings, message)
        if response is not None:  # one message per line; json.dumps never emits a raw newline
            target.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")
            target.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--state", type=Path, required=True, help="此窗口的私有凭据文件")
    parser.add_argument("--allow-loopback", action="store_true", help="允许隔离测试的 HTTP 回环服务")
    parser.add_argument("--client", type=Path, default=Path(__file__).resolve().with_name("round-client.py"),
                        help="round-client.py 的位置；默认与本文件同目录")
    settings = parser.parse_args()
    if not settings.client.is_file():
        parser.error("找不到 round-client.py：" + str(settings.client))
    serve(settings, sys.stdin.buffer, sys.stdout.buffer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
