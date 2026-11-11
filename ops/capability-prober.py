"""Run one approved capability probe from a private, administrator-managed environment."""
import argparse
import hashlib
from http.client import HTTPConnection, HTTPException
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys


def relay_client():
    spec = importlib.util.spec_from_file_location("round_client", Path(__file__).with_name("round-client.py"))
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    return client


def private_key(path):
    path = Path(path).expanduser()
    if path.is_symlink() or not path.is_file() or (os.name != "nt" and path.stat().st_mode & 0o077):
        raise ValueError("Hermes API 凭据须位于私有普通文件")
    value = path.read_text(encoding="utf-8").strip()
    if not value or len(value) > 1024 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError("Hermes API 凭据格式无效")
    return value


def hermes(config):
    if not config.get("hermes_key_file") or not config.get("hermes_port"):
        raise ValueError("请配置本机 Hermes API 端口和私有凭据文件")
    connection = HTTPConnection("127.0.0.1", config["hermes_port"], timeout=8)
    try:
        connection.request("GET", "/v1/capabilities", headers={
            "Authorization": "Bearer " + private_key(config["hermes_key_file"]),
        })
        response = connection.getresponse()
        raw = response.read(65537)
        if response.status != 200 or len(raw) > 65536:
            raise ValueError("Hermes 能力接口未通过认证或返回无效响应")
        value = json.loads(raw)
        if not isinstance(value, dict) or not isinstance(value.get("features"), dict) or not isinstance(value.get("endpoints"), dict):
            raise ValueError("Hermes 能力接口缺少功能与端点信息")
    finally:
        connection.close()
    return "available", {"environment": config["environment_label"]}


def runtime_options(config):
    options = {"env": {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "LANG", "LC_ALL") if key in os.environ}}
    name = config.get("runtime_user")
    if not name:
        return options
    if os.name != "posix":
        raise ValueError("此系统须由实际执行账号直接运行探测端")
    import pwd
    try:
        account = pwd.getpwnam(name)
    except KeyError as error:
        raise ValueError("配置的执行账号不存在") from error
    groups = os.getgrouplist(name, account.pw_gid)
    if os.geteuid() == 0:
        options.update(user=account.pw_uid, group=account.pw_gid, extra_groups=groups)
    elif (os.geteuid() != account.pw_uid or os.getegid() != account.pw_gid or
          set(os.getgroups()) | {os.getegid()} != set(groups)):
        raise ValueError("探测进程不能使用配置的执行账号及组权限")
    return options


def git(config):
    if not config.get("git"):
        raise ValueError("请配置受信 Git 程序的绝对路径")
    binary = Path(config["git"])
    if not binary.is_absolute() or not binary.is_file():
        raise ValueError("受信 Git 程序不可用")
    result = subprocess.run([str(binary), "--version"], cwd=binary.parent, **runtime_options(config),
                            capture_output=True, text=True, timeout=8, check=False)
    version = result.stdout.strip().removeprefix("git version ")
    if result.returncode or not re.fullmatch(r"[0-9][0-9A-Za-z.+-]{0,63}", version):
        raise ValueError("Git 未返回可核对的版本")
    return version, {"tools_version": version}


def workspace(config):
    if not config.get("scratch"):
        raise ValueError("请配置探测专用目录")
    root = Path(config["scratch"])
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("探测专用目录须是已存在的绝对目录")
    root = root.resolve(strict=True)
    # The fixed child code gets no verifier or gateway credentials.
    code = """import os, pathlib, sys, tempfile
with tempfile.TemporaryDirectory(prefix='agent-relay-probe-', dir=sys.argv[1]) as directory:
    marker = pathlib.Path(directory) / 'marker'
    nonce = os.urandom(32)
    marker.write_bytes(nonce)
    if marker.read_bytes() != nonce:
        raise SystemExit(1)
"""
    result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(root)], cwd=root,
                            **runtime_options(config), capture_output=True, timeout=8, check=False)
    if result.returncode:
        raise ValueError("实际执行账号未通过隔离目录读写核对")
    return "rw", {"environment": config["environment_label"]}


PROBES = {"hermes-api": hermes, "git-version": git, "workspace-rw": workspace}


def report(config, job):
    note = "预批准的固定探测通过"
    value, measured = "", {}
    passed = False
    try:
        if job["environment_id"] != config["environment_id"] or job["template"] not in PROBES:
            raise ValueError("核验请求与本机已登记环境或模板不符")
        value, measured = PROBES[job["template"]](config)
        if job["expected_value"] not in {"*", value} or measured != job["expected_dimensions"]:
            raise ValueError("实测值与目录要求或执行配置不符，请核对配置后重新申请")
        passed = True
    except ValueError as error:
        note = str(error) if not isinstance(error, (json.JSONDecodeError, UnicodeError)) else "探测接口没有返回有效数据"
    except (OSError, HTTPException, subprocess.TimeoutExpired):
        note = "探测接口、工具或隔离目录暂不可用，请核对后重试"
    proof = {"template": job["template"], "passed": passed, "value": value, "measured": measured, "note": note}
    fingerprint = hashlib.sha256(json.dumps(proof, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    return {"request_id": "probe-result-" + secrets.token_hex(16), "verification_id": job["id"], "attempt": job["attempt"],
            "outcome": "pass" if passed else "fail", "value": value if passed else "", "measured": measured if passed else {},
            "evidence": {"note": note, "sha256": fingerprint}}


def once(state, client, allow_loopback):
    config = state.data
    api = client.Pool(config["url"], config["certificate_sha256"], allow_loopback, config.get("connect_host"))
    pending = config.get("pending")
    if pending is None:
        pending = {"request_id": "probe-claim-" + secrets.token_hex(16)}
        config["pending"] = pending
        state.save()
    if "result" not in pending:
        claimed = api.call("capability-probe-claim", config["token"], {"request_id": pending["request_id"]})
        if not claimed["job"]:
            del config["pending"]
            state.save()
            return {"status": "idle"}
        pending["result"] = report(config, claimed["job"])
        state.save()
    try:
        value = api.call("capability-probe-result", config["token"], pending["result"])
    except client.RequestError as error:
        if error.status == 409:
            config["last_rejection"] = {"verification_id": pending["result"]["verification_id"], "message": str(error)}
            del config["pending"]
            state.save()
        raise
    del config["pending"]
    state.save()
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    commands = parser.add_subparsers(dest="action", required=True)
    init = commands.add_parser("init")
    init.add_argument("--verifier-id", required=True)
    init.add_argument("--environment-id", required=True)
    init.add_argument("--environment-label", required=True, help="执行配置中对应的环境值")
    init.add_argument("--url", required=True)
    init.add_argument("--certificate-sha256", default="")
    init.add_argument("--connect-host")
    init.add_argument("--hermes-port", type=int, metavar="PORT")
    init.add_argument("--hermes-key-file")
    init.add_argument("--git")
    init.add_argument("--scratch")
    init.add_argument("--runtime-user", help="Git 与目录探测使用的实际 POSIX 执行账号")
    run = commands.add_parser("once", help="领取并完成一项核验，重试时使用原请求")
    run.add_argument("--allow-loopback", action="store_true", help="允许隔离测试的 HTTP 回环服务")
    args = parser.parse_args()
    client = relay_client()
    try:
        state = client.State(args.state)
        with state.exclusive():
            if args.action == "init":
                if state.path.exists():
                    raise ValueError("探测端已有凭据，保留原文件以恢复未确认请求")
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}", args.verifier_id):
                    raise ValueError("探测端编号格式无效")
                if args.hermes_port is not None and not 1 <= args.hermes_port <= 65535:
                    raise ValueError("Hermes 端口须在 1 至 65535 之间")
                config = {k: v for k, v in vars(args).items() if k not in {"action", "state"}}
                secret = secrets.token_urlsafe(32)
                state.data = {**config, "token": args.verifier_id + "." + secret}
                state.save()
                value = {"verifier_id": args.verifier_id, "environment_id": args.environment_id,
                         "token_sha256": hashlib.sha256(secret.encode("ascii")).hexdigest()}
            else:
                if not state.data.get("token"):
                    raise ValueError("请先初始化并登记独立探测端")
                value = once(state, client, args.allow_loopback)
        print(json.dumps(value, ensure_ascii=False))
        return 0
    except (client.RequestError, OSError, HTTPException, ValueError, KeyError) as error:
        print("探测端处理失败：" + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
