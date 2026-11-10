"""Local administration and HTTP entry point for the independent pilot."""

import argparse
import base64
import codecs
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import signal
import threading
from contextlib import nullcontext
import sys
import uuid

from pool.httpd import Server
from pool import __version__, RELEASE_NAME
from pool.packages import ClientError, artifact_name, make_delivery, strict_json, string, unpack_delivery
from pool.service import ADMIN, COMMITTER, COORDINATOR, ID, Service, Unavailable, exclusive, state_path, store_once
from pool.storage import LedgerBackend, initialize_backend
from pool.lifecycle import Control, control_request
from 协作存储 import digest, encoded, read_json, safe
from 账本前提探针 import qualify


def emit(data):
    print(json.dumps(data, ensure_ascii=False, indent=2), flush=True)


def initialize(args, store):
    all_origins = [*args.worker, args.receiver, COORDINATOR, COMMITTER]
    if len(set(all_origins)) != len(all_origins) or not all(ID.fullmatch(name) for name in all_origins):
        raise ClientError("执行者和接收者名称须合法且互不相同")
    string(args.authority, "authority")
    credentials = safe(store, "credentials.json")
    roles = {**dict.fromkeys(args.worker, "executor"), args.receiver: "receiver"}
    if not credentials.exists():
        if any(name.casefold() == ADMIN for name in roles):
            raise ClientError("admin 是保留身份，请用 init-admin 初始化")
        config = {"authority": args.authority, "roles": roles, "receiver": args.receiver,
                  "tokens": {name: secrets.token_urlsafe(32) for name in roles}}
        store_once(store, "credentials.json", encoded(config))
    config = read_json(credentials)
    if config["roles"] != roles or config["authority"] != args.authority:
        raise ClientError("该试用库已绑定原身份和授权依据")
    report = safe(store, "qualification.json")
    if not report.exists():
        qualify(store, report, initialize_backend(store))
    if not safe(store, "repo.json").exists():
        LedgerBackend.create(store, COORDINATOR, args.authority, report)
    service = Service(store)
    try:
        body = {"request_id": "initialize-v1", "origins": {**roles, COMMITTER: "coordinator"}}
        status, result = service.submit(COORDINATOR, "bootstrap", body["request_id"], body)
        if status != 200:
            raise Unavailable("身份登记尚未完成")
        emit({"store": str(store), "credentials": str(credentials), "head": result["head"],
              "qualification_passed": read_json(report)["passed"]})
    finally:
        service.close()


def add_task(args, service, config):
    string(args.title, "title", 200)
    if not 1 <= len(args.criterion) <= 30 or len(set(args.criterion)) != len(args.criterion):
        raise ClientError("须提供 1 至 30 个互不重复的验收判据")
    for criterion in args.criterion:
        string(criterion, "criterion", 100)
    with args.input.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if not raw or len(raw) > 1024 * 1024:
        raise ClientError("冻结输入须为 1 字节至 1 MiB")
    path = f"inputs/{digest(raw)}/{artifact_name(args.input.name)}"
    body = {"request_id": args.request_id, "title": args.title, "path": path, "criteria": args.criterion,
            "receiver": config["receiver"], "input": base64.b64encode(raw).decode("ascii")}
    status, result = service.submit(COORDINATOR, "add-task", args.request_id, body)
    emit(result)
    return 0 if status == 200 else 1


def pack(args):
    data = strict_json(args.claim.read_bytes().removeprefix(codecs.BOM_UTF8))
    claim = data["claim"]
    artifacts = {}
    total = 0
    for path in args.artifact:
        key = artifact_name(path.name)
        if key.casefold() in {name.casefold() for name in artifacts}:
            raise ClientError("产物文件名重复")
        with path.open("rb") as stream:
            content = stream.read(24 * 1024 * 1024 - total + 1)
        total += len(content)
        if total > 24 * 1024 * 1024:
            raise ClientError("产物超出解压大小限制")
        artifacts[key] = content
    raw = make_delivery(claim, artifacts)
    info = {"package_sha256": digest(raw), "package": base64.b64encode(raw).decode("ascii")}
    unpack_delivery(info)
    with args.output.open("xb") as stream:
        stream.write(raw)
    emit({"file": str(args.output), "sha256": info["package_sha256"], "bytes": len(raw)})
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"内网任务服务 v{__version__} · {RELEASE_NAME}")
    parser.add_argument("--store", default="local", help="独立项目 .state 内的试用库名称")
    commands = parser.add_subparsers(dest="action", required=True)
    init = commands.add_parser("init", help="验证 Windows NTFS 或 Linux ext4 存储并初始化")
    init.add_argument("--worker", action="append", required=True)
    init.add_argument("--receiver", required=True)
    init.add_argument("--authority", required=True)
    add = commands.add_parser("add-task", help="本地登记资料类试用任务")
    add.add_argument("--request-id", required=True)
    add.add_argument("--title", required=True)
    add.add_argument("--input", type=Path, required=True)
    add.add_argument("--criterion", action="append", required=True)
    commands.add_parser("init-admin", help="初始化 admin 并仅向本机操作者输出其访问令牌")
    migrate = commands.add_parser("upgrade-migrate", help="迁移旧卷并将迭代任务设为待启动")
    migrate.add_argument("--task", default="T02")
    migrate.add_argument("--upgrade", required=True)
    migrate.add_argument("--image", required=True)
    round_migrate = commands.add_parser("round-migrate", help="将隔离 v2 卷升级至本轮 v3 合同")
    round_migrate.add_argument("--upgrade", required=True)
    round_migrate.add_argument("--image", required=True)
    admin_recover = commands.add_parser("admin-recover", help="独占账本维护时重置本机管理员密码")
    admin_recover.add_argument("--password-file", type=Path, help="受限 UTF-8 文件，省略时从终端输入")
    admin_recover.add_argument("--request-id", required=True)
    maintenance = commands.add_parser("maintenance", help="独占账本时设置维护标记")
    maintenance.add_argument("mode", choices=["on", "off"])
    maintenance.add_argument("--request-id", required=True)
    commands.add_parser("inspect-store", help="独占检查数据合同、任务和待恢复请求")
    safety_migrate = commands.add_parser('security-migrate', help='独占迁移安全语义3→4→5，保留活动任务及待处置请求')
    safety_migrate.add_argument('--target', type=int, choices=[4, 5], default=5)
    safety_migrate.add_argument('--request-id', required=True)
    control = commands.add_parser("upgrade-control", help="认证本机管理接口，不打开第二个账本写实例")
    control.add_argument("command", choices=["status", "drain", "freeze", "cancel", "shutdown", "backup"])
    control.add_argument("--timeout", type=float, default=30)
    control.add_argument("--archive", help="backup：当前服务用户可写的私有备份绝对目录")
    control.add_argument("--tag", help="backup：不覆盖现有快照的唯一名称")
    serve = commands.add_parser("serve", help="启动回环服务或显式启用局域网 TLS")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--lan-name", help="局域网 TLS 证书中的稳定主机名")
    serve.add_argument("--lan-alias", action="append", default=[], help="同一证书中需要继续接收的主机名")
    serve.add_argument("--tls-cert", type=Path)
    serve.add_argument("--tls-key", type=Path)
    package = commands.add_parser("pack", help="从 claim 回执及产物生成交付 ZIP")
    package.add_argument("--claim", type=Path, required=True)
    package.add_argument("--artifact", type=Path, action="append", required=True)
    package.add_argument("--output", type=Path, required=True)
    return parser


def upgrade_control(args, store):
    if not 0 < args.timeout <= 120:
        raise ValueError("排空时限须大于 0 且不超过 120 秒")
    if args.command == "backup" and (not args.archive or not args.tag):
        raise ValueError("backup 需要 --archive 私有绝对目录和 --tag 唯一名称")
    result = control_request(store, args.command, args.timeout, archive=args.archive, tag=args.tag)
    emit(result)
    return 0 if args.command not in {"freeze", "shutdown"} or result["phase"] == "frozen" else 1


def init_admin(service):
    status, result = service.initialize_admin()
    if status != 200:
        raise ClientError(result.get("message") or "管理员账号登记失败", status)
    emit(result)
    return 0


def inspect_store(service, state):
    snap = service.snapshot()
    emit({"head": snap["head"], "head_sha256": snap["sha256"], "repo_id": service.desk.meta["repo_id"],
          "format": state["pilot"].get("format"), "window_high_water": state["pilot"].get("serial", 0),
          "tasks": [{"id": task["task_id"], "status": task["status"], "version": task["version"],
                     "scope_version": task["scope_version"], "contract": task.get("contract"),
                     "inputs": task["inputs"]} for task in state["tasks"].values()],
          "active_claims": [{"task_id": claim["task_id"], "claim_id": claim["claim_id"],
                             "origin": claim["origin"], "execution": claim["E"]}
                            for claim in state["claims"].values() if claim["L"] == "active"],
          "requests": service.db.execute("SELECT count(*) FROM requests").fetchone()[0]})
    return 0


def admin_recover(args, service, state):
    from getpass import getpass
    from pool.round_service import enabled, password_change
    if not enabled(state) or not state["pilot"]["format"]["maintenance"]:
        raise ClientError("管理员恢复须使用已停止服务的 v3 维护卷")
    if args.password_file:
        value = args.password_file.read_text(encoding="utf-8-sig")
    else:
        if not sys.stdin.isatty():
            raise ClientError("请在交互终端输入或使用受限密码文件")
        value = getpass("新管理员密码: ")
        if value != getpass("确认密码: "):
            raise ClientError("两次输入不一致")
    protected = service.passwords.protect(value, ADMIN)
    status, result = password_change(service, ADMIN, ADMIN, "admin-recovery", args.request_id, protected)
    emit(result)
    return 0 if status == 200 else 1


def round_migrate(args, service):
    body = {"request_id": "round-" + digest(encoded([args.upgrade, args.image])),
            "upgrade": args.upgrade, "image": args.image.removeprefix("sha256:")}
    status, result = service.submit(ADMIN, args.action, body["request_id"], body)
    emit(result)
    return 0 if status == 200 else 1


def security_migrate(args, service):
    from pool.safety import migrate
    status, result = migrate(service, args.target, args.request_id)
    emit(result)
    return 0 if status == 200 else 1


def contract_change(args, service, state):
    """upgrade-migrate and maintenance: one administrator request through the ordinary write path."""
    if args.action == "upgrade-migrate":
        task = state["tasks"][args.task]
        request_id = "migration-" + digest(encoded([args.upgrade, args.image, args.task]))
        existing = service.db.execute("SELECT response FROM requests WHERE key=? AND status=200",
                                      (digest(encoded([ADMIN, request_id])),)).fetchone()
        if existing:
            emit(json.loads(existing[0]))
            return 0
        body = {"request_id": request_id, "task_id": args.task, "upgrade": args.upgrade,
                "image": args.image.removeprefix("sha256:"), "version": task["version"],
                "scope_version": task["scope_version"]}
        action = args.action
    else:
        body = {"request_id": args.request_id, "enabled": args.mode == "on"}
        action = "maintenance-mode"
    status, result = service.submit(ADMIN, action, body["request_id"], body)
    emit(result)
    return 0 if status == 200 else 1


def serve(args, service, config, store):
    if not 0 <= args.port <= 65535:
        raise ClientError("端口须在 0 至 65535 之间")
    tls = None
    fingerprint = None
    if args.lan_name or args.lan_alias or args.tls_cert or args.tls_key:
        if (not args.lan_name or not all(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,120}", name)
                for name in [args.lan_name, *args.lan_alias])
                or not args.tls_cert or not args.tls_key or not args.port):
            raise ClientError("局域网入口需要主机名、证书、私钥和固定端口")
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(args.tls_cert, args.tls_key)
        pem = args.tls_cert.read_text(encoding="ascii").split("-----END CERTIFICATE-----", 1)[0]
        fingerprint = digest(ssl.PEM_cert_to_DER_cert(pem + "-----END CERTIFICATE-----"))
    with Server(args.port, service, config["tokens"], tls, args.lan_name, args.lan_alias, fingerprint) as server:
        from pool.safety import record_configuration
        record_configuration(service, {'service_version': __version__, 'port': server.server_address[1],
            'lan_name': args.lan_name, 'lan_aliases': args.lan_alias,
            'tls_cert': str(args.tls_cert) if args.tls_cert else None,
            'tls_key': str(args.tls_key) if args.tls_key else None,
            'launch_config_sha256': os.environ.get('TASKPOOL_LAUNCH_CONFIG_SHA256')})
        scheme, host = ("https", args.lan_name) if tls else ("http", "127.0.0.1")

        def graceful_shutdown():
            service.lifecycle.drain()
            try:
                result = service.lifecycle.freeze(30)
            except ValueError:
                print("一致性备份仍在完成，本次停服已取消；请等待备份结束后重试", file=sys.stderr, flush=True)
                return
            if result["phase"] == "frozen":
                server.shutdown()
            else:
                print("排空超时，已取消停服，请检查升级控制状态", file=sys.stderr, flush=True)

        def on_signal(_number, _frame):
            threading.Thread(target=graceful_shutdown, name="graceful-stop", daemon=True).start()
        signals = {kind: signal.getsignal(kind) for kind in (signal.SIGTERM, signal.SIGINT)}
        for kind in signals:
            signal.signal(kind, on_signal)
        try:
            control_context = Control(store, service.lifecycle, server.shutdown, service.consistent_backup) if os.name == "posix" else nullcontext()
            with control_context:
                emit({"url": f"{scheme}://{host}:{server.server_address[1]}", "store": str(store)})
                server.serve_forever()
        finally:
            for kind, previous in signals.items():
                signal.signal(kind, previous)
    return 0


def run_with_service(args, service, config, store):
    """Everything that needs the opened ledger: recover pending requests, then run the command."""
    state = service.snapshot()['state']
    if (args.action == 'serve' and state.get('pilot', {}).get('format', {}).get('schema', 0) in {3, 4}
            and (args.port != 0 or args.lan_name)):
        raise ClientError('启动新版服务前须先独占运行 security-migrate --target 5 --request-id <稳定编号>', 409)
    if args.action not in {'security-migrate', 'inspect-store'} and not service.recover():
        raise Unavailable("有未得到终局决定的请求")
    state = service.snapshot()["state"]
    if any(role not in state["origins"].get(name, {}).get("roles", []) for name, role in config["roles"].items()):
        raise Unavailable("身份登记未完成，请重跑 init")
    if args.action == "add-task":
        return add_task(args, service, config)
    if args.action == "init-admin":
        return init_admin(service)
    if args.action == "inspect-store":
        return inspect_store(service, state)
    if args.action == "admin-recover":
        return admin_recover(args, service, state)
    if args.action == "round-migrate":
        return round_migrate(args, service)
    if args.action == 'security-migrate':
        return security_migrate(args, service)
    if args.action in {"upgrade-migrate", "maintenance"}:
        return contract_change(args, service, state)
    return serve(args, service, config, store)


def main():
    args = build_parser().parse_args()
    try:
        if sys.version_info < (3, 13):
            raise ClientError("任务池运行需要 Python 3.13 或更新版本")
        if args.action == "pack":
            return pack(args)
        if sys.platform not in {"win32", "linux"}:
            raise ClientError("账本写入需要 Windows NTFS 或 Linux ext4")
        if os.name == "posix":
            os.umask(0o077)
        store = state_path(args.store)
        if args.action == "upgrade-control":
            return upgrade_control(args, store)
        if args.action == "init":
            store.mkdir(parents=True, exist_ok=True)
        with exclusive(store):
            if args.action == "init":
                initialize(args, store)
                return 0
            config = read_json(safe(store, "credentials.json"))
            service = Service(store)
            try:
                return run_with_service(args, service, config, store)
            finally:
                service.close()
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, Unavailable, KeyError, TypeError, AssertionError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
