"""Private incremental snapshot of a stopped/frozen store; never restores over live data."""
import argparse
from contextlib import ExitStack, closing, contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import tempfile

from .service import exclusive
from .storage import LedgerBackend


RUNTIME = {"service.lock", "service-writer.lock", "upgrade-control.sock", "upgrade-control.key"}
IMMUTABLE = {"inputs", "artifacts", "deliveries", "handoffs", "packages"}
TLS_ALLOWLIST = ("key.pem", "cert-v2.pem", "cert.pem")
RESTORE_HELP = ("TLS 材料只来自当前 local 数据目录的同级 tls 白名单。恢复 service_files 时，"
                "必须先恢复并核对同一份当前 store，再映射到该 store.parent/tls；"
                "仅允许 key.pem、cert-v2.pem、cert.pem，不接受清单指定的任意目录或 ../ 路径。"
                "恢复前核对对象 SHA256，私钥及备份对象权限保持 0600；此工具不自动恢复或覆盖新写入。")


@contextmanager
def regular_reader(path):
    expected = path.lstat()
    if not stat.S_ISREG(expected.st_mode):
        raise ValueError("备份来源须为普通文件，不能是符号链接")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        actual = os.fstat(stream.fileno())
        if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise ValueError("备份来源在打开时发生变化")
        yield stream


def tls_sources(store):
    """Only the explicitly selected local store has the deployed fixed sibling TLS scope."""
    if store.name != "local":
        return {}, {"status": "not_configured", "included": False,
                    "message": "当前 store 不是 local，未读取同级 TLS 材料"}
    root = store.parent / "tls"
    try:
        info = root.lstat()
    except FileNotFoundError:
        return {}, {"status": "absent", "included": False, "message": "TLS 目录不存在，本快照不包含 TLS 身份材料"}
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("同级 TLS 目录须为真实目录，不能是符号链接")
    sources = {}
    for name in TLS_ALLOWLIST:
        path = root / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("TLS 白名单材料须为普通文件，不能是符号链接")
        sources["tls/" + name] = path
    complete = "tls/key.pem" in sources and bool({"tls/cert-v2.pem", "tls/cert.pem"} & sources.keys())
    return sources, {"status": "complete" if complete else "incomplete" if sources else "absent",
                     "included": complete, "files": len(sources),
                     "missing": [name for name in TLS_ALLOWLIST if "tls/" + name not in sources],
                     "message": "已包含 TLS 私钥与证书白名单" if complete else "TLS 白名单缺失，不构成完整 TLS 身份备份"}


def service_restore_targets(store, entries):
    """Validate a private manifest's service scope; return paths, never write any files."""
    store = Path(store).resolve(strict=True)
    if store.name != "local" or not isinstance(entries, dict):
        raise ValueError("TLS 恢复须对应当前 local 数据目录")
    # This also rejects a substituted sibling directory or existing symlink member.
    tls_sources(store)
    allowed = {"tls/" + name: store.parent / "tls" / name for name in TLS_ALLOWLIST}
    if any(key not in allowed for key in entries):
        raise ValueError("TLS 恢复清单包含白名单以外的目标")
    return {key: allowed[key] for key in entries}


def fingerprint(path):
    with regular_reader(path) as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def archive_file(path, objects):
    before = path.lstat()
    sha = fingerprint(path)
    target = objects / sha
    if target.exists():
        if target.is_symlink() or fingerprint(target) != sha:
            raise ValueError("备份内容对象损坏，停止快照")
        if os.name == "posix" and stat.S_IMODE(target.stat().st_mode) != 0o600:
            raise ValueError("已有备份内容对象权限须为 0600")
    else:
        fd, temporary = tempfile.mkstemp(prefix=".object-", dir=objects)
        try:
            with os.fdopen(fd, "wb") as output, regular_reader(path) as source:
                shutil.copyfileobj(source, output)
                output.flush()
                os.fsync(output.fileno())
            if fingerprint(Path(temporary)) != sha:
                raise ValueError("源文件在备份期间发生变化")
            os.replace(temporary, target)
        finally:
            Path(temporary).unlink(missing_ok=True)
    after = path.lstat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError("源文件在备份期间发生变化")
    return {"sha256": sha, "bytes": before.st_size, "mode": before.st_mode & 0o777}


def snapshot(store, archive, tag, seed=False, *, service=None):
    store, archive = Path(store).resolve(strict=True), Path(archive)
    if not archive.is_absolute():
        raise ValueError("备份目录须为绝对路径")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", tag):
        raise ValueError("快照名称须为小写字母数字和短横线")
    if archive.is_symlink() or any(parent.is_symlink() for parent in archive.parents):
        raise ValueError("备份目录不能经由符号链接")
    if archive.resolve().is_relative_to(store) or store.is_relative_to(archive.resolve()):
        raise ValueError("备份目录必须独立于服务数据目录")
    tls_root = store.parent / "tls"
    if store.name == "local" and (archive.resolve().is_relative_to(tls_root) or tls_root.is_relative_to(archive.resolve())):
        raise ValueError("备份目录必须独立于 TLS 材料目录")
    archive.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix" and archive.stat().st_mode & 0o077:
        raise ValueError("备份根目录须为仅当前用户可访问的私有目录")
    objects = archive / "objects"
    objects.mkdir(exist_ok=True, mode=0o700)
    if objects.is_symlink():
        raise ValueError("备份对象目录不能是符号链接")
    manifest = archive / (tag + ".json")
    if not seed and manifest.exists():
        raise ValueError("快照名称已使用，原快照保留")
    rows, service_files = {}, {}
    tls_status = {"status": "seed_only", "included": False, "message": "预存材料不构成完整 TLS 备份"}
    with ExitStack() as stack:
        if not seed:
            if service is None:
                # External CLI never bypasses the live writer's locks.
                stack.enter_context(exclusive(store))
                stack.enter_context(exclusive(store, "service-writer.lock"))
            else:
                stack.enter_context(service.lock)
                status = service.lifecycle.status()
                if (Path(service.desk.store).resolve() != store or service._writer_guard is None or
                        status["phase"] != "backing_up" or status["active_requests"]):
                    raise ValueError("在线备份须由现有唯一写实例在完全排空的备份窗口内执行")
                if service.db.in_transaction:
                    raise ValueError("数据库事务尚未结束，本次备份已取消")
        before = None if seed else (service.snapshot() if service else LedgerBackend(store).read())
        if not seed:
            tls_paths, tls_status = tls_sources(store)
        for path in sorted(store.rglob("*")):
            relative = path.relative_to(store).as_posix()
            if path.relative_to(store).parts[0]=='.runtime':
                continue
            if path.is_symlink():
                raise ValueError("服务目录包含符号链接，停止备份")
            if not path.is_file() or relative in RUNTIME or relative.endswith(("-wal", "-shm", "-journal")):
                continue
            if seed and path.relative_to(store).parts[0] not in IMMUTABLE:
                continue
            if path.suffix in {".sqlite3", ".db", ".sqlite"}:
                with tempfile.TemporaryDirectory(prefix=".sqlite-", dir=archive) as temporary:
                    target = Path(temporary) / "consistent.sqlite3"
                    with ExitStack() as databases:
                        source = service.db if service is not None and path.name == "http-journal.sqlite3" else databases.enter_context(
                            closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)))
                        backup = databases.enter_context(closing(sqlite3.connect(target)))
                        source.backup(backup)
                        if backup.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                            raise ValueError("SQLite 一致性校验未通过")
                    rows[relative] = {**archive_file(target, objects), "sqlite_backup": True}
            else:
                rows[relative] = archive_file(path, objects)
        if not seed:
            for relative, path in tls_paths.items():
                service_files[relative] = {**archive_file(path, objects), "mode": 0o600}
            current_paths, _ = tls_sources(store)
            if current_paths.keys() != tls_paths.keys() or any(
                    fingerprint(current_paths[key]) != row["sha256"] for key, row in service_files.items()):
                raise ValueError("TLS 材料在备份期间发生变化，未发布快照清单")
        if os.name == "posix":
            fd = os.open(objects, os.O_DIRECTORY | os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        if not seed:
            after = service.snapshot() if service else LedgerBackend(store).read()
            if (before["head"], before.get("sha256")) != (after["head"], after.get("sha256")):
                raise ValueError("账本在备份窗口内发生变化，未发布快照清单")
            content = {"format": 1, "created_at": datetime.now(timezone.utc).isoformat(), "tag": tag,
                       "ledger_head": before["head"], "ledger_sha256": before.get("sha256"),
                       "files": rows, "service_files": service_files, "tls_backup": tls_status,
                       'configuration_backup': {'status':'complete' if 'service-config.json' in rows else 'absent',
                                                'file':'service-config.json',
                                                'sha256':rows.get('service-config.json',{}).get('sha256')},
                       "service_restore": {"scope": "current-store-sibling-tls", "store_name": "local",
                                           "allowed_files": list(TLS_ALLOWLIST), "help": RESTORE_HELP},
                       "restore_policy": "manual-only; never overwrite writes after upgrade"}
            fd, temporary = tempfile.mkstemp(prefix=".snapshot-", dir=archive)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump(content, stream, ensure_ascii=False, sort_keys=True)
                    stream.flush()
                    os.fsync(stream.fileno())
                # Atomic create, never replace a previous snapshot or expose partial JSON.
                os.link(temporary, manifest)
            finally:
                Path(temporary).unlink(missing_ok=True)
            if os.name == "posix":
                fd = os.open(archive, os.O_DIRECTORY | os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
    return {"status": "seeded" if seed else "backed_up", "files": len(rows),
            "service_file_count": len(service_files), "tls_status": tls_status["status"],
            "head": None if seed else before["head"],
            "manifest": None if seed else str(manifest), "private_archive": str(archive)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, epilog=RESTORE_HELP)
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--seed", action="store_true", help="服务运行时仅预存不可变材料，不生成一致性快照")
    args = parser.parse_args()
    try:
        if os.name == "posix":
            os.umask(0o077)
        print(json.dumps(snapshot(args.store, args.archive, args.tag, args.seed), ensure_ascii=False))
        return 0
    except (ValueError, OSError, RuntimeError, sqlite3.Error) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
