"""Validate a complete private recovery point; print only basename, counts and head."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


def verify(archive, tag, legacy_config=None, launch_sha=None):
    archive = Path(archive)
    if archive.is_symlink() or any(path.is_symlink() for path in archive.parents):
        raise ValueError("备份根不能经过链接")
    if os.name == "posix" and archive.stat().st_mode & 0o077:
        raise ValueError("备份根须为私有目录")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", tag):
        raise ValueError("快照名称无效")
    path = archive / (tag + ".json")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("快照清单不存在或无效")
    value = json.loads(path.read_bytes())
    if (value.get("tag") != tag or type(value.get("ledger_head")) is not int or value["ledger_head"] < 0 or
            not re.fullmatch(r"[a-f0-9]{64}", value.get("ledger_sha256", "")) or
            value.get("tls_backup", {}).get("status") != "complete" or
            value.get("tls_backup", {}).get("included") is not True):
        raise ValueError("不是包含实际 TLS 身份的完整恢复点")
    normal, service = value.get("files"), value.get("service_files")
    if not isinstance(normal, dict) or not isinstance(service, dict) or not normal:
        raise ValueError("完整备份清单缺失")
    if not {"repo.json", "http-journal.sqlite3", "credentials.json"} <= normal.keys():
        raise ValueError("完整恢复点缺少账本元数据、请求日志或服务凭据")
    head = value["ledger_head"]
    if (head > len(normal)
        or any("ledger/" + str(index).zfill(12) + ".json" not in normal for index in range(1, head + 1))):
        raise ValueError("账本事件文件与固定 head 不完整")
    for name in normal:
        logical = PurePosixPath(name)
        if (not isinstance(name, str) or logical.is_absolute() or str(logical) != name or ".." in logical.parts
            or "\\" in name or ":" in name):
            raise ValueError("备份原件路径无效")
    if "tls/key.pem" not in service or not ({"tls/cert-v2.pem", "tls/cert.pem"} & service.keys()):
        raise ValueError("TLS 白名单不完整")
    if not service.keys() <= {"tls/key.pem", "tls/cert-v2.pem", "tls/cert.pem"}:
        raise ValueError("TLS 清单超出白名单")
    configuration = value.get("configuration_backup") or {}
    if configuration.get("status") == "complete":
        row = normal.get("service-config.json")
        if (configuration.get("file") != "service-config.json" or not row or
                configuration.get("sha256") != row.get("sha256")):
            raise ValueError("实际启动配置清单不完整")
        config_status = "complete"
    elif legacy_config is not None:
        legacy_config = Path(legacy_config)
        if (legacy_config.resolve() != (archive / (tag + ".launch.json")).resolve() or legacy_config.is_symlink() or
                not legacy_config.is_file() or not isinstance(launch_sha, str) or
                not re.fullmatch(r"[a-f0-9]{64}", launch_sha) or
                os.name == "posix" and legacy_config.stat().st_mode & 0o077):
            raise ValueError("首次旧版备份需要同档案中已经固定的私有启动配置")
        raw = legacy_config.read_bytes()
        if hashlib.sha256(raw).hexdigest() != launch_sha or json.loads(raw).get("format") != 1:
            raise ValueError("首次旧版启动配置摘要不一致")
        config_status = "legacy-separate"
    else:
        raise ValueError("完整恢复点缺少实际启动配置")
    if (archive / "objects").is_symlink():
        raise ValueError("备份对象目录不能是链接")
    for row in [*normal.values(), *service.values()]:
        sha, size = row.get("sha256"), row.get("bytes")
        if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{64}", sha) or type(size) is not int or size < 0:
            raise ValueError("备份对象引用无效")
        obj = archive / "objects" / sha
        info = obj.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_size != size
            or os.name == "posix" and stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("备份对象缺失、链接、大小或权限无效")
        with obj.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != sha:
                raise ValueError("备份对象摘要不一致")
    return {"snapshot": path.name, "files": len(normal), "service_files": len(service), "head": value["ledger_head"],
            "configuration": config_status}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--allow-legacy-config", type=Path, help="仅首次旧版冷备份，指定同档案tag.launch.json")
    parser.add_argument("--launch-config-sha256")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.archive, args.tag, args.allow_legacy_config, args.launch_config_sha256)))
    except (OSError, ValueError, TypeError, KeyError):
        raise SystemExit("Backup is incomplete or could not be verified; existing snapshots retained.")
