"""Select and qualify the actual local storage backend."""

import os
from pathlib import Path
import re
import uuid

from 协作账本 import Ledger
from 协作存储 import encoded, ntfs_identity, publish, read_json, safe, sync_directory


def ext4_identity(store):
    store = Path(store).resolve(strict=True)
    mounts = []
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        before, after = line.split(" - ", 1)
        mount = Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), before.split()[4]))
        if store.is_relative_to(mount):
            mounts.append((len(mount.parts), after.split()[0]))
    if not mounts or max(mounts)[1] != "ext4":
        raise ValueError("Linux 账本须使用本机 ext4 数据卷")
    marker = read_json(safe(store, "volume-id.json"))
    if not isinstance(marker, dict) or not re.fullmatch(r"[0-9a-f]{32}", marker.get("id", "")):
        raise ValueError("数据卷标识无效")
    return {"filesystem": "ext4", "store": str(store), "volume_id": marker["id"]}


def initialize_backend(store):
    if os.name == "nt":
        return ntfs_identity
    sync_directory(store.parent)
    marker = safe(store, "volume-id.json")
    if not marker.exists():
        publish(marker, encoded({"id": uuid.uuid4().hex}))
    return ext4_identity


class Ext4Ledger(Ledger):
    @staticmethod
    def check_qualification(path, proof):
        if proof.get("failed") != 0 or any(proof.get(key) != "passed" for key in ("V1", "V3", "V4")):
            raise ValueError("ext4 文件发布资格未通过")
        if ext4_identity(path) != proof.get("identity"):
            raise ValueError("ext4 数据卷或账本位置已变化")
        probe = safe(path, ".permission-probe-" + uuid.uuid4().hex)
        if not publish(probe, b"qualified ext4 publication probe\n"):
            raise ValueError("提交权限探测冲突")
        probe.unlink()


LedgerBackend = Ledger if os.name == "nt" else Ext4Ledger
