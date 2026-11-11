"""Select and qualify the actual local storage backend."""

import os
from pathlib import Path
import pickle
import re
import threading
import uuid

from 协作账本 import Ledger, apply_entry
from 协作存储 import digest, encoded, ntfs_identity, publish, read_json, safe, sync_directory


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


def _fingerprint(entry):
    info = entry.stat(follow_symlinks=False)
    return entry.name, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino


class IncrementalRead:
    """Read the ledger by applying only the entries added since the last read.

    Ledger entries are numbered files that are only ever added. The result of the last full
    verification is kept as pickled bytes, so every caller still gets its own independent copy.
    Before reusing it, every already-verified file must show the same name, size, modification
    time, change time and inode; any difference, a missing file or a halted ledger falls back to
    the full verification of the whole hash chain. New entries are checked exactly as a full read
    checks them: position, previous hash, own hash, structure and the security rules.
    """

    def _read_cache(self):
        if not hasattr(self, "_cache_lock"):
            self._cache_lock, self._cache = threading.Lock(), None
        return self._cache

    def read(self):
        cached = self._read_cache()
        folder = safe(self.store, "ledger")
        try:
            with os.scandir(folder) as found:
                listed = sorted(_fingerprint(entry) for entry in found if entry.name.endswith(".json"))
        except FileNotFoundError:
            listed = []
        except OSError:
            return self._full()
        if cached is None or len(listed) < len(cached[0]) or listed[:len(cached[0])] != cached[0]:
            return self._full(listed)
        snap = pickle.loads(cached[1])
        if len(listed) == len(cached[0]):
            return snap
        from 协作安全 import check as check_security
        for name, *_ in listed[len(cached[0]):]:
            try:
                if name != f"{snap['head'] + 1:012d}.json":
                    raise ValueError("账本位置缺失或文件名无效")
                entry = read_json(safe(self.store, "ledger/" + name))
                checksum = entry.pop("sha256")
                if (type(entry["ledger_seq"]) is not int or entry["ledger_seq"] != snap["head"] + 1 or
                        entry["prev_sha256"] != snap["sha256"] or digest(encoded(entry)) != checksum):
                    raise ValueError("账本SHA或前链不匹配")
                entry["sha256"] = checksum
                apply_entry(snap, entry)
                check_security(snap["state"])
            except (OSError, ValueError, KeyError, TypeError):
                return self._full()  # Report the failure exactly as a full read does.
        self._remember(listed, snap)
        return snap

    def _full(self, listed=None):
        snap = Ledger.read(self)
        if listed is not None and not snap["halted"] and snap["head"] == len(listed):
            self._remember(listed, snap)
        else:
            self._cache = None
        return snap

    def _remember(self, listed, snap):
        with self._cache_lock:
            self._cache = (listed, pickle.dumps(snap, protocol=pickle.HIGHEST_PROTOCOL))

    def copies(self):
        """Inbox copies, re-reading only files that are new or whose metadata changed.

        Inbox files are published once and never rewritten. A file whose name, size, modification
        time, change time and inode are unchanged since it was verified is not hashed again.
        Everything else is checked exactly as the full method checks it.
        """
        self._read_cache()
        kept = getattr(self, "_copies", {})
        folder = safe(self.store, "inbox")
        if not folder.exists():
            self._copies = {}
            return []
        with os.scandir(folder) as found:
            listed = sorted(_fingerprint(entry) for entry in found if entry.name.endswith(".json"))
        fresh, result = {}, []
        for fingerprint in listed:
            name = fingerprint[0]
            known = kept.get(name)
            if known and known[0] == fingerprint:
                raw = known[1]
            else:
                record = read_json(safe(self.store, "inbox/" + name))
                if digest(encoded(record["envelope"])) != record["sha256"] or name[:-5] != record["copy_id"]:
                    raise ValueError("收件箱副本已变化，保留现场")
                raw = pickle.dumps(record, protocol=pickle.HIGHEST_PROTOCOL)
            fresh[name] = (fingerprint, raw)
            result.append(pickle.loads(raw))
        self._copies = fresh
        return result

    def forget(self):
        """Drop what was kept so the next read verifies the whole chain and inbox again."""
        self._read_cache()
        self._cache = None
        self._copies = {}


class Ext4Ledger(IncrementalRead, Ledger):
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


class NtfsLedger(IncrementalRead, Ledger):
    pass


LedgerBackend = NtfsLedger if os.name == "nt" else Ext4Ledger
