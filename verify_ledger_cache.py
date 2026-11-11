"""The service reads only new ledger entries, and falls back to a full verification on any doubt.

Runs on disposable stores under .state/ built by the real init command and real writes.
Every incremental result is compared with a full read of the whole hash chain.
"""
import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT), str(ROOT / "vendor" / "ledger")]

from pool import storage  # noqa: E402
from pool.constants import COORDINATOR  # noqa: E402
from pool.service import Service, state_path  # noqa: E402
from 协作账本 import Ledger  # noqa: E402
from 协作存储 import digest, encoded  # noqa: E402


def full(store):
    return Ledger.read(storage.LedgerBackend(store))


def same(test, left, right):
    test.assertEqual((left["head"], left["sha256"], left["halted"]), (right["head"], right["sha256"], right["halted"]))
    test.assertEqual(left["state"], right["state"])
    test.assertEqual(left["control"], right["control"])
    test.assertEqual(left["entries"], right["entries"])


class IncrementalRead(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.name = "ledger-cache-" + secrets.token_hex(4)
        cls.store = state_path(cls.name)
        cls.addClassCleanup(shutil.rmtree, cls.store, True)
        done = subprocess.run([sys.executable, "-B", "-X", "utf8", str(ROOT / "taskpool.py"), "--store", cls.name, "init",
                               "--worker", "worker-a", "--receiver", "reviewer", "--authority", "ledger cache check"],
                              capture_output=True, cwd=ROOT, timeout=120)
        assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
        cls.service = Service(cls.store)
        cls.added = 0
        for _ in range(12):
            cls.add_task()

    @classmethod
    def add_task(cls):
        cls.added += 1
        raw = b"ledger cache input"
        rid = f"cache-{cls.added:04d}-{secrets.token_hex(3)}"
        body = {"request_id": rid, "title": f"Cache {cls.added}", "path": f"inputs/{digest(raw)}/brief.md",
                "criteria": ["ready"], "receiver": "reviewer", "input": base64.b64encode(raw).decode("ascii")}
        status, result = cls.service.submit(COORDINATOR, "add-task", rid, body)
        assert status == 200, result

    def copy(self):
        target = state_path("ledger-cache-copy-" + secrets.token_hex(4))
        shutil.copytree(self.store, target)
        self.addCleanup(shutil.rmtree, target, True)
        return target

    def test_01_the_service_uses_the_incremental_backend(self):
        self.assertIsInstance(self.service.desk, storage.IncrementalRead)

    def test_02_a_repeated_read_equals_a_full_read(self):
        desk = self.service.desk
        desk.read()
        same(self, desk.read(), full(self.store))

    def test_03_after_new_writes_only_new_entries_are_opened(self):
        desk = self.service.desk
        desk.read()
        before = len(list((self.store / "ledger").glob("*.json")))
        self.add_task()
        desk.read()  # The write itself warmed the cache; read once more after adding one more.
        self.add_task()
        after = len(list((self.store / "ledger").glob("*.json")))
        opened = []
        real = storage.read_json
        with patch.object(storage, "read_json", lambda path: opened.append(Path(path).name) or real(path)):
            snap = desk.read()
        self.assertGreater(after, before)
        self.assertLessEqual(len(opened), after - before)
        self.assertTrue(all(name.endswith(".json") and int(name[:-5]) > before for name in opened), opened)
        same(self, snap, full(self.store))

    def test_04_every_caller_gets_an_independent_copy(self):
        desk = self.service.desk
        first = desk.read()
        first["state"]["tasks"].clear()
        first["state"]["pilot"]["changed"] = 99
        first["entries"].clear()
        first["control"]["gaps"].add(("x", 1, 2))
        same(self, desk.read(), full(self.store))

    def test_05_a_changed_old_entry_is_caught_like_a_full_read(self):
        target = self.copy()
        desk = storage.LedgerBackend(target)
        desk.read()
        path = target / "ledger" / "000000000003.json"
        entry = json.loads(path.read_bytes())
        entry["prev_sha256"] = "f" * 64
        os.chmod(path, 0o600)
        path.write_bytes(encoded(entry))
        snap = desk.read()
        self.assertEqual(snap["halted"]["position"], 3)
        same(self, snap, full(target))

    def test_06_a_same_size_rewrite_is_still_caught(self):
        target = self.copy()
        desk = storage.LedgerBackend(target)
        desk.read()
        path = target / "ledger" / "000000000002.json"
        raw = bytearray(path.read_bytes())
        at = raw.index(b'"sha256"') + 12
        raw[at] = ord("0") if raw[at] != ord("0") else ord("1")
        info = path.stat()
        os.chmod(path, 0o600)
        path.write_bytes(bytes(raw))
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))  # Even with the old modification time restored.
        snap = desk.read()
        self.assertIsNotNone(snap["halted"])
        same(self, snap, full(target))

    def test_07_a_removed_entry_falls_back_to_a_full_read(self):
        target = self.copy()
        desk = storage.LedgerBackend(target)
        desk.read()
        last = sorted((target / "ledger").glob("*.json"))[-1]
        os.chmod(last.parent, 0o700)
        last.unlink()
        same(self, desk.read(), full(target))

    def test_08_a_broken_new_entry_halts_like_a_full_read(self):
        target = self.copy()
        desk = storage.LedgerBackend(target)
        good = desk.read()
        entry = {**good["entries"][-1], "ledger_seq": good["head"] + 1, "prev_sha256": "0" * 64}
        entry.pop("sha256")
        entry["sha256"] = digest(encoded(entry))
        path = target / "ledger" / f"{good['head'] + 1:012d}.json"
        os.chmod(path.parent, 0o700)
        path.write_bytes(encoded(entry))
        snap = desk.read()
        self.assertEqual(snap["halted"]["position"], good["head"] + 1)
        same(self, snap, full(target))
        same(self, desk.read(), full(target))  # A halted result is never kept.

    def test_09_a_gap_in_numbering_halts_like_a_full_read(self):
        target = self.copy()
        desk = storage.LedgerBackend(target)
        good = desk.read()
        source = target / "ledger" / f"{good['head']:012d}.json"
        os.chmod(source.parent, 0o700)
        shutil.copy(source, target / "ledger" / f"{good['head'] + 2:012d}.json")
        snap = desk.read()
        self.assertIsNotNone(snap["halted"])
        same(self, snap, full(target))

    def test_10_forget_makes_the_next_read_a_full_verification(self):
        desk = self.service.desk
        desk.read()
        desk.forget()
        with patch.object(Ledger, "read", wraps=Ledger.read, autospec=True) as whole:
            snap = desk.read()
        self.assertEqual(whole.call_count, 1)
        same(self, snap, full(self.store))

    def test_12_inbox_copies_equal_a_full_check_and_are_independent(self):
        desk = self.service.desk
        first = desk.copies()
        self.assertEqual(first, Ledger.copies(desk))
        first[0]["envelope"]["payload"] = "changed"
        first.clear()
        self.assertEqual(desk.copies(), Ledger.copies(desk))

    def test_13_only_new_inbox_copies_are_opened(self):
        desk = self.service.desk
        desk.copies()
        before = {path.name for path in (self.store / "inbox").glob("*.json")}
        self.add_task()
        desk.copies()
        self.add_task()
        added = {path.name for path in (self.store / "inbox").glob("*.json")} - before
        opened = []
        real = storage.read_json
        with patch.object(storage, "read_json", lambda path: opened.append(Path(path).name) or real(path)):
            desk.copies()
        self.assertTrue(added)
        self.assertTrue(set(opened) <= added, opened)

    def test_14_a_changed_inbox_copy_is_refused_like_a_full_check(self):
        target = self.copy()
        desk = storage.LedgerBackend(target)
        desk.copies()
        path = sorted((target / "inbox").glob("*.json"))[0]
        record = json.loads(path.read_bytes())
        record["envelope"]["event_id"] = "changed-" + record["envelope"]["event_id"]
        os.chmod(path, 0o600)
        path.write_bytes(encoded(record))
        with self.assertRaises(ValueError):
            Ledger.copies(desk)
        with self.assertRaises(ValueError):
            desk.copies()

    def test_11_an_unchanged_read_is_faster_than_a_full_read(self):
        desk = self.service.desk
        desk.read()
        rounds = 20
        start = time.perf_counter()
        for _ in range(rounds):
            desk.read()
        kept = time.perf_counter() - start
        start = time.perf_counter()
        for _ in range(rounds):
            full(self.store)
        whole = time.perf_counter() - start
        print(f"\n{len(desk.read()['entries'])} entries: kept read {kept / rounds * 1000:.2f} ms, "
              f"full read {whole / rounds * 1000:.2f} ms", file=sys.stderr)
        self.assertLess(kept, whole)


if __name__ == "__main__":
    unittest.main(verbosity=2)
