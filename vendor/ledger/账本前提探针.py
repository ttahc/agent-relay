#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V1/V3/V4: real files and owned Python processes; never starts the product."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import uuid

from 协作存储 import digest, encoded, ntfs_identity, publish


def worker(mode, target):
    path = Path(target)
    data = encoded({"payload": "fixture" * 32768})
    if mode == "partial":
        with (path.parent / (".pending-" + uuid.uuid4().hex)).open("xb") as stream:
            stream.write(data[:4096])
            stream.flush()
            print("partial", flush=True)
            sys.stdin.buffer.read(1)
    elif mode in {"staged", "published"}:
        def checkpoint(phase):
            if phase == mode:
                print(phase, flush=True)
                sys.stdin.buffer.read(1)
        publish(path, data, checkpoint)
    else:
        print("ready", flush=True)
        sys.stdin.buffer.read(1)
        print(json.dumps({"won": publish(path, data)}), flush=True)


def qualify(store, output, identity_fn=ntfs_identity):
    store = Path(store).absolute()
    store.mkdir(parents=True, exist_ok=True)
    identity = identity_fn(store)
    fixture = store / ("qualification-" + uuid.uuid4().hex)
    fixture.mkdir()
    checks = []
    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        checks.append(name)
    target = fixture / "once.json"
    original = encoded({"complete": True})
    check("V1:first-publication", publish(target, original))
    check("V1:no-replace", not publish(target, b"different"))
    check("V1:original-intact", target.read_bytes() == original)
    for mode in ("partial", "staged", "published"):
        for index in range(3):
            target = fixture / (mode + str(index) + ".json")
            proc = subprocess.Popen([sys.executable, "-B", __file__, "--worker", mode, str(target)],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                check("V3:owned-worker-" + mode + str(index), proc.stdout.readline().strip() == mode.encode())
                proc.kill()
                # Wait for termination before communicate closes the checkpoint pipe.
                proc.wait(timeout=10)
                proc.communicate(timeout=10)
                check("V3:target-" + mode + str(index),
                      (json.loads(target.read_bytes())["payload"] == "fixture" * 32768)
                      if mode == "published" else not target.exists())
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate(timeout=10)
    for round_no in range(4):
        target = fixture / ("race" + str(round_no) + ".json")
        processes = [subprocess.Popen([sys.executable, "-B", __file__, "--worker", "race", str(target)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                     for _ in range(8)]
        try:
            check("V4:ready-" + str(round_no), all(p.stdout.readline().strip() == b"ready" for p in processes))
            for proc in processes:
                proc.stdin.write(b"x")
                proc.stdin.flush()
            results = [p.communicate(timeout=15) for p in processes]
            check("V4:one-winner-" + str(round_no),
                  sum(json.loads(out)["won"] for out, err in results) == 1 and
                  all(p.returncode == 0 for p in processes))
            check("V4:complete-" + str(round_no),
                  json.loads(target.read_bytes())["payload"] == "fixture" * 32768)
        finally:
            for proc in processes:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate(timeout=10)
    report = {"schema": 1, "identity": identity, "V1": "passed", "V3": "passed", "V4": "passed",
              "V2": {"remote_vm": "not-run", "no_delete_acl": "not-run", "unqualified": "receive-only"},
              "passed": len(checks), "failed": 0, "checks": checks, "fixture": str(fixture)}
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not publish(path, encoded(report)):
        raise ValueError("不覆盖旧前提验证")
    return {"passed": len(checks), "failed": 0, "report": str(path), "sha256": digest(path.read_bytes())}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", choices=["partial", "staged", "published", "race"])
    parser.add_argument("target", nargs="?")
    parser.add_argument("--store")
    parser.add_argument("--output")
    args = parser.parse_args()
    if args.worker:
        worker(args.worker, args.target)
    else:
        print(json.dumps(qualify(args.store, args.output), ensure_ascii=False))
