"""Observe the built package on a dedicated ext4 fixture for the planned 24 hours."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import time
import zipfile

from verify import ROOT, claim_args, server, sha
from verify_round import Browser, Client, auth_checks, browser_admin_api, setup
from verify_upgrade import capability, control, register, review, seal


def utc():
    return datetime.now(timezone.utc).isoformat()


def record(path, value):
    pending = path.with_suffix(".pending")
    pending.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
    pending.replace(path)


def exercise(args):
    archive = ROOT / "dist" / "task-pool-local.zip"
    project = ROOT / "soak-fixture"
    project.mkdir()
    with zipfile.ZipFile(archive) as package:
        package.extractall(project)
    _, tokens, password = setup(project)
    result = {"status": "running", "started": utc(), "seconds_required": args.seconds, "artifact_sha256": sha(archive.read_bytes()),
              "restarts": 0, "tasks": [], "health_reads": 0}
    record(args.report, result)
    started = time.monotonic()
    try:
        for index in range(20):
            with server(project) as (_, url):
                if index == 0:
                    _, admin, _ = auth_checks(project, url, tokens, password)
                else:
                    result["restarts"] += 1
                    browser = Browser(url)
                    browser.login("admin", password)
                    browser.send("/")
                    admin = browser_admin_api(project, browser)
                w = Client(url, tokens["worker-a"])
                other = Client(url, tokens["worker-b"])
                receiver = Client(url, tokens["reviewer"])
                if index == 0:
                    capability(w, "worker-a")
                    capability(other, "worker-b")
                registration = register(admin, "reviewer")
                task = w.get("tasks/" + registration["task_id"])["task"]
                control(admin, "task-publish", task)
                task = w.get("tasks/" + task["task_id"])["task"]
                body = {k: task[k] for k in ("task_id", "version", "scope_version")}
                # Both callers use one immutable task and scope version.
                from verify import call
                from verify_round import request_id
                requests = [{**body, "request_id": request_id()}, {**body, "request_id": request_id()}]
                with ThreadPoolExecutor(2) as pool:
                    outcomes = list(pool.map(lambda item: call(url + "/claim", item[0].token, item[1]),
                                            zip((w, other), requests)))
                assert sorted(code for code, _ in outcomes) == [200, 409]
                winner_index = next(i for i, (status, _) in enumerate(outcomes) if status == 200)
                winner = (w, other)[winner_index]
                receipt = outcomes[winner_index][1]
                # Reconnect on a new HTTP connection and replay the exact request.
                assert call(url + "/claim", winner.token, requests[winner_index]) == (200, receipt)
                bundle = seal(winner, receipt)
                review(receiver, bundle)
                winner.post("stop", **claim_args(receipt), stop_evidence="隔离文档程序已结束")
                close = receiver.post("close", task_id=task["task_id"])
                assert close["task"]["status"] == "completed"
                result["tasks"].append({"task": task["task_id"], "head": close["head"], "at": utc(),
                                        "claim": receipt["claim"]["claim_id"]})
                record(args.report, result)
                deadline = started + args.seconds * (index + 1) / 20
                while time.monotonic() < deadline:
                    assert w.get("upgrade")["format"]["schema"] == 3
                    result["health_reads"] += 1
                    result["observed_seconds"] = int(time.monotonic() - started)
                    record(args.report, result)
                    time.sleep(min(60, max(0, deadline - time.monotonic())))
        result.update(status="passed", finished=utc(), observed_seconds=int(time.monotonic() - started))
    except BaseException as error:
        result.update(status="failed", finished=utc(), reason=type(error).__name__)
        raise
    finally:
        record(args.report, result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=86400)
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.seconds < 0:
        parser.error("--seconds must be nonnegative")
    exercise(arguments)
