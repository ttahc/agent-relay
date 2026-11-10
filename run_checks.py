"""Build once, then run every verify*.py / verify*.js check and print a summary.

    python -B run_checks.py                  # build + all checks except the 24h soak
    python -B run_checks.py --only verify_round,verify_upgrade
    python -B run_checks.py --list

Works from any working directory and any checkout path. Logs and reports go to
.state/checks/<timestamp>/ (override with --output). For the fingerprinted
release gate use ops/verify-release.py instead.
"""
import argparse
from datetime import datetime, timezone
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
HELPERS = {"verify_support"}
REPORT_OPTION = re.compile(r'^\s*parser\.add_argument\(\s*"--report"', re.M)  # the check's own --report flag
SLOW = {"verify_soak"}  # 24h by default; run explicitly with --only verify_soak


def discover():
    names = {}
    for path in sorted(ROOT.glob("verify*.py")) + sorted(ROOT.glob("verify*.js")):
        if path.stem not in HELPERS:
            names.setdefault(path.stem, path)
    return names


def command(path, reports):
    if path.suffix == ".js":
        node = shutil.which("node")
        if not node:
            return None
        return [node, str(path)]
    result = [sys.executable, "-B", "-X", "utf8", str(path)]
    if REPORT_OPTION.search(path.read_text(encoding="utf-8")):
        result += ["--report", str(reports / (path.stem + ".json"))]
    return result


def run_one(name, argv, log, timeout):
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
    started = time.monotonic()
    with log.open("wb") as stream:
        try:
            code = subprocess.run(argv, cwd=ROOT, env=environment, stdout=stream, stderr=subprocess.STDOUT,
                                  timeout=timeout, check=False).returncode
        except subprocess.TimeoutExpired:
            stream.write(f"\n[run_checks] timed out after {timeout}s\n".encode())
            code = "timeout"
    return code, time.monotonic() - started


def tail(path, lines=8):
    text = path.read_text(encoding="utf-8", errors="replace").rstrip().splitlines()
    return "\n".join("    " + line for line in text[-lines:])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", action="append", default=[], help="只运行指定检查，可重复或用逗号分隔")
    parser.add_argument("--skip", action="append", default=[], help="跳过指定检查，可重复或用逗号分隔")
    parser.add_argument("--no-build", action="store_true", help="复用现有 dist/，不重新构建")
    parser.add_argument("--timeout", type=int, default=900, help="单项超时秒数（默认 900）")
    parser.add_argument("--output", type=Path, help="日志与报告目录；默认 .state/checks/<时间>")
    parser.add_argument("--fail-fast", action="store_true", help="遇到第一项失败即停止")
    parser.add_argument("--list", action="store_true", help="列出将运行的检查后退出")
    args = parser.parse_args(argv)

    split = lambda items: [n.strip().removesuffix(".py").removesuffix(".js") for i in items
                           for n in i.split(",") if n.strip()]
    available = discover()
    only, skip = split(args.only), set(split(args.skip))
    unknown = [name for name in [*only, *skip] if name not in available]
    if unknown:
        parser.error("未知检查：" + ", ".join(unknown))
    selected = [name for name in (only or [n for n in available if n not in SLOW]) if name not in skip]
    if args.list:
        print("\n".join(selected))
        return 0

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = (args.output or ROOT / ".state" / "checks" / stamp).resolve()
    logs, reports = output / "logs", output / "reports"
    logs.mkdir(parents=True, exist_ok=True)
    reports.mkdir(exist_ok=True)

    results = []
    if not args.no_build:
        print("build ...", end=" ", flush=True)
        code, seconds = run_one("build", [sys.executable, "-B", "-X", "utf8", str(ROOT / "build.py")],
                                logs / "build.log", args.timeout)
        print("ok" if code == 0 else "FAILED", f"({seconds:.0f}s)", flush=True)
        if code != 0:
            print(tail(logs / "build.log"))
            print(f"构建失败，未运行检查。日志：{logs / 'build.log'}")
            return 1

    for name in selected:
        argv_ = command(available[name], reports)
        log = logs / (name + ".log")
        print(f"{name} ...", end=" ", flush=True)
        if argv_ is None:
            log.write_text("node 不可用，无法运行 JavaScript 检查\n", encoding="utf-8")
            code, seconds = "no-node", 0.0
        else:
            code, seconds = run_one(name, argv_, log, args.timeout)
        ok = code == 0
        results.append((name, ok, code, seconds))
        print("ok" if ok else f"FAILED ({code})", f"({seconds:.0f}s)", flush=True)
        if not ok:
            print(tail(log))
            if args.fail_fast:
                break

    failed = [r for r in results if not r[1]]
    print()
    print(f"{len(results) - len(failed)}/{len(results)} 项通过；日志与报告：{output}")
    for name, _, code, _ in failed:
        print(f"  FAILED {name} ({code}) -> {logs / (name + '.log')}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
