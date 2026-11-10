"""Run release checks on a disposable source copy and retain every result."""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import uuid


ROOT = Path(__file__).resolve().parents[1]
FAST = ("build", "verify_privacy", "verify_feedback_move", "verify_account_projects",
        "verify_v030_ux", "verify_v030_windows", "verify_v030_continuity", "verify_v030_identity",
        "verify_v030_review_read", "verify_v030_badges_history", "verify_release_runner",
        "verify_v030_credential_recovery", "verify_v030_input_packages", "verify_v030_r2_safety",
        "verify_r2_execution", "verify_r2_resume_segments", "verify_v030_resume_ui", "verify_v030_r2_client", "verify_v030_r2_ui", "verify_v030_execution_projection_ui", "verify_v030_review_mode_ui",
        "verify_v030_ux_readiness", "verify_v030_workspace_refresh", "verify_v030_post_recovery")
RELEASE = ("build", "verify", "verify_upgrade", "verify_round") + FAST[1:]
REPORTS = {"verify", "verify_upgrade", "verify_round"}
KNOWN = set(RELEASE) | {"verify_delegation", "verify_delegation_scope_regression", "verify_release_runner"}
SOURCE_SUFFIXES = {"pool": {".py", ".js", ".css", ".json"}, "docs": {".md", ".json", ".html"},
                   "ops": {".py", ".ps1", ".sh", ".service", ".timer"}}


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    temporary = path.with_name(path.name + ".new-" + uuid.uuid4().hex)
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def source_files(root):
    """Only source, bundled documentation and test helpers; no local stores or output."""
    paths = [root / name for name in (".gitignore", "README.md", "LICENSE", "build.py", "taskpool.py", "Containerfile") if (root/name).exists()]
    paths += list(root.glob("verify*.py")) + list(root.glob("verify*.js"))
    for folder, suffixes in SOURCE_SUFFIXES.items():
        paths += [path for path in (root / folder).rglob("*") if path.suffix.lower() in suffixes]
    paths += [root / "vendor" / "SHA256SUMS"] + list((root / "vendor" / "ledger").glob("*.py"))
    result = {}
    for path in sorted(set(paths)):
        relative = path.relative_to(root)
        if any(part in {".git", ".state", "dist", "__pycache__"} for part in relative.parts):
            continue
        if not path.exists():
            continue
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root and root in parent.parents):
            raise ValueError(f"候选源码不能通过符号链接取文件：{relative}")
        if path.is_file():
            result[relative.as_posix()] = path.read_bytes()
    for required in ("build.py", "taskpool.py", "pool/__init__.py"):
        if required not in result:
            raise ValueError(f"缺少候选源码：{required}")
    return result


def source_metadata(files):
    hashes = {name: sha(raw) for name, raw in sorted(files.items())}
    fingerprint = sha(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    version = "unknown"
    for node in ast.parse(files["pool/__init__.py"].decode("utf-8-sig")).body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets):
            value = ast.literal_eval(node.value)
            if isinstance(value, str):
                version = value
    return {"sha256": fingerprint, "version": version, "files": hashes}


def selected_tests(suite, only):
    if not only:
        return list(FAST if suite == "fast" else RELEASE)
    names = [name.removesuffix(".py").removesuffix('.js') for item in only for name in item.split(",") if name]
    unknown = {name for name in names if name not in KNOWN and not (
        re.fullmatch(r'verify_[A-Za-z0-9_]+',name) and any((ROOT/(name+ext)).is_file() for ext in ('.py','.js')))}
    if unknown:
        raise ValueError("未知验证项：" + ", ".join(sorted(unknown)))
    result = list(dict.fromkeys(names))
    if not result:
        raise ValueError("--only 须至少选择一个验证项")
    if any(name in REPORTS for name in result) and "build" not in result:
        result.insert(0, "build")
    if "build" in result:
        result = ["build"] + [name for name in result if name != "build"]
    return result


def default_output(root):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return root / ".state" / "verification" / (stamp + "-" + uuid.uuid4().hex[:10])


def check_output(root, output):
    if output == root or output in root.parents:
        raise ValueError("验证输出不能是源码目录或其上级目录")
    for folder in ("dist", "pool", "ops", "docs", "vendor", ".git"):
        protected = root / folder
        if output == protected or protected in output.parents:
            raise ValueError("验证输出不能写入原始源码或 dist 目录")


def command_for(name, candidate, report):
    if (candidate/(name+'.js')).is_file():
        node=shutil.which('node')
        if not node:
            raise ValueError('JavaScript 必验项需要可用 node，不能跳过计为通过')
        return [node,str(candidate/(name+'.js'))]
    command = [sys.executable, "-B", "-X", "utf8", str(candidate / ("build.py" if name == "build" else name + ".py"))]
    if name in REPORTS:
        command += ["--report", str(report)]
    return command


def collect_artifacts(candidate, destination, output):
    result = []
    dist = candidate / "dist"
    if not dist.exists():
        return result
    for path in sorted(dist.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(dist)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        result.append({"path": target.relative_to(output).as_posix(), "name": relative.as_posix(),
                       "sha256": sha(target.read_bytes()), "bytes": target.stat().st_size})
    return result


def restore_build(record, output, candidate):
    artifacts = record.get("artifacts", [])
    if not artifacts:
        raise ValueError("已通过的构建没有保留产物，不能继续复用；请另选新输出目录")
    for artifact in artifacts:
        source = (output / artifact["path"]).resolve()
        target = (candidate / "dist" / artifact["name"]).resolve()
        if output not in source.parents or (candidate / "dist").resolve() not in target.parents:
            raise ValueError("构建产物路径超出验证目录")
        raw = source.read_bytes()
        if sha(raw) != artifact["sha256"]:
            raise ValueError("已通过的构建产物指纹变化，拒绝复用")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)


def run(root, output=None, suite="fast", only=None, resume=False):
    root = Path(root).resolve()
    if resume and output is None:
        raise ValueError("--resume 须显式指定原 --output 目录")
    tests = selected_tests(suite, only)
    files = source_files(root)
    metadata = source_metadata(files)
    runtime = {"platform": sys.platform, "python": sys.version.split()[0], "executable": str(Path(sys.executable).resolve())}
    output = Path(output).resolve() if output else default_output(root)
    check_output(root, output)
    manifest_path = output / "manifest.json"
    if resume:
        if not manifest_path.is_file():
            raise ValueError("找不到可继续的 manifest.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("schema") != 1 or manifest.get("source", {}).get("sha256") != metadata["sha256"]:
            raise ValueError("候选源码指纹已变化，不能复用旧结果；请使用新输出目录")
        if manifest.get("runtime") != runtime:
            raise ValueError("验证运行环境已变化，不能复用旧结果；请使用新输出目录")
    else:
        if output.exists() and any(output.iterdir()):
            raise ValueError("输出目录非空；继续原验证请使用 --resume，否则请选择新目录")
        output.mkdir(parents=True, exist_ok=True)
        manifest = {"schema": 1, "created_utc": utc(), "source": metadata, "runtime": runtime, "attempts": [], "results": {}}
    attempt = "attempt-" + uuid.uuid4().hex[:12]
    attempt_root = output / attempt
    candidate = attempt_root / "source"
    candidate.mkdir(parents=True)
    for name, raw in files.items():
        path = candidate / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    attempt_record = {"id": attempt, "suite": suite, "selected": tests, "started_utc": utc(),
                      "source_sha256": metadata["sha256"], "reused": [], "executed": []}
    manifest["attempts"].append(attempt_record)
    manifest.update(status="running", updated_utc=utc())
    write_json(manifest_path, manifest)
    failed = False
    for name in tests:
        prior = manifest["results"].get(name)
        if resume and prior and prior.get("status") == "passed" and prior.get("source_sha256") == metadata["sha256"]:
            if name == "build" and any(test in REPORTS for test in tests):
                try:
                    restore_build(prior, output, candidate)
                except (OSError, ValueError) as error:
                    attempt_record.update(status="failed", error=str(error), finished_utc=utc())
                    manifest.update(status="failed", updated_utc=utc())
                    write_json(manifest_path, manifest)
                    raise
            attempt_record["reused"].append(name)
            print("REUSE", name, flush=True)
            continue
        if name in REPORTS and manifest["results"].get("build", {}).get("status") != "passed":
            failed = True
            manifest["results"][name] = {"status": "blocked", "reason": "build failed", "source_sha256": metadata["sha256"]}
            write_json(manifest_path, manifest)
            continue
        logs = attempt_root / "logs"
        logs.mkdir(exist_ok=True)
        reports = attempt_root / "reports"
        reports.mkdir(exist_ok=True)
        stdout_path, stderr_path = logs / (name + ".stdout.log"), logs / (name + ".stderr.log")
        record = {"status": "running", "started_utc": utc(), "source_sha256": metadata["sha256"],
                  "stdout": stdout_path.relative_to(output).as_posix(), "stderr": stderr_path.relative_to(output).as_posix()}
        if prior:
            record["previous_attempts"] = prior.get("previous_attempts", []) + [{key: value for key, value in prior.items() if key != "previous_attempts"}]
        manifest["results"][name] = record
        attempt_record["executed"].append(name)
        write_json(manifest_path, manifest)
        command = command_for(name, candidate, reports / (name + ".json"))
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", TASKPOOL_VERIFICATION_OUTPUT=str(attempt_root))
        try:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                code = subprocess.run(command, cwd=candidate, env=environment, stdout=stdout, stderr=stderr, check=False).returncode
        except OSError as error:
            stderr_path.write_text(str(error) + "\n", encoding="utf-8")
            code = 127
        record.update(status="passed" if code == 0 else "failed", exit_code=code, finished_utc=utc(),
                      artifacts=collect_artifacts(candidate, attempt_root / "artifacts" / name, output))
        report = reports / (name + ".json")
        if report.is_file():
            record["report"] = report.relative_to(output).as_posix()
            record["report_sha256"] = sha(report.read_bytes())
        failed |= code != 0
        manifest["updated_utc"] = utc()
        write_json(manifest_path, manifest)
        print(record["status"].upper(), name, flush=True)
    attempt_record["finished_utc"] = utc()
    attempt_record["status"] = "failed" if failed else "passed"
    failed |= any(record.get("status") != "passed" for record in manifest["results"].values())
    manifest.update(status="failed" if failed else "passed", updated_utc=utc())
    write_json(manifest_path, manifest)
    print(json.dumps({"status": manifest["status"], "output": str(output), "manifest": str(manifest_path),
                      "source_sha256": metadata["sha256"]}, ensure_ascii=False), flush=True)
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="本轮独立输出目录；默认使用唯一 .state/verification 子目录")
    parser.add_argument("--suite", choices=("fast", "release"), default="fast")
    parser.add_argument("--only", action="append", help="仅执行指定项，可重复或用逗号分隔；v1/v2/v3 自动先构建")
    parser.add_argument("--resume", action="store_true", help="仅复用同一源码指纹下已通过的项目")
    args = parser.parse_args(argv)
    try:
        return run(ROOT, args.output, args.suite, args.only, args.resume)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
