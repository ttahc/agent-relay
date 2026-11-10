"""Produce a reproducible, dependency-free source bundle on Windows or WSL."""

import hashlib
from io import BytesIO
import os
from pathlib import Path
import tempfile
import zipfile
from pool.privacy import check_release


ROOT = Path(__file__).resolve().parent
FILES = [".gitignore", "LICENSE", "README.md", "build.py", "taskpool.py", "pool/__init__.py", "pool/constants.py", "pool/task_state.py", "pool/task_views.py", "pool/reads.py", "pool/task_plans.py",
         "pool/httpd.py", "pool/packages.py", "pool/service.py", "pool/storage.py", "pool/web.py",
         "pool/accounts.py", "pool/auth.py", "pool/round_service.py", "pool/round_web.py",
         "pool/round_projects.py", "pool/round_projects_web.py", "pool/account_projects.py",
         "pool/delegation.py", "pool/delegation_pages.py", "pool/invite_links.py",
         "pool/privacy.py", "pool/release_views.py", "pool/release_pages.py", "pool/display_time.py", "pool/backup.py", "pool/input_packages.py",
         "pool/window_admin.py", "pool/window_admin_pages.py", "pool/lifecycle.py", "pool/wakeups.py", "pool/sessions.py", "pool/safety.py", "pool/execution.py", "pool/execution_pages.py",
         "pool/collaboration_visibility.py", "pool/post_completion.py", "pool/post_completion_pages.py", "pool/task_communication.py", "pool/task_communication_pages.py", "pool/task_pages.py", "pool/upgrade.py", "pool/upgrade_pages.py",
         "pool/taskpool.css", "pool/workbench.py", "pool/workbench_pages.py", "pool/workbench.css", "pool/workbench.js", "vendor/SHA256SUMS", "docs/内网任务服务升级操作.md", "docs/本轮优化操作.md",
         "ops/podman-up.sh", "ops/fresh-install.sh", "ops/upgrade-local.sh", "ops/Set-LanIngress.ps1",
         "ops/Set-EasyTierIngress.ps1", "ops/verify-peer.py", "ops/round-client.py", "ops/round-client.ps1", "ops/round-local.sh",
         "ops/backup-store.py", "ops/safe-local-upgrade.sh", "ops/verify-release.py", "ops/launch-config.py", "ops/verify-backup.py",
         "ops/install-local-backup.sh", "ops/local-backup.sh", "ops/taskpool-local-backup.service", "ops/taskpool-local-backup.timer",
         "docs/AI客户端操作.md", "docs/运维与升级.md", "docs/统一任务流程.md"]


def bundle_bytes():
    vendor = ROOT / "vendor" / "SHA256SUMS"
    files = {name: (ROOT / name).read_bytes() for name in FILES}
    from pool import __version__, RELEASE_NAME
    files['README.md'] = (f'# 任务协作平台\n\nv{__version__} · {RELEASE_NAME}\n\n'
        '人员使用账号与密码，AI 窗口使用独立凭据文件；实际运行版本以服务响应头为准。\n\n'
        '- [人员操作手册](docs/本轮优化操作.md)\n'
        '- [AI 客户端操作](docs/AI客户端操作.md)\n'
        '- [运维与升级](docs/运维与升级.md)\n\n'
        '本包不含生产数据、真实凭据或测试数据。发行检查脚本需要完整源码仓库及其测试入口；'
        '不能把本包中缺少的检查计为通过。\n').encode('utf-8')
    for line in vendor.read_text(encoding="utf-8").splitlines():
        expected, name = line.split("  ", 1)
        path = "vendor/ledger/" + name
        raw = (ROOT / path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError(f"固定账本源码指纹不匹配 {path}")
        files[path] = raw
    for path, raw in files.items():
        if path.endswith(".py"):
            compile(raw, path, "exec", dont_inherit=True)
    return archive_bytes(files)


def archive_bytes(files):
    check_release(files)
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path, raw in sorted(files.items()):
            info = zipfile.ZipInfo(path, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)
    with zipfile.ZipFile(BytesIO(stream.getvalue())) as archive:
        if set(archive.namelist()) != set(files) or any(archive.read(path) != raw for path, raw in files.items()):
            raise ValueError("构建包回读不一致")
    return stream.getvalue()


def client_bundle_bytes():
    import json
    from pool import __version__
    files = {name: (ROOT / name).read_bytes() for name in (
        "ops/round-client.py", "ops/round-client.ps1", "docs/AI客户端操作.md", "LICENSE")}
    files["README.md"] = files["docs/AI客户端操作.md"]
    files["client-version.json"] = json.dumps({"version": __version__, "protocol": 1,
        "purpose": "ai-window-client"}, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return archive_bytes(files)


def build():
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    for name, raw in (("task-pool-local.zip", bundle_bytes()), ("taskpool-ai-client.zip", client_bundle_bytes())):
        target = dist / name
        with tempfile.NamedTemporaryFile(dir=dist, suffix=".zip", delete=False) as stream:
            temporary = Path(stream.name)
        try:
            temporary.write_bytes(raw)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        print(hashlib.sha256(target.read_bytes()).hexdigest(), target)


if __name__ == "__main__":
    build()
