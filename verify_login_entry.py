"""Regression coverage for the v3 anonymous home and password login entry."""
import json
from pathlib import Path
import zipfile

from verify import ROOT, server, sha
from verify_support import report_path, scratch
from verify_round import Browser, setup


def password_page(response):
    status, _, body = response
    assert status == 200
    assert b'name="password"' in body and b'name="token"' not in body
    assert b'action="/login"' in body and b'/password/setup' in body
    assert b'name="csrf"' in body


def main():
    archive = ROOT / "dist/task-pool-local.zip"
    with scratch("login-entry-") as directory:
        project = Path(directory)
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(project)
        _, _, password = setup(project)
        with server(project) as (_, url):
            browser = Browser(url)
            password_page(browser.send("/"))
            password_page(browser.send("/login"))
            browser.login("admin", password)
            status, _, body = browser.send("/")
            assert status == 200 and "<title>我的工作 · 内网任务服务</title>".encode() in body
            assert b'href="/board"' in body
            assert b'name="password"' not in body
            assert browser.send("/logout", "POST")[0] == 303
            password_page(browser.send("/"))
            password_page(browser.send("/?mine=1"))
    report = {"status": "passed", "artifact_sha256": sha(archive.read_bytes()),
              "checks": ["anonymous-home", "explicit-login", "csrf-password-login",
                         "authenticated-home", "logout-home", "anonymous-home-query"]}
    report_path("login-entry-regression.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
