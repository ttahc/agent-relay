"""Verify the optional-password policy through all password entry points."""
from pathlib import Path
import json
import re
import zipfile

from verify import ROOT, server, sha
from verify_support import report_path, scratch
from verify_round import Browser, setup, password_record, browser_admin_api, bind, request_id


def main():
    archive = ROOT / "dist/task-pool-local.zip"
    with scratch("password-six-") as directory:
        project = Path(directory)
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(project)
        _, tokens, admin_password = setup(project)
        with server(project) as (_, url):
            admin = Browser(url)
            admin.login("admin", admin_password)
            admin.send("/")
            manager = browser_admin_api(project, admin)
            bind(manager, "worker-a", "executor")
            admin.send("/accounts")
            status, _, page = admin.send("/accounts", "POST", {"request_id": request_id(), "role": "executor"})
            assert status == 200
            code = re.search(rb'class="credential">([A-Za-z0-9_-]{43})<', page)[1].decode()
            assert password_record(Browser(url), "/register", "policy-person", "", invitation=code)[0] == 303
            person = Browser(url)
            person.login("policy-person", "")
            Browser(url).login("policy-person", "\0", 401)
            assert password_record(Browser(url), "/password/setup", "worker-a", "x", token=tokens["worker-a"])[0] == 303
            Browser(url).login("worker-a", "x")
            _, _, page = person.send("/password")
            assert "密码无长度要求，允许留空。".encode() in page
            for tag in re.findall(rb'<input[^>]+>', page):
                if b'type="password"' in tag:
                    assert b"required" not in tag and b"minlength" not in tag and b"maxlength" not in tag
            fields = {"request_id": request_id(), "current": "", "password": "kP7!z", "confirm": "kP7!z"}
            assert person.send("/password", "POST", fields)[0] == 303
            person.login("policy-person", "kP7!z")
            person.send("/password")
            changed = "kP7!z" + "long-password-check-" * 14
            assert person.send("/password", "POST", {**fields, "request_id": request_id(), "current": "kP7!z",
                               "password": changed, "confirm": changed})[0] == 303
            person.login("policy-person", changed)
            admin.send("/accounts/reset")
            status, _, page = admin.send("/accounts/reset", "POST", {"request_id": request_id(), "identity": "policy-person"})
            assert status == 200
            reset = re.search(rb'class="credential">([A-Za-z0-9_-]{43})<', page)[1].decode()
            assert password_record(Browser(url), "/password/reset", "policy-person", "", reset=reset)[0] == 303
            Browser(url).login("policy-person", "")
            Browser(url).login("admin", admin_password)
    result = {"status": "passed", "minimum": None, "maximum": None, "empty_allowed": True, "artifact_sha256": sha(archive.read_bytes()),
              "checks": ["registration", "legacy-setup", "password-change", "password-reset",
                         "empty-login", "one-character-login", "five-character-login", "over-128-character-login",
                         "malformed-input-rejected", "existing-password-login", "html-hints"]}
    report_path("password-policy-regression.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
