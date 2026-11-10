"""Release-runner isolation, receipt retention and source-bound resume checks."""
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
from io import StringIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("release_runner", ROOT / "ops" / "verify-release.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class ReleaseRunner(unittest.TestCase):
    def setUp(self):
        state = ROOT / ".state"
        state.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="verify-runner-", dir=state)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = self.base / "candidate"
        self.source.mkdir()
        for folder in ("pool", "ops", "docs", "vendor/ledger", ".state", ".git", "dist", "private-output"):
            (self.source / folder).mkdir(parents=True, exist_ok=True)
        (self.source / "pool/__init__.py").write_text('__version__ = "0.3.0-fixture"\n', encoding="utf-8")
        (self.source / "taskpool.py").write_text("# isolated source fixture\n", encoding="utf-8")
        (self.source / "docs/guide.md").write_text("synthetic documentation", encoding="utf-8")
        (self.source / "ops/helper.py").write_text("# helper", encoding="utf-8")
        (self.source / "vendor/SHA256SUMS").write_text("", encoding="utf-8")
        (self.source / "build.py").write_text(
            'from pathlib import Path\nroot=Path(__file__).parent\n'
            'assert root.name=="source", "build escaped disposable source"\n'
            '(root/"dist").mkdir(exist_ok=True)\n(root/"dist/artifact.zip").write_bytes(b"synthetic bundle")\nprint("build fixture")\n', encoding="utf-8")
        (self.source / "verify_privacy.py").write_text(
            'from pathlib import Path\nroot=Path(__file__).parent\nassert root.name=="source"\n'
            'assert not (root/".state/private").exists()\nassert not (root/".git/config").exists()\n'
            'assert not (root/"private-output").exists()\nassert not (root/"dist/original.zip").exists()\n'
            'print("isolated check passed")\n', encoding="utf-8")
        (self.source / "verify_feedback_move.py").write_text(
            'import os,sys\nfrom pathlib import Path\nprint("synthetic retry")\n'
            'if os.environ.get("VERIFY_RUNNER_GATE") and Path(os.environ["VERIFY_RUNNER_GATE"]).exists():\n'
            ' print("retained failure evidence",file=sys.stderr)\n sys.exit(7)\n', encoding="utf-8")
        for path in (".state/private", ".git/config", "private-output/credential.json", "dist/original.zip"):
            (self.source / path).write_bytes(b"do not copy or overwrite")
        self.output = self.base / "explicit-output"

    def run_runner(self, **kwargs):
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            return runner.run(self.source, **kwargs)

    def manifest(self, output=None):
        return json.loads(((output or self.output) / "manifest.json").read_text(encoding="utf-8"))

    def test_explicit_output_build_runs_only_in_copy_and_preserves_original_dist_private_data(self):
        self.assertEqual(self.run_runner(output=self.output, only=["build,verify_privacy"]), 0)
        manifest = self.manifest()
        self.assertEqual(manifest["source"]["version"], "0.3.0-fixture")
        self.assertEqual((self.source / "dist/original.zip").read_bytes(), b"do not copy or overwrite")
        self.assertFalse((self.source / "dist/artifact.zip").exists())
        self.assertFalse(any(name.startswith((".state/", ".git/", "dist/", "private-output/")) for name in manifest["source"]["files"]))
        for result in manifest["results"].values():
            self.assertTrue((self.output / result["stdout"]).is_file())
            self.assertTrue((self.output / result["stderr"]).is_file())
        self.assertTrue((self.output / manifest["results"]["build"]["artifacts"][0]["path"]).is_file())

    def test_default_output_is_unique_and_under_state_verification(self):
        self.assertEqual(self.run_runner(only=["verify_privacy"]), 0)
        self.assertEqual(self.run_runner(only=["verify_privacy"]), 0)
        outputs = list((self.source / ".state/verification").iterdir())
        self.assertEqual(len(outputs), 2)
        fingerprints = {self.manifest(output)["source"]["sha256"] for output in outputs}
        self.assertEqual(len(fingerprints), 1)

    def test_failure_keeps_passed_results_logs_and_resume_reuses_only_matching_source(self):
        gate = self.source / ".state/gate"
        gate.write_text("fail once", encoding="utf-8")
        with patch.dict(os.environ, {"VERIFY_RUNNER_GATE": str(gate)}):
            self.assertEqual(self.run_runner(output=self.output, only=["build,verify_privacy,verify_feedback_move"]), 1)
            first = self.manifest()
            self.assertEqual(first["results"]["verify_feedback_move"]["status"], "failed")
            original_log = self.output / first["results"]["verify_feedback_move"]["stderr"]
            self.assertIn("retained failure evidence", original_log.read_text(encoding="utf-8"))
            gate.unlink()
            self.assertEqual(self.run_runner(output=self.output, only=["build,verify_privacy,verify_feedback_move"], resume=True), 0)
        final = self.manifest()
        self.assertEqual(final["attempts"][-1]["reused"], ["build", "verify_privacy"])
        self.assertEqual(final["attempts"][-1]["executed"], ["verify_feedback_move"])
        self.assertEqual(final["results"]["build"], first["results"]["build"])
        self.assertEqual(final["results"]["verify_feedback_move"]["previous_attempts"][0]["exit_code"], 7)
        self.assertTrue(original_log.is_file())

    def test_resume_rejects_changed_source_without_modifying_old_manifest(self):
        self.run_runner(output=self.output, only=["verify_privacy"])
        before = (self.output / "manifest.json").read_bytes()
        (self.source / "pool/__init__.py").write_text('__version__="changed"\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "源码指纹"):
            self.run_runner(output=self.output, only=["verify_privacy"], resume=True)
        self.assertEqual((self.output / "manifest.json").read_bytes(), before)

    def test_existing_output_requires_resume_and_original_dist_is_never_a_valid_destination(self):
        self.run_runner(output=self.output, only=["verify_privacy"])
        with self.assertRaises(ValueError):
            self.run_runner(output=self.output, only=["verify_privacy"])
        for output in (self.source, self.source.parent, self.source / "dist", self.source / "pool/output"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                self.run_runner(output=output, only=["verify_privacy"])
        with self.assertRaises(ValueError):
            self.run_runner(only=["verify_privacy"], resume=True)

    def test_report_tests_add_build_and_resume_restores_verified_bundle_in_fresh_copy(self):
        (self.source / "verify.py").write_text(
            'import argparse\nfrom pathlib import Path\np=argparse.ArgumentParser();p.add_argument("--report",required=True);args=p.parse_args()\n'
            'assert (Path(__file__).parent/"dist/artifact.zip").read_bytes()==b"synthetic bundle"\n'
            'Path(args.report).write_text("{\\"passed\\":110,\\"fixture\\":true}",encoding="utf-8")\n', encoding="utf-8")
        self.assertEqual(self.run_runner(output=self.output, only=["build"]), 0)
        self.assertEqual(self.run_runner(output=self.output, only=["verify"], resume=True), 0)
        manifest = self.manifest()
        self.assertEqual(manifest["attempts"][-1]["reused"], ["build"])
        self.assertEqual(manifest["results"]["verify"]["status"], "passed")
        self.assertTrue((self.output / manifest["results"]["verify"]["report"]).is_file())

    def test_cli_parses_explicit_output_and_unknown_only_fails_before_creating_output(self):
        with patch.object(runner, "ROOT", self.source), redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            self.assertEqual(runner.main(["--output", str(self.output), "--suite", "fast", "--only", "verify_privacy"]), 0)
            self.assertEqual(runner.main(["--output", str(self.base / "unknown"), "--only", "made-up"]), 2)
        self.assertFalse((self.base / "unknown").exists())


if __name__ == "__main__":
    unittest.main()
