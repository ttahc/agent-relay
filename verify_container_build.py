"""Offline regression for the current Containerfile's explicit COPY inputs.

This stages the current simple file-only COPY instructions and runs build.py;
it is not a container engine, .containerignore interpreter, or WSL runtime test.
"""
import hashlib
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

import build

ROOT = Path(__file__).resolve().parent


def stage_copy_inputs(destination, containerfile):
    for line in containerfile.splitlines():
        fields = shlex.split(line, comments=True)
        if not fields or fields[0].upper() != "COPY":
            continue
        if any(field.startswith(("--", "[")) for field in fields[1:]):
            raise ValueError("Extend this check for the new COPY syntax")
        target = fields[-1]
        if not target.startswith("./") or ".." in Path(target).parts:
            raise ValueError("Expected a relative COPY destination under /app")
        folder = destination / target
        folder.mkdir(parents=True, exist_ok=True)
        for pattern in fields[1:-1]:
            sources = sorted(ROOT.glob(pattern))
            if not sources or any(not source.is_file() for source in sources):
                raise ValueError(f"Expected file-only COPY sources: {pattern}")
            for source in sources:
                shutil.copyfile(source, folder / source.name)


class ContainerBuild(unittest.TestCase):
    def test_copy_inputs_build_identical_service_and_client_archives(self):
        expected = {"task-pool-local.zip": build.bundle_bytes(),
                    "taskpool-ai-client.zip": build.client_bundle_bytes()}
        with tempfile.TemporaryDirectory(prefix="relay-container-copy-") as temporary:
            staged = Path(temporary)
            stage_copy_inputs(staged, (ROOT / "Containerfile").read_text(encoding="utf-8"))
            result = subprocess.run([sys.executable, "-B", "build.py"], cwd=staged,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name, raw in expected.items():
                self.assertEqual((staged / "dist" / name).read_bytes(), raw, name)
                print(name, hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    unittest.main()
