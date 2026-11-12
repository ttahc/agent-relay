"""GET /metrics: who may read it, what it says, and that it carries no names.

Runs the packaged service on a disposable store. The scrape token is made with the service running,
as an operator would. No production store is read.
"""
import json
from pathlib import Path
import re
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import zipfile

from pool import metrics
from verify import ROOT, call, command, server as running_service
from verify_round import activate, ai_prepare, auth_checks, invitation, setup
from verify_support import scratch

SAMPLE = re.compile(r'^[a-z_]+(\{[a-z_]+="[^"\n]*"(,[a-z_]+="[^"\n]*")*\})? -?[0-9.e+-]+$')


def scrape(url, token=None):
    headers = {"Authorization": "Bearer " + token} if token else {}
    try:
        with urlopen(Request(url, headers=headers), timeout=15) as response:
            return response.status, response.headers["Content-Type"], response.read().decode("utf-8")
    except HTTPError as error:
        return error.code, error.headers["Content-Type"], error.read().decode("utf-8")


class Served(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = scratch("metrics-")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.project = project = Path(cls.scratch.name)
        with zipfile.ZipFile(ROOT / "dist" / "task-pool-local.zip") as package:
            package.extractall(project)
        _, tokens, password = setup(project)
        cls.running = running_service(project)
        _, url = cls.running.__enter__()
        cls.addClassCleanup(cls.running.__exit__, None, None, None)
        cls.api, cls.metrics = url, url.removesuffix("/v1") + "/metrics"
        admin, _, _ = auth_checks(project, url, tokens, password)
        _, (status, issued) = ai_prepare(url, invitation(admin, "worker-a"), session="metrics-session")
        assert status == 200, (status, issued)
        activate(url, issued)
        cls.window = issued["token"]
        cls.token = command(project, "metrics-token")["token"]

    def figures(self, text):
        values = {}
        for line in text.splitlines():
            if line.startswith("#"):
                continue
            self.assertRegex(line, SAMPLE)
            name, value = line.rsplit(" ", 1)
            values[name] = float(value)
        return values

    def test_the_scrape_token_reads_the_figures_in_prometheus_text(self):
        status, kind, text = scrape(self.metrics, self.token)
        self.assertEqual(status, 200, text)
        self.assertEqual(kind, metrics.KIND)
        values = self.figures(text)
        self.assertEqual(values['agent_relay_phase{phase="running"}'], 1)
        self.assertGreater(values["agent_relay_ledger_entries"], 0)
        self.assertEqual(values['agent_relay_wait_requests{kind="limit"}'], 64)
        self.assertGreaterEqual(values["agent_relay_write_seconds_count"], 1)
        self.assertGreaterEqual(values['agent_relay_windows{presence="registered"}'], 1)
        for kind_ in ("task-unclaimed", "claim-silent", "claim-stalled"):
            self.assertIn(f'agent_relay_reminders{{type="{kind_}"}}', values)
        self.assertIn("# TYPE agent_relay_write_seconds summary", text)

    def test_no_name_title_or_token_leaves_the_service(self):
        text = scrape(self.metrics, self.token)[2]
        name = call(self.api + "/identity", self.window)[1]["identity"]
        for secret in (name, self.token, self.window, "worker-a", str(self.project)):
            self.assertNotIn(secret, text)

    def test_others_are_refused(self):
        self.assertEqual(scrape(self.metrics)[0], 401)
        self.assertEqual(scrape(self.metrics, "x" * 43)[0], 401)
        self.assertEqual(scrape(self.metrics, self.window)[0], 403)

    def test_a_new_token_replaces_the_old_one_and_only_its_digest_is_kept(self):
        old = command(self.project, "metrics-token")["token"]
        new = command(self.project, "metrics-token")["token"]
        self.assertEqual(scrape(self.metrics, old)[0], 401)
        self.assertEqual(scrape(self.metrics, new)[0], 200)
        stored = (self.project / ".state" / "local" / metrics.TOKEN_FILE)
        if not stored.exists():
            stored = next(self.project.rglob(metrics.TOKEN_FILE))
        self.assertNotIn(new, stored.read_text(encoding="utf-8"))
        self.assertEqual(stored.stat().st_mode & 0o077, 0)
        type(self).token = new

    def test_the_description_lists_the_route(self):
        self.assertIn("/metrics", json.loads((ROOT / "docs" / "openapi.json").read_bytes())["paths"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
