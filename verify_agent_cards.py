"""Windows exported as A2A agent cards, and the task stage to A2A state table.

The first class checks the export on synthetic window rows; the second reads the cards from the
packaged service on a disposable store. No production store is read.
"""
from pathlib import Path
import unittest
import zipfile

from pool import agent_cards, task_pages
from verify import ROOT, call, server as running_service
from verify_round import activate, ai_prepare, auth_checks, invitation, setup
from verify_support import scratch

NOW = 1_800_000_000
A2A_STATES = {"TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED",
              "TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED"}


def record(cap, level, expires=NOW + 60, project="demo"):
    return {"id": cap, "project_id": project, "value": "ok", "level": level, "expires": expires}


class Export(unittest.TestCase):
    def source(self, **changes):
        return {"executor_id": "exec-1", "window": "W-7", "window_name": "整理文档窗口", "platform": "claude",
                "owner": "person", "status": "active", "contact": "current",
                "capabilities": [record("git-version", "verified"), record("hermes-api", "probed"),
                                 record("workspace-rw", "declared"), record("old", "verified", expires=NOW - 1)], **changes}

    def test_a_card_uses_a2a_field_names_and_lists_no_interface(self):
        card = agent_cards.card(self.source(), NOW)
        self.assertEqual(set(card) - {"x-agent-relay"}, {"name", "description", "provider", "version", "capabilities",
                                                         "defaultInputModes", "defaultOutputModes", "skills", "supportedInterfaces"})
        self.assertEqual(card["name"], "整理文档窗口")
        self.assertEqual(card["provider"]["organization"], "claude")
        self.assertEqual(card["supportedInterfaces"], [], "windows do not serve A2A; work arrives as tasks")
        self.assertFalse(any(card["capabilities"].values()))
        self.assertEqual(card["x-agent-relay"]["executor_id"], "exec-1")

    def test_only_current_confirmed_skills_are_listed(self):
        skills = agent_cards.card(self.source(), NOW)["skills"]
        self.assertEqual([row["id"] for row in skills], ["demo:git-version", "demo:hermes-api"])
        self.assertEqual(skills[0]["tags"], ["demo", "verified"])
        self.assertEqual(agent_cards.card(self.source(capabilities=[]), NOW)["skills"], [])

    def test_archived_windows_are_left_out(self):
        view = agent_cards.view([self.source(), self.source(executor_id="exec-2", status="archived")], NOW)
        self.assertEqual([card["x-agent-relay"]["executor_id"] for card in view["cards"]], ["exec-1"])
        self.assertEqual(view["a2a_version"], "1.0")

    def test_every_task_stage_maps_to_an_a2a_state(self):
        self.assertEqual(set(agent_cards.TASK_STATES), set(task_pages.STAGES))
        self.assertLessEqual(set(agent_cards.TASK_STATES.values()), A2A_STATES)
        for stage in task_pages.ARCHIVED:
            self.assertIn(agent_cards.TASK_STATES[stage], {"TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"}, stage)
        self.assertEqual(agent_cards.TASK_STATES["cancel_pending"], "TASK_STATE_WORKING", "not cancelled until it stopped")
        rows = agent_cards.view([], NOW)["task_states"]
        self.assertEqual(len(rows), len(task_pages.STAGES))
        self.assertTrue(all(set(row) <= {"stage", "a2a_state", "note"} for row in rows))


class Served(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = scratch("cards-")
        cls.addClassCleanup(cls.scratch.cleanup)
        project = Path(cls.scratch.name)
        with zipfile.ZipFile(ROOT / "dist" / "task-pool-local.zip") as package:
            package.extractall(project)
        _, tokens, password = setup(project)
        cls.running = running_service(project)
        _, cls.url = cls.running.__enter__()
        cls.addClassCleanup(cls.running.__exit__, None, None, None)
        admin, _, _ = auth_checks(project, cls.url, tokens, password)
        _, (status, issued) = ai_prepare(cls.url, invitation(admin, "worker-a"), session="cards-session")
        assert status == 200, (status, issued)
        activate(cls.url, issued)
        cls.token = issued["token"]
        cls.name = call(cls.url + "/identity", cls.token)[1]["identity"]

    def test_a_window_reads_its_own_card_and_the_state_table(self):
        status, value = call(self.url + "/agent-cards", self.token)
        self.assertEqual(status, 200)
        self.assertEqual([card["x-agent-relay"]["executor_id"] for card in value["cards"]], [self.name])
        self.assertEqual(len(value["task_states"]), len(task_pages.STAGES))
        self.assertIs(call(self.url + "/features", self.token)[1]["features"]["agent-cards"], True)

    def test_no_credential_no_cards(self):
        self.assertEqual(call(self.url + "/agent-cards")[0], 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
