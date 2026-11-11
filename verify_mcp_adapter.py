"""The MCP adapter: protocol behaviour, the command line each tool runs, and one real round trip.

The first class drives ops/relay-mcp.py over its real stdin/stdout with a stand-in client that only
echoes its command line, so every message and argument mapping is checked without a service. The
second runs the packaged service on a disposable store with the real client. No production store
is read.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import zipfile

from verify import ROOT, call, server as running_service
from verify_round import activate, ai_prepare, auth_checks, invitation, setup
from verify_support import scratch

ADAPTER = Path(ROOT) / "ops" / "relay-mcp.py"
ECHO = """import json, sys
argv = sys.argv[1:]
if "retry" in argv:
    print("原请求仍待确认", file=sys.stderr)
    sys.exit(1)
print(json.dumps({"argv": argv}, ensure_ascii=False))
"""
MODERN = {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}


def session(arguments, messages):
    """Run the adapter once, send the messages, close stdin; return the decoded stdout lines."""
    sent = "".join(json.dumps(message, ensure_ascii=False) + "\n" for message in messages).encode("utf-8")
    done = subprocess.run([sys.executable, "-B", "-X", "utf8", str(ADAPTER), *arguments], input=sent, capture_output=True,
                          timeout=180, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")[-800:]
    return [json.loads(line) for line in done.stdout.decode("utf-8").splitlines()]


def request(number, method, **params):
    return {"jsonrpc": "2.0", "id": number, "method": method, "params": params}


class Protocol(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = scratch("mcp-")
        cls.addClassCleanup(cls.scratch.cleanup)
        folder = Path(cls.scratch.name)
        cls.client = folder / "echo-client.py"
        cls.client.write_text(ECHO, encoding="utf-8")
        cls.state = folder / "window.credential"
        cls.arguments = ["--state", str(cls.state), "--client", str(cls.client)]

    def ask(self, *messages):
        return session(self.arguments, messages)

    def call_tool(self, name, arguments, **params):
        (reply,) = self.ask(request(1, "tools/call", name=name, arguments=arguments, **params))
        return reply

    def ran(self, name, arguments):
        result = self.call_tool(name, arguments)["result"]
        self.assertFalse(result["isError"], result)
        argv = result["structuredContent"]["argv"]
        self.assertEqual(argv[:2], ["--state", str(self.state)])
        return argv[2:]

    def test_a_handshake_client_negotiates_a_version_it_asked_for(self):
        first, second = self.ask(
            request(1, "initialize", protocolVersion="2025-06-18", capabilities={}, clientInfo={"name": "t", "version": "0"}),
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            request(2, "ping"))
        self.assertEqual(first["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(first["result"]["capabilities"], {"tools": {}})
        self.assertEqual(first["result"]["serverInfo"]["name"], "agent-relay")
        self.assertNotIn("resultType", first["result"])
        self.assertEqual(second, {"jsonrpc": "2.0", "id": 2, "result": {}})

    def test_an_unknown_handshake_version_gets_the_newest_handshake_version(self):
        (reply,) = self.ask(request(1, "initialize", protocolVersion="1999-01-01"))
        self.assertEqual(reply["result"]["protocolVersion"], "2025-11-25")

    def test_a_client_without_a_handshake_discovers_and_calls_with_its_version(self):
        found, listed = self.ask(request(1, "server/discover", **MODERN), request(2, "tools/list", **MODERN))
        self.assertEqual(found["result"]["resultType"], "complete")
        self.assertIn("2026-07-28", found["result"]["supportedVersions"])
        self.assertEqual(found["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "agent-relay")
        self.assertEqual(listed["result"]["resultType"], "complete")
        refused = self.call_tool("relay_whoami", {}, _meta={"io.modelcontextprotocol/protocolVersion": "1900-01-01"})
        self.assertEqual(refused["error"]["code"], -32022)
        self.assertEqual(refused["error"]["data"]["requested"], "1900-01-01")
        self.assertIn("2026-07-28", refused["error"]["data"]["supported"])

    def test_the_tools_are_listed_with_closed_schemas(self):
        (reply,) = self.ask(request(1, "tools/list"))
        tools = {item["name"]: item for item in reply["result"]["tools"]}
        self.assertEqual(set(tools), {"relay_whoami", "relay_tasks", "relay_show", "relay_claim", "relay_download",
                                      "relay_deliver", "relay_handoff", "relay_wait", "relay_pending", "relay_retry"})
        for name, item in tools.items():
            self.assertEqual(item["inputSchema"]["type"], "object", name)
            self.assertIs(item["inputSchema"]["additionalProperties"], False, name)
            self.assertTrue(item["description"], name)
        self.assertTrue(tools["relay_show"]["annotations"]["readOnlyHint"])
        self.assertFalse(tools["relay_claim"]["annotations"]["readOnlyHint"])

    def test_each_tool_runs_one_client_command(self):
        self.assertEqual(self.ran("relay_whoami", {}), ["whoami"])
        self.assertEqual(self.ran("relay_tasks", {}), ["tasks", "--claimable"])
        self.assertEqual(self.ran("relay_tasks", {"all": True, "full": True, "project": "demo"}), ["tasks", "--full", "--project=demo"])
        self.assertEqual(self.ran("relay_show", {"task": "T01"}), ["show", "T01"])
        self.assertEqual(self.ran("relay_claim", {"task": "T01", "context_id": "ctx-1", "context_version": 2}),
                         ["claim", "T01", "--context-id=ctx-1", "--context-version=2"])
        self.assertEqual(self.ran("relay_download", {"task": "T01", "output": "out dir", "inputs": True}),
                         ["download", "T01", "--output=out dir", "--inputs"])
        self.assertEqual(self.ran("relay_deliver", {"task": "T01", "files": ["a.txt", "-b.txt"], "stop_evidence": "已停止"}),
                         ["deliver", "T01", "--file=a.txt", "--file=-b.txt", "--stop-evidence=已停止"])
        self.assertEqual(self.ran("relay_handoff", {"task": "T01", "evidence": "--help", "notes": "接续说明", "claim_id": "c-1"}),
                         ["handoff", "T01", "--claim-id=c-1", "--evidence=--help", "--notes=接续说明"])
        self.assertEqual(self.ran("relay_wait", {}), ["wait", "--timeout", "25"])
        self.assertEqual(self.ran("relay_wait", {"timeout": 0}), ["wait", "--timeout", "0"])
        self.assertEqual(self.ran("relay_pending", {}), ["pending"])

    def test_loopback_is_passed_only_when_the_adapter_was_started_with_it(self):
        (reply,) = session([*self.arguments, "--allow-loopback"], [request(1, "tools/call", name="relay_whoami", arguments={})])
        self.assertEqual(reply["result"]["structuredContent"]["argv"][2:], ["--allow-loopback", "whoami"])

    def test_arguments_that_could_become_options_or_are_unknown_are_refused_before_any_command(self):
        for name, arguments in (("relay_show", {"task": "--state"}), ("relay_show", {"task": "T01", "extra": 1}),
                                ("relay_show", {}), ("relay_claim", {"task": "T01", "context_version": "2"}),
                                ("relay_tasks", {"project": "-x"}), ("relay_wait", {"timeout": 51}), ("relay_wait", {"timeout": True}),
                                ("relay_deliver", {"task": "T01", "files": []}), ("relay_deliver", {"task": "T01", "files": [""]}),
                                ("relay_download", {"task": "T01", "output": "o", "inputs": True, "artifact": "a"}),
                                ("relay_handoff", {"task": "T01", "evidence": "e"}), ("relay_whoami", ["whoami"])):
            result = self.call_tool(name, arguments)["result"]
            self.assertTrue(result["isError"], (name, arguments))
            self.assertNotIn("structuredContent", result, (name, arguments))

    def test_a_failed_command_is_a_tool_error_carrying_the_clients_message(self):
        result = self.call_tool("relay_retry", {})["result"]
        self.assertTrue(result["isError"])
        self.assertEqual(result["content"], [{"type": "text", "text": "原请求仍待确认"}])

    def test_protocol_errors_are_json_rpc_errors_and_notifications_get_no_answer(self):
        done = subprocess.run([sys.executable, "-B", "-X", "utf8", str(ADAPTER), *self.arguments], capture_output=True, timeout=60,
                              input=b'not json\n\n[1]\n' + json.dumps(request(3, "tools/call", name="other", arguments={})).encode() + b"\n" +
                              json.dumps(request(4, "resources/list")).encode() + b"\n" +
                              json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 3}}).encode() + b"\n")
        self.assertEqual(done.returncode, 0)
        replies = [json.loads(line) for line in done.stdout.decode("utf-8").splitlines()]
        self.assertEqual([(reply["id"], reply["error"]["code"]) for reply in replies],
                         [(None, -32700), (None, -32600), (3, -32602), (4, -32601)])

    def test_the_adapter_refuses_to_start_without_the_client(self):
        done = subprocess.run([sys.executable, "-B", str(ADAPTER), "--state", str(self.state), "--client", str(self.state)],
                              capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
        self.assertEqual((done.returncode, done.stdout), (2, b""))


class Served(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = scratch("mcp-served-")
        cls.addClassCleanup(cls.scratch.cleanup)
        project = Path(cls.scratch.name)
        with zipfile.ZipFile(ROOT / "dist" / "task-pool-local.zip") as package:
            package.extractall(project)
        _, tokens, password = setup(project)
        cls.running = running_service(project)
        _, cls.url = cls.running.__enter__()
        cls.addClassCleanup(cls.running.__exit__, None, None, None)
        admin, _, _ = auth_checks(project, cls.url, tokens, password)
        _, (status, issued) = ai_prepare(cls.url, invitation(admin, "worker-a"), session="mcp-session")
        assert status == 200, (status, issued)
        activate(cls.url, issued)
        cls.token = issued["token"]
        cls.name = call(cls.url + "/identity", cls.token)[1]["identity"]
        cls.state = project / "mcp.credential"
        cls.state.write_text(json.dumps({"url": cls.url.removesuffix("/v1"), "token": cls.token}), encoding="utf-8")
        cls.state.chmod(0o600)
        cls.adapter = project / "ops" / "relay-mcp.py"  # the packaged copy, next to the packaged client

    def tools(self, *calls):
        messages = [request(number, "tools/call", name=name, arguments=arguments) for number, (name, arguments) in enumerate(calls)]
        sent = "".join(json.dumps(message) + "\n" for message in messages).encode()
        done = subprocess.run([sys.executable, "-B", "-X", "utf8", str(self.adapter), "--state", str(self.state), "--allow-loopback"],
                              input=sent, capture_output=True, timeout=300, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        self.assertEqual(done.returncode, 0, done.stderr.decode("utf-8", "replace")[-800:])
        self.assertNotIn(self.token.encode(), done.stdout)
        return [json.loads(line)["result"] for line in done.stdout.decode("utf-8").splitlines()]

    def test_the_real_client_answers_through_the_adapter(self):
        who, tasks, waited, pending = self.tools(("relay_whoami", {}), ("relay_tasks", {}), ("relay_wait", {"timeout": 0}),
                                                 ("relay_pending", {}))
        for result in (who, tasks, waited, pending):
            self.assertFalse(result["isError"], result)
        self.assertIn(self.name, who["content"][0]["text"])
        self.assertEqual(json.loads(who["content"][0]["text"]), who["structuredContent"])
        self.assertIn(waited["structuredContent"]["status"], {"idle", "changed"})
        self.assertIs(pending["structuredContent"]["pending"], False)

    def test_a_refusal_from_the_service_comes_back_as_a_tool_error(self):
        (result,) = self.tools(("relay_show", {"task": "no-such-task"}))
        self.assertTrue(result["isError"])
        self.assertTrue(result["content"][0]["text"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
