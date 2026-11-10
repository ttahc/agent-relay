"""Run a signed-in task round trip from a real wired or EasyTier peer."""

import argparse
import base64
from getpass import getpass
import hashlib
import http.client
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import time
from urllib.parse import urlencode, urlsplit


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--url", required=True)
    cli.add_argument("--cert", required=True, type=Path)
    cli.add_argument("--cert-sha256", required=True)
    cli.add_argument("--network", required=True, choices=["wired", "easytier"])
    cli.add_argument("--subnet", required=True)
    cli.add_argument("--identity", default="v2-check-peer")
    cli.add_argument("--task", required=True)
    cli.add_argument("--run", required=True)
    cli.add_argument("--recheck", action="store_true")
    cli.add_argument("--output", type=Path)
    args = cli.parse_args()
    parsed = urlsplit(args.url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.port != 18443 or parsed.username or parsed.password
            or (parsed.path not in {"", "/"} or parsed.query or parsed.fragment)):
        cli.error("use the HTTPS service origin on port 18443")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,30}", args.run):
        cli.error("run identifier must be 1-30 letters, digits, hyphens or underscores")
    network = ipaddress.IPv4Network(args.subnet)
    server_address = ipaddress.IPv4Address(parsed.hostname)
    if hashlib.sha256(args.cert.read_bytes()).hexdigest() != args.cert_sha256:
        cli.error("public certificate fingerprint differs from the expected fingerprint")
    tls = ssl.create_default_context(cafile=str(args.cert))
    origin = f"https://{parsed.hostname}:18443"
    account = getpass("Access token (hidden): ").strip()
    local = None

    def request(path, data=None, token=None, headers=None, status=200):
        nonlocal local
        params = dict(headers or {})
        if token:
            params["Authorization"] = "Bearer " + token
        connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=tls, timeout=15)
        try:
            connection.connect()
            address = ipaddress.IPv4Address(connection.sock.getsockname()[0])
            if address == server_address or address not in network:
                raise RuntimeError(f"source {address} is not a distinct peer in {network}")
            local = str(address)
            connection.request("POST" if data is not None else "GET", path, body=data, headers=params)
            reply = connection.getresponse()
            content = reply.read()
            if reply.status != status:
                raise RuntimeError(f"{path} returned {reply.status}, expected {status}")
            return dict(reply.getheaders()), content
        finally:
            connection.close()

    def get(route, token):
        return json.loads(request("/v1/" + route, token=token)[1])

    def post(route, token, request_id, **body):
        data = json.dumps({"request_id": request_id, **body}, ensure_ascii=False).encode()
        return json.loads(request("/v1/" + route, data, token, {"Content-Type": "application/json"})[1])

    health = json.loads(request("/healthz")[1])
    assert health["status"] == "ok"
    headers, _ = request("/login", urlencode({"identity": args.identity, "token": account}).encode(),
                         headers={"Origin": origin, "Content-Type": "application/x-www-form-urlencoded"}, status=303)
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    assert "任务看板".encode() in request("/", headers={"Cookie": cookie})[1]
    assert get("identity", account)["identity"] == args.identity
    issued = post("executor-enroll", account, "peer-enroll-" + args.run, project_id="upgrade-acceptance",
                  roles=["executor"], source={"platform": "external", "session": "peer-" + args.run,
                  "model": "peer-probe", "environment": args.network + "-https", "device": socket.gethostname(),
                  "directory": str(Path.cwd()), "url": "", "parent": None})
    token = issued["token"]
    stop_id = "peer-stop-" + args.run
    if not args.recheck:
        post("capability-save", token, "peer-cap-" + args.run, project_id="upgrade-acceptance",
             name=issued["executor_id"], capability="markdown", kind="skill", value="ok",
             level="declared", evidence={"note": "对端测试生成 Markdown 文档", "sha256": ""},
             environment=args.network + "-https", expires=int(time.time()) + 86400, version=0)
        listing = get("tasks?project=upgrade-acceptance", token)["tasks"]
        task = next(t for t in listing if t["task_id"] == args.task)
        receipt = post("claim", token, "peer-claim-" + args.run,
                       **{key: task[key] for key in ("task_id", "version", "scope_version")})
        assert receipt["claim"]["origin"] == issued["executor_id"]
        for ref in receipt["initial_inputs"]:
            _, content = request("/v1/artifact?" + urlencode({"path": ref["path"]}), token=token)
            assert hashlib.sha256(content).hexdigest() == ref["sha256"]
        claim = receipt["claim"]
        values = {"claim_id": claim["claim_id"], "epoch": claim["epoch"], "scope_version": claim["W"]["scope"]}
        text = (f"# Peer evidence\n\n"
                f"Network {args.network}, source {local}, task {args.task}, window {issued['window']}.\n")
        post("deliver-files", token, "peer-deliver-" + args.run, **values,
             files=[{"name": "peer.md", "content": base64.b64encode(text.encode()).decode()}])
        post("stop", token, stop_id, **values, stop_evidence="对端测试已读入、封存并结束全部写入")
    confirmed = get("receipt?" + urlencode({"request": stop_id}), token)
    assert confirmed["status"] == "applied" and confirmed["claim"]["E"]["state"] == "stopped"
    assert confirmed["task"]["task_id"] == args.task and confirmed["claim"]["origin"] == issued["executor_id"]
    report = {"status": "passed", "network": args.network, "peer_ipv4": local, "server_ipv4": str(server_address),
              "certificate_sha256": args.cert_sha256, "task": args.task, "window": issued["window"],
              "executor_id": issued["executor_id"], "claim_id": confirmed["claim"]["claim_id"],
              "request_id": stop_id, "head": confirmed["head"], "recheck": args.recheck}
    if args.output:
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
