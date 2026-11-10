"""Run delegated assistant flows against a disposable qualified service and real HTTP."""
import argparse
import base64
from html import unescape
from io import BytesIO
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import zipfile

from verify import ROOT, call, claim_args, server, sha
from verify_support import scratch
from verify_round import Browser, Client, browser_admin_api, setup
from verify_upgrade import PROJECT, capability, claim, control, register, seal


PREPARE = r'''
import json,os,time
from pathlib import Path
from pool.service import Service,exclusive,state_path
from 协作存储 import encoded
import 协作升级 as rules

store=state_path('local')
with exclusive(store):
    service=Service(store)
    try:
        seq=0
        def post(action,**body):
            global seq
            seq+=1;body={'request_id':'assistant-prepare-'+str(seq),**body}
            code,result=service.submit('admin',action,body['request_id'],body)
            assert code==200,(action,code,result.get('message'),[step.get('reason') for step in result.get('steps',[])])
            return result
        project='intranet-task-system'
        current=rules.grant(service.snapshot()['state'],project,'admin')
        post('project-grant',project_id=project,name='admin',roles=['manager','executor','receiver'],resources=[],version=current['version'])
        post('project-save',project_id='assistant-other',name='Assistant integration other project',version=0)
        current=rules.grant(service.snapshot()['state'],'assistant-other','admin')
        post('project-grant',project_id='assistant-other',name='admin',roles=['manager','executor','receiver'],resources=[],version=current['version'])
        windows={}
        for label in ('pure','cleanup','direct','manager'):
            source={'platform':'external','session':'assistant-fixture-'+label,'model':'fixture','environment':'fixture-env',
                    'device':'isolated-test','directory':'fixture','url':'','parent':None,'window_name':'Fixture '+label}
            issued=post('executor-enroll',project_id=project,roles=['executor'],source=source)
            windows[label]={'id':issued['executor_id'],'token':issued['token'],'window':issued['window']}
            if label!='direct':
                post('project-grant',project_id=project,name=issued['executor_id'],roles=[],resources=[],version=1)
        tasks={}
        for label in ('scoped','cleanup','outside','queued-revoke','queued-expiry','queued-claim','other'):
            target='assistant-other' if label=='other' else project
            task=post('register',project_id=target,title='Assistant fixture '+label,brief='frozen '+label,criteria=['ready'],kind='documentation',
                iteration={'goal':'check delegated boundaries','previous':[],'next':[]},delivery='output.md',
                requirements=[{'id':'markdown','kind':'skill','value':'*','required':True,'evidence':'declared'}],
                review_mode='source',user_basis='',resources=[],dependencies=[],receiver='admin')['task']
            if label not in ('queued-revoke','queued-expiry'):
                task=post('task-publish',task_id=task['task_id'],version=task['version'],scope_version=task['scope_version'],reason='isolated fixture')['task']
            tasks[label]=task['task_id']
        feedback=post('feedback-save',project_id=project,task_id='',kind='feedback',title='Assistant processing fixture',
            details='isolated feedback',impact='fixture only',evidence='fixture',visibility='project',observed='fixture')
        value={'windows':windows,'tasks':tasks,'feedback_id':feedback['record_id']}
        path=Path('.state/assistant-integration-fixture.json');path.write_bytes(encoded(value));os.chmod(path,0o600)
        print(json.dumps({'status':'prepared','windows':len(windows),'tasks':len(tasks)}))
    finally:service.close()
'''


QUEUED = r'''
import json,time
from pathlib import Path
from pool.service import Service,exclusive,state_path,COMMITTER,COORDINATOR
from pool import delegation
from 协作账本 import envelope,cursor
from 协作存储 import digest,encoded
import 协作升级 as rules

fixture=json.loads(Path('.state/assistant-integration-fixture.json').read_bytes())
store=state_path('local')
with exclusive(store):
    service=Service(store)
    try:
        def post(action,request,**body):
            body={'request_id':request,**body}
            code,result=service.submit('admin',action,request,body)
            assert code==200,(action,code,result.get('message'),[step.get('reason') for step in result.get('steps',[])])
            return result
        def grant(label,actions,task_ids=(),seconds=3600,request='queue-grant'):
            actor=fixture['windows'][label]['id'];state=service.snapshot()['state']
            key=delegation.delegation_id('admin',actor,'intranet-task-system')
            old=state['round'].get('delegation:'+key,{})
            post('delegate-grant',request,executor_id=actor,project_id='intranet-task-system',actions=list(actions),
                 task_ids=list(task_ids),expires=int(time.time())+seconds,version=old.get('version',0),reason='isolated queued request fixture')
            return service.snapshot()['state']['round']['delegation:'+key]
        def stage(actor,action,task_id,request):
            snap=service.snapshot();task=snap['state']['tasks'][task_id]
            body={'request_id':request,'task_id':task_id,'version':task['version'],'scope_version':task['scope_version']}
            if action=='task-publish':body['reason']='queued publication fixture'
            key=digest(encoded([actor,request]));fingerprint=digest(encoded([action,body]))
            with delegation.operation_context(snap['state'],actor,action,'intranet-task-system',task_id):
                plan=service.plan(actor,action,key,body,snap)
                with service.db:
                    service.db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)',(key,fingerprint,actor,action,encoded(body),encoded(plan),None,None))
                    service.record_request(key,actor,action,body,fingerprint,snap['state'],plan)
            return key
        def control(payload):
            snap=service.snapshot();payload={**payload,'_audit':{'schema':3,'actor':'admin','operation':payload['op']}}
            env=envelope(service.desk.meta['repo_id'],COORDINATOR,cursor(snap,COORDINATOR)+1,'pilot',payload,
                         {'generation':snap['state']['generation']})
            item=service.desk.receive(env,COMMITTER)
            result=service.desk.process(COMMITTER,handler=service.ledger_decide)
            assert result['control']['terminal'][item['key']]['result']=='applied'
        def rejected(key,task_id,was_open):
            assert service.recover()
            status,raw=service.db.execute('SELECT status,response FROM requests WHERE key=?',(key,)).fetchone()
            result=json.loads(raw)
            assert status==409,(status,result)
            task=service.snapshot()['state']['tasks'][task_id]
            assert task['contract']['open'] is was_open and not task['claims']
        manager=fixture['windows']['manager']['id']
        record=grant('manager',['read','task-publish'],request='queue-before-revoke-grant')
        task=fixture['tasks']['queued-revoke'];key=stage(manager,'task-publish',task,'queued-publication-before-revoke')
        control({'op':'delegate-revoke','delegation_id':record['id'],'version':record['version'],'reason':'withdraw before recovery'})
        rejected(key,task,False)
        record=grant('manager',['read','task-publish'],seconds=12,request='queue-before-expiry-grant')
        task=fixture['tasks']['queued-expiry'];key=stage(manager,'task-publish',task,'queued-publication-before-expiry')
        time.sleep(max(0,record['expires']-time.time()+0.1))
        rejected(key,task,False)
        pure=fixture['windows']['pure']['id'];task=fixture['tasks']['queued-claim']
        grant('pure',['read','claim'],task_ids=[task],request='queue-before-downgrade-grant')
        key=stage(pure,'claim',task,'queued-claim-before-owner-downgrade')
        current=rules.grant(service.snapshot()['state'],'intranet-task-system','admin')
        control({'op':'grant','project_id':'intranet-task-system','name':'admin','roles':['manager','receiver'],
                 'resources':current['resources'],'version':current['version']})
        rejected(key,task,True)
        print(json.dumps({'status':'passed','queued_revoke':True,'queued_expiry':True,'queued_owner_downgrade':True}))
    finally:service.close()
'''


def local(project, code, timeout=120):
    result = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", code], cwd=project,
                            capture_output=True, timeout=timeout)
    if result.returncode:
        raise AssertionError(result.stderr.decode("utf-8", errors="replace")[-6000:])
    return json.loads(result.stdout.splitlines()[-1])


def denied(url, token, path, body=None, statuses=(400, 403, 404, 409)):
    code, result = call(url + "/" + path, token, body)
    assert code in statuses, (path, code, result.get("message") if isinstance(result, dict) else "")
    return result


def authorize(browser, window, *, task_ids=(), preset="task", version=0):
    browser.send("/assistants")
    status, _, raw = browser.send("/assistants", "POST", {
        "request_id": "assistant-grant-" + window[-8:] + "-v" + str(version), "operation": "grant", "executor_id": window,
        "project_id": PROJECT, "version": str(version), "preset": preset, "task_ids": ",".join(task_ids),
        "hours": "24", "issued": str(int(time.time())), "reason": "fixture human explicitly consents"})
    assert status == 200 and "委托已更新".encode() in raw, (status, raw[-500:])


def revoke(browser, record):
    browser.send("/assistants")
    status, _, raw = browser.send("/assistants", "POST", {
        "request_id": "assistant-revoke-" + record["id"][-8:] + "-v" + str(record["version"]), "operation": "revoke",
        "delegation_id": record["id"], "version": str(record["version"]), "reason": "withdraw isolated consent"})
    assert status == 200 and "委托已撤回".encode() in raw, (status, raw[-500:])


def exercise(project):
    """project is an extracted app tree on a disposable qualified writable filesystem."""
    project = Path(project).resolve()
    assert (project / "taskpool.py").is_file()
    initial, _, password = setup(project)
    local(project, PREPARE)
    data = json.loads((project / ".state/assistant-integration-fixture.json").read_bytes())
    checks = []

    def passed(detail):
        checks.append(detail)
        print("PASS ASSISTANT", detail, flush=True)

    with server(project) as (_, url):
        browser = Browser(url)
        browser.login("admin", password)
        windows, ids = data["windows"], data["tasks"]
        pure, cleanup, direct, manager = (Client(url, windows[label]["token"]) for label in ("pure", "cleanup", "direct", "manager"))
        options_route = "task-options?project=" + PROJECT
        assert pure.get(options_route)["counts"]["visible"] == 0
        direct_ids = {task["task_id"] for task in direct.get(options_route)["tasks"]}
        assert {ids["scoped"], ids["cleanup"], ids["outside"]} <= direct_ids and ids["other"] not in direct_ids
        passed("independent AI project grant remains usable without delegation")

        authorize(browser, windows["pure"]["id"], task_ids=[ids["scoped"]])
        authorize(browser, windows["cleanup"]["id"], task_ids=[ids["cleanup"]])
        authorize(browser, windows["manager"]["id"], preset="project")
        options = pure.get(options_route)
        assert {row["task_id"] for row in options["tasks"]} == {ids["scoped"]}
        assert options["counts"]["claimable"] == 0 and any("markdown" in row["reason"] for row in options["missing_summary"])
        denied(url, pure.token, "tasks/" + ids["outside"], statuses=(404,))
        denied(url, pure.token, "tasks/" + ids["other"], statuses=(404,))
        capability(pure, windows["pure"]["id"])
        capability(cleanup, windows["cleanup"]["id"])
        assert pure.get(options_route)["counts"]["claimable"] == 1
        passed("pure delegate sees only whitelisted task and declares its own skill to qualify")
        for name, kind, level in (("admin", "skill", "declared"), (windows["pure"]["id"], "skill", "verified"),
                                  (windows["pure"]["id"], "environment", "verified")):
            denied(url, pure.token, "capability-save", {"request_id": "bad-cap-" + name[-4:] + "-" + kind + "-" + level,
                "project_id": PROJECT, "name": name, "capability": "no-inherited-capability", "kind": kind, "level": level,
                "value": "fixture", "evidence": {"note": "fixture", "sha256": "1" * 64}, "environment": "fixture-env",
                "expires": int(time.time()) + 3600, "version": 0})
        passed("delegation does not inherit another identity or verified/environment capability")

        created = register(manager, "admin", title="delegated manager creates task")
        published = control(manager, "task-publish", created)["task"]
        assert published["contract"]["open"] is True and published["receiver"] == "admin"
        held = control(manager, "task-hold", published)["task"]
        assert held["contract"]["open"] is False
        manager.post("feedback-update", project_id=PROJECT, id=data["feedback_id"], version=1, status="evidence",
            linked_task="", duplicate="", reason="delegated review fixture", evidence="fixture evidence", metrics=[], lesson="", limits="")
        events = manager.get("audit?task=" + created["task_id"])["events"]
        assert any(row.get("actor") == windows["manager"]["id"] and row.get("delegator") == "admin" and row.get("delegation_id") for row in events)
        passed("project assistant creates/publishes/holds tasks and handles feedback with human+AI audit")
        for action, body in (("project-grant", {"project_id": PROJECT, "name": windows["direct"]["id"], "roles": ["manager"], "resources": [], "version": 1}),
                             ("credential-change", {"name": windows["direct"]["id"], "version": 1, "status": "disabled", "reason": "must refuse"}),
                             ("delegate-grant", {"executor_id": windows["manager"]["id"], "project_id": PROJECT, "actions": ["read"], "task_ids": [],
                                                 "expires": int(time.time())+3600, "version": 0, "reason": "must refuse"})):
            denied(url, manager.token, action, {"request_id": "forbidden-" + action, **body})
        denied(url, manager.token, "tasks/" + ids["other"], statuses=(404,))
        passed("project delegation grants neither cross-project access nor permission/credential management")

        receipt = claim(pure, pure.get("tasks/" + ids["scoped"])["task"], request="assistant-pure-original-claim")
        sealed = seal(pure, receipt)
        pure.post("stop", **claim_args(sealed), stop_evidence="fixture first revision process actually exited")
        revision, manifest = next(reversed(sealed["claim"]["deliveries"].items()))
        browser_admin_api(project, browser).post("return", claim_id=sealed["claim"]["claim_id"], revision=revision,
            manifest_sha256=manifest["manifest_sha256"], criterion="ready", reason="fixture correction required")
        returned = pure.get("tasks/" + ids["scoped"])["claims"][-1]
        receipt = pure.post("resume", **claim_args({"claim": returned}))
        sealed = seal(pure, receipt)
        passed("pure delegate resumes a human-returned revision and delivers again under a new execution epoch")
        denied(url, pure.token, "close", {"request_id": "cannot-inherit-receiver", "task_id": ids["scoped"]})
        p_record = pure.get("delegations")["delegations"][0]
        revoke(browser, p_record)
        assert pure.get(options_route)["counts"]["visible"] == 0
        denied(url, pure.token, "tasks/" + ids["scoped"], statuses=(404,))
        denied(url, pure.token, "receipt?request=assistant-pure-original-claim", statuses=(404,))
        summaries = pure.get("cleanup")["claims"]
        own = next(row for row in summaries if row["claim_id"] == receipt["claim"]["claim_id"])
        assert set(own) == {"claim_id", "task_id", "epoch", "W", "origin", "L"}
        assert own["origin"] == windows["pure"]["id"] and set(own["W"]) == {"scope"}
        denied(url, pure.token, "deliver-files", {"request_id": "no-deliver-after-revoke", **claim_args(receipt),
               "files": [{"name": "late.md", "content": base64.b64encode(b"must refuse").decode()}]})
        revision = next(reversed(sealed["claim"]["deliveries"]))
        denied(url, pure.token, "withdraw", {"request_id": "no-withdraw-after-revoke", **claim_args(sealed),
                                             "revision": revision, "reason": "must refuse after consent withdrawal"})
        stop_body = {**claim_args(sealed), "stop_evidence": "fixture process actually exited"}
        pure.post("stop", request="assistant-cleanup-stop", **stop_body)
        replay = pure.post("stop", request="assistant-cleanup-stop", **stop_body)
        assert replay.get("cleanup_only") is True
        assert set(replay) <= {"status", "request_id", "head", "steps", "cleanup_only"}
        assert all(set(row) <= {"event_id", "result"} for row in replay.get("steps", []))
        passed("withdrawn consent hides project content, exposes only own cleanup metadata and permits real stop")

        cleanup_claim = claim(cleanup, cleanup.get("tasks/" + ids["cleanup"])["task"])
        revoke(browser, cleanup.get("delegations")["delegations"][0])
        cleanup.post("handoff", **claim_args(cleanup_claim), notes="fixture work stopped, no external effects",
                     stop_evidence="fixture executor actually exited")
        assert not cleanup.get("cleanup")["claims"]
        denied(url, cleanup.token, "tasks/" + ids["cleanup"], statuses=(404,))
        passed("withdrawn pure delegate can hand off its own active claim without regaining read/delivery rights")
    queued = local(project, QUEUED)
    assert all(queued[key] for key in ("queued_revoke", "queued_expiry", "queued_owner_downgrade"))
    passed("real persisted requests reject revoke, expiry and owner downgrade before journal recovery")
    with server(project) as (_, url):
        remaining = Client(url, data["windows"]["pure"]["token"]).get("cleanup")["claims"]
        assert len(remaining) == 1 and remaining[0]["task_id"] == data["tasks"]["scoped"]
        assert all(row["origin"] == data["windows"]["pure"]["id"] and "inputs" not in row for row in remaining)
        denied(url, data["windows"]["manager"]["token"], "tasks/" + data["tasks"]["other"], statuses=(404,))
    passed("service restarts cleanly after rejected queued operations")
    return {"status": "passed", "checks": checks, "qualification": initial["qualification_passed"], "production_modified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=ROOT / "dist/task-pool-local.zip")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    frozen_archive = args.archive.read_bytes()
    with scratch("assistant-integration-") as name:
        with zipfile.ZipFile(BytesIO(frozen_archive)) as archive:
            archive.extractall(name)
        report = exercise(Path(name))
    report["artifact_sha256"] = sha(frozen_archive)
    if args.report:
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]), "production_modified": False}))


if __name__ == "__main__":
    main()
