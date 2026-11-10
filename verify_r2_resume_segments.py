"""Business-resume segment binding without regranting claim or changing old facts."""
from copy import deepcopy
from types import SimpleNamespace
import time
import unittest

from pool import delegation, execution
from pool.packages import ClientError
import 协作执行 as engine
import 协作升级 as rules
from 协作本轮 import delegation_action, delegation_id
from 协作存储 import Rejected
import verify_r2_execution as execution_fixture
from verify_delegation import ASSISTANT, PERSON


class ResumeSegments(unittest.TestCase):
    def setUp(self):
        self.case = execution_fixture.ExecutionTests(); self.case.setUp()
        self.state = self.case.state
        self.task = self.state["tasks"]["T01"]
        self.claim = self.state["claims"]["ca"]
        self.service = SimpleNamespace(lifecycle=SimpleNamespace(status=lambda: {"phase": "running"}))

    def payload(self):
        with delegation.operation_context(self.state, ASSISTANT, "resume", "project-one", "T01") as delegated:
            audit = {"actor": ASSISTANT, "operation": "resume", "task_id": "T01", "project_id": "project-one", "credential_version": 7,
                     "authorization": rules.auth_stamp(self.state, ASSISTANT, "project-one"), **delegated}
        return {"claim_id": "ca", "scope_version": 1, "resumed_epoch": self.claim["epoch"], "_audit": audit}

    def business_resume(self):
        self.claim.update(epoch=2, E={"state": "running", "reason": None}, W={"state": "draft", "scope": 1, "revision": 2},
                          run={"state": "claimed", "automation": False, "notice": None})

    def test_paused_claim_cannot_start_by_skipping_business_resume(self):
        aid=self.case.prepare()
        self.case.request(aid)
        self.claim['E']={'state':'stopped','reason':'pause'}
        before=deepcopy(self.state)
        with self.assertRaises(Rejected):self.case.start(aid)
        self.assertEqual(self.state,before)

    def test_native_revision_resume_binds_new_round_without_eager_resource_reservation(self):
        from 协作账本 import initial
        from pool.upgrade import decide
        state=initial({'coordinator':'pilot-coordinator','repo_id':'resume-native-fixture','authority_ref':'fixture'})
        state.update(self.state)
        state['pilot']['format'].update(schema=5,min_reader=5)
        state['origins']['pilot-coordinator']={'roles':['coordinator'],'local':True,'version':1}
        claim=state['claims']['ca']
        claim.update(E={'state':'stopped','reason':'complete'},W={'state':'revision','scope':1,'revision':'revision-1'},
                     inputs={'inputs/source.md':'a'*64},deliveries={'revision-1':{'status':'revision'}},scope_ack_pending=False)
        payload=self.payload();payload.pop('resumed_epoch',None)
        payload.update(execution_protocol=5,baseline=claim['inputs']);payload['_audit']['schema']=5
        env={'command':'acquire','origin_id':ASSISTANT,'origin_seq':1,'event_id':'native-revision-resume',
             'payload':payload,'expects':{'epoch:ca':1,'scope:T01':1}}
        after,_=decide(state,env,{'now':time.time(),'seq':1})
        self.assertEqual(after['claims']['ca']['epoch'],2)
        self.assertEqual(after['claims']['ca']['W']['state'],'draft')
        self.assertEqual(after['claims']['ca']['R'],[])
        self.assertEqual(after['reservations'],{})
        segments=list(after['security']['execution']['segments'].values())
        self.assertTrue(any(row.get('authorization_operation')=='resume' and row['epoch']==2 for row in segments))

    def apply_plan(self, op, key, body):
        result = execution.plan(self.service, ASSISTANT, op, key * 64, {"request_id": "test-"+key, **body}, self.state)
        p = result["steps"][0]["payload"]
        engine.action(self.state, {"event_id": "actual-"+key, "payload": {**p, "_audit": {"actor": ASSISTANT, "credential_version": 7}}},
                      {"now": time.time(), "phase": "running"})
        return result

    def test_authorized_business_resume_creates_new_segment_and_preserves_old_delivery_segment_and_native_fields(self):
        old_action = self.case.prepare()
        old_segment_id = engine.ensure(self.state)["actions"][old_action]["segment_id"]
        old_segment = deepcopy(engine.ensure(self.state)["segments"][old_segment_id])
        self.claim["deliveries"] = {"revision-1": {"status": "revision", "manifest_sha256": "a"*64}}
        old_deliveries = deepcopy(self.claim["deliveries"])
        self.business_resume()
        after_business = deepcopy(self.claim)
        segment = engine.open_resume_segment(self.state, self.task, ASSISTANT, self.claim, time.time(), "authorized-resume", self.payload())
        self.assertEqual(self.claim, after_business)
        self.assertEqual(self.claim["deliveries"], old_deliveries)
        self.assertEqual(engine.ensure(self.state)["segments"][old_segment_id], old_segment)
        self.assertEqual((segment["epoch"], segment["scope_version"], segment["authorization_operation"]), (2, 1, "resume"))
        self.assertNotIn("permit_id", segment)
        self.assertEqual(engine.ensure(self.state)["grants"], {})
        replay = engine.open_resume_segment(self.state, self.task, ASSISTANT, self.claim, time.time()+10, "authorized-resume", self.payload())
        self.assertEqual(replay, segment)

    def test_resume_only_task_delegate_can_prepare_request_and_start_original_task_but_cannot_use_claim_category(self):
        self.task["resources"] = []
        self.state["pilot"][f"grant:project-one:{ASSISTANT}"]["roles"] = []
        delegation_action(self.state, {"op":"delegate-grant", "executor_id":ASSISTANT,"project_id":"project-one",
            "delegation_id":delegation_id(PERSON,ASSISTANT,"project-one"),"actions":["resume"],"task_ids":["T01"],
            "expires":int(time.time())+3600,"version":0,"reason":"only continue this existing task"}, PERSON, time.time(), "grant-resume-only")
        self.business_resume()
        segment = engine.open_resume_segment(self.state, self.task, ASSISTANT, self.claim, time.time(), "delegate-resume", self.payload())
        prepared = self.apply_plan("action-prepare", "a", {"segment_id":segment["id"],"version":1,"description":"continue returned task","resources":[],"adapter_id":"manual"})
        self.assertEqual(prepared["steps"][0]["payload"]["authority"]["delegated_operation"], "resume")
        action = prepared["round_result"]["action"]
        self.assertEqual(action["authorization_operation"], "resume")
        granted = self.apply_plan("resource-request", "b", {"action_id":action["id"],"version":action["version"],"resources":[]})
        current, grant = granted["round_result"]["action"], granted["round_result"]["grant"]
        started = self.apply_plan("action-start", "c", {"action_id":current["id"],"version":current["version"],"grant_id":grant["id"],"generation":grant["generation"]})
        self.assertTrue(started["round_result"]["action"]["permit_id"])
        with delegation.operation_context(self.state, ASSISTANT, "claim", "project-one", "T01"):
            self.assertNotIn("executor", rules.roles(self.state,"project-one",ASSISTANT))
        selected=engine.default_context(self.state,ASSISTANT)
        with self.assertRaises(Rejected):
            execution.plan(self.service,ASSISTANT,"segment-open","d"*64,{"request_id":"no-new-claim","task_id":"T01","claim_id":"ca",
                "scope_version":1,"epoch":2,"context_id":selected["context_id"],"context_version":selected["version"]},self.state)

    def test_unprepared_business_state_unknown_occupancy_and_http_authority_forgery_are_rejected(self):
        self.claim.update(E={"state":"stopped","reason":"complete"},W={"state":"revision","scope":1,"revision":"revision-1"})
        before=deepcopy(self.state)
        with self.assertRaises(Rejected):engine.open_resume_segment(self.state,self.task,ASSISTANT,self.claim,time.time(),"too-early",self.payload())
        self.assertEqual(self.state,before)
        self.business_resume()
        engine.ensure(self.state)["legacy"]["old-unknown"]={"active":True,"claim_id":"ca","physical":"unknown","resources":[{"id":"path:work","mode":"write"}]}
        before=deepcopy(self.state)
        with self.assertRaises(Rejected):engine.open_resume_segment(self.state,self.task,ASSISTANT,self.claim,time.time(),"unknown-stays",self.payload())
        self.assertEqual(self.state,before)
        with self.assertRaises(ClientError):
            execution.plan(self.service,ASSISTANT,"action-prepare","f"*64,{"request_id":"forged","segment_id":"none","version":1,
                "description":"forged","resources":[],"adapter_id":"manual","authority":{"delegated_operation":"resume"}},self.state)


if __name__ == "__main__":unittest.main()
