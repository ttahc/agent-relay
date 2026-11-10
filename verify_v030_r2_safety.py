"""Safety-boundary checks using isolated credentials and real request recovery paths."""
from copy import deepcopy
import unittest
from unittest.mock import patch
from email.message import Message
from types import SimpleNamespace
from threading import RLock
from unittest.mock import MagicMock
import pool
from pool.packages import ClientError
import verify_v030_credential_recovery as credential_fixture
ASSISTANT=credential_fixture.ASSISTANT
from 协作安全 import check, preserve_unknown, blocked_resources

class AuthenticationBoundary(unittest.TestCase):
    def setUp(self):
        self.fixture=credential_fixture.CredentialRecovery()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.service=self.fixture.service

    def test_recover_rotating_credentials_reauthenticates_before_new_plan(self):
        verifier=lambda:self.fixture.server.actor_for_token(self.fixture.old)
        def recover():
            self.fixture.state['pilot']['identity:'+ASSISTANT]['credential']+=1
            return True
        with patch.object(self.service,'recover',side_effect=recover),patch.object(self.service,'plan') as plan:
            with self.assertRaises(ClientError) as error:
                self.service.submit(ASSISTANT,'context-save','after-recover',{'request_id':'after-recover'},authorize=verifier)
            self.assertEqual(error.exception.status,401)
            plan.assert_not_called()
        self.assertEqual(self.service.db.execute('SELECT count(*) FROM requests').fetchone()[0],0)

    def test_inherited_session_verifier_is_rechecked_after_recovery(self):
        current=[ASSISTANT]
        def recover():current[0]=None;return True
        with self.service.request_identity(lambda:current[0]),patch.object(self.service,'recover',side_effect=recover):
            with self.assertRaises(ClientError) as error:
                self.service.submit(ASSISTANT,'context-save','old-session',{'request_id':'old-session'})
        self.assertEqual(error.exception.status,401)

    def test_token_checks_hold_the_same_lock(self):
        original=self.service.account_actor
        def check_actor(token):
            self.assertTrue(self.service.lock._is_owned())
            return original(token)
        with patch.object(self.service,'account_actor',side_effect=check_actor):
            self.assertEqual(self.fixture.server.actor_for_token(self.fixture.old),ASSISTANT)

    def test_unknown_superseded_request_cannot_be_used_as_new_intent(self):
        with self.assertRaises(ClientError) as error:
            self.service.submit(ASSISTANT,'context-save','new-id',{'request_id':'new-id','supersedes_request_id':'not-recorded'})
        self.assertEqual(error.exception.status,409)

    def test_accepted_linked_correction_retains_quarantined_original_input(self):
        from 协作存储 import digest,encoded
        old_key=digest(encoded([ASSISTANT,'old-quarantined']))
        original=encoded({'request_id':'old-quarantined','unchanged':'original frozen input'})
        with self.service.db:
            self.service.db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)',
                (old_key,'f'*64,ASSISTANT,'old',original,encoded({'steps':[]}),None,None))
            self.service.db.execute('INSERT INTO request_quarantine VALUES(?,?,?)',(old_key,'needs review',0))
        body={'request_id':'linked-new','supersedes_request_id':'old-quarantined'}
        with patch.object(self.service,'plan',return_value={'steps':[]}):
            status,_=self.service.submit(ASSISTANT,'context-save','linked-new',body)
        self.assertEqual(status,200)
        prior=self.service.db.execute('SELECT status,body,response FROM requests WHERE key=?',(old_key,)).fetchone()
        self.assertEqual(prior[0],409);self.assertEqual(prior[1],original)
        import json
        self.assertEqual(json.loads(prior[2])['superseded_by'],'linked-new')

    def test_get_rotated_between_precheck_and_read_cannot_read_new_scope(self):
        from pool.httpd import Handler
        handler=object.__new__(Handler)
        handler.server=self.fixture.server
        handler.server.is_round=True
        handler.server.tls=None
        handler.server.allows_host=lambda _:True
        handler.path='/v1/identity'
        handler.headers=Message()
        handler.headers['Authorization']='Bearer '+self.fixture.old
        initial=handler.authenticate
        calls=[]
        def auth():
            value=initial();calls.append(value)
            if len(calls)==1:
                self.fixture.state['pilot']['identity:'+ASSISTANT]['credential']+=1
            return value
        with patch.object(handler,'authenticate',side_effect=auth),patch.object(self.service,'read') as read:
            with self.assertRaises(ClientError) as error:handler.dispatch('GET')
            self.assertEqual(error.exception.status,401)
            read.assert_not_called()

    def test_fresh_window_can_declare_before_it_has_any_saved_context(self):
        import time
        import 协作升级 as rules
        from pool.upgrade import plan
        state=self.fixture.state
        state['pilot']['format'].update(schema=5,min_reader=5)
        state['security']={'schema':5,'phase':'ready'}
        rules.identity(state,ASSISTANT).update(platform='codex',model='unknown',environment='fixture')
        state['pilot']['grant:project-one:'+ASSISTANT]={'roles':['executor'],'resources':[],'version':1}
        body={'request_id':'first-capability','project_id':'project-one','name':ASSISTANT,'capability':'source-review',
              'kind':'skill','value':'*','level':'declared','evidence':{'note':'isolated declaration','sha256':''},
              'environment':rules.identity(state,ASSISTANT)['environment'],'expires':int(time.time())+3600,'version':0}
        prepared=plan(self.service,ASSISTANT,'capability-save','1'*64,body,{'state':state})
        payload=prepared['steps'][0]['payload'];payload['_audit']={'actor':ASSISTANT}
        rules.action(state,{'event_id':'first-declaration','payload':payload},{'now':time.time()})
        record=state['pilot']['cap:project-one:'+ASSISTANT+':source-review']
        self.assertIn(record['context_id']+':'+str(record['context_version']),state['security']['execution']['contexts'])
        self.assertEqual(record['level'],'declared')

    def test_ai_receiver_cannot_bypass_human_verification_using_legacy_capability_save(self):
        import time
        import 协作升级 as rules
        from pool.upgrade import plan
        from 协作存储 import Rejected
        state=self.fixture.state
        state['pilot']['format'].update(schema=5,min_reader=5)
        state['security']={'schema':5,'phase':'ready'}
        state['pilot']['grant:project-one:'+ASSISTANT]={'roles':['receiver','executor'],'resources':[],'version':1}
        body={'request_id':'ai-cannot-verify','project_id':'project-one','name':'window-two','capability':'source-review',
              'kind':'skill','value':'*','level':'verified','evidence':{'note':'synthetic cross-window attempt','sha256':'a'*64},
              'environment':'fixture','expires':int(time.time())+3600,'version':0}
        before=deepcopy(state)
        with self.assertRaises(ClientError) as error:plan(self.service,ASSISTANT,'capability-save','2'*64,body,{'state':state})
        self.assertEqual(error.exception.status,403)
        payload={'op':'capability','project_id':'project-one','name':'window-two','id':'source-review','version':0,
                 'record':{key:body[key] for key in ('kind','value','level','evidence','environment','expires')},'_audit':{'actor':ASSISTANT}}
        with self.assertRaises(Rejected):rules.action(state,{'event_id':'forged-legacy-verify','payload':payload},{'now':time.time()})
        self.assertEqual(state,before)

    def test_ended_claim_does_not_allow_transfer_while_external_action_remains_running(self):
        import time
        from pool import window_admin
        from 协作存储 import Rejected
        from verify_delegation import PERSON
        state=self.fixture.state
        state['claims']['old']={'claim_id':'old','origin':ASSISTANT,'L':'ended','R':[]}
        state['security']={'schema':5,'phase':'ready','execution':{'actions':{
            'still-running':{'executor_id':ASSISTANT,'claim_id':'old','state':'running'}}}}
        before=deepcopy(state)
        self.assertFalse(window_admin.view(state,PERSON,ASSISTANT)['transfer_allowed'])
        with self.assertRaises(Rejected):
            window_admin.apply(state,{'op':'window-admin','name':ASSISTANT,'operation':'transfer','owner':'other-person',
                              'version':1,'reason':'synthetic transfer'},PERSON,time.time(),'transfer')
        self.assertEqual(state,before)

class SafetyVersions(unittest.TestCase):
    def test_received_nonterminal_envelope_blocks_migration_before_sql_or_ledger_changes(self):
        from pool.safety import migrate
        db=MagicMock()
        service=SimpleNamespace(lock=RLock(),db=db,snapshot=lambda:{'state':{'pilot':{'format':{'schema':3,'min_reader':3}}},
            'control':{'terminal':{}}},desk=SimpleNamespace(copies=lambda:[{'envelope':{'origin_id':'old','event_id':'inflight'}}]))
        with self.assertRaises(ClientError) as error:migrate(service,5,'migration')
        self.assertEqual(error.exception.status,409)
        db.execute.assert_not_called()
    def test_legacy_stop_report_retains_unknown_occupancy_and_original_binding(self):
        state={'pilot':{'format':{'schema':5,'min_reader':5}},'security':{'schema':5,'phase':'ready',
             'execution':{'legacy':{'legacy-c1':{'active':True,'physical':'unknown','epoch':1,'scope_version':1}}}}}
        claim={'claim_id':'c1','epoch':2,'W':{'scope':1},'E':{'state':'stopped'},'stop_evidence':'original holder reports stopped'}
        preserve_unknown(state,claim,{'reservation_id':'r1','id':'path:work','mode':'write'},'logical return')
        self.assertEqual(state['security']['physical_blockers']['legacy:r1']['epoch'],1)
        self.assertTrue(blocked_resources(state))

    def test_parsed_model_requirements_cannot_be_satisfied_by_omitting_dependency(self):
        import 协作升级 as rules
        import 协作执行 as engine
        requirement=rules.requirement_rows([{'id':'analysis','kind':'skill','value':'*','required':True,
                    'evidence':'verified','dimensions':['platform','model'],'verified_dimensions':['model']}],True)[0]
        state={'security':{},'pilot':{}}
        record={'kind':'skill','level':'verified','applicability':{'rule_version':1,'dependencies':{'platform':'codex'},'verified_dimensions':[]}}
        outcome=engine.capability_check(state,'worker',record,{'config':{'platform':'codex','model':'unknown'}},requirement)
        self.assertFalse(outcome['matches'])

    def test_human_default_does_not_invent_ai_model_dependency(self):
        import 协作执行 as engine
        state={'security':{},'pilot':{'identity:person':{'kind':'human'}}}
        before=deepcopy(state)
        context=engine.default_context(state,'person')
        bound=engine.bind_evidence(state,'person',{'kind':'skill','level':'declared'},context)
        self.assertEqual(bound['applicability']['dependencies'],{})
        self.assertEqual(context['config']['platform'],'human')
        self.assertEqual(state,before)

    def test_reader_four_rejects_five_and_missing_migration_marker(self):
        state={'pilot':{'format':{'schema':5,'min_reader':5}},'security':{'schema':5,'phase':'ready'}}
        with self.assertRaises(ValueError):check(state,4)
        self.assertEqual(check(state),5)
        state['security']={}
        with self.assertRaises(ValueError):check(state)

    def test_logical_release_preserves_unknown_until_physical_end_is_confirmed(self):
        state={'pilot':{'format':{'schema':4,'min_reader':4}},'security':{'schema':4,'phase':'ready'}}
        claim={'claim_id':'c1','epoch':3,'W':{'scope':2},'E':{'state':'running'}}
        reservation={'reservation_id':'r1','id':'path:work','mode':'write','epoch':2,'scope_version':1}
        before=deepcopy(claim)
        preserve_unknown(state,claim,reservation,'manager removed platform reservation')
        self.assertEqual(blocked_resources(state),[{'id':'path:work','mode':'write'}])
        self.assertEqual(claim,before)
        self.assertEqual(state['security']['physical_blockers']['legacy:r1']['epoch'],2)
        preserve_unknown(state,claim,reservation,'duplicate')
        self.assertEqual(len(state['security']['physical_blockers']),1)

if __name__=='__main__':unittest.main()
