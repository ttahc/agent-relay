"""Fresh, source-bound rechecks and repairs cannot revive completed work."""
from copy import deepcopy
import json
import unittest
from types import SimpleNamespace

import pool
from pool.post_completion import plan, view
from pool.post_completion_pages import render
from pool.packages import ClientError
from 协作复查 import action, source
from 协作存储 import Rejected
from verify_direct_completion import fixture as completion_fixture, event, context, MANIFEST, ART
from 协作命令 import decide


def fixture():
    s = completion_fixture()
    t = s['tasks']['T1']
    t.update(title='original', resources=[], execution={k: False for k in ('compiled','tested','applied','deployed')},
             authorities=['fixture'], required_paths=[], parent=None, provided={})
    t['contract'].update(iteration={'goal':'original', 'previous':[], 'next':[]}, delivery='result',
                         requirements=[{'id':'notes','kind':'skill','value':'*','required':True,'evidence':'declared'}], user_basis='', open=True)
    s['pilot']['grant:p:reviewer']['roles'].append('manager')
    s['pilot']['project:p']['name'] = 'project'
    s['origins']['reviewer']['roles'].append('receiver')
    decide(s, event(s), context())
    t.update(status='completed', close_id='closed')
    s['closings']['closed'] = {'close_id':'closed','task_id':'T1','acceptance_id':'done','accepted_manifest':MANIFEST}
    s['next_task'] = 2
    return s


def request(s, action_name, actor='reviewer', **kwargs):
    b = {'request_id':'request', 'task_id':'T1', 'task_version':s['tasks']['T1']['version'], **kwargs}
    prepared = plan(SimpleNamespace(delivery_refs=lambda ref: [ART]), actor, action_name, 'a'*64, b, s)
    return prepared['steps'][0]['payload']


def open_issue(s, visibility='project'):
    p = request(s,'task-issue-open',actor='worker', title='<issue>',details='reproduction',evidence='log line',visibility=visibility)
    action(s,p,'worker',100,'open',1)
    return p['id']


def review(s,i,verdict,actor='reviewer',**kwargs):
    p=request(s,'task-issue-review',actor,id=i,version=s['round']['task-issue:'+i]['version'],
              verdict=verdict,reason='review reason',evidence='checked result',**kwargs)
    action(s,p,actor,101,'review',2,{'verified_manifests':{MANIFEST['sha256']}})
    return p


def repair(s,i,**options):
    return request(s,'task-repair-open', id=i,version=s['round']['task-issue:'+i]['version'],reason='repair required',
                   title='Repair',brief='New narrow work',criteria=['fixed'],receiver='reviewer',completion_policy='review-required',**options)


class PostCompletion(unittest.TestCase):
    def test_open_binds_exact_source_without_altering_original(self):
        s=fixture(); before=deepcopy({k:s[k] for k in ('tasks','claims','acceptances','closings','reservations')})
        i=open_issue(s);row=s['round']['task-issue:'+i]
        self.assertEqual(row['source'],source(s,s['tasks']['T1']))
        self.assertEqual(before,{k:s[k] for k in before})
        self.assertEqual(s['pilot']['format']['min_reader'],7)

    def test_nonterminal_observer_and_unknown_task_rejected(self):
        for change in ('running','observer','foreign'):
            s=fixture()
            if change=='running':s['tasks']['T1']['status']='running'
            elif change=='observer':s['pilot']['grant:p:worker']['roles']=['observer']
            else:s['pilot']['grant:p:worker']['roles']=[]
            with self.assertRaises(ClientError):open_issue(s)

    def test_recheck_requires_current_authority_and_payload_verification(self):
        s=fixture();i=open_issue(s)
        with self.assertRaises(ClientError):review(s,i,'resolved','worker')
        p=request(s,'task-issue-review',id=i,version=1,verdict='resolved',reason='verified',evidence='facts')
        with self.assertRaises(Rejected):action(deepcopy(s),p,'reviewer',102,'no-payload',3,{})
        s['pilot']['grant:p:reviewer']['roles']=[]
        with self.assertRaises(Rejected):action(s,p,'reviewer',102,'revoked',3,{'verified_manifests':{MANIFEST['sha256']}})

    def test_source_tampering_and_stale_task_issue_versions_rejected(self):
        s=fixture();i=open_issue(s)
        for field in ('source','version','task_version'):
            p=request(s,'task-issue-review',id=i,version=1,verdict='evidence',reason='check',evidence='needed')
            p[field] = {} if field=='source' else 99
            with self.assertRaises(Rejected):action(deepcopy(s),p,'reviewer',102,'stale',3)

    def test_repair_is_fresh_linked_and_preserves_old_claims_permissions(self):
        s=fixture();i=open_issue(s);review(s,i,'repair-required')
        original=deepcopy(s['tasks']['T1']);claims=deepcopy(s['claims']);accepted=deepcopy(s['acceptances'])
        p=repair(s,i);action(s,p,'reviewer',103,'repair-new',4)
        row=s['round']['task-issue:'+i];new=s['tasks'][row['repair_task']]
        self.assertNotEqual(new['task_id'],'T1');self.assertEqual(new['claims'],[])
        self.assertFalse(new['contract']['open']);self.assertEqual(new['scope_version'],1)
        self.assertEqual(new['related'],{'task':'T1','issue':i,'correction':'repair-new'})
        self.assertEqual(s['tasks']['T1'],original);self.assertEqual(s['claims'],claims);self.assertEqual(s['acceptances'],accepted)
        self.assertEqual(s['corrections']['repair-new']['target'],'closed')
        with self.assertRaises(ClientError):repair(s,i)
        # Serialized reload cannot revive the original or duplicate repair.
        loaded=json.loads(json.dumps(s))
        with self.assertRaises(ClientError):repair(loaded,i)
        with self.assertRaises(ClientError):review(loaded,i,'resolved')

    def test_restricted_issue_never_becomes_project_task_or_search_result(self):
        s=fixture();i=open_issue(s,'restricted');review(s,i,'repair-required')
        s['pilot']['grant:p:peer']['roles']=['executor']
        self.assertEqual(view(s,'peer','T1')['issues'],[])
        self.assertEqual(len(view(s,'worker','T1')['issues']),1)
        with self.assertRaises(ClientError):repair(s,i)

    def test_closed_issue_reopens_explicitly_preserving_old_conclusion(self):
        s=fixture();i=open_issue(s);review(s,i,'resolved')
        with self.assertRaises(ClientError):review(s,i,'repair-required')
        review(s,i,'evidence')
        self.assertEqual([r['verdict'] for r in s['round']['task-issue:'+i]['reviews']],['resolved','evidence'])
        self.assertEqual(s['tasks']['T1']['status'],'completed')

    def test_page_escapes_evidence_and_offers_explicit_new_repair(self):
        s=fixture();i=open_issue(s);review(s,i,'repair-required')
        html=render('reviewer',view(s,'reviewer','T1'),s['tasks']['T1'],['reviewer'])
        self.assertIn('&lt;issue&gt;',html);self.assertNotIn('<issue>',html)
        self.assertIn('task-repair-open',html);self.assertIn('新任务',html)

    def test_serial_repairs_keep_previous_completion_history(self):
        s=fixture();i=open_issue(s);review(s,i,'repair-required')
        p=repair(s,i);action(s,p,'reviewer',103,'repair-1',4)
        first=s['round']['task-issue:'+i]['repair_task']
        # Synthetic already-completed new repair, retaining the production exact source binding shape.
        t=s['tasks'][first];t.update(status='completed',accepted='repair-accept',close_id='repair-close',claims=['repair-claim'])
        c=deepcopy(s['claims']['c']);c.update(claim_id='repair-claim',task_id=first)
        s['claims']['repair-claim']=c
        a=deepcopy(s['acceptances']['done']);a.update(acceptance_id='repair-accept',claim_id='repair-claim',task_id=first)
        s['acceptances']['repair-accept']=a
        s['closings']['repair-close']={'acceptance_id':'repair-accept','accepted_manifest':MANIFEST,'task_id':first}
        frozen=deepcopy(t)
        review(s,i,'resolved');review(s,i,'evidence');review(s,i,'repair-required')
        p=repair(s,i,include_original_delivery=True)
        self.assertEqual(p['baseline_source']['task_id'],first)
        action(s,p,'reviewer',104,'repair-2',5,{'repair_baseline':p['baseline']})
        row=s['round']['task-issue:'+i]
        self.assertNotEqual(first,row['repair_task'])
        self.assertEqual(row['repair_history'][0]['task_id'],first)
        self.assertEqual(s['tasks'][first],frozen)
        self.assertEqual(s['tasks'][row['repair_task']]['claims'],[])

    def test_primary_brief_and_explicit_baseline_use_normal_input_permission(self):
        from pool import input_packages, reads
        s=fixture();s['tasks']['T1']['inputs']={'inputs/original/brief.md':'c'*64}
        i=open_issue(s);review(s,i,'repair-required')
        p=repair(s,i,include_original_delivery=True)
        self.assertIn(ART['path'],p['repair']['inputs'])
        with self.assertRaises(Rejected):action(deepcopy(s),p,'reviewer',103,'without-proof',4)
        action(s,p,'reviewer',103,'with-proof',4,{'repair_baseline':p['baseline']})
        t=s['tasks'][s['round']['task-issue:'+i]['repair_task']]
        svc=SimpleNamespace(visible=lambda state, task, actor: True)
        selected=input_packages.select(svc,'peer',s,{'task_id':t['task_id'],'scope_version':'1'})
        self.assertIn(ART['path'],selected['inputs'])
        self.assertIn('inputs/original/brief.md',selected['inputs'])
        svc.detail=lambda *args: {'task':t}
        svc.checked_file=lambda ref: b'New narrow work' if ref==t['primary_brief'] else b'Old original brief'
        svc.is_admin=lambda actor:False
        svc.db=SimpleNamespace(execute=lambda *args:[])
        r=SimpleNamespace(service=svc,tasks=s['tasks'],state=s,actor='peer',snap={'state':s,'entries':[]})
        self.assertEqual(reads.sheet(r,t['task_id'])['brief'],'New narrow work')

    def test_round_migration_keeps_new_reader_floor(self):
        from 协作本轮 import action as round_action
        from 协作安全 import check
        s=fixture();s['claims']={};s['pilot']['format']['schema']=2
        s['pilot']['identity:reviewer']['admin']=True
        env={'event_id':'migration','payload':{'op':'round-migrate','upgrade':'r3','image':'d'*64,'_audit':{'actor':'reviewer'}}}
        round_action(s,env,{'now':100})
        self.assertEqual(s['pilot']['format']['min_reader'],7)
        with self.assertRaises(ValueError):check(s,5)

    def test_private_request_metadata_receipt_and_pending_audit_follow_sources(self):
        from pool.collaboration_visibility import request_scope,request_visible
        from pool.upgrade import audit_rows
        from pool.service import Service
        from 协作存储 import encoded
        s=fixture();i=open_issue(s,'restricted')
        body={'id':i,'task_id':'T1'}
        scope=request_scope(s,'worker','task-issue-review',body)
        record={'actor':'worker','request_id':'secret-request','task_id':'T1','project_id':'p',
                'operation':'task-issue-review','collaboration_scope':scope}
        self.assertTrue(request_visible(s,'worker',record));self.assertFalse(request_visible(s,'peer',record))
        for status in (None,409,200):
            db=SimpleNamespace(execute=lambda *args:[(json.dumps(record),status,json.dumps({'status':'rejected'}) if status else None)])
            svc=SimpleNamespace(db=db,is_admin=lambda actor:False,visible=lambda *args:True)
            self.assertEqual(audit_rows(svc,{'state':s,'entries':[]},'peer',{'task':'T1'}),[])
        s['pilot']['grant:p:worker']['roles']=[]
        self.assertFalse(request_visible(s,'worker',record))
        svc=object.__new__(Service)
        svc.db=SimpleNamespace(execute=lambda *args:SimpleNamespace(fetchone=lambda:(encoded(record),)))
        with self.assertRaises(ClientError):svc.receipt_authorization('worker','key',s)

    def test_malformed_rejection_scopes_cannot_poison_journal_reads(self):
        from pool.collaboration_visibility import request_scope, request_visible, ACTIONS
        s=fixture()
        for operation in ACTIONS:
            for field in ('id','task_id','project_id','source_task','source_feedback'):
                for malformed in (['T1'], {'id':'T1'}, 1, True):
                    scope=request_scope(s,'worker',operation,{field:malformed})
                    record={'operation':operation,'collaboration_scope':scope}
                    self.assertTrue(request_visible(s,'worker',record))
                    self.assertFalse(request_visible(s,'peer',record))

    def test_direct_wait_event_targets_holder_without_fake_review(self):
        from pool.wakeups import events
        from unittest.mock import patch
        s=fixture();t=s['tasks']['T1'];c=s['claims']['c']
        t.update(status='running');c.update(L='active',W={'state':'review','scope':1,'revision':'r'})
        svc=SimpleNamespace(visible=lambda *args:True)
        with patch('pool.round_service.ready_tasks',return_value={}), patch('pool.round_service.Notices._returned',return_value={}):
            self.assertIn('completion-requested',[x['type'] for x in events(svc,s,'worker')])
            self.assertNotIn('review-requested',[x['type'] for x in events(svc,s,'reviewer')])

    def test_discussion_backlog_never_hides_resource_events_or_cursor_changes(self):
        from pool.wakeups import events,cursor_of,EVENT_LIMIT
        s=fixture();t=s['tasks']['T1']
        s['pilot']['format']['schema']=5
        s['security']={'schema':5,'execution':{'actions':{}}}
        i=open_issue(s)
        row=s['round']['task-issue:'+i]
        for number in range(55):
            other=deepcopy(row);other['id']='issue-'+str(number)
            s['round']['task-issue:'+other['id']]=other
        svc=SimpleNamespace(visible=lambda *args:True)
        first=events(svc,s,'worker')
        self.assertEqual(len(first),EVENT_LIMIT)
        s['security']['execution']['actions']['grant-one']={'id':'grant-one','executor_id':'worker','state':'granted',
            'grant_id':'g','generation':1,'task_id':'T1','claim_id':'c'}
        after=events(svc,s,'worker')
        self.assertIn('resource-granted',[e['type'] for e in after])
        self.assertNotEqual(cursor_of(first),cursor_of(after))
        hidden=next(x for x in s['round'].values() if isinstance(x,dict) and x.get('id')=='issue-50')
        hidden['version']+=1
        self.assertNotEqual(cursor_of(after),cursor_of(events(svc,s,'worker')))
        self.assertIn('more-events',[e['type'] for e in after])

    def test_malformed_choices_are_normal_client_rejections(self):
        for bad in ([],{},1,True,None):
            s=fixture()
            with self.assertRaises(ClientError):open_issue(s,bad)
            i=open_issue(s)
            with self.assertRaises(ClientError):review(s,i,bad)

    def test_feedback_resolved_does_not_require_fabricated_metrics(self):
        from 协作关系 import feedback
        s=fixture();s['round']['feedback:f']={'id':'f','project_id':'p','status':'review','linked_task':'T1','author':'worker','version':1,'updates':[]}
        p={'op':'feedback-update','project_id':'p','id':'f','version':1,'status':'resolved','linked_task':'T1',
           'duplicate':'','reason':'reproduction fixed','evidence':'checked original reproduction','metrics':[],'lesson':'','limits':''}
        feedback(s,p,'reviewer',100,'resolved')
        self.assertEqual(s['round']['feedback:f']['status'],'resolved')
        self.assertEqual(s['round']['feedback:f']['updates'][0]['metrics'],[])
        p.update(version=2,status='review');feedback(s,p,'reviewer',101,'reopen')
        p.update(version=3,status='verified')
        with self.assertRaises(Rejected):feedback(s,p,'reviewer',102,'not-metrics')

if __name__=='__main__':unittest.main()
