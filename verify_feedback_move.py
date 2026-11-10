"""Feedback reassignment must preserve evidence and enforce both project boundaries."""
from copy import deepcopy
import unittest

import pool
from pool.round_projects import payload, view
from 协作关系 import action
from 协作存储 import Rejected


def fixture():
    pilot={'format':{'schema':3}}
    for name in ('admin','manager','writer','peer'):
        pilot['identity:'+name]={'kind':'human','owner':name,'status':'active','admin':name=='admin'}
    for project in ('source','target'):
        pilot['project:'+project]={'id':project,'name':project,'owner':'admin','version':1}
        for name,roles in (('admin',[]),('peer',['manager']),('writer',['reporter']),('manager',['manager'] if project=='source' else [])):
            pilot[f'grant:{project}:{name}']={'roles':roles,'resources':[],'version':1}
    item={'id':'fb-1','project_id':'source','task_id':'','kind':'issue','title':'Evidence title',
        'details':'Original evidence','impact':'original','evidence':'source.txt','visibility':'restricted',
        'observed':'2026-11-09','author':'writer','status':'triage','version':1,'updates':[]}
    return {'pilot':pilot,'tasks':{},'round':{'feedback:fb-1':item}}


def body():
    return {'request_id':'move-1','project_id':'source','id':'fb-1','version':1,
            'target_project_id':'target','reason':'Administrator corrected project selection'}


class FeedbackMove(unittest.TestCase):
    def move(self,state,actor='admin',data=None):
        data=data or body()
        p={'op':'feedback-move',**payload(state,actor,'feedback-move',data,'key')}
        action(state,p,actor,1_700_000_000,'move-event')

    def test_admin_can_move_without_project_membership_and_retains_content(self):
        state=fixture(); before=deepcopy(state['round']['feedback:fb-1'])
        self.move(state)
        item=state['round']['feedback:fb-1']
        self.assertEqual(item['project_id'],'target');self.assertEqual(item['version'],2)
        self.assertEqual({k:item[k] for k in before if k not in {'project_id','version'}},
                         {k:v for k,v in before.items() if k not in {'project_id','version'}})
        self.assertEqual(item['project_history'][0]['from'],'source')
        self.assertEqual(item['project_history'][0]['to'],'target')
        self.assertEqual(view(state,'writer','source')['feedback'],[])
        self.assertEqual(view(state,'writer','target')['feedback'][0]['id'],'fb-1')

    def test_managing_both_projects_is_sufficient(self):
        state=fixture();self.move(state,'peer');self.assertEqual(state['round']['feedback:fb-1']['project_id'],'target')

    def test_author_or_single_project_manager_cannot_move(self):
        from pool.packages import ClientError
        for actor in ('writer','manager'):
            with self.assertRaises(ClientError):self.move(fixture(),actor)

    def test_commit_rechecks_revoked_target_permission(self):
        state=fixture();p={'op':'feedback-move',**payload(state,'peer','feedback-move',body(),'key')}
        state['pilot']['grant:target:peer']['roles']=[]
        with self.assertRaises(Rejected):action(state,p,'peer',1_700_000_000,'recovered')

    def test_stale_version_and_changed_source_rejected(self):
        for name,value in (('version',2),('project_id','target')):
            state=fixture();state['round']['feedback:fb-1'][name]=value
            with self.assertRaises(Rejected):self.move(state)

    def test_existing_task_association_is_not_silently_lost(self):
        state=fixture();state['tasks']['T1']={'contract':{'project_id':'source'}}
        state['round']['feedback:fb-1']['linked_task']='T1'
        with self.assertRaises(Rejected):self.move(state)
        self.assertEqual(state['round']['feedback:fb-1']['linked_task'],'T1')

    def test_duplicate_relationship_is_not_moved_across_projects(self):
        state=fixture();other=deepcopy(state['round']['feedback:fb-1'])
        other.update(id='fb-2',status='duplicate',updates=[{'duplicate':'fb-1'}])
        state['round']['feedback:fb-2']=other
        with self.assertRaises(Rejected):self.move(state)

    def test_missing_or_same_target_rejected(self):
        for target in ('missing','source'):
            data=body();data['target_project_id']=target
            with self.assertRaises(Rejected):self.move(fixture(),data=data)


if __name__=='__main__':unittest.main()
