from contextlib import contextmanager
from copy import deepcopy
from io import BytesIO
from types import SimpleNamespace
import hashlib,json,unittest,zipfile
import tempfile
from pathlib import Path
from pool.input_packages import package
from pool.packages import ClientError

class Service:
    def __init__(self):self.pinned=SimpleNamespace(active=False);self.material={'old.md':b'old','new.md':b'new'}
    def visible(self,state,task,actor):return actor!='outsider'
    def task_roles(self,state,task,actor):return {'manager'} if actor=='admin' else set()
    def delegated_actions(self,*_):return set()
    @contextmanager
    def one_snapshot(self):
        self.pinned.active=True
        try:yield
        finally:self.pinned.active=False
    def read(self,actor,route,path):return self.material[path]
def fixture():
    sha=lambda raw:hashlib.sha256(raw).hexdigest()
    return {'tasks':{'T1':{'task_id':'T1','scope_version':2,'inputs':{'new.md':sha(b'new')}}},
        'claims':{'c-old':{'claim_id':'c-old','task_id':'T1','origin':'worker','W':{'scope':1},'inputs':{'old.md':sha(b'old')}}}}
class InputPackageTests(unittest.TestCase):
    def test_unavailable_runtime_directory_does_not_poison_later_downloads(self):
        from pool.input_packages import select,generate
        service=Service()
        test_root=Path(__file__).resolve().parent/'.state'
        test_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=test_root) as name:
            root=Path(name);(root/'.runtime').write_text('preserve existing object')
            service.desk=SimpleNamespace(store=root)
            selected=select(service,'worker',fixture(),{'task_id':'T1','scope_version':'2'})
            with self.assertRaises(OSError):generate(service,'worker',selected)
            self.assertEqual((root/'.runtime').read_text(),'preserve existing object')
        del service.desk
        with generate(service,'worker',selected)[0] as stream:
            self.assertTrue(stream.read(2).startswith(b'PK'))

    def test_claim_frozen_scope_is_not_replaced_by_new_task_scope(self):
        state=fixture();before=deepcopy(state)
        raw=package(Service(),'worker',state,{'task_id':'T1','scope_version':'1','claim_id':'c-old'})
        with zipfile.ZipFile(BytesIO(raw)) as z:
            m=json.loads(z.read('manifest.json'));self.assertEqual(m['scope_version'],1)
            self.assertEqual(z.read(m['inputs'][0]['member']),b'old')
        self.assertEqual(state,before)
    def test_task_input_manifest_has_exact_bytes(self):
        with zipfile.ZipFile(BytesIO(package(Service(),'worker',fixture(),{'task_id':'T1','scope_version':'2'}))) as z:
            m=json.loads(z.read('manifest.json'));item=m['inputs'][0]
            self.assertEqual(hashlib.sha256(z.read(item['member'])).hexdigest(),item['sha256'])
    def test_visibility_claim_owner_and_scope_are_enforced(self):
        cases=[('outsider',{'task_id':'T1','scope_version':'2'},404),('peer',{'task_id':'T1','scope_version':'1','claim_id':'c-old'},403),
               ('worker',{'task_id':'T1','scope_version':'2','claim_id':'c-old'},409)]
        for actor,query,expected in cases:
            with self.assertRaises(ClientError) as e:package(Service(),actor,fixture(),query)
            self.assertEqual(e.exception.status,expected)
    def test_traversal_and_corruption_reject_without_changing_task(self):
        for corrupt in (True,False):
            state=fixture();original=deepcopy(state)
            if corrupt:state['tasks']['T1']['inputs']['new.md']='0'*64
            else:state['tasks']['T1']['inputs']={'../escape':'0'*64}
            with self.assertRaises(ClientError):package(Service(),'worker',state,{'task_id':'T1','scope_version':'2'})
            self.assertEqual(state['tasks']['T1']['scope_version'],original['tasks']['T1']['scope_version'])
    def test_large_count_has_individual_download_fallback(self):
        state=fixture();state['tasks']['T1']['inputs']={str(i):'0'*64 for i in range(501)}
        with self.assertRaises(ClientError) as e:package(Service(),'worker',state,{'task_id':'T1','scope_version':'2'})
        self.assertEqual(e.exception.status,413)

if __name__=='__main__':unittest.main()
