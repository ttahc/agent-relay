"""Real HTTP/Service integration on a qualified local ext4 or NTFS volume.

Run with Python 3.13+; set TASKPOOL_VERIFY_TMP to a qualified local filesystem.
A storage/runtime refusal is a BLOCKED result (exit 2), never a passing test.
No storage checks or ledger proof validation are mocked.
"""
import json
from pathlib import Path
import sys
import zipfile

from verify import ROOT, claim_args, server, sha
from verify_support import scratch
from verify_round import Browser, Client, bind, browser_admin_api, setup
from verify_upgrade import PROJECT, capability, claim, control, register, seal


def exercise(project):
    _, tokens, password = setup(project)
    with server(project) as (_, url):
        browser = Browser(url)
        browser.login('admin', password)
        browser.send('/')  # a signed-in page supplies the form token the admin actions need
        admin = browser_admin_api(project, browser)
        bind(admin, 'reviewer', 'receiver')
        bind(admin, 'worker-a', 'executor')
        worker = Client(url, tokens['worker-a'])
        reviewer = Client(url, tokens['reviewer'])
        capability(worker, 'worker-a')
        task = register(admin, 'reviewer', completion_policy='executor-direct')
        tid = task['task_id']
        task = worker.get('tasks/' + tid)['task']
        control(admin, 'task-publish', task)
        task = worker.get('tasks/' + tid)['task']
        held = claim(worker, task)
        sealed = seal(worker, held)
        c = sealed['claim']
        revision, record = next(reversed(c['deliveries'].items()))
        request = {'request_id': 'integration-direct-complete', **claim_args(sealed), 'revision': revision,
            'manifest_sha256': record['manifest_sha256'], 'checks': [{'id': 'ready',
                'path': record['manifest']['path'].rsplit('/', 1)[0] + '/output.md',
                'sha256': sha(b'fixture output'), 'note': 'Checked real immutable fixture output'}]}
        body = {k: v for k, v in request.items() if k != 'request_id'}
        done = worker.post('executor-complete', request=request['request_id'], **body)
        assert done == worker.post('executor-complete', request=request['request_id'], **body)
        view = worker.get('tasks/' + tid)
        assert view['task']['status'] == 'running'  # no fabricated stop
        assert view['claims'][0]['L'] == 'active'
        worker.post('close', 409, task_id=tid)
        worker.post('stop', **claim_args(done), stop_evidence='Fixture execution actually ended; no resources remain')
        closed = worker.post('close', request='integration-close', task_id=tid)
        assert closed == worker.post('close', request='integration-close', task_id=tid)
        view = worker.get('tasks/' + tid)
        assert view['task']['status'] == 'completed'
        assert view['claims'][0]['L'] == 'ended'
        assert view['delivery_reviews'][0]['completion_kind'] == 'executor-direct'
        assert view['delivery_reviews'][0]['independent'] is False
        frozen = view['task']
        issue = worker.post('task-issue-open', request='integration-issue', task_id=tid,
            task_version=frozen['version'], title='Follow-up finding', details='Fixture output needs a later check',
            evidence='output.md fixture inspection', visibility='project')
        rows = worker.get('post-completion?task_id=' + tid)['issues']
        assert len(rows) == 1
        row = rows[0]
        reviewer.post('task-issue-review', task_id=tid, task_version=frozen['version'], id=row['id'],
            version=row['version'], verdict='repair-required', reason='Follow-up confirms a repair is needed',
            evidence='Original immutable output checked')
        assert worker.get('tasks/' + tid)['task'] == frozen
        assert worker.get('post-completion?task_id=' + tid)['issues'][0]['status'] == 'repair-required'
        # Existing original completion stays intact; issue history is a separate record.
        assert worker.post('task-issue-open', request='integration-issue', task_id=tid,
            task_version=frozen['version'], title='Follow-up finding', details='Fixture output needs a later check',
            evidence='output.md fixture inspection', visibility='project') == issue
    with server(project) as (_, url):
        worker = Client(url, tokens['worker-a'])
        # A lost reply can be retried after process restart with the exact stable request.
        assert worker.post('executor-complete', request=request['request_id'], **body) == done
        assert worker.post('close', request='integration-close', task_id=tid) == closed
        view = worker.get('tasks/' + tid)
        assert view['task'] == frozen and len(view['delivery_reviews']) == 1
        assert len(worker.get('post-completion?task_id=' + tid)['issues']) == 1
    return {'passed': ['real HTTP direct completion', 'stop and close invariants', 'non-independent provenance',
                       'stable request retries', 'process restart retries', 'post-completion issue and review',
                       'original completion preserved']}


def main():
    if sys.version_info < (3, 13):
        print(json.dumps({'status': 'blocked', 'reason': 'Python 3.13+ is required; no checks bypassed'}))
        return 2
    with scratch('wf-') as directory:
        project = Path(directory)
        # Run the packaged release like the other end-to-end checks; the server needs the built client bundle.
        with zipfile.ZipFile(ROOT / 'dist' / 'task-pool-local.zip') as package:
            package.extractall(project)
        try:
            result = exercise(project)
        except RuntimeError as error:
            if 'ext4' in str(error) or 'NTFS' in str(error):
                print(json.dumps({'status': 'blocked', 'reason': str(error).strip(), 'passed': []}, ensure_ascii=False))
                return 2
            raise
    print(json.dumps({'status': 'passed', **result}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
