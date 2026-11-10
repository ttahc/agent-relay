"""Local-only safety migration with preserved, quarantined unfinished requests."""
import json
import time
import os
import tempfile
from .packages import ClientError
from 协作存储 import digest, encoded
from 协作安全 import check


def record_configuration(service, config):
    from 协作存储 import safe, sync_directory
    directory = service.desk.store
    target = safe(directory, 'service-config.json')
    raw = encoded({'schema': 1, **config})
    with service.lock:
        fd, name = tempfile.mkstemp(prefix='.service-config-', dir=directory)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, target)
            if os.name == 'posix':
                sync_directory(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)


def initialize(db):
    db.execute('CREATE TABLE IF NOT EXISTS request_quarantine('
               'key TEXT PRIMARY KEY,reason TEXT NOT NULL,created REAL NOT NULL)')
    db.commit()


def migrate(service, target, request_id):
    if target not in {4, 5}:
        raise ClientError('目标安全语义须为4或5')
    with service.lock:
        snap = service.snapshot()
        current = check(snap['state'])
        if current < 3 or target < current:
            raise ClientError('安全迁移只支持3→4→5，不能降级', 409)
        # An already received nonterminal envelope is a real migration prerequisite.
        # Do not let a new reader silently execute it or reuse its origin sequence.
        terminal = snap['control']['terminal']
        if any(record['envelope']['origin_id'] + '/' + record['envelope']['event_id'] not in terminal
               for record in service.desk.copies()):
            raise ClientError('已有接收但未终局的账本请求；请先按原语义恢复或核对，原数据保留，尚未开始安全迁移', 409)
        # Finish only requests whose complete ledger plan has already been committed.
        for key, raw_plan in service.db.execute('SELECT key,plan FROM requests WHERE status IS NULL').fetchall():
            plan = json.loads(raw_plan)
            terminal = snap['control']['terminal']
            rows = service.db.execute('SELECT envelope FROM steps WHERE request_key=? ORDER BY position',
                                      (key,)).fetchall()
            all_committed = len(rows) == len(plan['steps']) and all(
                (e := json.loads(raw[0])) and (entry := terminal.get(e['origin_id'] + '/' + e['event_id'])) and
                entry.get('result') == 'applied' and entry.get('content_sha256') == digest(encoded(e)) for raw in rows)
            if all_committed:
                service.execute(key)
            else:
                with service.db:
                    service.db.execute('INSERT OR IGNORE INTO request_quarantine VALUES(?,?,?)',
                        (key, '旧未终局请求保留待有权人员核对；不按新规则自动重放', time.time()))
        for version in range(current + 1, target + 1):
            rid = request_id + '-' + str(version)
            if len(rid) > 80:
                raise ClientError('迁移请求编号过长')
            body = {'request_id': rid, 'target': version}
            status, result = service.submit('admin', 'security-migrate', rid, body)
            if status != 200:
                return status, result
            service.accounts.baseline_executors(service.snapshot())
        state = service.snapshot()['state']
        return 200, {'status': 'applied', 'security_schema': check(state),
                     'quarantined_requests': service.db.execute(
                         'SELECT count(*) FROM request_quarantine').fetchone()[0],
                     'claims_preserved': len(state['claims']), 'head': service.snapshot()['head']}
