"""One authenticated download for exact task/claim frozen inputs."""
from contextlib import nullcontext
from copy import deepcopy
import hashlib
from io import BytesIO
import json
from pathlib import PurePosixPath
import zipfile
import tempfile
import threading
from .packages import ClientError

BUDGET = dict(json_bytes=8 * 1024**2, zip_bytes=144 * 1024**2, total_bytes=128 * 1024**2,
              file_bytes=64 * 1024**2, files=500, manifest_bytes=1024**2)
_GENERATOR = threading.BoundedSemaphore(1)


def select(service, actor, state, query):
    if not isinstance(query, dict) or not set(query) <= {'task_id', 'scope_version', 'claim_id'}:
        raise ClientError('输入包参数无效')
    task = state['tasks'].get(query.get('task_id'))
    if not task or not service.visible(state, task, actor):
        raise ClientError('任务不存在或无权读取', 404)
    claim = None
    if query.get('claim_id'):
        claim = state['claims'].get(query['claim_id'])
        if not claim or claim['task_id'] != task['task_id']:
            raise ClientError('领取与任务不匹配', 404)
        if not (claim['origin'] == actor or {'manager', 'receiver'} & set(service.task_roles(state, task, actor)) or
                'read' in service.delegated_actions(state, task, actor)):
            raise ClientError('无权读取该领取输入', 403)
    scope = claim['W']['scope'] if claim else task['scope_version']
    if str(query.get('scope_version')) != str(scope):
        raise ClientError('输入范围已更新，请重新读取任务或领取回执', 409)
    inputs = claim['inputs'] if claim else task['inputs']
    if len(inputs) > 500:
        raise ClientError('本卡输入较多，请改用逐项下载，已领取状态保持', 413)
    seen = set()
    for path, sha in inputs.items():
        logical = PurePosixPath(path)
        if (logical.is_absolute() or '\\' in path or ':' in path or '..' in logical.parts or str(logical) != path or
                path.casefold() in seen or not isinstance(sha, str) or len(sha) != 64 or
                any(c not in '0123456789abcdef' for c in sha)):
            raise ClientError('输入文件路径或指纹无效', 503)
        seen.add(path.casefold())
    return {'task_id': task['task_id'], 'scope_version': scope, 'claim_id': claim['claim_id'] if claim else None,
            'inputs': deepcopy(inputs)}


def generate(service, actor, selection):
    if not _GENERATOR.acquire(blocking=False):
        raise ClientError('另一份输入包正在生成，请稍后重试', 503)
    try:
        runtime = None
        if hasattr(service, 'desk'):
            from 协作存储 import safe
            runtime = safe(service.desk.store, '.runtime')
            runtime.mkdir(mode=0o700, exist_ok=True)
            if not runtime.is_dir():
                raise ClientError('输入包临时目录不可用', 503)
        output = tempfile.TemporaryFile('w+b', dir=runtime)
    except BaseException:
        _GENERATOR.release()
        raise
    try:
        rows = []
        total = 0
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED, compresslevel=5) as archive:
            for path, sha in sorted(selection['inputs'].items()):
                member = 'files/' + path
                checksum = hashlib.sha256()
                size = 0
                if hasattr(service, 'desk'):
                    from 协作存储 import safe
                    from .backup import regular_reader
                    source_context = regular_reader(safe(service.desk.store, path))
                else:
                    source_context = BytesIO(service.read(actor, 'artifact', path))
                with source_context as source, archive.open(member, 'w') as target:
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        total += len(chunk)
                        if size > BUDGET['file_bytes'] or total > BUDGET['total_bytes']:
                            raise ClientError('输入超过单文件或展开预算；领取和已核验文件保留', 413)
                        checksum.update(chunk)
                        target.write(chunk)
                if checksum.hexdigest() != sha:
                    raise ClientError('输入字节与冻结指纹不一致', 503)
                rows.append({'path': path, 'sha256': sha, 'bytes': size, 'member': member})
            manifest = {**{k: selection[k] for k in ('task_id', 'scope_version', 'claim_id')}, 'inputs': rows}
            raw = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
            if len(raw) > BUDGET['manifest_bytes']:
                raise ClientError('输入清单超过预算', 413)
            archive.writestr('manifest.json', raw)
        if output.tell() > BUDGET['zip_bytes']:
            raise ClientError('输入包传输预算超限', 413)
        output.seek(0)
        return output, hashlib.sha256(raw).hexdigest()
    except BaseException:
        output.close()
        raise
    finally:
        _GENERATOR.release()


def package(service, actor, state, query):
    with generate(service, actor, select(service, actor, state, query))[0] as stream:
        return stream.read()
