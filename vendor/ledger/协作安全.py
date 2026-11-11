"""Fail-closed safety semantics and append-only upgrade checkpoints."""
from copy import deepcopy
from 协作存储 import Rejected

READER = 8

DOMAIN_OPS = {'environment-save', 'resource-map-save', 'storage-domain-register', 'storage-domain-merge'}
DOMAIN_TABLES = {'environments', 'environment_history', 'resource_mappings', 'resource_mapping_history',
                 'storage_domains', 'storage_domain_parents', 'storage_domain_merges'}
DOMAIN_PROOF_KEYS = {'ancestor_identities', 'physical_paths', 'descendant_identities', 'domain_identities',
                     'domain_paths', 'scope_uncertain', 'mapping_id', 'mapping_version', 'environment_id',
                     'storage_domain_id'}


def requires_domains(security):
    """Inspect execution structure, never user-authored evidence or message text."""
    execution = security.get('execution', {})
    if DOMAIN_TABLES.intersection(execution):
        return True
    if any('environment_id' in row for row in execution.get('contexts', {}).values()):
        return True
    rows = [row for table in ('actions', 'resource_requests', 'grants', 'legacy', 'blockers')
            for row in execution.get(table, {}).values()]
    rows.extend(security.get('physical_blockers', {}).values())
    for row in rows:
        proofs = row.get('resource_proofs', {}).values()
        if any(DOMAIN_PROOF_KEYS.intersection(proof) for proof in proofs):
            return True
        if any(DOMAIN_PROOF_KEYS.intersection(resource) for resource in row.get('resources', [])):
            return True
    return False


def check(state, reader=READER):
    fmt = state.get('pilot', {}).get('format', {})
    security = state.get('security', {})
    version = security.get('schema', fmt.get('schema', 1))
    if type(version) is not int or version > min(reader, 5) or fmt.get('min_reader', 1) > reader:
        raise ValueError('当前写入者不支持此账本安全语义')
    if fmt.get('min_reader') == 6 or requires_domains(security):
        # Reader 7 adds task workflows on main, not the parallel reader-6 branch.
        # A combined build must actually include its execution operations/tables.
        from 协作执行 import OPS, TABLES
        if reader < 6 or not DOMAIN_OPS.issubset(OPS) or not DOMAIN_TABLES.issubset(TABLES):
            raise ValueError('当前程序未包含此账本所需的执行环境与资源域规则')
    if fmt.get('schema', 1) >= 4 and (security.get('schema') != fmt['schema'] or
                                     security.get('phase') not in {'migrating', 'ready'}):
        raise ValueError('安全迁移状态不完整；只可使用相容恢复程序')
    return version

def migrate(state, actor, target, event, now, source=None):
    import 协作升级 as rules
    rules.require(rules.system_admin(state, actor), '安全迁移须由本机有效人员管理员办理', 'intent-final')
    current = check(state)
    rules.require(target in {4, 5} and target >= current and current >= 3, '迁移只支持 3→4→5，不能降级')
    security = state.setdefault('security', {})
    if target == current:
        return
    rules.require(target == current + 1, '须逐安全版本提交检查点')
    history = security.setdefault('migrations', [])
    history.append({'from': current, 'to': target, 'event': event, 'at': now,
                    'source':deepcopy(source),
                    'claim_count': len(state.get('claims', {})), 'task_count': len(state.get('tasks', {}))})
    security.update(schema=target, phase='ready')
    security.setdefault('physical_blockers', {})
    state['pilot']['format'].update(schema=target, min_reader=max(target, state['pilot']['format'].get('min_reader', 1)))
    if target == 5:
        from 协作执行 import migrate_legacy
        migrate_legacy(state, now, event)

def preserve_unknown(state, claim, reservation, evidence):
    if check(state) < 4:
        return
    legacy=state.get('security',{}).get('execution',{}).get('legacy',{}).get('legacy-'+claim['claim_id'],{})
    if (claim.get('E', {}).get('state') == 'stopped' and claim.get('stop_evidence') and
            not (legacy.get('active') and legacy.get('physical') in {'unknown','in-use'})):
        return
    blockers = state['security'].setdefault('physical_blockers', {})
    key = 'legacy:' + reservation['reservation_id']
    blockers.setdefault(key, {'id': key, 'claim_id': claim['claim_id'],
                             'epoch':reservation.get('epoch',legacy.get('epoch',claim['epoch'])),
                             'scope_version':reservation.get('scope_version',legacy.get('scope_version',claim['W']['scope'])),
                             'resources': [{'id': reservation['id'], 'mode': reservation['mode']}],
                             'physical': 'unknown', 'active': True,
                             'reason': '预约解除不证明外部写入已结束', 'logical_release_evidence': evidence})

def blocked_resources(state):
    return [resource for row in state.get('security', {}).get('physical_blockers', {}).values()
            if row.get('active') and row.get('physical') == 'unknown' for resource in row['resources']]
