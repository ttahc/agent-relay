"""Redacted diagnostics and distributable-source checks; never rewrite evidence."""
from copy import deepcopy
import logging
from pathlib import PurePosixPath
import re
import traceback
import uuid

SECRET_FIELDS = {'token', 'tokens', 'access_token', 'refresh_token', 'rotation_token', 'code', 'password', 'passwd',
    'current', 'confirm', 'recovery', 'secret', 'private_key', 'verifier', 'salt', 'proof_sha', 'token_sha',
    'reset', 'reset_code', 'invitation_url', 'invite_url', 'token_sha256'}
PATTERNS = (
    ('private-key', re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', re.S)),
    ('bearer', re.compile(r'(?i)(\bBearer\s+)[A-Za-z0-9._~+/-]{25,}')),
    ('provider-key', re.compile(r'\b(?:ghp_|github_pat_|sk-proj-|sk-ant-)[A-Za-z0-9_-]{24,}')),
    ('credential-assignment', re.compile(r'''(?i)((?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|recovery|code)\s*[=:]\s*["']?)[A-Za-z0-9_./+~=-]{24,}''')),
    ('invitation-link', re.compile(r'(https?://[^\s"<>]+/ai/join/[^\s"<>#]+)#[^\s"<>]+')),
)


def text(value, private_paths=False):
    value = str(value)
    for name, pattern in PATTERNS:
        if name in {'bearer', 'credential-assignment'}:
            value = pattern.sub(lambda m: m.group(1) + '[已隐藏]', value)
        elif name == 'invitation-link':
            value = pattern.sub(lambda m: m.group(1) + '#[已隐藏]', value)
        else:
            value = pattern.sub('[已隐藏]', value)
    if private_paths:
        value = re.sub(r'(?i)[A-Z]:[\\/]Users[\\/][^\\/\s"<>]+', '%USERPROFILE%', value)
        value = re.sub(r'/home/[^/\s"<>]+', '~', value)
    return value


def public(value, private_paths=False):
    if isinstance(value, dict):
        return {key: ('[已隐藏]' if str(key).lower() in SECRET_FIELDS else public(item, private_paths)) for key, item in value.items()}
    if isinstance(value, list):
        return [public(item, private_paths) for item in value]
    if isinstance(value, tuple):
        return tuple(public(item, private_paths) for item in value)
    return text(value, private_paths) if isinstance(value, str) else value


def log_exception(error):
    """Log a correlation id and safe frame locations, without request locals."""
    incident = uuid.uuid4().hex[:12]
    frames = [f'{PurePosixPath(frame.filename.replace(chr(92), "/")).name}:{frame.lineno}:{frame.name}'
            for frame in traceback.extract_tb(error.__traceback__)]
    logging.error('Task pool incident=%s type=%s message=%s frames=%s', incident, type(error).__name__,
                  text(str(error), True), ' > '.join(frames))
    return incident


def window_source(state, actor, source):
    from 协作升级 import system_admin
    result = deepcopy(source)
    name = source.get('executor_id') or source.get('name')
    if actor not in {name, source.get('owner')} and not system_admin(state, actor):
        for key in ('directory', 'device', 'session', 'url'):
            result[key] = None
        result['private_source_redacted'] = True
    return result


def release_findings(files):
    findings = []
    private_names = {'credentials.json', 'http-journal.sqlite3', 'window.credential', 'key.pem'}
    key_pattern = re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----')
    provider_pattern = re.compile(rb'\b(?:ghp_|github_pat_|sk-proj-|sk-ant-)[A-Za-z0-9_-]{24,}')
    for name, raw in files.items():
        path = PurePosixPath(name)
        if path.name.lower() in private_names or path.suffix.lower() in {'.pfx', '.p12', '.key', '.dpapi', '.sqlite3'} or '.state' in path.parts:
            findings.append({'path': name, 'kind': 'private-file'})
        if key_pattern.search(raw):
            findings.append({'path': name, 'kind': 'private-key'})
        if provider_pattern.search(raw):
            findings.append({'path': name, 'kind': 'provider-key'})
    return findings


def check_release(files):
    findings = release_findings(files)
    if findings:
        labels = ', '.join(item['path'] + ' (' + item['kind'] + ')' for item in findings)
        raise ValueError('发行包含疑似私有材料，请移出后重新构建：' + labels)
