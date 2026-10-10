from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from dc_v2.contracts import Denied, Manifest, Principal, Request, canonical, digest
from dc_v2.gateway import Gateway, TransportGuard, approval_preview, deny_legacy, LEGACY_READ_NAMES, LEGACY_WRITE_NAMES
from dc_v2.ledger import Ed25519Verifier, Ledger
from dc_v2.output import OutputBuffer, Redactor
from dc_v2.policy import Classification, ExportEntry, ExportRegistry, TaskGrant, clean_environment, inspect_tool, relative_name


@pytest.fixture
def principal():
    return Principal('owner', 'test-client', 'test-recipient', frozenset({'file.read', 'task.start', 'project:demo'}))


@pytest.fixture
def manifest(principal):
    return Manifest(principal.binding, 'demo', 'task.start', '1' * 64, '2' * 64, '3' * 64,
                    'sandbox-001', 'test-recipient', ('python', '-m', 'pytest'), (), ('build',), 60, 4096)


class TestOnlyVerifier:
    """A deterministic TEST FIXTURE, never used by production components."""
    __test__ = False
    def sign(self, message):
        return hmac.digest(b'SYNTHETIC-TEST-KEY-NOT-A-CREDENTIAL', message, 'sha256')
    def verify(self, key_id, message, signature):
        return key_id == 'test-key' and hmac.compare_digest(self.sign(message), signature)


def make_ledger(tmp_path, manifest, principal):
    verifier = TestOnlyVerifier()
    clock = [1000]
    ledger = Ledger(tmp_path / 'ledger.db', verifier, lambda: clock[0])
    challenge = ledger.propose(manifest, principal)['challenge_id']
    ledger.receive_approval(challenge, 'test-key', verifier.sign(ledger.approval_message(challenge)))
    return ledger, challenge, clock


def request(operation='file.read'):
    return dict(version='2.2', request_id='req-1', project_id='demo', operation=operation,
                resource_id='source-1', idempotency_key='idem-1')


def test_canonical_stable():
    assert digest({'a': 1, 'b': 2}) == digest({'b': 2, 'a': 1})
    assert canonical({'a': 'é'}) == b'{"a":"\\u00e9"}'


@pytest.mark.parametrize('value', [float('nan'), 1.2, {1: 'x'}, object(), 2**54])
def test_canonical_rejects_ambiguous_types(value):
    with pytest.raises(Denied):
        canonical(value)


@pytest.mark.parametrize('extra', ['principal', 'approved', 'role', 'cwd', 'env', 'token', 'shell', 'backend'])
def test_request_rejects_client_authority(extra):
    with pytest.raises(Denied, match='INVALID_REQUEST'):
        Request.parse({**request(), extra: True})


@pytest.mark.parametrize('field,value', [('version','1'), ('operation','execute_command'),
    ('project_id','../secret'), ('resource_id','C:\\Users\\owner'), ('request_id','x\nadmin'),
    ('idempotency_key',''), ('project_id',None), ('operation',[]), ('version',{})])
def test_request_validation(field, value):
    with pytest.raises(Denied):
        Request.parse({**request(), field: value})


def test_request_valid():
    assert Request.parse(request()).operation == 'file.read'


@pytest.mark.parametrize('field,value', [('snapshot_digest','4'*64), ('tool_digest','5'*64),
    ('policy_digest','6'*64), ('target_id','other-sandbox'), ('recipient_id','other-recipient'),
    ('argv',('python','-c','print(42)')), ('environment',(('LANG','C'),)),
    ('timeout_s',61), ('output_limit',8192), ('capabilities',('network',)), ('project_id','other')])
def test_every_manifest_change_changes_digest(manifest, field, value):
    assert replace(manifest, **{field: value}).digest != manifest.digest


@pytest.mark.parametrize('bad', ['../x', '/etc/passwd', 'C:/Windows/x', 'C:x', '//host/share',
    '\\\\host\\share', 'a/../b', 'a//b', 'a:stream', 'a~1/file', 'a.', 'a ', 'CON', 'LPT1.txt',
    '.git/config', '.ssh/id', '.npmrc', '.env.local', 'data/key.pem', '.git-credentials', 'a\0b'])
def test_path_corpus(bad):
    with pytest.raises(Denied):
        relative_name(bad)


def test_path_valid():
    assert relative_name('src/example.py') == ('src','example.py')


def registry_for(tmp_path, data=b'hello', classification=Classification.MODEL_EXPORT_ALLOWED):
    root = tmp_path / 'snapshot'
    root.mkdir(exist_ok=True)
    (root / 'source.py').write_bytes(data)
    entry = ExportEntry('source-1', 'source.py', classification, frozenset({'test-recipient'}), hashlib.sha256(data).hexdigest())
    return ExportRegistry(root, (entry,), (tmp_path / 'installed-runtime',))


def test_export_exact_digest(tmp_path, principal):
    registry = registry_for(tmp_path)
    assert registry.read('source-1', principal) == b'hello'
    (registry.root / 'source.py').write_bytes(b'changed')
    with pytest.raises(Denied, match='MANIFEST_CHANGED'):
        registry.read('source-1', principal)


@pytest.mark.parametrize('classification', [Classification.SECRET, Classification.LOCAL_ONLY])
def test_no_export_confidential(tmp_path, principal, classification):
    registry = registry_for(tmp_path, classification=classification)
    with pytest.raises(Denied, match='EXPORT_DENIED'):
        registry.read('source-1', principal)


def test_cross_recipient_denied(tmp_path, principal):
    registry = registry_for(tmp_path)
    with pytest.raises(Denied, match='EXPORT_DENIED'):
        registry.read('source-1', replace(principal, recipient_id='someone-else'))


def test_export_unknown_id_denied(tmp_path, principal):
    with pytest.raises(Denied):
        registry_for(tmp_path).read('secret-path', principal)


def test_runtime_protected(tmp_path):
    installed = tmp_path / 'runtime'
    installed.mkdir()
    with pytest.raises(Denied):
        ExportRegistry(installed, (), (installed,))
    with pytest.raises(Denied):
        ExportRegistry(tmp_path, (), (installed,))


def test_symlink_denied(tmp_path, principal):
    registry = registry_for(tmp_path)
    victim = tmp_path / 'outside'
    victim.write_bytes(b'hello')
    link = registry.root / 'link.py'
    try:
        link.symlink_to(victim)
    except OSError:
        pytest.skip('Symlink privilege unavailable; Windows reparse gate remains NOT_RUN')
    entry = ExportEntry('link', 'link.py', Classification.PUBLIC, frozenset({'test-recipient'}), hashlib.sha256(b'hello').hexdigest())
    altered = ExportRegistry(registry.root, (entry,), (tmp_path / 'runtime',))
    with pytest.raises(Denied):
        altered.read('link', principal)


def test_tool_no_name_fallback(tmp_path, monkeypatch):
    trusted, work = tmp_path / 'trusted', tmp_path / 'work'
    trusted.mkdir(); work.mkdir()
    good, bad = trusted / 'git.exe', work / 'git.exe'
    good.write_bytes(b'TRUSTED-METADATA-ONLY'); bad.write_bytes(b'NEVER-EXECUTE')
    expected = hashlib.sha256(good.read_bytes()).hexdigest()
    same = work / 'same.exe'
    same.write_bytes(good.read_bytes())
    monkeypatch.setenv('PATH', str(work))
    assert inspect_tool(good, expected, trusted)['executed'] is False
    for candidate in (Path('git.exe'), bad, same):
        with pytest.raises(Denied):
            inspect_tool(candidate, expected, trusted)
    good.write_bytes(b'TAMPERED')
    with pytest.raises(Denied):
        inspect_tool(good, expected, trusted)


@pytest.mark.parametrize('name', ['PATH', 'PYTHONPATH', 'NODE_OPTIONS', 'GIT_CONFIG_COUNT',
    'GH_TOKEN', 'CLOUDFLARE_API_TOKEN', 'HOME', 'USERPROFILE'])
def test_environment_no_credential_or_code_inheritance(name, monkeypatch):
    monkeypatch.setenv(name, 'SYNTHETIC-CANARY')
    assert clean_environment({'LANG':'C'}) == {'LANG':'C'}
    with pytest.raises(Denied):
        clean_environment({name: 'bad'})


def test_grant_scope(manifest, principal):
    grant = TaskGrant(principal.binding, 'demo', '1'*64, '2'*64, '3'*64, 'sandbox-001',
                      'test-recipient', frozenset({'task.start'}), frozenset({'build'}), 1100, 60, 4096)
    grant.authorize(manifest, principal, 1000)
    # Repeated commands inside the task do not consume a one-shot boundary approval.
    for i in range(20):
        grant.authorize(replace(manifest, argv=('python', '-m', 'pytest', f'test_{i}.py')), principal, 1000)
    with pytest.raises(Denied, match='GRANT_EXPIRED'):
        grant.authorize(manifest, principal, 1100)
    with pytest.raises(Denied, match='APPROVAL_REQUIRED'):
        grant.authorize(replace(manifest, capabilities=('network',)), principal, 1000)


@pytest.mark.parametrize('split', range(1, 22))
def test_redaction_across_every_boundary(split):
    canary = b'SYNTHETIC-SECRET-12345'
    raw = b'prefix:' + canary + b':suffix'
    redactor = Redactor((canary,))
    out = redactor.feed(raw[:split]) + redactor.feed(raw[split:], final=True)
    assert canary not in out and out == b'prefix:[REDACTED]:suffix'


def test_redaction_bytewise_and_overlapping():
    redactor = Redactor((b'abc', b'abcd', b'xyz'))
    chunks = [redactor.feed(bytes([x])) for x in b'00abcdabcxyz99']
    chunks.append(redactor.feed(b'', final=True))
    assert b''.join(chunks) == b'00[REDACTED][REDACTED][REDACTED]99'


def test_output_flood_bounded():
    out = OutputBuffer(128)
    for _ in range(200):
        out.append(b'x' * 1024)
        assert len(out.data) <= 128
    out.append(b'', final=True)
    result = out.read()
    assert result['truncated'] and result['dropped_bytes'] == 204800 - 128
    assert len(result['data']) == 128 and result['eof']


def test_output_cursor_and_closed():
    out = OutputBuffer(128)
    out.append(b'12345', final=True)
    assert out.read(2, 2)['data'] == b'34'
    with pytest.raises(Denied):
        out.read(100)
    with pytest.raises(Denied):
        out.append(b'6')


def test_default_verifier_denies(tmp_path, manifest, principal):
    ledger = Ledger(tmp_path / 'state.db', clock=lambda: 1000)
    challenge = ledger.propose(manifest, principal)['challenge_id']
    with pytest.raises(Denied, match='APPROVAL_INVALID'):
        ledger.receive_approval(challenge, 'pretend', b'approved=true')


def test_atomic_reservation_20_clients(tmp_path, manifest, principal):
    ledger, challenge, _ = make_ledger(tmp_path, manifest, principal)
    barrier = threading.Barrier(20)
    def submit(_):
        barrier.wait()
        return ledger.reserve(challenge, manifest, principal, 'one-operation')
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(submit, range(20)))
    assert sum(r['created'] for r in results) == 1
    assert len({r['operation_id'] for r in results}) == 1
    head = ledger.verify_outbox()
    assert head[0] == 3
    assert ledger.verify_outbox(head) == head
    with pytest.raises(Denied, match='APPROVAL_REQUIRED'):
        ledger.reserve(challenge, manifest, principal, 'another-operation')


def test_manifest_mismatch_and_expiry(tmp_path, manifest, principal):
    ledger, challenge, clock = make_ledger(tmp_path, manifest, principal)
    with pytest.raises(Denied, match='MANIFEST_CHANGED'):
        ledger.reserve(challenge, replace(manifest, argv=('different',)), principal, 'idem')
    clock[0] += 120
    with pytest.raises(Denied, match='APPROVAL_EXPIRED'):
        ledger.reserve(challenge, manifest, principal, 'idem')


def test_object_authorization_and_idempotency(tmp_path, manifest, principal):
    ledger, challenge, _ = make_ledger(tmp_path, manifest, principal)
    result = ledger.reserve(challenge, manifest, principal, 'idem')
    assert ledger.status(result['operation_id'], principal)['status'] == 'RESERVED'
    other = replace(principal, client_id='other-client')
    with pytest.raises(Denied, match='ACCESS_DENIED'):
        ledger.status(result['operation_id'], other)
    with pytest.raises(Denied, match='IDEMPOTENCY_CONFLICT'):
        ledger.reserve(challenge, replace(manifest, argv=('changed',)), principal, 'idem')


def test_stop_survives_restart_and_broken_audit(tmp_path, manifest, principal):
    ledger, challenge, _ = make_ledger(tmp_path, manifest, principal)
    with sqlite3.connect(ledger.path) as con:
        con.execute('DROP TABLE outbox')  # synthetic test fixture only
    ledger.stop_latch()
    # Restart has no reset/resume API; stop remains latched.
    restarted = Ledger(ledger.path, clock=lambda: 1000)
    with pytest.raises(Denied, match='OPERATION_CANCELLED'):
        restarted.reserve(challenge, manifest, principal, 'idem')


def test_audit_truncation_requires_independent_anchor(tmp_path, manifest, principal):
    ledger, challenge, _ = make_ledger(tmp_path, manifest, principal)
    ledger.reserve(challenge, manifest, principal, 'idem')
    head = ledger.verify_outbox()
    with sqlite3.connect(ledger.path) as con:
        con.execute('DELETE FROM outbox WHERE seq=3')  # only synthetic fixture
    with pytest.raises(Denied, match='AUDIT_INTEGRITY_ERROR'):
        ledger.verify_outbox(head)


def test_no_reservation_if_audit_write_fails(tmp_path, manifest, principal):
    ledger, challenge, _ = make_ledger(tmp_path, manifest, principal)
    with sqlite3.connect(ledger.path) as con:
        con.execute("CREATE TRIGGER deny_event BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture'); END")
    with pytest.raises(sqlite3.DatabaseError):
        ledger.reserve(challenge, manifest, principal, 'idem')
    with sqlite3.connect(ledger.path) as con:
        assert con.execute('SELECT COUNT(*) FROM operations').fetchone()[0] == 0
        assert con.execute('SELECT state FROM challenges WHERE id=?', (challenge,)).fetchone()[0] == 'APPROVED'


def test_challenge_quota(tmp_path, manifest, principal):
    ledger = Ledger(tmp_path / 'state.db', clock=lambda: 1000)
    for _ in range(32):
        ledger.propose(manifest, principal)
    with pytest.raises(Denied, match='QUOTA_EXCEEDED'):
        ledger.propose(manifest, principal)


def test_ed25519_real_signature_optional():
    pytest.importorskip('cryptography')
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    verifier = Ed25519Verifier({'test-key': public})
    signature = key.sign(b'manifest')
    assert verifier.verify('test-key', b'manifest', signature)
    assert not verifier.verify('test-key', b'changed', signature)
    assert not verifier.verify('unknown', b'manifest', signature)


def test_gateway_default_deny():
    assert Gateway({}).call(request(), 'dummy')['error_code'] == 'AUTH_REQUIRED'


class FixtureIdentity:
    def __init__(self, principal): self.principal = principal
    def authenticate(self, credential):
        if credential != 'fixture-only': raise Denied('AUTH_REQUIRED')
        return self.principal


def test_gateway_export_and_safe_errors(tmp_path, principal):
    registry = registry_for(tmp_path, b'x' * 70000 + b'SYNTHETIC-CANARY')
    gateway = Gateway({'demo': registry}, FixtureIdentity(principal), (b'SYNTHETIC-CANARY',))
    result = gateway.call(request(), 'fixture-only')
    assert result['status'] == 'OK' and result['redactions'] == 1
    assert result['content'] == 'x' * 70000 + '[REDACTED]'
    assert gateway.call(request(), 'wrong')['error_code'] == 'AUTH_REQUIRED'
    assert gateway.call(request('task.start'), 'fixture-only')['error_code'] == 'EXECUTION_HOLD'
    assert gateway.call({**request(), 'approved': True}, 'fixture-only')['error_code'] == 'INVALID_REQUEST'
    class CrashingIdentity:
        def authenticate(self, credential): raise RuntimeError('SYNTHETIC-CANARY')
    assert 'SYNTHETIC' not in json.dumps(Gateway({}, CrashingIdentity()).call(request(), 'a'))


def test_gateway_cross_project_denied(tmp_path, principal):
    no_project = replace(principal, scopes=frozenset({'file.read'}))
    gateway = Gateway({'demo': registry_for(tmp_path)}, FixtureIdentity(no_project))
    assert gateway.call(request(), 'fixture-only')['error_code'] == 'ACCESS_DENIED'


@pytest.mark.parametrize('name', sorted(LEGACY_READ_NAMES | LEGACY_WRITE_NAMES))
def test_all_legacy_paths_denied_until_migrated(name):
    with pytest.raises(Denied, match='LEGACY_MIGRATION_REQUIRED'):
        deny_legacy(name)


@pytest.mark.parametrize('host,origin,headers', [('evil','https://approved',{}),
    ('localhost:18766','https://evil',{}), ('localhost:18766',None,{}),
    ('localhost:18766','https://approved',{'X-Forwarded-User':'admin'})])
def test_transport_negative(host, origin, headers):
    guard = TransportGuard(frozenset({'localhost:18766'}), frozenset({'https://approved'}))
    with pytest.raises(Denied):
        guard.check(host, origin, headers)


def test_transport_native_explicit():
    guard = TransportGuard(frozenset({'localhost:18766'}), frozenset(), native_clients=True)
    guard.check('localhost:18766', None, {})


def test_approval_preview_is_not_confirmation(manifest):
    preview = approval_preview(replace(manifest, argv=('<script>alert(1)</script>', '\u202eadmin')))
    assert '<script>' not in preview and '\\u202e' in preview
    assert 'PREVIEW ONLY' in preview and '<button' not in preview
