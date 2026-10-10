from __future__ import annotations
import asyncio
import hashlib
import json
from pathlib import Path
import pytest
from dc_v2.contracts import Denied
from dc_v2.readonly_snapshot import FrozenSnapshot,load_snapshot
from dc_v2.readonly_mcp import create_app_from_config,MAX_BODY
from tests_phase02.test_readonly import service,app_for,run_http,snapshot_data,verifier,P,TOKEN,NOW


def test_invalid_header_duplicates(service):
    async def run(headers):
        app=app_for(service);sent=[]
        scope={'type':'http','method':'POST','path':'/mcp','raw_path':b'/mcp','query_string':b'',
            'client':('127.0.0.1',1234),'headers':headers}
        async def receive():return {'type':'http.request','body':b'{}','more_body':False}
        async def send(v):sent.append(v)
        await app(scope,receive,send);return sent
    base=[(b'host',b'127.0.0.1:18766'),(b'authorization',('Bearer '+TOKEN).encode())]
    for duplicate in (base[0],base[1]):
        messages=asyncio.run(run(base+[duplicate]));assert messages[0]['status']==403
        assert TOKEN.encode() not in messages[1]['body']


def test_streaming_body_limit_without_content_length(service):
    async def run():
        app=app_for(service);sent=[];chunks=iter([b' '*(MAX_BODY//2),b' '*(MAX_BODY//2),b'x'])
        scope={'type':'http','method':'POST','path':'/mcp','raw_path':b'/mcp','query_string':b'',
            'client':('127.0.0.1',1234),'headers':[(b'host',b'127.0.0.1:18766'),
            (b'authorization',('Bearer '+TOKEN).encode()),(b'content-type',b'application/json'),
            (b'accept',b'application/json, text/event-stream')]}
        async def receive():return {'type':'http.request','body':next(chunks),'more_body':True}
        async def send(v):sent.append(v)
        await app(scope,receive,send);return sent
    assert asyncio.run(run())[0]['status']==413


def test_missing_native_origin_denied_when_not_permitted(service):
    app=app_for(service);app.guard.native_clients=False
    assert run_http(app).status_code==403


def test_audit_failure_before_initialize(service):
    class Broken:
        def record(self,*a):raise OSError('private error')
    service.audit=Broken()
    r=run_http(app_for(service));assert r.status_code==503 and 'private error' not in r.text


def test_metadata_redacted_under_neutral_keys(tmp_path):
    from dc_v2.readonly_service import ReadOnlyService
    from dc_v2.readonly_audit import LocalAuditJournal
    canary=b'NEUTRAL_METADATA_CANARY'
    s=snapshot_data();s['projects'][0]['title']=canary.decode()
    svc=ReadOnlyService(FrozenSnapshot.from_dict(s),LocalAuditJournal(tmp_path/'audit.jsonl'),(canary,))
    assert canary.decode() not in json.dumps(svc.invoke('projects_list',{},P))


def test_empty_and_large_utf8_resource(service):
    s=snapshot_data();s['projects'][0]['resources'][0].update(utf8='',sha256=hashlib.sha256(b'').hexdigest())
    snap=FrozenSnapshot.from_dict(s); assert snap.projects['demo'].resources['readme'].data==b''
    s['projects'][0]['resources'][0]['utf8']='x'*(1024*1024+1)
    with pytest.raises(Denied):FrozenSnapshot.from_dict(s)


def test_snapshot_hardlink_refused(tmp_path):
    p=tmp_path/'original.json';data=json.dumps(snapshot_data()).encode();p.write_bytes(data)
    alias=tmp_path/'alias.json';alias.hardlink_to(p)
    with pytest.raises(Denied):load_snapshot(alias,hashlib.sha256(data).hexdigest())


def test_bootstrap_exact_profile_and_no_authority_extensions(tmp_path):
    snap=tmp_path/'snapshot.json';raw=json.dumps(snapshot_data()).encode();snap.write_bytes(raw)
    token={'token_sha256':hashlib.sha256(TOKEN.encode()).hexdigest(),
           'subject':P.subject,'client_id':P.client_id,'recipient_id':P.recipient_id,
           'scopes':sorted(P.scopes),'not_before':NOW-1,'expires_at':NOW+60}
    cfg={'profile':'loopback-readonly-dev','port':18766,'issuer':'local-test','snapshot_path':str(snap),
         'snapshot_sha256':hashlib.sha256(raw).hexdigest(),'audit_path':str(tmp_path/'bootstrap-audit.jsonl'),
         'tokens':[token]}
    p=tmp_path/'config.json';p.write_text(json.dumps(cfg))
    app,port=create_app_from_config(p);assert port==18766 and app.identity.audience=='http://127.0.0.1:18766/mcp'
    for key,value in [('profile','production'),('host','0.0.0.0'),('execution_enabled',True),('port',True)]:
        changed=dict(cfg);changed[key]=value;p.write_text(json.dumps(changed))
        with pytest.raises(Denied):create_app_from_config(p)


def test_unknown_configuration_never_reads_snapshot(tmp_path,monkeypatch):
    p=tmp_path/'config.json';p.write_text('{"approved": true,"snapshot_path":"C:/secret"}')
    with pytest.raises(Denied):create_app_from_config(p)


def test_file_read_after_input_snapshot_changed_uses_frozen_bytes(service):
    assert service.snapshot.projects['demo'].resources['readme'].data.startswith(b'hello')
    # No file opener exists on the request path: this test disables all builtin file opens.
    import builtins
    old=service.audit
    class MemoryAudit:
        def record(self,*a):pass
    service.audit=MemoryAudit()
    def forbidden(*a,**k):raise AssertionError('Request attempted host file IO')
    from unittest.mock import patch
    with patch.object(builtins,'open',forbidden),patch.object(Path,'open',forbidden):
        assert service.invoke('file_read',{'project_id':'demo','resource_id':'readme'},P)['status']=='OK'
    service.audit=old
