from __future__ import annotations
import asyncio
import hashlib
from dataclasses import replace
import json
from pathlib import Path
import pytest
from tests_phase02.test_readonly import service,app_for,run_http,snapshot_data,P,TOKEN,NOW
from dc_v2.readonly_service import ReadOnlyService
from dc_v2.readonly_snapshot import FrozenSnapshot
from dc_v2.readonly_audit import LocalAuditJournal

def test_large_metadata_has_explicit_output_quota(tmp_path):
    s=snapshot_data();template=s['projects'][0]['resources'][0]
    s['projects'][0]['resources']=[dict(template,resource_id=f'r{i}',display_name=('x'*900)+f'{i}.txt') for i in range(128)]
    svc=ReadOnlyService(FrozenSnapshot.from_dict(s),LocalAuditJournal(tmp_path/'audit.jsonl'))
    assert svc.invoke('project_describe',{'project_id':'demo'},P)=={'status':'DENIED','error_code':'QUOTA_EXCEEDED'}

def test_audit_missing_final_newline_is_detected(service,tmp_path):
    service.invoke('capabilities_list',{},P);p=tmp_path/'audit.jsonl';p.write_bytes(p.read_bytes()[:-1])
    assert service.invoke('capabilities_list',{},P)['error_code']=='AUDIT_UNAVAILABLE'

def test_bearer_expiring_during_body_receipt_is_rejected(service):
    from dc_v2.readonly_auth import BearerRecord,PinnedBearerVerifier
    clock=[NOW]
    auth=PinnedBearerVerifier('local-test','http://127.0.0.1:18766/mcp',(
        BearerRecord(hashlib.sha256(TOKEN.encode()).hexdigest(),P,'local-test','http://127.0.0.1:18766/mcp',NOW-1,NOW+1),),
        clock=lambda:clock[0])
    app=app_for(service,auth=auth)
    async def run():
        sent=[]
        scope={'type':'http','method':'POST','path':'/mcp','raw_path':b'/mcp','query_string':b'',
            'client':('127.0.0.1',1234),'headers':[(b'host',b'127.0.0.1:18766'),
            (b'authorization',('Bearer '+TOKEN).encode()),(b'content-type',b'application/json'),
            (b'accept',b'application/json, text/event-stream')]}
        async def receive():
            clock[0]=NOW+2
            return {'type':'http.request','body':b'{"jsonrpc":"2.0","id":1,"method":"ping"}','more_body':False}
        async def send(v):sent.append(v)
        await app(scope,receive,send);return sent
    assert asyncio.run(run())[0]['status']==401

def test_concurrency_budget_releases_on_completion(service):
    app=app_for(service,max_concurrency=1)
    async def run():
        first=asyncio.Event();release=asyncio.Event();one=[];two=[]
        scope={'type':'http','method':'POST','path':'/mcp','raw_path':b'/mcp','query_string':b'',
            'client':('127.0.0.1',1234),'headers':[(b'host',b'127.0.0.1:18766'),
            (b'authorization',('Bearer '+TOKEN).encode()),(b'content-type',b'application/json'),
            (b'accept',b'application/json, text/event-stream')]}
        async def receive():
            first.set();await release.wait()
            return {'type':'http.request','body':b'{"jsonrpc":"2.0","id":1,"method":"ping"}','more_body':False}
        async def send_one(v):one.append(v)
        async def send_two(v):two.append(v)
        task=asyncio.create_task(app(scope,receive,send_one));await first.wait()
        await app(scope,receive,send_two);assert two[0]['status']==429
        release.set();await task;assert one[0]['status']==200
    asyncio.run(run());assert app._active==0

def test_runtime_modules_have_no_execution_or_dynamic_import():
    import ast
    root=Path(__file__).resolve().parents[1]/'dc_v2'
    for name in ('readonly_service.py','readonly_snapshot.py','readonly_auth.py','readonly_audit.py'):
        tree=ast.parse((root/name).read_text())
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):assert not any(x.name in ('subprocess','socket','ctypes','importlib') for x in node.names)
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):assert node.func.id not in ('exec','eval','__import__')
