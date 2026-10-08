from __future__ import annotations
import asyncio
import hashlib
import json
import time
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from dc_v2.contracts import Denied, Principal
from dc_v2.readonly_auth import BearerRecord, PinnedBearerVerifier
from dc_v2.readonly_audit import LocalAuditJournal
from dc_v2.readonly_snapshot import FrozenSnapshot, load_snapshot
from dc_v2.readonly_service import ReadOnlyService, TOOL_SPECS
from dc_v2.readonly_mcp import ReadOnlyASGI

TOKEN = 'synthetic-test-credential-' + 'A' * 48
OTHER = 'synthetic-test-credential-' + 'B' * 48
NOW = 2000000000
OPS = frozenset({'capabilities.list','project.list','project.describe','file.read','tools.inspect','git.inspect','project:demo'})
P = Principal('owner','test-client','test-provider', OPS)
CANARY = b'SYNTHETIC_CANARY_NOT_A_REAL_SECRET'

def snapshot_data():
    text = 'hello world\n' + CANARY.decode() + '\nПривет 🛠\n'
    record = dict(resource_id='readme',display_name='README.md',kind='file',
                  classification='MODEL_EXPORT_ALLOWED',recipients=['test-provider'],
                  sha256=hashlib.sha256(text.encode()).hexdigest(),utf8=text)
    diag = dict(record,resource_id='git-state',display_name='reports/status.txt',kind='git-diagnostic',
                utf8='clean\n',sha256=hashlib.sha256(b'clean\n').hexdigest())
    return {'schema':'personal-dc.readonly.v2.2','projects':[{
        'project_id':'demo','title':'Synthetic project','classification':'MODEL_EXPORT_ALLOWED',
        'recipients':['test-provider'],'source_revision':'a'*40,'resources':[record,diag],
        'tools':[{'tool_id':'python','classification':'MODEL_EXPORT_ALLOWED','recipients':['test-provider'],
                  'sha256':'b'*64,'size':4096}]}]}

def verifier(p=P, **changes):
    fields=dict(token_sha256=hashlib.sha256(TOKEN.encode()).hexdigest(), principal=p,
                issuer='local-test',audience='http://127.0.0.1:18766/mcp',not_before=NOW-1,
                expires_at=NOW+600,revoked=False)
    fields.update(changes)
    return PinnedBearerVerifier('local-test','http://127.0.0.1:18766/mcp',(BearerRecord(**fields),),clock=lambda:NOW)

@pytest.fixture
def service(tmp_path):
    return ReadOnlyService(FrozenSnapshot.from_dict(snapshot_data()),LocalAuditJournal(tmp_path/'audit.jsonl'),(CANARY,))

def app_for(service, auth=None, **kwargs):
    return ReadOnlyASGI(service,auth or verifier(),frozenset({'127.0.0.1:18766'}),
                       frozenset({'https://trusted.example'}),native_clients=True,**kwargs)

def run_http(app, body=None, method='POST',headers=None, path='/mcp', raw=None, client=('127.0.0.1',1234)):
    async def run():
        h={'Authorization':'Bearer '+TOKEN,'Accept':'application/json, text/event-stream',
           'Content-Type':'application/json','MCP-Protocol-Version':'2025-11-25'}
        if headers:
            for k,v in headers.items():
                if v is None: h.pop(k,None)
                else: h[k]=v
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=client),
                                    base_url='http://127.0.0.1:18766') as c:
            data=raw if raw is not None else json.dumps(body or {'jsonrpc':'2.0','id':1,'method':'ping'})
            return await c.request(method,path,headers=h,content=data if method=='POST' else None)
    return asyncio.run(run())

def rpc_call(name, args=None):
    return {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':name,'arguments':args or {}}}

def test_token_valid_reusable():
    v=verifier()
    assert v.authenticate(TOKEN)==v.authenticate(TOKEN)==P

@pytest.mark.parametrize('token',['',OTHER,'Bearer '+TOKEN,'x'*9000,'\n'+TOKEN,None])
def test_bad_tokens(token):
    with pytest.raises(Denied): verifier().authenticate(token)

@pytest.mark.parametrize('changes',[{'expires_at':NOW},{'not_before':NOW+1},{'revoked':True},
                                     {'issuer':'wrong'},{'audience':'http://localhost:18766/mcp'}])
def test_invalid_token_binding(changes):
    with pytest.raises(Denied): verifier(**changes).authenticate(TOKEN)

def test_duplicate_token_registration():
    v=verifier(); record=v.records[0]
    with pytest.raises(Denied): PinnedBearerVerifier('local-test',v.audience,(record,record))

@pytest.mark.parametrize('field,value',[('expires_at',True),('not_before',1.1),('revoked',1),('token_sha256','x')])
def test_invalid_auth_config(field,value):
    with pytest.raises(Denied): verifier(**{field:value})

@pytest.mark.parametrize('classification',['SECRET','LOCAL_ONLY','UNKNOWN',None])
def test_snapshot_rejects_forbidden_data(classification):
    s=snapshot_data();s['projects'][0]['resources'][0]['classification']=classification
    with pytest.raises(Denied): FrozenSnapshot.from_dict(s)

@pytest.mark.parametrize('name',['../README.md','.env','.npmrc','.git/config','a:secret','\\\\host\\share','a/../b',
                                'CON.txt','a~/b','a.','/abs','a\\b','x/private.key','a\x00b'])
def test_snapshot_rejects_path_keys(name):
    s=snapshot_data();s['projects'][0]['resources'][0]['display_name']=name
    with pytest.raises(Denied): FrozenSnapshot.from_dict(s)

def test_snapshot_digest_required():
    s=snapshot_data();s['projects'][0]['resources'][0]['sha256']='0'*64
    with pytest.raises(Denied): FrozenSnapshot.from_dict(s)

def test_snapshot_is_immutable(service):
    with pytest.raises(TypeError): service.snapshot.projects['x']='y'
    project=service.snapshot.projects['demo']
    with pytest.raises(TypeError): project.resources['x']='y'
    with pytest.raises(Exception): project.title='changed'

def test_snapshot_has_no_dependency_on_mutable_input():
    s=snapshot_data();snap=FrozenSnapshot.from_dict(s);s['projects'][0]['resources'][0]['utf8']='changed'
    assert snap.projects['demo'].resources['readme'].data.startswith(b'hello')

@pytest.mark.parametrize('where',['top','project','resource','tool'])
def test_unknown_snapshot_fields_rejected(where):
    s=snapshot_data();node={'top':s,'project':s['projects'][0],
                          'resource':s['projects'][0]['resources'][0],'tool':s['projects'][0]['tools'][0]}[where]
    node['approved']=True
    with pytest.raises(Denied): FrozenSnapshot.from_dict(s)

def test_duplicate_snapshot_objects_rejected():
    for field in ['resources','tools']:
        s=snapshot_data(); s['projects'][0][field].append(dict(s['projects'][0][field][0]))
        with pytest.raises(Denied): FrozenSnapshot.from_dict(s)

def test_load_snapshot_pinned(tmp_path):
    p=tmp_path/'snapshot.json';data=json.dumps(snapshot_data()).encode();p.write_bytes(data)
    assert load_snapshot(p,hashlib.sha256(data).hexdigest()).projects['demo'].title=='Synthetic project'
    with pytest.raises(Denied):load_snapshot(p,'0'*64)

def test_duplicate_json_key_refused(tmp_path):
    p=tmp_path/'snapshot.json';data=b'{"schema":"x","schema":"y","projects":[]}'
    p.write_bytes(data)
    with pytest.raises(Denied):load_snapshot(p,hashlib.sha256(data).hexdigest())

def test_file_read_masks_canary_and_reports_hashes(service):
    result=service.invoke('file_read',{'project_id':'demo','resource_id':'readme'},P)
    assert result['status']=='OK' and CANARY.decode() not in json.dumps(result)
    assert '[REDACTED]' in result['content'] and result['data_trust']=='UNTRUSTED'
    assert result['source_sha256']!=result['export_sha256']
    assert result['eof'] and not result['truncated']

def test_utf8_pagination_lossless(service):
    parts=[];offset=0
    while True:
        r=service.invoke('file_read',{'project_id':'demo','resource_id':'readme','offset':offset,'limit':1},P)
        assert r['status']=='OK';parts.append(r['content']);offset=r['next_offset']
        if r['eof']:break
    assert ''.join(parts)==service.invoke('file_read',{'project_id':'demo','resource_id':'readme'},P)['content']
    assert 'Привет 🛠' in ''.join(parts)

@pytest.mark.parametrize('args',[{'path':'C:/secret'},{'project_id':'demo','resource_id':'readme','approved':True},
    {'project_id':'demo','resource_id':'readme','offset':True},
    {'project_id':'demo','resource_id':'readme','limit':0},
    {'project_id':'demo','resource_id':'readme','limit':100000},
    {'project_id':'demo','resource_id':'readme','offset':99999999}])
def test_invalid_tool_args(service,args):
    assert service.invoke('file_read',args,P)['status']=='DENIED'

@pytest.mark.parametrize('principal',[replace(P,scopes=frozenset({'file.read'})),
                                      replace(P,scopes=frozenset({'project:demo'})),
                                      replace(P,recipient_id='different-provider')])
def test_cross_principal_denied(service,principal):
    assert service.invoke('file_read',{'project_id':'demo','resource_id':'readme'},principal)['status']=='DENIED'

def test_hidden_and_absent_project_indistinguishable(service):
    p=replace(P,scopes=frozenset({'file.read'}))
    assert service.invoke('file_read',{'project_id':'demo','resource_id':'readme'},p)==service.invoke(
        'file_read',{'project_id':'unknown','resource_id':'unknown'},p)

def test_metadata_filters_recipients(service):
    p=replace(P,recipient_id='different-provider')
    assert service.invoke('projects_list',{},p)['projects']==[]
    assert service.invoke('project_describe',{'project_id':'demo'},p)['status']=='DENIED'

@pytest.mark.parametrize('tool',['task_start','execute_command','start_process','run_project_tests','git_push',
                               'read_text_file','recent_audit_log','write_text_file','approval_approve','task.start'])
def test_no_legacy_or_execution_fallback(service,tool):
    r=service.invoke(tool,{},P)
    assert r['status']=='DENIED'

def test_inspect_metadata_only(service,monkeypatch):
    import subprocess
    def forbidden(*a,**k):raise AssertionError('Process execution forbidden')
    monkeypatch.setattr(subprocess,'Popen',forbidden)
    r=service.invoke('tools_inspect',{'project_id':'demo','tool_id':'python'},P)
    assert r['status']=='OK' and r['executed'] is False and r['execution_supported'] is False
    assert 'path' not in r

def test_git_is_explicitly_snapshot_only(service):
    r=service.invoke('git_inspect',{'project_id':'demo','resource_id':'git-state'},P)
    assert r['status']=='OK' and r['freshness']=='SNAPSHOT_NOT_LIVE'
    assert service.invoke('git_inspect',{'project_id':'demo','resource_id':'readme'},P)['status']=='DENIED'
    assert service.invoke('file_read',{'project_id':'demo','resource_id':'git-state'},P)['status']=='DENIED'

def test_audit_fail_closed(service):
    class Broken:
        def record(self,*a,**kw):raise OSError('secret error must not leave host')
    service.audit=Broken()
    r=service.invoke('file_read',{'project_id':'demo','resource_id':'readme'},P)
    assert r=={'status':'DENIED','error_code':'AUDIT_UNAVAILABLE'}

def test_audit_content_minimized(service,tmp_path):
    args={'project_id':'demo','resource_id':'readme'}
    service.invoke('file_read',args,P)
    data=(tmp_path/'audit.jsonl').read_text()
    assert CANARY.decode() not in data and 'hello world' not in data and TOKEN not in data
    assert 'test-provider' not in data and 'README' not in data
    head=service.audit.anchor
    assert head[0]==1 and service.audit.verify(head)==head

@pytest.mark.parametrize('tamper',['truncate','modify','append','reorder'])
def test_audit_tamper_fail_closed(service,tmp_path,tamper):
    service.invoke('capabilities_list',{},P);service.invoke('projects_list',{},P)
    p=tmp_path/'audit.jsonl';data=p.read_bytes();lines=data.splitlines(keepends=True)
    changed={'truncate':b''.join(lines[:-1]),'modify':data.replace(b'OK',b'NO',1),
             'append':data+b'{}\n','reorder':b''.join(reversed(lines))}[tamper]
    p.write_bytes(changed)
    assert service.invoke('capabilities_list',{},P)=={'status':'DENIED','error_code':'AUDIT_UNAVAILABLE'}

def test_stop_does_not_need_audit(service):
    service.stop();assert service.invoke('file_read',{'project_id':'demo','resource_id':'readme'},P)['error_code']=='OPERATION_CANCELLED'

def test_http_initialize_and_mcp_call(service):
    app=app_for(service)
    r=run_http(app,{'jsonrpc':'2.0','id':1,'method':'initialize','params':{
        'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'pytest','version':'1'}}})
    assert r.status_code==200 and r.json()['result']['protocolVersion']=='2025-11-25'
    r=run_http(app,rpc_call('file_read',{'project_id':'demo','resource_id':'readme'}))
    result=r.json()['result']; assert result['isError'] is False
    assert result['structuredContent']['status']=='OK' and CANARY.decode() not in r.text

@pytest.mark.parametrize('headers,code',[
    ({'Authorization':None},401),({'Authorization':'Bearer '+OTHER},401),
    ({'Host':'evil.example'},403),({'Origin':'https://evil.example'},403),
    ({'Origin':'null'},403),({'X-Forwarded-For':'127.0.0.1'},403),
    ({'Forwarded':'for=127.0.0.1'},403),({'X-Auth-User':'admin'},403),
    ({'MCP-Protocol-Version':'2099-01-01'},400),({'Content-Type':'text/plain'},415),
    ({'Accept':'text/html'},406),({'Content-Encoding':'gzip'},415),
])
def test_http_guards(service,headers,code):
    assert run_http(app_for(service),headers=headers).status_code==code

def test_http_native_and_trusted_origin(service):
    assert run_http(app_for(service)).status_code==200
    assert run_http(app_for(service),headers={'Origin':'https://trusted.example'}).status_code==200

def test_non_loopback_peer_denied(service):
    assert run_http(app_for(service),client=('192.0.2.5',1234)).status_code==403

@pytest.mark.parametrize('path',['/mcp?token=abc','/other','/mcp/'])
def test_no_query_or_other_path(service,path):
    assert run_http(app_for(service),path=path).status_code in (400,404)

@pytest.mark.parametrize('method',['GET','DELETE','OPTIONS','PUT'])
def test_no_stream_or_mutation_http(service,method):
    assert run_http(app_for(service),method=method).status_code==405

@pytest.mark.parametrize('raw',[
    b'[]',b'{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}',
    b'{"jsonrpc":"2.0","id":true,"method":"ping"}',
    b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"approved":true}}',
    b'{"jsonrpc":"2.0","id":1,"method":"ping","extra":"bad"}',
    b'{"jsonrpc":"2.0","id":1,"method":"ping","params":NaN}',
])
def test_strict_rpc(service,raw):
    r=run_http(app_for(service),raw=raw)
    assert r.status_code==400 or 'error' in r.json()

def test_request_size_bound(service):
    assert run_http(app_for(service),raw=b' '*40000).status_code==413

def test_rejected_argument_not_echoed(service):
    r=run_http(app_for(service),rpc_call('file_read',{'approved':True,'token':TOKEN}))
    assert TOKEN not in r.text and r.json()['result']['isError']

def test_tools_list_no_write_tools(service):
    r=run_http(app_for(service),{'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}})
    tools=r.json()['result']['tools'];assert len(tools)==6
    assert {t['name'] for t in tools}==set(TOOL_SPECS)
    assert all(t['annotations']['readOnlyHint'] for t in tools)

def test_tools_list_filtered(service):
    p=replace(P,scopes=frozenset({'file.read','project:demo'}))
    r=run_http(app_for(service,auth=verifier(p)),{'jsonrpc':'2.0','id':1,'method':'tools/list'})
    assert [t['name'] for t in r.json()['result']['tools']]==['file_read']

def test_known_bearer_repeated_http_allowed(service):
    app=app_for(service)
    assert run_http(app).status_code==run_http(app).status_code==200

def test_rate_limit(service):
    app=app_for(service,requests_per_minute=2)
    assert run_http(app).status_code==200
    assert run_http(app).status_code==200
    assert run_http(app).status_code==429

def test_auth_errors_are_audited_without_token(service,tmp_path):
    assert run_http(app_for(service),headers={'Authorization':'Bearer '+OTHER}).status_code==401
    text=(tmp_path/'audit.jsonl').read_text(); assert 'AUTH_REQUIRED' in text and OTHER not in text

def test_notifications_initialized(service):
    r=run_http(app_for(service),{'jsonrpc':'2.0','method':'notifications/initialized'})
    assert r.status_code==202 and not r.content
