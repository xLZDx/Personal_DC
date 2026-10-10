"""Single policy-enforced read-only service over immutable approved snapshots.

This module never invokes a subprocess, opens a requested path, issues credentials,
updates the running gateway, or falls through to a legacy tool implementation.
"""
from __future__ import annotations
import hashlib
import json
import threading
from .contracts import Denied, Principal, digest, identifier, require
from .gateway import LEGACY_READ_NAMES, LEGACY_WRITE_NAMES
from .readonly_snapshot import FrozenSnapshot


def spec(operation,description,properties=None,required=None):
    return {'operation':operation,'description':description,
            'inputSchema':{'type':'object','properties':properties or {},'required':required or [],'additionalProperties':False}}
ID={'type':'string','pattern':'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'}
PAGE={'project_id':ID,'resource_id':ID,'offset':{'type':'integer','minimum':0},
      'limit':{'type':'integer','minimum':1,'maximum':4096}}
TOOL_SPECS={
    'capabilities_list':spec('capabilities.list','List only granted read-only capabilities; execution is HOLD.'),
    'projects_list':spec('project.list','List approved snapshot projects visible to this authenticated recipient.'),
    'project_describe':spec('project.describe','Describe an approved snapshot; this is not a live directory listing.',
                            {'project_id':ID},['project_id']),
    'file_read':spec('file.read','Read approved UTF-8 snapshot text by resource ID; offset/limit count Unicode code points.',
                     PAGE,['project_id','resource_id']),
    'tools_inspect':spec('tools.inspect','Inspect approved tool metadata; does not execute the binary or establish executability.',
                         {'project_id':ID,'tool_id':ID},['project_id','tool_id']),
    'git_inspect':spec('git.inspect','Read approved captured Git diagnostic text; does not run Git and is not live status.',
                       PAGE,['project_id','resource_id']),
}

class ReadOnlyService:
    def __init__(self,snapshot: FrozenSnapshot,audit,canaries: tuple[bytes,...]=()):
        require(type(snapshot) is FrozenSnapshot and type(canaries) is tuple and len(canaries)<=128 and
                all(type(c) is bytes and 8<=len(c)<=256 for c in canaries),'INVALID_CONFIGURATION')
        self.snapshot=snapshot;self.audit=audit;self.canaries=tuple(sorted(set(canaries),key=len,reverse=True))
        self._stopped=threading.Event()

    def stop(self):
        """Local read-only latch; no remote resume and NOT an OS executor kill switch."""
        self._stopped.set()

    def _scrub(self,value):
        if isinstance(value,str):
            data=value.encode('utf-8')
            for secret in self.canaries:data=data.replace(secret,b'[REDACTED]')
            return data.decode('utf-8')
        if isinstance(value,dict):return {k:self._scrub(v) for k,v in value.items()}
        if isinstance(value,list):return [self._scrub(v) for v in value]
        return value

    def event(self,action,principal,object_digest,decision):
        try:
            self.audit.record(action,principal.binding if type(principal) is Principal else '0'*64,
                              object_digest,decision)
        except Exception:raise Denied('AUDIT_UNAVAILABLE') from None

    def _project(self,pid,principal):
        identifier(pid)
        require('project:'+pid in principal.scopes,'ACCESS_DENIED')
        project=self.snapshot.projects.get(pid)
        require(project is not None and principal.recipient_id in project.recipients,'ACCESS_DENIED')
        return project

    def list_tools(self,principal):
        require(type(principal) is Principal,'AUTH_REQUIRED')
        result=[]
        for name,s in TOOL_SPECS.items():
            if s['operation'] in principal.scopes:
                result.append({'name':name,'description':s['description'],'inputSchema':s['inputSchema'],
                    'annotations':{'readOnlyHint':True,'destructiveHint':False,'idempotentHint':True,'openWorldHint':False}})
        return result

    def invoke(self,name: str,args: dict,principal: Principal):
        object_hash='0'*64
        try:
            require(not self._stopped.is_set(),'OPERATION_CANCELLED')
            require(type(principal) is Principal,'AUTH_REQUIRED')
            require(type(name) is str and len(name)<=128 and type(args) is dict,'INVALID_REQUEST')
            if name in ('task_start','task.start','execute_command','start_process'):
                raise Denied('EXECUTION_HOLD')
            if name in LEGACY_READ_NAMES | LEGACY_WRITE_NAMES:
                raise Denied('LEGACY_MIGRATION_REQUIRED')
            s=TOOL_SPECS.get(name);require(s is not None,'UNSUPPORTED_OPERATION')
            require(s['operation'] in principal.scopes,'ACCESS_DENIED')
            allowed=set(s['inputSchema']['properties']);required=set(s['inputSchema']['required'])
            require(required<=set(args)<=allowed,'INVALID_REQUEST')
            # Hash only validated argument structures. The actual parameters never reach audit.
            object_hash=digest({'tool':name,'args':args})
            for k in ('project_id','resource_id','tool_id'):
                if k in args:identifier(args[k])
            if name=='capabilities_list':
                result={'status':'OK','api_version':'2.2','profile':'loopback-readonly-dev','phase':'02',
                        'execution':'HOLD','legacy_fallback':False,'snapshot_only':True,
                        'operations':sorted(s['operation'] for s in TOOL_SPECS.values() if s['operation'] in principal.scopes)}
            elif name=='projects_list':
                result={'status':'OK','projects':[{'project_id':p.project_id,'title':p.title,'source_revision':p.source_revision}
                    for p in self.snapshot.projects.values() if 'project:'+p.project_id in principal.scopes and
                    principal.recipient_id in p.recipients]}
            else:
                p=self._project(args['project_id'],principal)
                if name=='project_describe':
                    result={'status':'OK','project_id':p.project_id,'title':p.title,'source_revision':p.source_revision,
                            'freshness':'SNAPSHOT_NOT_LIVE','resources':[{'resource_id':r.resource_id,
                            'display_name':r.display_name,'kind':r.kind} for r in p.resources.values()
                            if principal.recipient_id in r.recipients and
                            ('file.read' if r.kind=='file' else 'git.inspect') in principal.scopes],
                            'tools':[t.tool_id for t in p.tools.values() if principal.recipient_id in t.recipients
                                     and 'tools.inspect' in principal.scopes]}
                elif name=='tools_inspect':
                    t=p.tools.get(args['tool_id'])
                    require(t is not None and principal.recipient_id in t.recipients,'ACCESS_DENIED')
                    result={'status':'OK','tool_id':t.tool_id,'sha256':t.sha256,'size':t.size,
                            'executed':False,'signature_verified':False,'execution_supported':False,'freshness':'SNAPSHOT_NOT_LIVE'}
                else:
                    r=p.resources.get(args['resource_id'])
                    require(r is not None and principal.recipient_id in r.recipients and
                            r.kind==('file' if name=='file_read' else 'git-diagnostic'),'ACCESS_DENIED')
                    text=self._scrub(r.data.decode('utf-8'));offset=args.get('offset',0);limit=args.get('limit',4096)
                    require(type(offset) is int and 0<=offset<=len(text) and type(limit) is int and 1<=limit<=4096,
                            'INVALID_REQUEST')
                    content=text[offset:offset+limit];next_offset=offset+len(content)
                    result={'status':'OK','project_id':p.project_id,'resource_id':r.resource_id,
                            'content':content,'offset':offset,'next_offset':next_offset,'eof':next_offset==len(text),
                            'offset_unit':'UNICODE_CODE_POINT','total_characters':len(text),'truncated':False,
                            'source_sha256':r.source_sha256,'export_sha256':hashlib.sha256(text.encode()).hexdigest(),
                            'data_trust':'UNTRUSTED','freshness':'SNAPSHOT_NOT_LIVE','source_revision':p.source_revision}
            result=self._scrub(result)
            require(len(json.dumps(result,ensure_ascii=True,separators=(',',':')).encode())<=65536,
                    'QUOTA_EXCEEDED')
            require(not self._stopped.is_set(),'OPERATION_CANCELLED')
        except Denied as exc:result={'status':'DENIED','error_code':exc.code}
        except Exception:result={'status':'DENIED','error_code':'INTERNAL_DENIED'}
        # Never allow an audit outage to prevent setting/observing the stop latch.
        if self._stopped.is_set():return {'status':'DENIED','error_code':'OPERATION_CANCELLED'}
        try:self.event('TOOL',principal,object_hash,result.get('error_code','OK'))
        except Denied:return {'status':'DENIED','error_code':'AUDIT_UNAVAILABLE'}
        return result
