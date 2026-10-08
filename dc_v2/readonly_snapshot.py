"""Owner-pinned immutable export snapshots; request processing never opens paths.

Only preclassified exportable text/metadata is ingested. A snapshot is not live
filesystem access. Trusted bootstrap file checks are defense in depth, not an OS
sandbox or protection against a compromised owner/runtime. No secret stores are
scanned and no path is resolved from an MCP argument.
"""
from __future__ import annotations
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping
from .contracts import Denied, identifier, require, sha256_hex
from .policy import relative_name, _no_links

MAX_SNAPSHOT_BYTES=8*1024*1024
MAX_RESOURCE_BYTES=1024*1024
EXPORTABLE=frozenset({'PUBLIC','MODEL_EXPORT_ALLOWED'})

def exact(obj: dict, required: set[str], optional: set[str] | None=None):
    require(type(obj) is dict and required <= set(obj) <= required | (optional or set()), 'INVALID_CONFIGURATION')

def recipients(value) -> frozenset[str]:
    require(type(value) is list and 0 < len(value) <= 128, 'INVALID_CONFIGURATION')
    result=frozenset(identifier(v) for v in value)
    require(len(result)==len(value), 'INVALID_CONFIGURATION')
    return result

def exported(obj):
    require(obj.get('classification') in EXPORTABLE, 'EXPORT_DENIED')
    return recipients(obj.get('recipients'))

def bounded_label(s: str) -> str:
    require(type(s) is str and 0 < len(s) <= 256 and not any(ord(c)<32 or ord(c)==127 or
        0x202a <= ord(c) <= 0x202e or 0x2066 <= ord(c) <= 0x2069 for c in s), 'INVALID_CONFIGURATION')
    return s

def strict_json(data: bytes):
    def unique(pairs):
        obj={}
        for k,v in pairs:
            require(k not in obj,'INVALID_REQUEST');obj[k]=v
        return obj
    def no_constant(_): raise Denied('INVALID_REQUEST')
    try:
        return json.loads(data.decode('utf-8'),object_pairs_hook=unique,parse_constant=no_constant)
    except Denied: raise
    except (ValueError,UnicodeError,RecursionError): raise Denied('INVALID_REQUEST') from None

@dataclass(frozen=True)
class FrozenResource:
    resource_id: str
    display_name: str
    kind: str
    classification: str
    recipients: frozenset[str]
    source_sha256: str
    data: bytes

@dataclass(frozen=True)
class FrozenTool:
    tool_id: str
    classification: str
    recipients: frozenset[str]
    sha256: str
    size: int

@dataclass(frozen=True)
class FrozenProject:
    project_id: str
    title: str
    classification: str
    recipients: frozenset[str]
    source_revision: str
    resources: Mapping[str,FrozenResource]
    tools: Mapping[str,FrozenTool]

@dataclass(frozen=True)
class FrozenSnapshot:
    projects: Mapping[str,FrozenProject]
    @classmethod
    def from_dict(cls, data: dict):
        exact(data,{'schema','projects'})
        require(data['schema']=='personal-dc.readonly.v2.2' and type(data['projects']) is list and
                1 <= len(data['projects']) <= 64, 'INVALID_CONFIGURATION')
        projects={};total=0
        for p in data['projects']:
            exact(p,{'project_id','title','classification','recipients','source_revision','resources','tools'})
            pid=identifier(p['project_id']);pr=exported(p)
            require(pid not in projects and type(p['resources']) is list and len(p['resources']) <= 128 and
                    type(p['tools']) is list and len(p['tools']) <= 128,'INVALID_CONFIGURATION')
            title=bounded_label(p['title']);rev=identifier(p['source_revision'])
            resources={};tools={};names=set()
            for r in p['resources']:
                exact(r,{'resource_id','display_name','kind','classification','recipients','sha256','utf8'})
                rid=identifier(r['resource_id']);rr=exported(r);relative_name(r['display_name'])
                require(r['kind'] in ('file','git-diagnostic') and type(r['utf8']) is str,'INVALID_CONFIGURATION')
                require(rid not in resources and r['display_name'].casefold() not in names,'INVALID_CONFIGURATION')
                sha256_hex(r['sha256'])
                try: raw=r['utf8'].encode('utf-8')
                except UnicodeError: raise Denied('EXPORT_DENIED') from None
                total+=len(raw)
                require(len(raw)<=MAX_RESOURCE_BYTES and total<=MAX_SNAPSHOT_BYTES,'QUOTA_EXCEEDED')
                require(hashlib.sha256(raw).hexdigest()==r['sha256'],'MANIFEST_CHANGED')
                names.add(r['display_name'].casefold())
                resources[rid]=FrozenResource(rid,r['display_name'],r['kind'],r['classification'],rr,r['sha256'],raw)
            for t in p['tools']:
                exact(t,{'tool_id','classification','recipients','sha256','size'})
                tid=identifier(t['tool_id']);tr=exported(t);sha256_hex(t['sha256'])
                require(tid not in tools and type(t['size']) is int and 0<=t['size']<=268435456,'INVALID_CONFIGURATION')
                tools[tid]=FrozenTool(tid,t['classification'],tr,t['sha256'],t['size'])
            projects[pid]=FrozenProject(pid,title,p['classification'],pr,rev,MappingProxyType(resources),MappingProxyType(tools))
        return cls(MappingProxyType(projects))

def load_snapshot(path: Path, expected_sha256: str) -> FrozenSnapshot:
    sha256_hex(expected_sha256)
    require(path.is_absolute(),'INVALID_CONFIGURATION')
    try:
        _no_links(path)
        flags=os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0)
        with os.fdopen(os.open(path,flags),'rb') as f:
            before=os.fstat(f.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=MAX_SNAPSHOT_BYTES,
                    'EXPORT_DENIED')
            data=f.read(MAX_SNAPSHOT_BYTES+1);after=os.fstat(f.fileno())
        require(len(data)<=MAX_SNAPSHOT_BYTES and
                (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'MANIFEST_CHANGED')
        require(hashlib.sha256(data).hexdigest()==expected_sha256,'MANIFEST_CHANGED')
        return FrozenSnapshot.from_dict(strict_json(data))
    except Denied: raise
    except (OSError,ValueError):raise Denied('EXPORT_DENIED') from None
