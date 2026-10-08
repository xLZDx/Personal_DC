"""Local development audit, bounded and fsynced before data is released.

Hash chaining and a retained anchor detect tested edits/truncation. This is NOT
an independently protected/remote append-only production audit service. A writer
with runtime/anchor control can forge it. Production G08 remains gated on that
separate trust boundary. No credentials, request arguments or file data enter it.
"""
from __future__ import annotations
import hashlib
import json
import os
import stat
import threading
import time
from pathlib import Path
from .contracts import Denied, canonical, digest, require, sha256_hex
from .policy import _no_links
from .readonly_snapshot import strict_json

class LocalAuditJournal:
    def __init__(self,path: Path,max_bytes: int=4*1024*1024,expected_anchor: tuple[int,str]|None=None):
        require(path.is_absolute() and path.parent.is_dir() and type(max_bytes) is int and
                1024 <= max_bytes <= 16*1024*1024,'INVALID_CONFIGURATION')
        _no_links(path.parent)
        if path.exists():_no_links(path)
        self.path=path;self.max_bytes=max_bytes;self._lock=threading.Lock()
        fd=os.open(path,os.O_APPEND|os.O_CREAT|os.O_WRONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'AUDIT_UNAVAILABLE')
        finally:os.close(fd)
        self.anchor=self.verify(expected_anchor)

    def verify(self,expected_anchor=None):
        _no_links(self.path)
        s=self.path.stat();require(s.st_size<=self.max_bytes and s.st_nlink==1,'AUDIT_INTEGRITY_ERROR')
        with self.path.open('rb') as handle:raw=handle.read(self.max_bytes+1)
        require(len(raw)<=self.max_bytes and (not raw or raw.endswith(b'\n')),'AUDIT_INTEGRITY_ERROR')
        head=(0,'0'*64)
        for line in raw.splitlines():
            row=strict_json(line)
            require(type(row) is dict and set(row)=={'event','previous','sha256'},'AUDIT_INTEGRITY_ERROR')
            e=row['event']
            require(type(e) is dict and e.get('sequence')==head[0]+1 and row['previous']==head[1],
                    'AUDIT_INTEGRITY_ERROR')
            require(row['sha256']==digest({'event':e,'previous':head[1]}),'AUDIT_INTEGRITY_ERROR')
            head=(head[0]+1,row['sha256'])
        require(expected_anchor is None or head==expected_anchor,'AUDIT_INTEGRITY_ERROR')
        return head

    def record(self,action: str,principal_binding: str,object_digest: str,decision: str):
        # These arguments are assigned by server code, never arbitrary raw input.
        require(action in {'TOOL','TRANSPORT','PROTOCOL'},'AUDIT_UNAVAILABLE')
        sha256_hex(principal_binding);sha256_hex(object_digest)
        require(type(decision) is str and 1<=len(decision)<=64 and
                all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for c in decision),'AUDIT_UNAVAILABLE')
        with self._lock:
            head=self.verify(self.anchor)
            event={'sequence':head[0]+1,'utc_seconds':int(time.time()),'action':action,
                   'principal_binding':principal_binding,'object_digest':object_digest,'decision':decision}
            checksum=digest({'event':event,'previous':head[1]})
            row=canonical({'event':event,'previous':head[1],'sha256':checksum})+b'\n'
            require(self.path.stat().st_size+len(row)<=self.max_bytes,'AUDIT_QUOTA_EXCEEDED')
            fd=os.open(self.path,os.O_APPEND|os.O_WRONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0))
            try:
                s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'AUDIT_UNAVAILABLE')
                sent=0
                while sent<len(row):
                    n=os.write(fd,row[sent:]);require(n>0,'AUDIT_UNAVAILABLE');sent+=n
                os.fsync(fd)
            finally:os.close(fd)
            self.anchor=(head[0]+1,checksum)
