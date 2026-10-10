"""Pinned opaque bearer authentication for the loopback DEVELOPMENT profile.

No token minting, environment lookup, JWT claim trust, network introspection or
OAuth authorization server. Only hashes of separately issued random credentials
are retained. This local test profile is NOT an OAuth 2.1 deployment attestation.
"""
from __future__ import annotations
import hashlib
import re
import time
from dataclasses import dataclass
from typing import Callable
from types import MappingProxyType
from .contracts import Principal, require, sha256_hex

@dataclass(frozen=True)
class BearerRecord:
    token_sha256: str
    principal: Principal
    issuer: str
    audience: str
    not_before: int
    expires_at: int
    revoked: bool = False

    def __post_init__(self):
        sha256_hex(self.token_sha256)
        require(type(self.principal) is Principal, 'INVALID_CONFIGURATION')
        require(type(self.issuer) is str and 0 < len(self.issuer) <= 512, 'INVALID_CONFIGURATION')
        require(type(self.audience) is str and 0 < len(self.audience) <= 512, 'INVALID_CONFIGURATION')
        require(type(self.not_before) is int and type(self.expires_at) is int and
                0 <= self.not_before < self.expires_at <= 2**53-1 and
                self.expires_at-self.not_before <= 3600, 'INVALID_CONFIGURATION')
        require(type(self.revoked) is bool, 'INVALID_CONFIGURATION')

class PinnedBearerVerifier:
    def __init__(self, issuer: str, audience: str, records: tuple[BearerRecord,...],
                 clock: Callable[[],int] | None=None):
        require(type(issuer) is str and bool(issuer) and type(audience) is str and bool(audience),
                'INVALID_CONFIGURATION')
        require(type(records) is tuple and 1 <= len(records) <= 128 and
                all(type(r) is BearerRecord for r in records), 'INVALID_CONFIGURATION')
        require(len({r.token_sha256 for r in records})==len(records), 'INVALID_CONFIGURATION')
        self.issuer,self.audience,self.records=issuer,audience,records
        self._records=MappingProxyType({r.token_sha256:r for r in records})
        self.clock=clock or (lambda:int(time.time()))

    def authenticate(self, credential: str) -> Principal:
        require(type(credential) is str and re.fullmatch(r'[A-Za-z0-9._~-]{32,512}',credential) is not None,
                'AUTH_REQUIRED')
        record=self._records.get(hashlib.sha256(credential.encode('ascii')).hexdigest())
        now=self.clock()
        require(record is not None and type(now) is int, 'AUTH_REQUIRED')
        require(not record.revoked and record.issuer==self.issuer and record.audience==self.audience and
                record.not_before <= now < record.expires_at, 'AUTH_REQUIRED')
        return record.principal
