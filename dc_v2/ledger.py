"""Transactional approval reservations and audit outbox; no execution side effects.

This is a broker-owned storage component, not an MCP API. Deployment must protect
its database, trusted verifier and clock. SQLite alone is not append-only audit.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import time
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Callable, Protocol

from .contracts import Denied, Manifest, Principal, canonical, digest, identifier, require


class Verifier(Protocol):
    def verify(self, key_id: str, message: bytes, signature: bytes) -> bool: ...


class RejectAll:
    def verify(self, key_id: str, message: bytes, signature: bytes) -> bool:
        return False


class Ed25519Verifier:
    """Pinned PUBLIC keys only. Missing crypto dependency fails closed.

A valid signature here is not evidence of WebAuthn UV or a trusted display.
Production Approval Agent enrollment/ceremony is deliberately not supplied.
"""
    def __init__(self, public_keys: dict[str, bytes]):
        self.public_keys = dict(public_keys)
        for key, value in self.public_keys.items():
            identifier(key)
            require(type(value) is bytes and len(value) == 32, "INVALID_CONFIGURATION")

    def verify(self, key_id: str, message: bytes, signature: bytes) -> bool:
        key = self.public_keys.get(key_id)
        if key is None or type(signature) is not bytes or len(signature) != 64:
            return False
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
            return True
        except Exception:
            return False


class Ledger:
    def __init__(self, path: Path, verifier: Verifier | None = None, clock: Callable[[], int] | None = None):
        require(path.is_absolute(), "INVALID_CONFIGURATION")
        self.path = path
        self.verifier = verifier or RejectAll()
        self.clock = clock or (lambda: int(time.time()))
        # Parent creation and ACL provisioning belong to the trusted installer.
        with closing(self._connect()) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL);
                INSERT OR IGNORE INTO settings VALUES('stop','0');
                CREATE TABLE IF NOT EXISTS challenges(
                  id TEXT PRIMARY KEY, binding TEXT NOT NULL, manifest TEXT NOT NULL,
                  nonce TEXT NOT NULL UNIQUE, expires INTEGER NOT NULL, state TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS operations(
                  id TEXT PRIMARY KEY, binding TEXT NOT NULL, idem TEXT NOT NULL,
                  manifest TEXT NOT NULL, challenge TEXT NOT NULL UNIQUE,
                  state TEXT NOT NULL, UNIQUE(binding,idem));
                CREATE TABLE IF NOT EXISTS outbox(
                  seq INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL,
                  prev TEXT NOT NULL, hash TEXT NOT NULL);
            """)

    def _connect(self):
        con = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA busy_timeout=5000")
        con.execute("PRAGMA synchronous=FULL")
        return con

    @contextmanager
    def _tx(self):
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def _active(self, con):
        require(con.execute("SELECT v FROM settings WHERE k='stop'").fetchone()[0] == '0', "OPERATION_CANCELLED")

    def _event(self, con, kind: str, object_id: str, binding: str, manifest: str):
        previous = con.execute("SELECT seq,hash FROM outbox ORDER BY seq DESC LIMIT 1").fetchone()
        prev = previous['hash'] if previous else "0" * 64
        seq = previous['seq'] + 1 if previous else 1
        event = {"seq": seq, "kind": kind, "object_id": object_id, "principal_binding": binding,
                 "manifest_digest": manifest, "timestamp": self.clock()}
        checksum = digest({"prev": prev, "event": event})
        con.execute("INSERT INTO outbox(seq,body,prev,hash) VALUES(?,?,?,?)",
                    (seq, canonical(event).decode(), prev, checksum))

    def propose(self, manifest: Manifest, principal: Principal, ttl: int = 120) -> dict:
        require(manifest.principal_binding == principal.binding and manifest.recipient_id == principal.recipient_id, "ACCESS_DENIED")
        require(type(ttl) is int and 1 <= ttl <= 300, "INVALID_REQUEST")
        now = self.clock()
        with self._tx() as con:
            self._active(con)
            count = con.execute("SELECT COUNT(*) FROM challenges WHERE binding=? AND expires>? AND state IN ('PENDING','APPROVED')",
                                (principal.binding, now)).fetchone()[0]
            require(count < 32, "QUOTA_EXCEEDED")
            key, nonce, expires = secrets.token_hex(16), secrets.token_hex(32), now + ttl
            con.execute("INSERT INTO challenges VALUES(?,?,?,?,?,?)",
                        (key, principal.binding, manifest.digest, nonce, expires, "PENDING"))
            self._event(con, "PROPOSED", key, principal.binding, manifest.digest)
            return {"challenge_id": key, "nonce": nonce, "expires_at": expires,
                    "manifest_digest": manifest.digest, "status": "APPROVAL_REQUIRED"}

    @staticmethod
    def _message(row) -> bytes:
        return canonical({"domain": "personal-dc.boundary-approval.v2.2", "challenge_id": row["id"],
                          "nonce": row["nonce"], "expires_at": row["expires"],
                          "principal_binding": row["binding"], "manifest_digest": row["manifest"]})

    def approval_message(self, challenge_id: str) -> bytes:
        """Trusted approval-service interface, not exported to MCP tools."""
        identifier(challenge_id)
        with closing(self._connect()) as con:
            row = con.execute("SELECT * FROM challenges WHERE id=?", (challenge_id,)).fetchone()
        require(row is not None, "ACCESS_DENIED")
        return self._message(row)

    def receive_approval(self, challenge_id: str, key_id: str, signature: bytes) -> None:
        """Called only by independently authenticated Approval Agent, not frontend."""
        identifier(challenge_id)
        identifier(key_id)
        with self._tx() as con:
            self._active(con)
            row = con.execute("SELECT * FROM challenges WHERE id=?", (challenge_id,)).fetchone()
            require(row is not None and row['state'] == 'PENDING', "APPROVAL_INVALID")
            require(self.clock() < row['expires'], "APPROVAL_EXPIRED")
            try:
                verified = self.verifier.verify(key_id, self._message(row), signature)
            except Exception:
                verified = False
            require(verified is True, "APPROVAL_INVALID")
            con.execute("UPDATE challenges SET state='APPROVED' WHERE id=?", (challenge_id,))
            self._event(con, "APPROVED", challenge_id, row['binding'], row['manifest'])

    def reserve(self, challenge_id: str, manifest: Manifest, principal: Principal, idempotency_key: str) -> dict:
        """Atomic approval consumption + durable reservation + audit outbox.

        Reservation is NOT an execution. Recovery must not replay external effects.
        """
        identifier(challenge_id)
        identifier(idempotency_key)
        require(manifest.principal_binding == principal.binding, "ACCESS_DENIED")
        with self._tx() as con:
            self._active(con)
            existing = con.execute("SELECT * FROM operations WHERE binding=? AND idem=?",
                                   (principal.binding, idempotency_key)).fetchone()
            if existing:
                require(existing['manifest'] == manifest.digest and existing['challenge'] == challenge_id,
                        "IDEMPOTENCY_CONFLICT")
                return {"operation_id": existing['id'], "status": existing['state'], "created": False}
            row = con.execute("SELECT * FROM challenges WHERE id=?", (challenge_id,)).fetchone()
            require(row is not None and row['binding'] == principal.binding, "ACCESS_DENIED")
            require(row['manifest'] == manifest.digest, "MANIFEST_CHANGED")
            require(self.clock() < row['expires'], "APPROVAL_EXPIRED")
            require(row['state'] == 'APPROVED', "APPROVAL_REQUIRED")
            operation = secrets.token_hex(16)
            con.execute("UPDATE challenges SET state='CONSUMED' WHERE id=?", (challenge_id,))
            con.execute("INSERT INTO operations VALUES(?,?,?,?,?,?)",
                        (operation, principal.binding, idempotency_key, manifest.digest, challenge_id, "RESERVED"))
            self._event(con, "RESERVED", operation, principal.binding, manifest.digest)
            return {"operation_id": operation, "status": "RESERVED", "created": True}

    def status(self, operation_id: str, principal: Principal) -> dict:
        identifier(operation_id)
        with closing(self._connect()) as con:
            row = con.execute("SELECT id,state FROM operations WHERE id=? AND binding=?",
                              (operation_id, principal.binding)).fetchone()
        require(row is not None, "ACCESS_DENIED")
        return {"operation_id": row['id'], "status": row['state']}

    def stop_latch(self) -> None:
        """State-only latch; NOT the independent OS-level emergency controller."""
        with self._tx() as con:
            con.execute("UPDATE settings SET v='1' WHERE k='stop'")
        # No audit dependency: a separate controller must stop actual computation.

    def verify_outbox(self, expected_head: tuple[int, str] | None = None) -> tuple[int, str]:
        prev, seq = "0" * 64, 0
        with closing(self._connect()) as con:
            for row in con.execute("SELECT * FROM outbox ORDER BY seq"):
                event = json.loads(row['body'])
                require(row['seq'] == seq + 1 and event['seq'] == seq + 1 and row['prev'] == prev,
                        "AUDIT_INTEGRITY_ERROR")
                require(row['hash'] == digest({"prev": prev, "event": event}), "AUDIT_INTEGRITY_ERROR")
                seq, prev = row['seq'], row['hash']
        head = (seq, prev)
        require(expected_head is None or head == expected_head, "AUDIT_INTEGRITY_ERROR")
        return head
