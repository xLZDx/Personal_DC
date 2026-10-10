"""Snapshot ingestion policy, synthetic fixtures only."""
from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from dc_v2.contracts import Denied
from dc_v2.execution import WorkspacePool
from dc_v2.phase03_import import ImportResource, SnapshotImporter
from dc_v2.policy import Classification


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


@pytest.fixture
def importer(tmp_path):
    source, target = tmp_path/"source", tmp_path/"pool"
    source.mkdir()
    target.mkdir()
    pool = WorkspacePool(target, (source,))
    return source, target, SnapshotImporter(source, pool, ()), pool


def entry(name="safe.txt", content=b"hello", classification=Classification.PUBLIC,
          recipients=frozenset(("recipient",))):
    return ImportResource("resource", name, sha(content), classification, recipients)


def test_import_valid_snapshot(importer):
    source, target, service, pool = importer
    (source/"safe.txt").write_bytes(b"hello")
    ws, registry = service.import_approved((entry(),), "recipient")
    assert registry == {"resource": "safe.txt"}
    assert pool.read(ws.workspace_id, "safe.txt") == b"hello"


@pytest.mark.parametrize("classification", [Classification.SECRET, Classification.LOCAL_ONLY])
def test_confidential_input_is_denied_before_workspace_creation(importer, classification):
    source, target, service, pool = importer
    (source/"safe.txt").write_bytes(b"hello")
    with pytest.raises(Denied, match="EXPORT_DENIED"):
        service.import_approved((entry(classification=classification),), "recipient")
    assert list(target.iterdir()) == []


def test_other_recipient_denied(importer):
    source, target, service, pool = importer
    (source/"safe.txt").write_bytes(b"hello")
    with pytest.raises(Denied, match="EXPORT_DENIED"):
        service.import_approved((entry(),), "another")
    assert list(target.iterdir()) == []


def test_changed_source_denied(importer):
    source, target, service, pool = importer
    (source/"safe.txt").write_bytes(b"mutated")
    with pytest.raises(Denied, match="MANIFEST_CHANGED"):
        service.import_approved((entry(),), "recipient")
    assert list(target.iterdir()) == []


@pytest.mark.parametrize("path", ("../secret.txt", ".git/config", "C:/Windows/win.ini", "a:stream"))
def test_invalid_path_is_denied(importer, path):
    with pytest.raises(Denied):
        entry(name=path)


def test_duplicate_resource_id_denied(importer):
    source, target, service, pool = importer
    (source/"safe.txt").write_bytes(b"hello")
    with pytest.raises(Denied, match="INVALID_REQUEST"):
        service.import_approved((entry(), entry()), "recipient")
    assert list(target.iterdir()) == []


def test_symlink_source_fails_closed(importer):
    source, target, service, pool = importer
    outside = source.parent/"outside.txt"
    outside.write_bytes(b"hello")
    try:
        (source/"safe.txt").symlink_to(outside)
    except OSError:
        pytest.skip("Windows symlink privilege not enabled")
    with pytest.raises(Denied):
        service.import_approved((entry(),), "recipient")
    assert list(target.iterdir()) == []
