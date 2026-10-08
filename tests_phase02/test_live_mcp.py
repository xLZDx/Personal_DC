"""Real loopback HTTP + official MCP SDK. Synthetic snapshots/credentials only.

No existing tunnel, host projects, credentials, settings, or service is touched.
The listener uses an OS-assigned port and is shut down and checked at test exit.
"""
from __future__ import annotations
import asyncio
import hashlib
import importlib.util
import socket
import threading
import time
from dataclasses import replace

import httpx
import pytest

from dc_v2.readonly_auth import BearerRecord,PinnedBearerVerifier
from dc_v2.readonly_audit import LocalAuditJournal
from dc_v2.readonly_snapshot import FrozenSnapshot
from dc_v2.readonly_service import ReadOnlyService
from dc_v2.readonly_mcp import ReadOnlyASGI
from tests_phase02.test_readonly import snapshot_data,P,TOKEN,OTHER,NOW,CANARY


def test_official_sdk_roundtrip_and_cross_client(tmp_path):
    pytest.importorskip('mcp');uvicorn=pytest.importorskip('uvicorn')
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    url=f'http://127.0.0.1:{port}/mcp'
    outsider=replace(P,subject='other-owner',client_id='other-client',recipient_id='other-provider')
    records=tuple(BearerRecord(hashlib.sha256(t.encode()).hexdigest(),p,'local-test',url,NOW-1,NOW+60)
                  for t,p in ((TOKEN,P),(OTHER,outsider)))
    auth=PinnedBearerVerifier('local-test',url,records,clock=lambda:NOW)
    service=ReadOnlyService(FrozenSnapshot.from_dict(snapshot_data()),LocalAuditJournal(tmp_path/'audit.jsonl'),(CANARY,))
    app=ReadOnlyASGI(service,auth,frozenset({f'127.0.0.1:{port}'}),frozenset(),native_clients=True)
    server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,access_log=False,
                         log_level='critical',proxy_headers=False,timeout_keep_alive=1,ws='none'))
    thread=threading.Thread(target=server.run,kwargs={'sockets':[sock]},daemon=True)
    thread.start()
    try:
        deadline=time.monotonic()+10
        while not server.started and thread.is_alive() and time.monotonic()<deadline:time.sleep(0.02)
        assert server.started, 'Synthetic read-only server failed to start'
        async def client(token,authorized):
            async with httpx.AsyncClient(headers={'Authorization':'Bearer '+token},timeout=10,trust_env=False) as http:
                async with streamable_http_client(url,http_client=http,terminate_on_close=False) as (read,write,_):
                    async with ClientSession(read,write) as session:
                        initialized=await session.initialize()
                        assert initialized.serverInfo.name=='Personal DC Phase02 ReadOnly'
                        tools=await session.list_tools()
                        assert len(tools.tools)==6
                        result=await session.call_tool('file_read',{'project_id':'demo','resource_id':'readme'})
                        assert result.isError is not authorized
                        if authorized:
                            assert result.structuredContent['content'].startswith('hello world')
                            assert CANARY.decode() not in str(result)
                            for _ in range(3):
                                assert (await session.call_tool('capabilities_list',{})).structuredContent['execution']=='HOLD'
                        else:
                            assert result.structuredContent['status']=='DENIED'
                        try:
                            invalid=await session.call_tool('task_start',{})
                            assert invalid.isError and invalid.structuredContent['error_code']=='EXECUTION_HOLD'
                        finally:await session.send_ping()
        async def all_clients():
            await asyncio.gather(*(client(TOKEN,True) for _ in range(4)),client(OTHER,False))
        asyncio.run(asyncio.wait_for(all_clients(),timeout=25))
    finally:
        server.should_exit=True;thread.join(timeout=8)
        sock.close()
    assert not thread.is_alive(), 'Test listener did not stop'
    with socket.socket() as check:
        check.settimeout(0.5);assert check.connect_ex(('127.0.0.1',port))!=0
    audit=(tmp_path/'audit.jsonl').read_text()
    assert TOKEN not in audit and OTHER not in audit and CANARY.decode() not in audit
    assert service.audit.verify(service.audit.anchor)[0]>20
