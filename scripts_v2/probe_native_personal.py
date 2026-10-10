"""Real local native MCP roundtrip; isolated synthetic files only."""
import asyncio, json, os, secrets
from pathlib import Path
import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

SECRET=os.environ["PDC_V2_BACKEND_KEY"]
URL="http://127.0.0.1:18766/mcp"
BASE=Path(r"D:\Temp\Personal_DC_v2_2_isolated\native-smoke")
BASE.mkdir(parents=True,exist_ok=True)
PATH=BASE/("native-"+secrets.token_hex(6)+".txt")

async def main():
    async with httpx.AsyncClient(trust_env=False,timeout=20,headers={"X-PDC-V2-Demo-Auth":SECRET}) as h:
        async with streamable_http_client(URL,http_client=h,terminate_on_close=False) as (r,w,_):
            async with ClientSession(r,w) as session:
                init=await session.initialize()
                tools={t.name for t in (await session.list_tools()).tools}
                needed={"health","list_projects","read_text_file","write_text_file",
                        "replace_text","project_git_status","run_project_tests"}
                assert needed<=tools,(needed-tools)
                async def invoke(name,**args):
                    x=await session.call_tool(name,args)
                    assert not x.isError,(name,str(x)[:400])
                    return x.structuredContent
                health=await invoke("health")
                assert health.get("ok")
                w=await invoke("write_text_file",path=str(PATH),content="alpha\n",overwrite=False)
                assert w.get("ok")
                data=await invoke("read_text_file",path=str(PATH))
                assert data.get("content")=="alpha\n"
                edited=await invoke("replace_text",path=str(PATH),old="alpha",new="beta")
                assert edited.get("replacements")==1
                data2=await invoke("read_text_file",path=str(PATH))
                assert data2.get("content")=="beta\n"
                git=await invoke("project_git_status",project="D:\\Temp\\Personal_DC_v2_2_full_20261008")
                assert git.get("exit_code")==0,git
                return {"status":"PASS","tool_count":len(tools),"created_synthetic_file":str(PATH),
                        "file_write":True,"file_read":True,"file_edit":True,"git_status":True,
                        "local_only":True,"docker_used":False}
if __name__=="__main__":
    try:
        result=asyncio.run(main())
    except Exception as e:
        result={"status":"FAIL","error_type":type(e).__name__,
                "detail":str(e)[:300],"created_synthetic_file":str(PATH)}
    dest=BASE/"latest_result.json";dest.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print("NATIVE_MCP_"+result["status"])
    print(json.dumps({k:v for k,v in result.items() if k not in ("detail",)},ensure_ascii=True))
    raise SystemExit(0 if result["status"]=="PASS" else 1)
