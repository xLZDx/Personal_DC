"""Real offline Node/npm/git capability probe, not a production tool registry."""
import json
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dc_v2.contracts import Manifest, Principal
from dc_v2.execution import DockerExecutor, WorkspacePool
from dc_v2.policy import TaskGrant

ROOT=Path(r"D:\Temp\Personal_DC_v2_2_isolated")
WORK=ROOT/("phase03-node-"+secrets.token_hex(6))
WORK.mkdir()
(WORK/"work").mkdir()
(WORK/"control").mkdir()
IMAGE="sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8"
POOL=WorkspacePool(WORK/"work",(Path(r"D:\Repo\Personal_DC"),WORK/"control"))
RUNNER=DockerExecutor(Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"),
 IMAGE, POOL, WORK/"control","npipe:////./pipe/dockerDesktopLinuxEngine")
PRINCIPAL=Principal("owner","node-probe","probe-recipient",frozenset(("task.start","task.status","task.output","task.cancel","task.list","project:phase03-probe")))
EVIDENCE=Path(__file__).resolve().parents[1]/"evidence"/"phase03"/"toolchains.json"
REPORT={"status":"RUNNING","image_id":IMAGE,"checks":{},"workspace":str(WORK)}
def execute(name,files,args):
    ws=POOL.create(files)
    manifest=Manifest(PRINCIPAL.binding,"phase03-probe","task.start",ws.snapshot_digest,
      IMAGE[7:],RUNNER.policy_digest,ws.workspace_id,PRINCIPAL.recipient_id,
      tuple(args),(),("sandbox-exec",),40,8192)
    grant=TaskGrant(PRINCIPAL.binding,"phase03-probe",ws.snapshot_digest,IMAGE[7:],
      RUNNER.policy_digest,ws.workspace_id,PRINCIPAL.recipient_id,
      frozenset(("task.start",)),frozenset(("sandbox-exec",)),
      int(time.time())+90,40,8192)
    launched=RUNNER.start(manifest,grant,PRINCIPAL,ws.workspace_id)
    for _ in range(60):
        status=RUNNER.status(launched["task_id"],PRINCIPAL)
        if status["status"]=="EXITED":
            break
        time.sleep(.5)
    out=RUNNER.output(launched["task_id"],PRINCIPAL)
    ok=status.get("exit_code")==0
    REPORT["checks"][name]={"pass":ok,"exit_code":status.get("exit_code"),
      "output":out["data"][:250],
      "diff_present":bool(POOL.diff(ws.workspace_id))}
    EVIDENCE.write_text(json.dumps(REPORT,indent=2),encoding="utf-8")
    print(name,"PASS" if ok else "FAIL",out["data"][:90],flush=True)
    return ok
try:
    RUNNER.check()
    execute("node",{"app.js":b"const fs=require('fs');fs.writeFileSync('artifact.txt','node');console.log('NODE_OK');\n"},
            ("node","app.js"))
    execute("npm-build",{
     "package.json":b'{"private":true,"scripts":{"build":"node build.js"}}',
     "build.js":b"require('fs').writeFileSync('dist.txt','offline');console.log('NPM_BUILD_OK');"},
     ("npm","run","build","--offline"))
    execute("git-cli",{},("git","--version"))
    execute("no-inherited-secrets",{},("node","-e","if(process.env.GH_TOKEN||process.env.AWS_SECRET_ACCESS_KEY)process.exit(3); console.log('ENV_CLEAN')"))
    execute("network-is-disabled",{},("node","-e",
      "const fs=require('fs');let text=fs.readFileSync('/proc/net/route','utf8');if(text.trim().split('\\n').length>1)process.exit(4); console.log('NO_ROUTE')"))
    RUNNER.emergency_stop()
    REPORT["status"]="PASS" if all(x["pass"] for x in REPORT["checks"].values()) else "FAIL"
except Exception as error:
    REPORT["status"]="FAIL"
    REPORT["error_type"]=type(error).__name__
    REPORT["error"]=str(error)[:150]
finally:
    EVIDENCE.write_text(json.dumps(REPORT,indent=2),encoding="utf-8")
print("FINAL",REPORT["status"],flush=True)
sys.exit(0 if REPORT["status"]=="PASS" else 1)
