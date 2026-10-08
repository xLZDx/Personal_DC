"""Real Docker Desktop, offline-only, disposable Phase03 acceptance smoke.

Only containers labelled personal-dc.owner=phase03 are spawned. Nothing in
the installed Personal_DC main checkout, MCP tunnel or existing containers
is touched. The control/root fixtures are outside the active repository.
"""
import hashlib
import json
import secrets
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dc_v2.contracts import Denied, Manifest, Principal
from dc_v2.execution import DockerExecutor, WorkspacePool
from dc_v2.policy import TaskGrant

BASE = Path(r"D:\Temp\Personal_DC_v2_2_isolated")
DOCKER = Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe")
IMAGE = "sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
HOST = "npipe:////./pipe/dockerDesktopLinuxEngine"
OUT = Path(__file__).resolve().parents[1] / "evidence" / "phase03" / "live-probe.json"
report = {"date": "2026-10-08", "image_id": IMAGE, "tests": {}, "status": "RUNNING",
          "synthetic_fixture": True}
created = []

def note(name, ok, detail=""):
    report["tests"][name] = {"pass": bool(ok), "detail": str(detail)[:300]}
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(name, "PASS" if ok else "FAIL", str(detail)[:150], flush=True)

def make_manifest(executor, work, principal, command, timeout_s=30):
    manifest = Manifest(principal.binding, "phase03-probe", "task.start",
        work.snapshot_digest, IMAGE[7:], executor.policy_digest, work.workspace_id,
        principal.recipient_id, tuple(command), (), ("sandbox-exec",), timeout_s, 8192)
    grant = TaskGrant(principal.binding, "phase03-probe", work.snapshot_digest,
        IMAGE[7:], executor.policy_digest, work.workspace_id, principal.recipient_id,
        frozenset(("task.start",)), frozenset(("sandbox-exec",)),
        int(time.time()) + 120, timeout_s, 8192)
    return manifest, grant

try:
    unique = "phase03-live-" + secrets.token_hex(6)
    staging = BASE / unique
    staging.mkdir()
    workroot, control = staging / "work", staging / "control"
    workroot.mkdir()
    control.mkdir()
    report["staging"] = str(staging)
    pool = WorkspacePool(workroot, (Path(r"D:\Repo\Personal_DC"), control))
    runner = DockerExecutor(DOCKER, IMAGE, pool, control, HOST)
    note("engine", runner.check()["engine"] == "linux", "pinned local image")
    principal = Principal("phase03-test-owner", "local-cli", "fixture-recipient",
                          frozenset(("task.start", "task.status", "task.output",
                                     "task.cancel", "task.list", "project:phase03-probe")))
    ws = pool.create({"hello.py": b'print("PDC_SANDBOX_42")\n'})
    manifest, grant = make_manifest(runner, ws, principal, ("python", "hello.py"))
    launched = runner.start(manifest, grant, principal, ws.workspace_id)
    task_id = launched["task_id"]
    created.append(task_id)
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        state = runner.status(task_id, principal)
        if state["status"] != "RUNNING":
            break
        time.sleep(0.5)
    else:
        raise RuntimeError("container did not complete")
    logs = runner.output(task_id, principal)["data"]
    note("python-cli", state["status"] == "EXITED" and state["exit_code"] == 0 and
         "PDC_SANDBOX_42" in logs, {"exit_code":state.get("exit_code"),"output": logs[:150]})
    change_ws = pool.create({"README.txt": b"ORIGINAL\n"})
    cmd = ("python", "-c",
           "from pathlib import Path; Path('result.txt').write_text('PDC_WRITE_42'); print('WROTE')")
    change_manifest, change_grant = make_manifest(runner, change_ws, principal, cmd)
    write_task = runner.start(change_manifest, change_grant, principal, change_ws.workspace_id)
    created.append(write_task["task_id"])
    deadline = time.monotonic()+35
    while time.monotonic()<deadline:
        write_state = runner.status(write_task["task_id"], principal)
        if write_state["status"]!="RUNNING":
            break
        time.sleep(.5)
    changed = (change_ws.path/"result.txt").exists()
    note("guest-write-and-diff", write_state.get("exit_code")==0 and changed and
         "result.txt" in pool.diff(change_ws.workspace_id),
         {"exit_code":write_state.get("exit_code"),"changed":changed,
          "output":runner.output(write_task["task_id"],principal)["data"][:120]})
    long_ws=pool.create({"readme.txt":b"long-process\n"})
    long_manifest, long_grant=make_manifest(runner,long_ws,principal,
        ("python","-c","import time;print('STARTED',flush=True);time.sleep(90)"),100)
    slow=runner.start(long_manifest,long_grant,principal,long_ws.workspace_id)
    created.append(slow["task_id"])
    time.sleep(.5)
    response=runner.cancel(slow["task_id"],principal)
    stop_state=runner.status(slow["task_id"],principal)
    note("cancel-long-process",response["status"]=="CANCEL_REQUESTED" and
         stop_state["status"]=="EXITED",stop_state)
    watchdog_ws=pool.create({"watchdog.txt":b"autonomous timeout\n"})
    timeout_manifest, timeout_grant=make_manifest(runner,watchdog_ws,principal,
        ("python","-c","import time;time.sleep(20)"),2)
    watchdog_task=runner.start(timeout_manifest,timeout_grant,principal,watchdog_ws.workspace_id)
    created.append(watchdog_task["task_id"])
    time.sleep(5)
    deadline_state=runner.status(watchdog_task["task_id"],principal)
    note("guest-enforced-deadline",
         deadline_state["status"]=="EXITED" and deadline_state.get("exit_code")==124,
         deadline_state)
    stop=runner.emergency_stop()
    note("emergency-latch",stop["stop_latched"] and
         runner.stop_file.exists(),stop)
    try:
        runner.start(manifest, grant, principal, ws.workspace_id)
    except Denied as exc:
        note("stop-denies-restart",exc.code=="OPERATION_CANCELLED",exc.code)
    else:
        note("stop-denies-restart",False,"start unexpectedly allowed")
    report["status"] = ("PASS" if all(v["pass"] for v in report["tests"].values())
                        else "FAIL")
except Exception as exc:
    report["status"]="FAIL"
    report["error_type"]=type(exc).__name__
    report["error_detail"]=str(exc)[:200]
    traceback.print_exc()
finally:
    report["created_tasks"]=created
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True),encoding="utf-8")
print("FINAL",report["status"], flush=True)
sys.exit(0 if report["status"]=="PASS" else 1)
