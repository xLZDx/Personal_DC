"""Developer runner: bounded synthetic test suites; never a remotely exposed tool.

Results bind to source hashes and exact Git HEAD where available. Evidence is not
production deployment acceptance. Logs remain in the independent development clone.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from datetime import datetime,timezone
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--label',default='local');parser.add_argument('--legacy',action='store_true')
    args=parser.parse_args()
    if not args.label.replace('-','').isalnum():raise SystemExit('Invalid evidence label')
    directory=ROOT/'evidence'/'phase02'/args.label;directory.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ);env['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'
    env['PYTHONIOENCODING']='utf-8'
    for k in ('PYTEST_ADDOPTS','PYTEST_PLUGINS','PYTHONPATH','PERSONAL_DC_HOME'):env.pop(k,None)
    jobs=[('foundation',[sys.executable,'-m','pytest','-c','pytest-v2.ini','tests_v2']),
          ('phase02',[sys.executable,'-m','pytest','-c','pytest-phase02.ini'])]
    if args.legacy:jobs.append(('legacy-and-discovery',[sys.executable,'-m','pytest','-c','pyproject.toml']))
    results=[]
    for name,cmd in jobs:
        xml=directory/(name+'.xml');log=directory/(name+'.log')
        started=datetime.now(timezone.utc).isoformat();tick=time.monotonic()
        with log.open('wb') as output:
            try:
                p=subprocess.run(cmd+['--junitxml='+str(xml)],cwd=ROOT,env=env,stdin=subprocess.DEVNULL,
                                 stdout=output,stderr=subprocess.STDOUT,timeout=180)
                code=p.returncode
            except subprocess.TimeoutExpired:code=124
        row={'suite':name,'started_utc':started,'duration_s':round(time.monotonic()-tick,3),'exit_code':code}
        if xml.exists():
            cases=list(ET.parse(xml).getroot().iter('testcase'))
            row.update(collected=len(cases),passed=sum(c.find('failure') is None and c.find('error') is None and c.find('skipped') is None for c in cases),
                       failed=sum(c.find('failure') is not None or c.find('error') is not None for c in cases),
                       skipped=sum(c.find('skipped') is not None for c in cases))
        results.append(row)
    hashes={}
    for folder in ('dc_v2','tests_phase02','tests_v2','scripts_v2'):
        for p in sorted((ROOT/folder).glob('*.py')):
            hashes[p.relative_to(ROOT).as_posix()]=hashlib.sha256(p.read_text(encoding='utf-8').encode()).hexdigest()
    packages={}
    for package in ('mcp','httpx','uvicorn','pytest','cryptography'):
        try:packages[package]=importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:packages[package]='NOT_INSTALLED'
    report={'finished_utc':datetime.now(timezone.utc).isoformat(),'platform':platform.platform(),
            'python':platform.python_version(),'packages':packages,'results':results,
            'source_sha256_lf_normalized':hashes,'execution':'HOLD','production_activation':'NOT_PERFORMED',
            'all_command_exit_codes_zero':all(x['exit_code']==0 for x in results)}
    (directory/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='source_sha256_lf_normalized'},indent=2))
    return 0 if report['all_command_exit_codes_zero'] else 1

if __name__=='__main__':raise SystemExit(main())
