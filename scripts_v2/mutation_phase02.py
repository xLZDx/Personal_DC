"""Negative mutations in disposable source copies; never mutate the active clone."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
CASES=(
 ('P02-M01','dc_v2/readonly_auth.py','record.audience==self.audience','True','test_invalid_token_binding'),
 ('P02-M02','dc_v2/gateway.py','require(host in self.hosts, "TRANSPORT_DENIED")','pass  # MUTANT: Host binding removed','test_http_guards'),
 ('P02-M03','dc_v2/readonly_snapshot.py',"require(obj.get('classification') in EXPORTABLE, 'EXPORT_DENIED')","pass  # MUTANT: classification removed",'test_snapshot_rejects_forbidden_data'),
 ('P02-M04','dc_v2/readonly_service.py',"require('project:'+pid in principal.scopes,'ACCESS_DENIED')","pass  # MUTANT: project scope removed",'test_cross_principal_denied'),
 ('P02-M05','dc_v2/readonly_service.py',"for secret in self.canaries:data=data.replace(secret,b'[REDACTED]')","for secret in self.canaries:pass  # MUTANT: masking removed",'test_file_read_masks_canary_and_reports_hashes'),
 ('P02-M06','dc_v2/readonly_service.py',"except Denied:return {'status':'DENIED','error_code':'AUDIT_UNAVAILABLE'}","except Denied:pass  # MUTANT: allow response on audit failure",'test_audit_fail_closed'),
 ('P02-M07','dc_v2/readonly_service.py',"raise Denied('EXECUTION_HOLD')","return {'status':'OK'}  # MUTANT: false execution capability",'test_no_legacy_or_execution_fallback'),
)

def main():
    directory=ROOT/'evidence/phase02/mutations';directory.mkdir(parents=True,exist_ok=True)
    originals={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for _,n,_,_,_ in CASES}
    results=[]
    for case,name,old,new,test in CASES:
        with tempfile.TemporaryDirectory(prefix='personal-dc-p02-mutation-') as temp:
            target=Path(temp)
            for folder in ('dc_v2','tests_phase02'):
                shutil.copytree(ROOT/folder,target/folder,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
            shutil.copyfile(ROOT/'pytest-phase02.ini',target/'pytest-phase02.ini')
            path=target/name;text=path.read_text(encoding='utf-8')
            if text.count(old)!=1:raise RuntimeError('MUTATION_ANCHOR_MISMATCH:'+case)
            path.write_text(text.replace(old,new),encoding='utf-8')
            env=dict(os.environ);env['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1';env['PYTHONIOENCODING']='utf-8'
            for key in ('PYTEST_ADDOPTS','PYTEST_PLUGINS','PYTHONPATH'):env.pop(key,None)
            xml=directory/(case+'.xml')
            with (directory/(case+'.log')).open('wb') as log:
                p=subprocess.run([sys.executable,'-m','pytest','-c','pytest-phase02.ini','-k',test,
                                  '--junitxml='+str(xml)],cwd=target,env=env,stdin=subprocess.DEVNULL,
                                 stdout=log,stderr=subprocess.STDOUT,timeout=60)
            tests=list(ET.parse(xml).getroot().iter('testcase')) if xml.exists() else []
            failures=sum(x.find('failure') is not None for x in tests)
            errors=sum(x.find('error') is not None for x in tests)
            results.append({'id':case,'pytest_exit_code':p.returncode,'collected':len(tests),
                            'assertion_failures':failures,'errors':errors,
                            'detected':p.returncode==1 and failures>0 and errors==0})
    unchanged=all(hashlib.sha256((ROOT/n).read_bytes()).hexdigest()==h for n,h in originals.items())
    report={'mutations':results,'original_sources_unchanged':unchanged,
            'all_detected':unchanged and all(r['detected'] for r in results),
            'scope':'synthetic local source mutations; not OS sandbox acceptance'}
    (directory/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2));return 0 if report['all_detected'] else 1

if __name__=='__main__':raise SystemExit(main())
