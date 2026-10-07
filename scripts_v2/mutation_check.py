"""Run three bounded negative test mutations in disposable source copies.

Never changes the live checkout, user projects, policy, installed runtime or host
settings. This script is a developer test utility, not an exposed MCP operation.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = (
    ('R01', 'dc_v2/policy.py',
     'require(_inside(safe, root) and safe.is_file() and safe.stat().st_size <= 268435456, "TOOL_UNTRUSTED")',
     'require(safe.is_file(), "TOOL_UNTRUSTED")', 'test_tool_no_name_fallback'),
    ('R02', 'dc_v2/output.py', 'out.extend(b"[REDACTED]")', 'out.extend(secret)',
     'test_redaction_across_every_boundary'),
    ('R03', 'dc_v2/policy.py',
     'require(not any(_inside(self.root, p) or _inside(p, self.root) for p in self.protected), "ACCESS_DENIED")',
     'pass  # MUTATION: runtime protection removed', 'test_runtime_protected'),
)

def main():
    results = []
    for case, filename, old, new, test in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix='personal-dc-mutation-') as temp:
            target = Path(temp)
            for name in ('dc_v2', 'tests_v2'):
                shutil.copytree(ROOT / name, target / name, ignore=shutil.ignore_patterns('__pycache__'))
            shutil.copyfile(ROOT / 'pytest-v2.ini', target / 'pytest-v2.ini')
            path = target / filename
            source = path.read_text(encoding='utf-8')
            if source.count(old) != 1:
                raise RuntimeError('Mutation anchor mismatch: ' + case)
            path.write_text(source.replace(old, new), encoding='utf-8')
            env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
            proc = subprocess.run([sys.executable, '-m', 'pytest', '-c', 'pytest-v2.ini',
                                   'tests_v2/test_security.py', '-k', test], cwd=target,
                                  capture_output=True, timeout=30, env=env)
            results.append({'id': case, 'mutation_detected': proc.returncode == 1,
                            'pytest_exit_code': proc.returncode})
    print(json.dumps(results, indent=2))
    return 0 if all(r['mutation_detected'] for r in results) else 1

if __name__ == '__main__':
    raise SystemExit(main())
