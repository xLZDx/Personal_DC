"""Sanitized, reproducible test evidence. No host commands or credential reads."""
import hashlib
import importlib.metadata
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
START = datetime.now(timezone.utc).isoformat()
OUTCOMES = {}


def pytest_runtest_logreport(report):
    if report.failed:
        OUTCOMES[report.nodeid] = 'failed'
    elif report.skipped:
        OUTCOMES[report.nodeid] = 'skipped'
    elif report.when == 'call' and OUTCOMES.get(report.nodeid) != 'failed':
        OUTCOMES[report.nodeid] = 'passed'


def pytest_sessionfinish(session, exitstatus):
    packages = {}
    for name in ('pytest', 'cryptography'):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = 'NOT_INSTALLED'
    expected_path = ROOT / 'SOURCE_MANIFEST.json'
    reference = json.loads(expected_path.read_text(encoding='utf-8')) if expected_path.exists() else {}
    hashes = {}
    for name in reference:
        data = (ROOT / name).read_text(encoding='utf-8').encode('utf-8')
        hashes[name] = hashlib.sha256(data).hexdigest()
    evidence = {
        'suite': 'v2-foundation-only', 'started_utc': START,
        'finished_utc': datetime.now(timezone.utc).isoformat(),
        'python': platform.python_version(), 'platform': platform.platform(), 'packages': packages,
        'collected': session.testscollected, 'exit_code': int(exitstatus),
        'passed': sum(v == 'passed' for v in OUTCOMES.values()),
        'failed': sum(v == 'failed' for v in OUTCOMES.values()),
        'skipped': sum(v == 'skipped' for v in OUTCOMES.values()),
        'source_sha256_lf_normalized': hashes, 'reference_present': bool(reference),
        'source_matches_reference': bool(reference) and all(hashes[n] == v['sha256'] for n, v in reference.items()),
        'production_gates': 'NOT_RUN', 'execution': 'HOLD'}
    directory = ROOT / 'evidence'
    directory.mkdir(exist_ok=True)
    (directory / 'foundation-summary.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
