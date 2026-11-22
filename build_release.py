"""Build a portable source ZIP from explicit files, never private experiments."""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile

from webloglens import __version__

ROOT_FILES = ['README.md', '.gitignore', 'analyze.py', 'run_experiment.py', 'build_release.py',
              'main.py', 'read_demo.py', 'stats_demo.py', 'detect_demo.py',
              'watch.py', 'report_events.py', 'run_nginx_experiment.py', 'run_baseline.py', 'check_input.py', 'investigate.py', 'assemble_events.py']
MODULES = ['__init__', 'parser', 'reader', 'stats', 'detector', 'behavior', 'config', 'report', 'privacy',
           'local_lab', 'follow', 'stream', 'event_report', 'nginx_lab', 'ingest', 'site_stream', 'event_index', 'output']
TESTS = ['parser', 'reader', 'stats', 'detector', 'behavior', 'config', 'report', 'privacy',
         'cli', 'local_lab', 'experiment_runner', 'release', 'follow', 'watch_cli', 'stream',
         'stream_cli', 'nginx_lab', 'nginx_runner_cli', 'event_report', 'event_report_cli', 'baseline', 'ingest', 'site_stream', 'event_index', 'output', 'runtime_cli']
DOCS = ['QUICKSTART', 'ARCHITECTURE', 'PRIVACY', 'INTERVIEW', 'ACCEPTANCE',
        'V2-REALTIME', 'NGINX-LAB', 'EVENT-REPORT', 'BASELINE', 'V3-INPUT', 'V3-SITES', 'V3-INDEX', 'V3-RUNTIME', 'RELEASE-3.0.0']
FILES = (ROOT_FILES + [f'webloglens/{name}.py' for name in MODULES]
         + [f'tests/test_{name}.py' for name in TESTS]
         + [f'docs/{name}.md' for name in DOCS]
         + ['rules/default.json', 'rules/example.json', 'examples/nginx-json-format.conf',
            'examples/synthetic_nginx.jsonl', 'examples/synthetic_sites.jsonl']
         + [f'examples/synthetic_{name}.log' for name in ['access', 'sensitive', 'burst']])

if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description='Allowlisted portable source package; no private reports')
    parser.add_argument('--output', type=Path, default=root / 'dist' / f'WebLogLens-{__version__}.zip')
    args = parser.parse_args()
    try:
        payloads = {}
        for name in FILES:
            source = root / name
            if source.is_symlink() or not source.is_file():
                raise ValueError(f'Missing or symlinked release file: {name}')
            if any(parent.is_symlink() for parent in source.parents if parent != root.parent):
                raise ValueError(f'Symlinked source parent: {name}')
            payloads[name] = source.read_bytes()
        manifest = {
            'project': 'WebLogLens', 'version': __version__,
            'file_count': len(payloads),
            'sha256': {name: hashlib.sha256(data).hexdigest() for name, data in sorted(payloads.items())},
            'privacy': 'Explicit source/documentation/synthetic-example allowlist only; no experiments or private reports.',
        }
        payloads['RELEASE-MANIFEST.json'] = (json.dumps(manifest, indent=2) + '\n').encode('utf-8')
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.output, mode='x', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(payloads.items()):
                info = zipfile.ZipInfo('WebLogLens/' + name, date_time=(2020, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, data)
        print(f'Built: {args.output.resolve()}')
        print(f'archive_members={len(payloads)}')
        print(f'sha256={hashlib.sha256(args.output.read_bytes()).hexdigest()}')
    except (OSError, ValueError) as exc:
        parser.exit(1, f'Packaging failed: {ascii(str(exc))}\n')
