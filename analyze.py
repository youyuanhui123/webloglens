"""Offline combined-log analysis. No network requests or automatic blocking."""

import argparse
import json
from pathlib import Path
import sys

from webloglens import __version__
from webloglens.config import load_config
from webloglens.privacy import redact_report
from webloglens.report import render_markdown
from webloglens.behavior import detect_path_bursts
from webloglens.detector import detect_sensitive_paths
from webloglens.reader import read_log
from webloglens.stats import summarize

if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description='Offline WebLogLens analysis')
    parser.add_argument('--version', action='version', version=f'WebLogLens {__version__}')
    parser.add_argument('--format', choices=['json', 'markdown'], default='json',
                        help='Output format; default preserves existing JSON behavior')
    parser.add_argument('input', type=Path, nargs='?', default=root / 'examples' / 'synthetic_sensitive.log')
    parser.add_argument('--output', type=Path, help='Save UTF-8 JSON or Markdown; parent directory must exist')
    parser.add_argument('--config', type=Path, default=root / 'rules' / 'default.json',
                        help='Strict JSON config; default resolved relative to this script')
    parser.add_argument('--data-kind', choices=['unspecified', 'synthetic', 'local-experiment', 'authorized'],
                        default='unspecified', help='User-supplied provenance label, not verified by this tool')
    parser.add_argument('--window-seconds', type=int, default=None, help='Override configured window; > 0')
    parser.add_argument('--min-paths', type=int, default=None, help='Override configured path threshold; >= 2')
    parser.add_argument('--redact-share', action='store_true',
                        help='Allowlisted sharing view; omit raw evidence and replace IP/path identifiers')
    args = parser.parse_args()
    try:
        settings = load_config(args.config)
    except (OSError, ValueError) as exc:
        parser.error(f'Config error: {ascii(str(exc))}')
    overrides = {}
    if args.window_seconds is not None:
        if args.window_seconds <= 0:
            parser.error('--window-seconds must be > 0')
        overrides['window_seconds'] = args.window_seconds
    if args.min_paths is not None:
        if args.min_paths < 2:
            parser.error('--min-paths must be >= 2')
        overrides['min_paths'] = args.min_paths
    settings.update(overrides)
    try:
        result = read_log(args.input)
        behavior = detect_path_bursts(result['records'], settings['window_seconds'], settings['min_paths'])
        findings = detect_sensitive_paths(result['records'], settings['sensitive_paths']) + behavior['findings']
        report = {
            'schema_version': '1.1',
            'source': {'path': str(args.input.resolve()), 'data_kind': args.data_kind,
                       'provenance_verified': False},
            'configuration': {'path': str(args.config.resolve()),
                              'effective': settings, 'cli_overrides': overrides},
            'parsing': {
                'total_lines': result['total_lines'], 'parsed': len(result['records']),
                'errors': len(result['errors']), 'blank_lines': result['blank_lines'],
            },
            'summary': summarize(result['records']),
            'finding_count': len(findings),
            'findings': findings,
            'behavior': {
                'config': {'window_seconds': settings['window_seconds'], 'min_paths': settings['min_paths'],
                           'emit_policy': 'first_qualifying_window_per_ip'},
                **behavior,
            },
            'records': result['records'],
            'parse_errors': result['errors'],
            'limitations': [
                'Indicators only; HTTP status does not prove sensitive data leakage.',
                'Multi-path windows can be normal traffic; thresholds are illustrative, not universal.',
                'Behavior events sorted in UTC; invalid timestamps excluded from behavior only and reported.',
                'Only first qualifying window per recorded IP is emitted; proxy attribution is not resolved.',
                'Exact undecoded configured paths only; encoded variants and other attacks are not covered.',
                'An empty sensitive_paths list explicitly disables sensitive-path matching, not behavior analysis.',
                'Fixed combined log structure and UTF-8 input only; results are kept in memory.',
                'Report contains source paths, IPs, request targets and raw logs; redact before sharing.',
                'Data-kind is a user declaration, not independently verified evidence.',
            ],
        }
        if args.redact_share:
            report = redact_report(report)
        text = (render_markdown(report) if args.format == 'markdown'
                else json.dumps(report, ensure_ascii=False, indent=2))
        if args.output:
            with args.output.open('x', encoding='utf-8') as output:
                output.write(text + '\n')
            print(f'Saved report: {args.output.resolve()}')
            print(f"parsed={len(result['records'])} errors={len(result['errors'])} findings={len(findings)}")
            print(f"behavior_findings={len(behavior['findings'])} time_errors={len(behavior['time_errors'])}")
        else:
            print(text)
    except (OSError, UnicodeError) as exc:
        parser.exit(1, f'Analysis failed: {ascii(str(exc))}\n')
