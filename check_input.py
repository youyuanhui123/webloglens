"""Inspect a bounded local log prefix before watch/replay. Private metadata, not a verdict."""
import argparse
import json
import sys

from webloglens.ingest import inspect_log


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log')
    parser.add_argument('--log-format', choices=('combined', 'nginx-json'), default='combined')
    parser.add_argument('--max-lines', type=int, default=1000)
    parser.add_argument('--max-bytes', type=int, default=4194304)
    parser.add_argument('--max-line-bytes', type=int, default=65536)
    parser.add_argument('--max-sites', type=int, default=16)
    parser.add_argument('--output', help='new private JSON report; parent must exist')
    args = parser.parse_args(argv)
    report = inspect_log(args.log, args.log_format, args.max_lines, args.max_bytes,
                         args.max_line_bytes, max_sites=args.max_sites)
    text = json.dumps(report, ensure_ascii=True, indent=2) + '\n'
    if args.output:
        with open(args.output, 'x', encoding='utf-8') as output:
            output.write(text)
    else:
        sys.stdout.write(text)
    if not report['ready_for_detection']:
        print('Warning: sampled input has errors, missing valid records, or changed during inspection.', file=sys.stderr)
    if report['sample_limited']:
        print('Warning: only a bounded prefix was inspected; later records are unverified.', file=sys.stderr)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print('Input check failed: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
