"""Generate a private stage report from saved watch/replay JSONL; no detection rerun."""
import argparse
import json
from pathlib import Path
import sys

from webloglens.event_report import summarize_events, render_stage_markdown


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('events', help='static saved JSONL from a single watch/replay run')
    parser.add_argument('--format', choices=('markdown', 'json'), default='markdown')
    parser.add_argument('--output', help='new private report; parent must exist; never overwrite')
    parser.add_argument('--max-samples', type=int, default=20)
    parser.add_argument('--max-event-bytes', type=int, default=2097152)
    parser.add_argument('--max-sample-bytes', type=int, default=262144)
    args = parser.parse_args(argv)
    report = summarize_events(args.events, max_samples=args.max_samples,
                              max_event_bytes=args.max_event_bytes,
                              max_sample_bytes=args.max_sample_bytes)
    text = (json.dumps(report, ensure_ascii=False, indent=2) + '\n'
            if args.format == 'json' else render_stage_markdown(report))
    if args.output:
        with open(args.output, 'x', encoding='utf-8') as output:
            output.write(text)
        print('Saved private report: ' + str(Path(args.output).resolve()), file=sys.stderr)
    else:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
        sys.stdout.write(text)
    if report['quality']['analysis_has_gaps']:
        print('Warning: report contains analysis gaps or review requirements; '
              'successful export is not a clean-run verdict.', file=sys.stderr)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f'Event report failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
