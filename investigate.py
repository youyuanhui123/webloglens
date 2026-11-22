"""Private event import, parameterized query and source timeline. No detection rerun."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys

from webloglens.event_index import import_events, query_events, timeline


def render_markdown(value):
    heading = '# WebLogLens 私有调查结果'
    lines = [heading, '', '> 含原始日志、IP、查询串和本地路径，未脱敏，不可直接公开。',
             '> 线索不是攻击结论；零匹配不是安全证明。时间线只整理已有记录，不推断攻击链。', '',
             '## 结构化结果', '']
    lines += ['    ' + line for line in json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False).splitlines()]
    return '\n'.join(lines) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    added = commands.add_parser('import', help='index one complete static JSONL; incomplete streams rejected')
    added.add_argument('events')
    added.add_argument('--database', required=True)
    added.add_argument('--append', action='store_true', help='explicitly append a distinct run to an existing index')
    for name, default in [('max-source-bytes', 268435456), ('max-event-bytes', 2097152),
                          ('max-events', 100000), ('max-links', 500000)]:
        added.add_argument('--' + name, type=int, default=default)
    for action in ('query', 'timeline'):
        command = commands.add_parser(action)
        command.add_argument('database')
        command.add_argument('--run-id', type=int)
        command.add_argument('--site')
        command.add_argument('--ip', required=action == 'timeline')
        command.add_argument('--path', help='exact path without query; no decoding/substring matching')
        command.add_argument('--status', type=int)
        command.add_argument('--start', help='inclusive ISO8601 event time with timezone')
        command.add_argument('--end', help='inclusive ISO8601 event time with timezone')
        command.add_argument('--limit', type=int, default=100)
        command.add_argument('--offset', type=int, default=0)
        command.add_argument('--max-payload-bytes', type=int, default=4194304)
        if action == 'query':
            command.add_argument('--kind', choices=('record', 'finding', 'all'), default='record')
            command.add_argument('--rule-id')
    for command in (added, *[commands.choices[k] for k in ('query', 'timeline')]):
        command.add_argument('--format', choices=('json', 'markdown'), default='json')
        command.add_argument('--output', help='new private report; parent must exist')
    args = parser.parse_args(argv)
    if args.output:
        output = Path(args.output).absolute()
        if output.exists():
            raise FileExistsError('Output exists; refuses overwrite')
        if not output.parent.is_dir():
            raise ValueError('Output parent must exist')
        if output.resolve() == Path(args.database).resolve():
            raise ValueError('Report output must not be the database path')
    if args.action == 'import':
        value = import_events(args.events, args.database, append=args.append,
                              **{name: getattr(args, name) for name in
                                 ('max_source_bytes', 'max_event_bytes', 'max_events', 'max_links')})
    else:
        kwargs = {name: getattr(args, name) for name in ('run_id', 'site', 'ip', 'path', 'status',
                  'start', 'end', 'limit', 'offset', 'max_payload_bytes')}
        if args.action == 'query':
            value = query_events(args.database, kind=args.kind, rule_id=args.rule_id, **kwargs)
        else:
            value = timeline(args.database, **kwargs)
    text = (json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + '\n'
            if args.format == 'json' else render_markdown(value))
    if args.output:
        with open(args.output, 'x', encoding='utf-8') as output:
            output.write(text)
    else:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
        sys.stdout.write(text)
    summaries = [value] if args.action == 'import' else value['runs']
    if any(r.get('quality', {}).get('analysis_has_gaps') or r.get('index', {}).get('issues') for r in summaries):
        print('Warning: source analysis or evidence index has gaps; inspect quality and index issues.', file=sys.stderr)
    if value.get('next_item_exceeds_budget'):
        print('Warning: next item exceeds remaining payload budget; increase budget rather than skipping evidence.', file=sys.stderr)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, sqlite3.Error, OverflowError) as exc:
        print('Investigation failed: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
