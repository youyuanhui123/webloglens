"""Follow combined logs; --detect enables incremental rules; --replay reads a static file.

Private JSONL contains raw logs. Never publish it without manual review.
"""
import argparse
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import sys
import time

from webloglens.config import load_config
from webloglens.follow import FileFollower
from webloglens.ingest import parse_access_line
from webloglens.stream import StreamAnalyzer
from webloglens.site_stream import SiteAnalyzer
from webloglens.output import RollingOutput


def positive(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError('must be positive finite')
    return number


def polling_interval(value):
    number = positive(value)
    if number > 60:
        raise argparse.ArgumentTypeError('interval must be at most 60 seconds')
    return number


def runtime_health(counts, *, missing=False, active=False):
    """Input is current-poll state; parse/capacity flags are sticky for this run.

    'healthy' means no observed runtime issue, never a security verdict.
    """
    input_state = 'missing' if missing else ('active' if active else 'waiting')
    parse_problem = any(counts.get(kind, 0) for kind in
                        ('parse_error', 'decode_error', 'line_too_long', 'time_error'))
    capacity_gap = bool(counts.get('state_limit', 0))
    late_records = bool(counts.get('late_record', 0))
    analysis_gap = capacity_gap or late_records or bool(counts.get('time_error', 0))
    state = ('input_missing' if missing else 'capacity_gap' if capacity_gap else
             'parse_problem' if parse_problem else 'analysis_gap' if analysis_gap else
             'healthy' if active else 'waiting')
    return dict(state=state, input_state=input_state, parse_problem=bool(parse_problem),
                capacity_gap=capacity_gap, late_records=late_records, analysis_gap=analysis_gap)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', help='existing local UTF-8 access log file')
    parser.add_argument('--log-format', choices=('combined', 'nginx-json'), default='combined')
    parser.add_argument('--start', choices=('beginning', 'end'))
    parser.add_argument('--interval', type=polling_interval, default=0.2)
    parser.add_argument('--duration', type=positive, help='seconds; default: until Ctrl+C')
    parser.add_argument('--status-interval', type=positive, default=5.0)
    outputs = parser.add_mutually_exclusive_group()
    outputs.add_argument('--output', help='new private JSONL file; refuses overwrite')
    outputs.add_argument('--output-dir', help='new private rolling run directory; refuses existing directory')
    parser.add_argument('--output-max-bytes', type=int, help='positive shard byte target; oversized lines remain whole')
    parser.add_argument('--output-keep-shards', type=int, help='explicitly delete old shards of THIS run; makes full assembly impossible')
    parser.add_argument('--detect', action='store_true', help='enable incremental rules')
    parser.add_argument('--replay', action='store_true', help='static file-order replay; implies --detect')
    parser.add_argument('--config', default=str(Path(__file__).resolve().parent / 'rules/default.json'))
    for option in ('window-seconds', 'min-paths'):
        parser.add_argument('--' + option, type=int)
    parser.add_argument('--lateness-seconds', type=int, default=2)
    parser.add_argument('--cooldown-seconds', type=int, default=60)
    parser.add_argument('--max-buffer', type=int, default=512)
    parser.add_argument('--max-window-records', type=int, default=2048)
    parser.add_argument('--max-ips', type=int, default=256)
    parser.add_argument('--max-sites', type=int, help='JSON only: site admission cap, default 16 (1..128)')
    args = parser.parse_args(argv)
    if args.output_dir:
        if args.output_max_bytes is None or args.output_max_bytes < 1:
            parser.error('--output-dir requires positive --output-max-bytes')
    elif args.output_max_bytes is not None or args.output_keep_shards is not None:
        parser.error('shard options require --output-dir')
    if args.output_keep_shards is not None and args.output_keep_shards < 1:
        parser.error('--output-keep-shards must be positive')
    if args.max_sites is not None:
        if args.log_format != 'nginx-json' or not 1 <= args.max_sites <= 128:
            parser.error('--max-sites requires nginx-json and an integer in 1..128')
    if args.replay and (args.start == 'end' or args.duration is not None):
        parser.error('--replay requires beginning and cannot be combined with --duration')
    start = args.start or ('beginning' if args.replay else 'end')
    analyzer = None
    settings = None
    if args.detect or args.replay:
        settings = load_config(args.config)
        overrides = {}
        for name in ('window_seconds', 'min_paths'):
            value = getattr(args, name)
            if value is not None:
                settings[name] = value
                overrides[name] = value
        settings.update({name: getattr(args, name) for name in
                         ('lateness_seconds', 'cooldown_seconds', 'max_buffer',
                          'max_window_records', 'max_ips')})
        if args.log_format == 'nginx-json':
            settings['max_sites'] = args.max_sites if args.max_sites is not None else 16
            analyzer = SiteAnalyzer(**settings)
        else:
            analyzer = StreamAnalyzer(**settings)
    counts = Counter()
    started = time.monotonic()
    last_status = started
    last_record_at = None
    with ExitStack() as stack:
        follower = stack.enter_context(FileFollower(args.log, start=start))
        replay_stat = os.fstat(follower.file.fileno())
        replay_size = replay_stat.st_size
        replay_signature = (replay_stat.st_dev, replay_stat.st_ino, replay_stat.st_size, replay_stat.st_mtime_ns)
        output = stack.enter_context(open(args.output, 'x', encoding='utf-8')) if args.output else None
        rolling = (stack.enter_context(RollingOutput(args.output_dir, args.output_max_bytes,
                                                    args.output_keep_shards))
                   if args.output_dir else None)

        def emit(event):
            event = dict(event, observed_at=datetime.now(timezone.utc).isoformat())
            text = json.dumps(event, ensure_ascii=True)
            if rolling:
                rolling.write(text + '\n')
            if output:
                output.write(text + '\n')
                output.flush()
            print(text, flush=True)

        def emit_analysis(events):
            for item in events:
                counts[item['type']] += 1
                emit(item)

        initial = dict(type='started', source=str(follower.path), start=start,
                       stage='detection' if analyzer else 'input-only', private=True,
                       mode='replay' if args.replay else 'watch', log_format=args.log_format)
        if analyzer:
            initial.update(settings=settings, cli_overrides=overrides,
                           config_source=str(Path(args.config).resolve()))
        emit(initial)
        reason = 'duration'
        active = False
        try:
            while args.duration is None or time.monotonic() - started < args.duration:
                active = False
                for event in follower.poll():
                    if event['type'] == 'line':
                        raw = event['raw']
                        if not raw.strip():
                            event['type'] = 'blank'
                        else:
                            try:
                                event['fields'] = parse_access_line(raw, args.log_format)
                                event['type'] = 'record'
                                active = True
                                last_record_at = datetime.now(timezone.utc).isoformat()
                            except ValueError as exc:
                                event['type'] = 'parse_error'
                                event['reason'] = str(exc)
                    counts[event['type']] += 1
                    emit(event)
                    if analyzer and event['type'] == 'record':
                        emit_analysis(analyzer.feed(event, now=time.monotonic()))
                if args.replay:
                    current = follower.path.stat()
                    signature = (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
                    if signature != replay_signature or follower.generation != 1:
                        raise ValueError('replay input changed; use a static copy')
                    if follower.file.tell() >= replay_size:
                        reason = 'replay_complete'
                        break
                now = time.monotonic()
                if analyzer and not args.replay:
                    emit_analysis(analyzer.tick(now))
                if now - last_status >= args.status_interval:
                    status = dict(type='status', source=str(follower.path),
                                  read_offset=follower.file.tell(), generation=follower.generation,
                                  pending_bytes=len(follower.pending), counts=dict(counts),
                                  last_record_at=last_record_at, path_missing=follower.missing,
                                  health=runtime_health(counts, missing=follower.missing, active=active))
                    if analyzer:
                        status['analysis'] = analyzer.snapshot()
                    emit(status)
                    last_status = now
                if not args.replay:
                    delay = args.interval
                    if args.duration is not None:
                        delay = min(delay, max(0, args.duration - (time.monotonic() - started)))
                    time.sleep(delay)
        except KeyboardInterrupt:
            reason = 'interrupted'
        if analyzer:
            emit_analysis(analyzer.finish())
        summary = dict(type='summary', source=str(follower.path), reason=reason,
                       counts=dict(counts), pending_bytes=len(follower.pending),
                       read_offset=follower.file.tell(), generation=follower.generation,
                       elapsed_seconds=time.monotonic() - started,
                       health=runtime_health(counts, missing=follower.missing, active=active))
        if analyzer:
            summary['analysis'] = analyzer.snapshot()
        emit(summary)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f'watch failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
