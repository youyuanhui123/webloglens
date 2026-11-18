"""Controlled synthetic resource/latency baseline, not a production capacity test."""
import argparse
from datetime import datetime, timedelta
import json
import math
from pathlib import Path
import platform
import queue
import subprocess
import sys
import threading
import time
import tracemalloc

from webloglens.parser import parse_line
from webloglens.stream import StreamAnalyzer

ROOT = Path(__file__).resolve().parent


def log_line(index, target='/'):
    # Fixed English month: independent of Windows locale.
    stamp = (datetime(2026, 11, 5) + timedelta(seconds=index)).strftime('%d')
    instant = datetime(2026, 11, 5) + timedelta(seconds=index)
    stamp += '/Nov/2026:' + instant.strftime('%H:%M:%S') + ' +0000'
    return f'192.0.2.10 - - [{stamp}] "GET {target} HTTP/1.1" 404 10 "-" "baseline"\n'


def core_trial(size):
    analyzer = StreamAnalyzer(lateness_seconds=0)
    tracemalloc.start()
    started, cpu = time.perf_counter(), time.process_time()
    findings = 0
    for index in range(size):
        raw = log_line(index, '/.env' if index % 10 == 0 else '/') .rstrip('\n')
        record = dict(raw=raw, fields=parse_line(raw), source='synthetic',
                      generation=1, line_number=index + 1, offset=0)
        findings += sum(e['type'] == 'finding' for e in analyzer.feed(record, now=index))
    findings += sum(e['type'] == 'finding' for e in analyzer.finish())
    elapsed, cpu_used = time.perf_counter() - started, time.process_time() - cpu
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    state = analyzer.snapshot()
    assert state['records'] == size
    assert findings == (size + 9) // 10
    assert not state.get('state_limits', 0)
    return dict(records=size, findings=findings, wall_seconds=elapsed,
                cpu_seconds=cpu_used, records_per_second= size / elapsed,
                python_current_bytes=current, python_peak_bytes=peak,
                state_limits=state.get('state_limits', 0), final_state=state)


def live_trial(output, count):
    source = output / 'live-access.log'
    source.write_bytes(b'')
    command = [sys.executable, str(ROOT / 'watch.py'), str(source), '--detect',
               '--interval', '0.05', '--lateness-seconds', '0',
               '--duration', str(count * 0.05 + 2), '--output', str(output / 'live-events.jsonl')]
    events = queue.Queue()
    with open(output / 'watch-stderr.txt', 'w', encoding='utf-8') as error:
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=error,
                                 text=True, encoding='utf-8', cwd=ROOT)
        def drain():
            try:
                for line in child.stdout:
                    events.put((time.perf_counter(), json.loads(line)))
            finally:
                events.put((time.perf_counter(), None))
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            _, event = events.get(timeout=10)
            if not event or event.get('type') != 'started':
                raise RuntimeError('watch failed before started')
            sent = {}
            with open(source, 'ab', buffering=0) as writer:
                for index in range(count):
                    target = '/.env?baseline=' + str(index)
                    sent[target] = time.perf_counter()
                    writer.write(log_line(index, target).encode('utf-8'))
                    time.sleep(0.05)
            samples, seen, summary = [], set(), None
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                received, event = events.get(timeout=max(0.01, deadline - time.monotonic()))
                if event is None:
                    break
                if event['type'] == 'finding' and event['rule_id'] == 'sensitive-path-exact-v1':
                    target = event['evidence'][0]['fields']['target']
                    if target in seen:
                        raise RuntimeError('duplicate finding')
                    seen.add(target)
                    samples.append(dict(target=target, latency_ms=(received - sent[target]) * 1000))
                if event['type'] == 'summary':
                    summary = event
            code = child.wait(timeout=5)
            reader.join(timeout=2)
            if code or len(samples) != count or not summary or summary['counts'].get('record') != count:
                raise RuntimeError('live counts/exit verification failed')
            ordered = sorted(s['latency_ms'] for s in samples)
            return dict(records_written=count, matched_findings=len(samples),
                        summary_records=summary['counts']['record'], interval_seconds=0.05,
                        latency_ms=dict(p50=ordered[math.ceil(count * 0.50) - 1],
                                        p95=ordered[math.ceil(count * 0.95) - 1], maximum=ordered[-1]),
                        samples=samples, command=command, summary=summary)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            reader.join(timeout=2)
            child.stdout.close()


def positive_int(value):
    number = int(value)
    if not 1 <= number <= 1000000:
        raise argparse.ArgumentTypeError('must be 1..1000000')
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--sizes', nargs='+', type=positive_int, default=[1000, 10000])
    parser.add_argument('--live-records', type=positive_int, default=40)
    parser.add_argument('--worker', type=positive_int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(core_trial(args.worker)))
        return
    if args.output is None:
        parser.error('--output is required')
    if args.live_records > 200:
        parser.error('--live-records must be at most 200')
    args.output.mkdir(parents=True, exist_ok=False)
    report = dict(data_kind='synthetic_controlled', python=sys.version,
                  executable=sys.executable, platform=platform.platform(),
                  memory_metric='tracemalloc Python allocations, not RSS', core=[])
    for size in args.sizes:
        run = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--worker', str(size)],
                             cwd=ROOT, capture_output=True, text=True, timeout=180, check=True)
        report['core'].append(json.loads(run.stdout))
    report['live'] = live_trial(args.output, args.live_records)
    (args.output / 'baseline.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Verified baseline: ' + str(args.output / 'baseline.json'))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, queue.Empty) as exc:
        print('Baseline failed: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
