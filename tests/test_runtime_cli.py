import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def cli(*args):
    return subprocess.run([sys.executable, *map(str, args)], cwd=ROOT,
                          capture_output=True, text=True, encoding='utf-8', timeout=15)


class RuntimeCliTests(unittest.TestCase):
    def test_late_record_summary_cannot_look_healthy(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'late.log'
            log.write_text(''.join('192.0.2.1 - - [05/Nov/2026:10:00:' + second +
                                    ' +0800] "GET /a HTTP/1.1" 200 10 "-" "test"\n'
                                    for second in ('10', '00')), encoding='utf-8')
            result = cli('watch.py', log, '--replay', '--lateness-seconds', '0')
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout.splitlines()[-1])
            self.assertEqual(summary['counts']['late_record'], 1)
            self.assertEqual(summary['health']['state'], 'analysis_gap')
            self.assertTrue(summary['health']['late_records'])

    def test_midstream_output_io_failure_exits_nonzero_and_manifest_stays_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / 'input.log'
            log.touch()
            code = '''import runpy, sys
from webloglens.output import RollingOutput
original = RollingOutput.write
def fail(self, line):
    if self.first_type is not None:
        raise OSError('injected output write failure')
    return original(self, line)
RollingOutput.write = fail
sys.argv = ['watch.py', sys.argv[1], '--replay', '--output-dir', sys.argv[2], '--output-max-bytes', '100']
runpy.run_path('watch.py', run_name='__main__')
'''
            result = cli('-c', code, log, root / 'run')
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('injected output write failure', result.stderr)
            manifest = json.loads((root / 'run' / 'manifest.json').read_text())
            self.assertFalse(manifest['complete'])

    def test_retention_cli_cannot_export_partial_evidence_as_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / 'input.log'
            log.touch()
            result = cli('watch.py', log, '--replay', '--output-dir', root / 'run',
                         '--output-max-bytes', '1', '--output-keep-shards', '1')
            self.assertEqual(result.returncode, 0, result.stderr)
            result = cli('-m', 'webloglens.output', 'assemble', root / 'run',
                         '--output', root / 'partial.jsonl')
            self.assertEqual(result.returncode, 1)
            self.assertIn('deleted', result.stderr)
            self.assertFalse((root / 'partial.jsonl').exists())

    def test_invalid_rolling_options_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'input.log'
            log.touch()
            for args in [('--output-dir', str(Path(tmp) / 'run')),
                         ('--output-max-bytes', '1'), ('--output-keep-shards', '1'),
                         ('--output-dir', str(Path(tmp) / 'run'), '--output-max-bytes', '0'),
                         ('--output-dir', str(Path(tmp) / 'run'), '--output-max-bytes', '1',
                          '--output-keep-shards', '0')]:
                self.assertEqual(cli('watch.py', log, '--replay', *args).returncode, 2)

    def test_health_distinguishes_waiting_missing_parse_and_capacity_without_clean_verdict(self):
        import watch
        cases = [({}, False, False, 'waiting'), ({}, True, False, 'input_missing'),
                 ({'parse_error': 2}, False, True, 'parse_problem'),
                 ({'decode_error': 1}, False, False, 'parse_problem'),
                 ({'time_error': 1}, False, True, 'parse_problem'),
                 ({'line_too_long': 1}, False, False, 'parse_problem'),
                 ({'late_record': 1}, False, True, 'analysis_gap'),
                 ({'state_limit': 1}, False, True, 'capacity_gap'),
                 ({'record': 1}, False, True, 'healthy')]
        for counts, missing, active, state in cases:
            with self.subTest(state=state, counts=counts):
                health = watch.runtime_health(counts, missing=missing, active=active)
                self.assertEqual(health['state'], state)
        health = watch.runtime_health({'parse_error': 1, 'state_limit': 1}, missing=True)
        self.assertTrue(health['parse_problem'])
        self.assertTrue(health['capacity_gap'])
        self.assertEqual(health['input_state'], 'missing')

    def test_watch_status_exposes_parse_and_capacity_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'input.log'
            for text, extra, state in [
                ('broken line\n', [], 'parse_problem'),
                ('192.0.2.1 - - [05/Nov/2026:10:00:00 +0800] "GET /a HTTP/1.1" 404 10 "-" "test"\n' * 3,
                 ['--detect', '--max-buffer', '1'], 'capacity_gap'),
                ('', [], 'waiting')]:
                log.write_text(text, encoding='utf-8')
                result = cli('watch.py', log, '--start', 'beginning', '--duration', '.16',
                             '--interval', '.02', '--status-interval', '.01', *extra)
                self.assertEqual(result.returncode, 0, result.stderr)
                events = [json.loads(line) for line in result.stdout.splitlines()]
                statuses = [event for event in events if event['type'] == 'status']
                self.assertTrue(statuses)
                self.assertEqual(statuses[-1]['health']['state'], state)
                self.assertEqual(events[-1]['health']['state'], state)

    def test_missing_path_is_distinct_from_idle(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'input.log'
            log.touch()
            proc = subprocess.Popen([sys.executable, 'watch.py', str(log), '--duration', '.4',
                                     '--interval', '.02', '--status-interval', '.01'], cwd=ROOT,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(json.loads(proc.stdout.readline())['type'], 'started')
            log.unlink()
            stdout, stderr = proc.communicate(timeout=10)
            self.assertEqual(proc.returncode, 0, stderr)
            events = [json.loads(line) for line in stdout.splitlines()]
            self.assertEqual(events[-1]['health']['state'], 'input_missing')

    def test_rolling_replay_assembles_for_report_and_investigation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / 'input.log'
            log.write_text('192.0.2.1 - - [05/Nov/2026:10:00:00 +0800] '
                           '"GET /.env HTTP/1.1" 404 10 "-" "test"\n', encoding='utf-8')
            run = root / 'run'
            result = cli('watch.py', log, '--replay', '--output-dir', run,
                         '--output-max-bytes', '200')
            self.assertEqual(result.returncode, 0, result.stderr)
            joined = root / 'joined.jsonl'
            result = cli('-m', 'webloglens.output', 'assemble', run, '--output', joined)
            self.assertEqual(result.returncode, 0, result.stderr)
            events = [json.loads(line) for line in joined.read_text().splitlines()]
            self.assertEqual(events[0]['type'], 'started')
            self.assertEqual(events[-1]['type'], 'summary')
            self.assertEqual(events[-1]['health']['state'], 'healthy')
            for command in [('report_events.py', joined, '--format', 'json'),
                            ('investigate.py', 'import', joined, '--database', root / 'events.sqlite')]:
                result = cli(*command)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotEqual(cli('watch.py', log, '--replay', '--output-dir', run,
                                    '--output-max-bytes', '200').returncode, 0)
            self.assertNotEqual(cli('-m', 'webloglens.output', 'assemble', run,
                                    '--output', joined).returncode, 0)

    def test_single_output_remains_default_and_output_failure_is_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / 'empty.log'
            log.touch()
            target = root / 'events.jsonl'
            result = cli('watch.py', log, '--replay', '--output', target)
            self.assertEqual(result.returncode, 0, result.stderr)
            before = target.read_bytes()
            self.assertEqual(json.loads(before.splitlines()[0])['type'], 'started')
            self.assertNotEqual(cli('watch.py', log, '--replay', '--output', target).returncode, 0)
            self.assertEqual(target.read_bytes(), before)
            self.assertNotEqual(cli('watch.py', log, '--replay', '--output',
                                    root / 'missing' / 'events.jsonl').returncode, 0)
