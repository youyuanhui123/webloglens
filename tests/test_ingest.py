import json
import unittest

from webloglens.ingest import parse_access_line


def fixture(**overrides):
    item = dict(schema='webloglens-nginx-1', time='2026-11-18T10:00:00+08:00',
                ip='192.0.2.10', method='GET', target='/.env?x=%22', protocol='HTTP/1.1',
                status=404, body_bytes=12, site='demo.local', request_time=0.003,
                request_id='demo-request-1')
    item.update(overrides)
    return json.dumps(item)


class IngestTests(unittest.TestCase):
    def test_invalid_contract_is_value_error_not_a_partial_record(self):
        invalid = [fixture(status=True), fixture(status='404'), fixture(status=99),
                   fixture(body_bytes=-1), fixture(request_time=float('nan')), fixture(request_time=10 ** 400),
                   fixture(request_time=-1), fixture(request_time=True), fixture(schema='future'),
                   fixture(ip='not-an-ip'), fixture(time='2026-11-18T10:00:00'),
                   fixture(time='2026-11-18T10:00:00.123+08:00'), fixture(time='2026-11-18T10:00:00+08:99'), fixture(target='/a b'),
                   fixture(site=''), fixture(protocol='oops'), fixture(extra='unknown'),
                   fixture(method='GET\nX'), fixture(request_id=''), '[]', '{"schema":1, "schema":2}',
                   '{}', '{']
        for line in invalid:
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    parse_access_line(line, 'nginx-json')

    def test_combined_is_unchanged_and_forwarded_identity_is_not_implicitly_trusted(self):
        raw = '192.0.2.10 - - [18/Nov/2026:10:00:00 +0800] "GET / HTTP/1.1" 200 1 "-" "test"'
        from webloglens.parser import parse_line
        self.assertEqual(parse_access_line(raw), parse_line(raw))
        with self.assertRaises(ValueError):
            parse_access_line(fixture(x_forwarded_for='203.0.113.9'), 'nginx-json')
        with self.assertRaises(ValueError):
            parse_access_line(raw, 'guess')

    def test_bounded_preflight_preserves_counts_missing_capabilities_and_offsets(self):
        from webloglens.ingest import inspect_log
        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'input.log'
            content = (fixture() + '\nBROKEN\n\n' + fixture(target='/other') + '\n').encode()
            path.write_bytes(content)
            result = inspect_log(path, 'nginx-json', max_lines=10)
            self.assertEqual(result['counts'], dict(lines=4, parsed=2, errors=1, blank=1, time_errors=0))
            self.assertEqual(result['error_samples'][0]['line'], 2)
            self.assertEqual(result['error_samples'][0]['offset'], len((fixture() + '\n').encode()))
            self.assertFalse(result['ready_for_detection'])
            self.assertFalse(result['sample_limited'])
            limited = inspect_log(path, 'nginx-json', max_lines=1)
            self.assertTrue(limited['sample_limited'])
            self.assertEqual(limited['counts']['parsed'], 1)
            path.write_bytes((fixture() + '\n').encode())
            boundary = inspect_log(path, 'nginx-json', max_line_bytes=len(fixture().encode()))
            self.assertTrue(boundary['ready_for_detection'])
            path.write_bytes(b'X' * 100 + b'\n' + fixture().encode() + b'\n')
            bounded = inspect_log(path, 'nginx-json', max_line_bytes=50, max_bytes=80)
            self.assertLessEqual(bounded['bytes_read'], 80)
            self.assertTrue(bounded['sample_limited'])
            path.write_text('192.0.2.10 - - [18/Nov/2026:10:00:00 +0800] "GET / HTTP/1.1" 200 1 "-" "test"\n', encoding='utf-8')
            old = inspect_log(path)
            self.assertTrue(old['ready_for_detection'])
            self.assertIn('site', old['unavailable_fields'])
            self.assertIn('request_time', old['unavailable_fields'])

    def test_preflight_flags_partial_tail_invalid_time_changed_file_and_invalid_budgets(self):
        from webloglens.ingest import inspect_log
        from pathlib import Path
        from unittest.mock import patch
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_text(fixture(), encoding='utf-8')
            self.assertFalse(inspect_log(path, 'nginx-json')['ready_for_detection'])
            path.write_text('192.0.2.10 - - [32/Nov/2026:10:00:00 +0800] "GET / HTTP/1.1" 200 1 "-" "test"\n', encoding='utf-8')
            badtime = inspect_log(path)
            self.assertEqual(badtime['counts']['time_errors'], 1)
            self.assertFalse(badtime['ready_for_detection'])
            path.write_text(fixture() + '\n', encoding='utf-8')
            original = parse_access_line
            def append(raw, fmt):
                with path.open('ab') as output:
                    output.write(b'\n')
                return original(raw, fmt)
            with patch('webloglens.ingest.parse_access_line', side_effect=append):
                changed = inspect_log(path, 'nginx-json', max_lines=1)
            self.assertTrue(changed['source_changed'])
            self.assertFalse(changed['ready_for_detection'])
            for kwargs in [dict(max_lines=0), dict(max_bytes=True), dict(max_line_bytes=2 ** 32)]:
                with self.assertRaises(ValueError):
                    inspect_log(path, **kwargs)

    def test_json_normalizes_for_existing_core_without_rewriting_target(self):
        fields = parse_access_line(fixture(), 'nginx-json')
        self.assertEqual(fields['time'], '18/Nov/2026:10:00:00 +0800')
        self.assertEqual(fields['target'], '/.env?x=%22')
        self.assertEqual(fields['site'], 'demo.local')
        self.assertEqual(fields['request_time'], 0.003)
        self.assertEqual(fields['request_id'], 'demo-request-1')
        self.assertEqual(fields['ip'], '192.0.2.10')
        self.assertIsNone(fields['user_agent'])


class IngestCliTests(unittest.TestCase):
    def test_json_live_replay_and_stage_report_share_existing_core(self):
        import subprocess
        import sys
        from pathlib import Path
        import tempfile
        root = Path(__file__).resolve().parents[1]
        content = fixture() + '\nBROKEN\n' + fixture(target='/other') + '\n'
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_bytes(b'')
            events_path = Path(folder) / 'events.jsonl'
            command = [sys.executable, str(root / 'watch.py'), str(path), '--detect',
                       '--log-format', 'nginx-json', '--min-paths', '2', '--interval', '0.01']
            live = subprocess.Popen(command + ['--duration', '0.5', '--output', str(events_path)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, encoding='utf-8')
            try:
                started = json.loads(live.stdout.readline())
                self.assertEqual(started['log_format'], 'nginx-json')
                with path.open('ab') as output:
                    output.write(content.encode())
                stdout, stderr = live.communicate(timeout=10)
            finally:
                if live.poll() is None:
                    live.kill()
                    live.communicate()
                live.stdout.close()
                live.stderr.close()
            self.assertEqual(live.returncode, 0, stderr)
            left = [json.loads(s) for s in stdout.splitlines()]
            replay = subprocess.run(command + ['--replay'], capture_output=True, text=True,
                                    encoding='utf-8', timeout=10)
            self.assertEqual(replay.returncode, 0, replay.stderr)
            right = [json.loads(s) for s in replay.stdout.splitlines()]
            for events in (left, right):
                summary = events[-1]
                self.assertEqual(summary['counts']['record'], 2)
                self.assertEqual(summary['counts']['parse_error'], 1)
                self.assertEqual(summary['counts']['finding'], 2)
                records = [e for e in events if e['type'] == 'record']
                self.assertEqual(records[0]['raw'], fixture())
                self.assertEqual(records[0]['fields']['site'], 'demo.local')
            report = subprocess.run([sys.executable, str(root / 'report_events.py'), str(events_path),
                                     '--format', 'json'], capture_output=True, text=True, encoding='utf-8')
            self.assertEqual(report.returncode, 0, report.stderr)
            quality = json.loads(report.stdout)['quality']
            self.assertTrue(quality['event_stream_complete'])
            self.assertTrue(quality['analysis_has_gaps'])

    def test_multi_site_is_isolated_and_capacity_exclusion_is_not_parse_error(self):
        from webloglens.ingest import inspect_log
        import subprocess
        import sys
        from pathlib import Path
        import tempfile
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_text(fixture(target='/a') + '\n' + fixture(site='other.local', target='/b') + '\n', encoding='utf-8')
            checked = inspect_log(path, 'nginx-json')
            self.assertTrue(checked['ready_for_detection'])
            self.assertTrue(checked['multiple_sites'])
            self.assertFalse(inspect_log(path, 'nginx-json', max_sites=1)['ready_for_detection'])
            command = [sys.executable, str(root / 'watch.py'), str(path), '--replay',
                       '--log-format', 'nginx-json', '--min-paths', '2']
            run = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            events = [json.loads(s) for s in run.stdout.splitlines()]
            self.assertEqual(events[-1]['counts'].get('finding', 0), 0)
            self.assertEqual(events[-1]['counts'].get('parse_error', 0), 0)
            self.assertEqual(events[-1]['analysis']['allocated_sites'], 2)
            self.assertEqual(events[-1]['analysis']['records'], 2)
            output = Path(folder) / 'limited.jsonl'
            limited = subprocess.run(command + ['--max-sites', '1', '--output', str(output)],
                                     capture_output=True, text=True, encoding='utf-8', timeout=10)
            self.assertEqual(limited.returncode, 0, limited.stderr)
            events = [json.loads(s) for s in limited.stdout.splitlines()]
            self.assertEqual(events[-1]['counts']['state_limit'], 1)
            self.assertEqual(events[-1]['analysis']['records'], 2)
            report = subprocess.run([sys.executable, str(root / 'report_events.py'), str(output), '--format', 'json'],
                                    capture_output=True, text=True, encoding='utf-8', timeout=10)
            self.assertEqual(report.returncode, 0, report.stderr)
            quality = json.loads(report.stdout)['quality']
            self.assertTrue(quality['event_stream_complete'])
            self.assertIn('capacity_limit_excluded', quality['issues'])


    def test_preflight_cli_outputs_private_report_and_refuses_overwrite(self):
        import subprocess
        import sys
        from pathlib import Path
        import tempfile
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            source, output = Path(folder) / 'input.log', Path(folder) / 'check.json'
            source.write_text(fixture() + '\n', encoding='utf-8')
            command = [sys.executable, str(root / 'check_input.py'), str(source),
                       '--log-format', 'nginx-json', '--output', str(output)]
            run = subprocess.run(command, cwd=folder, capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            report = json.loads(output.read_text(encoding='utf-8'))
            self.assertTrue(report['ready_for_detection'])
            self.assertTrue(report['private'])
            again = subprocess.run(command, capture_output=True, timeout=10)
            self.assertNotEqual(again.returncode, 0)
            invalid = subprocess.run(command[:-2] + ['--max-lines', '0'], capture_output=True, timeout=10)
            self.assertNotEqual(invalid.returncode, 0)


if __name__ == '__main__':
    unittest.main()
