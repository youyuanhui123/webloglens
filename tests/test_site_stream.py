import json
import unittest

from webloglens.ingest import parse_access_line
from webloglens.site_stream import SiteAnalyzer


def record(site, path, second=0):
    item = dict(schema='webloglens-nginx-1', time=f'2026-11-18T10:00:{second:02d}+08:00',
                ip='192.0.2.10', method='GET', target=path, protocol='HTTP/1.1', status=404,
                body_bytes=10, site=site, request_time=0.001, request_id='synthetic')
    raw = json.dumps(item)
    return dict(raw=raw, fields=parse_access_line(raw, 'nginx-json'), source='synthetic',
                offset=0, generation=1, line_number=1)


class SiteStreamTests(unittest.TestCase):
    def test_site_capacity_is_bounded_but_excluded_site_still_has_exact_findings(self):
        analyzer = SiteAnalyzer(max_sites=1, lateness_seconds=0, max_window_records=2)
        analyzer.feed(record('a.local', '/a'), 0)
        events = analyzer.feed(record('b.local', '/.env'), 1)
        self.assertEqual([e['type'] for e in events], ['finding', 'state_limit'])
        self.assertTrue(all(e['site'] == 'b.local' for e in events))
        self.assertEqual(events[-1]['reason'], 'max_sites')
        for number in range(20):
            analyzer.feed(record(str(number) + '.local', '/'), number + 2)
        summary = analyzer.snapshot()
        self.assertEqual(summary['allocated_sites'], 1)
        self.assertEqual(summary['records'], 22)
        self.assertEqual(summary['state_limits'], 21)
        self.assertEqual(summary['path_findings'], 1)
        self.assertEqual(summary['status_counts'], {'404': 22})
        self.assertEqual(summary['capacity_scope'], 'per-site limits; first admitted sites retained for run')
        self.assertEqual(summary['aggregate_upper_bounds']['window_records'], 2)
        for bad in (0, True, 129):
            with self.assertRaises(ValueError):
                SiteAnalyzer(max_sites=bad)
        with self.assertRaises(ValueError):
            SiteAnalyzer(max_buffer=0)

    def test_watermark_and_cooldown_of_one_site_do_not_exclude_another(self):
        analyzer = SiteAnalyzer(lateness_seconds=0, min_paths=2, cooldown_seconds=100)
        events = []
        for number, item in enumerate([record('a.local', '/a', 40), record('a.local', '/b', 41),
                                       record('b.local', '/a', 0), record('b.local', '/b', 1),
                                       record('a.local', '/c', 42), record('b.local', '/c', 2)]):
            events += analyzer.feed(item, number)
        self.assertEqual([(e['type'], e['site']) for e in events], [('finding', 'a.local'), ('finding', 'b.local')])
        self.assertEqual(analyzer.snapshot().get('late_records', 0), 0)
        self.assertEqual(analyzer.snapshot()['suppressed_windows'], 2)

    def test_idle_flush_is_per_site_and_summary_retains_partition_identity(self):
        analyzer = SiteAnalyzer(lateness_seconds=2, min_paths=2)
        analyzer.feed(record('a.local', '/a'), 0)
        analyzer.feed(record('a.local', '/b'), 0)
        analyzer.feed(record('b.local', '/c'), 10)
        events = analyzer.tick(10)
        self.assertEqual([(e['type'], e['site']) for e in events], [('finding', 'a.local')])
        summary = analyzer.snapshot()
        self.assertEqual(summary['buffered_records'], 1)
        self.assertEqual(summary['sites']['a.local']['records'], 2)
        self.assertEqual(summary['sites']['b.local']['records'], 1)
        analyzer.finish()
        analyzer.tick(200)
        self.assertEqual(analyzer.snapshot()['active_ips'], 0)
        self.assertEqual(analyzer.snapshot()['records'], 3)

    def test_invalid_site_is_rejected_without_allocating_partition_or_counting_record(self):
        analyzer = SiteAnalyzer()
        for value in (None, '', 'two sites', 'a\x00b', 17):
            item = record('valid.local', '/')
            item['fields']['site'] = value
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    analyzer.feed(item, 0)
        self.assertEqual(analyzer.snapshot()['allocated_sites'], 0)
        self.assertEqual(analyzer.snapshot()['records'], 0)

    def test_cli_invalid_site_budget_does_not_create_output(self):
        from pathlib import Path
        import subprocess
        import sys
        import tempfile
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'events.jsonl'
            for fmt, value in [('nginx-json', '0'), ('nginx-json', '129'), ('combined', '1')]:
                run = subprocess.run([sys.executable, str(root / 'watch.py'),
                                      str(root / 'examples/synthetic_nginx.jsonl'), '--replay',
                                      '--log-format', fmt, '--max-sites', value, '--output', str(output)],
                                     capture_output=True, timeout=10)
                self.assertNotEqual(run.returncode, 0)
                self.assertFalse(output.exists())
                self.assertNotIn(b'Traceback', run.stderr)

    def test_preflight_site_count_is_bounded_and_reported_as_lower_bound(self):
        from pathlib import Path
        import tempfile
        from webloglens.ingest import inspect_log
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_text(''.join(record(str(n) + '.local', '/')['raw'] + '\n' for n in range(50)), encoding='utf-8')
            result = inspect_log(path, 'nginx-json')
            self.assertEqual(result['counts']['parsed'], 50)
            self.assertEqual(result['site_count_observed_at_least'], 17)
            self.assertLessEqual(len(result['site_samples']), 20)
            self.assertTrue(result['site_capacity_exceeded'])
            self.assertFalse(result['ready_for_detection'])

    def test_windows_do_not_mix_sites_and_findings_have_site_identity(self):
        analyzer = SiteAnalyzer(lateness_seconds=0, min_paths=2)
        output = analyzer.feed(record('a.local', '/a'), 0)
        output += analyzer.feed(record('b.local', '/b'), 1)
        self.assertFalse(output)
        output += analyzer.feed(record('a.local', '/c'), 2)
        output += analyzer.feed(record('b.local', '/d'), 3)
        output += analyzer.finish()
        self.assertEqual([(e['site'], e['paths']) for e in output],
                         [('a.local', ['/a', '/c']), ('b.local', ['/b', '/d'])])
        for event in output:
            self.assertTrue(all(r['fields']['site'] == event['site'] for r in event['evidence']))
        summary = analyzer.snapshot()
        self.assertEqual(summary['records'], 4)
        self.assertEqual(summary['window_findings'], 2)
        self.assertEqual(summary['allocated_sites'], 2)


if __name__ == '__main__':
    unittest.main()
