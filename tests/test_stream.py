import unittest
from webloglens.parser import parse_line
from webloglens.stream import StreamAnalyzer


def record(second, path='/', ip='192.0.2.10'):
    raw = (f'{ip} - - [05/Nov/2026:10:00:{second:02d} +0800] '
           f'"GET {path} HTTP/1.1" 404 10 "-" "test"')
    return dict(raw=raw, fields=parse_line(raw), line_number=second + 1,
                source='access.log', generation=1, offset=second * 100)


class StreamTests(unittest.TestCase):
    def test_seeded_reordered_corpora_match_v1_first_windows_with_sufficient_budget(self):
        import random
        from webloglens.behavior import detect_path_bursts
        rng = random.Random(17)
        for _ in range(20):
            records = [record(rng.randrange(60), '/' + str(rng.randrange(5)),
                              ip='192.0.2.' + str(rng.randrange(2) + 10)) for _ in range(30)]
            rng.shuffle(records)
            analyzer = StreamAnalyzer(lateness_seconds=60, cooldown_seconds=60, min_paths=3)
            output = []
            for number, item in enumerate(records):
                output += analyzer.feed(item, now=number)
            output += analyzer.finish()
            actual = [e for e in output if e.get('rule_id') == 'multi-path-window-v2']
            expected = detect_path_bursts(records, min_paths=3)['findings']
            def signature(events):
                return sorted((e['ip'], e['start_time'], e['end_time'],
                               e['request_count'], e['distinct_path_count']) for e in events)
            self.assertEqual(signature(actual), signature(expected))

    def test_watermark_rejects_records_beyond_lateness_even_before_first_commit(self):
        analyzer = StreamAnalyzer(lateness_seconds=2)
        analyzer.feed(record(40), now=0)
        event = analyzer.feed(record(0), now=1)[0]
        self.assertEqual(event['type'], 'late_record')
        self.assertEqual(analyzer.snapshot()['late_records'], 1)
        self.assertEqual(analyzer.snapshot()['status_counts'], {'404': 2})

    def test_repeated_path_queries_do_not_count_as_distinct_and_ips_do_not_mix(self):
        analyzer = StreamAnalyzer(lateness_seconds=0, min_paths=2, cooldown_seconds=2)
        output = []
        output += analyzer.feed(record(0, '/a?x=1'), now=0)
        output += analyzer.feed(record(1, '/a?x=2'), now=1)
        output += analyzer.feed(record(2, '/b', ip='192.0.2.20'), now=2)
        self.assertFalse(output)
        output += analyzer.feed(record(2, '/b'), now=3)
        output += analyzer.feed(record(4, '/c'), now=4)
        self.assertEqual(len([e for e in output if e['type'] == 'finding']), 2)

    def test_idle_flush_late_exclusion_and_expiry(self):
        analyzer = StreamAnalyzer(window_seconds=10, lateness_seconds=2)
        self.assertEqual(analyzer.feed(record(10), now=0), [])
        self.assertEqual(analyzer.snapshot()['buffered_records'], 1)
        analyzer.tick(now=2)
        self.assertEqual(analyzer.snapshot()['buffered_records'], 0)
        events = analyzer.feed(record(1, '/.env'), now=3)
        self.assertEqual([e['type'] for e in events], ['finding', 'late_record'])
        analyzer.tick(now=100)
        self.assertEqual(analyzer.snapshot()['active_ips'], 0)

    def test_limits_are_explicit_and_state_stays_bounded(self):
        analyzer = StreamAnalyzer(lateness_seconds=10, max_buffer=2,
                                  max_window_records=2, max_ips=1)
        analyzer.feed(record(1), now=0)
        analyzer.feed(record(1), now=1)
        self.assertEqual(analyzer.feed(record(1), now=2)[0]['type'], 'state_limit')
        analyzer.finish()
        self.assertLessEqual(analyzer.snapshot()['window_records'], 2)
        second = StreamAnalyzer(lateness_seconds=0, max_window_records=2, max_ips=1)
        second.feed(record(1), now=0)
        event = second.feed(record(2, ip='192.0.2.20'), now=1)[0]
        self.assertEqual(event['reason'], 'max_ips')
        second.feed(record(2), now=2)
        self.assertEqual(second.feed(record(3), now=3)[0]['reason'], 'max_window_records')
        self.assertEqual(second.snapshot()['window_records'], 2)

    def test_invalid_time_does_not_disable_exact_detection(self):
        analyzer = StreamAnalyzer()
        bad = record(0, '/.env')
        bad['fields']['time'] = 'invalid'
        self.assertEqual([e['type'] for e in analyzer.feed(bad, now=0)], ['finding', 'time_error'])

    def test_reorders_window_includes_boundary_and_cools_repeated_alerts(self):
        analyzer = StreamAnalyzer(window_seconds=10, min_paths=3, lateness_seconds=2,
                                  cooldown_seconds=10)
        output = []
        for second, path in [(0, '/a'), (10, '/c'), (9, '/b'), (11, '/d')]:
            output += analyzer.feed(record(second, path), now=second)
        output += analyzer.finish()
        windows = [e for e in output if e.get('rule_id') == 'multi-path-window-v2']
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0]['distinct_path_count'], 3)
        self.assertEqual([r['fields']['target'] for r in windows[0]['evidence']], ['/a', '/b', '/c'])
        self.assertEqual(analyzer.snapshot()['suppressed_windows'], 1)
        self.assertEqual(analyzer.snapshot()['buffered_records'], 0)

    def test_sensitive_path_reuses_existing_rule_and_preserves_source(self):
        analyzer = StreamAnalyzer()
        events = analyzer.feed(record(1, '/.env?x=1'), now=0)
        finding = next(e for e in events if e['type'] == 'finding')
        self.assertEqual(finding['rule_id'], 'sensitive-path-exact-v1')
        self.assertEqual(finding['evidence'][0]['offset'], 100)
        self.assertEqual(analyzer.snapshot()['records'], 1)
        self.assertFalse(analyzer.feed(record(2, '/login?next=/.env'), now=1))


if __name__ == '__main__':
    unittest.main()
