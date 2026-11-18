import unittest

from webloglens.behavior import detect_path_bursts
from webloglens.parser import parse_line


def record(number, time, target, ip='192.0.2.10'):
    raw = f'{ip} - - [{time}] "GET {target} HTTP/1.1" 404 64 "-" "test"'
    return {'line_number': number, 'raw': raw, 'fields': parse_line(raw)}


class BehaviorTests(unittest.TestCase):
    def test_sort_events_and_include_exact_window_boundary(self):
        records = [
            record(1, '05/Nov/2026:10:01:00 +0800', '/c'),
            record(2, '05/Nov/2026:02:00:00 +0000', '/a'),
            record(3, '05/Nov/2026:10:00:30 +0800', '/b?x=1'),
        ]
        result = detect_path_bursts(records, window_seconds=60, min_paths=3)
        self.assertEqual(result['time_errors'], [])
        self.assertEqual(len(result['findings']), 1)
        finding = result['findings'][0]
        self.assertEqual(finding['rule_id'], 'multi-path-window-v1')
        self.assertEqual(finding['ip'], '192.0.2.10')
        self.assertEqual(finding['distinct_path_count'], 3)
        self.assertEqual(finding['request_count'], 3)
        self.assertEqual(finding['paths'], ['/a', '/b', '/c'])
        self.assertEqual([r['line_number'] for r in finding['evidence']], [2, 3, 1])
        self.assertEqual(finding['evidence'][0]['raw'], records[1]['raw'])
        self.assertEqual(finding['start_time'], '2026-11-05T02:00:00+00:00')
        self.assertEqual(finding['end_time'], '2026-11-05T02:01:00+00:00')
        self.assertEqual(finding['conclusion'], 'review_required_not_proof_of_attack')

    def test_repeated_path_queries_are_not_distinct_paths(self):
        records = [record(i, '05/Nov/2026:10:00:00 +0800', f'/search?q={i}')
                   for i in range(1, 8)]
        self.assertEqual(detect_path_bursts(records, min_paths=2)['findings'], [])

    def test_expired_paths_and_other_ips_do_not_complete_window(self):
        records = [
            record(1, '05/Nov/2026:10:00:00 +0800', '/a'),
            record(2, '05/Nov/2026:10:01:01 +0800', '/b'),
            record(3, '05/Nov/2026:10:01:01 +0800', '/c', '192.0.2.20'),
        ]
        self.assertEqual(detect_path_bursts(records, min_paths=2)['findings'], [])

    def test_invalid_time_is_reported_but_other_events_continue(self):
        records = [
            record(1, '31/Feb/2026:10:00:00 +0800', '/a'),
            record(2, '05/Nov/2026:10:00:00 +0800', '/b'),
            record(3, '05/Nov/2026:10:00:01 +0800', '/c'),
        ]
        result = detect_path_bursts(records, min_paths=2)
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual([e['line_number'] for e in result['time_errors']], [1])

    def test_only_first_qualifying_window_per_ip(self):
        records = [record(i, '05/Nov/2026:10:00:00 +0800', f'/path{i}')
                   for i in range(1, 5)]
        result = detect_path_bursts(records, min_paths=2)
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['request_count'], 2)

    def test_empty_input(self):
        self.assertEqual(detect_path_bursts([]), {'findings': [], 'time_errors': []})

    def test_invalid_thresholds_are_rejected(self):
        for options in [{'window_seconds': 0}, {'window_seconds': True},
                        {'min_paths': 1}, {'min_paths': 2.5}]:
            with self.subTest(options=options), self.assertRaises(ValueError):
                detect_path_bursts([], **options)


if __name__ == '__main__':
    unittest.main()
