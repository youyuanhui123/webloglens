import unittest

from webloglens.detector import detect_sensitive_paths
from webloglens.parser import parse_line


class DetectorTests(unittest.TestCase):
    def test_exact_sensitive_path_with_evidence_and_query_boundaries(self):
        targets = [
            '/.env', '/.git/config?download=1',
            '/login?next=/.env', '/.env.example', '/',
        ]
        records = []
        for number, target in enumerate(targets, start=1):
            raw = (f'192.0.2.10 - - [05/Nov/2026:10:00:00 +0800] '
                   f'"GET {target} HTTP/1.1" 404 64 "-" "LearningClient/1.0"')
            records.append({
                'line_number': number, 'raw': raw, 'fields': parse_line(raw),
            })
        findings = detect_sensitive_paths(records)
        self.assertEqual(len(findings), 2)
        self.assertEqual([f['line_number'] for f in findings], [1, 2])
        self.assertEqual(findings[0]['rule_id'], 'sensitive-path-exact-v1')
        self.assertEqual(findings[0]['raw'], records[0]['raw'])
        self.assertEqual(findings[0]['ip'], '192.0.2.10')
        self.assertEqual(findings[0]['status'], 404)
        self.assertEqual(findings[1]['target'], '/.git/config?download=1')
        self.assertEqual(findings[1]['matched_path'], '/.git/config')
        self.assertIn('/.env', findings[0]['reason'])
        self.assertEqual(findings[0]['conclusion'], 'suspicious_access_only')


    def test_custom_paths_replace_defaults_and_empty_list_disables_matches(self):
        raw = ('192.0.2.10 - - [05/Nov/2026:10:00:00 +0800] '
               '"GET /backup.zip HTTP/1.1" 404 64 "-" "test"')
        records = [{'line_number': 1, 'raw': raw, 'fields': parse_line(raw)}]
        self.assertEqual(len(detect_sensitive_paths(records, sensitive_paths=['/backup.zip'])), 1)
        self.assertEqual(detect_sensitive_paths(records, sensitive_paths=[]), [])
        self.assertEqual(detect_sensitive_paths(records), [])


if __name__ == '__main__':
    unittest.main()
