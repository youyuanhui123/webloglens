import copy
import json
import unittest

from webloglens.privacy import redact_report


class PrivacyTests(unittest.TestCase):
    def test_share_report_is_allowlisted_and_does_not_modify_private_report(self):
        secret = 'TOKEN-MUST-NOT-LEAK'
        record = {'line_number': 1, 'raw': secret, 'fields': {
            'ip': '192.0.2.42', 'target': '/account?token=' + secret,
            'user_agent': secret, 'referer': secret, 'time': secret}}
        finding = {'rule_id': 'sensitive-path-exact-v1', 'line_number': 1,
                   'ip': '192.0.2.42', 'target': '/account?token=' + secret,
                   'matched_path': '/account', 'status': 200, 'reason': secret, 'raw': secret}
        report = {
            'schema_version': '1.1',
            'source': {'path': 'C:/private/' + secret, 'data_kind': 'authorized', 'provenance_verified': False},
            'configuration': {'path': secret, 'effective': {
                'sensitive_paths': ['/account'], 'window_seconds': 60, 'min_paths': 5}, 'cli_overrides': {}},
            'parsing': {'total_lines': 2, 'parsed': 1, 'errors': 1, 'blank_lines': 0},
            'summary': {'request_count': 1, 'status_counts': {'200': 1},
                        'ip_counts': {'192.0.2.42': 1}, 'path_counts': {'/account': 1}},
            'finding_count': 1, 'findings': [finding], 'records': [record],
            'parse_errors': [{'line_number': 2, 'raw': secret, 'reason': secret}],
            'behavior': {'config': {'window_seconds': 60, 'min_paths': 5}, 'findings': [],
                         'time_errors': [{'line_number': 1, 'time': secret, 'raw': secret}]},
            'limitations': [secret], 'unknown_future_field': secret,
        }
        original = copy.deepcopy(report)
        shared = redact_report(report)
        text = json.dumps(shared)
        for value in [secret, '192.0.2.42', '/account', 'C:/private/']:
            self.assertNotIn(value, text)
        self.assertEqual(report, original)
        self.assertEqual(shared['privacy']['mode'], 'share-redacted')
        self.assertEqual(shared['summary']['ip_counts'], {'IP-001': 1})
        self.assertEqual(shared['summary']['path_counts'], {'PATH-001': 1})
        self.assertEqual(shared['findings'][0]['ip'], 'IP-001')
        self.assertEqual(shared['findings'][0]['matched_path'], 'PATH-001')
        self.assertEqual(shared['findings'][0]['line_number'], 1)
        self.assertNotIn('raw', shared['findings'][0])
        self.assertNotIn('records', shared)
        self.assertNotIn('unknown_future_field', shared)
        self.assertEqual(shared['finding_count'], 1)


    def test_unknown_rules_fail_closed_instead_of_exporting_future_fields(self):
        report = {
            'summary': {'request_count': 0, 'status_counts': {}, 'ip_counts': {}, 'path_counts': {}},
            'findings': [{'rule_id': 'future-rule', 'raw': 'SECRET'}],
        }
        with self.assertRaises(ValueError):
            redact_report(report)


if __name__ == '__main__':
    unittest.main()
