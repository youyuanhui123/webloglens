import unittest

from webloglens.report import render_markdown


class ReportTests(unittest.TestCase):
    def test_render_summary_evidence_and_limits(self):
        report = {
            'schema_version': '1.1',
            'source': {'path': 'input.log', 'data_kind': 'synthetic', 'provenance_verified': False},
            'parsing': {'total_lines': 2, 'parsed': 1, 'errors': 1, 'blank_lines': 0},
            'summary': {'request_count': 1, 'status_counts': {'404': 1},
                        'ip_counts': {'192.0.2.10': 1}, 'path_counts': {'/.env': 1}},
            'finding_count': 1,
            'findings': [{'rule_id': 'sensitive-path-exact-v1', 'line_number': 1,
                          'target': '/.env', 'raw': '<script>alert(1)</script> ```\n# forged heading'}],
            'parse_errors': [{'line_number': 2, 'raw': 'BROKEN'}],
            'behavior': {'config': {'window_seconds': 60, 'min_paths': 5}, 'time_errors': []},
            'limitations': ['Indicators only'],
        }
        report['configuration'] = {'effective': {'sensitive_paths': ['/backup.zip']}}
        text = render_markdown(report)
        self.assertIn('"effective_configuration"', text)
        self.assertIn('/backup.zip', text)
        self.assertIn('# WebLogLens 日志分析报告', text)
        self.assertIn('合成测试数据', text)
        self.assertIn('| 成功解析 | 1 |', text)
        self.assertIn('192.0.2.10', text)
        self.assertIn('sensitive-path-exact-v1', text)
        self.assertIn('"line_number": 1', text)
        self.assertIn('BROKEN', text)
        self.assertIn('Indicators only', text)
        self.assertNotIn('\n# forged heading', text)
        self.assertIn('    {', text)
        self.assertIn('未自动脱敏', text)


    def test_empty_report_does_not_claim_no_attack(self):
        report = {
            'source': {'data_kind': 'unspecified'},
            'parsing': {'total_lines': 0, 'parsed': 0, 'errors': 0, 'blank_lines': 0},
            'summary': {'status_counts': {}, 'ip_counts': {}, 'path_counts': {}},
            'finding_count': 0, 'findings': [],
        }
        text = render_markdown(report)
        self.assertIn('来源未声明', text)
        self.assertIn('不等于系统安全或没有攻击', text)
        self.assertNotIn('### 线索 1', text)


if __name__ == '__main__':
    unittest.main()
