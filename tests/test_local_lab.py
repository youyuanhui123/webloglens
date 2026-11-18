import json
from pathlib import Path
import socket
import tempfile
import unittest

from webloglens.local_lab import run_local_experiment
from webloglens.reader import read_log
from webloglens.detector import detect_sensitive_paths
from webloglens.behavior import detect_path_bursts


class LocalLabTests(unittest.TestCase):
    def test_real_http_requests_are_logged_and_server_is_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'mixed'
            manifest = run_local_experiment(output, scenario='mixed')
            saved = json.loads((output / 'manifest.json').read_text(encoding='utf-8'))
            self.assertEqual(saved, manifest)
            self.assertEqual(manifest['server_host'], '127.0.0.1')
            self.assertEqual(manifest['data_kind'], 'local-experiment')
            self.assertEqual([r['status'] for r in manifest['requests']], [200, 200, 200, 404, 404, 404])
            self.assertTrue(all(r['body_bytes'] > 0 for r in manifest['requests']))
            result = read_log(output / 'access.log')
            self.assertEqual(len(result['records']), 6)
            self.assertEqual(result['errors'], [])
            self.assertEqual([r['fields']['target'] for r in result['records']],
                             [r['target'] for r in manifest['requests']])
            self.assertEqual(len(detect_sensitive_paths(result['records'])), 2)
            self.assertEqual(len(detect_path_bursts(result['records'])['findings']), 1)
            with socket.socket() as check:
                check.settimeout(1)
                self.assertNotEqual(check.connect_ex(('127.0.0.1', manifest['server_port'])), 0)

    def test_baseline_and_normal_browsing_expose_rule_boundary(self):
        with tempfile.TemporaryDirectory() as folder:
            for scenario, expected_behavior in [('baseline', 0), ('normal-wide', 1)]:
                with self.subTest(scenario=scenario):
                    output = Path(folder) / scenario
                    run_local_experiment(output, scenario=scenario)
                    records = read_log(output / 'access.log')['records']
                    self.assertEqual(len(detect_sensitive_paths(records)), 0)
                    self.assertEqual(len(detect_path_bursts(records)['findings']), expected_behavior)
                    self.assertTrue(all(r['fields']['status'] == 200 for r in records))

    def test_existing_evidence_directory_is_not_reused(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(FileExistsError):
                run_local_experiment(folder)


if __name__ == '__main__':
    unittest.main()
