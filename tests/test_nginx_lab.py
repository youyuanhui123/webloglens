import json
import os

import tempfile
import unittest
from pathlib import Path

from webloglens.nginx_lab import prepare_files


class NginxLabTests(unittest.TestCase):
    def test_config_uses_nginx_combined_and_fixed_responses_not_real_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'scenario'
            paths = prepare_files(root)
            config = paths['config'].read_text(encoding='utf-8')
            self.assertIn('access_log /evidence/access.log combined;', config)
            self.assertIn('location = /ready', config)
            self.assertIn('access_log off;', config)
            self.assertIn('location = /.env', config)
            self.assertIn('return 404', config)
            self.assertNotIn('proxy_pass', config)
            self.assertNotIn('alias ', config)
            self.assertEqual(paths['log'].read_bytes(), b'')
            with self.assertRaises(FileExistsError):
                prepare_files(root)
    def test_listener_parser_does_not_confuse_other_ports_or_established_connections(self):
        from webloglens.nginx_lab import _listeners_for_port
        rows = ('TCP 127.0.0.1:8080 127.0.0.1:40000 TIME_WAIT 0\n'
                'TCP 127.0.0.1:80800 0.0.0.0:0 LISTENING 123\n')
        self.assertEqual(_listeners_for_port(8080, rows), [])
        self.assertEqual(len(_listeners_for_port(80800, rows)), 1)
        self.assertEqual(len(_listeners_for_port(8080,
            'TCP 0.0.0.0:8080 0.0.0.0:0 LISTENING 123\n')), 1)

    def test_port_release_probe_distinguishes_listener_from_free_port(self):
        import socket
        from webloglens.nginx_lab import _port_released
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            port = server.getsockname()[1]
            server.listen()
            self.assertFalse(_port_released(port))
        self.assertTrue(_port_released(port))

    @unittest.skipUnless(os.environ.get('WEBLOGLENS_NGINX_TEST') == '1',
                         'opt-in actual Docker/Nginx integration')
    def test_real_nginx_all_scenarios_live_replay_and_cleanup(self):
        from webloglens.nginx_lab import run_experiment
        with tempfile.TemporaryDirectory(prefix='weblog-nginx-') as folder:
            result = run_experiment(Path(folder) / 'evidence')
            self.assertEqual(len(result['scenarios']), 3)
            for scenario in result['scenarios']:
                self.assertTrue(scenario['verified'])
                self.assertTrue(scenario['cleanup']['container_removed'])
                self.assertTrue(scenario['cleanup']['port_closed'])
                self.assertEqual(scenario['actual'], scenario['expected'])
                self.assertTrue(scenario['matched_live_replay'])
                events = [json.loads(line) for line in
                          (Path(folder) / 'evidence' / scenario['name'] / 'live.jsonl')
                          .read_text(encoding='utf-8').splitlines()]
                self.assertEqual(events[-1]['type'], 'summary')
                self.assertEqual(events[-1]['analysis']['records'], scenario['request_count'])
    @unittest.skipUnless(os.environ.get('WEBLOGLENS_NGINX_TEST') == '1',
                         'opt-in actual Docker/Nginx failure cleanup')
    def test_request_failure_still_removes_only_its_container(self):
        from unittest.mock import patch
        from webloglens import nginx_lab
        original = nginx_lab._request
        def fail_after_ready(opener, base, target):
            if target != '/ready':
                raise RuntimeError('injected request failure')
            return original(opener, base, target)
        with tempfile.TemporaryDirectory(prefix='weblog-nginx-failure-') as folder:
            evidence = Path(folder) / 'evidence'
            with patch.object(nginx_lab, '_request', fail_after_ready):
                with self.assertRaisesRegex(RuntimeError, 'injected request failure'):
                    nginx_lab.run_experiment(evidence)
            cleanup = json.loads((evidence / 'baseline/cleanup.json').read_text(encoding='utf-8'))
            self.assertTrue(cleanup['container_removed'])
            self.assertTrue(cleanup['port_closed'])
            summary = json.loads((evidence / 'summary.json').read_text(encoding='utf-8'))
            self.assertFalse(summary['verified'])
            self.assertIn('injected request failure', summary['error'])


if __name__ == '__main__':
    unittest.main()
