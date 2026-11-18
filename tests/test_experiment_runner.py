import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ExperimentRunnerTests(unittest.TestCase):
    def test_one_command_creates_private_and_share_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / '中文证据'
            run = subprocess.run([sys.executable, str(ROOT / 'run_experiment.py'),
                                  '--output-root', str(output)], cwd=folder,
                                 capture_output=True, text=True, encoding='utf-8', timeout=60)
            self.assertEqual(run.returncode, 0, run.stderr)
            summary = json.loads((output / 'summary.json').read_text(encoding='utf-8'))
            self.assertTrue(summary['all_passed'])
            self.assertTrue((output / 'REPORT.md').exists())
            for result in summary['results']:
                directory = output / result['scenario']
                self.assertEqual(result['report_path'], result['scenario'] + '/report.json')
                self.assertTrue((output / result['report_path']).is_file())
                self.assertTrue(result['server_port_closed_verified'])
                self.assertEqual(hashlib.sha256((directory / 'access.log').read_bytes()).hexdigest(),
                                 result['access_log_sha256'])
                for name in ['report.json', 'analysis.md', 'share.json', 'share.md']:
                    self.assertTrue((directory / name).is_file(), name)
                public = json.loads((directory / 'share.json').read_text(encoding='utf-8'))
                self.assertEqual(public['privacy']['mode'], 'share-redacted')
                self.assertEqual(public['finding_count'], result['sensitive_findings'] + result['behavior_findings'])
                for name in ['share.json', 'share.md']:
                    text = (directory / name).read_text(encoding='utf-8')
                    self.assertNotIn('127.0.0.1', text)
                    self.assertNotIn(str(output), text)
                    self.assertNotIn('/.env', text)
            before = (output / 'summary.json').read_bytes()
            repeat = subprocess.run([sys.executable, str(ROOT / 'run_experiment.py'),
                                     '--output-root', str(output)], cwd=folder,
                                    capture_output=True, text=True, encoding='utf-8', timeout=15)
            self.assertNotEqual(repeat.returncode, 0)
            self.assertNotIn('Traceback', repeat.stderr)
            self.assertEqual((output / 'summary.json').read_bytes(), before)
            moved = Path(folder) / '搬迁后的证据'
            output.rename(moved)
            for result in summary['results']:
                self.assertTrue((moved / result['report_path']).is_file())


if __name__ == '__main__':
    unittest.main()
