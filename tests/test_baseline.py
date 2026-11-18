import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BaselineTests(unittest.TestCase):
    def test_actual_baseline_checks_counts_latency_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'result'
            command = [sys.executable, str(ROOT / 'run_baseline.py'), '--output', str(output),
                       '--sizes', '20', '80', '--live-records', '4']
            run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            report = json.loads((output / 'baseline.json').read_text(encoding='utf-8'))
            self.assertEqual([r['records'] for r in report['core']], [20, 80])
            for item in report['core']:
                self.assertGreater(item['python_peak_bytes'], 0)
                self.assertEqual(item['state_limits'], 0)
            self.assertEqual(report['live']['matched_findings'], 4)
            self.assertEqual(report['live']['summary_records'], 4)
            self.assertGreaterEqual(report['live']['latency_ms']['p95'], 0)
            again = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=5)
            self.assertNotEqual(again.returncode, 0)


if __name__ == '__main__':
    unittest.main()
