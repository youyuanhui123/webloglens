import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NginxRunnerCliTests(unittest.TestCase):
    def test_help_explains_local_image_and_output_without_starting_docker(self):
        result = subprocess.run([sys.executable, str(ROOT / 'run_nginx_experiment.py'), '--help'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--image', result.stdout)
        self.assertIn('--output', result.stdout)


if __name__ == '__main__':
    unittest.main()
