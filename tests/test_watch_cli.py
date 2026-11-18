import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOOD = ('127.0.0.1 - - [05/Nov/2026:10:00:00 +0800] '
        '"GET /.env HTTP/1.1" 404 10 "-" "test"\n')


class WatchCliTests(unittest.TestCase):
    def test_live_append_outputs_records_errors_and_summary(self):
        with tempfile.TemporaryDirectory(prefix='weblog-watch-') as folder:
            path = Path(folder) / 'access.log'
            output = Path(folder) / 'events.jsonl'
            path.write_bytes(b'')
            process = subprocess.Popen(
                [sys.executable, str(ROOT / 'watch.py'), str(path), '--output', str(output),
                 '--duration', '0.6', '--interval', '0.01'], cwd=folder,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
            try:
                first = json.loads(process.stdout.readline())
                self.assertEqual(first['type'], 'started')
                with path.open('ab') as stream:
                    stream.write((GOOD + 'BROKEN\n\n').encode('utf-8'))
                stdout, stderr = process.communicate(timeout=15)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
                process.stdout.close()
                process.stderr.close()
            self.assertEqual(process.returncode, 0, stderr)
            events = [json.loads(line) for line in output.read_text(encoding='utf-8').splitlines()]
            self.assertEqual([e['type'] for e in events],
                             ['started', 'record', 'parse_error', 'blank', 'summary'])
            self.assertEqual(events[1]['fields']['target'], '/.env')
            self.assertIsNone(events[1]['line_number'])
            self.assertEqual(events[-1]['counts']['record'], 1)
            self.assertEqual(json.loads(stdout.splitlines()[-1])['type'], 'summary')
            original = output.read_bytes()
            rerun = subprocess.run(
                [sys.executable, str(ROOT / 'watch.py'), str(path), '--output', str(output),
                 '--duration', '0.01'], capture_output=True, timeout=15)
            self.assertNotEqual(rerun.returncode, 0)
            self.assertEqual(output.read_bytes(), original)

    def test_unrepresentable_sleep_interval_rejected_before_start(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / 'watch.py'), str(ROOT / 'examples/synthetic_burst.log'),
             '--interval', '1e300', '--duration', '1e300'],
            capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertNotIn(b'Traceback', result.stderr)
        self.assertIn(b'at most 60', result.stderr)

    def test_invalid_interval_rejected(self):
        result = subprocess.run([sys.executable, str(ROOT / 'watch.py'), 'unused.log',
                                 '--interval', '0'], capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'positive finite', result.stderr)


if __name__ == '__main__':
    unittest.main()
