import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class EventReportCliTests(unittest.TestCase):
    def test_actual_replay_exports_both_formats_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory(prefix='weblog-report-') as folder:
            events = Path(folder) / 'events.jsonl'
            created = subprocess.run([sys.executable, str(ROOT / 'watch.py'),
                str(ROOT / 'examples/synthetic_sensitive.log'), '--replay', '--min-paths', '3',
                '--output', str(events)], capture_output=True, timeout=15)
            self.assertEqual(created.returncode, 0, created.stderr)
            original = events.read_bytes()
            for form, extension in [('json', 'json'), ('markdown', 'md')]:
                output = Path(folder) / ('report.' + extension)
                command = [sys.executable, str(ROOT / 'report_events.py'), str(events),
                           '--format', form, '--output', str(output), '--max-samples', '1']
                result = subprocess.run(command, cwd=folder, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                content = output.read_text(encoding='utf-8')
                if form == 'json':
                    report = json.loads(content)
                    self.assertEqual(report['observed']['counts']['record'], 5)
                    self.assertEqual(report['observed']['counts']['finding'], 3)
                    self.assertTrue(report['quality']['event_stream_complete'])
                    self.assertEqual(report['samples']['omitted'], 2)
                else:
                    self.assertIn('阶段排查报告', content)
                    self.assertIn('省略 2', content)
                again = subprocess.run(command, capture_output=True, timeout=15)
                self.assertNotEqual(again.returncode, 0)
                self.assertEqual(output.read_text(encoding='utf-8'), content)
            self.assertEqual(events.read_bytes(), original)

    def test_invalid_limits_leave_no_output(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'events.jsonl'
            source.write_bytes(b'')
            output = Path(folder) / 'report.json'
            result = subprocess.run([sys.executable, str(ROOT / 'report_events.py'), str(source),
                '--max-samples', '-1', '--output', str(output)], capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertNotIn(b'Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
