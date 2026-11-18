import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StreamCliTests(unittest.TestCase):
    def test_live_and_replay_share_findings_for_same_ordered_input(self):
        content = (ROOT / 'examples/synthetic_sensitive.log').read_bytes()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_bytes(b'')
            command = [sys.executable, str(ROOT / 'watch.py'), str(path),
                       '--detect', '--min-paths', '3', '--interval', '0.01']
            live = subprocess.Popen(command + ['--duration', '0.5'], cwd=folder,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, encoding='utf-8')
            try:
                started = json.loads(live.stdout.readline())
                self.assertEqual(started['stage'], 'detection')
                with path.open('ab') as output:
                    output.write(content)
                stdout, stderr = live.communicate(timeout=10)
            finally:
                if live.poll() is None:
                    live.kill()
                    live.communicate()
                live.stdout.close()
                live.stderr.close()
            self.assertEqual(live.returncode, 0, stderr)
            replay = subprocess.run(command + ['--replay'], cwd=folder, capture_output=True,
                                    text=True, encoding='utf-8', timeout=10)
            self.assertEqual(replay.returncode, 0, replay.stderr)
            left = [json.loads(s) for s in stdout.splitlines()]
            right = [json.loads(s) for s in replay.stdout.splitlines()]
            def comparable(value):
                if isinstance(value, dict):
                    return {k: comparable(v) for k, v in value.items()
                            if k not in ('observed_at', 'line_number')}
                if isinstance(value, list):
                    return [comparable(v) for v in value]
                return value
            def simplified(events):
                return [comparable(e) for e in events if e['type'] == 'finding']
            self.assertEqual(simplified(left), simplified(right))
            self.assertEqual(len(simplified(left)), 3)
            self.assertEqual(left[-1]['analysis']['records'], 5)
            self.assertEqual(left[-1]['analysis']['buffered_records'], 0)
            self.assertEqual(right[-1]['reason'], 'replay_complete')

    def test_replay_rejects_input_changed_during_read_instead_of_waiting_forever(self):
        import contextlib
        import io
        from unittest.mock import patch
        import watch
        from webloglens.follow import FileFollower
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_bytes((ROOT / 'examples/synthetic_sensitive.log').read_bytes())
            original = FileFollower.poll
            calls = []
            def truncate(follower):
                if calls:
                    raise AssertionError('replay failed to stop after input changed')
                calls.append(True)
                path.write_bytes(b'')
                return original(follower)
            with patch.object(FileFollower, 'poll', truncate), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, 'replay input changed'):
                    watch.main([str(path), '--replay'])

    def test_invalid_stream_config_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'events.jsonl'
            result = subprocess.run([sys.executable, str(ROOT / 'watch.py'),
                str(ROOT / 'examples/synthetic_sensitive.log'), '--detect',
                '--max-buffer', '0', '--output', str(output)], capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertNotIn(b'Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
