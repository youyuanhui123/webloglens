import tempfile
import unittest
from pathlib import Path

from webloglens.follow import FileFollower


class FollowTests(unittest.TestCase):
    def test_append_waits_for_complete_utf8_line_and_never_repeats(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_bytes(b'first\n')
            with FileFollower(path, start='beginning') as follower:
                events = follower.poll()
                lines = [e for e in events if e['type'] == 'line']
                self.assertEqual([(e['raw'], e['line_number'], e['offset']) for e in lines],
                                 [('first', 1, 0)])
                self.assertEqual(follower.poll(), [])
                encoded = '中文'.encode('utf-8')
                with path.open('ab') as output:
                    output.write(encoded[:2])
                self.assertEqual(follower.poll(), [])
                with path.open('ab') as output:
                    output.write(encoded[2:] + b'\r\n')
                line = follower.poll()[0]
                self.assertEqual(line['raw'], '中文')
                self.assertEqual(line['line_number'], 2)
                self.assertEqual(line['offset'], 6)
                self.assertEqual(follower.poll(), [])

    def test_end_skips_existing_partial_and_uses_session_line_numbers(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_bytes(b'old\npart')
            with FileFollower(path) as follower:
                self.assertEqual(follower.poll(), [])
                with path.open('ab') as output:
                    output.write(b'ial\nnew\n')
                lines = [e for e in follower.poll() if e['type'] == 'line']
                self.assertEqual([e['raw'] for e in lines], ['new'])
                self.assertIsNone(lines[0]['line_number'])
                self.assertEqual(lines[0]['offset'], 12)

    def test_rotation_drains_old_file_then_reads_new_generation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_bytes(b'old\n')
            with FileFollower(path, start='beginning') as follower:
                follower.poll()
                path.rename(Path(folder) / 'access.log.1')
                with (Path(folder) / 'access.log.1').open('ab') as output:
                    output.write(b'tail\n')
                path.write_bytes(b'new\n')
                events = follower.poll()
                self.assertEqual([e['raw'] for e in events if e['type'] == 'line'], ['tail'])
                self.assertIn('rotated', [e['type'] for e in events])
                line = follower.poll()[0]
                self.assertEqual((line['raw'], line['generation'], line['line_number']), ('new', 2, 1))

    def test_rotation_open_race_keeps_old_events_and_retries(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_bytes(b'old\n')
            with FileFollower(path, start='beginning') as follower:
                path.rename(Path(folder) / 'old.log')
                path.write_bytes(b'new\n')
                with patch('webloglens.follow._open_shared', side_effect=FileNotFoundError):
                    events = follower.poll()
                self.assertEqual([e['type'] for e in events], ['line', 'path_missing'])
                self.assertEqual(events[0]['raw'], 'old')
                self.assertEqual([e['type'] for e in follower.poll()], ['path_available', 'rotated'])
                self.assertEqual(follower.poll()[0]['raw'], 'new')

    def test_missing_path_is_reported_once_and_rotation_discards_old_fragment(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_bytes(b'partial')
            with FileFollower(path, start='beginning') as follower:
                self.assertEqual(follower.poll(), [])
                path.rename(Path(folder) / 'old.log')
                self.assertEqual([e['type'] for e in follower.poll()], ['path_missing'])
                self.assertEqual(follower.poll(), [])
                path.write_bytes(b'fresh\n')
                events = follower.poll()
                self.assertEqual([e['type'] for e in events], ['path_available', 'rotated'])
                self.assertEqual(events[-1]['pending_bytes'], 7)
                self.assertEqual(follower.poll()[0]['raw'], 'fresh')

    def test_truncate_and_rewrite_detected_even_if_file_grows(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_bytes(b'old\n')
            with FileFollower(path, start='beginning') as follower:
                follower.poll()
                path.write_bytes(b'longer replacement\n')
                events = follower.poll()
                self.assertIn('truncated', [e['type'] for e in events])
                lines = [e for e in events if e['type'] == 'line']
                self.assertEqual(lines[0]['raw'], 'longer replacement')
                self.assertEqual(lines[0]['generation'], 2)

    def test_oversized_event_points_to_current_physical_line(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_bytes(b'ok\nTOOLONG\nnext\n')
            with FileFollower(path, start='beginning', max_line_bytes=4) as follower:
                event = follower.poll()[1]
                self.assertEqual(event['type'], 'line_too_long')
                self.assertEqual(event['line_number'], 2)
                self.assertEqual(event['offset'], 3)

    def test_oversized_and_invalid_utf8_lines_recover_without_unbounded_buffer(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_bytes(b'x' * 100 + b'\n\xff\nok\n')
            with FileFollower(path, start='beginning', chunk_bytes=7, max_line_bytes=16) as follower:
                events = []
                for _ in range(25):
                    events += follower.poll()
                    self.assertLessEqual(len(follower.pending), 16)
                self.assertEqual([e['type'] for e in events], ['line_too_long', 'decode_error', 'line'])
                self.assertEqual(events[-1]['raw'], 'ok')
                self.assertEqual(events[-1]['line_number'], 3)


if __name__ == '__main__':
    unittest.main()
