import tempfile
import unittest
from pathlib import Path

from webloglens.reader import read_log


class ReaderTests(unittest.TestCase):
    def test_bad_and_blank_lines_do_not_stop_reading(self):
        good = ('127.0.0.1 - - [05/Nov/2026:10:00:00 +0800] '
                '"GET / HTTP/1.1" 200 10 "-" "test"')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_text(good + '\nBROKEN\n\n' + good + '\n', encoding='utf-8')
            result = read_log(path)
        self.assertEqual(result['total_lines'], 4)
        self.assertEqual(result['blank_lines'], 1)
        self.assertEqual([r['line_number'] for r in result['records']], [1, 4])
        self.assertEqual(result['records'][0]['raw'], good)
        self.assertEqual(result['records'][0]['fields']['status'], 200)
        self.assertEqual(len(result['errors']), 1)
        self.assertEqual(result['errors'][0]['line_number'], 2)
        self.assertEqual(result['errors'][0]['raw'], 'BROKEN')
        self.assertIn('malformed', result['errors'][0]['reason'])


if __name__ == '__main__':
    unittest.main()
