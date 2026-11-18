import unittest

from webloglens.parser import parse_line


class ParserTests(unittest.TestCase):
    def test_parse_combined_log(self):
        line = ('127.0.0.1 - - [05/Nov/2026:10:00:00 +0800] '
                '"GET /login?next=%2F HTTP/1.1" 200 512 '
                '"-" "Mozilla/5.0"')
        self.assertEqual(parse_line(line), {
            'ip': '127.0.0.1',
            'time': '05/Nov/2026:10:00:00 +0800',
            'method': 'GET',
            'target': '/login?next=%2F',
            'protocol': 'HTTP/1.1',
            'status': 200,
            'body_bytes': 512,
            'referer': '-',
            'user_agent': 'Mozilla/5.0',
        })


if __name__ == '__main__':
    unittest.main()
