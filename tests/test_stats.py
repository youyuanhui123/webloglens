import unittest

from webloglens.stats import summarize


class StatsTests(unittest.TestCase):
    def test_count_successful_records(self):
        records = [
            {'fields': {'ip': '127.0.0.1', 'status': 200, 'target': '/'}},
            {'fields': {'ip': '127.0.0.1', 'status': 200, 'target': '/login'}},
            {'fields': {'ip': '192.0.2.10', 'status': 404, 'target': '/login'}},
        ]
        self.assertEqual(summarize(records), {
            'request_count': 3,
            'status_counts': {'200': 2, '404': 1},
            'ip_counts': {'127.0.0.1': 2, '192.0.2.10': 1},
            'path_counts': {'/': 1, '/login': 2},
        })

    def test_group_paths_without_query_but_preserve_encoding(self):
        records = [
            {'fields': {'ip': '127.0.0.1', 'status': 200, 'target': '/search?q=a'}},
            {'fields': {'ip': '127.0.0.1', 'status': 200, 'target': '/search?q=b'}},
            {'fields': {'ip': '127.0.0.1', 'status': 200, 'target': '/a%2Fb?x=1'}},
            {'fields': {'ip': '127.0.0.1', 'status': 200, 'target': '/a/b'}},
        ]
        self.assertEqual(summarize(records)['path_counts'], {
            '/search': 2, '/a%2Fb': 1, '/a/b': 1,
        })


if __name__ == '__main__':
    unittest.main()
