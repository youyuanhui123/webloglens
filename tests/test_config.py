import json
from pathlib import Path
import tempfile
import unittest

from webloglens.config import load_config


class ConfigTests(unittest.TestCase):
    def test_valid_config_is_loaded_without_normalizing_paths(self):
        data = {'sensitive_paths': ['/.env', '/backup.zip'], 'window_seconds': 90, 'min_paths': 8}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'config.json'
            path.write_text(json.dumps(data), encoding='utf-8-sig')
            self.assertEqual(load_config(path), data)


    def test_invalid_structure_types_and_paths_are_rejected(self):
        valid = {'sensitive_paths': ['/.env'], 'window_seconds': 60, 'min_paths': 5}
        invalid = [[], {}, dict(valid, typo=1), dict(valid, window_seconds=True),
                   dict(valid, window_seconds=0), dict(valid, min_paths=1),
                   dict(valid, min_paths=2.5), dict(valid, sensitive_paths='/.env')]
        for paths in [['/.env', '/.env'], ['http://example.invalid'], ['//host/path'],
                      ['/a?x=1'], ['/a#frag'], ['/a\nb'], ['/a b'], ['/a\\b'], [3]]:
            invalid.append(dict(valid, sensitive_paths=paths))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'bad.json'
            for data in invalid:
                with self.subTest(data=data):
                    path.write_text(json.dumps(data), encoding='utf-8')
                    with self.assertRaises(ValueError):
                        load_config(path)


    def test_duplicate_json_keys_are_rejected(self):
        text = '{"sensitive_paths": [], "window_seconds": 60, "min_paths": 5, "min_paths": 8}'
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'duplicate.json'
            path.write_text(text, encoding='utf-8')
            with self.assertRaises(ValueError):
                load_config(path)


if __name__ == '__main__':
    unittest.main()
