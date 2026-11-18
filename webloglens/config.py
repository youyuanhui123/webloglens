"""Load detector settings from UTF-8 JSON."""

import json


def load_config(path):
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON config key: ' + key)
            result[key] = value
        return result

    with open(path, encoding='utf-8-sig') as file:
        data = json.load(file, object_pairs_hook=unique_keys)
    if type(data) is not dict or set(data) != {'sensitive_paths', 'window_seconds', 'min_paths'}:
        raise ValueError('Config requires exactly sensitive_paths, window_seconds and min_paths')
    if type(data['window_seconds']) is not int or data['window_seconds'] <= 0:
        raise ValueError('window_seconds must be a positive integer (not boolean)')
    if type(data['min_paths']) is not int or data['min_paths'] < 2:
        raise ValueError('min_paths must be an integer >= 2 (not boolean)')
    paths = data['sensitive_paths']
    if type(paths) is not list:
        raise ValueError('sensitive_paths must be a list of literal origin-form paths')
    for path in paths:
        if (type(path) is not str or not path.startswith('/') or path.startswith('//')
                or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in path)
                or any(char in path for char in ['?', '#', '\\'])):
            raise ValueError('Each sensitive path must start with / and have no query, fragment, whitespace or backslash')
    if len(paths) != len(set(paths)):
        raise ValueError('Duplicate sensitive paths are not allowed')
    return data
