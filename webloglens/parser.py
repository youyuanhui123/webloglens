"""Parse the standard combined access-log format, not custom formats."""

import re

_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<target>\S+) (?P<protocol>HTTP/\d+(?:\.\d+)?)" '
    r'(?P<status>\d{3}) (?P<body_bytes>\d+|-) '
    r'"(?P<referer>(?:\\.|[^"\\])*)" '
    r'"(?P<user_agent>(?:\\.|[^"\\])*)"'
)


def parse_line(line):
    """Return fields; preserve URL encoding and escaped quoted fields."""
    match = _PATTERN.fullmatch(line.rstrip('\r\n'))
    if match is None:
        raise ValueError('Unsupported or malformed combined access-log line')
    record = match.groupdict()
    record['status'] = int(record['status'])
    size = record['body_bytes']
    record['body_bytes'] = None if size == '-' else int(size)
    return record
