"""Learning demo: this input is synthetic, not a real server log."""

import json

from webloglens.parser import parse_line

# SYNTHETIC TEST DATA. Do not describe this as collected server evidence.
SAMPLE_LINE = (
    '127.0.0.1 - - [05/Nov/2026:10:00:00 +0800] '
    '"GET /login?next=%2F HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
)

if __name__ == '__main__':
    print('SYNTHETIC SAMPLE - NOT REAL SERVER EVIDENCE')
    print(json.dumps(parse_line(SAMPLE_LINE), ensure_ascii=False, indent=2))
