"""Summarize the synthetic sample; no network requests are sent."""

import json
from pathlib import Path

from webloglens.reader import read_log
from webloglens.stats import summarize

LOG_PATH = Path(__file__).resolve().parent / 'examples' / 'synthetic_access.log'

if __name__ == '__main__':
    print('SYNTHETIC TEST DATA - NOT REAL SERVER EVIDENCE')
    try:
        result = read_log(LOG_PATH)
    except (OSError, UnicodeError) as exc:
        raise SystemExit(f'Cannot read UTF-8 log file: {exc}')
    print(f"total_lines={result['total_lines']}")
    print(f"parsed={len(result['records'])}")
    print(f"errors={len(result['errors'])}")
    print(f"blank_lines={result['blank_lines']}")
    summary = summarize(result['records'])
    print(json.dumps(summary, ensure_ascii=False, indent=2))
