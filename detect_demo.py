"""Detect indicators in SYNTHETIC data. No requests are sent."""

import json
from pathlib import Path

from webloglens.detector import detect_sensitive_paths
from webloglens.reader import read_log

LOG_PATH = Path(__file__).resolve().parent / 'examples' / 'synthetic_sensitive.log'

if __name__ == '__main__':
    print('SYNTHETIC TEST DATA - NOT REAL SERVER EVIDENCE')
    try:
        result = read_log(LOG_PATH)
    except (OSError, UnicodeError) as exc:
        raise SystemExit(f'Cannot read UTF-8 log file: {exc}')
    findings = detect_sensitive_paths(result['records'])
    print(f"parsed={len(result['records'])}")
    print(f"errors={len(result['errors'])}")
    print(f'finding_count={len(findings)}')
    print('INDICATORS ONLY - HTTP STATUS DOES NOT PROVE DATA LEAKAGE')
    print(json.dumps(findings, ensure_ascii=False, indent=2))
