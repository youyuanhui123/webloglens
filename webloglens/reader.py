"""Read small UTF-8 combined log files, keeping evidence and line numbers."""

from webloglens.parser import parse_line


def read_log(path):
    result = {'total_lines': 0, 'blank_lines': 0, 'records': [], 'errors': []}
    # utf-8-sig also accepts UTF-8 files saved with a BOM on Windows.
    with open(path, encoding='utf-8-sig') as log_file:
        for line_number, line in enumerate(log_file, start=1):
            result['total_lines'] += 1
            raw = line.rstrip('\r\n')
            if not raw.strip():
                result['blank_lines'] += 1
                continue
            try:
                fields = parse_line(raw)
            except ValueError as exc:
                result['errors'].append({
                    'line_number': line_number, 'raw': raw, 'reason': str(exc),
                })
                continue
            result['records'].append({
                'line_number': line_number, 'raw': raw, 'fields': fields,
            })
    return result
