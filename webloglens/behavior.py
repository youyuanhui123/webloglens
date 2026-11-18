"""Find the first qualifying multi-path window per recorded source IP."""

from collections import Counter, defaultdict, deque
from datetime import datetime, timezone

_MONTHS = {name: f'{number:02d}' for number, name in enumerate(
    ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'), 1
)}


def detect_path_bursts(records, window_seconds=60, min_paths=5):
    """Inclusive window, distinct undecoded paths, first finding per IP."""
    if type(window_seconds) is not int or window_seconds <= 0:
        raise ValueError('window_seconds must be a positive integer')
    if type(min_paths) is not int or min_paths < 2:
        raise ValueError('min_paths must be an integer >= 2')
    grouped = defaultdict(list)
    time_errors = []
    for record in records:
        fields = record['fields']
        try:
            # Convert English month explicitly, independent of machine locale.
            day, month, rest = fields['time'].split('/', 2)
            numeric = f'{day}/{_MONTHS[month]}/{rest}'
            instant = datetime.strptime(numeric, '%d/%m/%Y:%H:%M:%S %z').astimezone(timezone.utc)
        except (ValueError, KeyError):
            time_errors.append({
                'line_number': record['line_number'], 'raw': record['raw'],
                'time': fields['time'], 'reason': 'Invalid combined-log timestamp',
            })
            continue
        path = fields['target'].split('?', 1)[0]
        grouped[fields['ip']].append((instant, record['line_number'], path, record))

    findings = []
    for ip in sorted(grouped):
        events = sorted(grouped[ip], key=lambda event: (event[0], event[1]))
        window = deque()
        counts = Counter()
        for event in events:
            now, _, path, _ = event
            window.append(event)
            counts[path] += 1
            while (now - window[0][0]).total_seconds() > window_seconds:
                expired = window.popleft()
                counts[expired[2]] -= 1
                if counts[expired[2]] == 0:
                    del counts[expired[2]]
            if len(counts) >= min_paths:
                findings.append({
                    'rule_id': 'multi-path-window-v1', 'ip': ip,
                    'window_seconds': window_seconds, 'min_paths': min_paths,
                    'start_time': window[0][0].isoformat(), 'end_time': now.isoformat(),
                    'request_count': len(window), 'distinct_path_count': len(counts),
                    'paths': sorted(counts),
                    'reason': f'At least {min_paths} distinct paths within {window_seconds} seconds',
                    'conclusion': 'review_required_not_proof_of_attack',
                    'evidence': [item[3] for item in window],
                })
                # Limit duplicate alerts; not a full session/episode detector.
                break
    return {'findings': findings, 'time_errors': time_errors}
