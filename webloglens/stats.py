"""Descriptive statistics, not attack detection."""

from collections import Counter


def summarize(records):
    """Accept reader's successful records; return JSON-friendly counts."""
    status_counts = Counter()
    ip_counts = Counter()
    path_counts = Counter()
    request_count = 0
    for record in records:
        fields = record['fields']
        request_count += 1
        status_counts[str(fields['status'])] += 1
        ip_counts[fields['ip']] += 1
        # Group origin-form request paths without decoding or changing evidence.
        path = fields['target'].split('?', 1)[0]
        path_counts[path] += 1
    return {
        'request_count': request_count,
        'status_counts': dict(status_counts),
        'ip_counts': dict(ip_counts),
        'path_counts': dict(path_counts),
    }
