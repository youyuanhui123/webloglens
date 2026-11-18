"""Explainable access indicators, not proof of exploitation."""

SENSITIVE_PATHS = {'/.env', '/.git/config'}


def detect_sensitive_paths(records, sensitive_paths=None):
    """Match exact case-sensitive, undecoded origin-form paths only."""
    paths = SENSITIVE_PATHS if sensitive_paths is None else set(sensitive_paths)
    findings = []
    for record in records:
        fields = record['fields']
        path = fields['target'].split('?', 1)[0]
        if path not in paths:
            continue
        findings.append({
            'rule_id': 'sensitive-path-exact-v1',
            'line_number': record['line_number'],
            'ip': fields['ip'],
            'target': fields['target'],
            'matched_path': path,
            'status': fields['status'],
            'reason': f'Request path exactly matches sensitive path {path}',
            'conclusion': 'suspicious_access_only',
            'raw': record['raw'],
        })
    return findings
