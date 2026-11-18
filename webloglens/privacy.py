"""Conservative allowlist-based sharing view, not a guarantee of anonymity."""


def redact_report(report):
    """Return a new report; omit raw evidence, exact paths, times and headers."""
    ips, paths = {}, {}

    def alias(value, mapping, prefix):
        if value not in mapping:
            mapping[value] = f'{prefix}-{len(mapping) + 1:03d}'
        return mapping[value]

    def number(value):
        if type(value) is not int or value < 0:
            raise ValueError('Expected a nonnegative report integer')
        return value

    def safe_config(config):
        return {key: number(config[key]) for key in ('window_seconds', 'min_paths') if key in config}

    summary = report['summary']
    safe_summary = {'request_count': number(summary['request_count']), 'status_counts': {},
                    'ip_counts': {}, 'path_counts': {}}
    for code, count in summary['status_counts'].items():
        key = code if type(code) is str and code.isascii() and code.isdigit() and len(code) == 3 else 'OTHER'
        safe_summary['status_counts'][key] = safe_summary['status_counts'].get(key, 0) + number(count)
    for ip, count in summary['ip_counts'].items():
        safe_summary['ip_counts'][alias(ip, ips, 'IP')] = number(count)
    for path, count in summary['path_counts'].items():
        safe_summary['path_counts'][alias(path, paths, 'PATH')] = number(count)

    safe_findings = []
    for finding in report['findings']:
        rule = finding.get('rule_id')
        if rule not in {'sensitive-path-exact-v1', 'multi-path-window-v1'}:
            raise ValueError('Sharing policy does not support this rule; update policy before export')
        safe = {'rule_id': rule, 'ip': alias(finding['ip'], ips, 'IP'),
                'conclusion': 'review_required_not_proof_of_attack'}
        if rule == 'sensitive-path-exact-v1':
            safe.update({
                'line_number': number(finding['line_number']),
                'matched_path': alias(finding['matched_path'], paths, 'PATH'),
                'status': number(finding['status']),
                'reason': 'Exact configured path matched; target and raw evidence removed for sharing.',
            })
        else:
            safe.update(safe_config(finding))
            safe.update({
                'request_count': number(finding['request_count']),
                'distinct_path_count': number(finding['distinct_path_count']),
                'paths': [alias(path, paths, 'PATH') for path in finding['paths']],
                'evidence_line_numbers': [number(item['line_number']) for item in finding['evidence']],
                'reason': 'Distinct-path window reached threshold; original times and evidence removed.',
            })
        safe_findings.append(safe)
    config = report.get('configuration', {})
    effective = config.get('effective', {})
    safe_effective = safe_config(effective)
    if 'sensitive_paths' in effective:
        safe_effective['sensitive_paths'] = [alias(path, paths, 'PATH') for path in effective['sensitive_paths']]
    behavior = report.get('behavior', {})
    data_kind = report['source'].get('data_kind', 'unspecified')
    if data_kind not in {'unspecified', 'synthetic', 'local-experiment', 'authorized'}:
        data_kind = 'unspecified'
    return {
        'schema_version': '1.1',
        'privacy': {
            'mode': 'share-redacted',
            'policy_version': '1',
            'warning': 'Pseudonyms are export-local. Counts, relationships and line numbers remain; manually review before sharing.',
            'removed': ['source/config paths', 'exact IPs and request paths', 'query strings',
                        'raw records and errors', 'headers', 'exact timestamps', 'unknown fields'],
        },
        'source': {'path': '[REMOVED]', 'data_kind': data_kind, 'provenance_verified': False},
        'configuration': {'path': '[REMOVED]', 'effective': safe_effective,
                          'cli_overrides': safe_config(config.get('cli_overrides', {}))},
        'parsing': {key: number(report['parsing'][key])
                    for key in ('total_lines', 'parsed', 'errors', 'blank_lines')},
        'summary': safe_summary,
        'finding_count': len(safe_findings), 'findings': safe_findings,
        'parse_errors': [{'line_number': number(item['line_number']), 'reason': 'Details removed for sharing'}
                         for item in report.get('parse_errors', [])],
        'behavior': {
            'config': {**safe_config(behavior.get('config', {})),
                       'emit_policy': 'first_qualifying_window_per_ip'},
            'findings': [f for f in safe_findings if f['rule_id'] == 'multi-path-window-v1'],
            'time_errors': [{'line_number': number(item['line_number']), 'reason': 'Invalid time; details removed'}
                            for item in behavior.get('time_errors', [])],
        },
        'limitations': [
            'Sharing view, not complete original evidence and not guaranteed anonymous.',
            'Indicators only. Normal browsing can trigger path-window rules.',
            'Only configured exact undecoded paths and first qualifying window per recorded IP.',
            'Keep original logs and private reports separately; review sharing scope manually.',
        ],
    }
