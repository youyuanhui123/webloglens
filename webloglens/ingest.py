"""Explicit input adapters. Raw text is kept by callers, never rewritten here."""
from datetime import datetime
import ipaddress
import json
import math
import re

from webloglens.parser import parse_line

MONTHS = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')
REQUIRED = {'schema', 'time', 'ip', 'method', 'target', 'protocol', 'status', 'body_bytes',
            'site', 'request_time', 'request_id'}
OPTIONAL = {'referer', 'user_agent'}


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field: ' + key)
        result[key] = value
    return result


def _constant(value):
    raise ValueError('Non-finite JSON number is unsupported')


def _text(item, key, maximum, allow_empty=False):
    value = item[key]
    if not isinstance(value, str) or len(value) > maximum or (not value and not allow_empty):
        raise ValueError('Invalid text field: ' + key)
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Control character in field: ' + key)
    value.encode('utf-8')
    return value


def parse_access_line(line, log_format='combined'):
    if log_format == 'combined':
        return parse_line(line)
    if log_format != 'nginx-json':
        raise ValueError('Unsupported log format')
    if len(line) > 1048576:
        raise ValueError('JSON record exceeds adapter limit')
    try:
        item = json.loads(line, object_pairs_hook=_object, parse_constant=_constant)
    except RecursionError as exc:
        raise ValueError('JSON nesting exceeds parser limit') from exc
    if not isinstance(item, dict) or set(item) - REQUIRED - OPTIONAL or REQUIRED - set(item):
        raise ValueError('Nginx JSON fields do not match webloglens-nginx-1')
    if item['schema'] != 'webloglens-nginx-1':
        raise ValueError('Unsupported Nginx JSON schema')
    stamp = _text(item, 'time', 40)
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})', stamp):
        raise ValueError('time must be second-resolution ISO8601 with timezone')
    if stamp[-1] != 'Z' and (int(stamp[-5:-3]) > 23 or int(stamp[-2:]) > 59):
        raise ValueError('Invalid timezone offset')
    instant = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    ipaddress.ip_address(_text(item, 'ip', 45))
    method = _text(item, 'method', 64)
    if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", method):
        raise ValueError('Invalid HTTP method')
    target = _text(item, 'target', 16384)
    if not target.startswith('/') or any(c.isspace() for c in target):
        raise ValueError('Only origin-form request targets are supported')
    if _text(item, 'protocol', 20) not in ('HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0', 'HTTP/3.0'):
        raise ValueError('Unsupported HTTP protocol')
    for key, minimum, maximum in [('status', 100, 599), ('body_bytes', 0, 2 ** 63 - 1)]:
        if type(item[key]) is not int or not minimum <= item[key] <= maximum:
            raise ValueError('Invalid integer field: ' + key)
    duration = item['request_time']
    if type(duration) not in (int, float) or not 0 <= duration <= 1e9 or not math.isfinite(duration):
        raise ValueError('Invalid request_time')
    site = _text(item, 'site', 255)
    if any(c.isspace() for c in site):
        raise ValueError('Invalid site identifier')
    _text(item, 'request_id', 256)
    for key in OPTIONAL & set(item):
        _text(item, key, 16384, allow_empty=True)
    combined = (f'{instant.day:02d}/{MONTHS[instant.month - 1]}/{instant.year:04d}:'
                + instant.strftime('%H:%M:%S %z'))
    return dict(ip=item['ip'], time=combined, event_time_iso=stamp, method=method,
                target=target, protocol=item['protocol'], status=item['status'],
                body_bytes=item['body_bytes'], site=site, request_time=duration,
                request_id=item['request_id'], referer=item.get('referer'),
                user_agent=item.get('user_agent'))


def inspect_log(path, log_format='combined', max_lines=1000, max_bytes=4194304,
                max_line_bytes=65536, max_sites=16):
    """Read only a bounded prefix. Readiness refers to the observed sample, not the file."""
    from pathlib import Path
    import hashlib
    import os
    from webloglens.behavior import parse_timestamp
    if log_format not in ('combined', 'nginx-json'):
        raise ValueError('Unsupported log format')
    for name, value, ceiling in [('max_lines', max_lines, 100000),
                                  ('max_bytes', max_bytes, 67108864),
                                  ('max_line_bytes', max_line_bytes, 1048576),
                                  ('max_sites', max_sites, 128)]:
        if type(value) is not int or not 1 <= value <= ceiling:
            raise ValueError('Invalid preflight budget: ' + name)
    path = Path(path).resolve()
    counts = dict(lines=0, parsed=0, errors=0, blank=0, time_errors=0)
    errors, times = [], [None, None]
    coverage = dict(site=0, request_time=0, request_id=0)
    sites = set()
    multiple_sites = False
    read = 0
    digest = hashlib.sha256()
    def signature(stat):
        return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns
    with path.open('rb') as source:
        before = os.fstat(source.fileno())
        while counts['lines'] < max_lines and read < max_bytes:
            offset = read
            data = source.readline(min(max_line_bytes + 1, max_bytes - read))
            if not data:
                break
            read += len(data)
            digest.update(data)
            counts['lines'] += 1
            reason = None
            if len(data) - int(data.endswith(b'\n')) > max_line_bytes or (not data.endswith(b'\n') and read < before.st_size):
                reason = 'Line exceeds line/sample byte budget'
                while not data.endswith(b'\n') and read < max_bytes:
                    data = source.readline(min(65536, max_bytes - read))
                    if not data:
                        break
                    read += len(data)
                    digest.update(data)
            elif not data.endswith(b'\n'):
                reason = 'Incomplete trailing line; live watcher waits for newline'
            else:
                try:
                    raw = data.decode('utf-8-sig' if offset == 0 else 'utf-8').rstrip('\r\n')
                    if not raw.strip():
                        counts['blank'] += 1
                        continue
                    fields = parse_access_line(raw, log_format)
                    counts['parsed'] += 1
                    if fields.get('site') is not None:
                        if sites and fields['site'] not in sites:
                            multiple_sites = True
                        if len(sites) < max_sites + 1:
                            sites.add(fields['site'])
                    for key in coverage:
                        coverage[key] += fields.get(key) is not None
                    try:
                        instant = parse_timestamp(fields['time'])
                        times[0] = instant if times[0] is None else min(times[0], instant)
                        times[1] = instant if times[1] is None else max(times[1], instant)
                    except (ValueError, KeyError, OverflowError):
                        counts['time_errors'] += 1
                        if len(errors) < 20:
                            errors.append(dict(line=counts['lines'], offset=offset,
                                               reason='Parsed structure but invalid event time'))
                except (ValueError, OverflowError) as exc:
                    reason = str(exc)
            if reason is not None:
                counts['errors'] += 1
                if len(errors) < 20:
                    errors.append(dict(line=counts['lines'], offset=offset, reason=reason))
        after = os.fstat(source.fileno())
    try:
        changed = signature(before) != signature(after) or signature(before) != signature(path.stat())
    except OSError:
        changed = True
    return dict(schema_version='input-check-1.0', private=True, source=str(path),
                log_format=log_format, counts=counts, bytes_read=read,
                sample_sha256=digest.hexdigest(), sample_limited=read < before.st_size,
                source_changed=changed, budgets=dict(max_lines=max_lines, max_bytes=max_bytes,
                                                    max_line_bytes=max_line_bytes, max_sites=max_sites),
                time_range_utc=[t.isoformat() if t else None for t in times],
                field_presence=coverage, site_samples=sorted(sites)[:20], multiple_sites=multiple_sites,
                site_count_observed_at_least=len(sites), site_capacity_exceeded=len(sites) > max_sites,
                limitations=['JSON state is partitioned per site; limits apply per site and max_sites bounds total partitions'],
                unavailable_fields=[key for key, present in coverage.items() if present == 0],
                error_samples=errors, errors_omitted=max(0, counts['errors'] + counts['time_errors'] - len(errors)),
                ready_for_detection=counts['parsed'] > 0 and not counts['errors']
                                    and not counts['time_errors'] and not changed and len(sites) <= max_sites)

