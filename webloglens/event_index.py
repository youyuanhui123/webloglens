"""Private, rebuildable SQLite index. JSONL remains the original evidence."""
from datetime import datetime, timezone
import hashlib
import re
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile

from webloglens.event_report import summarize_events, _unique, _reject_constant, _signature

APPLICATION_ID = 0x574c4c33
SCHEMA = '''
PRAGMA application_id=0x574c4c33;
PRAGMA user_version=1;
CREATE TABLE runs(id INTEGER PRIMARY KEY, sha256 TEXT NOT NULL UNIQUE, metadata TEXT NOT NULL);
CREATE TABLE events(id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id),
 event_line INTEGER NOT NULL, event_offset INTEGER NOT NULL, kind TEXT NOT NULL,
 site TEXT, ip TEXT, path TEXT, status INTEGER, event_time TEXT, rule_id TEXT,
 source TEXT, generation INTEGER, source_offset INTEGER, payload TEXT NOT NULL,
 UNIQUE(run_id,event_line));
CREATE INDEX records_locator ON events(run_id,source,generation,source_offset);
CREATE INDEX events_scope_time ON events(site,ip,event_time,run_id,event_line);
CREATE INDEX events_rule ON events(rule_id,kind);
CREATE TABLE evidence_links(finding_event_id INTEGER NOT NULL REFERENCES events(id),
 evidence_ordinal INTEGER NOT NULL, record_event_id INTEGER REFERENCES events(id),
 PRIMARY KEY(finding_event_id,evidence_ordinal));
CREATE INDEX evidence_record ON evidence_links(record_event_id,finding_event_id);
'''


def _connect(path, readonly=False):
    path = Path(path).absolute()
    if readonly:
        con = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5)
        con.execute('PRAGMA query_only=ON')
    else:
        con = sqlite3.connect(path, timeout=5)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    con.execute('PRAGMA trusted_schema=OFF')
    return con


def _check(con):
    if (con.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID or
            con.execute('PRAGMA user_version').fetchone()[0] != 1):
        raise ValueError('Not a supported WebLogLens index')


def _budget(name, value, maximum):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f'{name} must be an integer in 1..{maximum}')


def _string(value, name, maximum=65536):
    if value is not None and (not isinstance(value, str) or len(value) > maximum):
        raise ValueError('Invalid index text field: ' + name)
    if value is not None:
        value.encode('utf-8')
    return value


def _iso(value):
    if not isinstance(value, str) or not re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)', value):
        raise ValueError('Time must be ISO8601 with explicit timezone and seconds')
    return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc).isoformat(timespec='microseconds')


def _event_time(event):
    from webloglens.behavior import parse_timestamp
    try:
        if event['type'] == 'finding' and event.get('end_time'):
            return _iso(event['end_time'])
        fields = event.get('fields')
        if event['type'] == 'finding':
            evidence = event.get('evidence', [])
            fields = evidence[0].get('fields') if evidence else None
        if isinstance(fields, dict) and 'time' in fields:
            return parse_timestamp(fields['time']).isoformat(timespec='microseconds')
    except (ValueError, TypeError, KeyError, OverflowError, AttributeError, IndexError):
        pass
    return None


def _project(event):
    fields = event.get('fields', {}) if event['type'] == 'record' else event
    if not isinstance(fields, dict):
        raise ValueError('Invalid fields object')
    target = _string(fields.get('target'), 'target')
    site, ip = _string(fields.get('site'), 'site', 255), _string(fields.get('ip'), 'ip', 256)
    status = fields.get('status')
    if status is not None and (type(status) is not int or not 0 <= status <= 999):
        raise ValueError('Invalid projected status')
    if event['type'] == 'record' and (not ip or not target or status is None):
        raise ValueError('Record is missing queryable ip/target/status')
    locator = [event.get('generation'), event.get('offset')]
    for value in locator:
        if value is not None and (type(value) is not int or not 0 <= value <= 2 ** 63 - 1):
            raise ValueError('Invalid source locator integer')
    return (event['type'], site, ip, target.split('?', 1)[0] if target else None, status,
            _event_time(event), _string(event.get('rule_id'), 'rule_id', 256),
            _string(event.get('source'), 'source'), *locator)


def _link_evidence(con, run_id, max_links):
    total = unresolved = without_evidence = 0
    for row in con.execute("SELECT id,payload FROM events WHERE run_id=? AND kind='finding'", (run_id,)):
        finding = json.loads(row['payload'])
        evidence = finding.get('evidence', [])
        if not isinstance(evidence, list):
            raise ValueError('Finding evidence must be a list')
        if not evidence:
            without_evidence += 1
        for ordinal, reference in enumerate(evidence):
            total += 1
            if total > max_links:
                raise ValueError('Evidence link budget exceeded')
            if not isinstance(reference, dict) or not isinstance(reference.get('fields'), dict):
                raise ValueError('Invalid finding evidence record')
            fields = reference['fields']
            for key in ('site', 'ip'):
                if finding.get(key) is not None and fields.get(key) != finding[key]:
                    raise ValueError('Finding identity contradicts evidence')
            locator = (reference.get('source'), reference.get('generation'), reference.get('offset'))
            matched = []
            if all(value is not None for value in locator):
                # Projection validation rejects unsupported SQL binding types/ranges.
                _project(dict(reference, type='record'))
                matched = con.execute("""SELECT id,payload FROM events WHERE run_id=? AND kind='record'
                    AND source=? AND generation=? AND source_offset=? LIMIT 2""", (run_id, *locator)).fetchall()
            identity = None
            if len(matched) == 1:
                record = json.loads(matched[0]['payload'])
                if record.get('fields') != fields or record.get('raw') != reference.get('raw'):
                    raise ValueError('Evidence locator contradicts indexed record content')
                identity = matched[0]['id']
            else:
                unresolved += 1
            con.execute('INSERT INTO evidence_links VALUES (?,?,?)', (row['id'], ordinal, identity))
    missing_times = con.execute("SELECT count(*) FROM events WHERE run_id=? AND kind='record' AND event_time IS NULL", (run_id,)).fetchone()[0]
    missing_finding_times = con.execute("SELECT count(*) FROM events WHERE run_id=? AND kind='finding' AND event_time IS NULL", (run_id,)).fetchone()[0]
    info = dict(evidence_links=total, unresolved_evidence_links=unresolved,
                findings_without_evidence=without_evidence, records_without_event_time=missing_times,
                findings_without_event_time=missing_finding_times)
    info['issues'] = [name for name, value in info.items() if name != 'evidence_links' and value]
    return info


def import_events(source, database, *, append=False, max_source_bytes=268435456,
                  max_event_bytes=2097152, max_events=100000, max_links=500000):
    for name, value, ceiling in [('max_source_bytes', max_source_bytes, 1073741824),
            ('max_event_bytes', max_event_bytes, 2097152), ('max_events', max_events, 1000000),
            ('max_links', max_links, 1000000)]:
        _budget(name, value, ceiling)
    source, database = Path(source).resolve(), Path(database).absolute()
    if database.is_symlink():
        raise ValueError('Symlinked index target is unsupported')
    if append and not database.is_file():
        raise ValueError('--append requires an existing index')
    if not append and database.exists():
        raise FileExistsError('Index exists; use explicit append or a new file')
    before = source.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > max_source_bytes:
        raise ValueError('Input must be a regular file within max_source_bytes')
    # A bounded private staging copy stops a growing source from making the
    # quality pre-pass run indefinitely. No unbounded read() or readlines().
    with tempfile.TemporaryDirectory(prefix='webloglens-index-') as temporary:
        snapshot = Path(temporary) / 'events.jsonl'
        remaining = before.st_size
        with source.open('rb') as original, snapshot.open('wb') as copied:
            if _signature(os.fstat(original.fileno())) != _signature(before):
                raise ValueError('Input changed before snapshot')
            while remaining:
                chunk = original.read(min(65536, remaining))
                if not chunk:
                    raise ValueError('Input truncated during snapshot')
                copied.write(chunk)
                remaining -= len(chunk)
            if original.read(1) or _signature(source.stat()) != _signature(before):
                raise ValueError('Input changed during snapshot')
        report = summarize_events(snapshot, max_samples=0, max_event_bytes=max_event_bytes)
        if not report['quality']['event_stream_complete']:
            raise ValueError('Structurally incomplete event stream: ' + ', '.join(report['quality']['issues']))
        report['input']['events_file'] = str(source)
        metadata = dict(source=report['input'], counts=report['observed']['counts'],
                        quality=report['quality'], run=report['run'])
        created = False
        con = None
        success = False
        try:
            if not append:
                with database.open('xb'):
                    pass
                created = True
            con = _connect(database)
            if created:
                con.executescript(SCHEMA)
            _check(con)
            with con:
                if con.execute('SELECT id FROM runs WHERE sha256=?', (report['input']['sha256'],)).fetchone():
                    raise ValueError('This exact JSONL SHA-256 is already indexed')
                run_id = con.execute('INSERT INTO runs(sha256,metadata) VALUES (?,?)',
                                     (report['input']['sha256'], json.dumps(metadata, allow_nan=False))).lastrowid
                offset = 0
                digest = hashlib.sha256()
                with snapshot.open('rb') as stream:
                    for number in range(1, max_events + 2):
                        line = stream.readline(max_event_bytes + 1)
                        if not line:
                            break
                        if number > max_events or len(line) > max_event_bytes or not line.endswith(b'\n'):
                            raise ValueError('Event/line budget or complete-line requirement exceeded')
                        digest.update(line)
                        event = json.loads(line.decode('utf-8-sig' if offset == 0 else 'utf-8'),
                                           object_pairs_hook=_unique, parse_constant=_reject_constant)
                        projection = _project(event)
                        con.execute('''INSERT INTO events(run_id,event_line,event_offset,kind,site,ip,path,status,
                                     event_time,rule_id,source,generation,source_offset,payload)
                                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                                    (run_id, number, offset, *projection, json.dumps(event, ensure_ascii=True, allow_nan=False)))
                        offset += len(line)
                metadata['index'] = _link_evidence(con, run_id, max_links)
                con.execute('UPDATE runs SET metadata=? WHERE id=?', (json.dumps(metadata, allow_nan=False), run_id))
                if digest.hexdigest() != report['input']['sha256'] or _signature(source.stat()) != _signature(before):
                    raise ValueError('Input/snapshot changed before commit')
            success = True
            return dict(source=metadata['source'], counts=metadata['counts'], quality=metadata['quality'],
                        index=metadata['index'], run_id=run_id, private=True)
        finally:
            if con:
                con.close()
            if created and not success:
                database.unlink(missing_ok=True)


def _run_summaries(con, run_ids):
    runs = []
    for identity in run_ids[:20]:
        row = con.execute('SELECT metadata FROM runs WHERE id=?', (identity,)).fetchone()
        if row:
            meta = json.loads(row[0])
            runs.append(dict(run_id=identity, source=meta['source'], quality=meta['quality'],
                             counts=meta['counts'], index=meta.get('index', {})))
    return runs


def timeline(database, *, ip, site=None, run_id=None, **filters):
    if not isinstance(ip, str) or not ip:
        raise ValueError('Timeline requires a nonempty source ip')
    if 'kind' in filters or 'rule_id' in filters:
        raise ValueError('Timeline is a request view; query findings separately')
    result = query_events(database, ip=ip, site=site, run_id=run_id, **filters)
    con = _connect(database, readonly=True)
    try:
        _check(con)
        items, used, exceeds = [], 0, result['next_item_exceeds_budget']
        for item in result['items']:
            count = con.execute('SELECT count(DISTINCT finding_event_id) FROM evidence_links WHERE record_event_id=?', (item['id'],)).fetchone()[0]
            references = con.execute('''SELECT DISTINCT e.id,e.run_id,e.site,e.rule_id FROM evidence_links l
                JOIN events e ON e.id=l.finding_event_id WHERE l.record_event_id=? ORDER BY e.id LIMIT 20''', (item['id'],))
            item['related_findings'] = [dict(row) for row in references]
            item['related_findings_total'] = count
            item['related_findings_has_more'] = count > len(item['related_findings'])
            size = len(json.dumps(item, ensure_ascii=True).encode('utf-8'))
            if used + size > result['max_payload_bytes']:
                exceeds = True
                break
            used += size
            items.append(item)
        identities = sorted({item['run_id'] for item in items} | ({run_id} if run_id else set()))
        more = result['offset'] + len(items) < result['total']
        result.update(view='source-timeline', items=items, returned=len(items), payload_bytes=used,
                      runs=_run_summaries(con, identities), run_summaries_omitted=max(0, len(identities) - 20),
                      has_more=more, next_offset=result['offset'] + len(items) if more else None,
                      next_item_exceeds_budget=exceeds)
        return result
    finally:
        con.close()


def _item(row):
    return dict(id=row['id'], run_id=row['run_id'], kind=row['kind'], site=row['site'], ip=row['ip'],
                path=row['path'], status=row['status'], rule_id=row['rule_id'], event_time_utc=row['event_time'],
                event_line=row['event_line'], event_offset=row['event_offset'], event=json.loads(row['payload']))


def query_events(database, *, run_id=None, kind='record', site=None, ip=None, path=None,
                 status=None, rule_id=None, start=None, end=None, limit=100, offset=0,
                 max_payload_bytes=4194304):
    _budget('limit', limit, 1000)
    _budget('max_payload_bytes', max_payload_bytes, 16777216)
    if type(offset) is not int or not 0 <= offset <= 1000000:
        raise ValueError('offset must be in 0..1000000')
    if kind not in ('record', 'finding', 'all'):
        raise ValueError('kind must be record, finding or all')
    if kind != 'record' and (path is not None or status is not None):
        raise ValueError('path/status filters require kind=record; windows have no single path/status')
    if rule_id is not None and kind == 'record':
        raise ValueError('rule_id requires kind=finding or all')
    if run_id is not None:
        _budget('run_id', run_id, 2 ** 63 - 1)
    if status is not None and (type(status) is not int or not 0 <= status <= 999):
        raise ValueError('Invalid status filter')
    start, end = _iso(start) if start is not None else None, _iso(end) if end is not None else None
    if start and end and start > end:
        raise ValueError('start must not be after end')
    clauses, params = [], []
    for column, value in [('run_id', run_id), ('kind', None if kind == 'all' else kind),
                          ('site', site), ('ip', ip), ('path', path), ('status', status), ('rule_id', rule_id)]:
        if value is not None:
            if column not in ('run_id', 'status'):
                _string(value, column)
            clauses.append(column + '=?')
            params.append(value)
    for operation, value in [('>=', start), ('<=', end)]:
        if value is not None:
            clauses.append('event_time' + operation + '?')
            params.append(value)
    where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
    con = _connect(database, readonly=True)
    try:
        _check(con)
        con.execute('BEGIN')  # Count/page/quality share one read snapshot.
        total = con.execute('SELECT count(*) FROM events' + where, params).fetchone()[0]
        rows = con.execute('SELECT * FROM events' + where +
                           ' ORDER BY event_time IS NULL,event_time,run_id,event_line LIMIT ? OFFSET ?',
                           [*params, limit, offset])
        items, payload_bytes, exceeds = [], 0, False
        for row in rows:
            item = _item(row)
            size = len(json.dumps(item, ensure_ascii=True).encode('utf-8'))
            if payload_bytes + size > max_payload_bytes:
                exceeds = True
                break  # Do not skip or truncate original evidence to make it fit.
            payload_bytes += size
            items.append(item)
        run_ids = sorted({item['run_id'] for item in items} | ({run_id} if run_id else set()))
        runs = _run_summaries(con, run_ids)
        more = offset + len(items) < total
        return dict(schema_version='event-query-1.0', private=True, total=total, returned=len(items),
                    limit=limit, offset=offset, has_more=more,
                    next_offset=offset + len(items) if more else None,
                    payload_bytes=payload_bytes, max_payload_bytes=max_payload_bytes,
                    next_item_exceeds_budget=exceeds, runs=runs, run_summaries_omitted=max(0, len(run_ids) - 20),
                    quality_scope='returned rows and explicitly requested run only', items=items)
    finally:
        con.close()
