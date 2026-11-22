import json
from pathlib import Path
import tempfile
import unittest

from webloglens.event_index import import_events, query_events


def sample_events():
    records = []
    for n, (site, target, status) in enumerate([('a.local', '/a', 200), ('a.local', '/.env?token=private', 404), ('b.local', '/b', 200)]):
        fields = dict(site=site, ip='192.0.2.10', target=target, status=status,
                      time=f'18/Nov/2026:10:00:0{n} +0800')
        records.append(dict(type='record', source='synthetic.log', generation=1, offset=n * 100,
                            line_number=n + 1, raw='synthetic-' + str(n), fields=fields))
    finding = dict(type='finding', rule_id='sensitive-path-exact-v1', site='a.local',
                   ip='192.0.2.10', target='/.env?token=private', status=404, evidence=[records[1]])
    return [dict(type='started', stage='detection'), *records, finding,
            dict(type='summary', counts={'record': 3, 'finding': 1},
                 analysis={'records': 3, 'path_findings': 1})]


def save(path, events):
    path.write_text(''.join(json.dumps(e) + '\n' for e in events), encoding='utf-8')


class EventIndexTests(unittest.TestCase):
    def test_append_is_explicit_deduplicated_and_transactional(self):
        with tempfile.TemporaryDirectory() as folder:
            source, db = Path(folder) / 'events.jsonl', Path(folder) / 'private.sqlite'
            save(source, sample_events())
            import_events(source, db)
            with self.assertRaises(FileExistsError):
                import_events(source, db)
            with self.assertRaises(ValueError):
                import_events(source, db, append=True)
            second = sample_events()
            second[1]['raw'] = 'another-run'
            save(source, second)
            self.assertEqual(import_events(source, db, append=True)['run_id'], 2)
            self.assertEqual(query_events(db)['total'], 6)
            second[1]['raw'] = 'failed-run'
            save(source, second)
            with self.assertRaises(ValueError):
                import_events(source, db, append=True, max_events=1)
            self.assertEqual(query_events(db)['total'], 6)

    def test_incomplete_input_and_budget_failure_leave_no_new_database(self):
        with tempfile.TemporaryDirectory() as folder:
            source, db = Path(folder) / 'events.jsonl', Path(folder) / 'private.sqlite'
            save(source, sample_events()[:-1])
            with self.assertRaises(ValueError):
                import_events(source, db)
            self.assertFalse(db.exists())
            save(source, sample_events())
            for options in (dict(max_source_bytes=10), dict(max_events=1), dict(max_event_bytes=10)):
                with self.assertRaises(ValueError):
                    import_events(source, db, **options)
                self.assertFalse(db.exists())
            # An analysis gap is not a structurally broken event stream.
            events = sample_events()
            events.insert(-1, dict(type='state_limit', reason='max_sites', evidence=[]))
            events[-1]['counts']['state_limit'] = 1
            save(source, events)
            result = import_events(source, db)
            self.assertIn('capacity_limit_excluded', result['quality']['issues'])

    def test_readonly_query_does_not_create_missing_file_and_foreign_db_is_rejected(self):
        import sqlite3
        from contextlib import closing
        with tempfile.TemporaryDirectory() as folder:
            source, db = Path(folder) / 'events.jsonl', Path(folder) / 'foreign.sqlite'
            with self.assertRaises((OSError, ValueError, sqlite3.Error)):
                query_events(db)
            self.assertFalse(db.exists())
            with closing(sqlite3.connect(db)) as con:
                con.execute('CREATE TABLE keep(value TEXT)')
            save(source, sample_events())
            with self.assertRaises(ValueError):
                import_events(source, db, append=True)
            with closing(sqlite3.connect(db)) as con:
                self.assertEqual(con.execute('SELECT count(*) FROM keep').fetchone()[0], 0)

    def test_filters_pagination_timezones_and_sql_parameters(self):
        with tempfile.TemporaryDirectory() as folder:
            source, db = Path(folder) / 'events.jsonl', Path(folder) / 'private.sqlite'
            save(source, sample_events())
            import_events(source, db)
            result = query_events(db, site='a.local', ip='192.0.2.10', status=404, path='/.env',
                                  start='2026-11-18T02:00:01Z', end='2026-11-18T10:00:01+08:00')
            self.assertEqual(result['total'], 1)
            self.assertEqual(result['items'][0]['event']['fields']['target'], '/.env?token=private')
            page = query_events(db, limit=1)
            self.assertTrue(page['has_more'])
            self.assertEqual(page['next_offset'], 1)
            self.assertEqual(query_events(db, offset=1, limit=1)['items'][0]['event_line'], 3)
            self.assertEqual(query_events(db, site="' OR 1=1 --")['total'], 0)
            self.assertEqual(query_events(db, kind='finding', rule_id='sensitive-path-exact-v1')['total'], 1)
            limited = query_events(db, max_payload_bytes=1)
            self.assertEqual(limited['returned'], 0)
            self.assertTrue(limited['has_more'])
            self.assertTrue(limited['next_item_exceeds_budget'])
            self.assertEqual(len(page['runs']), 1)
            self.assertTrue(page['runs'][0]['quality']['event_stream_complete'])
            for kwargs in [dict(limit=0), dict(offset=-1), dict(start='2026-11-18'),
                           dict(start='2026-11-19T00:00:00Z', end='2026-11-18T00:00:00Z'),
                           dict(kind='finding', path='/a')]:
                with self.assertRaises(ValueError):
                    query_events(db, **kwargs)

    def test_timeline_links_findings_without_duplicating_requests(self):
        from webloglens.event_index import timeline
        with tempfile.TemporaryDirectory() as folder:
            source, db = Path(folder) / 'events.jsonl', Path(folder) / 'private.sqlite'
            save(source, sample_events())
            result = import_events(source, db)
            self.assertEqual(result['index']['unresolved_evidence_links'], 0)
            view = timeline(db, site='a.local', ip='192.0.2.10')
            self.assertEqual(view['total'], 2)
            self.assertEqual([e['path'] for e in view['items']], ['/a', '/.env'])
            self.assertEqual(view['items'][0]['related_findings'], [])
            self.assertEqual(view['items'][1]['related_findings'][0]['rule_id'], 'sensitive-path-exact-v1')
            self.assertEqual(view['items'][1]['related_findings_total'], 1)
            self.assertEqual(query_events(db)['total'], 3)
            raw_budget = query_events(db, limit=1)['payload_bytes']
            clipped = timeline(db, site='a.local', ip='192.0.2.10', limit=1, max_payload_bytes=raw_budget)
            self.assertEqual(clipped['returned'], 0)
            self.assertEqual(clipped['runs'], [])
            self.assertTrue(clipped['has_more'])
            with self.assertRaises(ValueError):
                timeline(db, ip='')

    def test_unresolved_evidence_and_bad_record_time_are_explicit(self):
        from webloglens.event_index import timeline
        with tempfile.TemporaryDirectory() as folder:
            source, db = Path(folder) / 'events.jsonl', Path(folder) / 'private.sqlite'
            events = sample_events()
            events[1]['fields']['time'] = 'invalid'
            events[-2]['evidence'] = [dict(events[-2]['evidence'][0], offset=9999)]
            save(source, events)
            result = import_events(source, db)
            self.assertEqual(result['index']['unresolved_evidence_links'], 1)
            self.assertEqual(result['index']['records_without_event_time'], 1)
            view = timeline(db, ip='192.0.2.10', site='a.local')
            self.assertEqual(view['total'], 2)
            self.assertIsNone(view['items'][-1]['event_time_utc'])
            self.assertTrue(view['runs'][0]['index']['issues'])

    def test_changed_source_during_import_is_rolled_back(self):
        from unittest.mock import patch
        from webloglens import event_index
        original = event_index.summarize_events
        with tempfile.TemporaryDirectory() as folder:
            source, db = Path(folder) / 'events.jsonl', Path(folder) / 'private.sqlite'
            save(source, sample_events())
            def changed(path, **kwargs):
                report = original(path, **kwargs)
                with source.open('ab') as output:
                    output.write(b'\n')
                return report
            with patch.object(event_index, 'summarize_events', side_effect=changed):
                with self.assertRaises(ValueError):
                    import_events(source, db)
            self.assertFalse(db.exists())

    def test_nonfinite_exponent_and_contradictory_evidence_are_not_indexed(self):
        with tempfile.TemporaryDirectory() as folder:
            source, db = Path(folder) / 'events.jsonl', Path(folder) / 'private.sqlite'
            events = sample_events()
            events[0]['extra'] = 1.0
            save(source, events)
            source.write_text(source.read_text().replace('"extra": 1.0', '"extra": 1e400'), encoding='utf-8')
            with self.assertRaises(ValueError):
                import_events(source, db)
            self.assertFalse(db.exists())
            events = sample_events()
            evidence = dict(events[-2]['evidence'][0])
            evidence['fields'] = dict(evidence['fields'], ip='203.0.113.9')
            events[-2]['evidence'] = [evidence]
            save(source, events)
            with self.assertRaises(ValueError):
                import_events(source, db)
            self.assertFalse(db.exists())

    def test_evidence_link_budget_rolls_back_and_timeline_reference_list_is_bounded(self):
        from webloglens.event_index import timeline
        with tempfile.TemporaryDirectory() as folder:
            source, db = Path(folder) / 'events.jsonl', Path(folder) / 'private.sqlite'
            base = sample_events()
            events = base[:-2] + [base[-2]] * 25 + [dict(type='summary', counts={'record': 3, 'finding': 25},
                                                      analysis={'records': 3, 'path_findings': 25})]
            save(source, events)
            with self.assertRaises(ValueError):
                import_events(source, db, max_links=1)
            self.assertFalse(db.exists())
            import_events(source, db)
            view = timeline(db, ip='192.0.2.10', site='a.local')
            self.assertEqual(view['total'], 2)
            item = view['items'][1]
            self.assertEqual(item['related_findings_total'], 25)
            self.assertEqual(len(item['related_findings']), 20)
            self.assertTrue(item['related_findings_has_more'])
            self.assertEqual(query_events(db)['total'], 3)

    def test_import_counts_top_level_records_and_preserves_original_payload_and_locator(self):
        with tempfile.TemporaryDirectory() as folder:
            source, db = Path(folder) / 'events.jsonl', Path(folder) / 'private.sqlite'
            save(source, sample_events())
            result = import_events(source, db)
            self.assertEqual(result['counts']['record'], 3)
            self.assertEqual(result['counts']['finding'], 1)
            self.assertTrue(result['quality']['event_stream_complete'])
            result = query_events(db)
            self.assertEqual(result['total'], 3)
            self.assertEqual(result['items'][1]['event']['raw'], 'synthetic-1')
            self.assertEqual(result['items'][1]['event']['fields']['target'], '/.env?token=private')
            self.assertEqual(result['items'][1]['event']['offset'], 100)
            self.assertGreater(result['items'][1]['event_offset'], 0)
            self.assertEqual(result['items'][1]['event_line'], 3)
            self.assertTrue(result['private'])


class EventIndexCliTests(unittest.TestCase):
    def test_actual_cli_import_query_timeline_and_private_markdown(self):
        import subprocess
        import sys
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix='索引测试-') as folder:
            source, db = Path(folder) / 'events.jsonl', Path(folder) / 'private.sqlite'
            events = sample_events()
            events[1]['raw'] = '<script>\n# injected'
            save(source, events)
            prefix = [sys.executable, str(root / 'investigate.py')]
            added = subprocess.run(prefix + ['import', str(source), '--database', str(db)],
                                   cwd=folder, capture_output=True, text=True, encoding='utf-8', timeout=15)
            self.assertEqual(added.returncode, 0, added.stderr)
            self.assertEqual(json.loads(added.stdout)['run_id'], 1)
            query = subprocess.run(prefix + ['query', str(db), '--site', 'a.local', '--status', '404'],
                                   capture_output=True, text=True, encoding='utf-8', timeout=15)
            self.assertEqual(query.returncode, 0, query.stderr)
            self.assertEqual(json.loads(query.stdout)['total'], 1)
            output = Path(folder) / 'timeline.md'
            command = prefix + ['timeline', str(db), '--ip', '192.0.2.10', '--site', 'a.local',
                                '--format', 'markdown', '--output', str(output)]
            view = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', timeout=15)
            self.assertEqual(view.returncode, 0, view.stderr)
            text = output.read_text(encoding='utf-8')
            self.assertIn('私有', text)
            self.assertNotIn('\n<script>', text)
            self.assertNotIn('\n# injected', text)
            repeat = subprocess.run(command, capture_output=True, timeout=10)
            self.assertNotEqual(repeat.returncode, 0)
            duplicate = subprocess.run(prefix + ['import', str(source), '--database', str(db), '--append'],
                                       capture_output=True, timeout=15)
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertNotIn(b'Traceback', duplicate.stderr)


if __name__ == '__main__':
    unittest.main()
