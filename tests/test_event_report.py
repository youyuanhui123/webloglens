import json
from pathlib import Path
import tempfile
import unittest

from webloglens.event_report import summarize_events


class EventReportTests(unittest.TestCase):
    def test_detection_summary_is_required_and_unknown_rules_fail_closed(self):
        fixtures = [
            [dict(type='started', stage='detection'), dict(type='summary', counts={})],
            [dict(type='started', stage='detection'),
             dict(type='finding', rule_id='future-rule'),
             dict(type='summary', counts={'finding': 1}, analysis={})],
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            for events in fixtures:
                path.write_text(''.join(json.dumps(e) + '\n' for e in events), encoding='utf-8')
                report = summarize_events(path)
                self.assertFalse(report['quality']['event_stream_complete'])
                self.assertTrue(report['quality']['analysis_has_gaps'])

    def test_markdown_keeps_untrusted_values_in_code_and_explains_gaps_and_omission(self):
        from webloglens.event_report import render_stage_markdown
        events = [dict(type='started', stage='input-only', source='<script>\n# injected'),
                  dict(type='finding', rule_id='sensitive-path-exact-v1', raw='```\n<script>bad</script>'),
                  dict(type='summary', counts={'finding': 1})]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            path.write_text(''.join(json.dumps(e) + '\n' for e in events), encoding='utf-8')
            report = summarize_events(path, max_samples=0)
            text = render_stage_markdown(report)
            with_sample = render_stage_markdown(summarize_events(path, max_samples=1))
        self.assertIn('bad</script>', with_sample)
        self.assertNotIn('\n<script>', with_sample)
        self.assertNotIn('\n```', with_sample)
        self.assertTrue(report['quality']['analysis_has_gaps'])
        self.assertIn('detection_not_enabled', report['quality']['issues'])
        self.assertIn('分析存在缺口', text)
        self.assertIn('省略 1', text)
        self.assertNotIn('\n<script>', text)
        self.assertNotIn('\n# injected', text)
        self.assertIn('私有', text)

    def test_malformed_truncated_unknown_and_multiple_runs_are_explicit(self):
        contents = [
            b'{"type":"started"}\nnot-json\n{"type":"summary","counts":{}}\n',
            b'{"type":"started"}\n{"type":"record"',
            b'{"type":"started"}\n{"type":"future-kind"}\n{"type":"summary","counts":{}}\n',
            b'{"type":"started"}\n{"type":"started"}\n{"type":"summary","counts":{}}\n',
            b'{"type":"started","type":"summary"}\n',
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            for content in contents:
                path.write_bytes(content)
                report = summarize_events(path)
                self.assertFalse(report['quality']['event_stream_complete'])
                self.assertTrue(report['quality']['analysis_has_gaps'])

    def test_oversized_lines_and_samples_are_bounded_but_hash_covers_original_bytes(self):
        import hashlib
        content = (b'{"type":"started"}\n' + b'x' * 2000 + b'\n' +
                   json.dumps(dict(type='finding', rule_id='sensitive-path-exact-v1',
                                   raw='y' * 100)).encode() + b'\n' +
                   b'{"type":"summary","counts":{"finding":1}}\n')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            path.write_bytes(content)
            report = summarize_events(path, max_event_bytes=512, max_sample_bytes=32)
        self.assertEqual(report['input']['sha256'], hashlib.sha256(content).hexdigest())
        self.assertEqual(report['input']['physical_lines'], 4)
        self.assertEqual(report['samples']['retained'], 0)
        self.assertEqual(report['samples']['omitted'], 1)
        self.assertEqual(report['samples']['oversized_or_budget_skipped'], 1)
        self.assertIn('oversized_event_line', report['quality']['issues'])
        self.assertFalse(report['quality']['event_stream_complete'])

    def test_declared_counts_mismatch_and_late_records_are_not_a_clean_run(self):
        events = [dict(type='started'), dict(type='late_record', evidence=[]),
                  dict(type='state_limit', reason='max_buffer'),
                  dict(type='summary', counts={'record': 10, 'late_record': 1, 'state_limit': 1},
                       analysis={'records': 10})]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            path.write_text(''.join(json.dumps(e) + '\n' for e in events), encoding='utf-8')
            report = summarize_events(path)
        self.assertFalse(report['quality']['event_stream_complete'])
        self.assertTrue(report['quality']['analysis_has_gaps'])
        self.assertIn('declared_counts_mismatch', report['quality']['issues'])
        self.assertIn('late_records_excluded', report['quality']['issues'])
        self.assertIn('capacity_limit_excluded', report['quality']['issues'])
        self.assertEqual(report['observed']['counts'].get('record', 0), 0)
        self.assertEqual(report['run']['summary']['counts']['record'], 10)

    def test_totals_and_bounded_samples_do_not_count_finding_evidence_as_requests(self):
        events = [dict(type='started', mode='watch', source='access.log', settings={})]
        for index in range(4):
            events += [dict(type='record', fields={'status': 404}),
                       dict(type='finding', rule_id='sensitive-path-exact-v1',
                            evidence=[{'raw': 'private', 'offset': index}])]
        events += [dict(type='summary', counts={'record': 4, 'finding': 4},
                        analysis={'records': 4, 'path_findings': 4})]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            path.write_text(''.join(json.dumps(e) + '\n' for e in events), encoding='utf-8')
            report = summarize_events(path, max_samples=2)
        self.assertEqual(report['observed']['counts']['record'], 4)
        self.assertEqual(report['observed']['counts']['finding'], 4)
        self.assertEqual(report['samples']['retained'], 2)
        self.assertEqual(report['samples']['omitted'], 2)
        self.assertEqual(len(report['finding_samples']), 2)
        self.assertTrue(report['quality']['event_stream_complete'])
        self.assertFalse(report['quality']['analysis_has_gaps'])
        self.assertEqual(len(report['input']['sha256']), 64)


if __name__ == '__main__':
    unittest.main()
