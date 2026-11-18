import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'analyze.py'
GOOD = ('192.0.2.10 - - [05/Nov/2026:10:00:00 +0800] '
        '"GET /.env HTTP/1.1" 200 64 "-" "LearningClient/1.0"')


class CliTests(unittest.TestCase):
    def test_export_full_report_from_any_working_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'input.log'
            output = Path(folder) / 'report.json'
            source.write_text(GOOD + '\nBROKEN\n\n', encoding='utf-8')
            run = subprocess.run([
                sys.executable, str(SCRIPT), str(source),
                '--output', str(output), '--data-kind', 'synthetic',
            ], cwd=folder, capture_output=True, text=True, encoding='utf-8')
            self.assertEqual(run.returncode, 0, run.stderr)
            report = json.loads(output.read_text(encoding='utf-8'))
            self.assertEqual(report['schema_version'], '1.1')
            self.assertEqual(report['source']['data_kind'], 'synthetic')
            self.assertEqual(report['source']['path'], str(source.resolve()))
            self.assertEqual(report['parsing'], {
                'total_lines': 3, 'parsed': 1, 'errors': 1, 'blank_lines': 1,
            })
            self.assertEqual(report['summary']['request_count'], 1)
            self.assertEqual(report['finding_count'], 1)
            self.assertEqual(report['findings'][0]['raw'], GOOD)
            self.assertEqual(report['parse_errors'][0]['line_number'], 2)
            self.assertEqual(report['records'][0]['line_number'], 1)
            self.assertTrue(report['limitations'])

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'input.log'
            output = Path(folder) / 'report.json'
            source.write_text(GOOD + '\n', encoding='utf-8')
            output.write_text('KEEP THIS CONTENT', encoding='utf-8')
            run = subprocess.run([
                sys.executable, str(SCRIPT), str(source), '--output', str(output),
            ], capture_output=True, text=True, encoding='utf-8')
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual(output.read_text(encoding='utf-8'), 'KEEP THIS CONTENT')

    def test_behavior_options_and_report(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'input.log'
            second = GOOD.replace('/.env', '/other')
            source.write_text(GOOD + '\n' + second + '\n', encoding='utf-8')
            run = subprocess.run([
                sys.executable, str(SCRIPT), str(source),
                '--window-seconds', '60', '--min-paths', '2',
            ], capture_output=True, text=True, encoding='utf-8')
            self.assertEqual(run.returncode, 0, run.stderr)
            report = json.loads(run.stdout)
            self.assertEqual(report['schema_version'], '1.1')
            self.assertEqual(report['behavior']['config']['min_paths'], 2)
            self.assertEqual(len(report['behavior']['findings']), 1)
            self.assertEqual(report['behavior']['time_errors'], [])
            self.assertEqual(report['finding_count'], 2)
            self.assertEqual(len(report['findings']), 2)

    def test_markdown_export_and_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'input.log'
            output = Path(folder) / 'report.md'
            source.write_text(GOOD + '\n', encoding='utf-8')
            command = [sys.executable, str(SCRIPT), str(source), '--format', 'markdown',
                       '--data-kind', 'local-experiment', '--output', str(output)]
            first = subprocess.run(command, capture_output=True, text=True, encoding='utf-8')
            self.assertEqual(first.returncode, 0, first.stderr)
            text = output.read_text(encoding='utf-8')
            self.assertIn('# WebLogLens 日志分析报告', text)
            self.assertIn('本地实验日志', text)
            self.assertIn('"line_number": 1', text)
            self.assertIn('"target": "/.env"', text)
            self.assertIn('不证明攻击成功', text)
            second = subprocess.run(command, capture_output=True, text=True, encoding='utf-8')
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(output.read_text(encoding='utf-8'), text)


    def test_config_and_cli_override_are_recorded(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'input.log'
            config = Path(folder) / 'rules.json'
            source.write_text(GOOD + '\n' + GOOD.replace('/.env', '/other') + '\n', encoding='utf-8')
            config.write_text(json.dumps({'sensitive_paths': [], 'window_seconds': 90, 'min_paths': 8}), encoding='utf-8')
            base = [sys.executable, str(SCRIPT), str(source), '--config', str(config)]
            first = subprocess.run(base, capture_output=True, text=True, encoding='utf-8')
            self.assertEqual(first.returncode, 0, first.stderr)
            report = json.loads(first.stdout)
            self.assertEqual(report['finding_count'], 0)
            self.assertEqual(report['configuration']['cli_overrides'], {})
            second = subprocess.run(base + ['--min-paths', '2'], capture_output=True, text=True, encoding='utf-8')
            self.assertEqual(second.returncode, 0, second.stderr)
            report = json.loads(second.stdout)
            self.assertEqual(report['finding_count'], 1)
            self.assertEqual(report['configuration']['path'], str(config.resolve()))
            self.assertEqual(report['configuration']['effective'], {
                'sensitive_paths': [], 'window_seconds': 90, 'min_paths': 2})
            self.assertEqual(report['configuration']['cli_overrides'], {'min_paths': 2})

    def test_invalid_config_does_not_export_report(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'input.log'
            config = Path(folder) / 'bad.json'
            output = Path(folder) / 'report.json'
            source.write_text(GOOD + '\n', encoding='utf-8')
            config.write_text('{"min_path": 5}', encoding='utf-8')
            run = subprocess.run([
                sys.executable, str(SCRIPT), str(source), '--config', str(config), '--output', str(output),
            ], capture_output=True, text=True, encoding='utf-8')
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse(output.exists())
            self.assertIn('Config', run.stderr)
            self.assertNotIn('Traceback', run.stderr)


    def test_sharing_json_and_markdown_remove_private_values(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'PRIVATE-SENTINEL.log'
            source.write_text(GOOD.replace('/.env', '/.env?token=PRIVATE-SENTINEL') + '\n'
                              + GOOD.replace('/.env', '/other') + '\nPRIVATE-SENTINEL\n', encoding='utf-8')
            for format in ['json', 'markdown']:
                with self.subTest(format=format):
                    run = subprocess.run([
                        sys.executable, str(SCRIPT), str(source), '--min-paths', '2',
                        '--redact-share', '--format', format,
                    ], capture_output=True, text=True, encoding='utf-8')
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertNotIn('PRIVATE-SENTINEL', run.stdout)
                    self.assertNotIn('192.0.2.10', run.stdout)
                    self.assertNotIn('/.env', run.stdout)
                    self.assertIn('IP-001', run.stdout)
                    if format == 'json':
                        report = json.loads(run.stdout)
                        self.assertEqual(report['privacy']['mode'], 'share-redacted')
                        self.assertEqual(report['finding_count'], 2)
                        self.assertEqual(report['behavior']['findings'][0]['evidence_line_numbers'], [1, 2])
                    else:
                        self.assertIn('分享版', run.stdout)
                        self.assertNotIn('未自动脱敏', run.stdout)


    def test_version(self):
        run = subprocess.run([sys.executable, str(SCRIPT), '--version'],
                             capture_output=True, text=True, encoding='utf-8')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), 'WebLogLens 1.0.0')

    def test_missing_input_and_invalid_utf8_fail_without_export(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'input.log'
            output = Path(folder) / 'report.json'
            for exists in [False, True]:
                if exists:
                    source.write_bytes(b'\xff\xfe\x80')
                run = subprocess.run([sys.executable, str(SCRIPT), str(source), '--output', str(output)],
                                     capture_output=True, text=True, encoding='utf-8')
                self.assertNotEqual(run.returncode, 0)
                self.assertFalse(output.exists())
                self.assertNotIn('Traceback', run.stderr)


if __name__ == '__main__':
    unittest.main()
