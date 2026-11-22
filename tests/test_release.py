import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]


class ReleaseTests(unittest.TestCase):
    def test_portable_assembly_entry(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder) / 'rolling'
            run = subprocess.run([sys.executable, str(ROOT / 'watch.py'),
                                  str(ROOT / 'examples/synthetic_sites.jsonl'), '--replay',
                                  '--log-format', 'nginx-json', '--output-dir', str(directory),
                                  '--output-max-bytes', '4096'], capture_output=True, timeout=15)
            self.assertEqual(run.returncode, 0, run.stderr)
            result = subprocess.run([sys.executable, str(ROOT / 'assemble_events.py'),
                                     str(directory), '--output', str(Path(folder) / 'joined.jsonl')],
                                    cwd=folder, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = (Path(folder) / 'joined.jsonl').read_bytes()
            self.assertEqual(json.loads(data.splitlines()[0])['type'], 'started')
            self.assertEqual(json.loads(data.splitlines()[-1])['type'], 'summary')
            repeated = subprocess.run([sys.executable, str(ROOT / 'assemble_events.py'),
                                       str(directory), '--output', str(Path(folder) / 'joined.jsonl')],
                                      cwd=folder, capture_output=True, timeout=15)
            self.assertEqual(repeated.returncode, 1)
            self.assertEqual((Path(folder) / 'joined.jsonl').read_bytes(), data)

    def test_v3_package_contains_all_runtime_tests_and_portable_replay_report(self):
        with tempfile.TemporaryDirectory(prefix='webloglens-中文-') as folder:
            output = Path(folder) / 'v3.zip'
            run = subprocess.run([sys.executable, str(ROOT / 'build_release.py'), '--output', str(output)],
                                 capture_output=True, text=True, encoding='utf-8', timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            with zipfile.ZipFile(output) as archive:
                names = set(archive.namelist())
                required = ['watch.py', 'report_events.py', 'run_baseline.py', 'run_nginx_experiment.py',
                            'investigate.py', 'assemble_events.py', 'webloglens/output.py', 'docs/V3-RUNTIME.md',
                            'docs/RELEASE-3.0.0.md', 'webloglens/event_index.py',
                            'webloglens/follow.py', 'webloglens/stream.py', 'webloglens/event_report.py',
                            'webloglens/nginx_lab.py', 'docs/V2-REALTIME.md', 'docs/EVENT-REPORT.md',
                            'docs/BASELINE.md', 'docs/NGINX-LAB.md']
                required += ['tests/' + path.name for path in (ROOT / 'tests').glob('test_*.py')]
                self.assertTrue(set('WebLogLens/' + name for name in required) <= names)
                self.assertFalse(any('/acceptance/' in name or '/dist/' in name or
                                     name.endswith('/study.md') for name in names))
                archive.extractall(Path(folder) / '迁移目录')
            extracted = Path(folder) / '迁移目录' / 'WebLogLens'
            events = Path(folder) / 'events.jsonl'
            replay = subprocess.run([sys.executable, str(extracted / 'watch.py'),
                                     str(extracted / 'examples/synthetic_sensitive.log'),
                                     '--replay', '--min-paths', '3', '--output', str(events)],
                                    cwd=folder, capture_output=True, text=True, encoding='utf-8', timeout=15)
            self.assertEqual(replay.returncode, 0, replay.stderr)
            report = subprocess.run([sys.executable, str(extracted / 'report_events.py'), str(events),
                                     '--format', 'json'], cwd=folder, capture_output=True,
                                    text=True, encoding='utf-8', timeout=15)
            self.assertEqual(report.returncode, 0, report.stderr)
            result = json.loads(report.stdout)
            self.assertEqual(result['observed']['counts']['record'], 5)
            self.assertEqual(result['observed']['counts']['finding'], 3)
            self.assertTrue(result['quality']['event_stream_complete'])
            database = Path(folder) / 'private.sqlite'
            imported = subprocess.run([sys.executable, str(extracted / 'investigate.py'), 'import',
                                       str(events), '--database', str(database)], cwd=folder,
                                      capture_output=True, text=True, encoding='utf-8', timeout=15)
            self.assertEqual(imported.returncode, 0, imported.stderr)
            indexed = subprocess.run([sys.executable, str(extracted / 'investigate.py'), 'query', str(database)],
                                     cwd=folder, capture_output=True, text=True, encoding='utf-8', timeout=15)
            self.assertEqual(indexed.returncode, 0, indexed.stderr)
            self.assertEqual(json.loads(indexed.stdout)['total'], 5)

    def test_release_is_allowlisted_and_runs_after_extraction(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'release.zip'
            command = [sys.executable, str(ROOT / 'build_release.py'), '--output', str(output)]
            run = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            with zipfile.ZipFile(output) as archive:
                names = archive.namelist()
                self.assertTrue(all(name.startswith('WebLogLens/') for name in names))
                self.assertFalse(any('/experiments/' in name or '__pycache__' in name or '.env' in name for name in names))
                manifest = json.loads(archive.read('WebLogLens/RELEASE-MANIFEST.json'))
                self.assertEqual(len(names), manifest['file_count'] + 1)
                for name, digest in manifest['sha256'].items():
                    self.assertEqual(hashlib.sha256(archive.read('WebLogLens/' + name)).hexdigest(), digest)
                archive.extractall(Path(folder) / 'unpacked')
            extracted = Path(folder) / 'unpacked' / 'WebLogLens'
            version = subprocess.run([sys.executable, str(extracted / 'analyze.py'), '--version'],
                                     cwd=folder, capture_output=True, text=True, encoding='utf-8')
            self.assertEqual(version.returncode, 0, version.stderr)
            self.assertEqual(version.stdout.strip(), 'WebLogLens 3.0.0')
            default = subprocess.run([sys.executable, str(extracted / 'analyze.py')],
                                     cwd=folder, capture_output=True, text=True, encoding='utf-8')
            self.assertEqual(default.returncode, 0, default.stderr)
            self.assertEqual(json.loads(default.stdout)['parsing']['errors'], 0)
            second = subprocess.run(command, capture_output=True, text=True, encoding='utf-8')
            self.assertNotEqual(second.returncode, 0)


if __name__ == '__main__':
    unittest.main()
