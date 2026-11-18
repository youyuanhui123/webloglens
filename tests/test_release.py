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
            self.assertEqual(version.stdout.strip(), 'WebLogLens 1.0.0')
            default = subprocess.run([sys.executable, str(extracted / 'analyze.py')],
                                     cwd=folder, capture_output=True, text=True, encoding='utf-8')
            self.assertEqual(default.returncode, 0, default.stderr)
            self.assertEqual(json.loads(default.stdout)['parsing']['errors'], 0)
            second = subprocess.run(command, capture_output=True, text=True, encoding='utf-8')
            self.assertNotEqual(second.returncode, 0)


if __name__ == '__main__':
    unittest.main()
