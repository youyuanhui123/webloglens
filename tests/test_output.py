import errno
import importlib
import io
import json
from pathlib import Path
import tempfile
import unittest


class OutputTests(unittest.TestCase):
    def test_buffered_close_failure_removes_partial_target(self):
        from unittest.mock import patch
        api = importlib.import_module('webloglens.output')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'run'
            target = Path(tmp) / 'all.jsonl'
            with api.RollingOutput(root, max_bytes=1000) as writer:
                writer.write('{"type":"started"}\n')
                writer.write('{"type":"summary"}\n')
            original_open = Path.open
            written = bytearray()

            class FailingRaw(io.RawIOBase):
                def __init__(self):
                    self.file = original_open(target, 'xb', buffering=0)

                def writable(self):
                    return True

                def write(self, data):
                    if written:
                        raise OSError(errno.ENOSPC, 'injected disk full')
                    chunk = bytes(data[:20])
                    count = self.file.write(chunk)
                    written.extend(chunk[:count])
                    return count

                def close(self):
                    try:
                        self.file.close()
                    finally:
                        super().close()

            def failing_open(path, *args, **kwargs):
                if path == target and args == ('xb',):
                    return io.BufferedWriter(FailingRaw())
                return original_open(path, *args, **kwargs)

            with patch.object(Path, 'open', failing_open):
                with self.assertRaisesRegex(OSError, 'injected disk full') as caught:
                    api.assemble(root, target)
            self.assertEqual(caught.exception.errno, errno.ENOSPC)
            self.assertEqual(written, b'{"type":"started"}\n{')
            self.assertFalse(target.exists())

    def test_write_error_survives_close_and_removal_cleanup_failures(self):
        from unittest.mock import patch
        api = importlib.import_module('webloglens.output')
        for removal_fails in (False, True):
            with self.subTest(removal_fails=removal_fails), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / 'run'
                target = Path(tmp) / 'all.jsonl'
                with api.RollingOutput(root, max_bytes=1000) as writer:
                    writer.write('{"type":"started"}\n')
                    writer.write('{"type":"summary"}\n')
                original_open = Path.open
                original_unlink = Path.unlink
                initial_error = OSError(errno.ENOSPC, 'initial write failure')

                class FailingDestination:
                    def __init__(self):
                        self.file = original_open(target, 'xb', buffering=0)

                    def write(self, data):
                        self.file.write(data[:20])
                        raise initial_error

                    def close(self):
                        self.file.close()
                        raise OSError(errno.EIO, 'secondary close failure')

                def failing_open(path, *args, **kwargs):
                    if path == target and args == ('xb',):
                        return FailingDestination()
                    return original_open(path, *args, **kwargs)

                def failing_unlink(path, *args, **kwargs):
                    if path == target and removal_fails:
                        raise PermissionError('secondary removal failure')
                    return original_unlink(path, *args, **kwargs)

                with patch.object(Path, 'open', failing_open), \
                        patch.object(Path, 'unlink', failing_unlink):
                    with self.assertRaises(OSError) as caught:
                        api.assemble(root, target)
                self.assertIs(caught.exception, initial_error)
                self.assertTrue(any('secondary close failure' in note
                                    for note in initial_error.__notes__))
                self.assertEqual(target.exists(), removal_fails)
                if removal_fails:
                    self.assertTrue(any('secondary removal failure' in note
                                        for note in initial_error.__notes__))

    def test_source_changed_during_assembly_fails_and_removes_partial_target(self):
        from unittest.mock import patch
        api = importlib.import_module('webloglens.output')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'run'
            target = Path(tmp) / 'all.jsonl'
            with api.RollingOutput(root, max_bytes=1000) as writer:
                writer.write('{"type":"started"}\n')
                writer.write('{"type":"summary"}\n')
            original_open = Path.open
            def racing_open(path, *args, **kwargs):
                if path == target and args == ('xb',):
                    (root / 'part-000001.jsonl').write_bytes(b'changed\n')
                return original_open(path, *args, **kwargs)
            with patch.object(Path, 'open', racing_open):
                with self.assertRaisesRegex(ValueError, 'integrity'):
                    api.assemble(root, target)
            self.assertFalse(target.exists())

    def test_existing_shard_collision_fails_without_overwrite_and_run_is_incomplete(self):
        api = importlib.import_module('webloglens.output')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'run'
            with self.assertRaises(FileExistsError):
                with api.RollingOutput(root, max_bytes=1) as writer:
                    writer.write('{"type":"started"}\n')
                    collision = root / 'part-000002.jsonl'
                    collision.write_bytes(b'foreign')
                    writer.write('{"type":"summary"}\n')
            self.assertEqual(collision.read_bytes(), b'foreign')
            self.assertFalse(json.loads((root / 'manifest.json').read_text())['complete'])

    def test_explicit_retention_removes_only_owned_shards_and_refuses_assembly(self):
        api = importlib.import_module('webloglens.output')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'run'
            with api.RollingOutput(root, max_bytes=1, keep_shards=1) as writer:
                foreign = root / 'foreign.jsonl'
                foreign.write_text('untouched', encoding='utf-8')
                for kind in ('started', 'record', 'summary'):
                    writer.write(json.dumps({'type': kind}) + '\n')
            self.assertEqual(foreign.read_text(), 'untouched')
            manifest = json.loads((root / 'manifest.json').read_text())
            self.assertEqual([s['deleted'] for s in manifest['shards']], [True, True, False])
            with self.assertRaisesRegex(ValueError, 'deleted'):
                api.assemble(root, Path(tmp) / 'all.jsonl')

    def test_incomplete_missing_and_corrupt_shards_fail_without_output(self):
        api = importlib.import_module('webloglens.output')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'run'
            target = Path(tmp) / 'all.jsonl'
            with api.RollingOutput(root, max_bytes=1) as writer:
                writer.write('{"type":"started"}\n')
            with self.assertRaisesRegex(ValueError, 'complete'):
                api.assemble(root, target)
            self.assertFalse(target.exists())
            root2 = Path(tmp) / 'complete'
            with api.RollingOutput(root2, max_bytes=1) as writer:
                writer.write('{"type":"started"}\n')
                writer.write('{"type":"summary"}\n')
            shard = root2 / 'part-000001.jsonl'
            original = shard.read_bytes()
            shard.write_bytes(b'corrupt\n')
            with self.assertRaisesRegex(ValueError, 'integrity'):
                api.assemble(root2, target)
            shard.unlink()
            with self.assertRaises(FileNotFoundError):
                api.assemble(root2, target)
            self.assertFalse(target.exists())

    def test_rotate_whole_utf8_lines_and_assemble_exact_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            api = importlib.import_module('webloglens.output')
            root = Path(tmp) / 'run'
            lines = [json.dumps(e, ensure_ascii=False) + '\n' for e in
                     [{'type': 'started'}, {'type': 'record', 'raw': '中文' * 40},
                      {'type': 'summary'}]]
            with api.RollingOutput(root, max_bytes=40) as writer:
                for line in lines:
                    writer.write(line)
            shards = sorted(root.glob('*.jsonl'))
            self.assertEqual(len(shards), 3)
            self.assertEqual([p.read_bytes() for p in shards],
                             [line.encode('utf-8') for line in lines])
            target = Path(tmp) / 'all.jsonl'
            api.assemble(root, target)
            self.assertEqual(target.read_bytes(), ''.join(lines).encode('utf-8'))
            with self.assertRaises(FileExistsError):
                api.assemble(root, target)
            self.assertEqual(target.read_bytes(), ''.join(lines).encode('utf-8'))
            with self.assertRaises(FileExistsError):
                api.RollingOutput(root, max_bytes=40)
