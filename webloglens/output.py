"""Private rolling JSONL evidence. Assemble only finalized, intact runs.

A byte target never splits a line: one oversized event occupies its own shard.
Directories are exclusive per run. No resume or automatic recovery is attempted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys


class RollingOutput:
    def __init__(self, directory, max_bytes, keep_shards=None):
        if not isinstance(max_bytes, int) or max_bytes < 1:
            raise ValueError('max_bytes must be a positive integer')
        if keep_shards is not None and (not isinstance(keep_shards, int) or keep_shards < 1):
            raise ValueError('keep_shards must be a positive integer')
        self.keep_shards = keep_shards
        self.directory = Path(directory)
        self.directory.mkdir()
        self.max_bytes = max_bytes
        self.manifest = dict(format='webloglens-rolling-v1', complete=False, shards=[])
        self.file = None
        self.first_type = None
        self.last_type = None
        self._save()

    def _save(self):
        temp = self.directory / 'manifest.tmp'
        with temp.open('x', encoding='utf-8') as stream:
            json.dump(self.manifest, stream, ensure_ascii=True, indent=2)
            stream.write('\n')
        temp.replace(self.directory / 'manifest.json')

    def __enter__(self):
        return self

    def _finish_shard(self):
        if self.file is not None:
            self.file.close()
            self.file = None
            self.manifest['shards'][-1]['sha256'] = self.digest.hexdigest()

    def write(self, line):
        if not line.endswith('\n') or '\n' in line[:-1] or '\r' in line:
            raise ValueError('write requires exactly one complete JSONL line')
        event = json.loads(line)
        data = line.encode('utf-8')
        if self.file is None or (self.size and self.size + len(data) > self.max_bytes):
            self._finish_shard()
            name = f"part-{len(self.manifest['shards']) + 1:06d}.jsonl"
            self.file = (self.directory / name).open('xb')
            self.size = 0
            self.digest = hashlib.sha256()
            self.manifest['shards'].append(dict(name=name, bytes=0, sha256=None, deleted=False))
            self._save()
            if self.keep_shards is not None:
                for item in self.manifest['shards'][:-self.keep_shards]:
                    if not item['deleted']:
                        item['deleted'] = True
                        self._save()
                        (self.directory / item['name']).unlink()
        self.file.write(data)
        self.file.flush()
        self.digest.update(data)
        self.size += len(data)
        self.manifest['shards'][-1]['bytes'] = self.size
        if self.first_type is None:
            self.first_type = event.get('type')
        self.last_type = event.get('type')

    def __exit__(self, exc_type, exc, tb):
        self._finish_shard()
        self.manifest['complete'] = (exc_type is None and self.first_type == 'started'
                                     and self.last_type == 'summary')
        self._save()


def assemble(directory, output):
    """Validate all manifest shards then create a new, complete JSONL file."""
    directory = Path(directory)
    manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('format') != 'webloglens-rolling-v1' or not manifest.get('complete'):
        raise ValueError('run is not finalized and complete')
    shards = manifest['shards']
    if not shards:
        raise ValueError('manifest has no shards')
    paths = []
    for index, item in enumerate(shards, 1):
        if item['name'] != f'part-{index:06d}.jsonl' or item.get('deleted'):
            raise ValueError('manifest contains missing/deleted or invalid shards')
        path = directory / item['name']
        digest = hashlib.sha256()
        size = 0
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(65536), b''):
                size += len(block)
                digest.update(block)
        if size != item['bytes'] or digest.hexdigest() != item['sha256']:
            raise ValueError('shard integrity check failed: ' + item['name'])
        paths.append(path)
    target = Path(output)
    dest = target.open('xb')  # Only clean up a target created by this call.
    try:
        for path, item in zip(paths, shards):
            digest = hashlib.sha256()
            size = 0
            with path.open('rb') as stream:
                for block in iter(lambda: stream.read(65536), b''):
                    size += len(block)
                    digest.update(block)
                    dest.write(block)
            if size != item['bytes'] or digest.hexdigest() != item['sha256']:
                raise ValueError('shard integrity changed during assembly: ' + item['name'])
        dest.close()  # Buffered flush/close failures also invalidate the target.
    except BaseException as exc:
        try:
            dest.close()
        except BaseException as cleanup_error:
            exc.add_note(f'assembly target close failed: {cleanup_error}')
        try:
            target.unlink()
        except BaseException as cleanup_error:
            exc.add_note(f'assembly target removal failed: {cleanup_error}')
        raise
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('assemble', help='refuse incomplete, deleted or corrupt shards')
    command.add_argument('directory')
    command.add_argument('--output', required=True, help='new JSONL; never overwrite')
    args = parser.parse_args(argv)
    assemble(args.directory, args.output)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'assemble failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
