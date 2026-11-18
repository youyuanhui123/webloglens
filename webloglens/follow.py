"""Incremental UTF-8 file input; each poll reads a bounded chunk.

Not an exactly-once collector: late writes after rotation handoff and
copytruncate races can lose data. Offsets are bytes within a generation.
"""
import os
from pathlib import Path


def _open_shared(path):
    # CPython's regular Windows open blocks rename/delete while held open.
    if os.name != 'nt':
        return open(path, 'rb', buffering=0)
    import ctypes
    from ctypes import wintypes
    import msvcrt
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                       wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    handle = create(str(path), 0x80000000, 7, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        close = kernel.CloseHandle
        close.argtypes = [wintypes.HANDLE]
        close(handle)
        raise
    return os.fdopen(fd, 'rb', buffering=0)


class FileFollower:
    def __init__(self, path, start='end', chunk_bytes=65536,
                 max_line_bytes=262144):
        if start not in ('beginning', 'end'):
            raise ValueError('start must be beginning or end')
        if chunk_bytes < 1 or max_line_bytes < 1:
            raise ValueError('buffer limits must be positive')
        self.path = Path(path).resolve()
        self.chunk_bytes = chunk_bytes
        self.max_line_bytes = max_line_bytes
        self.file = _open_shared(self.path)
        self.generation = 1
        self.line_number = 0 if start == 'beginning' else None
        self.pending = b''
        self.discard = False
        self.missing = False
        if start == 'end':
            self.file.seek(0, os.SEEK_END)
            size = self.file.tell()
            if size:
                self.file.seek(size - 1)
                self.discard = self.file.read(1) != b'\n'
        self.offset = self.file.tell()
        self._save_anchor()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.file.close()

    def _event(self, kind, **values):
        return dict(type=kind, source=str(self.path), generation=self.generation,
                    offset=self.offset, line_number=self.line_number, **values)

    def _save_anchor(self):
        position = self.file.tell()
        self.anchor_start = max(0, position - 64)
        self.file.seek(self.anchor_start)
        self.anchor = self.file.read(position - self.anchor_start)
        self.file.seek(position)

    def _changed(self):
        position = self.file.tell()
        self.file.seek(self.anchor_start)
        changed = self.file.read(len(self.anchor)) != self.anchor
        self.file.seek(position)
        return changed or os.fstat(self.file.fileno()).st_size < position

    def _reset(self):
        self.generation += 1
        self.offset = 0
        self.line_number = 0
        self.pending = b''
        self.discard = False
        self.file.seek(0)
        self._save_anchor()

    def poll(self):
        events = []
        if self._changed():
            events.append(self._event('truncated', pending_bytes=len(self.pending)))
            self._reset()
        chunk = self.file.read(self.chunk_bytes)
        self._save_anchor()
        # Splitting one bounded chunk does not accumulate the whole file.
        parts = chunk.split(b'\n')
        for index, part in enumerate(parts):
            complete = index < len(parts) - 1
            if not part and not complete:
                continue
            if not self.discard and len(self.pending) + len(part) > self.max_line_bytes:
                event = self._event('line_too_long', limit=self.max_line_bytes)
                # No newline has been consumed yet; the event concerns the next line.
                if self.line_number is not None:
                    event['line_number'] = self.line_number + 1
                events.append(event)
                self.offset += len(self.pending)
                self.pending = b''
                self.discard = True
            if self.discard:
                self.offset += len(part) + int(complete)
            else:
                self.pending += part
            if complete:
                if self.line_number is not None:
                    self.line_number += 1
                if not self.discard:
                    payload = self.pending.removesuffix(b'\r')
                    try:
                        raw = payload.decode('utf-8-sig' if self.offset == 0 else 'utf-8')
                        events.append(self._event('line', raw=raw))
                    except UnicodeDecodeError:
                        events.append(self._event('decode_error'))
                    self.offset += len(self.pending) + 1
                self.pending = b''
                self.discard = False
        try:
            current = self.path.stat()
        except FileNotFoundError:
            if not self.missing:
                events.append(self._event('path_missing'))
            self.missing = True
            return events
        if self.missing:
            events.append(self._event('path_available'))
            self.missing = False
        old = os.fstat(self.file.fileno())
        if (current.st_dev, current.st_ino) != (old.st_dev, old.st_ino):
            if self.file.tell() >= old.st_size:
                try:
                    replacement = _open_shared(self.path)
                except FileNotFoundError:
                    # The path can disappear between stat and open during rotation.
                    # Return the old file's events instead of losing them on an exception.
                    if not self.missing:
                        events.append(self._event('path_missing'))
                    self.missing = True
                    return events
                events.append(self._event('rotated', pending_bytes=len(self.pending)))
                self.file.close()
                self.file = replacement
                self._reset()
        return events
