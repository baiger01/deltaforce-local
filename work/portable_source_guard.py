"""Hold source bytes immutable on Windows; retain exact hashes elsewhere."""
import ctypes
from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
from copy import deepcopy
from functools import wraps
import hashlib
import os
from pathlib import Path
import stat
import threading
import time


_qualification_cache = ContextVar('portable_admission_qualification_cache', default=None)


@contextmanager
def qualification_scope():
    """Share pure schema derivations only while their exact source leases live."""
    if _qualification_cache.get() is not None:
        yield
        return
    with ExitStack() as leases:
        token = _qualification_cache.set(({}, leases))
        try:
            yield
        finally:
            _qualification_cache.reset(token)


def cached_qualification(root, *, extra_pins=None):
    """Cache a zero-argument source-qualified schema within one admission."""
    def decorate(function):
        @wraps(function)
        def qualified():
            scope = _qualification_cache.get()
            if scope is None:
                return function()
            entries, leases = scope
            if function in entries:
                value, _ = entries[function]
                if not all(guard() for _, guard in entries.values()):
                    raise ValueError('A cached admission qualification source changed')
                return deepcopy(value)
            if len(entries) >= 64:
                raise ValueError('The admission qualification cache exceeds its bound')
            value = function()
            if type(value) is not dict or type(value.get('sources')) is not dict:
                raise ValueError('A cached qualification requires its exact source pins')
            pins = dict(value['sources'])
            for path, digest in (extra_pins() if extra_pins is not None else {}).items():
                if path in pins and pins[path] != digest:
                    raise ValueError('The admission qualification source pins disagree')
                pins[path] = digest
            guard = SourceGuard(root, pins)
            leases.callback(guard.close)
            entries[function] = (deepcopy(value), guard)
            return deepcopy(value)
        return qualified
    return decorate


def _fingerprint(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _open_locked(path):
    if os.name != 'nt':
        return path.open('rb')
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes, close.restype = (wintypes.HANDLE,), wintypes.BOOL
    filename = str(path)
    if not filename.startswith('\\\\?\\'):
        filename = '\\\\?\\UNC\\' + filename[2:] if filename.startswith('\\\\') else '\\\\?\\' + filename
    # FILE_SHARE_READ denies writers and rename/delete for this handle's lifetime.
    handle = create(filename, 0x80000000, 1, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        close(handle)
        raise
    try:
        os.set_inheritable(descriptor, False)
        return os.fdopen(descriptor, 'rb', buffering=0)
    except BaseException:
        os.close(descriptor)
        raise


class SourceGuard:
    """One hash-qualified, closable source lease, with no metadata-only cache."""
    # Admission profiles transfer this lease's cleanup to their owning probe.
    _probe_owned_source_lease = True

    def __init__(self, root, pins):
        self._files, self._closed = [], True
        self._current_until = 0.0
        self._lock = threading.RLock()
        root = Path(root).resolve(strict=True)
        if not root.is_dir() or type(pins) is not dict or not 1 <= len(pins) <= 4096:
            raise ValueError('A bounded exact source set and existing root are required')
        try:
            total = 0
            for relative, digest in sorted(pins.items()):
                if (type(relative) is not str or '\\' in relative or
                        Path(relative).is_absolute() or '..' in Path(relative).parts or
                        type(digest) is not str or len(digest) != 64 or
                        any(c not in '0123456789abcdef' for c in digest)):
                    raise ValueError('Sources require canonical relative paths and exact SHA256')
                path = root/relative
                resolved = path.resolve(strict=True)
                if resolved != path or not resolved.is_relative_to(root):
                    raise ValueError('A source escaped or aliased its frozen project root')
                stream = _open_locked(path)
                self._files.append((path, stream, digest, None))
                before = os.fstat(stream.fileno())
                before_path = path.stat()
                total += before.st_size
                if (not stat.S_ISREG(before.st_mode) or before.st_size > 64*1024*1024 or
                        total > 512*1024*1024):
                    raise ValueError('The source set exceeds its fixed file/byte bound')
                actual = hashlib.file_digest(stream, 'sha256').hexdigest()
                expected = (_fingerprint(before), _fingerprint(before_path))
                if actual != digest:
                    raise ValueError('A source hash changed during qualification: ' + relative)
                if (expected[0][:5] != expected[1][:5] or
                        _fingerprint(os.fstat(stream.fileno())) != expected[0] or
                        _fingerprint(path.stat()) != expected[1]):
                    raise ValueError('A source file identity changed during qualification: ' + relative)
                self._files[-1] = (path, stream, digest, expected)
            self._files = tuple(self._files)
            self._closed = False
        except BaseException:
            self.close()
            raise

    def __call__(self):
        with self._lock:
            if self._closed:
                return False
            # On Windows every source stays open with FILE_SHARE_READ, so no
            # writer, rename or delete can occur while the lease is open. A
            # full re-stat of hundreds of files on each network packet only
            # stalls the receiver; reuse a positive result for a short window.
            now = time.monotonic()
            if os.name == 'nt' and now < self._current_until:
                return True
            try:
                for path, stream, digest, expected in self._files:
                    if (stream.closed or _fingerprint(path.stat()) != expected[1] or
                            _fingerprint(os.fstat(stream.fileno())) != expected[0]):
                        return False
                    if os.name != 'nt':
                        stream.seek(0)
                        if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                            return False
                        if _fingerprint(path.stat()) != expected[1]:
                            return False
                self._current_until = now + 1.0
                return True
            except (OSError, ValueError):
                return False

    def close(self):
        with self._lock:
            self._closed = True
            self._current_until = 0.0
            failed, errors = [], []
            for entry in self._files:
                try:
                    entry[1].close()
                except Exception as error:
                    failed.append(entry)
                    errors.append(error)
            self._files = tuple(failed)
            if len(errors) == 1:
                raise errors[0]
            if errors:
                raise ExceptionGroup('Source lease cleanup failed', errors)

    def __enter__(self):
        if not self():
            raise ValueError('The source lease is no longer current')
        return self

    def __exit__(self, *unused):
        self.close()

    def __del__(self):
        if hasattr(self, '_lock'):
            self.close()
