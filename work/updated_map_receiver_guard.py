"""Recheck the current enabled receiver on one exact read-only process identity."""
import hashlib
import math
from pathlib import Path

from portable_source_guard import SourceGuard
from snapshot_updated_client_code import (
    ROOT, SOURCE_SHA, IMAGE_SIZE, EXECUTABLE_RELATIVE, validate_plan, bounded,
)
from updated_enabled_header_context import source_pins, read_enabled_header_context


class LiveReceiverGuard:
    """No successful observation is cached or transferred to another admission."""
    def __init__(self, game_root, pid, created_at, *, reader_factory=None):
        if (type(pid) is not int or pid <= 0 or type(created_at) not in (int, float) or
                not math.isfinite(created_at) or created_at <= 0):
            raise ValueError('An exact live receiver PID and creation time are required')
        bounded.qualified_shadow_root(game_root)
        self.game_root = Path(game_root).resolve(strict=True)
        self.executable = self.game_root/EXECUTABLE_RELATIVE
        validate_plan(self.game_root)
        if reader_factory is None:
            from export_native_replication_metadata import Win32MetadataReader
            reader_factory = Win32MetadataReader
        self.reader_factory, self.pid, self.created_at = reader_factory, pid, float(created_at)
        self.sources = source_pins()
        for path in ('work/updated_map_receiver_guard.py', 'work/export_native_replication_metadata.py',
                     'work/snapshot_updated_client_code.py', 'work/portable_source_guard.py'):
            self.sources[path] = hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
        self._sources = SourceGuard(ROOT, self.sources)
        self.closed, self.last_observation = False, None

    def __call__(self):
        if self.closed or not self._sources():
            return False
        reader = None
        try:
            reader = self.reader_factory(self.executable, IMAGE_SIZE, self.pid,
                self.created_at, maximum_seconds=10)
            reader.verify_identity()
            result = read_enabled_header_context(reader.read_exact, reader.module_base,
                client_sha256=SOURCE_SHA)
            reader.verify_identity()
            if not self._sources():
                raise ValueError('Current live receiver source lease changed')
            self.last_observation = dict(result, pid=self.pid, process_create_time=self.created_at,
                process_identity_verified=True, image_hash_verified_by_observer=True,
                future_process_authorized=False, native_gameplay_qualified=False)
            return result['native_receiver_route_qualified'] is True
        except Exception as error:
            self.last_observation = dict(status='live_receiver_check_failed',
                reason=str(error)[:512], pid=self.pid, process_create_time=self.created_at,
                future_process_authorized=False, native_gameplay_qualified=False)
            return False
        finally:
            if reader is not None:
                reader.close()

    def close(self):
        self.closed = True
        self._sources.close()
