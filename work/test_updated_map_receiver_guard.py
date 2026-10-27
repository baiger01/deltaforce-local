import importlib
import importlib.util
import os
import unittest
from unittest.mock import patch

from test_updated_enabled_header_context import Fixture


class Reader:
    instances = []
    fixture = None
    fail_identity = False

    def __init__(self, executable, image_size, pid, created_at, *, maximum_seconds):
        from export_native_replication_metadata import collection_duration
        collection_duration(maximum_seconds)
        self.request = (pid, created_at)
        self.module_base = self.fixture.base
        self.closed = False
        self.instances.append(self)

    def read_exact(self, address, size):
        return self.fixture.read(address, size)

    def verify_identity(self):
        if self.fail_identity:
            raise ValueError('Reused process identity')

    def close(self):
        self.closed = True


class UpdatedLiveReceiverTests(unittest.TestCase):
    def guard(self):
        spec = importlib.util.find_spec('updated_map_receiver_guard')
        self.assertIsNotNone(spec, 'New Actor activation needs a live process-bound check')
        module = importlib.import_module(spec.name)
        return module.LiveReceiverGuard('F:/deltaforce-local-shadow-build-79fb7b10',
            123, 456.0, reader_factory=Reader)

    def setUp(self):
        configured_shadow = patch.dict(os.environ,
            DF_LOCAL_SHADOW_GAME='F:/deltaforce-local-shadow-build-79fb7b10')
        configured_shadow.start()
        self.addCleanup(configured_shadow.stop)
        Reader.instances = []
        Reader.fixture = Fixture()
        Reader.fail_identity = False

    def test_live_context_is_rechecked_and_handles_are_closed(self):
        guard = self.guard()
        try:
            self.assertTrue(guard())
            self.assertTrue(Reader.instances[-1].closed)
            self.assertEqual(Reader.instances[-1].request, (123, 456.0))
            Reader.fixture.hook(Reader.fixture.cells[0]['rva'], 1)
            self.assertFalse(guard())
            self.assertTrue(Reader.instances[-1].closed)
        finally:
            guard.close()

    def test_identity_reuse_and_closed_guard_refuse_activation(self):
        guard = self.guard()
        try:
            Reader.fail_identity = True
            self.assertFalse(guard())
            self.assertTrue(Reader.instances[-1].closed)
        finally:
            guard.close()
        self.assertFalse(guard())


if __name__ == '__main__':
    unittest.main()
