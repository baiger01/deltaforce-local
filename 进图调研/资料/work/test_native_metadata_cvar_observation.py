"""Fixed scalar observation regression tests; no process/Windows API is used."""
from contextlib import ExitStack
from pathlib import Path
import struct
import unittest
from unittest.mock import Mock, patch

import export_native_replication_metadata as export
from native_replication_metadata_core import MetadataSession


class FixedCvarObservationTests(unittest.TestCase):
    base = 0x140000000
    rva = 0x1cba32f0  # Literal source fixture, not a copied production constant.
    source_sha = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'

    def observe(self, backend, *, source_sha=None, base=None):
        session = MetadataSession(backend)
        result = export.observe_dynamic_address_switch_cvar(session,
            self.base if base is None else base,
            source_sha256=self.source_sha if source_sha is None else source_sha)
        return result, session

    def test_literal_int32_zero_two_exact_reads_no_pointer_chase(self):
        backend = Mock(return_value=b'\x00\x00\x00\x00')
        result, session = self.observe(backend)
        self.assertEqual(result, {'rva': '0x1cba32f0', 'value': 0,
                                  'status': 'observed_stable_int32'})
        self.assertEqual(backend.call_args_list,
            [((self.base+self.rva, 4),), ((self.base+self.rva, 4),)])
        self.assertEqual((session.calls, session.bytes_read), (2, 8))

    def test_nonzero_and_signed_values_remain_scalars(self):
        for literal, expected in ((b'\x01\x00\x00\x00', 1),
                                  (b'\xff\xff\xff\xff', -1),
                                  (b'\x78\x56\x34\x12', 0x12345678)):
            with self.subTest(value=expected):
                backend = Mock(return_value=literal)
                result, session = self.observe(backend)
                self.assertEqual(result['value'], expected)
                self.assertEqual((session.calls, session.bytes_read), (2, 8))
                self.assertEqual({args.args for args in backend.call_args_list},
                                 {(self.base+self.rva, 4)})

    def test_changed_or_partial_read_never_reports_a_value(self):
        for values in ((b'\x01\x00\x00\x00', b'\x00\x00\x00\x00'),
                       (b'\x00\x00\x00',)):
            with self.subTest(values=values):
                result, session = self.observe(Mock(side_effect=values))
                self.assertEqual(result, {'rva': '0x1cba32f0', 'value': None,
                                          'status': 'read_refused'})
                self.assertIn(session.calls, (1, 2))

    def test_version_mismatch_and_invalid_module_base_do_not_read(self):
        backend = Mock(side_effect=AssertionError('An unqualified read occurred'))
        result, session = self.observe(backend, source_sha='0'*64)
        self.assertEqual(result['status'], 'unqualified_source')
        self.assertEqual((session.calls, session.bytes_read), (0, 0))
        result, session = self.observe(backend, base=0)
        self.assertEqual(result['status'], 'read_refused')
        self.assertEqual((session.calls, session.bytes_read), (0, 0))
        backend.assert_not_called()

    def test_backend_deadline_or_access_failure_diagnostic_only(self):
        for error, status in ((ValueError('Metadata collection time budget exhausted'), 'read_refused'),
                              (OSError('Read-only memory access failed'), 'read_failed')):
            with self.subTest(status=status):
                result, session = self.observe(Mock(side_effect=error))
                self.assertEqual(result['status'], status)
                self.assertIsNone(result['value'])
                self.assertEqual((session.calls, session.bytes_read), (1, 4))

    def collect(self, backend, metadata_export):
        reader = Mock(module_base=self.base)
        reader.deadline = 1000000
        reader.read_exact = backend
        reader.find_module.return_value = self.base
        with ExitStack() as stack:
            stack.enter_context(patch.object(export, 'validate_source', return_value=(Path('mock-client.exe'), export.SHIPPING_IMAGE_SIZE)))
            ctor = stack.enter_context(patch.object(export, 'Win32MetadataReader', return_value=reader))
            operation = stack.enter_context(patch.object(export, 'export_metadata', side_effect=metadata_export))
            saved = stack.enter_context(patch.object(export, 'save'))
            report = export.collect(Path('mock-game'), Path('mock-output'), pid=123, created_at=456.0)
        ctor.assert_called_once_with(Path('mock-client.exe'), export.SHIPPING_IMAGE_SIZE, 123, 456.0)
        reader.close.assert_called_once()
        saved.assert_called_once_with(Path('mock-output'), report)
        return report, reader, operation

    def test_optional_read_failure_does_not_refuse_metadata_export(self):
        def metadata(session, base, **kwargs):
            self.assertEqual((session.calls, session.bytes_read), (1, 4))
            return {'roots': {}, 'class_cache_exports': 0, 'replication_layout_exports': 0}
        report, reader, operation = self.collect(Mock(side_effect=OSError('no access')), metadata)
        self.assertEqual(report['status'], 'metadata_export_complete')
        self.assertEqual(report['dynamic_address_switch_cvar_observation'],
            {'rva': '0x1cba32f0', 'value': None, 'status': 'read_failed'})
        operation.assert_called_once()
        reader.verify_identity.assert_called_once()

    def test_early_observation_survives_later_metadata_timeout(self):
        def metadata(session, base, **kwargs):
            self.assertEqual((session.calls, session.bytes_read), (2, 8))
            self.assertTrue(callable(kwargs['remaining_time']))
            raise ValueError('Metadata collection time budget exhausted')
        report, _, operation = self.collect(Mock(return_value=b'\x00\x00\x00\x00'), metadata)
        self.assertEqual(report['status'], 'metadata_export_refused')
        self.assertEqual(report['dynamic_address_switch_cvar_observation'],
            {'rva': '0x1cba32f0', 'value': 0, 'status': 'observed_stable_int32'})
        self.assertFalse(report['runtime_class_cache_recovered'])
        operation.assert_called_once()

    def test_source_preflight_failure_never_opens_a_reader(self):
        with patch.object(export, 'validate_source', side_effect=ValueError('source mismatch')), \
                patch.object(export, 'Win32MetadataReader') as constructor, \
                patch.object(export, 'save'):
            report = export.collect(Path('mock-game'), Path('mock-output'), pid=123, created_at=456.0)
        constructor.assert_not_called()
        self.assertEqual(report['dynamic_address_switch_cvar_observation'],
            {'rva': '0x1cba32f0', 'value': None, 'status': 'not_attempted'})
        self.assertEqual(report['status'], 'metadata_export_refused')


if __name__ == '__main__':
    unittest.main()
