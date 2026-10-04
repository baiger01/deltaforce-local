"""Disk evidence and synthetic reader tests. No real Windows API or game runs."""
import argparse
import ast
import contextlib
import copy
import hashlib
import io
import json
import mmap
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import read_native_control_code as reader
from test_native_control_candidate_interval import GAME_ROOT, EXECUTABLE, FakeKernel


class FieldHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = EXECUTABLE.open('rb')
        cls.raw = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_READ)
        cls.image = reader.Image(cls.raw)
        cls.evidence = reader.sealed_field_plan()
        cls.sample = reader.FIELD_SOURCE_SAMPLE.read_bytes()
        cls.plan = reader.validate_field_helpers(cls.image)

    @classmethod
    def tearDownClass(cls):
        cls.raw.close()
        cls.stream.close()

    def test_real_profile_is_three_exact_reads_and_twenty_source_e8_calls(self):
        with mock.patch.object(reader, 'kernel', side_effect=AssertionError('Windows API forbidden')):
            plan = reader.build_plan(GAME_ROOT, field_helpers=True)
        self.assertEqual((plan['fixed_read_count'], plan['maximum_reads'], plan['maximum_code_bytes']), (3, 3, 2487))
        self.assertEqual([x['code_bytes'] for x in plan['field_helper_roots']], [1679, 474, 334])
        self.assertEqual(plan['source_direct_call_proof']['call_count'], 20)
        self.assertEqual(plan['source_direct_call_proof']['verified_source_code_ranges'], [['0x128668d0', '0x12867722']])
        self.assertNotIn('named_prefixes', plan)
        self.assertNotIn('candidate_roots', plan)
        self.assertFalse(plan['helper_wire_types_verified'])

    def test_profile_flags_are_explicit_bools_and_mutually_exclusive_before_disk_or_process(self):
        for kwargs in ({'field_helpers': 1}, {'field_helpers': None}, {'field_helpers': 'yes'},
                       {'candidate_interval': 1}, {'candidate_interval': True, 'field_helpers': True}):
            with self.subTest(kwargs=kwargs), mock.patch.object(reader, 'digest') as disk, \
                    mock.patch.object(reader, 'verified_pids') as pids, self.assertRaises(ValueError):
                reader.collect(GAME_ROOT, Path('unused-offline-output'), **kwargs)
            disk.assert_not_called()
            pids.assert_not_called()

    def test_cli_flag_defaults_off_and_rejects_two_profiles(self):
        tree = ast.parse(Path(reader.__file__).read_text(encoding='utf-8'))
        main = next(x for x in tree.body if isinstance(x, ast.If) and ast.unparse(x.test) == "__name__ == '__main__'")
        nodes = []
        for node in main.body:
            if isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) and x.id == 'args' for x in node.targets):
                break
            nodes.append(node)
        scope = {'argparse': argparse, 'Path': Path, '__doc__': 'Offline CLI parser'}
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), '<offline-parser>', 'exec'), scope)
        base = ['--game-root', 'offline', '--validate-plan']
        self.assertFalse(scope['parser'].parse_args(base).field_helpers)
        self.assertTrue(scope['parser'].parse_args(base+['--field-helpers']).field_helpers)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            scope['parser'].parse_args(base+['--field-helpers', '--candidate-interval'])
        self.assertEqual(caught.exception.code, 2)

    def test_bad_plan_hash_and_wrong_shipping_reject_before_process_access(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'altered.json'
            path.write_bytes(b'{}')
            with mock.patch.object(reader, 'FIELD_PLAN', path), mock.patch.object(reader, 'verified_pids') as pids, \
                    self.assertRaisesRegex(ValueError, 'plan file identity'):
                reader.collect(GAME_ROOT, Path('unused-offline-output'), field_helpers=True)
            pids.assert_not_called()
        with mock.patch.object(reader, 'digest', return_value='wrong-sha'), mock.patch.object(reader, 'verified_pids') as pids, \
                self.assertRaisesRegex(ValueError, 'Client version hash'):
            reader.collect(GAME_ROOT, Path('unused-offline-output'), field_helpers=True)
        pids.assert_not_called()

    def test_source_file_payload_and_header_identity_are_separate_guards(self):
        for sample in (self.sample[:-1], self.sample[:-1]+bytes([self.sample[-1]^1])):
            with self.subTest(length=len(sample)), self.assertRaisesRegex(ValueError, 'sample file identity'):
                reader.validate_field_source_sample(sample, self.evidence)
        changed = struct.pack('<Q', 0)+self.sample[8:]
        with mock.patch.object(reader, 'FIELD_SOURCE_FILE_SHA', hashlib.sha256(changed).hexdigest()), \
                self.assertRaisesRegex(ValueError, 'header/code identity'):
            reader.validate_field_source_sample(changed, self.evidence)

    def test_twenty_call_sites_cannot_be_redirected_omitted_or_moved_into_table(self):
        altered = []
        value = copy.deepcopy(self.evidence)
        value['fixed_direct_targets'][0]['source_direct_calls'].pop()
        altered.append(value)
        value = copy.deepcopy(self.evidence)
        value['fixed_direct_targets'][0]['source_direct_calls'][0]['instruction_rva'] = '0x12867724'
        altered.append(value)
        value = copy.deepcopy(self.evidence)
        value['fixed_direct_targets'][0]['source_direct_calls'][0]['direct_target_rva'] = '0x12bab170'
        altered.append(value)
        value = copy.deepcopy(self.evidence)
        value['fixed_direct_targets'][0]['source_direct_calls'][0]['instruction_bytes_hex'] = 'e800000000'
        altered.append(value)
        value = copy.deepcopy(self.evidence)
        value['source_code_ranges'][0][1] = '0x12867798'
        altered.append(value)
        for index, evidence in enumerate(altered):
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, 'Field-helper'):
                reader.validate_field_source_sample(self.sample, evidence)

    def test_changed_source_e8_is_rejected_even_after_separate_sha_checks_are_rebound(self):
        offset = 32+0x12866fdf-reader.FIELD_SOURCE_RVA
        changed = bytearray(self.sample)
        changed[offset+1] ^= 1
        changed = bytes(changed)
        evidence = copy.deepcopy(self.evidence)
        evidence['source_file_sha256'] = hashlib.sha256(changed).hexdigest()
        evidence['source_code_sha256'] = hashlib.sha256(changed[32:]).hexdigest()
        with mock.patch.object(reader, 'FIELD_SOURCE_FILE_SHA', evidence['source_file_sha256']), \
                mock.patch.object(reader, 'FIELD_SOURCE_CODE_SHA', evidence['source_code_sha256']), \
                self.assertRaisesRegex(ValueError, 'fixed source call count'):
            reader.validate_field_source_sample(changed, evidence)

    def test_pdata_and_each_root_unwind_metadata_must_match(self):
        original = self.image.data
        for target in (reader.FIELD_PDATA_RVA, 0x1bdd77ec, 0x1bf5bcf0, 0x1bdcb484):
            def changed(rva, length):
                data = original(rva, length)
                if rva != target:
                    return data
                index = 3 if len(data) > 3 else 0
                return data[:index]+bytes([data[index]^1])+data[index+1:]
            with self.subTest(target=hex(target)), mock.patch.object(self.image, 'data', side_effect=changed), \
                    self.assertRaisesRegex(ValueError, 'pdata|unwind'):
                reader.validate_field_helpers(self.image)

    def test_independent_span_and_executable_guard_fail_closed(self):
        original_span = self.image.function_span
        def changed(target):
            root, length, fragments = original_span(target)
            return (root, length+1, fragments) if target == 0x109ea340 else (root, length, fragments)
        with mock.patch.object(self.image, 'function_span', side_effect=changed), \
                self.assertRaisesRegex(ValueError, 'same-root function boundary'):
            reader.validate_field_helpers(self.image)
        original_exec = self.image.executable
        with mock.patch.object(self.image, 'executable', side_effect=lambda r, n=1: False if r == 0x12bab170 else original_exec(r, n)), \
                self.assertRaisesRegex(ValueError, 'executable scope'):
            reader.validate_field_helpers(self.image)

    def collect_fake(self, api, field_validator=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name)
        process = lambda pid: SimpleNamespace(create_time=lambda: 123.0, exe=lambda: str(EXECUTABLE.resolve()))
        with mock.patch.object(reader, 'verified_pids', return_value=[77]), \
                mock.patch.object(reader, 'kernel', return_value=api), \
                mock.patch.object(reader.psutil, 'Process', side_effect=process), \
                mock.patch.object(reader, 'direct_e9_span', side_effect=AssertionError('Follow forbidden')), \
                mock.patch.object(reader, 'validate_field_helpers', side_effect=field_validator or reader.validate_field_helpers):
            report = reader.collect(GAME_ROOT, folder, field_helpers=True)
        return folder, report

    def test_mocked_collection_reads_exact_three_spans_no_follow_and_pins_saved_files(self):
        api = FakeKernel()
        folder, report = self.collect_fake(api)
        self.assertEqual(report['status'], 'bounded_read_attempt_complete')
        self.assertEqual(api.read_lengths, [1679, 474, 334])
        self.assertEqual((report['actual_code_bytes'], report['maximum_reads']), (2487, 3))
        self.assertEqual([x['name'] for x in report['functions']], [x['label'] for x in self.plan['field_helper_roots']])
        for item in report['functions']:
            saved = (folder/(item['name']+'.dfcode')).read_bytes()
            self.assertEqual(hashlib.sha256(saved).hexdigest(), item['file_sha256'])
            self.assertEqual(hashlib.sha256(saved[32:]).hexdigest(), item['code_sha256'])
            self.assertIn('field_helper_source_evidence', item)
            self.assertNotIn('direct_e9_follow', item)
        self.assertEqual(api.closed, [2, 1])
        self.assertFalse(report['native_control_logic_verified'])

    def test_memory_guard_and_opened_pid_mismatch_never_read(self):
        for api in (FakeKernel(protection=0x120), FakeKernel(opened_pid=78)):
            with self.subTest(protection=api.protection, opened_pid=api.opened_pid):
                _, report = self.collect_fake(api)
                self.assertEqual(api.read_lengths, [])
                self.assertEqual(report['actual_code_bytes'], 0)

    def test_changed_field_evidence_after_mock_open_stops_before_code_reads(self):
        altered = copy.deepcopy(self.plan)
        altered['field_helper_roots'][0]['code_bytes'] += 1
        api = FakeKernel()
        _, report = self.collect_fake(api, field_validator=mock.Mock(side_effect=[self.plan, altered]))
        self.assertEqual(report['status'], 'bounded_read_failed')
        self.assertIn('evidence changed', report['error_reason'])
        self.assertEqual(api.read_lengths, [])
        self.assertEqual(api.query_count, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
