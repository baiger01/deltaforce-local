"""Disk and mocked sender-body scope tests; no live process or Windows API."""
import copy
import ctypes as C
import json
import mmap
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import read_native_sender_body as reader
from test_native_control_continuations import FakeKernel as CommonFake

GAME_ROOT = Path(os.environ.get('DF_OFFLINE_TEST_GAME_ROOT', 'D:/个人工作区/DeltaForce-local-client'))
EXECUTABLE = GAME_ROOT/reader.EXECUTABLE_RELATIVE


def control_fixture(calls=(8,), target=reader.BASE_RVA):
    code = bytearray(b'\x90'*reader.CONTROL_BYTES)
    for offset in calls:
        code[offset:offset+5] = b'\xe8'+struct.pack('<i', target-(reader.CONTROL_RVA+offset+5))
    return bytes(code)


class FakeKernel(CommonFake):
    def __init__(self, wrapper, control=None, **values):
        super().__init__(**values)
        self.wrapper = wrapper
        self.control = control if control is not None else control_fixture()

    def ReadProcessMemory(self, handle, address, buffer, length, copied):
        rva = address-self.base
        self.reads.append((rva, length))
        code = (self.wrapper if rva == reader.PREFIX_RVA else self.control if rva == reader.CONTROL_RVA
                else b'\x90'*reader.BASE_BYTES)
        assert len(code) == length
        C.memmove(buffer, code, length)
        copied._obj.value = length+self.values['copy_delta']
        return self.values['copy_ok']


class SenderBodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = EXECUTABLE.open('rb')
        cls.raw = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_READ)
        cls.image = reader.Image(cls.raw)
        cls.sealed = reader.sealed_json(reader.FIXED_PLAN, reader.FIXED_PLAN_SHA)
        cls.prefix = reader.source_prefix(cls.sealed)
        # Synthetic complete normal epilogue fixture, not a newly collected native sample.
        cls.wrapper = cls.prefix+b'\xc4\x20\x5b\xc3'
        cls.plan = reader.validate_image(cls.image)

    @classmethod
    def tearDownClass(cls):
        cls.raw.close()
        cls.stream.close()

    def changed_plan(self, mutate):
        changed = copy.deepcopy(self.sealed)
        mutate(changed)
        original = reader.sealed_json
        return mock.patch.object(reader, 'sealed_json', side_effect=lambda path, pin:
            changed if path == reader.FIXED_PLAN else original(path, pin))

    def collect_mock(self, api, process=None, revalidated=None):
        process = process or SimpleNamespace(exe=lambda: str(EXECUTABLE.resolve()), create_time=lambda: 123.0)
        with tempfile.TemporaryDirectory(prefix='df-sender-body-offline-') as folder, \
                mock.patch.object(reader, 'build_plan', return_value=copy.deepcopy(self.plan)), \
                mock.patch.object(reader, 'validate_image', return_value=revalidated or copy.deepcopy(self.plan)), \
                mock.patch.object(reader, 'verified_pids', return_value=[77]), \
                mock.patch.object(reader, 'kernel', return_value=api), \
                mock.patch.object(reader.psutil, 'Process', side_effect=process if isinstance(process, list) else lambda _: process):
            result = reader.collect(GAME_ROOT, folder)
            files = sorted(p.name for p in Path(folder).glob('*.dfcode'))
        return result, files

    def test_real_disk_plan_three_functions_five_metadata_fragments_no_process_lookup(self):
        with mock.patch.object(reader, 'verified_pids', side_effect=AssertionError('no process lookup')), \
                mock.patch.object(reader, 'kernel', side_effect=AssertionError('no Windows API')):
            plan = reader.build_plan(GAME_ROOT)
        self.assertEqual((plan['initial_code_bytes'], plan['maximum_code_bytes'], plan['maximum_reads']), (499, 3737, 3))
        roots = plan['initial_reads']+[plan['conditional_single_e8_read']]
        self.assertEqual([v['code_bytes'] for v in roots], [36, 463, 3238])
        self.assertEqual(sum(len(v['unwind_metadata']) for v in roots), 5)
        self.assertFalse(plan['actual_instance_table_ownership_verified'])

    def test_cli_requires_explicit_collect(self):
        p = reader.argument_parser()
        self.assertFalse(p.parse_args(['--game-root', 'fixture']).collect)
        self.assertTrue(p.parse_args(['--game-root', 'fixture', '--collect']).collect)
        with self.assertRaises(SystemExit), mock.patch('sys.stderr'):
            p.parse_args(['--game-root', 'fixture', '--validate-plan', '--collect'])

    def test_sealed_plan_tamper_precedes_all_process_access(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'plan.json'; path.write_bytes(b'{}')
            with mock.patch.object(reader, 'FIXED_PLAN', path), mock.patch.object(reader, 'verified_pids') as pids:
                with self.assertRaisesRegex(ValueError, 'sealed JSON identity'):
                    reader.collect(GAME_ROOT, Path(folder)/'output')
            pids.assert_not_called()

    def test_saved_prefix_scope_and_known_incomplete_tail_are_verified(self):
        evidence = copy.deepcopy(self.sealed)
        evidence['source_measured_slot'] = '0x2c0'
        with self.assertRaisesRegex(ValueError, 'saved prefix scope'):
            reader.source_prefix(evidence)
        evidence = copy.deepcopy(self.sealed); evidence['source_prefix_decoded_bytes'] = 32
        with self.assertRaisesRegex(ValueError, 'wrapper prefix instruction'):
            reader.source_prefix(evidence)
        self.assertEqual(len(self.prefix), 32)
        self.assertEqual(self.prefix[-2:], b'\x48\x83')

    def test_wrapper_verifies_complete_permutation_return_and_epilogue(self):
        result = reader.validate_wrapper(self.wrapper, self.prefix)
        self.assertTrue(result['normal_epilogue_and_return_verified'])
        self.assertEqual((result['instruction_count'], result['measured_virtual_slot']), (12, '0x2b8'))
        for wrong in (self.wrapper[:-1], self.wrapper[:-1]+b'\x90', self.wrapper[:-2]+b'\x5f\xc3'):
            with self.subTest(wrong=wrong[-4:].hex()), self.assertRaises(ValueError):
                reader.validate_wrapper(wrong, self.prefix)

    def test_wrapper_must_match_all_saved_first32_bytes(self):
        wrong = bytearray(self.wrapper); wrong[8] ^= 1
        with self.assertRaisesRegex(ValueError, 'saved first32'):
            reader.validate_wrapper(wrong, self.prefix)

    def test_conditional_direct_E8_is_exact_and_same_source(self):
        code = control_fixture((91,))
        proof = reader.conditional_e8(code)
        self.assertEqual(proof['call_rva'], hex(reader.CONTROL_RVA+91))
        self.assertEqual(proof['source_code_sha256'], reader.sha(code))
        self.assertEqual(proof['target_rva'], hex(reader.BASE_RVA))
        self.assertFalse(proof['recursive_follow'])

    def test_missing_ambiguous_wrong_target_and_incomplete_source_reject_base(self):
        for code in (control_fixture(()), control_fixture((8, 80)), control_fixture((8,), reader.BASE_RVA+1),
                     b'\x90'*462+b'\x0f'):
            with self.subTest(code_hash=reader.sha(code)), self.assertRaises(ValueError):
                reader.conditional_e8(code)

    def test_E8_bytes_inside_an_immediate_are_not_an_instruction(self):
        pretend_rva = reader.CONTROL_RVA+2
        immediate = b'\xe8'+struct.pack('<i', reader.BASE_RVA-(pretend_rva+5))+b'\0\0\0'
        code = b'\x48\xb8'+immediate+b'\x90'*(reader.CONTROL_BYTES-10)
        with self.assertRaisesRegex(ValueError, 'absent or ambiguous'):
            reader.conditional_e8(code)

    def test_static_regions_and_typed_complete_records_are_required(self):
        for mutate in (
            lambda p: p['static_regions'][0].__setitem__('sha256', '0'*64),
            lambda p: p['typed_bindings'][0]['six_qwords'].__setitem__(2, '0x140000000'),
            lambda p: p['typed_bindings'][1]['arguments'][0].__setitem__('label', 'Other *'),
        ):
            with self.changed_plan(mutate), self.assertRaises(ValueError):
                reader.validate_image(self.image)

    def test_pdata_unwind_chain_and_bounds_are_required(self):
        for mutate in (
            lambda p: p['pdata'].__setitem__('sha256', '0'*64),
            lambda p: p['initial_reads'][1]['unwind_metadata'][1].__setitem__('chain_parent', None),
            lambda p: p['conditional_single_e8_read'].__setitem__('code_bytes', 3239),
            lambda p: p.__setitem__('maximum_attempted_reads', 4),
        ):
            with self.changed_plan(mutate), self.assertRaises(ValueError):
                reader.validate_image(self.image)

    def test_changed_shared_guard_dependency_rejects(self):
        with mock.patch.object(reader, 'digest', return_value='0'*64), self.assertRaisesRegex(ValueError, 'guard dependency'):
            reader.validate_image(self.image)

    def test_success_is_three_exact_RPMs_even_with_five_unwind_fragments(self):
        api = FakeKernel(self.wrapper)
        report, files = self.collect_mock(api)
        self.assertEqual(report['status'], 'bounded_read_attempt_complete')
        self.assertEqual(api.reads, [(reader.PREFIX_RVA, 36), (reader.CONTROL_RVA, 463), (reader.BASE_RVA, 3238)])
        self.assertEqual((report['actual_read_count'], report['actual_code_bytes'], report['attempted_code_bytes']), (3, 3737, 3737))
        self.assertEqual((report['attempted_read_count'], report['rpm_requested_bytes']), (3, 3737))
        self.assertEqual(len(files), 3)
        proof = report['functions'][1]['conditional_direct_e8_proof']
        self.assertEqual(proof['source_file_sha256'], report['functions'][1]['file_sha256'])
        self.assertEqual(proof['source_code_sha256'], report['functions'][1]['code_sha256'])
        self.assertEqual(api.closed, [2, 1])
        self.assertNotIn('module_base', json.dumps(report))
        self.assertNotIn(str(api.base), json.dumps(report))

    def test_bad_wrapper_stops_before_Control_candidate(self):
        api = FakeKernel(self.wrapper[:-1]+b'\x90')
        report, files = self.collect_mock(api)
        self.assertEqual(report['status'], 'bounded_read_failed')
        self.assertEqual(api.reads, [(reader.PREFIX_RVA, 36)])
        self.assertEqual(len(files), 1)
        self.assertEqual(api.closed, [2, 1])

    def test_condition_refusal_stops_after_two_reads_and_preserves_Control_sample(self):
        for control in (control_fixture(()), control_fixture((8, 80)), b'\x90'*462+b'\x0f'):
            api = FakeKernel(self.wrapper, control=control)
            report, files = self.collect_mock(api)
            self.assertEqual(report['status'], 'bounded_read_conditional_refused')
            self.assertEqual(api.reads, [(reader.PREFIX_RVA, 36), (reader.CONTROL_RVA, 463)])
            self.assertEqual(report['actual_code_bytes'], 499)
            self.assertEqual((report['actual_read_count'], report['attempted_read_count']), (2, 2))
            self.assertEqual(len(files), 2)
            self.assertEqual(api.closed, [2, 1])

    def test_identity_module_path_size_and_PID_guards_stop_before_RPM(self):
        for values in ({'pid': 78}, {'path': str(EXECUTABLE.parent/'other.exe')}, {'size': reader.IMAGE_SIZE-1}):
            api = FakeKernel(self.wrapper, **values)
            report, files = self.collect_mock(api)
            self.assertEqual(report['status'], 'bounded_read_failed')
            self.assertEqual(api.reads, [])
            self.assertEqual(files, [])
            self.assertIn(1, api.closed)

    def test_process_creation_time_change_prevents_code_read(self):
        first = SimpleNamespace(create_time=lambda: 123.0, exe=lambda: str(EXECUTABLE.resolve()))
        second = SimpleNamespace(create_time=lambda: 124.0, exe=lambda: str(EXECUTABLE.resolve()))
        api = FakeKernel(self.wrapper)
        report, _ = self.collect_mock(api, process=[first, second])
        self.assertEqual(report['status'], 'bounded_read_failed')
        self.assertEqual(api.reads, [])
        self.assertEqual(api.closed, [2, 1])

    def test_read_identity_is_rechecked_before_sample_is_saved(self):
        first = SimpleNamespace(create_time=lambda: 123.0, exe=lambda: str(EXECUTABLE.resolve()))
        changed = SimpleNamespace(create_time=lambda: 124.0, exe=lambda: str(EXECUTABLE.resolve()))
        api = FakeKernel(self.wrapper)
        report, files = self.collect_mock(api, process=[first, first, changed])
        self.assertEqual(report['status'], 'bounded_read_failed')
        self.assertEqual(len(api.reads), 1)
        self.assertEqual(files, [])

    def test_evidence_revalidated_after_module_snapshot(self):
        changed = copy.deepcopy(self.plan); changed['maximum_code_bytes'] += 1
        api = FakeKernel(self.wrapper)
        report, _ = self.collect_mock(api, revalidated=changed)
        self.assertEqual(report['status'], 'bounded_read_failed')
        self.assertEqual(api.reads, [])

    def test_memory_page_region_protection_and_exact_copy_guards(self):
        for values in ({'state': 0x2000}, {'kind': 0x20000}, {'protection': 0x04}, {'protection': 0x120},
                       {'allocation': FakeKernel.base+1}, {'region_size': 1}, {'query_ok': False},
                       {'copy_ok': False}, {'copy_delta': -1}):
            api = FakeKernel(self.wrapper, **values)
            report, files = self.collect_mock(api)
            self.assertEqual(report['status'], 'bounded_read_failed')
            self.assertEqual(report['actual_code_bytes'], 0)
            self.assertEqual(files, [])
            self.assertLessEqual(len(api.reads), 1)
            self.assertEqual(report['actual_read_count'], len(api.reads))
            self.assertEqual(report['attempted_read_count'], 1)
            self.assertEqual(api.closed, [2, 1])

    def test_no_region_split_fallback_creates_additional_RPMs(self):
        api = FakeKernel(self.wrapper)
        original_query = api.VirtualQueryEx
        def query(handle, address, pointer, length):
            result = original_query(handle, address, pointer, length)
            if address-api.base == reader.CONTROL_RVA:
                pointer._obj.RegionSize = reader.CONTROL_RVA+245
            return result
        api.VirtualQueryEx = query
        report, files = self.collect_mock(api)
        self.assertEqual(report['status'], 'bounded_read_failed')
        self.assertEqual(api.reads, [(reader.PREFIX_RVA, 36)])
        self.assertEqual((report['actual_read_count'], report['attempted_read_count']), (1, 2))
        self.assertEqual(len(files), 1)

    def test_duplicate_module_matches_are_refused(self):
        api = FakeKernel(self.wrapper)
        calls = [True, False]
        api.Module32NextW = lambda snapshot, pointer: calls.pop(0)
        report, files = self.collect_mock(api)
        self.assertEqual(report['status'], 'bounded_read_failed')
        self.assertEqual(api.reads, [])
        self.assertEqual(files, [])

    def test_nonunique_processes_never_open_API(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(reader, 'build_plan', return_value=self.plan), \
                mock.patch.object(reader, 'verified_pids', return_value=[77, 78]), \
                mock.patch.object(reader, 'kernel', side_effect=AssertionError('no Windows API')):
            report = reader.collect(GAME_ROOT, folder)
        self.assertEqual(report['status'], 'original_process_not_unique')


if __name__ == '__main__':
    unittest.main()
