"""Immutable-disk and synthetic API tests; never opens a Windows process."""
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

import read_native_control_continuations as reader

GAME_ROOT = Path(os.environ.get('DF_OFFLINE_TEST_GAME_ROOT', 'D:/个人工作区/DeltaForce-local-client'))
EXECUTABLE = GAME_ROOT/reader.EXECUTABLE_RELATIVE


class FakeKernel:
    base = 0x140000000

    def __init__(self, **changes):
        self.values = dict(open=True, pid=77, path=str(EXECUTABLE.resolve()), size=reader.IMAGE_SIZE,
            state=0x1000, kind=0x1000000, protection=0x20, allocation=self.base,
            region_start=self.base, region_size=reader.IMAGE_SIZE, query_ok=True, copy_ok=True,
            copy_delta=0, leading_e9=False)
        self.values.update(changes)
        self.reads, self.queries, self.closed = [], [], []

    def OpenProcess(self, access, inherit, pid):
        assert (access, inherit, pid) == (0x1010, False, 77)
        return 1 if self.values['open'] else 0

    def GetProcessId(self, handle):
        return self.values['pid']

    def CreateToolhelp32Snapshot(self, flags, pid):
        assert (flags, pid) == (0x18, 77)
        return 2

    def Module32FirstW(self, snapshot, pointer):
        item = pointer._obj
        item.szExePath = self.values['path']
        item.modBaseAddr, item.modBaseSize = self.base, self.values['size']
        return True

    def Module32NextW(self, snapshot, pointer):
        return False

    def VirtualQueryEx(self, handle, address, pointer, length):
        self.queries.append(address-self.base)
        item = pointer._obj
        item.BaseAddress, item.RegionSize = self.values['region_start'], self.values['region_size']
        item.AllocationBase = self.values['allocation']
        item.State, item.Type, item.Protect = self.values['state'], self.values['kind'], self.values['protection']
        return C.sizeof(reader.Memory) if self.values['query_ok'] else 0

    def ReadProcessMemory(self, handle, address, buffer, length, copied):
        self.reads.append((address-self.base, length))
        C.memset(buffer, 0x90, length)
        if self.values['leading_e9']:
            C.memmove(buffer, b'\xe9\x00\x00\x00\x00', 5)
        copied._obj.value = length+self.values['copy_delta']
        return self.values['copy_ok']

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return True


class ContinuationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = EXECUTABLE.open('rb')
        cls.raw = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_READ)
        cls.image = reader.Image(cls.raw)
        cls.sealed = reader.sealed_json(reader.FIXED_PLAN, reader.FIXED_PLAN_SHA)
        cls.plan = reader.validate_image(cls.image)
        cls.sample = (reader.ROOT/cls.sealed['sources'][0]['path']).read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.raw.close()
        cls.stream.close()

    def changed_plan(self, mutation):
        changed = copy.deepcopy(self.sealed)
        mutation(changed)
        original = reader.sealed_json
        def load(path, expected):
            return changed if path == reader.FIXED_PLAN else original(path, expected)
        return mock.patch.object(reader, 'sealed_json', side_effect=load)

    def sample_with_new_hashes(self, changed):
        declared = copy.deepcopy(self.sealed['sources'][0])
        spec = list(reader.SOURCE_SPECS[0])
        spec[3], spec[4] = reader.sha(changed), reader.sha(changed[32:])
        declared['file_sha256'], declared['code_sha256'] = spec[3:5]
        return declared, tuple(spec)

    def collect_mock(self, api, process=None, revalidated=None):
        process = process or SimpleNamespace(create_time=lambda: 123.0, exe=lambda: str(EXECUTABLE.resolve()))
        with tempfile.TemporaryDirectory(prefix='df-continuation-offline-') as folder, \
                mock.patch.object(reader, 'build_plan', return_value=copy.deepcopy(self.plan)), \
                mock.patch.object(reader, 'validate_image', return_value=revalidated or copy.deepcopy(self.plan)), \
                mock.patch.object(reader, 'verified_pids', return_value=[77]), \
                mock.patch.object(reader, 'kernel', return_value=api), \
                mock.patch.object(reader.psutil, 'Process', side_effect=process if isinstance(process, list) else lambda _: process):
            report = reader.collect(GAME_ROOT, folder)
            files = sorted(p.name for p in Path(folder).glob('*.dfcode'))
        return report, files

    def test_real_offline_plan_has_exact_four_roots_and_no_process_api(self):
        with mock.patch.object(reader, 'kernel', side_effect=AssertionError('no Windows API')), \
                mock.patch.object(reader, 'verified_pids', side_effect=AssertionError('no process lookup')):
            plan = reader.build_plan(GAME_ROOT)
        self.assertEqual((plan['maximum_reads'], plan['maximum_code_bytes']), (4, 2346))
        self.assertEqual([v['code_bytes'] for v in plan['continuation_roots']], [87, 164, 212, 1883])
        self.assertFalse(plan['native_control_logic_verified'])
        self.assertEqual(self.sealed['targets'][3]['immutable_span']['unwind_metadata']['flags'], 3)

    def test_cli_is_offline_by_default_and_collect_is_explicit(self):
        parser = reader.argument_parser()
        self.assertFalse(parser.parse_args(['--game-root', 'fixture']).collect)
        self.assertTrue(parser.parse_args(['--game-root', 'fixture', '--collect']).collect)
        with self.assertRaises(SystemExit), mock.patch('sys.stderr'):
            parser.parse_args(['--game-root', 'fixture', '--validate-plan', '--collect'])

    def test_sealed_plan_tamper_rejects_before_process_lookup(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'plan.json'
            path.write_bytes(b'{}')
            with mock.patch.object(reader, 'FIXED_PLAN', path), mock.patch.object(reader, 'verified_pids') as pids:
                with self.assertRaisesRegex(ValueError, 'Sealed JSON file identity'):
                    reader.collect(GAME_ROOT, Path(folder)/'output')
            pids.assert_not_called()

    def test_plan_size_cap_rejects(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'plan.json'
            path.write_bytes(b'x'*(reader.MAX_JSON_BYTES+1))
            with self.assertRaisesRegex(ValueError, 'size bound'):
                reader.sealed_json(path, reader.sha(path.read_bytes()))

    def test_source_hash_and_length_fail_closed(self):
        for sample in (self.sample[:-1], self.sample+b'\0', self.sample[:-1]+bytes([self.sample[-1]^1])):
            with self.subTest(length=len(sample)), self.assertRaisesRegex(ValueError, 'file/scope identity'):
                reader.validate_source(sample, self.sealed['sources'][0], reader.SOURCE_SPECS[0])

    def test_header_identity_is_checked_after_matching_hashes(self):
        changed = bytearray(self.sample)
        struct.pack_into('<Q', changed, 8, reader.SOURCE_SPECS[0][0]+1)
        declared, spec = self.sample_with_new_hashes(changed)
        with self.assertRaisesRegex(ValueError, 'header/code identity'):
            reader.validate_source(changed, declared, spec)

    def test_e8_target_domain_is_checked_after_matching_hashes(self):
        changed = bytearray(self.sample)
        call, _ = reader.SOURCE_SPECS[0][5][0]
        struct.pack_into('<i', changed, 32+call-reader.SOURCE_SPECS[0][0]+1, 0)
        declared, spec = self.sample_with_new_hashes(changed)
        with self.assertRaisesRegex(ValueError, 'source-call domain'):
            reader.validate_source(changed, declared, spec)

    def test_instruction_boundary_and_declared_e8_bytes_are_checked(self):
        declared = copy.deepcopy(self.sealed['sources'][0])
        declared['selected_e8_calls'][0]['instruction_bytes_hex'] = 'e800000000'
        with self.assertRaisesRegex(ValueError, 'E8 instruction evidence'):
            reader.validate_source(self.sample, declared, reader.SOURCE_SPECS[0])
        declared = copy.deepcopy(self.sealed['sources'][0])
        declared['instruction_count'] += 1
        with self.assertRaisesRegex(ValueError, 'completely decode'):
            reader.validate_source(self.sample, declared, reader.SOURCE_SPECS[0])

    def test_source_scope_cannot_be_expanded(self):
        with self.changed_plan(lambda p: p['sources'][0]['code_ranges'][0].__setitem__(1, '0x109ea9d0')):
            with self.assertRaisesRegex(ValueError, 'file/scope identity'):
                reader.validate_image(self.image)

    def test_target_span_and_unwind_hash_must_match_immutable_PE(self):
        mutations = (
            lambda p: p['targets'][0]['immutable_span'].__setitem__('code_bytes', 88),
            lambda p: p['targets'][3]['immutable_span']['unwind_metadata'].__setitem__('metadata_prefix_sha256', '0'*64),
            lambda p: p['targets'][3]['immutable_span']['unwind_metadata'].__setitem__('handler_rva', '0x1'),
        )
        for change in mutations:
            with self.subTest(change=change), self.changed_plan(change), self.assertRaisesRegex(ValueError, 'target evidence'):
                reader.validate_image(self.image)

    def test_complete_pdata_identity_and_budget_are_mandatory(self):
        with self.changed_plan(lambda p: p['pdata'].__setitem__('sha256', '0'*64)):
            with self.assertRaisesRegex(ValueError, 'complete pdata'):
                reader.validate_image(self.image)
        with self.changed_plan(lambda p: p['summary'].__setitem__('maximum_code_bytes', 2347)):
            with self.assertRaisesRegex(ValueError, 'budget mismatch'):
                reader.validate_image(self.image)

    def test_shared_guard_dependency_changes_are_rejected(self):
        with mock.patch.object(reader, 'digest', return_value='0'*64):
            with self.assertRaisesRegex(ValueError, 'guard dependency identity'):
                reader.validate_image(self.image)

    def test_fixed_reads_do_not_follow_even_a_leading_E9(self):
        api = FakeKernel(leading_e9=True)
        report, files = self.collect_mock(api)
        self.assertEqual(report['status'], 'bounded_read_attempt_complete')
        self.assertEqual(api.reads, [(v[0], v[3]) for v in reader.TARGET_SPECS])
        self.assertEqual(report['actual_code_bytes'], 2346)
        self.assertEqual(len(files), 4)
        self.assertEqual(api.closed, [2, 1])
        serialized = json.dumps(report)
        self.assertNotIn('module_base', serialized)
        self.assertNotIn(str(api.base), serialized)

    def test_PID_handle_path_and_module_size_fail_before_any_read(self):
        for changes in ({'pid': 78}, {'path': str(EXECUTABLE.parent/'other.exe')}, {'size': reader.IMAGE_SIZE-1}):
            api = FakeKernel(**changes)
            report, files = self.collect_mock(api)
            self.assertEqual(report['status'], 'bounded_read_failed')
            self.assertEqual(api.reads, [])
            self.assertEqual(files, [])
            self.assertIn(1, api.closed)

    def test_process_create_time_or_path_change_stops_all_reads(self):
        initial = SimpleNamespace(create_time=lambda: 123.0, exe=lambda: str(EXECUTABLE.resolve()))
        alternatives = (
            SimpleNamespace(create_time=lambda: 124.0, exe=lambda: str(EXECUTABLE.resolve())),
            SimpleNamespace(create_time=lambda: 123.0, exe=lambda: str(EXECUTABLE.parent/'other.exe')),
        )
        for changed in alternatives:
            api = FakeKernel()
            report, files = self.collect_mock(api, process=[initial, changed])
            self.assertEqual(report['status'], 'bounded_read_failed')
            self.assertEqual(api.reads, [])
            self.assertEqual(files, [])
            self.assertEqual(api.closed, [2, 1])

    def test_disk_evidence_is_revalidated_after_module_snapshot(self):
        changed = copy.deepcopy(self.plan)
        changed['continuation_roots'][0]['code_bytes'] = 88
        api = FakeKernel()
        report, _ = self.collect_mock(api, revalidated=changed)
        self.assertEqual(report['status'], 'bounded_read_failed')
        self.assertEqual(api.reads, [])
        self.assertEqual(api.closed, [2, 1])

    def test_all_memory_page_guards_prevent_RPM(self):
        cases = ({'state': 0x2000}, {'kind': 0x20000}, {'protection': 0x04}, {'protection': 0x120},
                 {'allocation': FakeKernel.base+1}, {'region_start': FakeKernel.base+reader.IMAGE_SIZE},
                 {'region_size': 1}, {'query_ok': False})
        for values in cases:
            with self.subTest(values=values):
                api = FakeKernel(**values)
                report, files = self.collect_mock(api)
                self.assertEqual(report['status'], 'bounded_read_partial')
                self.assertEqual(len(api.queries), 4)
                self.assertEqual(api.reads, [])
                self.assertEqual(files, [])
                self.assertEqual(api.closed, [2, 1])

    def test_failed_or_short_RPM_never_saves_a_code_file(self):
        for values in ({'copy_ok': False}, {'copy_delta': -1}):
            api = FakeKernel(**values)
            report, files = self.collect_mock(api)
            self.assertEqual(report['status'], 'bounded_read_partial')
            self.assertEqual(report['actual_code_bytes'], 0)
            self.assertEqual(len(api.reads), 4)
            self.assertEqual(files, [])

    def test_nonunique_process_lookup_never_invokes_API(self):
        for pids in ([], [77, 78]):
            with tempfile.TemporaryDirectory() as folder, mock.patch.object(reader, 'build_plan', return_value=self.plan), \
                    mock.patch.object(reader, 'verified_pids', return_value=pids), \
                    mock.patch.object(reader, 'kernel', side_effect=AssertionError('no Windows API')):
                report = reader.collect(GAME_ROOT, folder)
            self.assertEqual(report['status'], 'original_process_not_unique')


if __name__ == '__main__':
    unittest.main()
