"""Immutable-image and synthetic Windows API fixtures only; never a client test."""
import ast
import ctypes as C
import hashlib
import json
import mmap
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import read_native_sender_code as reader

GAME_ROOT = Path(os.environ.get('DF_OFFLINE_TEST_GAME_ROOT', 'D:/个人工作区/DeltaForce-local-client'))
EXECUTABLE = GAME_ROOT / reader.EXECUTABLE_RELATIVE
BODY_TARGET = 0x128634a0


def direct_prefix(target=BODY_TARGET):
    return b'\xe9' + struct.pack('<i', target - reader.PREFIX_RVA - 5) + b'\xcc' * 27


def virtual_prefix(slot=0x288):
    return b'\x48\x8b\x01\xff\xa0' + struct.pack('<i', slot) + b'\xcc' * 23


class FakeKernel:
    base = 0x140000000

    def __init__(self, prefix=b'\x90' * 32, pid=77, size=536408064,
                 protection=0x20, memory_type=0x1000000, allocation_base=None,
                 region_end=None, partial=False):
        self.prefix, self.pid, self.size = prefix, pid, size
        self.protection, self.memory_type = protection, memory_type
        self.allocation_base = self.base if allocation_base is None else allocation_base
        self.region_end = region_end or self.base + self.size
        self.partial, self.reads, self.closed, self.identity_checks = partial, [], [], 0

    def OpenProcess(self, access, inherit, pid):
        assert (access, inherit, pid) == (0x1010, False, 77)
        return 1

    def GetProcessId(self, handle):
        self.identity_checks += 1
        return self.pid

    def CreateToolhelp32Snapshot(self, flags, pid):
        assert (flags, pid) == (0x18, 77)
        return 2

    def Module32FirstW(self, snapshot, pointer):
        module = pointer._obj
        module.szExePath = str(EXECUTABLE.resolve())
        module.modBaseAddr, module.modBaseSize = self.base, self.size
        return True

    def Module32NextW(self, snapshot, pointer):
        return False

    def VirtualQueryEx(self, handle, address, pointer, length):
        memory = pointer._obj
        memory.BaseAddress, memory.AllocationBase = self.base, self.allocation_base
        memory.RegionSize, memory.State, memory.Type = self.region_end - self.base, 0x1000, self.memory_type
        memory.Protect = self.protection
        return C.sizeof(reader.Memory)

    def ReadProcessMemory(self, handle, address, buffer, length, copied):
        self.reads.append((address - self.base, length))
        code = self.prefix if address - self.base == reader.PREFIX_RVA else direct_prefix() + b'\xcc' * (length - 32)
        C.memmove(buffer, code, length)
        copied._obj.value = length - 1 if self.partial else length
        return True

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return True


class SenderCodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = EXECUTABLE.open('rb')
        cls.raw = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_READ)
        cls.image = reader.Image(cls.raw)
        with mock.patch.object(reader, 'kernel', side_effect=AssertionError('No Windows API')):
            cls.plan = reader.build_plan(GAME_ROOT)

    @classmethod
    def tearDownClass(cls):
        cls.raw.close()
        cls.stream.close()

    def fake_collect(self, api, factory=None):
        factory = factory or (lambda pid: SimpleNamespace(
            create_time=lambda: 123.0, exe=lambda: str(EXECUTABLE.resolve())))
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name)
        with mock.patch.object(reader, 'build_plan', return_value=self.plan), \
                mock.patch.object(reader, 'verified_pids', return_value=[77]), \
                mock.patch.object(reader, 'kernel', return_value=api), \
                mock.patch.object(reader.psutil, 'Process', side_effect=factory):
            report = reader.collect(GAME_ROOT, folder)
        return folder, report

    def test_sealed_plan_contains_one_shared_prefix_and_no_initbase(self):
        self.assertEqual((self.plan['fixed_read_count'], self.plan['initial_read_bytes']), (1, 32))
        self.assertEqual((self.plan['maximum_reads'], self.plan['maximum_code_bytes']), (2, 8224))
        self.assertEqual([b['label'] for b in self.plan['bindings']],
                         ['UControlChannel.SendBunch', 'UChannel.SendBunch'])
        self.assertNotIn('InitBase', json.dumps(self.plan['bindings']))
        self.assertFalse(self.plan['actual_instance_table_ownership_verified'])
        self.assertFalse(self.plan['sender_header_writer_role_verified'])

    def test_bad_shipping_hash_fails_before_process_enumeration(self):
        with mock.patch.object(reader, 'digest', return_value='wrong'), \
                mock.patch.object(reader, 'verified_pids') as pids, \
                self.assertRaisesRegex(ValueError, 'Client version hash'):
            reader.collect(GAME_ROOT, Path('unused-offline'))
        pids.assert_not_called()

    def test_tampered_sealed_plan_fails_before_process_access(self):
        with mock.patch.object(reader, 'FIXED_PLAN_SHA', '0' * 64), \
                mock.patch.object(reader, 'verified_pids') as pids, \
                self.assertRaisesRegex(ValueError, 'Sealed evidence file identity'):
            reader.collect(GAME_ROOT, Path('unused-offline'))
        pids.assert_not_called()

    def test_complete_six_qword_signature_and_arguments_are_checked(self):
        original = self.image.data
        for rva, reason in ((0x1b3e8b60, 'six-qword signature'), (0x1d7a1190, 'argument table')):
            def altered(address, length):
                value = original(address, length)
                return bytes([value[0] ^ 1]) + value[1:] if address == rva else value
            with self.subTest(rva=hex(rva)), mock.patch.object(self.image, 'data', side_effect=altered), \
                    self.assertRaisesRegex(ValueError, reason):
                reader.validate_image(self.image)

    def test_whole_pdata_and_static_table_windows_are_pinned(self):
        original = self.image.data
        for rva, reason in ((reader.PDATA_RVA, 'complete pdata'),
                            (reader.TABLE_BASE - 8, 'anchor window'),
                            (reader.TABLE_BASE, 'table window identity')):
            def altered(address, length):
                value = original(address, length)
                return bytes([value[0] ^ 1]) + value[1:] if address == rva else value
            with self.subTest(rva=hex(rva)), mock.patch.object(self.image, 'data', side_effect=altered), \
                    self.assertRaisesRegex(ValueError, reason):
                reader.validate_image(self.image)

    def test_shared_guard_changes_are_refused(self):
        with mock.patch.object(reader, 'digest', return_value='changed'), \
                self.assertRaisesRegex(ValueError, 'guard dependency identity'):
            reader.validate_image(self.image)

    def test_leading_e9_selects_one_exact_complete_root(self):
        follow = reader.select_follow(self.image, direct_prefix())
        self.assertEqual((follow['route'], follow['target_rva'], follow['code_bytes']),
                         ('leading_direct_E9', hex(BODY_TARGET), 304))
        self.assertFalse(follow['recursive_follow'])
        self.assertTrue(follow['unwind_metadata'])

    def test_e9_inside_function_or_back_into_prefix_is_refused(self):
        for target in (BODY_TARGET + 1, reader.PREFIX_RVA):
            with self.subTest(target=hex(target)), self.assertRaises(ValueError):
                reader.select_follow(self.image, direct_prefix(target))

    def test_synthetic_virtual_slot_uses_only_immutable_candidate(self):
        follow = reader.select_follow(self.image, virtual_prefix())
        self.assertEqual(follow['measured_slot_offset'], '0x288')
        self.assertEqual(follow['target_rva'], '0x128668d0')
        self.assertEqual(follow['immutable_table_pointer_rva'], '0x167ea950')
        self.assertFalse(follow['actual_instance_table_ownership_verified'])
        self.assertFalse(follow['sender_header_writer_role_verified'])

    def test_virtual_thunk_rejects_unproved_receiver_register_and_slot(self):
        for code in (b'\x48\x8b\x02' + virtual_prefix()[3:],
                     b'\x48\x8b\x09' + virtual_prefix()[3:],
                     b'\x48\x8b\x41\x08' + virtual_prefix()[3:-1],
                     virtual_prefix(0x28c), virtual_prefix(-8), virtual_prefix(0x2a0),
                     b'\xe8' + virtual_prefix()[1:], b'\x90' * 32):
            with self.subTest(prefix=code.hex()), self.assertRaises(ValueError):
                reader.select_follow(self.image, code)

    def test_virtual_prefix_requires_complete_instruction_decode(self):
        code = virtual_prefix()[:-1] + b'\x0f'
        with self.assertRaisesRegex(ValueError, 'fully decode'):
            reader.select_follow(self.image, code)

    def test_follow_span_over_budget_or_fragment_budget_is_refused(self):
        root, length, fragments = self.image.function_span(BODY_TARGET)
        for span in ((root, 8193, fragments), (root, length, fragments * 33)):
            with self.subTest(length=span[1]), mock.patch.object(self.image, 'function_span', return_value=span), \
                    self.assertRaisesRegex(ValueError, 'complete bounded same-root'):
                reader.select_follow(self.image, direct_prefix())

    def test_mock_e9_reads_only_prefix_and_one_body_and_pins_files(self):
        api = FakeKernel(direct_prefix())
        folder, report = self.fake_collect(api)
        self.assertEqual(report['status'], 'bounded_read_attempt_complete')
        self.assertEqual(api.reads, [(reader.PREFIX_RVA, 32), (BODY_TARGET, 304)])
        self.assertEqual((report['actual_code_bytes'], report['actual_read_count']), (336, 2))
        self.assertEqual(api.closed, [2, 1])
        self.assertEqual(api.identity_checks, 5)
        for row in report['functions']:
            sample = (folder / (row['name'] + '.dfcode')).read_bytes()
            self.assertEqual(hashlib.sha256(sample).hexdigest(), row['file_sha256'])
            self.assertEqual(hashlib.sha256(sample[32:]).hexdigest(), row['code_sha256'])
        self.assertFalse(report['playable_map_verified'])

    def test_mock_virtual_reads_candidate_code_but_never_table_or_heap(self):
        api = FakeKernel(virtual_prefix())
        _, report = self.fake_collect(api)
        self.assertEqual(report['status'], 'bounded_read_attempt_complete')
        self.assertEqual(api.reads, [(reader.PREFIX_RVA, 32), (0x128668d0, 3784)])
        self.assertFalse(report['live_object_or_vtable_read'])
        self.assertFalse(report['actual_instance_table_ownership_verified'])

    def test_unrecognized_prefix_is_saved_without_any_follow(self):
        api = FakeKernel()
        _, report = self.fake_collect(api)
        self.assertEqual(api.reads, [(reader.PREFIX_RVA, 32)])
        self.assertIn('implementation_not_followed', report['functions'][0])

    def test_wrong_opened_pid_or_module_size_never_reads_code(self):
        for api in (FakeKernel(pid=78), FakeKernel(size=536408063)):
            with self.subTest(pid=api.pid, size=api.size):
                _, report = self.fake_collect(api)
                self.assertEqual(report['status'], 'bounded_read_failed')
                self.assertEqual(api.reads, [])
                self.assertIn(1, api.closed)

    def test_process_creation_time_and_path_rechecked_before_read(self):
        for kind in ('time', 'path'):
            calls = []
            def factory(pid):
                calls.append(pid)
                return SimpleNamespace(create_time=lambda: 124.0 if kind == 'time' and len(calls) > 1 else 123.0,
                    exe=lambda: 'D:/other/client.exe' if kind == 'path' and len(calls) > 1 else str(EXECUTABLE.resolve()))
            api = FakeKernel()
            with self.subTest(kind=kind):
                _, report = self.fake_collect(api, factory)
                self.assertEqual(report['status'], 'bounded_read_failed')
                self.assertEqual(api.reads, [])

    def test_page_guard_private_memory_wrong_allocation_and_cross_boundary_refused(self):
        for api in (FakeKernel(protection=0x120), FakeKernel(protection=0x04),
                    FakeKernel(memory_type=0x20000), FakeKernel(allocation_base=0x150000000),
                    FakeKernel(region_end=FakeKernel.base + reader.PREFIX_RVA + 31)):
            with self.subTest(protect=api.protection, memory_type=api.memory_type):
                _, report = self.fake_collect(api)
                self.assertEqual(report['status'], 'bounded_read_failed')
                self.assertEqual(api.reads, [])
                self.assertEqual(api.closed, [2, 1])

    def test_partial_read_never_saves_or_follows(self):
        api = FakeKernel(direct_prefix(), partial=True)
        folder, report = self.fake_collect(api)
        self.assertEqual(report['status'], 'bounded_read_failed')
        self.assertEqual(api.reads, [(reader.PREFIX_RVA, 32)])
        self.assertEqual(report['actual_code_bytes'], 0)
        self.assertFalse((folder / 'SendBunch.prefix.dfcode').exists())

    def test_cli_defaults_to_offline_and_collect_requires_output(self):
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(reader, 'PLAN_OUTPUT', Path(temporary) / 'plan.json'), \
                mock.patch.object(reader, 'build_plan', return_value=self.plan), \
                mock.patch.object(reader, 'collect', side_effect=AssertionError('No live collect')):
            self.assertEqual(reader.main(['--game-root', 'offline-root']), 0)
            with self.assertRaises(SystemExit) as error:
                reader.main(['--game-root', 'offline-root', '--collect'])
            self.assertEqual(error.exception.code, 2)

    def test_collector_contains_no_launch_elevation_or_memory_write_calls(self):
        tree = ast.parse(Path(reader.__file__).read_text(encoding='utf-8'))
        calls = {ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
        for forbidden in ('WriteProcessMemory', 'ShellExecuteExW', 'Popen', 'run', 'elevate', 'CreateProcessW'):
            self.assertFalse(any(c.split('.')[-1] == forbidden for c in calls), forbidden)


if __name__ == '__main__':
    unittest.main()
