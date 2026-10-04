"""Offline fixed-image and mocked-reader checks; no game or Windows API runs."""
import argparse
import ast
import ctypes as C
import hashlib
import json
import mmap
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import read_native_control_code as reader


GAME_ROOT = Path(os.environ.get('DF_OFFLINE_TEST_GAME_ROOT', 'D:/个人工作区/DeltaForce-local-client'))
EXECUTABLE = GAME_ROOT / reader.EXECUTABLE_RELATIVE


class FakeKernel:
    """Synthetic code/identity only, deliberately disconnected from Windows."""
    base = 0x140000000

    def __init__(self, protection=0x20, opened_pid=77):
        self.protection, self.opened_pid = protection, opened_pid
        self.read_lengths, self.closed, self.query_count = [], [], 0

    def OpenProcess(self, access, inherit, pid):
        assert (access, inherit, pid) == (0x1010, False, 77)
        return 1

    def GetProcessId(self, handle):
        return self.opened_pid

    def CreateToolhelp32Snapshot(self, flags, pid):
        assert (flags, pid) == (0x18, 77)
        return 2

    def Module32FirstW(self, snapshot, pointer):
        module = pointer._obj
        module.szExePath = str(EXECUTABLE.resolve())
        module.modBaseAddr, module.modBaseSize = self.base, 536408064
        return True

    def Module32NextW(self, snapshot, pointer):
        return False

    def VirtualQueryEx(self, handle, address, pointer, length):
        self.query_count += 1
        memory = pointer._obj
        memory.BaseAddress = memory.AllocationBase = self.base
        memory.RegionSize, memory.State, memory.Type = 536408064, 0x1000, 0x1000000
        memory.Protect = self.protection
        return C.sizeof(reader.Memory)

    def ReadProcessMemory(self, handle, address, buffer, length, copied):
        self.read_lengths.append(length)
        C.memset(buffer, 0x90, length)
        copied._obj.value = length
        return True

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return True


class CandidateIntervalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = EXECUTABLE.open('rb')
        cls.raw = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_READ)
        cls.image = reader.Image(cls.raw)

    @classmethod
    def tearDownClass(cls):
        cls.raw.close()
        cls.stream.close()

    def test_real_candidate_plan_has_only_thirteen_closed_roots(self):
        with mock.patch.object(reader, 'kernel', side_effect=AssertionError('Windows API forbidden')):
            plan = reader.build_plan(GAME_ROOT, candidate_interval=True)
        self.assertEqual((plan['maximum_reads'], plan['maximum_code_bytes']), (13, 17564))
        self.assertEqual(sum(x['code_bytes'] for x in plan['candidate_roots']), 17564)
        self.assertEqual(len(plan['candidate_roots']), 13)
        self.assertNotIn('named_prefixes', plan)
        self.assertFalse(plan['candidate_method_identity_verified'])
        self.assertTrue(all(not x['method_role_verified'] for x in plan['candidate_roots']))
        sealed = json.loads(reader.CANDIDATE_PLAN.read_bytes())
        self.assertEqual([x['label'] for x in plan['candidate_roots']],
                         [x['label'] for x in sealed['candidate_roots']])

    def test_default_plan_limits_and_named_profile_are_unchanged(self):
        with mock.patch.object(reader, 'kernel', side_effect=AssertionError('Windows API forbidden')):
            plan = reader.build_plan(GAME_ROOT)
        self.assertEqual((reader.MAX_READS, reader.MAX_CODE_BYTES), (14, 52747))
        self.assertEqual((plan['maximum_reads'], plan['maximum_code_bytes']), (14, 52747))
        self.assertEqual(len(plan['named_prefixes']), 6)
        self.assertNotIn('candidate_roots', plan)

    def test_cli_candidate_flag_is_explicit_and_defaults_off(self):
        tree = ast.parse(Path(reader.__file__).read_text(encoding='utf-8'))
        main = next(x for x in tree.body if isinstance(x, ast.If) and
                    ast.unparse(x.test) == "__name__ == '__main__'")
        nodes = []
        for node in main.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'args'
                                                   for t in node.targets):
                break
            nodes.append(node)
        scope = {'argparse': argparse, 'Path': Path, '__doc__': 'Offline parser fixture'}
        module = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
        exec(compile(module, '<offline argument parser>', 'exec'), scope)
        base = ['--game-root', 'offline-root', '--validate-plan']
        self.assertFalse(scope['parser'].parse_args(base).candidate_interval)
        self.assertTrue(scope['parser'].parse_args(base + ['--candidate-interval']).candidate_interval)

    def test_non_bool_opt_in_is_rejected(self):
        for value in (1, 0, 'yes', None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'explicit bool'):
                reader.build_plan(GAME_ROOT, candidate_interval=value)

    def test_tampered_plan_file_is_rejected_before_process_access(self):
        with mock.patch.object(Path, 'read_bytes', return_value=b'{}'), \
                mock.patch.object(reader, 'verified_pids') as pids, \
                self.assertRaisesRegex(ValueError, 'plan file identity'):
            reader.collect(GAME_ROOT, Path('unused-offline-output'), candidate_interval=True)
        pids.assert_not_called()

    def test_wrong_shipping_sha_is_rejected_before_process_access(self):
        with mock.patch.object(reader, 'digest', return_value='wrong-sha'), \
                mock.patch.object(reader, 'verified_pids') as pids, \
                self.assertRaisesRegex(ValueError, 'Client version hash'):
            reader.collect(GAME_ROOT, Path('unused-offline-output'), candidate_interval=True)
        pids.assert_not_called()

    def test_whole_pdata_and_each_unwind_identity_are_checked(self):
        original = self.image.data
        for target, error in ((0x1e5d1000, 'complete pdata'), (0x1bdcb444, 'unwind metadata identity')):
            def altered(rva, length):
                value = original(rva, length)
                return bytes([value[0] ^ 1]) + value[1:] if rva == target else value
            with self.subTest(target=hex(target)), mock.patch.object(self.image, 'data', side_effect=altered), \
                    self.assertRaisesRegex(ValueError, error):
                reader.validate_candidate_interval(self.image)

    def test_independent_function_span_mismatch_is_rejected(self):
        original = self.image.function_span
        def wrong_span(rva):
            root, length, fragments = original(rva)
            return (root, length + 1, fragments) if rva == reader.CANDIDATE_LOW else (root, length, fragments)
        with mock.patch.object(self.image, 'function_span', side_effect=wrong_span), \
                self.assertRaisesRegex(ValueError, 'same-root function boundary'):
            reader.validate_candidate_interval(self.image)

    def test_candidate_executable_boundary_is_checked(self):
        original = self.image.executable
        def refused(rva, length=1):
            return False if (rva, length) == (reader.CANDIDATE_LOW, 17648) else original(rva, length)
        with mock.patch.object(self.image, 'executable', side_effect=refused), \
                self.assertRaisesRegex(ValueError, 'interval bounds'):
            reader.validate_candidate_interval(self.image)

    def collect_fake(self, api, process_factory=None):
        factory = process_factory or (lambda pid: SimpleNamespace(
            create_time=lambda: 123.0, exe=lambda: str(EXECUTABLE.resolve())))
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name)
        with mock.patch.object(reader, 'verified_pids', return_value=[77]), \
                mock.patch.object(reader, 'kernel', return_value=api), \
                mock.patch.object(reader.psutil, 'Process', side_effect=factory), \
                mock.patch.object(reader, 'direct_e9_span', side_effect=AssertionError('No target follow allowed')):
            report = reader.collect(GAME_ROOT, folder, candidate_interval=True)
        return folder, report

    def test_mocked_candidate_reads_exact_budget_no_follow_and_pins_saved_files(self):
        api = FakeKernel()
        folder, report = self.collect_fake(api)
        self.assertEqual(report['status'], 'bounded_read_attempt_complete')
        self.assertEqual((len(api.read_lengths), sum(api.read_lengths)), (13, 17564))
        self.assertEqual(report['actual_code_bytes'], 17564)
        self.assertEqual(report['maximum_reads'], 13)
        self.assertFalse(report['native_control_logic_verified'])
        sealed = json.loads(reader.CANDIDATE_PLAN.read_bytes())
        self.assertEqual([x['name'] for x in report['functions']],
                         [x['label'] for x in sealed['candidate_roots']])
        for item in report['functions']:
            saved = (folder / (item['name'] + '.dfcode')).read_bytes()
            self.assertEqual(hashlib.sha256(saved).hexdigest(), item['file_sha256'])
            self.assertEqual(hashlib.sha256(saved[32:]).hexdigest(), item['code_sha256'])
            self.assertIn('candidate_root_evidence', item)
            self.assertNotIn('direct_e9_follow', item)
        self.assertEqual(api.closed, [2, 1])

    def test_guarded_memory_is_never_read(self):
        api = FakeKernel(protection=0x120)
        _, report = self.collect_fake(api)
        self.assertEqual(api.read_lengths, [])
        self.assertEqual(report['actual_code_bytes'], 0)
        self.assertTrue(all(not item['read_succeeded'] for item in report['functions']))

    def test_opened_pid_mismatch_is_never_read(self):
        api = FakeKernel(opened_pid=78)
        _, report = self.collect_fake(api)
        self.assertEqual(report['status'], 'bounded_read_failed')
        self.assertEqual(api.query_count, 0)
        self.assertEqual(api.read_lengths, [])
        self.assertEqual(api.closed, [1])

    def test_changed_process_creation_time_is_never_read(self):
        api, generations = FakeKernel(), []
        def changing(pid):
            generations.append(pid)
            stamp = 123.0 if len(generations) == 1 else 456.0
            return SimpleNamespace(create_time=lambda: stamp, exe=lambda: str(EXECUTABLE.resolve()))
        _, report = self.collect_fake(api, changing)
        self.assertEqual(report['status'], 'bounded_read_failed')
        self.assertEqual(api.query_count, 0)
        self.assertEqual(api.read_lengths, [])
        self.assertEqual(api.closed, [2, 1])


if __name__ == '__main__':
    unittest.main(verbosity=2)
