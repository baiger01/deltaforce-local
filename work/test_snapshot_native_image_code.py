"""Offline/mock only. No real process or kernel API calls."""
import ctypes as C
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import snapshot_native_image_code as s


class FakeApi:
    base = 0x400000000

    def __init__(self, protect=0x20, state=0x1000, type_=0x1000000, allocation=None,
                 query_ok=True, read_ok=True, short=False, split=0x1000):
        self.protect, self.state, self.type = protect, state, type_
        self.allocation = self.base if allocation is None else allocation
        self.query_ok, self.read_ok, self.short = query_ok, read_ok, short
        self.split, self.reads = split, []

    def VirtualQueryEx(self, handle, address, pointer, size):
        if not self.query_ok:
            return 0
        info = pointer._obj
        start = address-address % self.split
        info.BaseAddress, info.RegionSize = start, self.split
        info.AllocationBase, info.State, info.Type = self.allocation, self.state, self.type
        info.Protect = self.protect
        return size

    def ReadProcessMemory(self, handle, address, buffer, size, copied):
        self.reads.append((address-self.base, size))
        C.memset(buffer, 0x41, size)
        copied._obj.value = size-1 if self.short else size
        return self.read_ok


def small_plan(size=0x1801):
    return {'sections': [{'index': 0, 'rva': '0x1000', 'file_backed_code_bytes': size}],
        'maximum_code_bytes': size, 'maximum_region_split_RPM_count': (size+4095)//4096}


class Tests(unittest.TestCase):
    def test_guard_rejections_never_read(self):
        for kwargs in ({'protect': 0x104}, {'protect': 1}, {'protect': 4},
                       {'state': 0x2000}, {'type_': 0x20000}, {'allocation': 0x410000000},
                       {'protect': 0x120}, {'query_ok': False}):
            with self.subTest(kwargs=kwargs):
                api = FakeApi(**kwargs)
                length, reason = s.region_slice(api, 1, api.base, 0x1000, 0x800)
                self.assertEqual(length, 0x800)
                self.assertIsNotNone(reason)
                self.assertEqual(api.reads, [])

    def test_region_and_section_end_boundaries(self):
        api = FakeApi(split=0x2000)
        self.assertEqual(s.region_slice(api, 1, api.base, 0x1000, 0x9000), (0x1000, None))
        self.assertEqual(s.region_slice(api, 1, api.base, 0x1000, 11), (11, None))

    def test_one_MiB_bound(self):
        api = FakeApi(split=0x400000)
        self.assertEqual(s.region_slice(api, 1, api.base, 0x1000, 0x300000), (s.CHUNK_BYTES, None))

    def test_invalid_region_alignment_is_missing(self):
        api = FakeApi(split=0x1001)
        length, reason = s.region_slice(api, 1, api.base, 0x1000, 0x9000)
        self.assertEqual(length, 4096)
        self.assertEqual(reason, 'invalid_region_alignment')

    def test_snapshot_exact_scope_hash_and_split(self):
        plan, api, checks = small_plan(), FakeApi(), []
        known = (('mock', 0x1ffe, 6, hashlib.sha256(b'A'*6).hexdigest()),)
        with tempfile.TemporaryDirectory() as temp, patch.object(s, 'KNOWN_SENDERS', known):
            folder = Path(temp)
            result = s.snapshot_sections(api, 1, api.base, plan, folder, lambda: checks.append(True))
            self.assertEqual(api.reads, [(0x1000, 4096), (0x2000, 2049)])
            self.assertEqual(result['saved_code_bytes'], 6145)
            self.assertEqual(result['unavailable_bytes'], 0)
            self.assertTrue(result['known_sender_comparisons'][0]['matches_saved_native_sample'])
            self.assertEqual(len(checks), 4)
            for block in result['sections'][0]['blocks']:
                payload = (folder/block['file']).read_bytes()
                self.assertEqual(hashlib.sha256(payload).hexdigest(), block['code_sha256'])
            self.assertNotIn(hex(api.base), json.dumps(result))

    def test_short_read_not_saved(self):
        plan, api = small_plan(123), FakeApi(short=True)
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            result = s.snapshot_sections(api, 1, api.base, plan, folder, lambda: None)
            self.assertEqual(result['saved_code_bytes'], 0)
            self.assertEqual(result['unavailable_bytes'], 123)
            self.assertEqual(list(folder.iterdir()), [])

    def test_noaccess_records_all_missing(self):
        plan, api = small_plan(), FakeApi(protect=1)
        with tempfile.TemporaryDirectory() as temp:
            result = s.snapshot_sections(api, 1, api.base, plan, Path(temp), lambda: None)
            self.assertEqual(api.reads, [])
            self.assertEqual(result['unavailable_bytes'], plan['maximum_code_bytes'])
            self.assertEqual(sum(b['bytes'] for b in result['sections'][0]['blocks']), 6145)

    def test_identity_change_aborts_before_save(self):
        api, counter = FakeApi(), []
        def check():
            counter.append(True)
            if len(counter) == 2:
                raise RuntimeError('mock process changed')
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            with self.assertRaises(RuntimeError):
                s.snapshot_sections(api, 1, api.base, small_plan(11), folder, check)
            self.assertEqual(list(folder.iterdir()), [])

    def test_identity_mismatch_PID(self):
        class API:
            def GetProcessId(self, handle):
                return 99
        with patch.object(s.psutil, 'Process', side_effect=AssertionError('must not call')):
            with self.assertRaises(RuntimeError):
                s.process_identity(API(), 1, 98, Path('mock'), 1.0)

    def test_identity_path_and_created(self):
        class API:
            def GetProcessId(self, handle):
                return 98
        class Process:
            def create_time(self):
                return 1.5
            def exe(self):
                return 'mock'
        with patch.object(s.psutil, 'Process', return_value=Process()):
            with self.assertRaises(RuntimeError):
                s.process_identity(API(), 1, 98, Path('mock'), 1.0)
            with self.assertRaises(RuntimeError):
                s.process_identity(API(), 1, 98, Path('different'), 1.5)

    def test_output_restriction_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(s, 'CACHE_ROOT', Path(temp)/'cache'):
            self.assertEqual(s.private_output(Path(temp)/'cache/new'), Path(temp)/'cache/new')
            for bad in (Path(temp)/'outside', Path(temp)/'cache/new/deeper', Path(temp)/'cache'):
                with self.assertRaises(ValueError):
                    s.private_output(bad)
            (Path(temp)/'cache/new').mkdir(parents=True)
            with self.assertRaises(ValueError):
                s.private_output(Path(temp)/'cache/new')

    def test_live_parameters_fail_before_kernel(self):
        with patch.object(s, 'kernel', side_effect=AssertionError('no live APIs')):
            for pid, created in ((True, 1), (0, 1), (1, True), (1, float('nan')), (1, -1)):
                with self.assertRaises(ValueError):
                    s.collect(s.SHADOW_ROOT, Path('mock'), pid, created)
            with self.assertRaises(ValueError):
                s.collect(Path('unrelated'), Path('mock'), 1, 1)

    def test_offline_wrong_disk_size_no_process(self):
        with tempfile.TemporaryDirectory() as temp:
            executable = Path(temp)/s.EXECUTABLE_RELATIVE
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'x')
            with patch.object(s, 'kernel', side_effect=AssertionError('no live APIs')):
                with self.assertRaises(ValueError):
                    s.validate_plan(temp)

    def test_defaultCLI_static_and_mutual_mode(self):
        parser = s.argument_parser()
        args = parser.parse_args(['--game-root', 'mock'])
        self.assertFalse(args.collect)
        with self.assertRaises(SystemExit):
            parser.parse_args(['--game-root', 'mock', '--collect', '--validate-plan'])


if __name__ == '__main__':
    unittest.main()
