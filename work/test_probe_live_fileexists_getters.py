import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch


import probe_live_fileexists_getters as tool


class FileExistsGetterScopeTests(unittest.TestCase):
    BASE = 0x140000000
    SIZE = 0x1ff8f000
    CREATED = 1791145485.6238346

    def setUp(self):
        raw = Path(tool.SOURCE_CAPTURE).read_bytes()
        caller = json.loads(raw)['package_brush']['PackagePathPredicate']
        self.caller = bytes.fromhex(caller['bytes'])
        self.reads = []
        self.memory = {(tool.CALLER_RVA, tool.CALLER_SIZE): self.caller,
                       (tool.FIRST_RVA, tool.FIRST_SIZE): bytes.fromhex('488b0500000000c3') + bytes(8),
                       (tool.SECOND_RVA, tool.SECOND_SIZE): bytes(30) + b'\xc3'}

    def read(self, address, size):
        key = (address - self.BASE, size)
        self.reads.append(key)
        return self.memory[key]

    def capture(self, **options):
        options.setdefault('source_digest', tool.SOURCE_CAPTURE_SHA)
        options.setdefault('actual_created', self.CREATED)
        options.setdefault('expected_created', self.CREATED)
        return tool.capture(self.read, self.BASE, self.SIZE, **options)

    def test_only_three_fixed_code_spans_are_read(self):
        report = self.capture()
        self.assertEqual(self.reads, [(tool.CALLER_RVA, 1024),
                                     (tool.FIRST_RVA, 16), (tool.SECOND_RVA, 31)])
        self.assertEqual(report['captured_bytes'], 1071)
        self.assertFalse(report['fixed_code']['FileExistsFirstGetterPrefix']['function_complete'])
        self.assertTrue(report['fixed_code']['FileExistsSecondGetter']['function_complete'])
        for key in ('heap_read', 'pointer_followed', 'native_called', 'game_launched',
                    'filesystem_pointer_contract_proven', 'fileexists_outcome_proven'):
            self.assertFalse(report[key])

    def test_source_creation_and_bounds_reject_before_any_read(self):
        for options in ({'source_digest': '0' * 64}, {'actual_created': self.CREATED + 1},
                        {'expected_created': float('nan')}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.capture(**options)
            self.assertEqual(self.reads, [])
        for rva, size in tool.allowed_spans():
            with self.subTest(rva=rva), self.assertRaises(ValueError):
                tool.capture(self.read, self.BASE, rva + size - 1,
                             source_digest=tool.SOURCE_CAPTURE_SHA,
                             actual_created=self.CREATED, expected_created=self.CREATED)
            self.assertEqual(self.reads, [])
        for base, size in ((True, self.SIZE), (self.BASE, True), (0, self.SIZE),
                           (0x800000000000, self.SIZE)):
            with self.assertRaises(ValueError):
                tool.capture(self.read, base, size, source_digest=tool.SOURCE_CAPTURE_SHA,
                             actual_created=self.CREATED, expected_created=self.CREATED)
            self.assertEqual(self.reads, [])

    def test_full_fresh_caller_hash_gates_both_targets(self):
        changed = bytearray(self.caller)
        changed[-1] ^= 1
        self.memory[(tool.CALLER_RVA, 1024)] = bytes(changed)
        with self.assertRaisesRegex(ValueError, 'caller_hash'):
            self.capture()
        self.assertEqual(self.reads, [(tool.CALLER_RVA, 1024)])

    def test_both_exact_calls_and_displacements_gate_both_targets(self):
        for site, _, witness in tool.EDGES:
            for delta in (0, 1, 4):
                changed = bytearray(self.caller)
                changed[site - tool.CALLER_RVA + delta] ^= 1
                self.memory[(tool.CALLER_RVA, 1024)] = bytes(changed)
                self.reads.clear()
                with patch.object(tool, 'CALLER_SHA', hashlib.sha256(changed).hexdigest()):
                    with self.assertRaisesRegex(ValueError, 'direct_E8'):
                        self.capture()
                self.assertEqual(self.reads, [(tool.CALLER_RVA, 1024)])
                self.assertEqual(len(witness), 5)

    def test_short_and_nonbyte_reads_are_rejected(self):
        for key in self.memory:
            old = self.memory[key]
            for value in (old[:-1], bytearray(old)):
                self.memory[key] = value
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'short_fixed'):
                    self.capture()
            self.memory[key] = old

    def test_saved_source_full_hash_and_caller_are_qualified(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE), tool.SOURCE_CAPTURE_SHA)

    def test_original_metadata_scope_and_disk_hashes(self):
        memory = {(offset, len(bytes.fromhex(expected))): bytes.fromhex(expected)
                  for _, offset, expected, _ in tool.METADATA}
        memory.update({(offset, size): bytes(size)
                       for _, offset, size, _ in tool.DISK_CODE})
        disk_hashes = tuple((name, offset, size, hashlib.sha256(bytes(size)).hexdigest())
                            for name, offset, size, _ in tool.DISK_CODE)
        reads = []
        def read_at(offset, size):
            reads.append((offset, size))
            return memory[(offset, size)]
        with patch.object(tool, 'DISK_CODE', disk_hashes):
            report = tool.verify_metadata(read_at)
        self.assertFalse(report['first_getter']['function_complete'])
        self.assertEqual(report['second_getter']['end_exclusive_rva'], 0x10a3309f)
        self.assertEqual(report['caller']['end_exclusive_rva'], 0x10ecd35b)
        self.assertEqual(set(reads), set(memory))
        for key in memory:
            original = memory[key]
            memory[key] = original[:-1]
            with patch.object(tool, 'DISK_CODE', disk_hashes):
                with self.assertRaises(ValueError):
                    tool.verify_metadata(read_at)
            memory[key] = original

    def test_changed_original_pdata_and_unwind_rejected(self):
        memory = {(offset, len(bytes.fromhex(expected))): bytes.fromhex(expected)
                  for _, offset, expected, _ in tool.METADATA}
        for key, raw in memory.items():
            changed = bytes([raw[0] ^ 1]) + raw[1:]
            def read_at(offset, size):
                return changed if (offset, size) == key else memory[(offset, size)]
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'metadata'):
                tool.verify_metadata(read_at)


if __name__ == '__main__':
    unittest.main()
