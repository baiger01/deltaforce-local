import hashlib
import struct
import unittest
from unittest.mock import patch

import probe_live_package_filename_headers as tool


class FilenameHeaderScopeTests(unittest.TestCase):
    BASE = 0x140000000
    SIZE = 0x1ff8f000
    CREATED = 1791192020.449072

    def setUp(self):
        self.reads = []
        helper = bytearray(2653)
        at = tool.prior.ROOT_STATE_CALL_SITE - tool.prior.ROOTS_TARGET_RVA
        helper[at:at + 5] = tool.prior.ROOT_STATE_CALL_BYTES
        at = tool.ACCESSOR_EDGE[0] - tool.prior.ROOTS_TARGET_RVA
        helper[at:at + 6] = tool.ACCESSOR_EDGE[1]
        self.helper = bytes(helper)
        getter = bytearray(123)
        for site, witness in tool.GETTER_LEAS:
            at = site - tool.prior.ROOT_STATE_TARGET_RVA
            getter[at:at + 7] = witness
        self.getter = bytes(getter)
        self.memory = {(rva, size): self.helper[rva - tool.prior.ROOTS_TARGET_RVA:
                                              rva - tool.prior.ROOTS_TARGET_RVA + size]
                       for rva, size in tool.prior.ROOTS_CHUNKS}
        self.memory[(tool.prior.ROOT_STATE_TARGET_RVA, 123)] = self.getter
        for rva in tool.HEADERS.values():
            self.memory[(rva, 16)] = struct.pack('<Qii', 0xdeadbeef, 7, 8)
        self.memory[(tool.ACCESSOR_SLOT_RVA, 8)] = struct.pack('<Q', 0x1234)

    def read(self, address, size):
        key = (address - self.BASE, size)
        self.reads.append(key)
        return self.memory[key]

    def capture(self, **overrides):
        options = dict(source_digest=tool.CAPTURE_SHA, actual_created=self.CREATED,
                       expected_created=self.CREATED)
        options.update(overrides)
        with patch.object(tool.prior, 'ROOT_STATE_SOURCE_SHA', hashlib.sha256(self.helper).hexdigest()), \
                patch.object(tool, 'GETTER_SHA', hashlib.sha256(self.getter).hexdigest()):
            return tool.capture(self.read, self.BASE, self.SIZE, **options)

    def test_exact_scope_total_and_no_character_pointer_follows(self):
        report = self.capture()
        self.assertEqual(set(self.reads), tool.allowed_spans())
        self.assertEqual(len(self.reads), 16)
        self.assertEqual(report['captured_bytes'], 2952)
        for rva in tool.HEADERS.values():
            self.assertEqual(self.reads.count((rva, 16)), 2)
        self.assertEqual(self.reads.count((tool.ACCESSOR_SLOT_RVA, 8)), 2)
        self.assertTrue(report['headers_and_slot_rechecked'])
        for key in ('heap_read', 'pointer_followed', 'native_called',
                    'character_pointer_contract_proven', 'actual_filename_proven'):
            self.assertFalse(report[key])
        self.assertEqual(report['fixed_headers']['extension']['first_qword'], '0xdeadbeef')

    def test_all_fresh_code_spans_gate_data_reads(self):
        data_spans = set(tool.allowed_spans()) - set(tool.prior.ROOTS_CHUNKS) - {
            (tool.prior.ROOT_STATE_TARGET_RVA, 123)}
        for key in [*tool.prior.ROOTS_CHUNKS, (tool.prior.ROOT_STATE_TARGET_RVA, 123)]:
            with self.subTest(key=key):
                original = self.memory[key]
                changed = bytearray(original)
                changed[-1] ^= 1
                self.memory[key] = bytes(changed)
                self.reads.clear()
                with self.assertRaises(ValueError):
                    self.capture()
                self.assertTrue(data_spans.isdisjoint(self.reads))
                self.memory[key] = original

    def test_digest_creation_bounds_gate_first_read(self):
        for overrides in (dict(source_digest='0' * 64), dict(actual_created=self.CREATED + 1)):
            self.reads.clear()
            with self.assertRaises(ValueError):
                self.capture(**overrides)
            self.assertEqual(self.reads, [])
        for rva, size in tool.allowed_spans():
            with self.assertRaises(ValueError):
                tool.capture(self.read, self.BASE, rva + size - 1, source_digest=tool.CAPTURE_SHA,
                             actual_created=self.CREATED, expected_created=self.CREATED)
            self.assertEqual(self.reads, [])

    def test_short_reads_are_rejected(self):
        for key in self.memory:
            original = self.memory[key]
            self.memory[key] = original[:-1]
            with self.assertRaisesRegex(ValueError, 'short_fixed_filename_header_read'):
                self.capture()
            self.memory[key] = original

    def test_header_and_slot_instability_are_rejected(self):
        for unstable in [(rva, 16) for rva in tool.HEADERS.values()] + [(tool.ACCESSOR_SLOT_RVA, 8)]:
            counts = {}
            original_read = self.read
            def changing(address, size):
                key = (address - self.BASE, size)
                counts[key] = counts.get(key, 0) + 1
                raw = original_read(address, size)
                return bytes([raw[0] ^ 1]) + raw[1:] if key == unstable and counts[key] == 2 else raw
            self.read = changing
            with self.assertRaisesRegex(ValueError, 'changed_during_read'):
                self.capture()
            self.read = original_read

    def test_actual_saved_source_qualifies_exact_chain_and_fields(self):
        self.assertEqual(tool.load_source(tool.CAPTURE), tool.CAPTURE_SHA)


class FilenameAccessorPrefixScopeTests(unittest.TestCase):
    BASE = FilenameHeaderScopeTests.BASE
    SIZE = FilenameHeaderScopeTests.SIZE
    CREATED = FilenameHeaderScopeTests.CREATED

    def setUp(self):
        FilenameHeaderScopeTests.setUp(self)
        self.slot_span = (tool.ACCESSOR_SLOT_RVA, 8)
        self.prefix_span = (tool.ACCESSOR_TARGET_RVA, tool.ACCESSOR_PREFIX_SIZE)
        self.memory[self.slot_span] = struct.pack('<Q', self.BASE + tool.ACCESSOR_TARGET_RVA)
        self.memory[self.prefix_span] = bytes(16)

    def read(self, address, size):
        return FilenameHeaderScopeTests.read(self, address, size)

    def capture(self, **overrides):
        overrides.setdefault('source_digest', tool.HEADER_CAPTURE_SHA)
        overrides['accessor_prefix'] = True
        return FilenameHeaderScopeTests.capture(self, **overrides)

    def test_exact2808byte_prefix_only_scope(self):
        report = self.capture()
        self.assertEqual(set(self.reads), tool.allowed_spans(accessor_prefix=True))
        self.assertEqual(self.reads[-3:], [self.slot_span, self.prefix_span, self.slot_span])
        self.assertEqual(report['captured_bytes'], 2808)
        self.assertNotIn('fixed_headers', report)
        self.assertFalse(report['accessor_function_complete'])
        self.assertFalse(report['character_pointer_contract_proven'])
        self.assertFalse(report['heap_read'])
        self.assertFalse(report['pointer_followed'])

    def test_wrong_fresh_slot_refuses_fixed_prefix(self):
        for pointer in (0, self.BASE + tool.ACCESSOR_TARGET_RVA + 1, 0x1234):
            self.reads.clear()
            self.memory[self.slot_span] = struct.pack('<Q', pointer)
            with self.assertRaisesRegex(ValueError, 'does_not_match_source_fixed_target'):
                self.capture()
            self.assertNotIn(self.prefix_span, self.reads)

    def test_fresh_converter_and_getter_changes_refuse_slot_and_prefix(self):
        for key in [*tool.prior.ROOTS_CHUNKS, (tool.prior.ROOT_STATE_TARGET_RVA, 123)]:
            original = self.memory[key]
            changed = bytearray(original)
            changed[-1] ^= 1
            self.memory[key] = bytes(changed)
            self.reads.clear()
            with self.assertRaises(ValueError):
                self.capture()
            self.assertNotIn(self.slot_span, self.reads)
            self.assertNotIn(self.prefix_span, self.reads)
            self.memory[key] = original

    def test_actual_saved_source_qualifies_fixed_candidate(self):
        self.assertEqual(tool.load_accessor_source(tool.HEADER_CAPTURE), tool.HEADER_CAPTURE_SHA)

    def test_short_prefix_and_unstable_slot_rejected(self):
        self.memory[self.prefix_span] = bytes(15)
        with self.assertRaisesRegex(ValueError, 'short_fixed_filename_header_read'):
            self.capture()
        self.memory[self.prefix_span] = bytes(16)
        count = 0
        initial = self.read
        def changing(address, size):
            nonlocal count
            data = initial(address, size)
            if (address - self.BASE, size) == self.slot_span:
                count += 1
                if count == 2:
                    data = bytes([data[0] ^ 1]) + data[1:]
            return data
        self.read = changing
        with self.assertRaisesRegex(ValueError, 'slot_changed_during_prefix_read'):
            self.capture()


class FilenameRootStringScopeTests(unittest.TestCase):
    BASE = FilenameHeaderScopeTests.BASE
    SIZE = FilenameHeaderScopeTests.SIZE
    CREATED = FilenameHeaderScopeTests.CREATED

    def setUp(self):
        FilenameAccessorPrefixScopeTests.setUp(self)
        self.memory[self.prefix_span] = tool.ACCESSOR_LEAF_BYTES
        self.character_reads = []
        self.character_buffers = {}
        self.expected_strings = {}
        for index, (name, rva) in enumerate(tool.HEADERS.items()):
            value = f'/Synthetic{index}/'
            self.install_string(name, value, 0x220000000 + index * 4096)

    def install_string(self, name, value, pointer):
        data = value.encode('utf-16-le') + b'\0\0'
        count = len(data) // 2
        self.memory[(tool.HEADERS[name], 16)] = struct.pack('<Qii', pointer, count, count)
        self.character_buffers[pointer] = data
        self.expected_strings[name] = value

    def read(self, address, size):
        return FilenameHeaderScopeTests.read(self, address, size)

    def read_characters(self, header_rva, header):
        pointer, count, maximum, size = tool.bounded_header(header_rva, header)
        self.character_reads.append((header_rva, pointer, size))
        return self.character_buffers[pointer]

    def capture(self, **overrides):
        overrides.setdefault('source_digest', tool.ACCESSOR_CAPTURE_SHA)
        overrides.setdefault('read_characters', self.read_characters)
        overrides['root_strings'] = True
        return FilenameHeaderScopeTests.capture(self, **overrides)

    def test_only_five_current_header_buffers_twice_and_exact_accounting(self):
        report = self.capture()
        self.assertEqual(set(self.reads), tool.allowed_spans(root_strings=True))
        self.assertEqual(len(self.character_reads), 10)
        self.assertEqual(report['character_read_bytes'], sum(size for _, _, size in self.character_reads))
        self.assertEqual(report['captured_bytes'], 2968 + report['character_read_bytes'])
        self.assertEqual({name: item['value'] for name, item in report['strings'].items()}, self.expected_strings)
        self.assertTrue(report['character_pointer_contract_proven'])
        self.assertTrue(report['headers_characters_and_slot_rechecked'])
        self.assertFalse(report['dynamic_root_array_read'])
        self.assertFalse(report['actual_filename_proven'])
        for rva in tool.HEADERS.values():
            self.assertEqual(sum(header == rva for header, _, _ in self.character_reads), 2)

    def test_fresh_accessor_leaf_refuses_all_headers_and_characters(self):
        data_spans = {(rva, 16) for rva in tool.HEADERS.values()}
        for index in (0, 3, 15):
            changed = bytearray(tool.ACCESSOR_LEAF_BYTES)
            changed[index] ^= 1
            self.memory[self.prefix_span] = bytes(changed)
            self.reads.clear()
            with self.assertRaisesRegex(ValueError, 'fresh_filename_string_accessor_leaf_changed'):
                self.capture()
            self.assertTrue(data_spans.isdisjoint(self.reads))
            self.assertEqual(self.character_reads, [])

    def test_bad_header_counts_max_alignment_canonical_overflow_prevent_all_character_reads(self):
        rva = tool.HEADERS['first_root']
        original = self.memory[(rva, 16)]
        for pointer, count, maximum in ((0x220000000, -1, 4), (0x220000000, 5, 4),
                                        (0x220000000, 257, 257), (0x220000000, 2, 257),
                                        (0, 2, 2), (0x220000001, 2, 2),
                                        (0x800000000000, 2, 2), (0x7ffffffffffe, 2, 2)):
            self.memory[(rva, 16)] = struct.pack('<Qii', pointer, count, maximum)
            with self.assertRaises(ValueError):
                self.capture()
            self.assertEqual(self.character_reads, [])
        self.memory[(rva, 16)] = original

    def test_missing_terminal_embedded_NUL_and_invalid_UTF16_rejected(self):
        pointer = struct.unpack('<Qii', self.memory[(tool.HEADERS['first_root'], 16)])[0]
        original = self.character_buffers[pointer]
        for raw in (original[:-2] + b'A\0', b'\0\0' + original[2:], b'\0\xd8' + original[2:]):
            self.character_buffers[pointer] = raw
            with self.assertRaises(ValueError):
                self.capture()
        self.character_buffers[pointer] = original

    def test_short_character_read_rejected(self):
        def short(header_rva, header):
            return self.read_characters(header_rva, header)[:-1]
        with self.assertRaisesRegex(ValueError, 'short_bounded_filename_string_read'):
            self.capture(read_characters=short)

    def test_character_instability_rejected(self):
        counts = {}
        def changing(header_rva, header):
            raw = self.read_characters(header_rva, header)
            counts[header_rva] = counts.get(header_rva, 0) + 1
            return b'A\0' + raw[2:] if counts[header_rva] == 2 else raw
        with self.assertRaisesRegex(ValueError, 'characters_changed_during_read'):
            self.capture(read_characters=changing)

    def test_header_or_slot_instability_rejected(self):
        for unstable in [(tool.HEADERS['second_prefix'], 16), self.slot_span]:
            counts = {}
            initial = self.read
            def changing(address, size):
                raw = initial(address, size)
                key = (address - self.BASE, size)
                counts[key] = counts.get(key, 0) + 1
                return bytes([raw[0] ^ 1]) + raw[1:] if key == unstable and counts[key] == 2 else raw
            self.read = changing
            with self.assertRaisesRegex(ValueError, 'changed_during_read'):
                self.capture()
            self.read = initial

    def test_maximum_codeunit_cap_yields_exact8088byte_budget(self):
        for index, name in enumerate(tool.HEADERS):
            self.install_string(name, 'A' * 255, 0x330000000 + index * 4096)
        report = self.capture()
        self.assertEqual(report['captured_bytes'], 8088)
        self.assertTrue(all(size == 512 for _, _, size in self.character_reads))

    def test_zero_count_and_NUL_only_strings(self):
        first = tool.HEADERS['first_root']
        self.memory[(first, 16)] = struct.pack('<Qii', 0, 0, 0)
        self.expected_strings['first_root'] = ''
        self.install_string('second_root', '', 0x440000000)
        report = self.capture()
        self.assertEqual(report['strings']['first_root']['value'], '')
        self.assertEqual(report['strings']['second_root']['value'], '')
        self.assertEqual(sum(header == first for header, _, _ in self.character_reads), 0)

    def test_source_identity_combined_modes_and_missing_reader_reject_before_reads(self):
        for overrides in (dict(source_digest=tool.HEADER_CAPTURE_SHA),
                          dict(actual_created=self.CREATED + 1), dict(accessor_prefix=True),
                          dict(read_characters=None)):
            with self.assertRaises(ValueError):
                self.capture(**overrides)
            self.assertEqual(self.reads, [])
            self.assertEqual(self.character_reads, [])

    def test_actual_saved_accessor_source_closes_leaf_contract(self):
        self.assertEqual(tool.load_strings_source(tool.ACCESSOR_CAPTURE), tool.ACCESSOR_CAPTURE_SHA)


class FilenameRootMatcherScopeTests(unittest.TestCase):
    BASE = FilenameHeaderScopeTests.BASE
    SIZE = FilenameHeaderScopeTests.SIZE
    CREATED = FilenameHeaderScopeTests.CREATED

    def setUp(self):
        FilenameHeaderScopeTests.setUp(self)
        helper = bytearray(self.helper)
        for site, witness in (*tool.MATCH_EDGES, *tool.MATCH_ARGUMENT_WITNESSES):
            at = site - tool.prior.ROOTS_TARGET_RVA
            helper[at:at + len(witness)] = witness
        self.helper = bytes(helper)
        for rva, size in tool.prior.ROOTS_CHUNKS:
            at = rva - tool.prior.ROOTS_TARGET_RVA
            self.memory[(rva, size)] = self.helper[at:at + size]
        self.memory[(tool.MATCH_RVA, tool.MATCH_SIZE)] = bytes(tool.MATCH_SIZE)

    def read(self, address, size):
        return FilenameHeaderScopeTests.read(self, address, size)

    def capture(self, **overrides):
        overrides.setdefault('source_digest', tool.STRING_CAPTURE_SHA)
        overrides['root_match_helper'] = True
        return FilenameHeaderScopeTests.capture(self, **overrides)

    def test_exact2866byte_code_only_scope_and_actual_saved_source(self):
        report = self.capture()
        self.assertEqual(self.reads, [*tool.prior.ROOTS_CHUNKS, (tool.MATCH_RVA, tool.MATCH_SIZE)])
        self.assertEqual(set(self.reads), tool.allowed_spans(root_match_helper=True))
        self.assertEqual(report['captured_bytes'], 2866)
        self.assertTrue(report['fresh_match_edges_and_R8D1_verified'])
        self.assertFalse(report['heap_read'])
        self.assertFalse(report['pointer_followed'])
        self.assertEqual(tool.load_match_source(tool.STRING_CAPTURE), tool.STRING_CAPTURE_SHA)

    def test_fresh_converter_changes_prevent_matcher_read(self):
        for rva, size in tool.prior.ROOTS_CHUNKS:
            original = self.memory[(rva, size)]
            changed = bytearray(original)
            changed[-1] ^= 1
            self.memory[(rva, size)] = bytes(changed)
            self.reads.clear()
            with self.assertRaises(ValueError):
                self.capture()
            self.assertNotIn((tool.MATCH_RVA, tool.MATCH_SIZE), self.reads)
            self.memory[(rva, size)] = original

    def test_each_match_edge_and_argument_witness_rejected(self):
        for site, witness in (*tool.MATCH_EDGES, *tool.MATCH_ARGUMENT_WITNESSES):
            changed = bytearray(self.helper)
            changed[site - tool.prior.ROOTS_TARGET_RVA] ^= 1
            with self.assertRaisesRegex(ValueError, 'root_match_'):
                tool.verify_match_edges(bytes(changed))

    def test_wrong_source_mode_bounds_and_short_matcher_rejected(self):
        for overrides in (dict(source_digest=tool.ACCESSOR_CAPTURE_SHA), dict(accessor_prefix=True),
                          dict(root_strings=True), dict(actual_created=self.CREATED + 1)):
            self.reads.clear()
            with self.assertRaises(ValueError):
                self.capture(**overrides)
            self.assertEqual(self.reads, [])
        key = (tool.MATCH_RVA, tool.MATCH_SIZE)
        self.memory[key] = bytes(tool.MATCH_SIZE - 1)
        with self.assertRaisesRegex(ValueError, 'short_fixed_filename_header_read'):
            self.capture()


class FilenameCopyHelperScopeTests(unittest.TestCase):
    BASE = FilenameHeaderScopeTests.BASE
    SIZE = FilenameHeaderScopeTests.SIZE
    CREATED = FilenameHeaderScopeTests.CREATED

    def setUp(self):
        import json
        matcher_source = json.loads(tool.COPY_CAPTURE.read_bytes())
        getter_source = json.loads(tool.CAPTURE.read_bytes())
        compare_source = json.loads((tool.prior.ROOT / 'work/evidence/live-package-compare-bundle-20261005-private.json').read_bytes())
        self.helper = bytes.fromhex(matcher_source['fixed_code']['PackageFilenameRoots']['bytes'])
        self.memory = {(rva, size): self.helper[rva - tool.prior.ROOTS_TARGET_RVA:rva - tool.prior.ROOTS_TARGET_RVA + size]
                       for rva, size in tool.prior.ROOTS_CHUNKS}
        self.memory[(tool.prior.ROOT_STATE_TARGET_RVA, 123)] = bytes.fromhex(
            getter_source['fixed_code']['PackageFilenameRootStateGetter']['bytes'])
        self.memory[(tool.MATCH_RVA, tool.MATCH_SIZE)] = bytes.fromhex(
            matcher_source['fixed_code']['PackageRootMatchHelper']['bytes'])
        self.memory[(0x10a139d0, 165)] = bytes.fromhex(
            compare_source['fixed_code']['CacheFStringCompare']['bytes'])[0x200:0x2a5]
        self.memory[(0x109ed8b0, 24)] = bytes(24)
        self.memory[(0xd632b0, 123)] = bytes(123)
        self.reads = []

    def read(self, address, size):
        key = (address - self.BASE, size)
        self.reads.append(key)
        return self.memory[key]

    def capture(self, **overrides):
        options = dict(source_digest=tool.COPY_CAPTURE_SHA, actual_created=self.CREATED,
                       expected_created=self.CREATED, filename_copy_helpers=True)
        options.update(overrides)
        return tool.capture(self.read, self.BASE, self.SIZE, **options)

    def test_exact3301byte_fixed_code_scope_and_saved_source(self):
        report = self.capture()
        self.assertEqual(self.reads, [*tool.prior.ROOTS_CHUNKS,
                         (tool.prior.ROOT_STATE_TARGET_RVA, 123), (tool.MATCH_RVA, 213),
                         *tool.COPY_TARGETS.values()])
        self.assertEqual(set(self.reads), tool.allowed_spans(filename_copy_helpers=True))
        self.assertEqual(report['captured_bytes'], 3301)
        self.assertTrue(report['fresh_compare_full_span_verified'])
        for key in ('heap_read', 'pointer_followed', 'native_called', 'actual_filename_proven',
                    'append_entry_complete_function_claim'):
            self.assertFalse(report[key])
        self.assertEqual(tool.load_copy_source(tool.COPY_CAPTURE), tool.COPY_CAPTURE_SHA)

    def test_every_fresh_code_gate_prevents_next_targets(self):
        for key in [*tool.prior.ROOTS_CHUNKS, (tool.prior.ROOT_STATE_TARGET_RVA, 123),
                    (tool.MATCH_RVA, 213), (0x10a139d0, 165)]:
            original = self.memory[key]
            self.memory[key] = original[:-1] + bytes([original[-1] ^ 1])
            self.reads.clear()
            with self.assertRaises(ValueError):
                self.capture()
            self.assertNotIn((0x109ed8b0, 24), self.reads)
            self.assertNotIn((0xd632b0, 123), self.reads)
            self.memory[key] = original

    def test_each_direct_call_witness_rejected(self):
        matcher = self.memory[(tool.MATCH_RVA, 213)]
        for site, witness, target in tool.COPY_CALLS:
            changed = bytearray(self.helper)
            changed[site - tool.prior.ROOTS_TARGET_RVA] ^= 1
            with self.assertRaisesRegex(ValueError, 'direct_call_changed'):
                tool.verify_copy_calls(bytes(changed), matcher)
        changed = bytearray(matcher)
        changed[tool.COMPARE_CALL[0] - tool.MATCH_RVA] ^= 1
        with self.assertRaisesRegex(ValueError, 'direct_call_changed'):
            tool.verify_copy_calls(self.helper, bytes(changed))

    def test_modes_identity_digest_bounds_and_short_target_rejected(self):
        for overrides in (dict(root_match_helper=True), dict(root_strings=True),
                          dict(accessor_prefix=True), dict(source_digest=tool.STRING_CAPTURE_SHA),
                          dict(actual_created=self.CREATED + 1)):
            self.reads.clear()
            with self.assertRaises(ValueError):
                self.capture(**overrides)
            self.assertEqual(self.reads, [])
        self.reads.clear()
        with self.assertRaises(ValueError):
            tool.capture(self.read, self.BASE, 0x109ed8c7, source_digest=tool.COPY_CAPTURE_SHA,
                         actual_created=self.CREATED, expected_created=self.CREATED,
                         filename_copy_helpers=True)
        self.assertEqual(self.reads, [])
        for key in tool.COPY_TARGETS.values():
            original = self.memory[key]
            self.memory[key] = original[:-1]
            with self.assertRaisesRegex(ValueError, 'short_fixed_filename_header_read'):
                self.capture()
            self.memory[key] = original


if __name__ == '__main__':
    unittest.main()
