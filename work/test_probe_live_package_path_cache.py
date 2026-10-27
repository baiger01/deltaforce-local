import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

try:
    import probe_live_package_path_cache as tool
except ModuleNotFoundError as error:
    if error.name != 'probe_live_package_path_cache':
        raise
    tool = None


class PackagePathCacheScopeTests(unittest.TestCase):
    BASE = 0x140000000
    SIZE = 0x1ff8f000
    CREATED = 1791147488.5616868

    def setUp(self):
        self.assertIsNotNone(tool, 'source-gated package-cache code reader is not implemented')
        self.reads = []
        code = bytearray(1024)
        for site, target, expected in tool.CALL_EDGES:
            offset = site - tool.SOURCE_RVA
            code[offset:offset + 5] = expected
        self.memory = {(tool.SOURCE_RVA, 1024): bytes(code),
                       (tool.DELIMITER_SLOT_RVA, 8): struct.pack('<Q', 0x250000000)}
        for target in tool.TARGETS.values():
            self.memory[(target, 1024)] = bytes(1024)

    def read(self, address, size):
        key = (address - self.BASE, size)
        self.reads.append(key)
        return self.memory[key]

    def capture(self, **overrides):
        options = dict(source_capture_digest=tool.SOURCE_CAPTURE_SHA,
                       actual_created=self.CREATED, expected_created=self.CREATED)
        options.update(overrides)
        return tool.capture(self.read, self.BASE, self.SIZE, **options)

    def test_success_exact_code_scope_and_unfollowed_slot(self):
        report = self.capture()
        self.assertEqual(set(self.reads), tool.allowed_spans())
        self.assertEqual(self.reads[0], (tool.SOURCE_RVA, 1024))
        self.assertEqual(len(self.reads), 4)
        self.assertEqual(report['captured_bytes'], 3080)
        self.assertEqual(set(report['fixed_code']), set(tool.TARGETS))
        self.assertEqual(report['delimiter_slot']['bytes'], '0000005002000000')
        self.assertFalse(report['heap_read'])
        self.assertFalse(report['native_called'])
        self.assertFalse(report['cache_schema_verified'])
        self.assertTrue(all(size <= 1024 for _, size in self.reads))

    def test_both_fresh_calls_gate_all_extra_reads(self):
        extras = tool.allowed_spans() - {(tool.SOURCE_RVA, 1024)}
        for site, _, _ in tool.CALL_EDGES:
            for byte in (0, 1, 4):
                with self.subTest(site=site, byte=byte):
                    self.reads.clear()
                    original = self.memory[(tool.SOURCE_RVA, 1024)]
                    changed = bytearray(original)
                    changed[site - tool.SOURCE_RVA + byte] ^= 1
                    self.memory[(tool.SOURCE_RVA, 1024)] = bytes(changed)
                    with self.assertRaisesRegex(ValueError, 'fresh_package_cache_call_changed'):
                        self.capture()
                    self.assertTrue(extras.isdisjoint(self.reads))
                    self.memory[(tool.SOURCE_RVA, 1024)] = original

    def test_prior_digest_and_creation_fail_before_any_read(self):
        for overrides in (dict(source_capture_digest=None), dict(source_capture_digest='0' * 64),
                          dict(actual_created=self.CREATED + 1), dict(expected_created=float('nan'))):
            with self.subTest(overrides=overrides):
                self.reads.clear()
                with self.assertRaises(ValueError):
                    self.capture(**overrides)
                self.assertEqual(self.reads, [])

    def test_all_ranges_checked_before_first_read(self):
        for size in (0, tool.DELIMITER_SLOT_RVA + 7, tool.TARGETS['PathSplit'] + 100):
            with self.subTest(size=size):
                self.reads.clear()
                with self.assertRaisesRegex(ValueError, 'fixed_package_cache_ranges_outside_module'):
                    tool.capture(self.read, self.BASE, size,
                                 source_capture_digest=tool.SOURCE_CAPTURE_SHA,
                                 actual_created=self.CREATED, expected_created=self.CREATED)
                self.assertEqual(self.reads, [])

    def test_short_source_stops_before_targets_and_slot(self):
        self.memory[(tool.SOURCE_RVA, 1024)] = self.memory[(tool.SOURCE_RVA, 1024)][:-1]
        with self.assertRaisesRegex(ValueError, 'short_package_cache_code_read'):
            self.capture()
        self.assertEqual(self.reads, [(tool.SOURCE_RVA, 1024)])

    def test_short_target_or_slot_rejected(self):
        for key in tool.allowed_spans() - {(tool.SOURCE_RVA, 1024)}:
            with self.subTest(key=key):
                original = self.memory[key]
                self.memory[key] = original[:-1]
                with self.assertRaisesRegex(ValueError, 'short_package_cache_code_read'):
                    self.capture()
                self.memory[key] = original

    def source_report(self):
        code = self.memory[(tool.SOURCE_RVA, 1024)]
        return {'native_pe_sha256': tool.SOURCE_PE, 'package_brush': {'PackagePathPredicate': {
            'rva': tool.SOURCE_RVA, 'size': 1024, 'bytes': code.hex(),
            'sha256': hashlib.sha256(code).hexdigest()}}}

    def load_synthetic(self, report):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'source.json'
            raw = json.dumps(report).encode()
            path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            with patch.object(tool, 'SOURCE_CAPTURE_SHA', digest):
                return tool.load_source(path)

    def test_source_report_requires_digest_pe_span_and_calls(self):
        digest = self.load_synthetic(self.source_report())
        self.assertEqual(len(digest), 64)
        report = self.source_report()
        report['native_pe_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'source_package_cache_PE_changed'):
            self.load_synthetic(report)
        report = self.source_report()
        report['package_brush']['PackagePathPredicate']['rva'] += 1
        with self.assertRaisesRegex(ValueError, 'source_package_cache_span_changed'):
            self.load_synthetic(report)
        report = self.source_report()
        report['package_brush']['PackagePathPredicate']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'source_package_cache_span_changed'):
            self.load_synthetic(report)
        report = self.source_report()
        code = bytearray(self.memory[(tool.SOURCE_RVA, 1024)])
        code[tool.CALL_EDGES[0][0] - tool.SOURCE_RVA] = 0xe9
        report['package_brush']['PackagePathPredicate'].update(
            bytes=code.hex(), sha256=hashlib.sha256(code).hexdigest())
        with self.assertRaisesRegex(ValueError, 'fresh_package_cache_call_changed'):
            self.load_synthetic(report)

    def test_source_missing_oversized_or_unpinned_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'source.json'
            with self.assertRaisesRegex(ValueError, 'existing_bounded_package_cache_source_required'):
                tool.load_source(path)
            path.write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError, 'package_cache_source_full_sha256_changed'):
                tool.load_source(path)
            path.write_bytes(bytes(65537))
            with self.assertRaisesRegex(ValueError, 'existing_bounded_package_cache_source_required'):
                tool.load_source(path)


class ChildMapFollowupTests(unittest.TestCase):
    BASE = PackagePathCacheScopeTests.BASE
    SIZE = PackagePathCacheScopeTests.SIZE
    CREATED = PackagePathCacheScopeTests.CREATED
    SOURCE_RVA = 0x10ecd9a0
    TARGET_RVA = 0xdb7b30
    CALL_SITE = 0x10ecd9cd
    CALL_BYTES = bytes.fromhex('e85ea1eeef')

    def setUp(self):
        self.reads = []
        source = bytearray(1024)
        offset = self.CALL_SITE - self.SOURCE_RVA
        source[offset:offset + 5] = self.CALL_BYTES
        self.source = bytes(source)
        self.source_sha = hashlib.sha256(self.source).hexdigest()
        self.memory = {(self.SOURCE_RVA, 1024): self.source,
                       (self.TARGET_RVA, 1024): bytes(1024)}

    def read(self, address, size):
        key = (address - self.BASE, size)
        self.reads.append(key)
        return self.memory[key]

    def capture(self, **overrides):
        options = dict(source_capture_digest=tool.CHILD_CAPTURE_SHA,
                       actual_created=self.CREATED, expected_created=self.CREATED,
                       child_map_followup=True)
        options.update(overrides)
        with patch.object(tool, 'CHILD_SOURCE_SHA', self.source_sha):
            return tool.capture(self.read, self.BASE, self.SIZE, **options)

    def test_followup_has_only_fresh_lookup_and_one_direct_target(self):
        report = self.capture()
        self.assertEqual(self.reads, [(self.SOURCE_RVA, 1024), (self.TARGET_RVA, 1024)])
        self.assertEqual(set(self.reads), tool.allowed_spans(child_map_followup=True))
        self.assertEqual(report['captured_bytes'], 2048)
        self.assertEqual(set(report['fixed_code']), {'CacheChildMapFind'})
        self.assertNotIn('delimiter_slot', report)
        self.assertTrue(report['child_map_followup'])
        for name in ('heap_read', 'native_called', 'pointer_followed', 'cache_schema_verified'):
            self.assertFalse(report[name])

    def test_changed_fresh_call_refuses_target(self):
        for offset in (0, 1, 4):
            with self.subTest(offset=offset):
                changed = bytearray(self.source)
                changed[self.CALL_SITE - self.SOURCE_RVA + offset] ^= 1
                self.memory[(self.SOURCE_RVA, 1024)] = bytes(changed)
                self.reads.clear()
                with self.assertRaisesRegex(ValueError, 'fresh_child_map_call_changed'):
                    self.capture()
                self.assertEqual(self.reads, [(self.SOURCE_RVA, 1024)])

    def test_changed_fresh_span_refuses_target_even_with_valid_call(self):
        changed = bytearray(self.source)
        changed[200] ^= 1
        self.memory[(self.SOURCE_RVA, 1024)] = bytes(changed)
        with self.assertRaisesRegex(ValueError, 'fresh_child_map_source_span_changed'):
            self.capture()
        self.assertEqual(self.reads, [(self.SOURCE_RVA, 1024)])

    def test_unpinned_source_and_creation_refused_before_reads(self):
        for options in (dict(source_capture_digest=tool.SOURCE_CAPTURE_SHA),
                        dict(source_capture_digest='0' * 64),
                        dict(actual_created=self.CREATED + 1)):
            with self.subTest(options=options):
                self.reads.clear()
                with self.assertRaises(ValueError):
                    self.capture(**options)
                self.assertEqual(self.reads, [])

    def test_followup_ranges_preflight_and_short_reads(self):
        for size in (self.SOURCE_RVA + 1023, self.TARGET_RVA + 1023):
            with self.subTest(size=size):
                with self.assertRaisesRegex(ValueError, 'fixed_package_cache_ranges_outside_module'):
                    tool.capture(self.read, self.BASE, size,
                                 source_capture_digest=tool.CHILD_CAPTURE_SHA,
                                 actual_created=self.CREATED, expected_created=self.CREATED,
                                 child_map_followup=True)
                self.assertEqual(self.reads, [])
        for key in tuple(self.memory):
            original = self.memory[key]
            self.memory[key] = original[:-1]
            with self.assertRaisesRegex(ValueError, 'short_package_cache_code_read'):
                self.capture()
            self.memory[key] = original

    def source_report(self):
        return {'native_pe_sha256': tool.SOURCE_PE,
                'source_capture_sha256': tool.SOURCE_CAPTURE_SHA,
                'fixed_code': {'CacheChildLookup': {
                    'rva': self.SOURCE_RVA, 'size': 1024, 'bytes': self.source.hex(),
                    'sha256': self.source_sha}}}

    def load_synthetic(self, report):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'source.json'
            raw = json.dumps(report).encode()
            path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            with patch.object(tool, 'CHILD_CAPTURE_SHA', digest), \
                    patch.object(tool, 'CHILD_SOURCE_SHA', self.source_sha):
                return tool.load_source(path, child_map_followup=True)

    def test_source_requires_full_digest_original_chain_and_pinned_lookup_span(self):
        self.assertEqual(len(self.load_synthetic(self.source_report())), 64)
        for name, value, error in (
                ('native_pe_sha256', '0' * 64, 'source_package_cache_PE_changed'),
                ('source_capture_sha256', '0' * 64, 'child_map_source_chain_changed')):
            report = self.source_report()
            report[name] = value
            with self.assertRaisesRegex(ValueError, error):
                self.load_synthetic(report)
        for name, value in (('rva', self.SOURCE_RVA + 1), ('size', 1023), ('sha256', '0' * 64)):
            report = self.source_report()
            report['fixed_code']['CacheChildLookup'][name] = value
            with self.assertRaisesRegex(ValueError, 'source_package_cache_span_changed'):
                self.load_synthetic(report)
        report = self.source_report()
        changed = bytearray(self.source)
        changed[200] = 1
        report['fixed_code']['CacheChildLookup'].update(
            bytes=changed.hex(), sha256=hashlib.sha256(changed).hexdigest())
        with self.assertRaisesRegex(ValueError, 'child_map_source_lookup_sha256_changed'):
            self.load_synthetic(report)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'source.json'
            path.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'package_cache_source_full_sha256_changed'):
                tool.load_source(path, child_map_followup=True)


class CompareFollowupTests(unittest.TestCase):
    BASE = PackagePathCacheScopeTests.BASE
    SIZE = PackagePathCacheScopeTests.SIZE
    CREATED = PackagePathCacheScopeTests.CREATED
    SOURCE_RVA = 0xdb7b30
    TARGET_RVA = 0x10a137d0
    CALL_SITE = 0xdb7c0e
    CALL_BYTES = bytes.fromhex('e8bdbbc50f')

    def setUp(self):
        self.reads = []
        source = bytearray(1024)
        source[self.CALL_SITE - self.SOURCE_RVA:self.CALL_SITE - self.SOURCE_RVA + 5] = self.CALL_BYTES
        self.source = bytes(source)
        self.source_sha = hashlib.sha256(self.source).hexdigest()
        self.memory = {(self.SOURCE_RVA, 1024): self.source,
                       (self.TARGET_RVA, 1024): bytes(1024)}

    def read(self, address, size):
        key = (address - self.BASE, size)
        self.reads.append(key)
        return self.memory[key]

    def capture(self, **overrides):
        options = dict(source_capture_digest=tool.COMPARE_CAPTURE_SHA,
                       actual_created=self.CREATED, expected_created=self.CREATED,
                       compare_followup=True)
        options.update(overrides)
        with patch.object(tool, 'COMPARE_SOURCE_SHA', self.source_sha):
            return tool.capture(self.read, self.BASE, self.SIZE, **options)

    def test_only_fresh_map_find_and_fixed_comparator_are_read(self):
        report = self.capture()
        self.assertEqual(self.reads, [(self.SOURCE_RVA, 1024), (self.TARGET_RVA, 1024)])
        self.assertEqual(set(self.reads), tool.allowed_spans(compare_followup=True))
        self.assertEqual(report['captured_bytes'], 2048)
        self.assertEqual(set(report['fixed_code']), {'CacheFStringCompare'})
        self.assertNotIn('delimiter_slot', report)
        self.assertTrue(report['compare_followup'])
        for name in ('heap_read', 'native_called', 'pointer_followed', 'cache_schema_verified'):
            self.assertFalse(report[name])

    def test_changed_fresh_call_refuses_compare_read(self):
        for offset in (0, 1, 4):
            with self.subTest(offset=offset):
                changed = bytearray(self.source)
                changed[self.CALL_SITE - self.SOURCE_RVA + offset] ^= 1
                self.memory[(self.SOURCE_RVA, 1024)] = bytes(changed)
                self.reads.clear()
                with self.assertRaisesRegex(ValueError, 'fresh_cache_compare_call_changed'):
                    self.capture()
                self.assertEqual(self.reads, [(self.SOURCE_RVA, 1024)])

    def test_changed_fresh_span_with_valid_call_refuses_compare_read(self):
        changed = bytearray(self.source)
        changed[400] ^= 1
        self.memory[(self.SOURCE_RVA, 1024)] = bytes(changed)
        with self.assertRaisesRegex(ValueError, 'fresh_cache_compare_source_span_changed'):
            self.capture()
        self.assertEqual(self.reads, [(self.SOURCE_RVA, 1024)])

    def test_prior_digest_creation_and_combined_modes_fail_before_reads(self):
        for options in (dict(source_capture_digest=tool.CHILD_CAPTURE_SHA),
                        dict(source_capture_digest='0' * 64),
                        dict(actual_created=self.CREATED + 1),
                        dict(expected_created=float('nan')),
                        dict(child_map_followup=True)):
            with self.subTest(options=options):
                self.reads.clear()
                with self.assertRaises(ValueError):
                    self.capture(**options)
                self.assertEqual(self.reads, [])

    def test_ranges_and_exact_lengths_are_required(self):
        for size in (self.SOURCE_RVA + 1023, self.TARGET_RVA + 1023):
            with self.subTest(size=size):
                with self.assertRaisesRegex(ValueError, 'fixed_package_cache_ranges_outside_module'):
                    tool.capture(self.read, self.BASE, size,
                                 source_capture_digest=tool.COMPARE_CAPTURE_SHA,
                                 actual_created=self.CREATED, expected_created=self.CREATED,
                                 compare_followup=True)
                self.assertEqual(self.reads, [])
        for key in tuple(self.memory):
            original = self.memory[key]
            self.memory[key] = original[:-1]
            with self.assertRaisesRegex(ValueError, 'short_package_cache_code_read'):
                self.capture()
            self.memory[key] = original

    def source_report(self):
        return {'native_pe_sha256': tool.SOURCE_PE,
                'source_capture_sha256': tool.CHILD_CAPTURE_SHA,
                'fixed_code': {'CacheChildMapFind': {
                    'rva': self.SOURCE_RVA, 'size': 1024, 'bytes': self.source.hex(),
                    'sha256': self.source_sha}}}

    def load_synthetic(self, report, *, pinned_source_sha=None):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'source.json'
            raw = json.dumps(report).encode()
            path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            with patch.object(tool, 'COMPARE_CAPTURE_SHA', digest), \
                    patch.object(tool, 'COMPARE_SOURCE_SHA', pinned_source_sha or self.source_sha):
                return tool.load_source(path, compare_followup=True)

    def test_saved_source_requires_full_digest_chain_and_pinned_map_span(self):
        self.assertEqual(len(self.load_synthetic(self.source_report())), 64)
        for name, value, error in (
                ('native_pe_sha256', '0' * 64, 'source_package_cache_PE_changed'),
                ('source_capture_sha256', '0' * 64, 'cache_compare_source_chain_changed')):
            report = self.source_report()
            report[name] = value
            with self.assertRaisesRegex(ValueError, error):
                self.load_synthetic(report)
        for name, value in (('rva', self.SOURCE_RVA + 1), ('size', 1023), ('sha256', '0' * 64)):
            report = self.source_report()
            report['fixed_code']['CacheChildMapFind'][name] = value
            with self.assertRaisesRegex(ValueError, 'source_package_cache_span_changed'):
                self.load_synthetic(report)
        report = self.source_report()
        changed = bytearray(self.source)
        changed[400] = 1
        report['fixed_code']['CacheChildMapFind'].update(
            bytes=changed.hex(), sha256=hashlib.sha256(changed).hexdigest())
        with self.assertRaisesRegex(ValueError, 'cache_compare_source_map_sha256_changed'):
            self.load_synthetic(report)
        report = self.source_report()
        changed = bytearray(self.source)
        changed[self.CALL_SITE - self.SOURCE_RVA] = 0xe9
        report['fixed_code']['CacheChildMapFind'].update(
            bytes=changed.hex(), sha256=hashlib.sha256(changed).hexdigest())
        with self.assertRaisesRegex(ValueError, 'fresh_cache_compare_call_changed'):
            self.load_synthetic(report, pinned_source_sha=hashlib.sha256(changed).hexdigest())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'source.json'
            path.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'package_cache_source_full_sha256_changed'):
                tool.load_source(path, compare_followup=True)


class FilenameTransformFollowupTests(unittest.TestCase):
    BASE = PackagePathCacheScopeTests.BASE
    SIZE = PackagePathCacheScopeTests.SIZE
    CREATED = PackagePathCacheScopeTests.CREATED

    def setUp(self):
        self.reads = []
        source = bytearray(1024)
        for site, target, witness in tool.FILENAME_CALL_EDGES:
            source[site - tool.SOURCE_RVA:site - tool.SOURCE_RVA + 5] = witness
        site, target, witness = tool.FILENAME_STATIC_EDGE
        source[site - tool.SOURCE_RVA:site - tool.SOURCE_RVA + 7] = witness
        self.source = bytes(source)
        self.source_sha = hashlib.sha256(self.source).hexdigest()
        self.memory = {(tool.SOURCE_RVA, 1024): self.source,
                       (tool.FILENAME_TARGET_RVA, tool.FILENAME_TARGET_SIZE): bytes(tool.FILENAME_TARGET_SIZE),
                       (tool.FILENAME_STATIC_RVA, 16): bytes(16)}

    def read(self, address, size):
        key = (address - self.BASE, size)
        self.reads.append(key)
        return self.memory[key]

    def capture(self, **overrides):
        options = dict(source_capture_digest=tool.SOURCE_CAPTURE_SHA,
                       actual_created=self.CREATED, expected_created=self.CREATED,
                       filename_transform_followup=True)
        options.update(overrides)
        with patch.object(tool, 'FILENAME_SOURCE_SHA', self.source_sha):
            return tool.capture(self.read, self.BASE, self.SIZE, **options)

    def test_only_130byte_extent_and_unfollowed_static_header(self):
        report = self.capture()
        self.assertEqual(self.reads, [(tool.SOURCE_RVA, 1024),
                                     (tool.FILENAME_TARGET_RVA, 130),
                                     (tool.FILENAME_STATIC_RVA, 16)])
        self.assertEqual(set(self.reads), tool.allowed_spans(filename_transform_followup=True))
        self.assertEqual(report['captured_bytes'], 1170)
        self.assertEqual(set(report['fixed_code']), {'PackageFilenameTransform'})
        self.assertEqual(report['static_extension_header']['size'], 16)
        for key in ('heap_read', 'native_called', 'pointer_followed', 'static_header_type_proven'):
            self.assertFalse(report[key])
        self.assertTrue(report['filename_transform_followup'])
        self.assertNotIn('delimiter_slot', report)

    def test_both_calls_and_static_LEA_gate_every_extra_read(self):
        edges = [(site, witness) for site, _, witness in tool.FILENAME_CALL_EDGES]
        edges.append((tool.FILENAME_STATIC_EDGE[0], tool.FILENAME_STATIC_EDGE[2]))
        for site, witness in edges:
            for byte in (0, len(witness) - 1):
                with self.subTest(site=site, byte=byte):
                    changed = bytearray(self.source)
                    changed[site - tool.SOURCE_RVA + byte] ^= 1
                    self.memory[(tool.SOURCE_RVA, 1024)] = bytes(changed)
                    self.reads.clear()
                    with self.assertRaisesRegex(ValueError, 'fresh_package_filename_'):
                        self.capture()
                    self.assertEqual(self.reads, [(tool.SOURCE_RVA, 1024)])
        self.memory[(tool.SOURCE_RVA, 1024)] = self.source

    def test_full_fresh_span_pin_gates_extra_reads(self):
        changed = bytearray(self.source)
        changed[700] = 1
        self.memory[(tool.SOURCE_RVA, 1024)] = bytes(changed)
        with self.assertRaisesRegex(ValueError, 'fresh_package_filename_source_span_changed'):
            self.capture()
        self.assertEqual(self.reads, [(tool.SOURCE_RVA, 1024)])

    def test_creation_digest_scope_and_combined_modes_fail_before_read(self):
        for options in (dict(source_capture_digest='0' * 64),
                        dict(actual_created=self.CREATED + 1),
                        dict(child_map_followup=True), dict(compare_followup=True)):
            with self.subTest(options=options):
                self.reads.clear()
                with self.assertRaises(ValueError):
                    self.capture(**options)
                self.assertEqual(self.reads, [])
        for size in (tool.SOURCE_RVA + 1023, tool.FILENAME_TARGET_RVA + 129,
                     tool.FILENAME_STATIC_RVA + 15):
            self.reads.clear()
            with self.assertRaisesRegex(ValueError, 'fixed_package_cache_ranges_outside_module'):
                tool.capture(self.read, self.BASE, size, source_capture_digest=tool.SOURCE_CAPTURE_SHA,
                             actual_created=self.CREATED, expected_created=self.CREATED,
                             filename_transform_followup=True)
            self.assertEqual(self.reads, [])

    def test_all_exact_sizes_are_required(self):
        for key in self.memory:
            with self.subTest(key=key):
                original = self.memory[key]
                self.memory[key] = original[:-1]
                with self.assertRaisesRegex(ValueError, 'short_package_cache_code_read'):
                    self.capture()
                self.memory[key] = original

    def test_static_source_function_extent_metadata_is_exact(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'metadata.bin'
            raw = bytes.fromhex(tool.FILENAME_PDATA_HEX + tool.FILENAME_UNWIND_HEX)
            path.write_bytes(raw)
            with patch.object(tool, 'FILENAME_PDATA_OFFSET', 0), \
                    patch.object(tool, 'FILENAME_UNWIND_OFFSET', 12):
                self.assertEqual(tool.verify_filename_extent(path)['bytes'], 130)
                for offset in (0, 11, 12, 23):
                    changed = bytearray(raw)
                    changed[offset] ^= 1
                    path.write_bytes(changed)
                    with self.assertRaisesRegex(ValueError, 'package_filename_source_extent_changed'):
                        tool.verify_filename_extent(path)
                path.write_bytes(raw[:-1])
                with self.assertRaisesRegex(ValueError, 'package_filename_source_extent_changed'):
                    tool.verify_filename_extent(path)

    def test_saved_source_full_hash_and_span_qualify_filename_edges(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'source.json'
            block = {'rva': tool.SOURCE_RVA, 'size': 1024, 'bytes': self.source.hex(),
                     'sha256': self.source_sha}
            raw = json.dumps({'native_pe_sha256': tool.SOURCE_PE,
                              'package_brush': {'PackagePathPredicate': block}}).encode()
            path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            with patch.object(tool, 'SOURCE_CAPTURE_SHA', digest), \
                    patch.object(tool, 'FILENAME_SOURCE_SHA', self.source_sha):
                self.assertEqual(tool.load_source(path, filename_transform_followup=True), digest)
                with self.assertRaisesRegex(ValueError, 'followup_modes_are_exclusive'):
                    tool.load_source(path, filename_transform_followup=True, compare_followup=True)


class FilenameRootsFollowupTests(unittest.TestCase):
    BASE = PackagePathCacheScopeTests.BASE
    SIZE = PackagePathCacheScopeTests.SIZE
    CREATED = PackagePathCacheScopeTests.CREATED

    def setUp(self):
        self.reads = []
        caller = bytearray(1024)
        for site, target, witness in tool.FILENAME_CALL_EDGES:
            caller[site - tool.SOURCE_RVA:site - tool.SOURCE_RVA + 5] = witness
        site, target, witness = tool.FILENAME_STATIC_EDGE
        caller[site - tool.SOURCE_RVA:site - tool.SOURCE_RVA + 7] = witness
        wrapper = bytearray(130)
        at = tool.ROOTS_CALL_SITE - tool.FILENAME_TARGET_RVA
        wrapper[at:at + 5] = tool.ROOTS_CALL_BYTES
        self.caller, self.wrapper = bytes(caller), bytes(wrapper)
        self.caller_sha = hashlib.sha256(self.caller).hexdigest()
        self.wrapper_sha = hashlib.sha256(self.wrapper).hexdigest()
        self.memory = {(tool.SOURCE_RVA, 1024): self.caller,
                       (tool.FILENAME_TARGET_RVA, 130): self.wrapper,
                       (tool.FILENAME_STATIC_RVA, 16): bytes(16)}
        self.memory.update({span: bytes([index + 1]) * span[1]
                            for index, span in enumerate(tool.ROOTS_CHUNKS)})

    def read(self, address, size):
        key = (address - self.BASE, size)
        self.reads.append(key)
        return self.memory[key]

    def capture(self, **overrides):
        options = dict(source_capture_digest=tool.ROOTS_CAPTURE_SHA,
                       actual_created=self.CREATED, expected_created=self.CREATED,
                       filename_roots_followup=True)
        options.update(overrides)
        with patch.object(tool, 'FILENAME_SOURCE_SHA', self.caller_sha), \
                patch.object(tool, 'ROOTS_SOURCE_SHA', self.wrapper_sha):
            return tool.capture(self.read, self.BASE, self.SIZE, **options)

    def test_exact_3823byte_scope_and_concatenated_helper_accounting(self):
        report = self.capture()
        self.assertEqual(self.reads, [(tool.SOURCE_RVA, 1024), (tool.FILENAME_TARGET_RVA, 130),
                                     *tool.ROOTS_CHUNKS, (tool.FILENAME_STATIC_RVA, 16)])
        self.assertEqual(set(self.reads), tool.allowed_spans(filename_roots_followup=True))
        self.assertEqual(report['captured_bytes'], 3823)
        helper = report['fixed_code']['PackageFilenameRoots']
        raw = b''.join(self.memory[span] for span in tool.ROOTS_CHUNKS)
        self.assertEqual((helper['rva'], helper['size'], bytes.fromhex(helper['bytes'])),
                         (tool.ROOTS_TARGET_RVA, 2653, raw))
        self.assertEqual(helper['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(sum(chunk['size'] for chunk in helper['chunk_spans']), 2653)
        self.assertTrue(all(size <= 1024 for rva, size in self.reads))
        for key in ('heap_read', 'native_called', 'pointer_followed', 'static_header_type_proven'):
            self.assertFalse(report[key])

    def test_caller_wrapper_edges_and_full_hashes_gate_helper_and_static(self):
        for key, offset in (((tool.SOURCE_RVA, 1024), 700),
                            ((tool.SOURCE_RVA, 1024), tool.FILENAME_STATIC_EDGE[0] - tool.SOURCE_RVA),
                            ((tool.FILENAME_TARGET_RVA, 130), 100),
                            ((tool.FILENAME_TARGET_RVA, 130),
                             tool.ROOTS_CALL_SITE - tool.FILENAME_TARGET_RVA)):
            with self.subTest(key=key, offset=offset):
                original = self.memory[key]
                changed = bytearray(original)
                changed[offset] ^= 1
                self.memory[key] = bytes(changed)
                self.reads.clear()
                with self.assertRaises(ValueError):
                    self.capture()
                self.assertTrue(set(tool.ROOTS_CHUNKS).isdisjoint(self.reads))
                self.assertNotIn((tool.FILENAME_STATIC_RVA, 16), self.reads)
                self.memory[key] = original

    def test_bad_digest_identity_mode_or_range_fail_before_read(self):
        for options in (dict(source_capture_digest=tool.SOURCE_CAPTURE_SHA),
                        dict(actual_created=self.CREATED + 1), dict(compare_followup=True),
                        dict(child_map_followup=True), dict(filename_transform_followup=True)):
            self.reads.clear()
            with self.assertRaises(ValueError):
                self.capture(**options)
            self.assertEqual(self.reads, [])
        for rva, size in tool.allowed_spans(filename_roots_followup=True):
            self.reads.clear()
            with self.assertRaisesRegex(ValueError, 'fixed_package_cache_ranges_outside_module'):
                tool.capture(self.read, self.BASE, rva + size - 1,
                             source_capture_digest=tool.ROOTS_CAPTURE_SHA,
                             actual_created=self.CREATED, expected_created=self.CREATED,
                             filename_roots_followup=True)
            self.assertEqual(self.reads, [])

    def test_each_short_fixed_read_stops_without_partial_report(self):
        for key in self.memory:
            with self.subTest(key=key):
                original = self.memory[key]
                self.memory[key] = original[:-1]
                with self.assertRaisesRegex(ValueError, 'short_package_cache_code_read'):
                    self.capture()
                self.memory[key] = original

    def test_exact_roots_pdata_and_28byte_unwind_source_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'metadata.bin'
            raw = bytes.fromhex(tool.ROOTS_PDATA_HEX + tool.ROOTS_UNWIND_HEX)
            path.write_bytes(raw)
            with patch.object(tool, 'ROOTS_PDATA_OFFSET', 0), \
                    patch.object(tool, 'ROOTS_UNWIND_OFFSET', 12):
                self.assertEqual(tool.verify_roots_extent(path)['bytes'], 2653)
                for offset in (0, 11, 12, 39):
                    changed = bytearray(raw)
                    changed[offset] ^= 1
                    path.write_bytes(changed)
                    with self.assertRaisesRegex(ValueError, 'roots_source_extent_changed'):
                        tool.verify_roots_extent(path)
                path.write_bytes(raw[:-1])
                with self.assertRaisesRegex(ValueError, 'roots_source_extent_changed'):
                    tool.verify_roots_extent(path)

    def test_saved_source_full_report_chain_and_both_code_spans(self):
        block = lambda rva, data: dict(rva=rva, size=len(data), bytes=data.hex(),
                                      sha256=hashlib.sha256(data).hexdigest())
        source = dict(native_pe_sha256=tool.SOURCE_PE, source_capture_sha256=tool.SOURCE_CAPTURE_SHA,
                      source_code=block(tool.SOURCE_RVA, self.caller),
                      fixed_code={'PackageFilenameTransform': block(tool.FILENAME_TARGET_RVA, self.wrapper)})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'source.json'
            for change in ('none', 'chain', 'wrapper', 'caller'):
                report = json.loads(json.dumps(source))
                if change == 'chain':
                    report['source_capture_sha256'] = '0' * 64
                elif change == 'wrapper':
                    report['fixed_code']['PackageFilenameTransform']['rva'] += 1
                elif change == 'caller':
                    report['source_code']['sha256'] = '0' * 64
                raw = json.dumps(report).encode()
                path.write_bytes(raw)
                with patch.object(tool, 'ROOTS_CAPTURE_SHA', hashlib.sha256(raw).hexdigest()), \
                        patch.object(tool, 'ROOTS_SOURCE_SHA', self.wrapper_sha), \
                        patch.object(tool, 'FILENAME_SOURCE_SHA', self.caller_sha):
                    if change == 'none':
                        self.assertEqual(len(tool.load_source(path, filename_roots_followup=True)), 64)
                    else:
                        with self.assertRaises(ValueError):
                            tool.load_source(path, filename_roots_followup=True)


class FilenameRootStateFollowupTests(unittest.TestCase):
    BASE = PackagePathCacheScopeTests.BASE
    SIZE = PackagePathCacheScopeTests.SIZE
    CREATED = PackagePathCacheScopeTests.CREATED

    def setUp(self):
        FilenameRootsFollowupTests.setUp(self)
        helper = bytearray([0x90] * tool.ROOTS_TARGET_SIZE)
        offset = tool.ROOT_STATE_CALL_SITE - tool.ROOTS_TARGET_RVA
        helper[offset:offset + 5] = tool.ROOT_STATE_CALL_BYTES
        self.helper = bytes(helper)
        self.helper_sha = hashlib.sha256(self.helper).hexdigest()
        for rva, size in tool.ROOTS_CHUNKS:
            offset = rva - tool.ROOTS_TARGET_RVA
            self.memory[(rva, size)] = self.helper[offset:offset + size]
        del self.memory[(tool.FILENAME_STATIC_RVA, 16)]
        self.getter_span = (tool.ROOT_STATE_TARGET_RVA, tool.ROOT_STATE_TARGET_SIZE)
        self.memory[self.getter_span] = bytes(123)

    def read(self, address, size):
        return FilenameRootsFollowupTests.read(self, address, size)

    def capture(self, **overrides):
        options = dict(source_capture_digest=tool.ROOT_STATE_CAPTURE_SHA,
                       actual_created=self.CREATED, expected_created=self.CREATED,
                       filename_root_state_followup=True)
        options.update(overrides)
        with patch.object(tool, 'FILENAME_SOURCE_SHA', self.caller_sha), \
                patch.object(tool, 'ROOTS_SOURCE_SHA', self.wrapper_sha), \
                patch.object(tool, 'ROOT_STATE_SOURCE_SHA', self.helper_sha):
            return tool.capture(self.read, self.BASE, self.SIZE, **options)

    def test_exact_3930byte_code_only_scope(self):
        report = self.capture()
        self.assertEqual(self.reads, [(tool.SOURCE_RVA, 1024), (tool.FILENAME_TARGET_RVA, 130),
                                     *tool.ROOTS_CHUNKS, self.getter_span])
        self.assertEqual(set(self.reads), tool.allowed_spans(filename_root_state_followup=True))
        self.assertEqual(report['captured_bytes'], 3930)
        self.assertTrue(report['fresh_roots_full_span_verified'])
        self.assertTrue(report['filename_root_state_followup'])
        self.assertNotIn('static_extension_header', report)
        for name in ('heap_read', 'native_called', 'pointer_followed', 'root_state_type_proven',
                     'actual_filename_proven', 'cache_schema_verified'):
            self.assertFalse(report[name])

    def test_getter_call_opcode_and_displacement_gate_getter(self):
        key = tool.ROOTS_CHUNKS[0]
        original = self.memory[key]
        for byte in (0, 1, 4):
            with self.subTest(byte=byte):
                changed = bytearray(original)
                changed[tool.ROOT_STATE_CALL_SITE - key[0] + byte] ^= 1
                self.memory[key] = bytes(changed)
                self.reads.clear()
                with self.assertRaisesRegex(ValueError, 'fresh_package_filename_root_state_call_changed'):
                    self.capture()
                self.assertNotIn(self.getter_span, self.reads)
        self.memory[key] = original

    def test_every_fresh_helper_chunk_full_hash_gates_getter(self):
        for key in tool.ROOTS_CHUNKS:
            with self.subTest(key=key):
                original = self.memory[key]
                changed = bytearray(original)
                changed[-1] ^= 1
                self.memory[key] = bytes(changed)
                self.reads.clear()
                with self.assertRaisesRegex(ValueError, 'fresh_package_filename_root_state_helper_span_changed'):
                    self.capture()
                self.assertNotIn(self.getter_span, self.reads)
                self.memory[key] = original

    def test_fresh_caller_and_wrapper_gate_complete_helper(self):
        for key, offset in (((tool.SOURCE_RVA, 1024), 700),
                            ((tool.FILENAME_TARGET_RVA, 130), 100),
                            ((tool.FILENAME_TARGET_RVA, 130),
                             tool.ROOTS_CALL_SITE - tool.FILENAME_TARGET_RVA)):
            with self.subTest(key=key, offset=offset):
                original = self.memory[key]
                changed = bytearray(original)
                changed[offset] ^= 1
                self.memory[key] = bytes(changed)
                self.reads.clear()
                with self.assertRaises(ValueError):
                    self.capture()
                self.assertTrue(set(tool.ROOTS_CHUNKS).isdisjoint(self.reads))
                self.assertNotIn(self.getter_span, self.reads)
                self.memory[key] = original

    def test_prior_digest_creation_and_all_other_modes_reject_before_read(self):
        for options in (dict(source_capture_digest=tool.ROOTS_CAPTURE_SHA),
                        dict(actual_created=self.CREATED + 1), dict(child_map_followup=True),
                        dict(compare_followup=True), dict(filename_roots_followup=True),
                        dict(filename_transform_followup=True)):
            self.reads.clear()
            with self.assertRaises(ValueError):
                self.capture(**options)
            self.assertEqual(self.reads, [])

    def test_all_ranges_preflight_before_first_read(self):
        for rva, size in tool.allowed_spans(filename_root_state_followup=True):
            self.reads.clear()
            with self.assertRaisesRegex(ValueError, 'fixed_package_cache_ranges_outside_module'):
                tool.capture(self.read, self.BASE, rva + size - 1,
                             source_capture_digest=tool.ROOT_STATE_CAPTURE_SHA,
                             actual_created=self.CREATED, expected_created=self.CREATED,
                             filename_root_state_followup=True)
            self.assertEqual(self.reads, [])

    def test_each_short_read_rejects_without_a_report(self):
        for key in self.memory:
            with self.subTest(key=key):
                original = self.memory[key]
                self.memory[key] = original[:-1]
                with self.assertRaisesRegex(ValueError, 'short_package_cache_code_read'):
                    self.capture()
                self.memory[key] = original

    def test_getter_extent_metadata_and_exact_sizes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'metadata.bin'
            raw = bytes.fromhex(tool.ROOT_STATE_PDATA_HEX + tool.ROOT_STATE_UNWIND_HEX)
            path.write_bytes(raw)
            with patch.object(tool, 'ROOT_STATE_PDATA_OFFSET', 0), \
                    patch.object(tool, 'ROOT_STATE_UNWIND_OFFSET', 12):
                self.assertEqual(tool.verify_root_state_extent(path)['bytes'], 123)
                for offset in (0, 11, 12, 19):
                    changed = bytearray(raw)
                    changed[offset] ^= 1
                    path.write_bytes(changed)
                    with self.assertRaisesRegex(ValueError, 'root_state_source_extent_changed'):
                        tool.verify_root_state_extent(path)
                path.write_bytes(raw[:-1])
                with self.assertRaisesRegex(ValueError, 'root_state_source_extent_changed'):
                    tool.verify_root_state_extent(path)

    def source_report(self):
        def block(rva, data):
            return dict(rva=rva, size=len(data), bytes=data.hex(),
                        sha256=hashlib.sha256(data).hexdigest())
        helper = block(tool.ROOTS_TARGET_RVA, self.helper)
        helper['chunk_spans'] = [dict(rva=rva, size=size,
                                    sha256=hashlib.sha256(self.memory[(rva, size)]).hexdigest())
                                 for rva, size in tool.ROOTS_CHUNKS]
        return dict(native_pe_sha256=tool.SOURCE_PE, source_capture_sha256=tool.ROOTS_CAPTURE_SHA,
                    source_code=block(tool.SOURCE_RVA, self.caller),
                    fixed_code={'PackageFilenameTransform': block(tool.FILENAME_TARGET_RVA, self.wrapper),
                                'PackageFilenameRoots': helper})

    def load_synthetic(self, report):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'source.json'
            raw = json.dumps(report).encode()
            path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            with patch.object(tool, 'ROOT_STATE_CAPTURE_SHA', digest), \
                    patch.object(tool, 'FILENAME_SOURCE_SHA', self.caller_sha), \
                    patch.object(tool, 'ROOTS_SOURCE_SHA', self.wrapper_sha), \
                    patch.object(tool, 'ROOT_STATE_SOURCE_SHA', self.helper_sha):
                return tool.load_source(path, filename_root_state_followup=True)

    def test_saved_full_report_chain_caller_wrapper_helper_and_chunks(self):
        self.assertEqual(len(self.load_synthetic(self.source_report())), 64)
        for change in ('pe', 'chain', 'caller', 'wrapper', 'helper', 'chunk_count', 'chunk_hash'):
            with self.subTest(change=change):
                report = self.source_report()
                if change == 'pe':
                    report['native_pe_sha256'] = '0' * 64
                elif change == 'chain':
                    report['source_capture_sha256'] = '0' * 64
                elif change == 'caller':
                    report['source_code']['sha256'] = '0' * 64
                elif change == 'wrapper':
                    report['fixed_code']['PackageFilenameTransform']['rva'] += 1
                elif change == 'helper':
                    report['fixed_code']['PackageFilenameRoots']['sha256'] = '0' * 64
                elif change == 'chunk_count':
                    report['fixed_code']['PackageFilenameRoots']['chunk_spans'].pop()
                else:
                    report['fixed_code']['PackageFilenameRoots']['chunk_spans'][1]['sha256'] = '0' * 64
                with self.assertRaises(ValueError):
                    self.load_synthetic(report)

    def test_unpinned_saved_report_full_hash_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'source.json'
            path.write_text(json.dumps(self.source_report()), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'package_cache_source_full_sha256_changed'):
                tool.load_source(path, filename_root_state_followup=True)


if __name__ == '__main__':
    unittest.main()
