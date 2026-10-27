import struct
import inspect
from pathlib import Path
import tempfile
import unittest

import probe_live_local_image_loader as probe


class LocalImageScopeTests(unittest.TestCase):
    BASE = 0x140000000
    SIZE = 0x20000000
    CREATED = 1791143400.125

    def fixture(self):
        spans = {}
        for name, (rva, row) in probe.REGISTRATIONS.items():
            spans[(rva, 48)] = struct.pack('<6Q', *(self.BASE + value for value in row[:5]), row[5])
            spans[(row[0], 32)] = name.encode('ascii').ljust(32, b'\0')
        for key in probe.CALLBACKS.values():
            spans[key] = bytes(key[1])
        rva, size = probe.CALLBACKS['background_callback_region']
        code = bytearray(probe.BACKGROUND_PREFIX.ljust(size, b'\0'))
        for site, target, expected in probe.IMPLEMENTATIONS.values():
            code[site - rva:site - rva + 5] = expected
            spans[(target, probe.IMPLEMENTATION_SIZE)] = bytes(probe.IMPLEMENTATION_SIZE)
        spans[(rva, size)] = bytes(code)
        owners = {'callbacks': probe.CALLBACKS,
                  'implementations': {name: (target, probe.IMPLEMENTATION_SIZE)
                                      for name, (_, target, _) in probe.IMPLEMENTATIONS.items()}}
        for group, owner, site, target, expected, _ in probe.ROUTE_EDGES:
            key = owners[group][owner]
            code = bytearray(spans[key])
            code[site - key[0]:site - key[0] + len(expected)] = expected
            spans[key] = bytes(code)
            spans[(target, probe.IMPLEMENTATION_SIZE)] = bytes(probe.IMPLEMENTATION_SIZE)
        return spans

    def run_capture(self, spans, *, base=None, size=None, actual=None, expected=None):
        reads = []
        def read(address, length):
            key = (address - self.BASE, length)
            reads.append(key)
            return spans[key]
        report = probe.capture(read, self.BASE if base is None else base,
                               self.SIZE if size is None else size,
                               self.CREATED if actual is None else actual,
                               self.CREATED if expected is None else expected)
        return report, reads

    def rejected_without_implementations(self, spans, pattern):
        reads = []
        def read(address, size):
            key = (address - self.BASE, size)
            reads.append(key)
            return spans[key]
        with self.assertRaisesRegex(ValueError, pattern):
            probe.capture(read, self.BASE, self.SIZE, self.CREATED, self.CREATED)
        targets = {(target, probe.IMPLEMENTATION_SIZE) for _, target, _ in probe.IMPLEMENTATIONS.values()}
        self.assertTrue(targets.isdisjoint(reads))
        return reads

    def test_success_has_exact_readset(self):
        report, reads = self.run_capture(self.fixture())
        self.assertEqual(report['captured_bytes'], 2608)
        self.assertEqual(set(reads), probe.allowed_spans())
        self.assertEqual(len(reads), 10)
        self.assertEqual(set(report['implementations']), set(probe.IMPLEMENTATIONS))

    def test_registration_failure_before_callbacks(self):
        for name, (rva, _) in probe.REGISTRATIONS.items():
            with self.subTest(name=name):
                spans = self.fixture()
                spans[(rva, 48)] = bytes(48)
                reads = self.rejected_without_implementations(spans, 'registration_mismatch')
                self.assertTrue(set(probe.CALLBACKS.values()).isdisjoint(reads))

    def test_name_failure_before_callbacks(self):
        for name, (_, row) in probe.REGISTRATIONS.items():
            with self.subTest(name=name):
                spans = self.fixture()
                spans[(row[0], 32)] = b'x' * 32
                reads = self.rejected_without_implementations(spans, 'name_mismatch')
                self.assertTrue(set(probe.CALLBACKS.values()).isdisjoint(reads))

    def test_each_jump_must_match_before_either_target(self):
        for name, (site, _, _) in probe.IMPLEMENTATIONS.items():
            with self.subTest(name=name):
                spans = self.fixture()
                key = probe.CALLBACKS['background_callback_region']
                code = bytearray(spans[key])
                code[site - key[0]] = 0xe8
                spans[key] = bytes(code)
                self.rejected_without_implementations(spans, 'direct_jump_changed')

    def test_wrong_jump_target_rejects(self):
        spans = self.fixture()
        key = probe.CALLBACKS['background_callback_region']
        site, target, _ = probe.IMPLEMENTATIONS['SetBackgroundImageForWaterfall']
        code = bytearray(spans[key])
        code[site - key[0]:site - key[0] + 5] = b'\xe9' + struct.pack('<i', target + 16 - site - 5)
        spans[key] = bytes(code)
        self.rejected_without_implementations(spans, 'direct_jump_changed')

    def test_wrong_callback_region_prefix_rejects(self):
        spans = self.fixture()
        key = probe.CALLBACKS['background_callback_region']
        spans[key] = b'\0' + spans[key][1:]
        self.rejected_without_implementations(spans, 'prefix_changed')

    def test_short_callback_rejects_without_targets(self):
        spans = self.fixture()
        key = probe.CALLBACKS['CheckPathValid_callback']
        spans[key] = spans[key][:-1]
        self.rejected_without_implementations(spans, 'short_local_image')

    def test_timestamp_and_module_bounds_fail_before_any_read(self):
        invalid = [(self.BASE, self.SIZE, self.CREATED + 1, self.CREATED),
                   (self.BASE, self.SIZE, self.CREATED, float('nan')),
                   (self.BASE, 0x63c43e0 + 100, self.CREATED, self.CREATED),
                   (0, self.SIZE, self.CREATED, self.CREATED),
                   ((1 << 64) - self.SIZE, self.SIZE, self.CREATED, self.CREATED)]
        for base, size, actual, expected in invalid:
            with self.subTest(case=(base, size, actual, expected)):
                reads = []
                with self.assertRaises(ValueError):
                    probe.capture(lambda *args: reads.append(args), base, size, actual, expected)
                self.assertEqual(reads, [])

    def test_creation_precision_tolerance(self):
        probe.verify_creation(self.CREATED + 0.0001, self.CREATED)
        for invalid in (True, None, '1', float('inf'), -1):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                probe.verify_creation(invalid, self.CREATED)

    def test_output_is_new_project_evidence_outside_game_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            evidence, installed, shadow = root / 'work/evidence', root / 'game', root / 'shadow'
            evidence.mkdir(parents=True)
            valid = evidence / 'new.json'
            self.assertEqual(probe.output_path(valid, installed, shadow, evidence_root=evidence), valid)
            invalid = [root / 'outside.json', installed / 'report.json', shadow / 'report.json', evidence]
            for path in invalid:
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'output_must_be'):
                    probe.output_path(path, installed, shadow, evidence_root=evidence)
            valid.write_text('{}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'existing_evidence'):
                probe.output_path(valid, installed, shadow, evidence_root=evidence)

    def test_output_rejects_evidence_tree_inside_either_game(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            installed, shadow = root / 'game', root / 'shadow'
            for evidence in (installed / 'work/evidence', shadow / 'work/evidence'):
                with self.subTest(evidence=evidence), self.assertRaisesRegex(ValueError, 'output_must_be'):
                    probe.output_path(evidence / 'report.json', installed, shadow, evidence_root=evidence)

    def route_capture(self, spans, *, size=None, digest=probe.ROUTE_SOURCE_SHA, pe=probe.source.EXPECTED_PE):
        reads = []
        def read(address, length):
            key = (address - self.BASE, length)
            reads.append(key)
            return spans[key]
        report = probe.capture(read, self.BASE, self.SIZE if size is None else size,
                               self.CREATED, self.CREATED, local_route=True,
                               route_source_digest=digest, route_source_pe=pe)
        return report, reads

    def test_route_success_is_exact_three_extra_ranges(self):
        report, reads = self.route_capture(self.fixture())
        self.assertEqual(report['captured_bytes'], 5680)
        self.assertEqual(set(reads), probe.allowed_spans(True))
        self.assertEqual(len(reads), 13)
        self.assertEqual(set(report['local_route']), set(probe.ROUTE_TARGETS))

    def test_route_each_changed_source_displacement_blocks_all_extras(self):
        owners = {'callbacks': probe.CALLBACKS,
                  'implementations': {name: (target, probe.IMPLEMENTATION_SIZE)
                                      for name, (_, target, _) in probe.IMPLEMENTATIONS.items()}}
        extras = {(target, probe.IMPLEMENTATION_SIZE) for target in probe.ROUTE_TARGETS.values()}
        for group, owner, site, _, _, displacement in probe.ROUTE_EDGES:
            with self.subTest(owner=owner, site=site):
                spans, reads = self.fixture(), []
                key = owners[group][owner]
                code = bytearray(spans[key])
                code[site - key[0] + displacement] ^= 1
                spans[key] = bytes(code)
                def read(address, length):
                    selected = (address - self.BASE, length)
                    reads.append(selected)
                    return spans[selected]
                with self.assertRaisesRegex(ValueError, 'source_instruction_changed'):
                    probe.capture(read, self.BASE, self.SIZE, self.CREATED, self.CREATED,
                                  local_route=True, route_source_digest=probe.ROUTE_SOURCE_SHA,
                                  route_source_pe=probe.source.EXPECTED_PE)
                self.assertTrue(extras.isdisjoint(reads))

    def test_route_wrong_source_or_bounds_fail_before_reads(self):
        for digest, pe, size in [('x' * 64, probe.source.EXPECTED_PE, self.SIZE),
                                 (probe.ROUTE_SOURCE_SHA, 'x' * 64, self.SIZE),
                                 (probe.ROUTE_SOURCE_SHA, probe.source.EXPECTED_PE, 0x122abd90 + 100)]:
            with self.subTest(digest=digest, pe=pe, size=size):
                reads = []
                with self.assertRaises(ValueError):
                    probe.capture(lambda *args: reads.append(args), self.BASE, size,
                                  self.CREATED, self.CREATED, local_route=True,
                                  route_source_digest=digest, route_source_pe=pe)
                self.assertEqual(reads, [])

    def test_route_missing_or_mutated_prior_file_rejects(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'capture.json'
            with self.assertRaisesRegex(ValueError, 'existing_bounded_prior_capture'):
                probe.read_route_source(path)
            path.write_text('{}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'full_sha256_mismatch'):
                probe.read_route_source(path)

    def test_predicate_functor_option_is_explicit(self):
        self.assertIn('local_predicate_functor', inspect.signature(probe.capture).parameters)

    def predicate_fixture(self):
        spans = self.fixture()
        for owner, site, target, expected in [
                ('CheckPathValid', 0xd4c4a2c, 0xdac3d0, bytes.fromhex('e89f798ef3')),
                ('SharedLocalImageFunctor', 0x6382160, 0x63727f0, bytes.fromhex('e98b06ffff'))]:
            key = (probe.ROUTE_TARGETS[owner], probe.IMPLEMENTATION_SIZE)
            code = bytearray(spans[key])
            code[site - key[0]:site - key[0] + 5] = expected
            spans[key] = bytes(code)
            spans[(target, probe.IMPLEMENTATION_SIZE)] = bytes(probe.IMPLEMENTATION_SIZE)
        return spans

    def predicate_capture(self, spans, reads, *, route=True, digest=None, pe=None,
                          size=None, actual=None):
        def read(address, length):
            key = (address - self.BASE, length)
            reads.append(key)
            return spans[key]
        return probe.capture(
            read, self.BASE, self.SIZE if size is None else size,
            self.CREATED if actual is None else actual, self.CREATED,
            local_route=route, route_source_digest=probe.ROUTE_SOURCE_SHA,
            route_source_pe=probe.source.EXPECTED_PE, local_predicate_functor=True,
            predicate_source_digest=(probe.PREDICATE_FUNCTOR_SOURCE_SHA if digest is None else digest),
            predicate_source_pe=probe.source.EXPECTED_PE if pe is None else pe)

    def test_predicate_functor_exact_two_extra_reads_after_route(self):
        spans, reads = self.predicate_fixture(), []
        report = self.predicate_capture(spans, reads)
        self.assertEqual(report['captured_bytes'], 7728)
        self.assertEqual(len(reads), 15)
        self.assertEqual(set(reads), probe.allowed_spans(True, True))
        self.assertEqual(reads[-2:], [(0xdac3d0, 1024), (0x63727f0, 1024)])
        self.assertEqual(set(report['local_predicate_functor']), {'PathPredicate', 'LocalImageFunctorBody'})
        for value in report['local_predicate_functor'].values():
            self.assertTrue(value['all_source_edges_verified'])

    def test_predicate_functor_both_edges_gate_both_targets(self):
        extras = {(0xdac3d0, 1024), (0x63727f0, 1024)}
        for owner, site in [('CheckPathValid', 0xd4c4a2c), ('SharedLocalImageFunctor', 0x6382160)]:
            for byte in (0, 1, 4):
                with self.subTest(owner=owner, byte=byte):
                    spans, reads = self.predicate_fixture(), []
                    key = (probe.ROUTE_TARGETS[owner], 1024)
                    code = bytearray(spans[key])
                    code[site - key[0] + byte] ^= 1
                    spans[key] = bytes(code)
                    with self.assertRaisesRegex(ValueError, 'predicate_functor_source_instruction_changed'):
                        self.predicate_capture(spans, reads)
                    self.assertTrue(extras.isdisjoint(reads))

    def test_predicate_functor_requires_route_and_source_before_reads(self):
        for settings in [dict(route=False), dict(digest='x' * 64), dict(pe='x' * 64),
                         dict(size=0x122abd90 + 100), dict(actual=self.CREATED + 1)]:
            with self.subTest(settings=settings):
                reads = []
                with self.assertRaises(ValueError):
                    self.predicate_capture(self.predicate_fixture(), reads, **settings)
                self.assertEqual(reads, [])

    def test_predicate_functor_short_source_stops_before_extra_targets(self):
        spans, reads = self.predicate_fixture(), []
        key = (probe.ROUTE_TARGETS['SharedLocalImageFunctor'], 1024)
        spans[key] = spans[key][:-1]
        with self.assertRaisesRegex(ValueError, 'short_local_image'):
            self.predicate_capture(spans, reads)
        self.assertTrue({(0xdac3d0, 1024), (0x63727f0, 1024)}.isdisjoint(reads))

    def test_predicate_functor_prior_file_is_bounded_and_pinned(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'capture.json'
            with self.assertRaisesRegex(ValueError, 'existing_bounded_prior_capture'):
                probe.read_predicate_source(path)
            path.write_text('{}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'full_sha256_mismatch'):
                probe.read_predicate_source(path)
            path.write_bytes(bytes(65537))
            with self.assertRaisesRegex(ValueError, 'existing_bounded_prior_capture'):
                probe.read_predicate_source(path)

    def test_package_brush_option_is_explicit(self):
        self.assertIn('package_brush', inspect.signature(probe.capture).parameters)

    def package_fixture(self):
        spans = self.predicate_fixture()
        for rva, site, target, expected in [
                (0xdac3d0, 0xdac474, 0x10ecd110, bytes.fromhex('e8970c1210')),
                (0x63727f0, 0x6372983, 0x63c89a0, bytes.fromhex('e818600500'))]:
            key = (rva, 1024)
            code = bytearray(spans[key])
            code[site - rva:site - rva + 5] = expected
            spans[key] = bytes(code)
            spans[(target, 1024)] = bytes(1024)
        return spans

    def package_capture(self, spans, reads, *, predicate=True, digest=None,
                        pe=None, size=None, actual=None):
        def read(address, length):
            key = (address - self.BASE, length)
            reads.append(key)
            return spans[key]
        return probe.capture(
            read, self.BASE, self.SIZE if size is None else size,
            self.CREATED if actual is None else actual, self.CREATED,
            local_route=True, route_source_digest=probe.ROUTE_SOURCE_SHA,
            route_source_pe=probe.source.EXPECTED_PE, local_predicate_functor=predicate,
            predicate_source_digest=probe.PREDICATE_FUNCTOR_SOURCE_SHA,
            predicate_source_pe=probe.source.EXPECTED_PE, package_brush=True,
            package_brush_source_digest=(probe.PACKAGE_BRUSH_SOURCE_SHA if digest is None else digest),
            package_brush_source_pe=probe.source.EXPECTED_PE if pe is None else pe)

    def test_package_brush_exact_two_extra_reads_after_predecessors(self):
        spans, reads = self.package_fixture(), []
        report = self.package_capture(spans, reads)
        self.assertEqual(report['captured_bytes'], 9776)
        self.assertEqual(len(reads), 17)
        self.assertEqual(set(reads), probe.allowed_spans(True, True, True))
        self.assertEqual(reads[-2:], [(0x10ecd110, 1024), (0x63c89a0, 1024)])
        self.assertEqual(set(report['package_brush']), {'PackagePathPredicate', 'LocalImageBrushSetter'})
        self.assertTrue(all(value['all_source_edges_verified'] for value in report['package_brush'].values()))

    def test_package_brush_both_calls_gate_both_targets(self):
        extras = {(0x10ecd110, 1024), (0x63c89a0, 1024)}
        for rva, site in [(0xdac3d0, 0xdac474), (0x63727f0, 0x6372983)]:
            for byte in (0, 1, 4):
                with self.subTest(rva=rva, byte=byte):
                    spans, reads = self.package_fixture(), []
                    key = (rva, 1024)
                    code = bytearray(spans[key])
                    code[site - rva + byte] ^= 1
                    spans[key] = bytes(code)
                    with self.assertRaisesRegex(ValueError, 'package_brush_source_instruction_changed'):
                        self.package_capture(spans, reads)
                    self.assertTrue(extras.isdisjoint(reads))

    def test_package_brush_source_dependency_bounds_and_timestamp_before_reads(self):
        for settings in [dict(predicate=False), dict(digest='x' * 64),
                         dict(pe='x' * 64), dict(size=0x122abd90 + 100),
                         dict(actual=self.CREATED + 1)]:
            with self.subTest(settings=settings):
                reads = []
                with self.assertRaises(ValueError):
                    self.package_capture(self.package_fixture(), reads, **settings)
                self.assertEqual(reads, [])

    def test_package_brush_short_predecessor_blocks_both_new_reads(self):
        for key in [(0xdac3d0, 1024), (0x63727f0, 1024)]:
            with self.subTest(key=key):
                spans, reads = self.package_fixture(), []
                spans[key] = spans[key][:-1]
                with self.assertRaisesRegex(ValueError, 'short_local_image'):
                    self.package_capture(spans, reads)
                self.assertTrue({(0x10ecd110, 1024), (0x63c89a0, 1024)}.isdisjoint(reads))

    def test_package_brush_prior_file_is_bounded_and_pinned(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'capture.json'
            with self.assertRaisesRegex(ValueError, 'existing_bounded_prior_capture'):
                probe.read_package_brush_source(path)
            path.write_text('{}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'full_sha256_mismatch'):
                probe.read_package_brush_source(path)
            path.write_bytes(bytes(65537))
            with self.assertRaisesRegex(ValueError, 'existing_bounded_prior_capture'):
                probe.read_package_brush_source(path)


if __name__ == '__main__':
    unittest.main()
