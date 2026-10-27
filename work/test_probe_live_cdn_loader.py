"""Ensure CDN diagnostics cannot expand beyond their fixed code witnesses."""

import struct
import unittest

import probe_live_cdn_loader as probe


class CdnReadScopeTests(unittest.TestCase):
    BASE = 0x140000000
    SIZE = 0x20000000

    def fixture(self):
        spans = {}
        for rva, name, row in probe.REGISTRATIONS.values():
            spans[(rva, 48)] = struct.pack('<6Q', *(self.BASE + value for value in row[:5]), row[5])
            spans[(row[0], 32)] = name.encode('ascii').ljust(32, b'\0')
        for rva, size in probe.FIXED_CODE.values():
            spans[(rva, size)] = bytes(size)
        for name, (call, target, size) in probe.IMPLEMENTATION_CALLS.items():
            rva, length = probe.FIXED_CODE[name + '_callback']
            data = bytearray(spans[(rva, length)])
            data[call - rva:call - rva + 5] = b'\xe8' + struct.pack('<i', target - call - 5)
            spans[(rva, length)] = bytes(data)
            spans[(target, size)] = probe.IMPLEMENTATION_PREFIXES[name].ljust(size, b'\0')
        for owner, site, target, size, expected in (*probe.CONFIGURATION_CALLS.values(),
                                                  *probe.STATIC_CONFIGURATION.values()):
            _, rva, length = probe.IMPLEMENTATION_CALLS[owner]
            data = bytearray(spans[(rva, length)])
            data[site - rva:site - rva + len(expected)] = expected
            spans[(rva, length)] = bytes(data)
            spans[(target, size)] = bytes(size)
        _, rva, length = probe.IMPLEMENTATION_CALLS['IconManager_GetFinalDiskPath']
        data = bytearray(spans[(rva, length)])
        for site, _, expected in probe.FINAL_DISK_BRANCHES:
            data[site - rva:site - rva + len(expected)] = expected
        spans[(rva, length)] = bytes(data)
        spans[probe.FINAL_DISK_TAIL] = bytes(probe.FINAL_DISK_TAIL[1])
        owners = {name: (target, size) for name, (_, target, size) in probe.IMPLEMENTATION_CALLS.items()}
        owners.update({name: (target, size) for name, (_, _, target, size, _) in probe.CONFIGURATION_CALLS.items()})
        owners['IconManager_GetFinalDiskPath_tail'] = probe.FINAL_DISK_TAIL
        for owner, site, target, size, expected in probe.COMPOSITION_CALLS.values():
            rva, length = owners[owner]
            data = bytearray(spans[(rva, length)])
            data[site - rva:site - rva + len(expected)] = expected
            spans[(rva, length)] = bytes(data)
            spans[(target, size)] = bytes(size)
        for owner, site, target, expected, _ in probe.COMPOSITION_SCALARS.values():
            rva, length = owners[owner]
            data = bytearray(spans[(rva, length)])
            data[site - rva:site - rva + len(expected)] = expected
            spans[(rva, length)] = bytes(data)
            spans[(target, 1)] = b'\0'
        for rva, row in probe.IMAGE_REGISTRATIONS.values():
            spans[(rva, 48)] = struct.pack('<6Q', *(self.BASE + value for value in row[:5]), row[5])
            spans[(row[0], 32)] = next(name for name, entry in probe.IMAGE_REGISTRATIONS.items()
                                      if entry[0] == rva).encode('ascii').ljust(32, b'\0')
            spans[(row[1], probe.IMAGE_CALLBACK_SIZE)] = bytes(probe.IMAGE_CALLBACK_SIZE)
        for name, (site, target, size, expected) in probe.IMAGE_IMPLEMENTATION_CALLS.items():
            _, row = probe.IMAGE_REGISTRATIONS[name]
            rva = row[1]
            data = bytearray(probe.IMAGE_CALLBACK_PREFIXES[name].ljust(probe.IMAGE_CALLBACK_SIZE, b'\0'))
            data[site - rva:site - rva + len(expected)] = expected
            spans[(rva, probe.IMAGE_CALLBACK_SIZE)] = bytes(data)
            spans[(target, size)] = probe.IMAGE_IMPLEMENTATION_PREFIXES[name].ljust(size, b'\0')
        for name, (owner, site, target, size, expected) in probe.IMAGE_STORAGE_CALLS.items():
            _, rva, length, _ = probe.IMAGE_IMPLEMENTATION_CALLS[owner]
            data = bytearray(spans[(rva, length)])
            data[site - rva:site - rva + len(expected)] = expected
            spans[(rva, length)] = bytes(data)
            spans[(target, size)] = probe.IMAGE_STORAGE_PREFIXES[name].ljust(size, b'\0')
        owners = {name: (target, size) for name, (_, target, size, _) in probe.IMAGE_IMPLEMENTATION_CALLS.items()}
        owners.update({name: (target, size) for name, (_, _, target, size, _) in probe.IMAGE_STORAGE_CALLS.items()})
        rva, size = owners['ReqCdnDownload']
        data = bytearray(spans[(rva, size)])
        offset = 0x11ec580 - rva
        data[offset:offset + 8] = bytes.fromhex('4c894c242048894c')
        spans[(rva, size)] = bytes(data)
        for owner, site, target, size, expected in probe.IMAGE_PROCESSING_CALLS.values():
            rva, length = owners[owner]
            data = bytearray(spans[(rva, length)])
            data[site - rva:site - rva + len(expected)] = expected
            spans[(rva, length)] = bytes(data)
            spans[(target, size)] = bytes(size)
        rva, size = owners['SetCDNImage']
        data = bytearray(spans[(rva, size)])
        for site, _, expected in probe.SET_IMAGE_BRANCHES:
            data[site - rva:site - rva + len(expected)] = expected
        spans[(rva, size)] = bytes(data)
        for key in probe.SET_IMAGE_TAILS:
            spans[key] = bytes(key[1])
        rva, size = owners['Disk_ImagePath']
        data = bytearray(spans[(rva, size)])
        for site, target, expected in (probe.DISK_HASH_SCALAR, probe.DISK_MANAGER_SCALAR):
            data[site - rva:site - rva + len(expected)] = expected
            spans[(target, 1)] = b'\1' if target == probe.DISK_HASH_SCALAR[1] else b'\0'
        site, _, expected = probe.DISK_IMAGE_TAIL_BRANCH
        data[site - rva:site - rva + len(expected)] = expected
        spans[(rva, size)] = bytes(data)
        spans[probe.DISK_IMAGE_TAIL] = bytes(probe.DISK_IMAGE_TAIL[1])
        _, _, rva, size, _ = probe.IMAGE_PROCESSING_CALLS['Disk_BasenameHash']
        data = bytearray(probe.IMAGE_CRC_PREFIX.ljust(size, b'\0'))
        site, target, length, expected = probe.IMAGE_CRC_TABLE
        data[site - rva:site - rva + len(expected)] = expected
        spans[(rva, size)] = bytes(data)
        spans[(target, length)] = bytes(length)
        _, _, rva, size, _ = probe.IMAGE_PROCESSING_CALLS['Req_Worker']
        data = bytearray(bytes.fromhex('4c894c242048894c').ljust(size, b'\0'))
        for site, target, length, expected in probe.IMAGE_REQUEST_CALLS.values():
            data[site - rva:site - rva + len(expected)] = expected
            spans[(target, length)] = bytes(length)
        site, _, expected = probe.IMAGE_REQUEST_BRANCH
        data[site - rva:site - rva + len(expected)] = expected
        for site, target, length, expected, _ in probe.IMAGE_REQUEST_SCALARS.values():
            data[site - rva:site - rva + len(expected)] = expected
            spans[(target, length)] = bytes(length)
        spans[(rva, size)] = bytes(data)
        spans[probe.IMAGE_REQUEST_TAIL] = bytes(probe.IMAGE_REQUEST_TAIL[1])
        _, _, rva, size, _ = probe.IMAGE_PROCESSING_CALLS['Req_InputPath']
        data = bytearray(bytes.fromhex('4c8bdc49895b0889').ljust(size, b'\0'))
        site, target, length, expected = probe.IMAGE_REQUEST_QUALITY_TABLE
        data[site - rva:site - rva + len(expected)] = expected
        spans[(rva, size)] = bytes(data)
        spans[(target, length)] = bytes(length)
        owners = {name: (target, length) for name, (_, target, length, _) in probe.IMAGE_REQUEST_CALLS.items()}
        owners.update({name: (target, length) for name, (_, _, target, length, _) in probe.IMAGE_PROCESSING_CALLS.items()})
        for owner, prefix in probe.IMAGE_COMPONENT_PREFIXES.items():
            key = owners[owner]
            spans[key] = prefix + spans[key][len(prefix):]
        for owner, site, target, length, expected in (*probe.IMAGE_COMPONENT_CALLS.values(),
                                                     *probe.IMAGE_COMPONENT_DATA.values()):
            rva, size = owners[owner]
            data = bytearray(spans[(rva, size)])
            data[site - rva:site - rva + len(expected)] = expected
            spans[(rva, size)] = bytes(data)
            spans[(target, length)] = bytes(length)
        for owner, (target, length, site, _, expected) in probe.IMAGE_COMPONENT_TAILS.items():
            rva, size = owners[owner]
            data = bytearray(spans[(rva, size)])
            data[site - rva:site - rva + len(expected)] = expected
            spans[(rva, size)] = bytes(data)
            spans[(target, length)] = bytes(length)
        rva, length, _, _, _ = probe.IMAGE_COMPONENT_TAILS['Request_Dispatch']
        data = bytearray(spans[(rva, length)])
        site, target, size, expected = probe.IMAGE_QUEUE_CALL
        data[site - rva:site - rva + len(expected)] = expected
        spans[(rva, length)] = bytes(data)
        spans[(target, size)] = bytes(size)
        reads = []

        def read(address, size):
            key = (address - self.BASE, size)
            reads.append(key)
            return spans[key]

        return spans, reads, read

    def test_default_capture_does_not_read_implementation_targets(self):
        _, reads, read = self.fixture()
        report = probe.capture(read, self.BASE, self.SIZE)
        self.assertEqual(set(reads), probe.allowed_spans())
        self.assertNotIn('implementations', report)

    def test_expanded_capture_reads_only_verified_fixed_targets(self):
        _, reads, read = self.fixture()
        report = probe.capture(read, self.BASE, self.SIZE, True)
        self.assertEqual(set(reads), probe.allowed_spans(True))
        self.assertEqual(report['captured_bytes'], sum(size for _, size in probe.allowed_spans(True)))
        self.assertEqual(len(report['implementations']), 6)
        self.assertEqual(len(report['configuration_accessors']), 3)
        self.assertEqual(len(report['static_configuration_operands']), 2)
        self.assertEqual(len(report['fixed_tails']), 1)

    def test_changed_call_rejects_before_any_target_read(self):
        spans, reads, read = self.fixture()
        call, _, _ = probe.IMPLEMENTATION_CALLS['AppRow_GetCDNUrl']
        rva, size = probe.FIXED_CODE['AppRow_GetCDNUrl_callback']
        data = bytearray(spans[(rva, size)])
        data[call - rva] = 0xe9
        spans[(rva, size)] = bytes(data)
        with self.assertRaisesRegex(ValueError, 'witnessed direct'):
            probe.capture(read, self.BASE, self.SIZE, True)
        targets = {(target, size) for _, target, size in probe.IMPLEMENTATION_CALLS.values()}
        self.assertFalse(targets.intersection(reads))

    def assert_no_configuration_reads(self, reads):
        targets = {(target, size) for _, _, target, size, _ in
                   (*probe.CONFIGURATION_CALLS.values(), *probe.STATIC_CONFIGURATION.values())}
        targets.add(probe.FINAL_DISK_TAIL)
        self.assertFalse(targets.intersection(reads))

    def test_changed_implementation_prefix_rejects_before_configuration_reads(self):
        spans, reads, read = self.fixture()
        _, rva, size = probe.IMPLEMENTATION_CALLS['CDNConfig_GetCDNUrl']
        spans[(rva, size)] = b'\0' + spans[(rva, size)][1:]
        with self.assertRaisesRegex(ValueError, 'plaintext implementation prefix'):
            probe.capture(read, self.BASE, self.SIZE, True)
        self.assert_no_configuration_reads(reads)

    def test_changed_disk_branch_rejects_before_any_configuration_or_tail_read(self):
        spans, reads, read = self.fixture()
        _, rva, size = probe.IMPLEMENTATION_CALLS['IconManager_GetFinalDiskPath']
        site, _, _ = probe.FINAL_DISK_BRANCHES[1]
        code = bytearray(spans[(rva, size)])
        code[site - rva + 1] = 0x8f
        spans[(rva, size)] = bytes(code)
        with self.assertRaisesRegex(ValueError, 'Disk-path branch'):
            probe.capture(read, self.BASE, self.SIZE, True)
        self.assert_no_configuration_reads(reads)

    def test_changed_disk_target_rejects_before_any_configuration_or_tail_read(self):
        spans, reads, read = self.fixture()
        _, rva, size = probe.IMPLEMENTATION_CALLS['IconManager_GetFinalDiskPath']
        site, _, _ = probe.FINAL_DISK_BRANCHES[0]
        code = bytearray(spans[(rva, size)])
        code[site - rva + 1] ^= 1
        spans[(rva, size)] = bytes(code)
        with self.assertRaisesRegex(ValueError, 'Disk-path branch'):
            probe.capture(read, self.BASE, self.SIZE, True)
        self.assert_no_configuration_reads(reads)

    def test_final_span_module_bound_rejects_before_any_read(self):
        _, reads, read = self.fixture()
        last_end = max(rva + size for rva, size in probe.allowed_spans(True))
        with self.assertRaisesRegex(ValueError, 'outside'):
            probe.capture(read, self.BASE, last_end - 1, True)
        self.assertEqual(reads, [])

    def test_changed_configuration_call_rejects_before_any_configuration_read(self):
        spans, reads, read = self.fixture()
        owner, site, _, _, _ = probe.CONFIGURATION_CALLS['IconManager_AppRowAccess']
        _, rva, size = probe.IMPLEMENTATION_CALLS[owner]
        code = bytearray(spans[(rva, size)])
        code[site - rva] = 0xe9
        spans[(rva, size)] = bytes(code)
        with self.assertRaisesRegex(ValueError, 'configuration direct call'):
            probe.capture(read, self.BASE, self.SIZE, True)
        self.assert_no_configuration_reads(reads)

    def test_changed_configuration_target_rejects_before_any_configuration_read(self):
        spans, reads, read = self.fixture()
        owner, site, _, _, _ = probe.CONFIGURATION_CALLS['AppSetting_ConfigAccess']
        _, rva, size = probe.IMPLEMENTATION_CALLS[owner]
        code = bytearray(spans[(rva, size)])
        code[site - rva + 1] ^= 1
        spans[(rva, size)] = bytes(code)
        with self.assertRaisesRegex(ValueError, 'configuration direct call'):
            probe.capture(read, self.BASE, self.SIZE, True)
        self.assert_no_configuration_reads(reads)

    def test_changed_static_operand_rejects_before_any_configuration_read(self):
        spans, reads, read = self.fixture()
        owner, site, _, _, _ = probe.STATIC_CONFIGURATION['AppSetting_default_row_operand']
        _, rva, size = probe.IMPLEMENTATION_CALLS[owner]
        code = bytearray(spans[(rva, size)])
        code[site - rva + 3] ^= 1
        spans[(rva, size)] = bytes(code)
        with self.assertRaisesRegex(ValueError, 'static module operand'):
            probe.capture(read, self.BASE, self.SIZE, True)
        self.assert_no_configuration_reads(reads)

    def test_short_module_rejects_without_reading(self):
        _, reads, read = self.fixture()
        with self.assertRaisesRegex(ValueError, 'outside'):
            probe.capture(read, self.BASE, 1, True)
        self.assertEqual(reads, [])

    def assert_no_composition_reads(self, reads):
        targets = {(target, size) for _, _, target, size, _ in probe.COMPOSITION_CALLS.values()}
        targets.update((target, 1) for _, _, target, _, _ in probe.COMPOSITION_SCALARS.values())
        self.assertFalse(targets.intersection(reads))

    def test_composition_requires_implementations_before_any_read(self):
        _, reads, read = self.fixture()
        with self.assertRaisesRegex(ValueError, 'require --implementations'):
            probe.capture(read, self.BASE, self.SIZE, False, True)
        self.assertEqual(reads, [])

    def test_composition_only_reads_verified_code_and_module_bytes(self):
        _, reads, read = self.fixture()
        report = probe.capture(read, self.BASE, self.SIZE, True, True)
        self.assertEqual(set(reads), probe.allowed_spans(True, True))
        self.assertEqual(report['captured_bytes'], sum(size for _, size in probe.allowed_spans(True, True)) + 10)
        self.assertEqual(report['captured_bytes'], 12084)
        self.assertEqual(len(report['composition_helpers']), 4)
        self.assertEqual(len(report['composition_scalars']), 10)
        self.assertTrue(report['composition_scalars_stable'])

    def test_wrong_composition_call_rejects_before_any_additional_read(self):
        for name, (owner, site, _, _, _) in probe.COMPOSITION_CALLS.items():
            with self.subTest(name=name):
                spans, reads, read = self.fixture()
                if owner.endswith('_tail'):
                    rva, size = probe.FINAL_DISK_TAIL
                else:
                    _, rva, size = probe.IMPLEMENTATION_CALLS[owner]
                code = bytearray(spans[(rva, size)])
                code[site - rva] = 0xe9
                spans[(rva, size)] = bytes(code)
                with self.assertRaisesRegex(ValueError, 'composition direct call'):
                    probe.capture(read, self.BASE, self.SIZE, True, True)
                self.assert_no_composition_reads(reads)

    def test_wrong_composition_target_rejects_before_any_additional_read(self):
        spans, reads, read = self.fixture()
        _, site, _, _, _ = probe.COMPOSITION_CALLS['Disk_PathBase']
        rva, size = probe.FINAL_DISK_TAIL
        code = bytearray(spans[(rva, size)])
        code[site - rva + 1] ^= 1
        spans[(rva, size)] = bytes(code)
        with self.assertRaisesRegex(ValueError, 'composition direct call'):
            probe.capture(read, self.BASE, self.SIZE, True, True)
        self.assert_no_composition_reads(reads)

    def test_wrong_scalar_operand_rejects_before_any_additional_read(self):
        for name, (owner, site, _, _, displacement_offset) in probe.COMPOSITION_SCALARS.items():
            with self.subTest(name=name):
                spans, reads, read = self.fixture()
                if owner in probe.IMPLEMENTATION_CALLS:
                    _, rva, size = probe.IMPLEMENTATION_CALLS[owner]
                else:
                    _, _, rva, size, _ = probe.CONFIGURATION_CALLS[owner]
                code = bytearray(spans[(rva, size)])
                code[site - rva + displacement_offset] ^= 1
                spans[(rva, size)] = bytes(code)
                with self.assertRaisesRegex(ValueError, 'RIP-relative scalar operand'):
                    probe.capture(read, self.BASE, self.SIZE, True, True)
                self.assert_no_composition_reads(reads)

    def test_composition_module_bound_rejects_before_any_read(self):
        _, reads, read = self.fixture()
        last_end = max(rva + size for rva, size in probe.allowed_spans(True, True))
        with self.assertRaisesRegex(ValueError, 'outside'):
            probe.capture(read, self.BASE, last_end - 1, True, True)
        self.assertEqual(reads, [])

    def test_changed_scalar_is_reported_unstable(self):
        spans, _, read = self.fixture()
        target = probe.COMPOSITION_SCALARS['pc_url_selector'][2]
        count = 0

        def changed_read(address, size):
            nonlocal count
            data = read(address, size)
            if address == self.BASE + target and size == 1:
                count += 1
                return b'\1' if count == 2 else data
            return data

        report = probe.capture(changed_read, self.BASE, self.SIZE, True, True)
        self.assertFalse(report['composition_scalars_stable'])
        self.assertFalse(report['composition_scalars']['pc_url_selector']['stable'])

    def test_image_option_reads_only_fixed_registered_callbacks(self):
        _, reads, read = self.fixture()
        report = probe.capture(read, self.BASE, self.SIZE, image_path=True)
        self.assertEqual(set(reads), probe.allowed_spans(image_path=True))
        self.assertEqual(report['captured_bytes'], 3808)
        self.assertEqual(len(report['image_callbacks']), 4)
        self.assertNotIn('implementations', report)

    def test_changed_image_registration_rejects_before_any_image_callback(self):
        for name, (rva, _) in probe.IMAGE_REGISTRATIONS.items():
            with self.subTest(name=name):
                spans, reads, read = self.fixture()
                spans[(rva, 48)] = bytes(48)
                with self.assertRaisesRegex(ValueError, 'image registration'):
                    probe.capture(read, self.BASE, self.SIZE, image_path=True)
                targets = {(row[1], probe.IMAGE_CALLBACK_SIZE) for _, row in probe.IMAGE_REGISTRATIONS.values()}
                self.assertFalse(targets.intersection(reads))

    def test_changed_image_name_rejects_before_any_image_callback(self):
        spans, reads, read = self.fixture()
        _, row = probe.IMAGE_REGISTRATIONS['DecodeImageData']
        spans[(row[0], 32)] = b'wrong'.ljust(32, b'\0')
        with self.assertRaisesRegex(ValueError, 'image name'):
            probe.capture(read, self.BASE, self.SIZE, image_path=True)
        targets = {(row[1], probe.IMAGE_CALLBACK_SIZE) for _, row in probe.IMAGE_REGISTRATIONS.values()}
        self.assertFalse(targets.intersection(reads))

    def test_image_module_bound_rejects_before_any_read(self):
        _, reads, read = self.fixture()
        last_end = max(rva + size for rva, size in probe.allowed_spans(image_path=True))
        with self.assertRaisesRegex(ValueError, 'outside'):
            probe.capture(read, self.BASE, last_end - 1, image_path=True)
        self.assertEqual(reads, [])

    def test_image_implementations_require_callbacks_before_any_read(self):
        _, reads, read = self.fixture()
        with self.assertRaisesRegex(ValueError, 'require --image-path'):
            probe.capture(read, self.BASE, self.SIZE, image_implementations=True)
        self.assertEqual(reads, [])

    def test_image_implementations_read_exact_fixed_targets(self):
        _, reads, read = self.fixture()
        report = probe.capture(read, self.BASE, self.SIZE, image_path=True, image_implementations=True)
        self.assertEqual(set(reads), probe.allowed_spans(image_path=True, image_implementations=True))
        self.assertEqual(report['captured_bytes'], 7904)
        self.assertEqual(len(report['image_implementations']), 4)

    def test_wrong_image_edge_rejects_before_any_callee_read(self):
        for name, (site, _, _, _) in probe.IMAGE_IMPLEMENTATION_CALLS.items():
            with self.subTest(name=name):
                spans, reads, read = self.fixture()
                _, row = probe.IMAGE_REGISTRATIONS[name]
                key = (row[1], probe.IMAGE_CALLBACK_SIZE)
                code = bytearray(spans[key])
                code[site - row[1] + 1] ^= 1
                spans[key] = bytes(code)
                with self.assertRaisesRegex(ValueError, 'image implementation edge'):
                    probe.capture(read, self.BASE, self.SIZE, image_path=True, image_implementations=True)
                targets = {(target, size) for _, target, size, _ in probe.IMAGE_IMPLEMENTATION_CALLS.values()}
                self.assertFalse(targets.intersection(reads))

    def test_wrong_image_prefix_rejects_before_any_callee_read(self):
        spans, reads, read = self.fixture()
        _, row = probe.IMAGE_REGISTRATIONS['DecodeImageData']
        key = (row[1], probe.IMAGE_CALLBACK_SIZE)
        spans[key] = b'\0' + spans[key][1:]
        with self.assertRaisesRegex(ValueError, 'image implementation edge'):
            probe.capture(read, self.BASE, self.SIZE, image_path=True, image_implementations=True)
        targets = {(target, size) for _, target, size, _ in probe.IMAGE_IMPLEMENTATION_CALLS.values()}
        self.assertFalse(targets.intersection(reads))

    def test_image_callee_module_bound_rejects_before_any_read(self):
        _, reads, read = self.fixture()
        last_end = max(rva + size for rva, size in probe.allowed_spans(image_path=True, image_implementations=True))
        with self.assertRaisesRegex(ValueError, 'outside'):
            probe.capture(read, self.BASE, last_end - 1, image_path=True, image_implementations=True)
        self.assertEqual(reads, [])

    def test_image_storage_requires_implementation_stage_before_any_read(self):
        _, reads, read = self.fixture()
        with self.assertRaisesRegex(ValueError, 'require --image-implementations'):
            probe.capture(read, self.BASE, self.SIZE, image_path=True, image_storage=True)
        self.assertEqual(reads, [])

    def test_image_storage_only_reads_fixed_verified_targets(self):
        _, reads, read = self.fixture()
        report = probe.capture(read, self.BASE, self.SIZE, image_path=True, image_implementations=True, image_storage=True)
        self.assertEqual(set(reads), probe.allowed_spans(image_path=True, image_implementations=True, image_storage=True))
        self.assertEqual(report['captured_bytes'], 9952)
        self.assertEqual(len(report['image_storage_helpers']), 2)

    def test_wrong_image_storage_instruction_rejects_before_any_storage_read(self):
        for name, (owner, site, _, _, _) in probe.IMAGE_STORAGE_CALLS.items():
            with self.subTest(name=name):
                spans, reads, read = self.fixture()
                _, rva, size, _ = probe.IMAGE_IMPLEMENTATION_CALLS[owner]
                code = bytearray(spans[(rva, size)])
                code[site - rva] = 0xe9
                spans[(rva, size)] = bytes(code)
                with self.assertRaisesRegex(ValueError, 'image storage direct call'):
                    probe.capture(read, self.BASE, self.SIZE, image_path=True, image_implementations=True, image_storage=True)
                targets = {(target, size) for _, _, target, size, _ in probe.IMAGE_STORAGE_CALLS.values()}
                self.assertFalse(targets.intersection(reads))

    def test_wrong_image_implementation_prefix_rejects_before_storage_read(self):
        spans, reads, read = self.fixture()
        _, rva, size, _ = probe.IMAGE_IMPLEMENTATION_CALLS['ReqCdnDownload']
        spans[(rva, size)] = b'\0' + spans[(rva, size)][1:]
        with self.assertRaisesRegex(ValueError, 'image implementation prefix'):
            probe.capture(read, self.BASE, self.SIZE, image_path=True, image_implementations=True, image_storage=True)
        targets = {(target, size) for _, _, target, size, _ in probe.IMAGE_STORAGE_CALLS.values()}
        self.assertFalse(targets.intersection(reads))

    def test_storage_bounds_reject_before_any_read(self):
        _, reads, read = self.fixture()
        last_end = max(rva + size for rva, size in probe.allowed_spans(image_path=True, image_implementations=True, image_storage=True))
        with self.assertRaisesRegex(ValueError, 'outside'):
            probe.capture(read, self.BASE, last_end - 1, image_path=True, image_implementations=True, image_storage=True)
        self.assertEqual(reads, [])

    def processing_capture(self, read, size=None):
        return probe.capture(read, self.BASE, size or self.SIZE, image_path=True,
                             image_implementations=True, image_storage=True, image_processing=True)

    def assert_no_processing_reads(self, reads):
        targets = {(target, size) for _, _, target, size, _ in probe.IMAGE_PROCESSING_CALLS.values()}
        targets.update(probe.SET_IMAGE_TAILS)
        targets.add((probe.DISK_HASH_SCALAR[1], 1))
        targets.add((probe.DISK_MANAGER_SCALAR[1], 1))
        targets.add(probe.DISK_IMAGE_TAIL)
        self.assertFalse(targets.intersection(reads))

    def test_image_processing_requires_storage_before_any_read(self):
        _, reads, read = self.fixture()
        with self.assertRaisesRegex(ValueError, 'require --image-storage'):
            probe.capture(read, self.BASE, self.SIZE, image_path=True,
                          image_implementations=True, image_processing=True)
        self.assertEqual(reads, [])

    def test_image_processing_reads_only_verified_fixed_code_and_byte(self):
        _, reads, read = self.fixture()
        report = self.processing_capture(read)
        self.assertEqual(set(reads), probe.allowed_spans(image_path=True, image_implementations=True,
                                                       image_storage=True, image_processing=True))
        self.assertEqual(report['captured_bytes'], 16484)
        self.assertEqual(len(report['image_processing_helpers']), 5)
        self.assertEqual(report['image_processing_tails']['SetCDNImage']['size'], 4096)
        self.assertTrue(report['disk_hash_branch_byte']['stable'])
        self.assertTrue(report['disk_manager_override_byte']['stable'])
        self.assertEqual(report['image_processing_tails']['Disk_ImagePath']['size'], 1152)

    def test_wrong_processing_call_rejects_before_any_new_read(self):
        for name, (owner, site, _, _, _) in probe.IMAGE_PROCESSING_CALLS.items():
            with self.subTest(name=name):
                spans, reads, read = self.fixture()
                if owner in probe.IMAGE_IMPLEMENTATION_CALLS:
                    _, rva, size, _ = probe.IMAGE_IMPLEMENTATION_CALLS[owner]
                else:
                    _, _, rva, size, _ = probe.IMAGE_STORAGE_CALLS[owner]
                code = bytearray(spans[(rva, size)])
                code[site - rva + 1] ^= 1
                spans[(rva, size)] = bytes(code)
                with self.assertRaisesRegex(ValueError, 'image processing direct call'):
                    self.processing_capture(read)
                self.assert_no_processing_reads(reads)

    def test_wrong_setter_branch_rejects_before_any_new_read(self):
        spans, reads, read = self.fixture()
        _, rva, size, _ = probe.IMAGE_IMPLEMENTATION_CALLS['SetCDNImage']
        site, _, _ = probe.SET_IMAGE_BRANCHES[0]
        code = bytearray(spans[(rva, size)])
        code[site - rva + 1] ^= 1
        spans[(rva, size)] = bytes(code)
        with self.assertRaisesRegex(ValueError, 'Set-image branch'):
            self.processing_capture(read)
        self.assert_no_processing_reads(reads)

    def test_wrong_hash_selector_rejects_before_any_new_read(self):
        spans, reads, read = self.fixture()
        _, _, rva, size, _ = probe.IMAGE_STORAGE_CALLS['Disk_ImagePath']
        site, _, _ = probe.DISK_HASH_SCALAR
        code = bytearray(spans[(rva, size)])
        code[site - rva + 2] ^= 1
        spans[(rva, size)] = bytes(code)
        with self.assertRaisesRegex(ValueError, 'Disk hash selector'):
            self.processing_capture(read)
        self.assert_no_processing_reads(reads)

    def test_wrong_disk_image_branch_rejects_before_any_new_read(self):
        spans, reads, read = self.fixture()
        _, _, rva, size, _ = probe.IMAGE_STORAGE_CALLS['Disk_ImagePath']
        site, _, _ = probe.DISK_IMAGE_TAIL_BRANCH
        code = bytearray(spans[(rva, size)])
        code[site - rva + 1] ^= 1
        spans[(rva, size)] = bytes(code)
        with self.assertRaisesRegex(ValueError, 'Disk-image branch'):
            self.processing_capture(read)
        self.assert_no_processing_reads(reads)

    def test_wrong_storage_prefix_rejects_before_processing_reads(self):
        spans, reads, read = self.fixture()
        _, _, rva, size, _ = probe.IMAGE_STORAGE_CALLS['Disk_LoadBytes']
        spans[(rva, size)] = b'\0' + spans[(rva, size)][1:]
        with self.assertRaisesRegex(ValueError, 'image storage prefix'):
            self.processing_capture(read)
        self.assert_no_processing_reads(reads)

    def test_wrong_worker_prefix_rejects_before_processing_reads(self):
        spans, reads, read = self.fixture()
        _, rva, size, _ = probe.IMAGE_IMPLEMENTATION_CALLS['ReqCdnDownload']
        code = bytearray(spans[(rva, size)])
        code[0x11ec580 - rva] ^= 1
        spans[(rva, size)] = bytes(code)
        with self.assertRaisesRegex(ValueError, 'worker differs'):
            self.processing_capture(read)
        self.assert_no_processing_reads(reads)

    def test_processing_short_module_rejects_before_any_read(self):
        _, reads, read = self.fixture()
        last_end = max(rva + size for rva, size in probe.allowed_spans(image_path=True,
            image_implementations=True, image_storage=True, image_processing=True))
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.processing_capture(read, last_end - 1)
        self.assertEqual(reads, [])

    def crc_capture(self, read, size=None):
        return probe.capture(read, self.BASE, size or self.SIZE, image_path=True,
            image_implementations=True, image_storage=True, image_processing=True, image_crc_table=True)

    def test_crc_table_requires_processing_before_any_read(self):
        _, reads, read = self.fixture()
        with self.assertRaisesRegex(ValueError, 'requires --image-processing'):
            probe.capture(read, self.BASE, self.SIZE, image_crc_table=True)
        self.assertEqual(reads, [])

    def test_crc_table_exact_fixed_read(self):
        _, reads, read = self.fixture()
        report = self.crc_capture(read)
        self.assertEqual(report['captured_bytes'], 17508)
        self.assertEqual(report['image_crc_table']['size'], 1024)
        self.assertEqual(set(reads), probe.allowed_spans(image_path=True,
            image_implementations=True, image_storage=True, image_processing=True, image_crc_table=True))

    def test_crc_wrong_prefix_or_lea_no_table_read(self):
        for byte_offset in (0, 0x11, 0x14):
            with self.subTest(byte_offset=byte_offset):
                spans, reads, read = self.fixture()
                _, _, rva, size, _ = probe.IMAGE_PROCESSING_CALLS['Disk_BasenameHash']
                code = bytearray(spans[(rva, size)])
                code[byte_offset] ^= 1
                spans[(rva, size)] = bytes(code)
                with self.assertRaisesRegex(ValueError, 'CRC table'):
                    self.crc_capture(read)
                self.assertNotIn((probe.IMAGE_CRC_TABLE[1], 1024), reads)

    def test_crc_table_module_bound_no_read(self):
        _, reads, read = self.fixture()
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.crc_capture(read, probe.IMAGE_CRC_TABLE[1] + 1023)
        self.assertEqual(reads, [])

    def request_capture(self, read, size=None):
        return probe.capture(read, self.BASE, size or self.SIZE, image_path=True,
            image_implementations=True, image_storage=True, image_processing=True,
            image_crc_table=True, image_request_processing=True)

    def test_request_requires_processing_before_any_read(self):
        _, reads, read = self.fixture()
        with self.assertRaisesRegex(ValueError, 'requires --image-processing'):
            probe.capture(read, self.BASE, self.SIZE, image_request_processing=True)
        self.assertEqual(reads, [])

    def test_request_all_fixed_reads_and_old_default_unchanged(self):
        _, reads, read = self.fixture()
        report = self.request_capture(read)
        self.assertEqual(report['captured_bytes'], 20888)
        self.assertEqual(len(report['image_request_helpers']), 3)
        self.assertEqual(report['image_request_tails']['Req_Worker']['size'], 1280)
        self.assertTrue(all(x['stable'] for x in report['image_request_scalars'].values()))
        self.assertEqual(set(reads), probe.allowed_spans(image_path=True,
            image_implementations=True, image_storage=True, image_processing=True,
            image_crc_table=True, image_request_processing=True))

    def test_request_wrong_edges_and_scalars_no_additional_reads(self):
        offsets = [0, probe.IMAGE_REQUEST_BRANCH[0] - 0x11ec580]
        offsets += [site - 0x11ec580 + 1 for site, _, _, _ in probe.IMAGE_REQUEST_CALLS.values()]
        offsets += [site - 0x11ec580 + 2 for site, _, _, _, _ in probe.IMAGE_REQUEST_SCALARS.values()]
        for offset in offsets:
            with self.subTest(offset=offset):
                spans, reads, read = self.fixture()
                key = (0x11ec580, 1024)
                data = bytearray(spans[key]); data[offset] ^= 1; spans[key] = bytes(data)
                with self.assertRaises(ValueError):
                    self.request_capture(read)
                targets = {(target, size) for _, target, size, _ in probe.IMAGE_REQUEST_CALLS.values()}
                targets.update((target, size) for _, target, size, _, _ in probe.IMAGE_REQUEST_SCALARS.values())
                targets.add(probe.IMAGE_REQUEST_TAIL)
                targets.add((probe.IMAGE_REQUEST_QUALITY_TABLE[1], 32))
                self.assertFalse(targets.intersection(reads))

    def test_request_wrong_quality_table_no_additional_read(self):
        spans, reads, read = self.fixture()
        key = (0x11e6ee0, 1024)
        data = bytearray(spans[key]); data[0x79] ^= 1; spans[key] = bytes(data)
        with self.assertRaisesRegex(ValueError, 'quality table'):
            self.request_capture(read)
        self.assertNotIn((probe.IMAGE_REQUEST_QUALITY_TABLE[1], 32), reads)
        self.assertNotIn(probe.IMAGE_REQUEST_TAIL, reads)

    def test_request_bounds_fail_before_any_read(self):
        _, reads, read = self.fixture()
        spans = probe.allowed_spans(image_path=True, image_implementations=True,
            image_storage=True, image_processing=True, image_crc_table=True,
            image_request_processing=True)
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.request_capture(read, max(rva + size for rva, size in spans) - 1)
        self.assertEqual(reads, [])

    def component_capture(self, read, size=None):
        return probe.capture(read, self.BASE, size or self.SIZE, image_path=True,
            image_implementations=True, image_storage=True, image_processing=True,
            image_crc_table=True, image_request_processing=True, image_request_components=True)

    def test_component_requires_request_before_any_read(self):
        _, reads, read = self.fixture()
        with self.assertRaisesRegex(ValueError, 'require --image-request-processing'):
            probe.capture(read, self.BASE, self.SIZE, image_request_components=True)
        self.assertEqual(reads, [])

    def test_component_exact_fixed_reads(self):
        _, reads, read = self.fixture()
        report = self.component_capture(read)
        self.assertEqual(report['captured_bytes'], 23746)
        self.assertEqual(len(report['image_component_helpers']), 2)
        self.assertEqual(len(report['image_component_data']), 2)
        self.assertEqual(report['image_component_tails']['Disk_SplitEquals']['size'], 768)
        self.assertEqual(set(reads), probe.allowed_spans(image_path=True,
            image_implementations=True, image_storage=True, image_processing=True,
            image_crc_table=True, image_request_processing=True, image_request_components=True))

    def test_component_wrong_prefix_call_branch_lea_no_new_reads(self):
        owners = {name: (target, size) for name, (_, target, size, _) in probe.IMAGE_REQUEST_CALLS.items()}
        owners.update({name: (target, size) for name, (_, _, target, size, _) in probe.IMAGE_PROCESSING_CALLS.items()})
        mutations = [(owner, owners[owner][0]) for owner in probe.IMAGE_COMPONENT_PREFIXES]
        mutations += [(owner, site + 1) for owner, site, _, _, _ in probe.IMAGE_COMPONENT_CALLS.values()]
        mutations += [(owner, site + 3) for owner, site, _, _, _ in probe.IMAGE_COMPONENT_DATA.values()]
        mutations += [(owner, site + 1) for owner, (_, _, site, _, _) in probe.IMAGE_COMPONENT_TAILS.items()]
        targets = {(target, size) for _, _, target, size, _ in probe.IMAGE_COMPONENT_CALLS.values()}
        targets.update((target, size) for _, _, target, size, _ in probe.IMAGE_COMPONENT_DATA.values())
        targets.update((rva, size) for rva, size, _, _, _ in probe.IMAGE_COMPONENT_TAILS.values())
        for owner, site in mutations:
            with self.subTest(owner=owner, site=site):
                spans, reads, read = self.fixture()
                key = owners[owner]
                data = bytearray(spans[key]); data[site - key[0]] ^= 1; spans[key] = bytes(data)
                with self.assertRaises(ValueError):
                    self.component_capture(read)
                self.assertFalse(targets.intersection(reads))

    def test_component_bounds_no_read(self):
        _, reads, read = self.fixture()
        spans = probe.allowed_spans(image_path=True, image_implementations=True,
            image_storage=True, image_processing=True, image_crc_table=True,
            image_request_processing=True, image_request_components=True)
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.component_capture(read, max(rva + size for rva, size in spans) - 1)
        self.assertEqual(reads, [])

    def queue_capture(self, read):
        return probe.capture(read, self.BASE, self.SIZE, image_path=True,
            image_implementations=True, image_storage=True, image_processing=True,
            image_crc_table=True, image_request_processing=True, image_request_components=True,
            image_request_queue=True)

    def test_queue_requires_components_before_any_read(self):
        _, reads, read = self.fixture()
        with self.assertRaisesRegex(ValueError, 'requires --image-request-components'):
            probe.capture(read, self.BASE, self.SIZE, image_request_queue=True)
        self.assertEqual(reads, [])

    def test_queue_exact_fixed_callee(self):
        _, reads, read = self.fixture()
        result = self.queue_capture(read)
        self.assertEqual(result['captured_bytes'], 24770)
        self.assertEqual(result['image_queue_helper']['size'], 1024)

    def test_wrong_queue_call_no_extra_read(self):
        for position in (0, 1):
            spans, reads, read = self.fixture()
            rva, size, _, _, _ = probe.IMAGE_COMPONENT_TAILS['Request_Dispatch']
            key = (rva, size)
            site, target, length, _ = probe.IMAGE_QUEUE_CALL
            data = bytearray(spans[key]); data[site - rva + position] ^= 1; spans[key] = bytes(data)
            with self.subTest(position=position), self.assertRaisesRegex(ValueError, 'queue scheduling'):
                self.queue_capture(read)
            self.assertNotIn((target, length), reads)


if __name__ == '__main__':
    unittest.main()
