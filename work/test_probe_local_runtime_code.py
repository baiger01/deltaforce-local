"""Check that local-runtime diagnostics reject unrelated native reads."""

import struct
import hashlib
import unittest

import probe_local_runtime_code as probe
from probe_local_runtime_code import REGISTRATIONS, capture_metadata, code_targets, validate_call_witness


class LocalRuntimeReadTests(unittest.TestCase):
    def reader(self, base, *, corrupt=None):
        regions = {}
        for label, (name, rva, row) in REGISTRATIONS.items():
            values = tuple(base + value for value in row[:5]) + (row[5],)
            if label == corrupt:
                values = values[:2] + (values[2] + 8,) + values[3:]
            regions[base + rva, 48] = struct.pack('<6Q', *values)
            regions[base + row[0], len(name) + 1] = name.encode('ascii') + b'\0'
        calls = []

        def read(address, length):
            calls.append((address, length))
            return regions[address, length]

        return read, calls

    def test_aslr_relocated_fields_are_verified_before_code_capture(self):
        base = 0x7ff600000000
        read, calls = self.reader(base)
        report = capture_metadata(read, base, 0x20000000)
        self.assertEqual(len(report), len(REGISTRATIONS))
        self.assertTrue(all(row['all_fields_verified'] for row in report.values()))
        self.assertEqual(len(calls), 2 * len(REGISTRATIONS))

    def test_changed_binding_pointer_is_rejected(self):
        base = 0x7ff600000000
        read, _ = self.reader(base, corrupt='StartLocalDS.static')
        with self.assertRaisesRegex(ValueError, 'registration differs'):
            capture_metadata(read, base, 0x20000000)

    def test_small_module_is_rejected_before_any_native_read(self):
        read, calls = self.reader(0x140000000)
        with self.assertRaisesRegex(ValueError, 'module bounds'):
            capture_metadata(read, 0x140000000, 64)
        self.assertEqual(calls, [])

    def test_partial_native_read_is_not_treated_as_a_valid_record(self):
        with self.assertRaisesRegex(ValueError, 'read length'):
            capture_metadata(lambda _address, _size: b'\0', 0x140000000, 0x20000000)

    def test_only_named_fixed_prefixes_are_requested(self):
        targets = code_targets()
        self.assertEqual(len(targets), 53)
        self.assertTrue(all(length == 32 for _rva, length in targets.values()))

    def test_followup_reads_require_their_source_body_to_be_captured_first(self):
        available = set(code_targets())
        seen = set()
        for label, witness in probe.code_witnesses():
            self.assertIn(witness[0], available, label)
            self.assertNotIn(label, seen)
            seen.add(label)
            available.update((label, label + '.prefix'))
        self.assertTrue({
            'GetProjectFilePath.target',
            'UDFMGameInstance.native_registration_callback_reference',
            'DFMOfflinePlayerController.actor_open_hook',
            'UGPNetConnection.class_target',
            'UGPNetConnection.constructor_target',
            'UGPNetConnection.client_player_slot',
            'UGPNetConnection.client_player_gate',
            'UGPNetConnection.base_client_player',
            'UGPNetConnection.seamless_interface_constructor',
        }.issubset(seen))

    def class_reader(self, base, *, corrupt=False):
        regions = {}
        for name, descriptor, cell, name_rva, size, code in probe.CLASS_INITIALIZERS.values():
            regions[base + descriptor, 24] = struct.pack('<3Q', base + cell, base + name_rva, size)
            regions[base + cell, 8] = struct.pack('<Q', base + code + (8 if corrupt else 0))
            regions[base + name_rva, len(name) + 1] = name.encode('ascii') + b'\0'
        return lambda address, length: regions[address, length]

    def test_class_descriptor_and_initializer_cell_are_both_verified(self):
        base = 0x7ff600000000
        self.assertTrue(hasattr(probe, 'capture_class_metadata'))
        report = probe.capture_class_metadata(self.class_reader(base), base, 0x20000000)
        self.assertEqual(set(report), set(probe.CLASS_INITIALIZERS))
        self.assertTrue(all(row['all_fields_verified'] for row in report.values()))

    def test_changed_class_initializer_is_rejected(self):
        base = 0x7ff600000000
        self.assertTrue(hasattr(probe, 'capture_class_metadata'))
        with self.assertRaisesRegex(ValueError, 'initializer differs'):
            probe.capture_class_metadata(self.class_reader(base, corrupt=True), base, 0x20000000)

    def test_direct_call_target_must_match_the_captured_witness(self):
        body = b'\xe8' + struct.pack('<i', 0x200 - 0x100 - 5)
        pin = hashlib.sha256(body).hexdigest()
        validate_call_witness(body, 0x100, pin, 0x100, 0x200)
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            validate_call_witness(body, 0x100, pin, 0x100, 0x201)

    def test_changed_code_cannot_authorize_a_followup_read(self):
        body = b'\xe8' + struct.pack('<i', 0x200 - 0x100 - 5)
        pin = hashlib.sha256(body).hexdigest()
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            validate_call_witness(body[:-1] + b'\xff', 0x100, pin, 0x100, 0x200)

    def test_type_helper_reference_requires_the_exact_rip_relative_table(self):
        body = b'\x48\x8d\x0d' + struct.pack('<i', 0x200 - 0x100 - 7)
        self.assertTrue(hasattr(probe, 'validate_rip_witness'))
        pin = hashlib.sha256(body).hexdigest()
        probe.validate_rip_witness(body, 0x100, pin, 0x100, 0x200)
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            probe.validate_rip_witness(body, 0x100, pin, 0x100, 0x201)

    def test_other_lea_encoding_cannot_authorize_type_helper_reads(self):
        body = b'\x48\x8d\x14' + struct.pack('<i', 0x200 - 0x100 - 7)
        self.assertTrue(hasattr(probe, 'validate_rip_witness'))
        with self.assertRaisesRegex(ValueError, 'fixed RIP'):
            probe.validate_rip_witness(body, 0x100, hashlib.sha256(body).hexdigest(), 0x100, 0x200)

    def method_table_reader(self, base, *, changed_table=False, changed_prefix=False):
        regions = {}
        for _owner, (descriptor, row, method_label, _index, code, prefix) in probe.CLASS_METHOD_TABLES.items():
            relocated = tuple(base + value for value in row[:4]) + (row[4],)
            if changed_table:
                relocated = relocated[:1] + (relocated[1] + 48,) + relocated[2:]
            regions[base + descriptor, 40] = struct.pack('<5Q', *relocated)
            regions[base + code, len(prefix)] = prefix[:-1] + b'\xff' if changed_prefix else prefix
            _name, method_rva, method = REGISTRATIONS[method_label]
            regions[base + method_rva, 48] = struct.pack(
                '<6Q', *(tuple(base + value for value in method[:5]) + (method[5],)))
        return lambda address, length: regions[address, length]

    def test_class_ownership_requires_descriptor_helper_and_method_membership(self):
        self.assertTrue(hasattr(probe, 'CLASS_METHOD_TABLES'))
        self.assertTrue(hasattr(probe, 'capture_class_method_metadata'))
        base = 0x7ff600000000
        result = probe.capture_class_method_metadata(self.method_table_reader(base), base, 0x20000000)
        self.assertEqual(result['UGPGameplayStatics']['method_registration_rva'], '0x16078f50')
        self.assertEqual(result['UGPGameInstance']['method_registration_rva'], '0x16167b20')
        self.assertEqual(result['UDFMGameInstance']['method_registration_rva'], '0x15c23dd0')
        self.assertEqual(result['ADFMGameMode']['method_registration_rva'], '0x182bb3c0')

    def test_redirected_class_method_table_is_rejected(self):
        self.assertTrue(hasattr(probe, 'CLASS_METHOD_TABLES'))
        base = 0x7ff600000000
        with self.assertRaisesRegex(ValueError, 'method descriptor differs'):
            probe.capture_class_method_metadata(
                self.method_table_reader(base, changed_table=True), base, 0x20000000)

    def test_changed_class_helper_cannot_establish_method_ownership(self):
        self.assertTrue(hasattr(probe, 'CLASS_METHOD_TABLES'))
        base = 0x7ff600000000
        with self.assertRaisesRegex(ValueError, 'method helper differs'):
            probe.capture_class_method_metadata(
                self.method_table_reader(base, changed_prefix=True), base, 0x20000000)

    def test_class_code_reference_requires_its_pinned_rax_lea(self):
        body = b'\x48\x8d\x05' + struct.pack('<i', 0x200 - 0x100 - 7)
        pin = hashlib.sha256(body).hexdigest()
        probe.validate_rip_witness(body, 0x100, pin, 0x100, 0x200, opcode=b'\x48\x8d\x05')
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            probe.validate_rip_witness(body, 0x100, pin, 0x100, 0x201, opcode=b'\x48\x8d\x05')

    def test_registration_callback_reference_requires_the_r9_lea_used_by_class_metadata(self):
        body = b'\x4c\x8d\x0d' + struct.pack('<i', 0x200 - 0x100 - 7)
        pin = hashlib.sha256(body).hexdigest()
        probe.validate_rip_witness(body, 0x100, pin, 0x100, 0x200, opcode=b'\x4c\x8d\x0d')
        with self.assertRaisesRegex(ValueError, 'fixed RIP'):
            probe.validate_rip_witness(body, 0x100, pin, 0x100, 0x200, opcode=b'\x48\x8d\x05')

    def test_pinned_leaf_tail_jump_can_be_followed_without_inventing_a_body_span(self):
        prefix = b'\x48\x89\xc1\xe9' + struct.pack('<i', 0x200 - 0x103 - 5)
        self.assertTrue(hasattr(probe, 'validate_leaf_jump_witness'))
        pin = hashlib.sha256(prefix).hexdigest()
        probe.validate_leaf_jump_witness(prefix, 0x100, pin, 0x103, 0x200)
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            probe.validate_leaf_jump_witness(prefix, 0x100, pin, 0x103, 0x201)

    def test_other_branch_cannot_replace_a_leaf_tail_jump(self):
        self.assertTrue(hasattr(probe, 'validate_leaf_jump_witness'))
        prefix = b'\xe8' + struct.pack('<i', 0x200 - 0x100 - 5)
        with self.assertRaisesRegex(ValueError, 'direct E9'):
            probe.validate_leaf_jump_witness(prefix, 0x100, hashlib.sha256(prefix).hexdigest(), 0x100, 0x200)

    def test_null_checked_constructor_leaf_can_authorize_only_its_jne_target(self):
        prefix = b'\x48\x8b\x09\x48\x85\xc9\x0f\x85' + struct.pack('<i', 0x200 - 0x10c) + b'\xc3'
        pin = hashlib.sha256(prefix).hexdigest()
        probe.validate_constructor_branch_witness(prefix, 0x100, pin, 0x106, 0x200)
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            probe.validate_constructor_branch_witness(prefix, 0x100, pin, 0x106, 0x201)

    def test_changed_constructor_condition_cannot_authorize_a_followup(self):
        prefix = b'\x48\x8b\x09\x48\x85\xc9\x0f\x84' + struct.pack('<i', 0x200 - 0x10c) + b'\xc3'
        with self.assertRaisesRegex(ValueError, 'null-checked constructor'):
            probe.validate_constructor_branch_witness(prefix, 0x100, hashlib.sha256(prefix).hexdigest(), 0x106, 0x200)

    def test_changed_constructor_source_hash_cannot_authorize_a_followup(self):
        prefix = b'\x48\x8b\x09\x48\x85\xc9\x0f\x85' + struct.pack('<i', 0x200 - 0x10c) + b'\xc3'
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            probe.validate_constructor_branch_witness(prefix, 0x100, '0' * 64, 0x106, 0x200)

    def test_event_name_cell_requires_an_exact_pinned_image_load(self):
        body = b'\x48\x8b\x15' + struct.pack('<i', 0x200 - 0x100 - 7)
        pin = hashlib.sha256(body).hexdigest()
        probe.validate_image_load_witness(body, 0x100, pin, 0x100, 0x200)
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            probe.validate_image_load_witness(body, 0x100, pin, 0x100, 0x208)
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            probe.validate_image_load_witness(body[:-1] + b'\xff', 0x100, pin, 0x100, 0x200)

    def test_code_address_or_other_opcode_cannot_authorize_image_data_read(self):
        body = b'\x48\x8d\x15' + struct.pack('<i', 0x200 - 0x100 - 7)
        pin = hashlib.sha256(body).hexdigest()
        with self.assertRaisesRegex(ValueError, 'fixed RIP-relative MOV'):
            probe.validate_image_load_witness(body, 0x100, pin, 0x100, 0x200)
        with self.assertRaisesRegex(ValueError, 'fixed RIP-relative MOV'):
            probe.validate_image_load_witness(body, 0x100, pin, 0x200, 0x200)


if __name__ == '__main__':
    unittest.main()
