"""Offline RPC slices and rejection boundaries; no native camera claims."""
from dataclasses import replace
import unittest

from dfserver.legacy_ds_actor_content import (
    ActorContentBlock, read_actor_content_blocks, write_actor_content_blocks,
)
from dfserver.legacy_ds_actor_fields import (
    ClassFieldEnvelope, NormalClassFieldProfile, build_class_field_content, read_class_fields,
)
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_pc_view_target_rpc import (
    CLASS_PATH, CLIENT_FUNCTION_FLAGS, SERVER_FUNCTION_FLAGS, OBJECT_PROPERTY_VTABLE_RVA,
    PCViewTargetProfile, encode_default_view_target_parameters,
    decode_default_view_target_parameters, build_pc_view_target, decode_pc_verify_view_target_bunch,
)
from dfserver.legacy_ds_scalar_serializers import (
    NativeScalarBinding, OBJECT_SERIALIZER_RVA, SHIPPING_SHA256,
)
from dfserver.legacy_ds_wire_codec import ChannelName, WireBunch


BINDING = NativeScalarBinding(SHIPPING_SHA256, OBJECT_SERIALIZER_RVA,
                             property_vtable_rva=OBJECT_PROPERTY_VTABLE_RVA)
PROFILE = PCViewTargetProfile(CLASS_PATH, 245, 53, 85, CLIENT_FUNCTION_FLAGS,
                             SERVER_FUNCTION_FLAGS, 'a' * 64, BINDING)
FIELD_PROFILE = NormalClassFieldProfile(245, False)


def literal(octets, *, actor_present=True, transition_present=False):
    bits = 2 + len(octets) * 8
    value = int(actor_present) | (int.from_bytes(octets, 'little') << 1)
    value |= int(transition_present) << (bits - 1)
    return value.to_bytes((bits + 7) // 8, 'little'), bits


def verification(*, fields=None, blocks=None):
    if blocks is None:
        if fields is None:
            fields = (ClassFieldEnvelope(85, b'', 0),)
        blocks = (build_class_field_content(fields, profile=FIELD_PROFILE),)
    writer = BitWriter(maximum_bits=512)
    write_actor_content_blocks(writer, blocks)
    return WireBunch(2, writer.to_bytes(), writer.bit_count, reliable=True,
                     channel_sequence=200, channel_name=ChannelName(hardcoded_index=102))


class PCViewTargetCodecTests(unittest.TestCase):
    def test_guid_two_uses_two_presence_bits_and_exact_ten_bit_body(self):
        self.assertEqual(encode_default_view_target_parameters(actor_guid=2, profile=PROFILE,
            reference_resolved=True, exports_acknowledged=True), (b'\x09\x00', 10))
        self.assertEqual(decode_default_view_target_parameters(b'\x09\x00', 10,
            expected_actor_guid=2), 2)
        with self.assertRaises(ValueError):
            decode_default_view_target_parameters(b'\x09\x00', 9)

    def test_independent_packed_guid_vectors_have_no_transition_body_or_terminal(self):
        for guid, octets in ((2, b'\x04'), (126, b'\xfc'), (128, b'\x01\x02'),
                            (16384, b'\x01\x01\x02'), (0xfffffffe, b'\xfd\xff\xff\xff\x1e')):
            payload, bits = literal(octets)
            with self.subTest(guid=guid):
                self.assertEqual(encode_default_view_target_parameters(actor_guid=guid,
                    profile=PROFILE, reference_resolved=True, exports_acknowledged=True), (payload, bits))
                self.assertEqual(decode_default_view_target_parameters(payload, bits,
                    expected_actor_guid=guid), guid)

    def test_explicit_transition_absent_actor_null_static_and_mismatch_reject(self):
        invalid = [literal(b'\x04', actor_present=False), literal(b'\x04', transition_present=True)]
        invalid += [literal(raw) for raw in (b'\x00', b'\x02', b'\x06', b'\x01\x00',
                    b'\x01\x01\x01\x01\x20', b'\x01\x01\x01\x01\x01')]
        for payload, bits in invalid:
            with self.subTest(payload=payload.hex()), self.assertRaises(ValueError):
                decode_default_view_target_parameters(payload, bits)
        with self.assertRaises(ValueError):
            decode_default_view_target_parameters(b'\x09\x00', 10, expected_actor_guid=4)

    def test_every_truncation_and_following_bit_reject_with_exact_parent_eof(self):
        payload, bits = literal(b'\xfd\xff\xff\xff\x1e')
        value = int.from_bytes(payload, 'little')
        for length in range(bits):
            raw = (value & ((1 << length) - 1)).to_bytes((length + 7) // 8, 'little')
            with self.subTest(length=length), self.assertRaises(ValueError):
                decode_default_view_target_parameters(raw, length)
        for extra in (0, 1):
            raw = (9 | (extra << 10)).to_bytes(2, 'little')
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                decode_default_view_target_parameters(raw, 11)
        for payload, bits in ((b'\x09\x80', 10), (b'\x09\x00\x00', 10), (b'\x09', 10)):
            with self.assertRaises(ValueError):
                decode_default_view_target_parameters(payload, bits)

    def test_reference_resolution_exports_and_exact_scalar_types_are_required(self):
        for guid in (None, True, 2.0, '2', 0, 1, 3, -2, 0x100000000):
            with self.subTest(guid=guid), self.assertRaises(ValueError):
                encode_default_view_target_parameters(actor_guid=guid, profile=PROFILE,
                    reference_resolved=True, exports_acknowledged=True)
        for key in ('reference_resolved', 'exports_acknowledged'):
            for value in (False, None, 1, 'yes'):
                kwargs = {'reference_resolved': True, 'exports_acknowledged': True, key: value}
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    encode_default_view_target_parameters(actor_guid=2, profile=PROFILE, **kwargs)
        for bits in (True, 10.0, -1, 43):
            with self.assertRaises(ValueError):
                decode_default_view_target_parameters(b'\x09\x00', bits)
        for payload in (None, '09', bytearray(b'\x09\x00')):
            with self.assertRaises(ValueError):
                decode_default_view_target_parameters(payload, 10)
        for expected in (False, 2.0, 1, 3):
            with self.assertRaises(ValueError):
                decode_default_view_target_parameters(b'\x09\x00', 10, expected_actor_guid=expected)

    def test_profile_requires_exact_function_and_native_object_binding(self):
        for key, value in dict(class_path='/Wrong', exclusive_index_maximum=246,
                view_target_index=54, verify_index=84, client_function_flags=0x01020c40,
                server_function_flags=0x00220cc0, source_sha256='A' * 64, object_binding=None).items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                replace(PROFILE, **{key: value})
        for binding in (replace(BINDING, client_sha256='b' * 64),
                        replace(BINDING, serializer_target_rva=OBJECT_SERIALIZER_RVA + 1),
                        replace(BINDING, property_vtable_rva=OBJECT_PROPERTY_VTABLE_RVA + 8),
                        replace(BINDING, scalar_leaf_target_rva=1)):
            with self.assertRaises(ValueError):
                replace(PROFILE, object_binding=binding)
        with self.assertRaises(ValueError):
            encode_default_view_target_parameters(actor_guid=2, profile=object(),
                reference_resolved=True, exports_acknowledged=True)

    def test_build_is_one_reliable_rpc53_with_explicit_channel_and_sequence(self):
        for sequence in (0, 1023):
            bunch = build_pc_view_target(channel_index=2, channel_sequence=sequence, profile=PROFILE,
                actor_guid=2, reference_resolved=True, exports_acknowledged=True)
            self.assertEqual((bunch.channel_index, bunch.channel_sequence), (2, sequence))
            self.assertIs(bunch.reliable, True)
            self.assertFalse(any((bunch.open, bunch.close, bunch.package_exports, bunch.must_be_mapped, bunch.partial)))
            block, = read_actor_content_blocks(BitReader(bunch.payload, bit_count=bunch.payload_bits))
            field, = read_class_fields(BitReader(block.payload, bit_count=block.payload_bit_count), profile=FIELD_PROFILE)
            self.assertEqual((field.rep_index, field.payload, field.payload_bit_count), (53, b'\x09\x00', 10))

    def test_invalid_channel_and_sequence_do_not_build_a_request(self):
        for key, values in (('channel_index', (True, 2.0, 0, 1, 65536)),
                            ('channel_sequence', (False, 0.0, -1, 1024))):
            for value in values:
                kwargs = {'channel_index': 2, 'channel_sequence': 0, key: value}
                with self.assertRaises(ValueError):
                    build_pc_view_target(profile=PROFILE, actor_guid=2, reference_resolved=True,
                        exports_acknowledged=True, **kwargs)

    def test_verify_rpc_accepts_only_whole_single_empty_field85(self):
        self.assertIsNone(decode_pc_verify_view_target_bunch(verification(), channel_index=2, profile=PROFILE))
        good, other = ClassFieldEnvelope(85, b'', 0), ClassFieldEnvelope(67, b'\x09\x00', 9)
        for fields in ((), (other,), (good, other), (other, good), (good, good),
                       (ClassFieldEnvelope(85, b'\x00', 1),)):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                decode_pc_verify_view_target_bunch(verification(fields=fields), channel_index=2, profile=PROFILE)
        block = build_class_field_content((good,), profile=FIELD_PROFILE)
        for blocks in ((), (block, block), (ActorContentBlock(True, block.payload, block.payload_bit_count),)):
            with self.assertRaises(ValueError):
                decode_pc_verify_view_target_bunch(verification(blocks=blocks), channel_index=2, profile=PROFILE)

    def test_verify_rpc_rejects_flags_types_padding_truncation_and_subobject(self):
        good = verification()
        changes = dict(channel_index=3, reliable=1, channel_sequence=True, close_reason=True,
            channel_name=ChannelName(hardcoded_index=102, number=False), payload_bits=0)
        changes.update({flag: True for flag in ('open', 'close', 'flag4', 'connection_flag',
            'package_exports', 'must_be_mapped', 'partial', 'partial_initial', 'partial_final')})
        changes['payload'] = good.payload + b'\x00'
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                decode_pc_verify_view_target_bunch(replace(good, **{key: value}), channel_index=2, profile=PROFILE)
        for length in range(good.payload_bits):
            raw = (int.from_bytes(good.payload, 'little') & ((1 << length) - 1)).to_bytes((length + 7) // 8, 'little')
            with self.assertRaises(ValueError):
                decode_pc_verify_view_target_bunch(replace(good, payload=raw, payload_bits=length),
                    channel_index=2, profile=PROFILE)
        with self.assertRaises(ValueError):
            decode_pc_verify_view_target_bunch(replace(good, payload=bytes([good.payload[0] & ~2]) + good.payload[1:]),
                channel_index=2, profile=PROFILE)
        with self.assertRaises(ValueError):
            decode_pc_verify_view_target_bunch(object(), channel_index=2, profile=PROFILE)


if __name__ == '__main__':
    unittest.main()
