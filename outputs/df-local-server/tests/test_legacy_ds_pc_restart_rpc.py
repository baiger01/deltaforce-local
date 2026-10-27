"""Offline literal RPC slices; transport construction is not native possession."""
from dataclasses import replace
import unittest

from dfserver.legacy_ds_actor_content import (
    ActorContentBlock, read_actor_content_blocks, write_actor_content_blocks,
)
from dfserver.legacy_ds_actor_fields import (
    ClassFieldEnvelope, NormalClassFieldProfile, build_class_field_content,
    read_class_fields,
)
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_pc_restart_rpc import (
    CLASS_PATH, CLIENT_FUNCTION_FLAGS, SERVER_FUNCTION_FLAGS,
    OBJECT_PROPERTY_VTABLE_RVA, PCRestartProfile, encode_pawn_parameter,
    decode_pawn_parameter, build_pc_restart, decode_pc_possession_ack_bunch,
)
from dfserver.legacy_ds_scalar_serializers import (
    NativeScalarBinding, OBJECT_SERIALIZER_RVA, SHIPPING_SHA256,
)
from dfserver.legacy_ds_wire_codec import ChannelName, WireBunch


BINDING = NativeScalarBinding(SHIPPING_SHA256, OBJECT_SERIALIZER_RVA,
    property_vtable_rva=OBJECT_PROPERTY_VTABLE_RVA)
PROFILE = PCRestartProfile(CLASS_PATH, 245, 42, 67,
    CLIENT_FUNCTION_FLAGS, SERVER_FUNCTION_FLAGS, 'a' * 64, BINDING)
FIELD_PROFILE = NormalClassFieldProfile(245, False)


def literal_parameter(octets, *, present=True):
    """Place presence and independently specified packed octets as bit literals."""
    value = (int.from_bytes(octets, 'little') << 1) | int(present)
    bits = 1 + 8 * len(octets)
    return value.to_bytes((bits + 7) // 8, 'little'), bits


def acknowledgement(*, fields=None, blocks=None, sequence=200):
    if blocks is None:
        if fields is None:
            fields = (ClassFieldEnvelope(67, b'\x09\x00', 9),)
        blocks = (build_class_field_content(fields, profile=FIELD_PROFILE),)
    writer = BitWriter(maximum_bits=512)
    write_actor_content_blocks(writer, blocks)
    return WireBunch(2, writer.to_bytes(), writer.bit_count, reliable=True,
        channel_sequence=sequence, channel_name=ChannelName(hardcoded_index=102))


class PCRestartCodecTests(unittest.TestCase):
    def test_presence_then_guid_two_is_independent_nine_bit_literal(self):
        self.assertEqual(encode_pawn_parameter(pawn_guid=2, profile=PROFILE,
            reference_resolved=True, exports_acknowledged=True), (b'\x09\x00', 9))
        self.assertEqual(decode_pawn_parameter(b'\x09\x00', 9,
            expected_pawn_guid=2), 2)

    def test_packed_width_boundaries_use_no_property_handle_or_terminator(self):
        vectors = ((2, b'\x04'), (126, b'\xfc'), (128, b'\x01\x02'),
            (16382, b'\xfd\xfe'), (16384, b'\x01\x01\x02'),
            (0xfffffffe, b'\xfd\xff\xff\xff\x1e'))
        for guid, octets in vectors:
            with self.subTest(guid=guid):
                payload, bits = literal_parameter(octets)
                self.assertEqual(encode_pawn_parameter(pawn_guid=guid, profile=PROFILE,
                    reference_resolved=True, exports_acknowledged=True), (payload, bits))
                self.assertEqual(decode_pawn_parameter(payload, bits,
                    expected_pawn_guid=guid), guid)

    def test_every_truncation_and_extra_field_bit_are_rejected(self):
        payload, bits = literal_parameter(b'\xfd\xff\xff\xff\x1e')
        for length in range(bits):
            with self.subTest(length=length), self.assertRaises(ValueError):
                decode_pawn_parameter(payload[:(length + 7) // 8], length)
        for extra in (0, 1):
            data = ((9 | (extra << 9))).to_bytes(2, 'little')
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                decode_pawn_parameter(data, 10)

    def test_absent_null_default_static_and_overflow_are_not_confirmation(self):
        invalid = [(b'\x00', 1)]
        invalid.extend(literal_parameter(raw) for raw in (
            b'\x00', b'\x02', b'\x06', b'\x01\x01\x01\x01\x20',
            b'\x01\x01\x01\x01\x01'))
        for payload, bits in invalid:
            with self.subTest(payload=payload.hex()), self.assertRaises(ValueError):
                decode_pawn_parameter(payload, bits)

    def test_reference_contracts_and_exact_guid_types_are_mandatory(self):
        for guid in (None, True, False, 2.0, '2', 0, 1, 3, -2, 0x100000000):
            with self.subTest(guid=guid), self.assertRaises(ValueError):
                encode_pawn_parameter(pawn_guid=guid, profile=PROFILE,
                    reference_resolved=True, exports_acknowledged=True)
        for key in ('reference_resolved', 'exports_acknowledged'):
            for value in (False, None, 1, 'yes'):
                kwargs = dict(reference_resolved=True, exports_acknowledged=True)
                kwargs[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    encode_pawn_parameter(pawn_guid=2, profile=PROFILE, **kwargs)
        for bits in (True, 9.0, '9', -1, 42):
            with self.subTest(bits=bits), self.assertRaises(ValueError):
                decode_pawn_parameter(b'\x09\x00', bits)
        for expected in (True, 2.0, 0, 1, 3, 4):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                decode_pawn_parameter(b'\x09\x00', 9, expected_pawn_guid=expected)
        for payload in (None, '09', bytearray(b'\x09\x00')):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                decode_pawn_parameter(payload, 9)

    def test_profile_requires_exact_declaration_build_and_property_binding(self):
        changes = dict(class_path='/Wrong', exclusive_index_maximum=246,
            restart_index=43, acknowledgement_index=68, client_function_flags=0x40,
            server_function_flags=0x220cc0, source_sha256='A' * 64,
            object_binding=None)
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                replace(PROFILE, **{key: value})
        for key in ('exclusive_index_maximum', 'restart_index', 'acknowledgement_index',
                    'client_function_flags', 'server_function_flags'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                replace(PROFILE, **{key: float(getattr(PROFILE, key))})
        for binding in (replace(BINDING, client_sha256='b' * 64),
                replace(BINDING, serializer_target_rva=OBJECT_SERIALIZER_RVA + 1),
                replace(BINDING, property_vtable_rva=OBJECT_PROPERTY_VTABLE_RVA + 8),
                replace(BINDING, scalar_leaf_target_rva=0x286bf70)):
            with self.subTest(binding=binding), self.assertRaises(ValueError):
                replace(PROFILE, object_binding=binding)
        with self.assertRaises(ValueError):
            encode_pawn_parameter(pawn_guid=2, profile=object(),
                reference_resolved=True, exports_acknowledged=True)

    def test_restart_has_one_reliable_actor_rpc_on_explicit_channel_and_sequence(self):
        for sequence in (0, 1023):
            bunch = build_pc_restart(channel_index=2, channel_sequence=sequence,
                profile=PROFILE, pawn_guid=2, reference_resolved=True,
                exports_acknowledged=True)
            self.assertEqual((bunch.channel_index, bunch.channel_sequence), (2, sequence))
            self.assertIs(bunch.reliable, True)
            self.assertEqual(bunch.channel_name, ChannelName(hardcoded_index=102))
            self.assertFalse(any((bunch.open, bunch.close, bunch.package_exports,
                bunch.partial, bunch.must_be_mapped)))
            reader = BitReader(bunch.payload, bit_count=bunch.payload_bits)
            block, = read_actor_content_blocks(reader)
            self.assertEqual(reader.remaining, 0)
            self.assertIs(block.has_rep_layout, False)
            field, = read_class_fields(BitReader(block.payload,
                bit_count=block.payload_bit_count), profile=FIELD_PROFILE)
            self.assertEqual((field.rep_index, field.payload, field.payload_bit_count),
                (42, b'\x09\x00', 9))

    def test_invalid_channel_and_reliable_sequence_are_rejected(self):
        for channel in (True, 2.0, 0, 1, 65536):
            with self.subTest(channel=channel), self.assertRaises(ValueError):
                build_pc_restart(channel_index=channel, channel_sequence=0,
                    profile=PROFILE, pawn_guid=2, reference_resolved=True,
                    exports_acknowledged=True)
        for sequence in (False, 0.0, -1, 1024):
            with self.subTest(sequence=sequence), self.assertRaises(ValueError):
                build_pc_restart(channel_index=2, channel_sequence=sequence,
                    profile=PROFILE, pawn_guid=2, reference_resolved=True,
                    exports_acknowledged=True)

    def test_acknowledgement_accepts_only_expected_pawn_and_whole_rpc(self):
        self.assertEqual(decode_pc_possession_ack_bunch(acknowledgement(),
            channel_index=2, profile=PROFILE, expected_pawn_guid=2), 2)
        for expected in (None, True, 2.0, 0, 3, 4):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                decode_pc_possession_ack_bunch(acknowledgement(), channel_index=2,
                    profile=PROFILE, expected_pawn_guid=expected)
        good = ClassFieldEnvelope(67, b'\x09\x00', 9)
        unrelated = ClassFieldEnvelope(79, b'', 0)
        for fields in ((), (unrelated,), (good, unrelated), (unrelated, good), (good, good)):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                decode_pc_possession_ack_bunch(acknowledgement(fields=fields),
                    channel_index=2, profile=PROFILE, expected_pawn_guid=2)
        block = build_class_field_content((good,), profile=FIELD_PROFILE)
        for blocks in ((), (block, block), (ActorContentBlock(True, block.payload,
                block.payload_bit_count),)):
            with self.subTest(blocks=blocks), self.assertRaises(ValueError):
                decode_pc_possession_ack_bunch(acknowledgement(blocks=blocks),
                    channel_index=2, profile=PROFILE, expected_pawn_guid=2)

    def test_ack_bunch_rejects_lifecycle_flags_wrong_kind_and_truncated_envelopes(self):
        good = acknowledgement()
        changes = dict(channel_index=4, reliable=False, channel_sequence=True,
            channel_name=ChannelName(hardcoded_index=103), payload_bits=0)
        for flag in ('open', 'close', 'flag4', 'connection_flag', 'package_exports',
                'must_be_mapped', 'partial', 'partial_initial', 'partial_final'):
            changes[flag] = True
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                decode_pc_possession_ack_bunch(replace(good, **{key: value}),
                    channel_index=2, profile=PROFILE, expected_pawn_guid=2)
        for length in range(good.payload_bits):
            with self.subTest(length=length), self.assertRaises(ValueError):
                decode_pc_possession_ack_bunch(replace(good, payload_bits=length),
                    channel_index=2, profile=PROFILE, expected_pawn_guid=2)
        with self.assertRaises(ValueError):
            decode_pc_possession_ack_bunch(object(), channel_index=2,
                profile=PROFILE, expected_pawn_guid=2)


if __name__ == '__main__':
    unittest.main()
