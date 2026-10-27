from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct
import unittest

from dfserver.legacy_ds_actor_content import read_actor_content_blocks, write_actor_content_blocks
from dfserver.legacy_ds_actor_fields import ClassFieldEnvelope, NormalClassFieldProfile, build_class_field_content, read_class_fields
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_pc_ping_receiver import PCPingProfile, build_pc_ping_reply, decode_pc_ping_bunches
from dfserver.legacy_ds_pc_restart_rpc import PCRestartProfile, encode_pawn_parameter, build_pc_restart, decode_pc_possession_ack_bunch
from dfserver.legacy_ds_pc_rotation_rpc import PCRotationProfile, encode_rotation_parameters
import dfserver.legacy_ds_pc_startup_rpc as startup
import dfserver.legacy_ds_pc_view_target_rpc as view
import dfserver.transport.native.legacy_ds_current_pc_rpc_profile as current_profile
from dfserver.legacy_ds_rotator import CompressedRotator16
from dfserver.legacy_ds_scalar_serializers import NativeScalarBinding
from dfserver.legacy_ds_wire_codec import ChannelName, WireBunch, WirePacket, encode_observed_application, decode_observed_application


ROOT = Path(__file__).resolve().parents[3]
REPORT_PATH = 'work/research_updated_minimum_rpc_declarations_79fb7b10_v1.json'
REPORT_SHA = '246c6bdbf856f638c84d3f8916ac41773c38c8f7e53b8e1fcc25e657c52a9909'
CURRENT_SHA = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
RECEIVE_PATH = 'work/research_updated_rpc_receive_79fb7b10_v2.json'
RECEIVE_SHA = '7463766d9602b3b96bbaa2451bcdc5c4580142f9de00463db502b5ee39c8022c'
PC_PATH = '/Game/BluePrints/Characters/BP_DFMPlayerController.BP_DFMPlayerController_C'
CURRENT_BINDING = NativeScalarBinding(CURRENT_SHA, 0x10e8e6c0, None, 0x15a86a90)
OLD_BINDING = NativeScalarBinding('4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0',
                                0x10e8ed20, None, 0x15a86b80)


def rpc(index, payload=b'', bits=0, *, reliable=True, maximum=244):
    block = build_class_field_content((ClassFieldEnvelope(index, payload, bits),),
        profile=NormalClassFieldProfile(maximum, False))
    writer = BitWriter(maximum_bits=4096)
    write_actor_content_blocks(writer, (block,))
    return WireBunch(2, writer.to_bytes(), writer.bit_count, reliable=reliable,
        channel_sequence=1023 if reliable else None,
        channel_name=ChannelName(hardcoded_index=102) if reliable else None)


def field_from(bunch, maximum=244):
    block, = read_actor_content_blocks(BitReader(bunch.payload, bit_count=bunch.payload_bits))
    field, = read_class_fields(BitReader(block.payload, bit_count=block.payload_bit_count),
        profile=NormalClassFieldProfile(maximum, False))
    return field


class CurrentPCRPCProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report_raw = (ROOT / REPORT_PATH).read_bytes()
        cls.report = json.loads(cls.report_raw)
        cls.blobs = {p: (ROOT / p).read_bytes() for key in ('source_inputs', 'source_pins')
                     for p in cls.report[key]}
        cls.receive_raw = (ROOT / RECEIVE_PATH).read_bytes()
        cls.receive = json.loads(cls.receive_raw)
        cls.blobs.update({p: (ROOT / p).read_bytes() for key in ('source_inputs', 'source_pins')
                          for p in cls.receive[key] if p != REPORT_PATH})
        cls.blobs[RECEIVE_PATH] = cls.receive_raw
        cls.qualified = None

    def qualification(self):
        factory = getattr(startup, 'qualify_current_pc_rpc_sources', None)
        self.assertTrue(callable(factory), 'Explicit current PC RPC source qualification is missing')
        if type(self).qualified is None:
            type(self).qualified = factory(self.report_raw, source_blobs=self.blobs)
        return type(self).qualified

    def test_declarations_alone_cannot_qualify_current_rpc_recipes(self):
        factory = getattr(startup, 'qualify_current_pc_rpc_sources', None)
        self.assertTrue(callable(factory))
        declarations_only = {p: self.blobs[p] for key in ('source_inputs', 'source_pins')
                             for p in self.report[key]}
        with self.assertRaises(ValueError):
            factory(self.report_raw, source_blobs=declarations_only)

    def test_receiver_certificate_is_the_corrected_v2_guard_ownership_contract(self):
        self.assertEqual(current_profile.CURRENT_RPC_RECEIVE_SOURCE_PATH,
                         'work/research_updated_rpc_receive_79fb7b10_v2.json')
        self.assertEqual(current_profile.CURRENT_RPC_RECEIVE_SOURCE_SHA256,
                         '7463766d9602b3b96bbaa2451bcdc5c4580142f9de00463db502b5ee39c8022c')
        receive = json.loads((ROOT / current_profile.CURRENT_RPC_RECEIVE_SOURCE_PATH).read_bytes())
        self.assertEqual(receive['ordinary_receive_model']['guard'],
            'Channel connection at channel+0x28: connection byte+0xb4 bit0 clear OR channel byte+0xb0 nonzero; '
            'the selected ordinary connection path must establish this guard.')
        wrong = dict(self.blobs)
        wrong[RECEIVE_PATH] = (ROOT / 'work/research_updated_rpc_receive_79fb7b10_v1.json').read_bytes()
        with self.assertRaises(ValueError):
            startup.qualify_current_pc_rpc_sources(self.report_raw, source_blobs=wrong)

    def test_receiver_certificate_matches_every_current_body_length_and_loading_guard(self):
        q = self.qualification()
        self.assertIs(getattr(q, 'current_rpc_parameter_traversal_qualified', None), True)
        self.assertIs(getattr(q, 'selected_connection_archive_context_qualified', None), False)
        self.assertIs(getattr(q, 'selected_package_map_reference_dispatch_qualified', None), False)
        receive = json.loads((ROOT / RECEIVE_PATH).read_bytes())
        self.assertEqual(receive['derived_wire_shapes']['ServerBouncePing']['bits'], 225)
        self.assertEqual(receive['derived_wire_shapes']['ClientReturnPing']['bits'], 161)
        self.assertEqual(receive['derived_wire_shapes']['ClientSetViewTarget']['transition_present_bits'], 69)
        self.assertFalse(receive['derived_wire_shapes']['ClientSetViewTarget']['constructor_default_omission_qualified'])
        profile = self.profiles()[4]
        for axes in ((0, 0, 0), (1, 0, 0), (1, 2, 0), (1, 2, 65535)):
            for reset in (False, True):
                _, bits = encode_rotation_parameters(profile=profile,
                    rotation=CompressedRotator16(axes), reset_camera=reset)
                self.assertEqual(bits, 5 + 16 * sum(axis != 0 for axis in axes))

    def profiles(self):
        q = self.qualification()
        requests = tuple(startup.PCStartupField(n, i, k) for n, i, k in (
            ('ServerShortTimeout', 79, 'empty'), ('Server_RcvACWorldTime', 150, 'float32'),
            ('ServerFieldOfView', 216, 'float32'), ('NotifySeamlessLoginReady', 141, 'bool')))
        return (
            startup.PCStartupProfile(PC_PATH, 244, requests, 131, REPORT_SHA, current_qualification=q),
            PCPingProfile(PC_PATH, 244, 151, 138, REPORT_SHA, current_qualification=q),
            PCRestartProfile(PC_PATH, 244, 42, 67, 0x01020cc0, 0x80220cc0, REPORT_SHA,
                             CURRENT_BINDING, current_qualification=q),
            view.PCViewTargetProfile(PC_PATH, 244, 53, 85, 0x01020cc0, 0x80220cc0,
                                    REPORT_SHA, CURRENT_BINDING, current_qualification=q),
            PCRotationProfile(PC_PATH, 244, 14, 0x01820cc0, REPORT_SHA, current_qualification=q))

    def test_exact_report_and_every_direct_input_and_helper_pin_are_required(self):
        q = self.qualification()
        self.assertEqual(q.client_sha256, CURRENT_SHA)
        self.assertEqual(q.source_sha256, REPORT_SHA)
        self.assertFalse(q.native_acceptance_verified)
        self.assertFalse(q.runtime_native_cache_observed)
        expected = {REPORT_PATH: REPORT_SHA, **self.report['source_inputs'], **self.report['source_pins']}
        expected.update({RECEIVE_PATH: RECEIVE_SHA, **self.receive['source_inputs'], **self.receive['source_pins']})
        self.assertEqual(dict(q.source_pins), expected)
        self.assertEqual(q.summary()['validated_source_pins'], expected)
        factory = startup.qualify_current_pc_rpc_sources
        for path in self.blobs:
            with self.subTest(path=path):
                wrong = dict(self.blobs)
                wrong[path] += b' '
                with self.assertRaises(ValueError):
                    factory(self.report_raw, source_blobs=wrong)
                missing = dict(self.blobs)
                del missing[path]
                with self.assertRaises(ValueError):
                    factory(self.report_raw, source_blobs=missing)
        with self.assertRaises(ValueError):
            factory(self.report_raw + b' ', source_blobs=self.blobs)

    def test_current_and_historical_profile_bindings_cannot_be_mixed(self):
        profiles = self.profiles()
        for profile in profiles:
            for changes in ({'exclusive_index_maximum': 245}, {'source_sha256': 'a' * 64},
                            {'current_qualification': None}, {'current_qualification': object()}):
                with self.subTest(profile=type(profile).__name__, changes=changes):
                    with self.assertRaises(ValueError):
                        replace(profile, **changes)
        for profile in profiles[2:4]:
            for binding in (OLD_BINDING, replace(CURRENT_BINDING, serializer_target_rva=0x10e8ed20),
                            replace(CURRENT_BINDING, property_vtable_rva=0x15a86b80)):
                with self.assertRaises(ValueError):
                    replace(profile, object_binding=binding)
        with self.assertRaises(ValueError):
            replace(profiles[0], requests=tuple(replace(f, rep_index=149)
                if f.name == 'Server_RcvACWorldTime' else f for f in profiles[0].requests))
        with self.assertRaises(ValueError):
            replace(profiles[1], request_index=150)

    def test_current_startup_presence_rules_and_empty_ack(self):
        profile = self.profiles()[0]
        for index, payload, bits, expected in ((79, b'', 0, None), (141, b'\x00', 1, False),
                (141, b'\x01', 1, True), (150, b'\x00', 1, 0.0)):
            value, = startup.decode_pc_startup_bunch(rpc(index, payload, bits), channel_index=2, profile=profile)
            self.assertEqual(value.value, expected)
        raw = int.from_bytes(struct.pack('<f', 90.0), 'little') * 2 + 1
        value, = startup.decode_pc_startup_bunch(rpc(216, raw.to_bytes(5, 'little'), 33), channel_index=2, profile=profile)
        self.assertEqual(value.value, 90.0)
        field = field_from(startup.build_pc_ready_ack(channel_index=2, channel_sequence=0, profile=profile))
        self.assertEqual((field.rep_index, field.payload, field.payload_bit_count), (131, b'', 0))
        with self.assertRaises(ValueError):
            startup.decode_pc_startup_bunch(rpc(141, b'\x03', 2), channel_index=2, profile=profile)

    def test_nested_ping_is_flattened_once_and_reply_preserves_double_double_float_order(self):
        profile = self.profiles()[1]
        raw = struct.pack('<dfffff', 123.5, 1.0, 2.0, 3.0, 4.0, 5.0)
        payload = ((int.from_bytes(raw, 'little') << 1) | 1).to_bytes(29, 'little')
        params, = decode_pc_ping_bunches((rpc(151, payload, 225, reliable=False),),
            channel_index=2, profile=profile)
        self.assertEqual(tuple(getattr(params, k) for k in params.__dataclass_fields__),
                         (123.5, 1.0, 2.0, 3.0, 4.0, 5.0))
        field = field_from(build_pc_ping_reply(params, channel_index=2, profile=profile,
                                               world_seconds=7.0, delta_seconds=0.125))
        expected = ((int.from_bytes(struct.pack('<ddf', 123.5, 0.125, 7.0), 'little') << 1) | 1)
        self.assertEqual((field.rep_index, field.payload_bit_count), (138, 161))
        self.assertEqual(int.from_bytes(field.payload, 'little'), expected)
        with self.assertRaises(ValueError):
            decode_pc_ping_bunches((rpc(151, payload, 224, reliable=False),), channel_index=2, profile=profile)

    def test_restart_object_presence_and_packed_guid_survive_actual_packet_roundtrip(self):
        profile = self.profiles()[2]
        payload, bits = encode_pawn_parameter(pawn_guid=258, profile=profile,
            reference_resolved=True, exports_acknowledged=True)
        # Native packed-int bytes for258 are05 04, preceded by the RPC presence bit.
        self.assertEqual((payload, bits), (b'\x0b\x08\x00', 17))
        bunch = build_pc_restart(channel_index=2, channel_sequence=1023, profile=profile,
            pawn_guid=258, reference_resolved=True, exports_acknowledged=True)
        packet = WirePacket(16383, 0, (0,) * 8, False, 255, None, (bunch,), 0)
        decoded = decode_observed_application(encode_observed_application(packet, max_packet_bytes=1024,
            received_by_server=False), max_packet_bytes=1024, received_by_server=False)
        field = field_from(decoded.bunches[0])
        self.assertEqual((field.rep_index, field.payload, field.payload_bit_count), (42, payload, bits))
        self.assertEqual(decode_pc_possession_ack_bunch(rpc(67, payload, bits), channel_index=2,
            profile=profile, expected_pawn_guid=258), 258)
        for resolved, acknowledged in ((False, True), (True, False)):
            with self.assertRaises(ValueError):
                encode_pawn_parameter(pawn_guid=258, profile=profile,
                    reference_resolved=resolved, exports_acknowledged=acknowledged)

    def test_current_view_target_requires_explicit_transition_and_uses_three_enum_bits(self):
        profile = self.profiles()[3]
        transition_type = getattr(view, 'PCViewTargetTransition', None)
        self.assertTrue(callable(transition_type), 'Current explicit view transition is missing')
        transition = transition_type(0.25, 4, 2.0, True)
        bunch = view.build_pc_view_target(channel_index=2, channel_sequence=0, profile=profile,
            actor_guid=2, reference_resolved=True, exports_acknowledged=True, transition=transition)
        field = field_from(bunch)
        self.assertEqual(field.rep_index, 53)
        reader = BitReader(field.payload, bit_count=field.payload_bit_count)
        self.assertTrue(reader.read_bool())
        self.assertEqual(reader.read_packed_int(), 2)
        self.assertTrue(reader.read_bool())
        self.assertEqual(struct.unpack('<f', reader.read_payload(32))[0], 0.25)
        self.assertEqual(reader.read_bits(3), 4)
        self.assertEqual(struct.unpack('<f', reader.read_payload(32))[0], 2.0)
        self.assertTrue(reader.read_bool())
        self.assertEqual(reader.remaining, 0)
        self.assertEqual(field.payload_bit_count, 78)
        with self.assertRaises(ValueError):
            view.build_pc_view_target(channel_index=2, channel_sequence=0, profile=profile,
                actor_guid=2, reference_resolved=True, exports_acknowledged=True)
        for enum in (-1, 5, 7, True):
            with self.assertRaises(ValueError):
                view.build_pc_view_target(channel_index=2, channel_sequence=0, profile=profile,
                    actor_guid=2, reference_resolved=True, exports_acknowledged=True,
                    transition=transition_type(0.25, enum, 2.0, False))

    def test_explicit_transition_can_be_bound_in_profile_for_the_existing_sender_interface(self):
        profile = self.profiles()[3]
        self.assertIn('current_transition', profile.__dataclass_fields__)
        transition = view.PCViewTargetTransition(0.0, 1, 2.0, False)
        profile = replace(profile, current_transition=transition)
        implicit_argument = view.build_pc_view_target(channel_index=2, channel_sequence=0, profile=profile,
            actor_guid=2, reference_resolved=True, exports_acknowledged=True)
        explicit_argument = view.build_pc_view_target(channel_index=2, channel_sequence=0, profile=profile,
            actor_guid=2, reference_resolved=True, exports_acknowledged=True, transition=transition)
        self.assertEqual(implicit_argument, explicit_argument)
        with self.assertRaises(ValueError):
            replace(profile, current_qualification=None, exclusive_index_maximum=245,
                source_sha256='a' * 64, object_binding=OLD_BINDING)

    def test_current_transition_rejects_nonfinite_non_float32_and_boolean_scalar_values(self):
        profile = self.profiles()[3]
        transition_type = view.PCViewTargetTransition
        for value in (float('nan'), float('inf'), 1e300, 10 ** 1000, True):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(ValueError):
                    view.build_pc_view_target(channel_index=2, channel_sequence=0, profile=profile,
                        actor_guid=2, reference_resolved=True, exports_acknowledged=True,
                        transition=transition_type(value, 1, 2.0, False))

    def test_current_rotation_keeps_struct_presence_then_three_short_axes_then_direct_bool(self):
        profile = self.profiles()[4]
        payload, bits = encode_rotation_parameters(profile=profile,
            rotation=CompressedRotator16((1, 0, 65535)), reset_camera=True)
        reader = BitReader(payload, bit_count=bits)
        self.assertTrue(reader.read_bool())
        self.assertTrue(reader.read_bool())
        self.assertEqual(reader.read_bits(16), 1)
        self.assertFalse(reader.read_bool())
        self.assertTrue(reader.read_bool())
        self.assertEqual(reader.read_bits(16), 65535)
        self.assertTrue(reader.read_bool())
        self.assertEqual(reader.remaining, 0)
        self.assertEqual(bits, 37)

    def test_current_profile_source_evidence_has_complete_ordered_parameter_shapes(self):
        self.qualification()
        self.assertEqual(hashlib.sha256(self.report_raw).hexdigest(), REPORT_SHA)
        functions = {f['name']: f for f in self.report['functions']}
        self.assertEqual(len(functions), 12)
        self.assertEqual({f['exclusive_cache_index_maximum'] for f in functions.values()}, {244})
        self.assertEqual([(f['name'], f['kind']) for f in functions['ClientSetViewTarget']['declaration']['parameters']['fields']],
                         [('A', 'FObjectProperty'), ('TransitionParams', 'FStructProperty')])
        self.assertEqual([(f['name'], f['kind']) for f in functions['ClientSetRotation']['declaration']['parameters']['fields']],
                         [('NewRotation', 'FStructProperty'), ('bResetCamera', 'FBoolProperty')])


if __name__ == '__main__':
    unittest.main()
