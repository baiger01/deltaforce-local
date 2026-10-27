from dataclasses import replace
import hashlib
import importlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from dfserver.legacy_ds_actor_content import read_actor_content_blocks
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_wire_codec import WirePacket, encode_observed_application, decode_observed_application

from dfserver.legacy_ds_game_state_start import GameStateStartProfile
from dfserver.replication import legacy_ds_game_state_start as state


CURRENT_SHA = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
PROFILE_SHA = '64e5979c79b0876f62c6e03a9ad0407a88aaff3d7b9b81ed9961c920e4c2399a'
CLASS_PATH = '/Game/BluePrints/GameModes/TestGame/BP_GameState_PVPVE.BP_GameState_PVPVE_C'
ROOT = Path(__file__).resolve().parents[3]
PROFILE_PATH = 'work/evidence/updated-minimum-actor-profile-79fb7b10.json'
HEADER_PATH = 'work/evidence/updated-enabled-actor-receiver-79fb7b10-v3.json'


class CurrentGameStateStartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (ROOT / PROFILE_PATH).read_bytes()
        cls.document = json.loads(cls.raw)
        cls.blobs = {path: (ROOT / path).read_bytes() for path in cls.document['source_pins']}
        cls.blobs[HEADER_PATH] = (ROOT / HEADER_PATH).read_bytes()
        cls.qualified = None

    def qualification(self):
        try:
            current = importlib.import_module('dfserver.replication.legacy_ds_current_actor_profile')
        except ModuleNotFoundError:
            self.fail('The separate current Actor source qualifier is not implemented')
        if type(self).qualified is None:
            type(self).qualified = current.qualify_current_actor_sources(self.raw, source_blobs=self.blobs)
        return type(self).qualified

    def profile(self):
        self.assertIn('current_qualification', GameStateStartProfile.__dataclass_fields__)
        return GameStateStartProfile(CLASS_PATH, 19, CURRENT_SHA, PROFILE_SHA,
            all_ready_handle=24, abseil_handle=107, map_id_handle=52, room_id_handle=53,
            real_start_handle=108, current_qualification=self.qualification())

    def block(self, bunch):
        block, = read_actor_content_blocks(BitReader(bunch.payload, bit_count=bunch.payload_bits))
        self.assertTrue(block.has_rep_layout)
        return block

    def test_current_build_and_compiled_source_require_explicit_current_qualification(self):
        for client, source in ((CURRENT_SHA, PROFILE_SHA), (CURRENT_SHA, 'a' * 64),
                               ('4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0', PROFILE_SHA)):
            with self.subTest(client=client, source=source):
                with self.assertRaises(ValueError):
                    GameStateStartProfile(CLASS_PATH, 19, client, source, all_ready_handle=24,
                        abseil_handle=107, map_id_handle=52, room_id_handle=53, real_start_handle=108)

    def test_four_current_boolean_stages_use_only_their_qualified_one_bit_fields(self):
        profile = self.profile()
        stages = ((state.build_game_state_start, 19, '4c0200'),
                  (state.build_game_state_all_ready, 24, '600200'),
                  (state.build_game_state_abseil, 107, 'ac0300'),
                  (state.build_game_state_real_start, 108, 'b00300'))
        for build, handle, expected in stages:
            with self.subTest(handle=handle), patch.object(state, 'write_bool_value',
                    side_effect=AssertionError('Current values must not pass historical scalar guards')):
                bunch = build(channel_index=3, channel_sequence=1023, profile=profile)
                block = self.block(bunch)
                self.assertEqual((block.payload_bit_count, block.payload.hex()), (18, expected))
                self.assertEqual((bunch.channel_index, bunch.channel_sequence, bunch.reliable), (3, 1023, True))

    def test_current_uint64_values_preserve_all_unaligned_little_endian_bits(self):
        profile = self.profile()
        for map_id, room_id in ((2201, 0xfedcba9876543210), (0, (1 << 64) - 1), ((1 << 64) - 1, 0)):
            with self.subTest(map_id=map_id, room_id=room_id), patch.object(state, 'write_uint64_value',
                    side_effect=AssertionError('Current uint64 must not pass historical scalar guards')):
                bunch = state.build_game_state_match_info(channel_index=3, channel_sequence=0,
                    profile=profile, map_id=map_id, room_id=room_id)
                block = self.block(bunch)
                expected = (104 << 1) | (map_id << 9) | (106 << 73) | (room_id << 81)
                self.assertEqual((block.payload_bit_count, block.payload), (153, expected.to_bytes(20, 'little')))
                reader = BitReader(block.payload, bit_count=block.payload_bit_count)
                self.assertFalse(reader.read_bool())
                self.assertEqual(reader.read_packed_int(), 52)
                self.assertEqual(reader.read_payload(64), map_id.to_bytes(8, 'little'))
                self.assertEqual(reader.read_packed_int(), 53)
                self.assertEqual(reader.read_payload(64), room_id.to_bytes(8, 'little'))
                self.assertEqual(reader.read_packed_int(), 0)
                self.assertEqual(reader.remaining, 0)

    def test_current_match_info_survives_actual_packet_codec_with_maximum_history(self):
        profile = self.profile()
        bunch = state.build_game_state_match_info(channel_index=3, channel_sequence=1023,
            profile=profile, map_id=2201, room_id=(1 << 64) - 1)
        packet = WirePacket(16383, 0, (0,) * 8, False, 255, None, (bunch,), 0)
        raw = encode_observed_application(packet, max_packet_bytes=1024, received_by_server=False)
        parsed = decode_observed_application(raw, max_packet_bytes=1024, received_by_server=False)
        self.assertEqual(replace(parsed.bunches[0], header_start_bit=None, payload_start_bit=None), bunch)
        self.assertEqual(encode_observed_application(parsed, max_packet_bytes=1024, received_by_server=False), raw)
        self.assertEqual(self.block(parsed.bunches[0]), self.block(bunch))

    def test_current_class_source_identity_and_complete_six_handles_cannot_be_mixed(self):
        profile = self.profile()
        for field in ('begin_play_handle', 'all_ready_handle', 'abseil_handle',
                      'map_id_handle', 'room_id_handle', 'real_start_handle'):
            for value in (None, 1, True):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    replace(profile, **{field: value})
        for changes in ({'class_path': '/Game/Other.GameState_C'}, {'source_sha256': 'a' * 64},
                        {'client_sha256': '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'},
                        {'current_qualification': None}, {'current_qualification': object()}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(profile, **changes)

    def test_current_binding_rows_refuse_historical_tables_serializers_and_missing_fields(self):
        profile = self.profile()
        original = state.current_actor_field
        def modified(name, changes):
            def read(q, role, field):
                row = original(q, role, field)
                if field != name:
                    return row
                row = dict(row)
                binding = dict(row['property_method_binding'])
                methods = [dict(method) for method in binding['methods']]
                for key, value in changes.items():
                    if key in ('0x88', '0x90'):
                        for method in methods:
                            if method['slot'] == key:
                                method['target_rva'] = value
                    else:
                        binding[key] = value
                binding['methods'] = tuple(methods)
                row['property_method_binding'] = binding
                return row
            return read
        for name, changes in (
                ('bReplicatedHasBegunPlay', {'0x90': '0x10e8ebe0'}),
                ('bMatchRealStart', {'concrete_vtable_rva': '0x15a86b80'}),
                ('MapId', {'concrete_vtable_rva': '0x1ab60db0'}),
                ('MapId', {'0x90': '0x10e5ce20'}), ('RoomId', {'0x88': '0x286c000'})):
            with self.subTest(name=name, changes=changes), patch.object(state, 'current_actor_field', modified(name, changes)):
                with self.assertRaises(ValueError):
                    profile.__post_init__()
        for row in (None, {}):
            with patch.object(state, 'current_actor_field', return_value=row):
                with self.assertRaises(ValueError):
                    profile.__post_init__()

    def test_uint64_rejects_negative_overflow_boolean_float_and_string_values(self):
        profile = self.profile()
        for value in (-1, 1 << 64, True, 1.0, '2201'):
            for target in ('map_id', 'room_id'):
                values = dict(map_id=2201, room_id=1)
                values[target] = value
                with self.subTest(target=target, value=value), self.assertRaises(ValueError):
                    state.build_game_state_match_info(channel_index=3, channel_sequence=0, profile=profile, **values)

    def test_exact_current_compiled_leaf_contains_one_bit_and_eight_byte_native_bodies(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), PROFILE_SHA)
        leaf_path = 'work/research_updated_minimum_leaf_bindings_79fb7b10_v2.json'
        leaf_raw = self.blobs[leaf_path]
        self.assertEqual(hashlib.sha256(leaf_raw).hexdigest(), self.document['source_pins'][leaf_path])
        leaf = json.loads(leaf_raw)
        bodies = {body['entry_rva']: body for body in leaf['native_functions']}
        instructions = lambda body: body.get('instructions', [row for part in body.get('fragments', []) for row in part['instructions']])
        bool_rows = {row['rva']: row for row in instructions(bodies['0x10e8e580'])}
        wrapper = {row['rva']: row for row in instructions(bodies['0x10e5c7c0'])}
        uint_rows = {row['rva']: row for row in instructions(bodies['0x286bcc0'])}
        self.assertEqual(bool_rows['0x10e8e59a']['instruction'], 'mov r8d, 1')
        self.assertEqual(bool_rows['0x10e8e5b9']['instruction'], 'call qword ptr [rax + 0x68]')
        self.assertEqual(wrapper['0x10e5c815']['instruction'], 'call qword ptr [rax + 0x88]')
        self.assertTrue(bodies['0x286bcc0']['complete_control_flow'])
        self.assertEqual(uint_rows['0x286bced']['instruction'], 'test byte ptr [r9 + 0x29], 0x20')
        self.assertEqual(uint_rows['0x286bcfd']['instruction'], 'mov r8d, 8')
        self.assertEqual(uint_rows['0x286bd03']['instruction'], 'jmp qword ptr [rax + 0x60]')


if __name__ == '__main__':
    unittest.main()
