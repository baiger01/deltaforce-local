"""Synthetic transport/profile tests; no game RPC schema or dispatch claim."""
from dataclasses import replace
import unittest

from dfserver.legacy_ds_actor_content import ActorContentBlock, write_actor_content_blocks
from dfserver.legacy_ds_actor_fields import ClassFieldEnvelope, NormalClassFieldProfile, build_class_field_content
from dfserver.legacy_ds_actor_receive import (
    ActorChannelReceiveProfile, ActorInboundReceiver, NativeRPCFieldProfile,
)
from dfserver.legacy_ds_bit_archive import BitWriter
from dfserver.legacy_ds_wire_codec import ChannelName, WireBunch, WirePacket


PATH = '/Game/Test/Controller.Controller_C'
PIN = 'ab' * 32


def field_profile(index=1, *, decoder=None, reliable=True, **overrides):
    values = dict(rep_index=index, name='SyntheticQualifiedRPC', receiver_class_path=PATH,
        descriptor_representation=1, incompatible=False,
        function_flags=0x200040, driver_role_predicate=True, access_allowed=True,
        wire_reliable=reliable, function_source_sha256=PIN,
        permission_source_sha256=PIN, parameter_schema_source_sha256=PIN,
        decoder=decoder or (lambda reader: reader.read_payload(reader.remaining)))
    values.update(overrides)
    return NativeRPCFieldProfile(**values)


def profile(channel=2, guid=2, *, fields=None, maximum=4, **overrides):
    values = dict(channel_index=channel, actor_guid=guid, class_path=PATH,
        class_cache_source_sha256=PIN, exclusive_index_maximum=maximum,
        fields=fields if fields is not None else (field_profile(),))
    values.update(overrides)
    return ActorChannelReceiveProfile(**values)


def receiver(*profiles, seed=200, window=128, budget=1024):
    return ActorInboundReceiver(profiles=profiles or (profile(),),
        initial_channel_sequence=seed, max_packet_bytes=budget, retry_window=window)


def bunch(sequence=200, *, channel=2, index=1, payload=b'', bits=0,
          reliable=True, blocks=None, maximum=4):
    if blocks is None:
        blocks = (build_class_field_content((ClassFieldEnvelope(index, payload, bits),),
            profile=NormalClassFieldProfile(maximum, False)),)
    writer = BitWriter()
    write_actor_content_blocks(writer, blocks)
    return WireBunch(channel, writer.to_bytes(), writer.bit_count, reliable=reliable,
        channel_sequence=sequence if reliable else None,
        channel_name=ChannelName(hardcoded_index=102) if reliable else None)


def packet(*bunches):
    return WirePacket(20, 9, (1,), False, 0, None, tuple(bunches), 0)


class ActorInboundReceiveTests(unittest.TestCase):
    def test_preflight_returns_clone_and_deferred_values(self):
        original = receiver()
        prepared = original.preflight_packet(packet(bunch(payload=b'\x05', bits=3)))
        self.assertIsNot(prepared.receiver, original)
        self.assertEqual(original.channel_state(2)['expected_sequence'], 200)
        self.assertEqual(prepared.receiver.channel_state(2)['expected_sequence'], 201)
        self.assertEqual(prepared.decoded_fields[0].value, b'\x05')
        self.assertNotIn("b'\\x05'", repr(prepared))

    def test_each_actor_starts_at_same_hello_sequence_independently(self):
        current = receiver(profile(2, 2), profile(4, 4))
        current = current.preflight_packet(packet(bunch())).receiver
        current = current.preflight_packet(packet(bunch(channel=4))).receiver
        self.assertEqual(current.channel_state(2)['expected_sequence'], 201)
        self.assertEqual(current.channel_state(4)['expected_sequence'], 201)
        with self.assertRaises(ValueError):
            receiver(seed=200).preflight_packet(packet(bunch(sequence=204)))

    def test_exact_reliable_retry_does_not_decode_twice_or_advance(self):
        calls = []
        spec = field_profile(decoder=lambda r: calls.append(r.remaining))
        current = receiver(profile(fields=(spec,)))
        prepared = current.preflight_packet(packet(bunch(), bunch()))
        self.assertEqual(calls, [0])
        self.assertEqual(prepared.reliable_duplicates, 1)
        retried = prepared.receiver.preflight_packet(packet(bunch()))
        self.assertEqual(calls, [0])
        self.assertEqual(retried.decoded_fields, ())
        self.assertEqual(retried.receiver.channel_state(2)['expected_sequence'], 201)

    def test_same_sequence_changed_bits_and_wrong_actor_name_rejected(self):
        current = receiver().preflight_packet(packet(bunch())).receiver
        for bad in (bunch(payload=b'\x01', bits=1),
                    replace(bunch(), channel_name=ChannelName(hardcoded_index=255))):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                current.preflight_packet(packet(bad))
        self.assertEqual(current.channel_state(2)['expected_sequence'], 201)

    def test_whole_packet_unknown_later_frame_does_not_invoke_decoder(self):
        calls = []
        original = receiver(profile(fields=(field_profile(decoder=lambda r: calls.append(1)),)))
        with self.assertRaises(ValueError):
            original.preflight_packet(packet(bunch(), bunch(sequence=201, index=2)))
        self.assertEqual(calls, [])
        self.assertEqual(original.channel_state(2)['expected_sequence'], 200)

    def test_decoder_failure_rolls_back_whole_packet_and_hides_exception(self):
        def fail(reader):
            raise RuntimeError('PRIVATE PARAMETER VALUE')
        original = receiver(profile(fields=(field_profile(1), field_profile(2, decoder=fail))))
        with self.assertRaisesRegex(ValueError, '^Qualified Actor parameter decoder failed$'):
            original.preflight_packet(packet(bunch(), bunch(sequence=201, index=2)))
        self.assertEqual(original.channel_state(2)['remembered_reliable_sequences'], ())

    def test_exact_decoder_eof_and_archive_identity_required(self):
        def alter(reader):
            reader.bit_count = 0
        for decoder in (lambda r: None, alter):
            with self.subTest(decoder=decoder), self.assertRaises(ValueError):
                receiver(profile(fields=(field_profile(decoder=decoder),))).preflight_packet(
                    packet(bunch(payload=b'\x01', bits=1)))

    def test_explicit_33_bit_decoder_never_defaults_to_float(self):
        original = receiver(profile(fields=(field_profile(decoder=lambda r: r.read_bits(33)),)))
        prepared = original.preflight_packet(packet(bunch(payload=b'\x00\x00\x00\x00\x01', bits=33)))
        self.assertEqual(prepared.decoded_fields[0].value, 1 << 32)
        self.assertIs(type(prepared.decoded_fields[0].value), int)

    def test_unreliable_field_has_no_reliable_sequence_side_effect(self):
        current = receiver(profile(fields=(field_profile(reliable=False),)))
        prepared = current.preflight_packet(packet(bunch(reliable=False, payload=b'\x01', bits=1)))
        self.assertEqual(prepared.receiver.channel_state(2)['expected_sequence'], 200)
        self.assertEqual(prepared.receiver.channel_state(2)['remembered_reliable_sequences'], ())
        self.assertEqual(len(prepared.decoded_fields), 1)
        with self.assertRaises(ValueError):
            current.preflight_packet(packet(bunch(reliable=True)))

    def test_subobject_and_replayout_are_not_accepted_as_ordinary_fields(self):
        original = receiver()
        subobject = WireBunch(2, b'\x00', 2, reliable=True, channel_sequence=200,
            channel_name=ChannelName(hardcoded_index=102))
        replayout = bunch(blocks=(ActorContentBlock(True, b'', 0),))
        for bad in (subobject, replayout):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                original.preflight_packet(packet(bad))
        self.assertEqual(original.channel_state(2)['expected_sequence'], 200)

    def test_unsupported_header_channels_and_partial_rejected(self):
        original = receiver()
        base = bunch()
        for name in ('open', 'close', 'flag4', 'connection_flag', 'package_exports',
                     'must_be_mapped', 'partial'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                original.preflight_packet(packet(replace(base, **{name: True})))
        for channel in (0, 1, 3):
            with self.subTest(channel=channel), self.assertRaises(ValueError):
                original.preflight_packet(packet(bunch(channel=channel)))

    def test_cache_sentinel_and_unknown_index_rejected(self):
        for index in (2, 3):
            with self.subTest(index=index), self.assertRaises(ValueError):
                receiver().preflight_packet(packet(bunch(index=index)))
        with self.assertRaises(ValueError):
            profile(fields=(field_profile(index=3),), maximum=4)

    def test_wrap_expected_new_sequence_wins_and_history_is_bounded(self):
        current = receiver(seed=0, window=3)
        for ordinal in range(1025):
            prepared = current.preflight_packet(packet(bunch(sequence=ordinal & 1023)))
            self.assertEqual(len(prepared.decoded_fields), 1)
            self.assertEqual(prepared.reliable_duplicates, 0)
            current = prepared.receiver
        self.assertEqual(current.channel_state(2)['expected_sequence'], 1)
        self.assertEqual(current.channel_state(2)['remembered_reliable_sequences'], (1022, 1023, 0))
        with self.assertRaises(ValueError):
            current.preflight_packet(packet(bunch(sequence=1021)))
        self.assertEqual(current.preflight_packet(packet(bunch(sequence=1023))).reliable_duplicates, 1)

    def test_out_of_order_and_ambiguous_half_ring_are_not_resynchronized(self):
        for seq in (199, 201, (200 + 512) & 1023):
            with self.subTest(seq=seq), self.assertRaises(ValueError):
                receiver().preflight_packet(packet(bunch(sequence=seq)))

    def test_complete_packet_budget_before_any_decoder(self):
        calls = []
        original = receiver(profile(fields=(field_profile(decoder=lambda r: calls.append(1)),)), budget=16)
        with self.assertRaises(ValueError):
            original.preflight_packet(packet(bunch(), bunch(sequence=201)))
        self.assertEqual(calls, [])

    def test_bool_alias_missing_pins_and_native_direction_rejected(self):
        for overrides in ({'rep_index': True}, {'function_flags': True},
                          {'function_flags': 0x200000}, {'function_flags': 0x40},
                          {'access_allowed': False}, {'wire_reliable': 1},
                          {'parameter_schema_source_sha256': ''}, {'descriptor_representation': 0},
                          {'descriptor_representation': True}, {'incompatible': True}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                field_profile(**overrides)
        with self.assertRaises(ValueError):
            replace(field_profile(), decoder=None)
        for overrides in ({'channel_index': True}, {'actor_guid': 3},
                          {'class_cache_source_sha256': ''}, {'exclusive_index_maximum': True}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                profile(**overrides)
        for kwargs in ({'initial_channel_sequence': True}, {'retry_window': 512}, {'max_packet_bytes': 0}):
            values = dict(profiles=(profile(),), initial_channel_sequence=200,
                          max_packet_bytes=1024, retry_window=128)
            values.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                ActorInboundReceiver(**values)

    def test_profile_class_duplicate_channel_and_guid_rejected(self):
        with self.assertRaises(ValueError):
            profile(fields=(field_profile(receiver_class_path='/Script/Test.Other'),))
        for profiles in ((profile(), profile(2, 4)), (profile(), profile(4, 2))):
            with self.subTest(profiles=profiles), self.assertRaises(ValueError):
                receiver(*profiles)

    def test_public_frozen_dataclass_bypass_revalidated_before_use(self):
        spec = field_profile()
        original = receiver(profile(fields=(spec,)))
        object.__setattr__(spec, 'function_flags', 0)
        with self.assertRaises(ValueError):
            original.preflight_packet(packet(bunch()))
        self.assertEqual(original.channel_state(2)['expected_sequence'], 200)


if __name__ == '__main__':
    unittest.main()
