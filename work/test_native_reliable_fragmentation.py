"""Offline packet-codec and independent receiver checks for reliable splitting."""
from dataclasses import replace
import hashlib
import importlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "outputs/df-local-server"))
sys.path.insert(0, str(ROOT / "work"))

from dfserver.transport.native.legacy_ds_wire_codec import (
    ChannelName, WireBunch, WirePacket, encode_observed_application,
    decode_observed_application)
from dfserver.transport.native.legacy_ds_decoded_bunch import (
    DecodedBunch, DecodedBunchReceiver, OPEN, CLOSE, RELIABLE, PARTIAL, INITIAL, FINAL)

try:
    fragmentation = importlib.import_module("native_reliable_fragmentation")
except ModuleNotFoundError as error:
    if error.name != "native_reliable_fragmentation":
        raise
    fragmentation = None

MAX_PACKET = 1024
EXPLICIT_OVERHEAD = 17  # Test input, not a recovered live connection value.


def payload(bit_count):
    data = bytearray((i * 37 + 11) & 255 for i in range((bit_count + 7) // 8))
    if bit_count % 8:
        data[-1] &= (1 << (bit_count % 8)) - 1
    return bytes(data)


def actor_bunch(bit_count, **changes):
    return replace(WireBunch(7, payload(bit_count), bit_count, reliable=True,
        channel_sequence=1023, channel_name=ChannelName(text="Actor")), **changes)


def packet_roundtrip(fragment, packet_id=1):
    packet = WirePacket(packet_id, 0, (0xffffffff,) * 8, True, 255, 255,
        (fragment,), 0)
    encoded = encode_observed_application(packet, max_packet_bytes=MAX_PACKET,
        received_by_server=False)
    decoded = decode_observed_application(encoded, max_packet_bytes=MAX_PACKET,
        received_by_server=False)
    return encoded, decoded.bunches[0]


def receive_wire(receiver, fragment, packet_id):
    # The wire's ten-bit value is expanded before the independent raw-bunch
    # receiver, as in the qualified ordinary receive path.
    absolute = receiver.in_reliable + ((fragment.channel_sequence - receiver.in_reliable + 512) % 1024) - 512
    flags = sum(mask for field, mask in (("open", OPEN), ("close", CLOSE),
        ("reliable", RELIABLE), ("partial", PARTIAL), ("partial_initial", INITIAL),
        ("partial_final", FINAL)) if getattr(fragment, field))
    return receiver.receive(DecodedBunch(absolute, packet_id, flags,
        fragment.payload, fragment.payload_bits, close_reason=fragment.close_reason))


class ReliableFragmentationTests(unittest.TestCase):
    def split(self, bunch, **changes):
        self.assertIsNotNone(fragmentation, "The outgoing reliable fragmentation helper is missing")
        options = dict(max_packet_bytes=MAX_PACKET,
            connection_overhead_bits=EXPLICIT_OVERHEAD)
        options.update(changes)
        return fragmentation.split_reliable_bunch(bunch, **options)

    def test_known_large_objects_roundtrip_and_reassemble_across_sequence_wrap(self):
        for bit_count, sizes in ((8240, [7608, 632]), (16670, [7608, 7608, 1454])):
            with self.subTest(payload_bits=bit_count):
                original = actor_bunch(bit_count)
                fragments = self.split(original)
                self.assertIsInstance(fragments, tuple)
                self.assertEqual([b.payload_bits for b in fragments], sizes)
                self.assertEqual([b.channel_sequence for b in fragments],
                    [(1023 + i) % 1024 for i in range(len(fragments))])
                receiver = DecodedBunchReceiver(in_reliable=1022, opened=True,
                    max_assembly_bytes=65536)
                dispatched = []
                for i, fragment in enumerate(fragments):
                    encoded, decoded = packet_roundtrip(fragment, i + 1)
                    self.assertLessEqual(len(encoded), MAX_PACKET)
                    result = receive_wire(receiver, decoded, i + 1)
                    self.assertFalse(result.error)
                    if i < len(fragments) - 1:
                        self.assertEqual(result.ready, ())
                    dispatched.extend(result.ready)
                self.assertEqual(len(dispatched), 1)
                self.assertEqual(dispatched[0].payload_bits, original.payload_bits)
                self.assertEqual(dispatched[0].payload, original.payload)
                self.assertEqual(original, actor_bunch(bit_count))

    def test_sealed_current_native_rules_are_the_implementation_source(self):
        raw = (ROOT / "work/research_updated_transport_79fb7b10.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
            "d127c9b551192ba1a126f3b5f5e2c90f9a9a6a0e6d4ff806b6d037941fb73e92")
        source = json.loads(raw)
        self.assertIn("connection_overhead_bits-562", source["fragment_sender"])
        self.assertIn("New reliable fragments increment", source["fragment_sender"])
        self.assertIn("must be byte aligned", source["partial_receiver"])
        self.assertIsNotNone(fragmentation)
        self.assertEqual(fragmentation.TRANSPORT_SOURCE_SHA256, hashlib.sha256(raw).hexdigest())

    def test_unsplit_native_raw_budget_does_not_manufacture_partial_endpoints(self):
        # Native compares against the full budget before choosing aligned pieces.
        for bits in (1, 7608, 7613):
            with self.subTest(bits=bits):
                original = actor_bunch(bits)
                result = self.split(original)
                self.assertEqual(result, (original,))
                self.assertFalse(result[0].partial)
                packet_roundtrip(result[0])
        split = self.split(actor_bunch(7614))
        self.assertEqual([p.payload_bits for p in split], [7608, 6])

    def test_fragment_endpoints_preserve_open_first_and_close_only_last(self):
        original = actor_bunch(16670, open=True, close=True, close_reason=7)
        fragments = self.split(original)
        self.assertEqual([f.open for f in fragments], [True, False, False])
        self.assertEqual([f.close for f in fragments], [False, False, True])
        self.assertEqual([f.close_reason for f in fragments], [0, 0, 7])
        self.assertEqual([f.partial for f in fragments], [True, True, True])
        self.assertEqual([f.partial_initial for f in fragments], [True, False, False])
        self.assertEqual([f.partial_final for f in fragments], [False, False, True])
        receiver = DecodedBunchReceiver(in_reliable=1022, opened=False)
        for i, f in enumerate(fragments):
            _, decoded = packet_roundtrip(f, i + 1)
            result = receive_wire(receiver, decoded, i + 1)
            self.assertEqual(result.closed, i == 2)
            self.assertEqual(len(result.ready), int(i == 2))
        self.assertTrue(receiver.opened)
        self.assertTrue(receiver.closed)

    def test_missing_or_duplicate_fragments_never_dispatch_an_incomplete_object(self):
        wire = [packet_roundtrip(f, i + 1)[1]
            for i, f in enumerate(self.split(actor_bunch(16670)))]
        for delivered in ((1, 2), (0, 2), (0, 1), (2, 2), (0, 0, 2)):
            with self.subTest(delivered=delivered):
                receiver = DecodedBunchReceiver(in_reliable=1022, opened=True)
                for index in delivered:
                    result = receive_wire(receiver, wire[index], index + 1)
                    self.assertEqual(result.ready, ())

    def test_reordered_final_waits_for_missing_middle_then_dispatches_exactly_once(self):
        original = actor_bunch(16670)
        wire = [packet_roundtrip(f, i + 1)[1]
            for i, f in enumerate(self.split(original))]
        receiver = DecodedBunchReceiver(in_reliable=1022, opened=True)
        for index in (2, 2, 0):
            self.assertEqual(receive_wire(receiver, wire[index], index + 1).ready, ())
        result = receive_wire(receiver, wire[1], 2)
        self.assertEqual(len(result.ready), 1)
        self.assertEqual(result.ready[0].payload, original.payload)
        self.assertEqual(result.ready[0].payload_bits, 16670)
        self.assertEqual(receive_wire(receiver, wire[2], 3).ready, ())

    def test_explicit_connection_overhead_is_required_and_changes_the_piece_budget(self):
        self.assertIsNotNone(fragmentation)
        with self.assertRaises(TypeError):
            fragmentation.split_reliable_bunch(actor_bunch(8240), max_packet_bytes=1024)
        self.assertEqual([f.payload_bits for f in self.split(actor_bunch(8240),
            connection_overhead_bits=0)], [7624, 616])
        self.assertEqual([f.payload_bits for f in self.split(actor_bunch(8240),
            connection_overhead_bits=100)], [7528, 712])

    def test_invalid_packet_budget_and_local_resource_policies_are_refused(self):
        for options in (dict(max_packet_bytes=True), dict(max_packet_bytes=0),
                dict(max_packet_bytes=1493), dict(max_packet_bytes=71),
                dict(connection_overhead_bits=True), dict(connection_overhead_bits=-1),
                dict(connection_overhead_bits=7623), dict(connection_overhead_bits=1.5),
                dict(local_max_assembled_bytes=0), dict(local_max_assembled_bytes=True),
                dict(local_max_assembled_bytes=1024 * 1024 + 1),
                dict(local_max_assembled_bytes=1029)):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.split(actor_bunch(8240), **options)
        # A separate bounded local fragment-count policy prevents sequence reuse
        # inside a single object when a caller supplies a tiny packet budget.
        with self.assertRaises(ValueError):
            self.split(actor_bunch(4112), max_packet_bytes=73, connection_overhead_bits=0)

    def test_noncanonical_or_unsupported_bunches_are_refused(self):
        original = actor_bunch(16670)
        for index, changed in enumerate((None, replace(original, payload=bytearray(original.payload)),
                replace(original, payload=original.payload + b"\0"),
                replace(original, payload=original.payload[:-1] + b"\xff"),
                replace(original, payload_bits=True), replace(original, payload_bits=-1),
                actor_bunch(0), replace(original, channel_index=True),
                replace(original, channel_index=0), replace(original, channel_index=1),
                replace(original, channel_index=1 << 32),
                replace(original, channel_sequence=None), replace(original, channel_sequence=True),
                replace(original, channel_sequence=1024), replace(original, reliable=False),
                replace(original, reliable=1), replace(original, flag4=True),
                replace(original, connection_flag=True), replace(original, package_exports=True),
                replace(original, must_be_mapped=True), replace(original, partial=True),
                replace(original, partial_initial=True), replace(original, partial_final=True),
                replace(original, close_reason=1), replace(original, open=1),
                replace(original, channel_name=None),
                replace(original, channel_name=ChannelName(text="Control")),
                replace(original, channel_name=ChannelName(text="Actor", number=1)))):
            with self.subTest(case=index), self.assertRaises(ValueError):
                self.split(changed)

    def test_local_assembly_bound_is_not_an_official_live_limit(self):
        original = actor_bunch(65536 * 8)
        fragments = self.split(original)
        self.assertEqual(sum(f.payload_bits for f in fragments), original.payload_bits)
        self.assertIsNotNone(fragmentation)
        self.assertEqual(fragmentation.DEFAULT_LOCAL_MAX_ASSEMBLED_BYTES, 65536)
        self.assertFalse(fragmentation.OFFICIAL_LIVE_ASSEMBLY_LIMIT_QUALIFIED)
        with self.assertRaises(ValueError):
            self.split(actor_bunch(65536 * 8 + 1))
        accepted = self.split(actor_bunch(65536 * 8 + 1), local_max_assembled_bytes=65537)
        self.assertEqual(sum(f.payload_bits for f in accepted), 65536 * 8 + 1)


if __name__ == "__main__":
    unittest.main()
