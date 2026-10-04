"""Offline regression of one recorded Actor packet; not a game-spawn test."""
from dataclasses import replace
import hashlib
from pathlib import Path
import unittest

from native_actor_bootstrap import build_pawn_actor_bootstrap
from dfserver.legacy_ds_actor_manifest import GuidPathBinding, preflight_actor_manifest
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_guid_exports import read_guid_exports
from dfserver.legacy_ds_wire_codec import decode_observed_application


BASE = Path(__file__).resolve().parent.parent
TRIAL = 'work/native-client-tests/1791031744759217200'
PACKET = TRIAL + '/game-server-packets/17-udp.bin'
PACKET_SHA = '41f00c43c6a005d76a91d9265b574131fe5977cb8a29d8fb094577d44196ebde'
LEVEL = '/Game/Maps/Iris_Entry/Iris_Entry.Iris_Entry:PersistentLevel'


def corrected():
    relative = TRIAL + '/replication-metadata/result.json'
    raw = (BASE / relative).read_bytes()
    evidence_path = 'work/evidence/native-actor-level-package-rejection.json'
    return build_pawn_actor_bootstrap(raw,
        source_relative_path=relative, source_sha256=hashlib.sha256(raw).hexdigest(),
        level_path=LEVEL, level_source_relative_path=evidence_path,
        level_source_sha256=hashlib.sha256((BASE / evidence_path).read_bytes()).hexdigest(),
        package_guid=3, class_guid=5, archetype_guid=7, level_package_guid=25,
        level_outer_guid=9, level_guid=11, actor_guid=2, channel_index=4,
        channel_sequence=1023, connection_network_version=13, archive_network_version=13,
        max_packet_bytes=1024, references_resolvable=True)


class RecordedLevelPacketTests(unittest.TestCase):
    def test_real_packet_world_root_is_rejected_before_queue(self):
        raw = (BASE / PACKET).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), PACKET_SHA)
        self.assertEqual(len(raw), 256)
        packet = decode_observed_application(raw, max_packet_bytes=1024, received_by_server=False)
        self.assertEqual(len(packet.bunches), 1)
        bunch = packet.bunches[0]
        self.assertEqual((bunch.channel_index, bunch.payload_bits), (4, 1917))
        reader = BitReader(bunch.payload, bit_count=bunch.payload_bits)
        exports = read_guid_exports(reader)
        world = exports[2].outer
        self.assertEqual((exports[2].guid, world.guid, world.path, world.outer),
                         (11, 9, LEVEL.split(':')[0], None))
        self.assertEqual(reader.remaining, 28)
        self.assertEqual(reader.read_payload(28), bytes.fromhex('040e1600'))
        current = corrected().manifest
        bindings = tuple(b for b in current.path_bindings if b.guid not in (25, 9))
        bindings += (GuidPathBinding(9, world.path),)
        bad = replace(current, exports=exports, path_bindings=bindings)
        with self.assertRaisesRegex(ValueError, 'null-Outer root export'):
            preflight_actor_manifest(bad, channel_sequence=bunch.channel_sequence, max_packet_bytes=1024)

    def test_actual_metadata_now_serializes_package_world_level_without_invented_tail(self):
        result = corrected()
        reader = BitReader(result.preflight.bunch.payload, bit_count=result.preflight.bunch.payload_bits)
        level = read_guid_exports(reader)[2]
        self.assertEqual((level.guid, level.path, level.outer.guid, level.outer.path,
                          level.outer.outer.guid, level.outer.outer.path, level.outer.outer.outer),
                         (11, 'PersistentLevel', 9, 'Iris_Entry', 25,
                          '/Game/Maps/Iris_Entry/Iris_Entry', None))
        self.assertEqual(reader.remaining, 28)
        self.assertEqual(reader.read_payload(28), bytes.fromhex('040e1600'))
        self.assertFalse(result.preflight.native_acceptance)


if __name__ == '__main__':
    unittest.main()
