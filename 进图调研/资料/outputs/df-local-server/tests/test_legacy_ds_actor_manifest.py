"""Synthetic manifest consistency/budget tests, not native Actor acceptance."""

from dataclasses import FrozenInstanceError, replace
import unittest

from dfserver.legacy_ds_actor_bunch import build_actor_bunch
from dfserver.legacy_ds_actor_manifest import (
    ActorManifest, CLIENT_SHA256, GuidPathBinding, preflight_actor_manifest,
)
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_guid_exports import GuidExportNode, read_guid_exports
from dfserver.legacy_ds_quantized_vector import QuantizedVector10
from dfserver.legacy_ds_wire_codec import (
    WirePacket, decode_observed_application, encode_observed_application,
)


def fixture(**changes):
    # These exact paths/GUIDs describe an artificial fixture only. They are
    # deliberately not presented as actual registry objects or game defaults.
    package = GuidExportNode(3, '/Game/Test/BP_Pawn')
    cls = GuidExportNode(5, 'BP_Pawn_C', package)
    template = GuidExportNode(7, 'Default__BP_Pawn_C', package)
    map_package = GuidExportNode(25, '/Game/Test/Map')
    world = GuidExportNode(9, 'Map', map_package)
    level = GuidExportNode(11, 'PersistentLevel', world)
    args = dict(client_sha256=CLIENT_SHA256,
        source_relative_path='work/test-fixture.json', source_sha256='a' * 64,
        class_guid=5, class_path='/Game/Test/BP_Pawn.BP_Pawn_C',
        archetype_guid=7, archetype_path='/Game/Test/BP_Pawn.Default__BP_Pawn_C',
        archetype_qualification='named_default_object_candidate',
        level_guid=11, level_path='/Game/Test/Map.Map:PersistentLevel',
        path_bindings=(GuidPathBinding(3, package.path),
                       GuidPathBinding(5, '/Game/Test/BP_Pawn.BP_Pawn_C', '.'),
                       GuidPathBinding(7, '/Game/Test/BP_Pawn.Default__BP_Pawn_C', '.'),
                       GuidPathBinding(25, map_package.path),
                       GuidPathBinding(9, '/Game/Test/Map.Map', '.'),
                       GuidPathBinding(11, '/Game/Test/Map.Map:PersistentLevel', ':')),
        exports=(cls, template, level), actor_guid=2,
        connection_network_version=13, archive_network_version=13,
        references_resolvable=True, channel_index=1,
        location=None, scale=None, velocity=None)
    args.update(changes)
    return ActorManifest(**args)


def preflight(manifest=None, **profile):
    return preflight_actor_manifest(manifest or fixture(),
        channel_sequence=profile.get('channel_sequence', 1023),
        max_packet_bytes=profile.get('max_packet_bytes', 1024))


class ActorManifestTests(unittest.TestCase):
    def test_explicit_path_graph_composes_and_roundtrips_without_content(self):
        result = preflight()
        self.assertEqual(result.bunch, build_actor_bunch(channel_sequence=1023,
            max_packet_bytes=1024, **dict(result.actor_fields)))
        self.assertEqual(result.actor_fields['content_blocks'], ())
        reader = BitReader(result.bunch.payload, bit_count=result.bunch.payload_bits)
        self.assertEqual(read_guid_exports(reader), fixture().exports)
        # Four absent transforms after three one-byte packed GUIDs; no guessed
        # property handle, opaque block or derived PC tail follows them.
        self.assertEqual(reader.remaining, 28)
        self.assertEqual(reader.read_payload(28), bytes.fromhex('040e1600'))
        packet = WirePacket(0x3fff, 0x3fff, (0xffffffff,), False, 0, None, (result.bunch,), 0)
        encoded = encode_observed_application(packet, max_packet_bytes=1024, received_by_server=False)
        self.assertEqual(len(encoded), result.conservative_packet_bytes)
        self.assertEqual(decode_observed_application(encoded, max_packet_bytes=1024,
            received_by_server=False).bunches[0].payload, result.bunch.payload)

    def test_world_object_as_null_outer_reproduces_native_package_rejection(self):
        original = fixture()
        cls, template, _ = original.exports
        # The former factory emitted this exact two-node shape. Merely making
        # the full path internally consistent cannot make World a package.
        world = GuidExportNode(9, '/Game/Test/Map.Map')
        level = GuidExportNode(11, 'PersistentLevel', world)
        bindings = tuple(b for b in original.path_bindings if b.guid not in (25, 9))
        bindings += (GuidPathBinding(9, world.path),)
        with self.assertRaisesRegex(ValueError, 'null-Outer root export'):
            preflight(replace(original, exports=(cls, template, level), path_bindings=bindings))

    def test_level_cannot_omit_world_or_change_observed_world_level_separator(self):
        original = fixture()
        cls, template, level = original.exports
        package = level.outer.outer
        no_world = replace(level, outer=package)
        path = package.path + ':PersistentLevel'
        bindings = tuple(replace(b, full_path=path) if b.guid == 11 else b
                         for b in original.path_bindings if b.guid != 9)
        with self.assertRaisesRegex(ValueError, 'Package.World:Level'):
            preflight(replace(original, exports=(cls, template, no_world),
                              level_path=path, path_bindings=bindings))
        dot_path = '/Game/Test/Map.Map.PersistentLevel'
        bindings = tuple(replace(b, full_path=dot_path, separator_from_outer='.')
                         if b.guid == 11 else b for b in original.path_bindings)
        with self.assertRaisesRegex(ValueError, 'Package.World:Level'):
            preflight(replace(original, level_path=dot_path, path_bindings=bindings))

    def test_no_native_success_claim_and_connection_owned_profile(self):
        result = preflight()
        self.assertFalse(result.native_acceptance)
        self.assertNotIn('channel_sequence', result.actor_fields)
        self.assertNotIn('max_packet_bytes', result.actor_fields)
        with self.assertRaises(FrozenInstanceError):
            result.native_acceptance = True
        with self.assertRaises(TypeError):
            result.actor_fields['actor_guid'] = 4

    def test_generated_class_cannot_be_used_as_archetype(self):
        manifest = fixture()
        with self.assertRaisesRegex(ValueError, 'UClass'):
            preflight(replace(manifest, archetype_guid=5, archetype_path=manifest.class_path))

    def test_named_candidate_allows_observed_class_outer_and_class_itself(self):
        original = fixture()
        cls, template, level = original.exports
        child_template = replace(template, outer=cls)
        path = original.class_path + ':Default__BP_Pawn_C'
        bindings = tuple(replace(b, full_path=path, separator_from_outer=':')
                         if b.guid == 7 else b for b in original.path_bindings)
        result = preflight(replace(original, exports=(cls, child_template, level),
                                   archetype_path=path, path_bindings=bindings))
        self.assertFalse(result.native_acceptance)
        self.assertEqual(result.actor_fields['exports'][1].outer.guid, 5)

    def test_named_candidate_rejects_wrong_leaf_or_unrelated_outer(self):
        original = fixture()
        cls, template, level = original.exports
        for wrong, path in ((replace(template, path='Default__Other'),
                             '/Game/Test/BP_Pawn.Default__Other'),
                            (replace(template, outer=level.outer),
                             '/Game/Test/Map.Map.Default__BP_Pawn_C')):
            bindings = tuple(replace(b, full_path=path) if b.guid == 7 else b
                             for b in original.path_bindings)
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'candidate'):
                preflight(replace(original, exports=(cls, wrong, level),
                    archetype_path=path, path_bindings=bindings))

    def test_explicit_nondefault_template_remains_a_declared_qualification(self):
        original = fixture()
        cls, template, level = original.exports
        path = '/Game/Test/BP_Pawn.TemplateActor'
        bindings = tuple(replace(b, full_path=path) if b.guid == 7 else b
                         for b in original.path_bindings)
        result = preflight(replace(original, exports=(cls, replace(template, path='TemplateActor'), level),
            archetype_path=path, path_bindings=bindings, archetype_qualification='explicit_template'))
        self.assertFalse(result.native_acceptance)

    def test_profile_rejects_bool_overflow_and_mismatched_version(self):
        for changes in (dict(actor_guid=True), dict(class_guid=True), dict(level_guid=True),
                        dict(channel_index=0), dict(actor_guid=1 << 32),
                        dict(archive_network_version=12), dict(references_resolvable=False),
                        dict(local_player_index=True)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                preflight(fixture(**changes))
        for args in (dict(channel_sequence=True), dict(channel_sequence=1024),
                     dict(max_packet_bytes=True), dict(max_packet_bytes=1493)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                preflight(**args)

    def test_pre5_level_pair_is_omitted_and_newer_requires_explicit_level(self):
        manifest = fixture(connection_network_version=4, archive_network_version=4,
                           level_guid=None, level_path=None)
        self.assertIsNone(preflight(manifest).actor_fields['level_guid'])
        for changes in (dict(level_path=fixture().level_path),
                        dict(level_guid=fixture().level_guid),
                        dict(level_guid=5, level_path=manifest.class_path),
                        dict(connection_network_version=13, archive_network_version=13)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                preflight(replace(manifest, **changes))

    def test_source_pins_require_relative_paths_sha_and_exact_build(self):
        for path in ('/tmp/file', 'C:/file', 'work\\file', '../file', 'work/../file',
                     'work//file', './file', ''):
            with self.subTest(path=path), self.assertRaises(ValueError):
                preflight(fixture(source_relative_path=path))
        for sha in ('A' * 64, 'a' * 63, 'a' * 65, 'x' * 64, None):
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                preflight(fixture(source_sha256=sha))
        with self.assertRaises(ValueError):
            preflight(fixture(client_sha256='b' * 64))

    def test_bindings_reject_missing_extra_duplicate_guid_or_path(self):
        original = fixture()
        for bindings in (original.path_bindings[:-1],
                         original.path_bindings + (GuidPathBinding(13, '/Game/Other'),),
                         original.path_bindings + (original.path_bindings[0],),
                         tuple(replace(b, full_path=original.class_path) if b.guid == 7 else b
                               for b in original.path_bindings)):
            with self.subTest(bindings=bindings), self.assertRaises(ValueError):
                preflight(replace(original, path_bindings=bindings))

    def test_outer_separator_and_leaf_must_reproduce_complete_observed_path(self):
        original = fixture()
        for changed in (replace(original.path_bindings[1], separator_from_outer=':'),
                        replace(original.path_bindings[1], separator_from_outer=None),
                        replace(original.path_bindings[0], separator_from_outer='.'),
                        replace(original.path_bindings[0], full_path='/Wrong/Package')):
            bindings = tuple(changed if b.guid == changed.guid else b for b in original.path_bindings)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                preflight(replace(original, path_bindings=bindings))

    def test_complete_paths_reject_label_fragments_and_malformed_separators(self):
        for path in ('BP_Pawn_C', "Blueprint'/Game/A.A_C'", '/Game//A', '/Game/A..A_C',
                     '/Game/A:A_C:', '/Game/Bad Name', '/Game/A\\A_C', '/Game/A\x00'):
            original = fixture()
            binding = replace(original.path_bindings[1], full_path=path)
            with self.subTest(path=path), self.assertRaises(ValueError):
                preflight(replace(original, class_path=path,
                    path_bindings=(original.path_bindings[0], binding) + original.path_bindings[2:]))

    def test_input_graph_is_detached_from_staged_fields_and_bunch(self):
        original = fixture(location=QuantizedVector10((0, 1, -1)))
        result = preflight(original)
        original_payload = result.bunch.payload
        object.__setattr__(original.exports[0], 'path', 'Mutated')
        object.__setattr__(original.location, 'steps', (1, 2, 3))
        self.assertEqual(result.actor_fields['exports'][0].path, 'BP_Pawn_C')
        self.assertEqual(result.actor_fields['location'].steps, (0, 1, -1))
        self.assertEqual(build_actor_bunch(channel_sequence=1023, max_packet_bytes=1024,
                        **dict(result.actor_fields)).payload, original_payload)

    def test_cycles_conflicting_exports_and_excess_depth_are_bounded(self):
        original = fixture()
        cycle = GuidExportNode(3, '/Game/Cycle')
        object.__setattr__(cycle, 'outer', cycle)
        graph = GuidExportNode(3, '/Game/Deep')
        for guid in range(5, 43, 2):
            graph = GuidExportNode(guid, 'Nested', graph)
        for exports in ((cycle,), (graph,), original.exports + (GuidExportNode(5, '/Conflicting'),),
                        original.exports * 700):
            with self.subTest(exports_len=len(exports)), self.assertRaises(ValueError):
                preflight(replace(original, exports=exports))

    def test_exact_immutable_types_and_bypassed_vector_validation(self):
        class DerivedManifest(ActorManifest):
            pass
        original = fixture()
        with self.assertRaises(ValueError):
            preflight(DerivedManifest(**original.__dict__))
        for changes in (dict(exports=list(original.exports)),
                        dict(path_bindings=list(original.path_bindings)),
                        dict(force_unicode=1), dict(archetype_qualification='verified_cdo')):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                preflight(replace(original, **changes))
        vector = QuantizedVector10((0, 1, 2))
        object.__setattr__(vector, 'steps', [0, 1, 2])
        with self.assertRaises(ValueError):
            preflight(replace(original, location=vector))

    def test_packet_budget_covers_headers_and_handler_termination(self):
        original = fixture()
        result = preflight(original)
        budget = result.conservative_packet_bytes - 2
        # Changing MaxPacket affects length's bounded-int width, so verify the
        # complete encoder refuses this bound rather than assuming payload fit.
        standalone = build_actor_bunch(channel_sequence=1023, max_packet_bytes=budget,
                                      **dict(result.actor_fields))
        self.assertLess(standalone.payload_bits, budget * 8)
        with self.assertRaises(ValueError):
            preflight(original, max_packet_bytes=budget)


if __name__ == '__main__':
    unittest.main()
