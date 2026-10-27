"""Current-source Actor qualification is separate from historical metadata."""
from dataclasses import replace
from functools import lru_cache
import json
from pathlib import Path
import sys
import unittest

from dfserver.replication.legacy_ds_actor_manifest import ActorManifest, GuidPathBinding, preflight_actor_manifest
from dfserver.replication.legacy_ds_guid_exports import GuidExportNode

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'work'))


@lru_cache(maxsize=1)
def sources():
    from build_updated_minimum_actor_profile import source_blobs
    blobs = source_blobs()
    path = 'work/evidence/updated-enabled-actor-receiver-79fb7b10-v3.json'
    blobs[path] = (ROOT/path).read_bytes()
    return (ROOT/'work/evidence/updated-minimum-actor-profile-79fb7b10.json').read_bytes(), blobs


def qualification():
    from dfserver.replication.legacy_ds_current_actor_profile import qualify_current_actor_sources
    raw, blobs = sources()
    return qualify_current_actor_sources(raw, source_blobs=blobs)


def current_manifest(role, q, *, channel=2, actor=2):
    from dfserver.replication.legacy_ds_current_actor_profile import (
        CURRENT_CLIENT_SHA256, CURRENT_ACTOR_PROFILE_PATH, CURRENT_ACTOR_PROFILE_SHA256,
        current_actor_binding)
    row = current_actor_binding(q, role)
    package_path, leaf = row['class_path'].rsplit('.', 1)
    package_guid = 3+6*('PlayerController', 'Pawn', 'GameState', 'PlayerState').index(role)
    package = GuidExportNode(package_guid, package_path)
    cls = GuidExportNode(package_guid+2, leaf, package)
    cdo = GuidExportNode(package_guid+4, row['archetype_path'].rsplit('.', 1)[1], package)
    map_package = GuidExportNode(33, '/Game/Test/CurrentMap')
    world = GuidExportNode(35, 'CurrentMap', map_package)
    level = GuidExportNode(37, 'PersistentLevel', world)
    # No real spawn location or native server flag semantics are asserted by this fixture.
    return ActorManifest(client_sha256=CURRENT_CLIENT_SHA256,
        source_relative_path=CURRENT_ACTOR_PROFILE_PATH, source_sha256=CURRENT_ACTOR_PROFILE_SHA256,
        class_guid=cls.guid, class_path=row['class_path'], archetype_guid=cdo.guid, archetype_path=row['archetype_path'],
        archetype_qualification='source_cooked_class_default_object', level_guid=level.guid,
        level_path='/Game/Test/CurrentMap.CurrentMap:PersistentLevel',
        path_bindings=(GuidPathBinding(package.guid, package_path), GuidPathBinding(cls.guid, row['class_path'], '.'),
                       GuidPathBinding(cdo.guid, row['archetype_path'], '.'),
                       GuidPathBinding(map_package.guid, map_package.path),
                       GuidPathBinding(world.guid, '/Game/Test/CurrentMap.CurrentMap', '.'),
                       GuidPathBinding(level.guid, '/Game/Test/CurrentMap.CurrentMap:PersistentLevel', ':')),
        exports=(cls, cdo, level), actor_guid=actor, connection_network_version=13, archive_network_version=13,
        references_resolvable=True, channel_index=channel, location=None, scale=None, velocity=None,
        local_player_index=0 if role == 'PlayerController' else None,
        game_replication_flags=0 if role == 'Pawn' else None, current_qualification=q)


class CurrentActorProfileTests(unittest.TestCase):
    def test_exact_current_sources_have_no_live_or_native_acceptance_claim(self):
        q = qualification()
        summary = q.summary()
        self.assertFalse(summary['actor_transmission_enabled'])
        self.assertFalse(summary['native_acceptance_verified'])
        self.assertTrue(summary['fresh_live_receiver_gate_required'])
        self.assertEqual(summary['roles'], ['GameState', 'Pawn', 'PlayerController', 'PlayerState'])

    def test_missing_or_changed_compiled_and_receiver_sources_are_refused(self):
        from dfserver.replication.legacy_ds_current_actor_profile import qualify_current_actor_sources, HEADER_PROOF_PATH
        raw, blobs = sources()
        for body in (raw+b' ', raw.replace(b'79fb7b10', b'4254fbe6')):
            with self.assertRaises(ValueError): qualify_current_actor_sources(body, source_blobs=blobs)
        changed = dict(blobs)
        changed.pop(HEADER_PROOF_PATH)
        with self.assertRaises(ValueError): qualify_current_actor_sources(raw, source_blobs=changed)
        changed[HEADER_PROOF_PATH] = blobs[HEADER_PROOF_PATH]+b' '
        with self.assertRaises(ValueError): qualify_current_actor_sources(raw, source_blobs=changed)

    def test_fields_are_immutable_source_rows(self):
        from dfserver.replication.legacy_ds_current_actor_profile import current_actor_field
        field = current_actor_field(qualification(), 'GameState', 'MapId')
        self.assertEqual((field['relative_handle'], field['dispatch_opcode']), (52, 20))
        with self.assertRaises(TypeError): field['relative_handle'] = 1
        with self.assertRaises(TypeError): field['property_method_binding']['methods'][0]['target_rva'] = '0x0'

    def test_all_four_current_actor_shapes_preflight_without_a_hash_substitution(self):
        q = qualification()
        for index, role in enumerate(('PlayerController', 'Pawn', 'GameState', 'PlayerState')):
            manifest = current_manifest(role, q, channel=index+2, actor=2*(index+1))
            result = preflight_actor_manifest(manifest, channel_sequence=1023, max_packet_bytes=1024)
            self.assertFalse(result.native_acceptance)
            self.assertEqual(result.actor_fields['content_blocks'], ())

    def test_current_sha_without_qualification_and_mixed_history_are_rejected(self):
        from dfserver.replication.legacy_ds_actor_manifest import CLIENT_SHA256
        manifest = current_manifest('Pawn', qualification())
        for changed in (replace(manifest, current_qualification=None), replace(manifest, client_sha256=CLIENT_SHA256),
                        replace(manifest, source_sha256='a'*64),
                        replace(manifest, archetype_qualification='named_default_object_candidate')):
            with self.assertRaises(ValueError):
                preflight_actor_manifest(changed, channel_sequence=1, max_packet_bytes=1024)

    def test_class_cdo_and_derived_tail_bindings_cannot_be_mixed(self):
        q = qualification()
        pc, pawn, gs = (current_manifest(role, q) for role in ('PlayerController', 'Pawn', 'GameState'))
        for changed in (replace(pc, archetype_path=gs.archetype_path), replace(pc, local_player_index=None),
                        replace(gs, local_player_index=0), replace(pawn, game_replication_flags=None),
                        replace(gs, game_replication_flags=0), replace(pc, connection_network_version=12)):
            with self.assertRaises(ValueError):
                preflight_actor_manifest(changed, channel_sequence=1, max_packet_bytes=1024)


if __name__ == '__main__':
    unittest.main()
