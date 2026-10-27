from dataclasses import replace
import hashlib
import json
from pathlib import Path
import unittest

from dfserver.replication.legacy_ds_actor_manifest import GuidPathBinding, preflight_actor_manifest
from dfserver.replication.legacy_ds_guid_exports import GuidExportNode
from tests.test_legacy_ds_current_actor_profile import qualification, current_manifest


ROOT = Path(__file__).resolve().parents[3]
PROFILE = 'work/evidence/updated-movement-actor-profile-79fb7b10.json'


class CurrentMovementActorTests(unittest.TestCase):
    def sources(self):
        raw = (ROOT/PROFILE).read_bytes()
        return raw, {path: (ROOT/path).read_bytes() for path in json.loads(raw)['source_pins']}

    def qualified(self):
        from dfserver.replication.legacy_ds_current_movement_actor import qualify_current_movement_actor_sources
        raw, blobs = self.sources()
        return qualify_current_movement_actor_sources(raw, source_blobs=blobs, entry_qualification=qualification())

    def manifest(self):
        q = self.qualified()
        base = current_manifest('PlayerState', q.entry_qualification, channel=6, actor=10)
        package = GuidExportNode(39, '/Script/GPGameplay')
        cls = GuidExportNode(41, 'MovementReplicationActor', package)
        cdo = GuidExportNode(43, 'Default__MovementReplicationActor', package)
        return replace(base, source_relative_path=PROFILE,
            source_sha256=hashlib.sha256(self.sources()[0]).hexdigest(),
            class_guid=41, class_path=package.path+'.'+cls.path,
            archetype_guid=43, archetype_path=package.path+'.'+cdo.path,
            archetype_qualification='source_native_class_default_object',
            path_bindings=(GuidPathBinding(39, package.path),
                GuidPathBinding(41, package.path+'.'+cls.path, '.'),
                GuidPathBinding(43, package.path+'.'+cdo.path, '.'))+base.path_bindings[-3:],
            exports=(cls, cdo, base.exports[-1]), current_qualification=q)

    def test_current_native_movement_actor_has_an_empty_open_tail(self):
        manifest = self.manifest()
        result = preflight_actor_manifest(manifest, channel_sequence=1023, max_packet_bytes=1024)
        self.assertEqual(manifest.class_path, '/Script/GPGameplay.MovementReplicationActor')
        self.assertIsNone(result.actor_fields['game_replication_flags'])
        self.assertIsNone(result.actor_fields['local_player_index'])
        self.assertFalse(result.native_acceptance)

    def test_changed_or_missing_current_sources_are_refused(self):
        from dfserver.replication.legacy_ds_current_movement_actor import qualify_current_movement_actor_sources
        raw, blobs = self.sources()
        for data, sources in ((raw+b' ', blobs), (raw, {})):
            with self.assertRaises(ValueError):
                qualify_current_movement_actor_sources(data, source_blobs=sources,
                    entry_qualification=qualification())

    def test_native_current_manifest_cannot_borrow_cooked_or_historical_qualification(self):
        manifest = self.manifest()
        for changed in (replace(manifest, current_qualification=None),
                        replace(manifest, current_qualification=qualification()),
                        replace(manifest, archetype_qualification='source_cooked_class_default_object'),
                        replace(manifest, game_replication_flags=0)):
            with self.assertRaises(ValueError):
                preflight_actor_manifest(changed, channel_sequence=1023, max_packet_bytes=1024)


if __name__ == '__main__':
    unittest.main()
