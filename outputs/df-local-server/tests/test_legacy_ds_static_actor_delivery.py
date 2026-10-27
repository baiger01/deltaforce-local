"""Static Actor admission, atomic staging and retries; no native success claim."""
from dataclasses import replace
import unittest
from unittest.mock import PropertyMock, patch

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_actor_manifest import CLIENT_SHA256, GuidPathBinding, preflight_actor_manifest
from dfserver.legacy_ds_static_actor_manifest import StaticActorManifest
from dfserver.legacy_ds_guid_exports import GuidExportNode, read_guid_exports
from dfserver.legacy_ds_bit_archive import BitReader
from tests import test_legacy_ds_actor_delivery as delivery
from tests import test_legacy_ds_actor_bootstrap as bootstrap
from tests.test_legacy_ds_actor_delivery import actor_fields, decode
from tests.test_legacy_ds_actor_bootstrap import manifest
from tests.test_legacy_ds_control_probe import PEER


def static_manifest(**changes):
    package = GuidExportNode(25, '/Game/Test/Entry')
    world = GuidExportNode(9, 'Entry', package)
    level = GuidExportNode(11, 'PersistentLevel', world)
    actor = GuidExportNode(39, 'WorldSettings', level)
    path = '/Game/Test/Entry.Entry:PersistentLevel'
    fields = dict(client_sha256=CLIENT_SHA256, source_relative_path='work/fixture.json',
        source_sha256='a' * 64, class_path='/Script/Test.WorldSettings',
        actor_path=path + '.WorldSettings', actor_guid=39, level_guid=11, level_path=path,
        path_bindings=(GuidPathBinding(25, '/Game/Test/Entry'),
            GuidPathBinding(9, '/Game/Test/Entry.Entry', '.'),
            GuidPathBinding(11, path, ':'), GuidPathBinding(39, path + '.WorldSettings', '.')),
        exports=(actor,), channel_index=7, references_resolvable=True,
        actor_open_hook_has_no_extra_fields=True)
    fields.update(changes)
    return StaticActorManifest(**fields)


def static_fields():
    return dict(preflight_actor_manifest(static_manifest(), channel_sequence=1023,
                                         max_packet_bytes=1024).actor_fields)


class StaticManifestTests(unittest.TestCase):
    def test_paths_are_detached_and_static_header_contains_only_actor_reference(self):
        prepared = preflight_actor_manifest(static_manifest(), channel_sequence=217,
                                            max_packet_bytes=1024)
        reader = BitReader(prepared.bunch.payload, bit_count=prepared.bunch.payload_bits)
        self.assertEqual(read_guid_exports(reader)[0].guid, 39)
        self.assertEqual(reader.read_packed_int(), 39)
        self.assertEqual(reader.remaining, 0)
        self.assertFalse(prepared.native_acceptance)

    def test_bad_source_path_actor_kind_hook_and_outer_are_rejected(self):
        for changes in ({'source_relative_path': '../outside.json'}, {'client_sha256': 'b' * 64},
                        {'actor_path': '/Game/Test/Entry.Entry:Other.WorldSettings'},
                        {'actor_guid': 2}, {'actor_open_hook_has_no_extra_fields': False},
                        {'exports': (GuidExportNode(39, 'WorldSettings'),)},
                        {'level_guid': 9}, {'path_bindings': ()}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                preflight_actor_manifest(static_manifest(**changes), channel_sequence=217,
                                         max_packet_bytes=1024)


class StaticDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = delivery.ActorDeliveryTests()
        self.fixture.setUp()
        self.connection = self.fixture.connection

    def test_static_ack_and_retry_preserve_bunch_and_sequence(self):
        self.connection.queue_actor_open(PEER, **static_fields())
        first = decode(self.connection.poll(.1)[0][2])
        self.fixture.send(1259, first.sequence, history=(1 << 5,), now=.2)
        self.assertFalse(self.connection.control_peers[PEER].actor_opens[7].delivered)
        retry = decode(self.connection.poll(.7)[0][2])
        self.assertGreater(retry.sequence, first.sequence)
        self.assertEqual(retry.bunches[0], first.bunches[0])
        self.fixture.send(1260, retry.sequence, now=.8)
        self.assertTrue(self.connection.control_peers[PEER].actor_opens[7].delivered)
        self.assertEqual(self.connection.poll(2), [])
        self.assertFalse(self.connection.summary()['native_actor_resolution_verified'])

    def test_missing_static_ack_blocks_dynamic_content(self):
        dynamic = actor_fields(channel_index=2, actor_guid=4)
        plan = dict(channel_index=2, actor_guid=4,
                    content_blocks=(ActorContentBlock(True, b'\x15', 5),))
        self.connection.queue_actor_opens(PEER, (dynamic, static_fields()),
                                         post_open_actor_contents=(plan,))
        first, second = [decode(row[2]) for row in self.connection.poll(.1)]
        self.fixture.send(1259, second.sequence, history=(2,), now=.2)
        self.assertEqual(self.connection.poll(.3), [])
        self.fixture.send(1260, second.sequence, history=(3,), now=.4)
        content = decode(self.connection.poll(.5)[0][2]).bunches[0]
        self.assertEqual(content.channel_index, 2)
        self.assertFalse(content.open or content.package_exports)

    def test_late_static_failure_rolls_back_dynamic_queue_and_events(self):
        original = self.connection.control_peers[PEER]
        events = dict(self.connection.control_events)
        bad = static_fields(); bad['actor_open_hook_has_no_extra_fields'] = False
        with self.assertRaises(ValueError):
            self.connection.queue_actor_opens(PEER, (actor_fields(), bad))
        self.assertIs(self.connection.control_peers[PEER], original)
        self.assertEqual(original.actor_opens, {})
        self.assertEqual(dict(self.connection.control_events), events)

    def test_static_needs_join_and_cannot_get_unqualified_property_content(self):
        state = self.connection.control_peers[PEER]
        state.client_join_observed = False
        with self.assertRaises(ValueError):
            self.connection.queue_actor_open(PEER, **static_fields())
        state.client_join_observed = True
        plan = dict(channel_index=7, actor_guid=39,
                    content_blocks=(ActorContentBlock(True, b'\x15', 5),))
        with self.assertRaises(ValueError):
            self.connection.queue_actor_opens(PEER, (static_fields(),), post_open_actor_contents=(plan,))
        self.assertEqual(self.connection.control_peers[PEER].actor_opens, {})

    def test_static_channel_and_export_conflicts_are_atomic(self):
        self.connection.queue_actor_open(PEER, **static_fields())
        before = dict(self.connection.control_peers[PEER].actor_exports)
        for changes in ({'channel_index': 8}, {'actor_guid': 41}):
            bad = static_fields(); bad.update(changes)
            with self.assertRaises(ValueError):
                self.connection.queue_actor_open(PEER, **bad)
        bad = actor_fields(channel_index=2, actor_guid=4,
            exports=(GuidExportNode(3, 'FixtureClass'), GuidExportNode(25, 'WrongPackage')),
            level_guid=25)
        with self.assertRaises(ValueError):
            self.connection.queue_actor_open(PEER, **bad)
        self.assertEqual(self.connection.control_peers[PEER].actor_exports, before)


class StaticBootstrapRegistrationTests(unittest.TestCase):
    def test_mixed_manifest_registration_reaches_join_queue_and_resolver(self):
        fixture = bootstrap.BootstrapLifetimeTests(); fixture.setUp()
        try:
            server = fixture.server
            server._registered_bootstraps.clear()
            calls = []
            def resolver(ticket, fields):
                calls.append((ticket, tuple(row.get('actor_kind', 'dynamic') for row in fields)))
                return fields
            with patch.object(type(server), 'listening', new_callable=PropertyMock, return_value=True):
                server.register_initial_actor_manifests(fixture.ticket, (manifest(), static_manifest()),
                                                       resolver=resolver)
            with server._lock:
                server._queue_registered_bootstraps_locked()
            self.assertEqual(calls, [(fixture.ticket, ('dynamic', 'static'))])
            self.assertEqual(set(fixture.connection.control_peers[PEER].actor_opens), {1, 7})
            self.assertEqual(server._registered_bootstraps[fixture.ticket.cookie]['status'], 'queued')
        finally:
            fixture.doCleanups()


if __name__ == '__main__':
    unittest.main()
