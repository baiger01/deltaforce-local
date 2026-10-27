import json
from pathlib import Path
import socket
import tempfile
import time
import unittest

from dfserver.game_server_probe import GameServerProbe


class GameServerProbeTests(unittest.TestCase):
    def test_captures_both_possible_transports_without_claiming_gameplay(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            with GameServerProbe(path, max_packets=2) as probe:
                self.assertTrue(probe.listening)
                with socket.create_connection(('127.0.0.1', probe.port)) as connection:
                    connection.sendall(b'TCP-first-frame')
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                    datagram.sendto(b'UDP-first-frame', ('127.0.0.1', probe.port))
                    client_udp_port = datagram.getsockname()[1]
                deadline = time.monotonic() + 3
                while len(probe.records) < 2 and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertEqual({item['transport'] for item in probe.records}, {'tcp', 'udp'})
                self.assertTrue(probe.flush(timeout=3))
                self.assertEqual({(path / item['private_packet_file']).read_bytes()
                                  for item in probe.records},
                                 {b'TCP-first-frame', b'UDP-first-frame'})
            report = json.loads((path / 'report.json').read_text(encoding='utf-8'))
            self.assertFalse(report['listening'])
            self.assertFalse(report['gameplay_server_implemented'])
            self.assertNotIn('TCP-first-frame', json.dumps(report))
            udp_record = next(item for item in report['records'] if item['transport'] == 'udp')
            self.assertEqual(udp_record['peer_port'], client_udp_port)
            self.assertGreaterEqual(udp_record['elapsed_seconds'], 0)

    def test_rejects_invalid_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                GameServerProbe(temporary, max_packets=0)
            with self.assertRaises(ValueError):
                GameServerProbe(temporary, max_bytes=65536)

    def test_records_tcp_connection_even_when_client_sends_no_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            with GameServerProbe(path) as probe:
                with socket.create_connection(('127.0.0.1', probe.port)):
                    pass
                deadline = time.monotonic() + 3
                report = {}
                while time.monotonic() < deadline:
                    report = json.loads((path / 'report.json').read_text(encoding='utf-8'))
                    if report['tcp_connections_accepted']:
                        break
                    time.sleep(.01)
                self.assertEqual(report['tcp_connections_accepted'], 1)
                self.assertEqual(len(report['tcp_accept_samples']), 1)
                self.assertEqual(report['records'], [])
                self.assertFalse(report['gameplay_server_implemented'])


class PCRestartProbeTests(unittest.TestCase):
    def setUp(self):
        from dataclasses import replace
        from tests.test_legacy_ds_control_connection import PCRestartLifecycleTests, MAPS
        from tests.test_legacy_ds_pc_startup_rpc import PROFILE as startup_profile
        from tests.test_legacy_ds_actor_bootstrap import manifest
        from dfserver.legacy_ds_actor_manifest import GuidPathBinding
        from dfserver.legacy_ds_guid_exports import GuidExportNode
        from dfserver.legacy_ds_handshake_probe import PendingChallenge
        from tests.test_legacy_ds_control_probe import PEER
        self.fixture = PCRestartLifecycleTests()
        self.fixture.setUp()
        self.connection, self.ticket = self.fixture.connection, self.fixture.ticket
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.server = GameServerProbe(self.folder.name, handshake_probe=True, packet_ack_probe=True,
            control_probe=True, expected_net_version=1077088301, control_welcome_maps=MAPS)
        self.addCleanup(self.server.close)
        self.server._admissions = self.connection.admissions
        self.server._handshake.packet_ack_probe = self.connection
        self.peer = PEER
        self.generation = PendingChallenge(1.0, b'test' * 5, 0,
            echoed=True, verified_at=0, last_valid_activity_at=0)
        self.server._handshake.pending[PEER] = self.generation

        def typed_manifest(path, guid, channel, ids):
            base = manifest()
            package_path, name = path.rsplit('.', 1)
            package = GuidExportNode(ids[0], package_path)
            klass = GuidExportNode(ids[1], name, package)
            template = GuidExportNode(ids[2], 'Default__' + name, package)
            bindings = (GuidPathBinding(ids[0], package_path), GuidPathBinding(ids[1], path, '.'),
                GuidPathBinding(ids[2], package_path + '.Default__' + name, '.')) + base.path_bindings[-3:]
            return replace(base, class_guid=ids[1], class_path=path, archetype_guid=ids[2],
                archetype_path=bindings[2].full_path, path_bindings=bindings,
                exports=(klass, template, base.exports[-1]), actor_guid=guid, channel_index=channel)

        self.pc = typed_manifest(self.fixture.profile.class_path, 4, 2, (13, 15, 17))
        self.pawn = typed_manifest('/Game/BluePrints/Characters/BP_DFMCharacter.BP_DFMCharacter_C',
                                   2, 4, (3, 5, 7))
        gs = typed_manifest(self.fixture.start_profile.class_path, 6, 3, (19, 21, 23))
        self.gs = gs
        self.server.set_pc_startup_profile(2201, self.pc, startup_profile)
        self.server.set_game_state_start_profile(2201, gs, self.fixture.start_profile)

    def configure(self):
        self.server.set_pc_restart_profile(2201, self.pc, self.pawn, self.fixture.profile)

    def register(self):
        self.server._registered_bootstraps[self.ticket.cookie] = {
            'ticket': self.ticket, 'status': 'queued', 'peer': self.peer, 'generation': self.generation,
            'actor_fields': self.fixture.fields, 'post_open_actor_contents': self.fixture.plans}

    def test_owner_request_is_pending_until_one_current_registered_generation_and_then_idempotent(self):
        self.configure()
        self.assertEqual(self.server.request_pc_restart(2201), 'pending')
        self.assertFalse(self.fixture.state().pc_restart_requested)
        self.register()
        self.assertEqual(self.server.request_pc_restart(2201), 'queued')
        self.assertIsNone(self.fixture.state().pc_restart)
        self.assertEqual(self.server.request_pc_restart(2201), 'already_requested')
        self.fixture.ready()
        self.assertTrue(any(row[1] == 'pc_restart_send_prepared' for row in self.connection.poll(1.6)))
        self.assertFalse(self.connection.summary()['playable_map_verified'])

    def test_profile_is_source_typed_same_level_and_cannot_be_reconfigured_after_admission(self):
        from dataclasses import replace
        for pc, pawn in ((self.pc, self.pc), (self.pc, replace(self.pawn, level_path='/Game/Other.World:PersistentLevel')),
                         (replace(self.pc, class_path='/Game/Wrong.Wrong_C'), self.pawn)):
            with self.subTest(pc=pc.actor_guid, pawn=pawn.actor_guid), self.assertRaises(ValueError):
                self.server.set_pc_restart_profile(2201, pc, pawn, self.fixture.profile)
        self.configure()
        with self.assertRaises(ValueError):
            self.server.set_pc_restart_profile(2201, self.pc, self.pawn, self.fixture.profile)
        self.register()
        with self.assertRaises(ValueError):
            self.server.set_pc_restart_profile(2201, self.pc, self.pawn, self.fixture.profile)

    def test_foreign_generation_peer_and_actor_namespace_cannot_arm_current_request(self):
        from dataclasses import replace
        self.configure()
        self.register()
        registration = self.server._registered_bootstraps[self.ticket.cookie]
        registration['generation'] = replace(self.generation)
        self.assertEqual(self.server.request_pc_restart(2201), 'pending')
        self.assertFalse(self.fixture.state().pc_restart_requested)
        registration['generation'] = self.generation
        registration['peer'] = ('127.0.0.1', self.peer[1] + 1)
        self.assertEqual(self.server.request_pc_restart(2201), 'pending')
        registration['peer'] = self.peer
        registration['actor_fields'] = self.fixture.fields[:-1]
        with self.assertRaises(ValueError):
            self.server.request_pc_restart(2201)
        self.assertFalse(self.fixture.state().pc_restart_requested)

    def test_ticket_identity_and_closed_registration_do_not_transfer_post_travel_gate(self):
        from dataclasses import replace
        self.configure()
        self.register()
        registration = self.server._registered_bootstraps[self.ticket.cookie]
        registration['ticket'] = replace(self.ticket)
        self.assertEqual(self.server.request_pc_restart(2201), 'pending')
        self.assertFalse(self.fixture.state().pc_restart_requested)
        self.register()
        self.fixture.state().client_closed = True
        self.assertEqual(self.server.request_pc_restart(2201), 'pending')
        self.assertEqual(self.server._registered_bootstraps[self.ticket.cookie]['status'], 'client_closed')

    def capture_packet(self, bunches=()):
        from dataclasses import replace
        from dfserver.legacy_ds_wire_codec import encode_observed_application
        packet = replace(self.fixture.fixture.template, bunches=bunches)
        return b'opaque!!' + encode_observed_application(packet,
            max_packet_bytes=1024, received_by_server=True)

    def arm_capture(self):
        self.configure()
        self.register()
        self.assertEqual(self.server.request_pc_restart(2201), 'queued')

    def test_late_private_window_preserves_full_early_capture_and_has_no_handler_side_effect(self):
        import json
        from pathlib import Path
        self.server.max_packets = 1
        self.server._record('udp', b'early-private')
        self.arm_capture()
        early = self.server.records
        before = self.connection.summary()
        raw = self.capture_packet()
        self.server._record('udp', raw, peer=self.peer)
        pc_raw = self.capture_packet((self.fixture.state().actor_contents[2].bunch,))
        self.server._record('udp', pc_raw, peer=self.peer)
        self.assertTrue(self.server.flush())
        self.assertEqual(self.server.records, early)
        self.assertEqual(self.connection.summary(), before)
        report = json.loads((Path(self.folder.name) / 'report.json').read_text(encoding='utf-8'))
        window = report['pc_restart_packet_capture']
        self.assertEqual(len(window['records']), 2)
        self.assertFalse(window['gameplay_handled'])
        self.assertFalse(window['native_possession_verified'])
        for record, expected in zip(window['records'], (raw, pc_raw)):
            self.assertEqual((Path(self.folder.name) / record['private_packet_file']).read_bytes(), expected)

    def test_late_window_rejects_login_mixed_other_channels_and_foreign_generation(self):
        from dataclasses import replace
        self.arm_capture()
        control = self.fixture.fixture.template.bunches[0]
        pc = self.fixture.state().actor_contents[2].bunch
        self.server._record('udp', self.capture_packet((pc, control)), peer=self.peer)
        self.server._record('udp', self.capture_packet(), peer=('127.0.0.1', self.peer[1] + 1))
        self.server._handshake.pending[self.peer] = replace(self.generation)
        self.server._record('udp', self.capture_packet(), peer=self.peer)
        self.assertEqual(self.server._pc_restart_records, [])
        self.assertEqual(self.server._pc_restart_capture_skips['outside_pc_channel'], 1)
        self.server._handshake.pending[self.peer] = self.generation
        self.fixture.state().client_closed = True
        self.server._record('udp', self.capture_packet(), peer=self.peer)
        self.assertEqual(self.server._pc_restart_records, [])

    def test_late_window_is_bounded_and_duplicate_requests_do_not_reset_it(self):
        self.arm_capture()
        window = self.server._pc_restart_capture
        window['packet_limit'] = 2
        raw = self.capture_packet()
        for _ in range(3):
            self.server._record('udp', raw, peer=self.peer)
        self.assertEqual(len(self.server._pc_restart_records), 2)
        self.assertEqual(self.server.request_pc_restart(2201), 'already_requested')
        self.assertIs(self.server._pc_restart_capture, window)
        self.assertEqual(len(self.server._pc_restart_records), 2)
        window['packet_limit'] = 128
        window['started_at'] -= window['duration_seconds']
        self.server._record('udp', raw, peer=self.peer)
        self.assertEqual(len(self.server._pc_restart_records), 2)

    def view_profile(self):
        from dfserver.legacy_ds_pc_view_target_rpc import PCViewTargetProfile
        return PCViewTargetProfile(self.fixture.profile.class_path, 245, 53, 85,
            0x01020CC0, 0x80220CC0, 'd' * 64, self.fixture.profile.object_binding)

    def test_view_target_configuration_uses_exact_future_restart_manifests(self):
        from dataclasses import replace
        profile = self.view_profile()
        with self.assertRaises(ValueError):
            self.server.set_pc_view_target_profile(2201, self.pc, self.pawn, profile)
        self.configure()
        for pc, pawn in ((self.pawn, self.pc),
                         (self.pc, replace(self.pawn, actor_guid=8)),
                         (replace(self.pc, channel_index=5), self.pawn)):
            with self.assertRaises(ValueError):
                self.server.set_pc_view_target_profile(2201, pc, pawn, profile)
        self.server.set_pc_view_target_profile(2201, self.pc, self.pawn, profile)
        self.assertFalse(self.fixture.state().pc_view_target_requested)
        self.assertIsNone(self.fixture.state().pc_view_target_profile)
        with self.assertRaises(ValueError):
            self.server.set_pc_view_target_profile(2201, self.pc, self.pawn, profile)

    def test_view_target_cannot_be_configured_after_ticket_registration(self):
        self.configure()
        self.register()
        with self.assertRaises(ValueError):
            self.server.set_pc_view_target_profile(2201, self.pc, self.pawn, self.view_profile())

    def test_view_target_is_installed_after_restart_when_future_ticket_bootstrap_queues(self):
        from unittest.mock import PropertyMock, patch
        from tests.test_legacy_ds_actor_delivery import ActorDeliveryTests
        from dfserver.legacy_ds_rep_layout_refs import build_empty_rep_layout_content
        fresh = ActorDeliveryTests()
        fresh.setUp()
        self.server._admissions = fresh.admissions
        self.server._handshake.packet_ack_probe = fresh.connection
        self.configure()
        profile = self.view_profile()
        self.server.set_pc_view_target_profile(2201, self.pc, self.pawn, profile)
        manifests = (self.pc, self.gs, self.pawn)
        plans = tuple({'channel_index': m.channel_index, 'actor_guid': m.actor_guid,
            'content_blocks': (build_empty_rep_layout_content(),)} for m in manifests)
        with patch.object(GameServerProbe, 'listening', new_callable=PropertyMock, return_value=True):
            self.server.register_initial_actor_manifests(fresh.ticket, manifests,
                post_open_actor_contents=plans)
        with self.server._lock:
            self.server._queue_registered_bootstraps_locked()
        state = fresh.connection.control_peers[self.peer]
        self.assertEqual(self.server._registered_bootstraps[fresh.ticket.cookie]['status'], 'queued')
        self.assertEqual(state.pc_view_target_profile, profile)
        self.assertIs(state.pc_restart_ticket, fresh.ticket)
        self.assertFalse(state.pc_view_target_requested)
        self.assertIsNone(state.pc_view_target)
