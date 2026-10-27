"""Observe exact active-ticket content delivery, never native possession."""
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import PropertyMock, patch

from dfserver.match import game_server_probe as probe_runtime
from dfserver.game_server_probe import GameServerProbe
from dfserver.legacy_ds_actor_content import ActorContentBlock
from tests.test_legacy_ds_actor_bootstrap import BootstrapLifetimeTests, manifest
from tests.test_legacy_ds_actor_delivery import decode
from tests.test_legacy_ds_control_probe import PEER
from tests.test_game_server_probe_rebind import ProbeQueuedSendRebindTests


class ActorContentProgressTests(unittest.TestCase):
    def setUp(self):
        fixture = BootstrapLifetimeTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.server, self.connection, self.ticket = fixture.server, fixture.connection, fixture.ticket
        self.client_sequence = 1259
        self.fixture = fixture
        self.server._registered_bootstraps.clear()
        blocks = (ActorContentBlock(True, b'\x15', 5),)
        plans = (dict(channel_index=1, actor_guid=2, content_blocks=blocks),
                 dict(channel_index=2, actor_guid=4, content_blocks=blocks))
        with patch.object(GameServerProbe, 'listening', new_callable=PropertyMock, return_value=True):
            self.server.register_initial_actor_manifests(self.ticket,
                (manifest(), replace(manifest(), actor_guid=4, channel_index=2)),
                post_open_actor_contents=plans)
        with self.server._lock:
            self.server._queue_registered_bootstraps_locked()
        self.registration = self.server._registered_bootstraps[self.ticket.cookie]

    @property
    def state(self):
        return self.connection.control_peers[self.registration['peer']]

    def progress(self):
        return self.server.actor_transport_delivery_progress(require_post_open_contents=True)

    def ack(self, packet_sequence, *, history=(1,), peer=PEER, now=.2):
        fixture = self.fixture.connection
        # The original fixture's ordinary control template supplies only packet
        # framing; the exact emitted sequence/history supplies delivery proof.
        from dfserver.legacy_ds_wire_codec import encode_observed_application
        from tests.test_legacy_ds_wire_codec import HELLO_BODIES
        from dfserver.legacy_ds_wire_codec import decode_observed_application
        template = decode_observed_application(HELLO_BODIES[0],
            max_packet_bytes=1024, received_by_server=True)
        packet = replace(template, sequence=self.client_sequence,
            acknowledged_sequence=packet_sequence, history=history, bunches=())
        self.client_sequence += 1
        event, response = fixture.handle(b'opaque!!' + encode_observed_application(packet,
            max_packet_bytes=1024, received_by_server=True), peer, now)
        self.assertEqual((event, response), ('control_ack_only_consumed', None))

    def deliver_opens(self):
        opens = [decode(row[2]) for row in self.connection.poll(.1)]
        self.assertEqual(len(opens), 2)
        self.ack(opens[-1].sequence, history=(3,))
        return opens

    def deliver_contents(self):
        self.deliver_opens()
        contents = [decode(row[2]) for row in self.connection.poll(.3)]
        self.assertEqual(len(contents), 2)
        self.ack(contents[-1].sequence, history=(3,), now=.4)
        return contents

    def test_property_preserves_default_and_exact_content_acks_delay_complete_set(self):
        self.deliver_opens()
        default = self.server.actor_transport_progress
        self.assertEqual(default, self.server.actor_transport_delivery_progress())
        self.assertEqual(default['fully_delivered_sets'], 1)
        self.assertEqual(self.progress()['fully_delivered_sets'], 0)
        contents = [decode(row[2]) for row in self.connection.poll(.3)]
        self.ack(contents[-1].sequence, history=(2,), now=.4)
        self.assertEqual(self.connection.summary()['post_open_actor_content_delivery_acks'], 1)
        self.assertEqual(self.progress()['fully_delivered_sets'], 0)
        self.ack(contents[-1].sequence, history=(3,), now=.5)
        self.assertEqual(self.progress()['fully_delivered_sets'], 1)
        self.assertFalse(self.progress()['native_spawn_verified'])

    def test_global_ack_count_cannot_substitute_for_whole_active_set(self):
        with patch.object(self.connection, 'summary', return_value={'initial_actor_delivery_acks': 999}):
            self.assertEqual(self.progress()['delivery_acks'], 999)
            self.assertEqual(self.progress()['fully_delivered_sets'], 0)

    def test_missing_configuration_does_not_mean_required_contents_completed(self):
        self.deliver_contents()
        original = self.registration['post_open_actor_contents']
        for plans in (None, (), []):
            with self.subTest(plans=plans):
                self.registration['post_open_actor_contents'] = plans
                self.assertEqual(self.progress()['fully_delivered_sets'], 0)
                self.assertEqual(self.server.actor_transport_progress['fully_delivered_sets'], 1)
        del self.registration['post_open_actor_contents']
        self.assertEqual(self.progress()['fully_delivered_sets'], 0)
        self.registration['post_open_actor_contents'] = original

    def test_missing_mismatched_or_extra_queued_contents_cannot_complete(self):
        self.deliver_contents()
        state = self.state
        originals = dict(state.actor_contents)
        changed = replace(originals[1], actor_guid=6)
        wrong_body = replace(originals[1], bunch=replace(originals[1].bunch, payload=b'\x00'))
        cases = ({1: originals[1]}, {1: changed, 2: originals[2]},
                 {1: wrong_body, 2: originals[2]},
                 {**originals, 3: replace(originals[1], actor_guid=6)})
        for contents in cases:
            with self.subTest(channels=tuple(contents)):
                state.actor_contents = contents
                self.assertEqual(self.progress()['fully_delivered_sets'], 0)
                self.assertEqual(self.server.actor_transport_progress['fully_delivered_sets'], 1)
        state.actor_contents = originals
        self.assertEqual(self.progress()['fully_delivered_sets'], 1)

    def test_additional_unacknowledged_open_is_not_ignored_by_required_mode(self):
        self.deliver_contents()
        state = self.state
        state.actor_opens[3] = replace(state.actor_opens[1], actor_guid=6, delivered=False)
        self.assertEqual(self.progress()['fully_delivered_sets'], 0)
        self.assertEqual(self.server.actor_transport_progress['fully_delivered_sets'], 1)

    def test_acknowledged_content_cannot_replace_unacknowledged_actor_open(self):
        for item in self.state.actor_contents.values():
            item.delivered = True
        self.assertEqual(self.progress()['fully_delivered_sets'], 0)

    def test_wrong_peer_or_generation_cannot_inherit_delivered_set(self):
        self.deliver_contents()
        old_peer, old_generation = self.registration['peer'], self.registration['generation']
        self.registration['peer'] = ('127.0.0.1', PEER[1] + 1)
        self.assertEqual(self.progress()['fully_delivered_sets'], 0)
        self.registration['peer'] = old_peer
        self.registration['generation'] = replace(old_generation)
        self.assertEqual(self.progress()['fully_delivered_sets'], 0)
        self.registration['generation'] = old_generation
        self.assertEqual(self.progress()['fully_delivered_sets'], 1)

    def test_wrong_ticket_owner_cannot_inherit_delivered_set(self):
        self.deliver_contents()
        self.connection.ticket_peers[self.ticket.cookie] = ('127.0.0.1', PEER[1] + 1)
        self.assertEqual(self.progress()['fully_delivered_sets'], 0)
        self.connection.ticket_peers[self.ticket.cookie] = PEER
        self.state.ticket = replace(self.ticket)
        self.assertEqual(self.progress()['fully_delivered_sets'], 0)

    def test_expired_or_closed_connection_is_not_complete(self):
        self.deliver_contents()
        self.state.client_closed = True
        self.assertEqual(self.progress()['fully_delivered_sets'], 0)
        self.assertEqual(self.registration['status'], 'client_closed')
        # Join has a separately bounded lifetime; expiration of the login
        # ticket alone no longer expires its already admitted connection.
        deadline = max(self.ticket.expires_at,
            self.server._admissions._joined_until[self.ticket.cookie])
        self.server._admissions._clock = lambda: deadline
        self.assertEqual(self.progress()['fully_delivered_sets'], 0)
        self.assertNotIn(self.ticket.cookie, self.server._registered_bootstraps)

    def test_authenticated_rebind_preserves_complete_content_delivery(self):
        self.deliver_contents()
        generation = self.registration['generation']
        helper = ProbeQueuedSendRebindTests()
        helper.server, helper.connection, helper.ticket = self.server, self.connection, self.ticket
        helper.new_peer = ('127.0.0.1', PEER[1] + 55)
        helper.migrate(.5)
        self.assertEqual(self.registration['peer'], helper.new_peer)
        self.assertIs(self.registration['generation'], generation)
        self.assertEqual(self.progress()['fully_delivered_sets'], 1)

    def test_requirement_rejects_truthy_nonboolean_values(self):
        for value in (1, 0, None, 'true'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.server.actor_transport_delivery_progress(require_post_open_contents=value)

    def test_repeated_progress_does_not_rebuild_frozen_content(self):
        self.deliver_contents()
        with patch.object(probe_runtime, 'preflight_actor_content_plans',
                wraps=probe_runtime.preflight_actor_content_plans) as compile_content:
            for _ in range(64):
                self.assertEqual(self.progress()['fully_delivered_sets'], 1)
            self.assertEqual(compile_content.call_count, 1)

    def test_changed_content_cannot_reuse_a_cached_delivery_proof(self):
        self.deliver_contents()
        self.assertEqual(self.progress()['fully_delivered_sets'], 1)
        plan = self.registration['post_open_actor_contents'][0]
        original = plan['content_blocks']
        plan['content_blocks'] = (ActorContentBlock(True, b'\x16', 5),)
        self.assertEqual(self.progress()['fully_delivered_sets'], 0)
        plan['content_blocks'] = original
        self.assertEqual(self.progress()['fully_delivered_sets'], 1)

    def test_changed_channel_sequence_invalidates_compiled_content(self):
        self.deliver_contents()
        self.assertEqual(self.progress()['fully_delivered_sets'], 1)
        self.state.initial_actor_sequence -= 1
        self.assertEqual(self.progress()['fully_delivered_sets'], 0)

    def test_smaller_packet_budget_cannot_reuse_compiled_content(self):
        self.deliver_contents()
        self.assertEqual(self.progress()['fully_delivered_sets'], 1)
        self.connection.max_packet_bytes = 1
        self.assertEqual(self.progress()['fully_delivered_sets'], 0)

    def test_expired_source_lease_cannot_reuse_compiled_content(self):
        class SourceLease:
            _probe_owned_source_lease = True
            current = True
            def __call__(self):
                return self.current
            def close(self):
                self.current = False
        self.deliver_contents()
        source = SourceLease()
        self.registration['movement_profile'] = SimpleNamespace(sources_current=source)
        self.assertEqual(self.progress()['fully_delivered_sets'], 1)
        source.close()
        self.assertEqual(self.progress()['fully_delivered_sets'], 0)


if __name__ == '__main__':
    unittest.main()
