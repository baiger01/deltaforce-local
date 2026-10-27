"""Receipt-journal capacity across content bursts, retries and shared sends."""
from unittest.mock import patch
import unittest

from dfserver.transport.native import legacy_ds_control_connection as connection_module
from dfserver.transport.native.legacy_ds_control_fields import encode_message
from tests import test_legacy_ds_content_fragmentation as fixtures
from tests.test_legacy_ds_actor_delivery import actor_fields
from tests.test_legacy_ds_control_probe import PEER


class ContentSendBackpressureTests(unittest.TestCase):
    def fixture(self):
        value = fixtures.ContentFragmentationTests()
        value.setUp()
        value.generation = fixtures.PendingChallenge(1., fixtures.COOKIE, 0.,
            echoed=True, verified_at=0., last_valid_activity_at=0.)
        value.connection._local_stage_generation_for_peer = lambda peer, state, transport: value.generation
        return value

    def acknowledge(self, value, packets, now):
        self.assertTrue(packets)
        value.ack(packets[-1].sequence, (0xffffffff,) * ((len(packets) + 31) // 32), now=now)

    def queue_burst(self, value):
        channels = tuple((channel, 2 * channel) for channel in range(2, 18))
        block = fixtures.content(65500)
        plans = tuple(dict(channel_index=channel, actor_guid=guid, content_blocks=(block,),
            continuations=((fixtures.content(3),),) if channel == 2 else ())
            for channel, guid in channels)
        value.queue(plans, channels=channels)

    def queue_opens(self, value, count=5):
        value.connection.queue_actor_opens(PEER, tuple(actor_fields(
            channel_index=channel, actor_guid=2 * channel) for channel in range(2, 2 + count)))

    def test_large_concurrent_burst_keeps_every_receipt_and_releases_its_continuation(self):
        value = self.fixture()
        self.queue_burst(value)
        first = value.sent(value.connection.poll(.3), .3)
        self.assertGreater(len(first), 0)
        self.assertLess(len(first), 144)
        self.assertLess(len(first), connection_module.MAX_ACTUAL_APPLICATION_SENDS)
        self.acknowledge(value, first, .35)
        state = value.state()
        self.assertTrue(value.connection._content_stage_receipted(
            PEER, state, value.connection.peers[PEER], state.actor_contents[2]))
        second = value.sent(value.connection.poll(.4), .4)
        self.acknowledge(value, second, .45)
        state = value.state()
        self.assertTrue(state.actor_contents[2].continuations[0].delivered)
        self.assertTrue(all(head.delivered for head in state.actor_contents.values()))
        self.assertTrue(all(value.connection._content_stage_receipted(
            PEER, state, value.connection.peers[PEER], head) for head in state.actor_contents.values()))
        self.assertLessEqual(len(state.actual_application_sends), connection_module.MAX_ACTUAL_APPLICATION_SENDS)

    def test_unsent_preparations_reserve_slots_and_retries_reuse_them(self):
        value = self.fixture()
        self.queue_burst(value)
        first = value.connection.poll(.3)
        self.assertLess(len(first), 144)
        self.assertEqual(value.connection.poll(.4), [])
        retry = value.connection.poll(.9)
        self.assertEqual(len(retry), len(first))
        first_bunches = [fixtures.decode_observed_application(body, max_packet_bytes=1024,
            received_by_server=False).bunches for peer, event, body in first]
        retry_bunches = [fixtures.decode_observed_application(body, max_packet_bytes=1024,
            received_by_server=False).bunches for peer, event, body in retry]
        self.assertEqual(retry_bunches, first_bunches)
        self.assertEqual(value.connection.poll(1.), [])
        # Preparing and retrying alone never makes a piece ACK eligible.
        original_packets = [fixtures.decode_observed_application(body, max_packet_bytes=1024,
            received_by_server=False) for peer, event, body in first]
        self.acknowledge(value, original_packets, 1.05)
        self.assertFalse(any(piece.delivered for head in value.state().actor_contents.values()
            for piece in head.fragments))
        actual_retry = value.sent(retry, 1.1)
        self.acknowledge(value, actual_retry, 1.15)
        self.assertTrue(value.sent(value.connection.poll(1.2), 1.2))

    def test_shared_control_and_empty_send_traffic_cannot_evict_unreceipted_pieces(self):
        value = self.fixture()
        value.queue((dict(channel_index=2, actor_guid=4,
            content_blocks=(fixtures.content(16670),), continuations=((fixtures.content(3),),)),))
        fragments = value.sent(value.connection.poll(.3), .3)
        self.assertGreater(len(fragments), 1)
        state, transport = value.state(), value.connection.peers[PEER]
        value.connection._queue(state, 3, encode_message(3, 'pending-fixture'))
        last = None
        for index in range(connection_module.MAX_ACTUAL_APPLICATION_SENDS + 8):
            now = .4 + index / 10000
            body = value.connection._encode_reply(transport, state, transport.in_sequence,
                transport.history, now, count_as_control=False)
            last = value.sent(((PEER, 'shared_application_send', body),), now)[0]
        value.ack(last.sequence, (0xffffffff,) * 8, now=.5)
        state = value.state()
        self.assertTrue(state.actor_contents[2].delivered)
        self.assertTrue(value.connection._content_stage_receipted(
            PEER, state, value.connection.peers[PEER], state.actor_contents[2]))
        self.assertTrue(value.connection.poll(.6))
        self.assertLessEqual(len(state.actual_application_sends), connection_module.MAX_ACTUAL_APPLICATION_SENDS)

    def test_old_retry_ack_without_retained_full_send_proof_does_not_strand_an_open(self):
        value = self.fixture()
        with patch.object(connection_module, 'MAX_ACTUAL_APPLICATION_SENDS', 4):
            self.queue_opens(value)
            first = value.sent(value.connection.poll(.1), .1)
            self.assertEqual(len(first), 3)
            retry = value.sent(value.connection.poll(.9), .9)
            self.assertEqual(len(retry), 3)
            # The newest full send for each outstanding bunch is protected.
            self.assertNotIn(first[0].sequence, {s.sequence for s in value.state().actual_application_sends})
            value.ack(first[0].sequence, now=.95)
            self.assertFalse(value.state().actor_opens[2].delivered)
            self.acknowledge(value, retry, 1.)
            remaining = value.sent(value.connection.poll(1.1), 1.1)
            self.assertEqual(len(remaining), 2)
            self.acknowledge(value, remaining, 1.2)
            self.assertTrue(all(item.delivered for item in value.state().actor_opens.values()))

    def test_actor_opens_and_unsent_deadlines_share_the_same_bounded_reservations(self):
        value = self.fixture()
        with patch.object(connection_module, 'MAX_ACTUAL_APPLICATION_SENDS', 4):
            self.queue_opens(value)
            first = value.connection.poll(.1)
            self.assertEqual(len(first), 3)
            self.assertEqual(value.connection.poll(.2), [])
            later = value.connection.poll(121.)
            self.assertEqual(len(later), 2)
            self.assertTrue(all(item.local_stage_expired for channel, item in value.state().actor_opens.items()
                if channel < 5))
            self.assertFalse(any(item.sent_packets for item in value.state().actor_opens.values()))

    def test_stale_generation_full_send_callback_does_not_replace_the_current_journal(self):
        value = self.fixture()
        self.queue_opens(value, 1)
        prepared = value.connection.poll(.1)
        before = value.state().actual_application_sends
        old_generation = value.generation
        value.generation = fixtures.PendingChallenge(2., fixtures.COOKIE, 0.,
            echoed=True, verified_at=0., last_valid_activity_at=0.)
        self.assertFalse(value.connection._note_actual_application_send(PEER, prepared[0][2],
            generation=old_generation, ticket=value.ticket, transport=value.connection.peers[PEER], sent_at=.2))
        self.assertIs(value.state().actual_application_sends, before)

    def test_old_plus_new_wire_budget_is_checked_before_atomic_queue_publication(self):
        value = self.fixture()
        block = fixtures.content(65500)
        def plan(channel, guid):
            return dict(channel_index=channel, actor_guid=guid, content_blocks=(block,),
                continuations=tuple((block,) for _ in range(15)))
        value.connection.queue_actor_opens(PEER, (actor_fields(channel_index=2, actor_guid=4),),
            post_open_actor_contents=(plan(2, 4),))
        before = value.state()
        events = value.connection.control_events.copy()
        with self.assertRaisesRegex(ValueError, 'wire-fragment'):
            value.connection.queue_actor_opens(PEER, (actor_fields(channel_index=3, actor_guid=6),),
                post_open_actor_contents=(plan(3, 6),))
        self.assertIs(value.state(), before)
        self.assertEqual(value.connection.control_events, events)
        self.assertEqual(set(value.state().actor_opens), {2})
        self.assertEqual(set(value.state().actor_contents), {2})

    def test_combined_wire_budget_accepts_its_exact_boundary(self):
        value = self.fixture()
        large, small = fixtures.content(65500), fixtures.content(3)
        value.connection.queue_actor_opens(PEER, (actor_fields(channel_index=2, actor_guid=4),),
            post_open_actor_contents=(dict(channel_index=2, actor_guid=4, content_blocks=(large,),
                continuations=tuple((large,) for _ in range(15))),))
        value.connection.queue_actor_opens(PEER, (actor_fields(channel_index=3, actor_guid=6),),
            post_open_actor_contents=(dict(channel_index=3, actor_guid=6, content_blocks=(large,),
                continuations=tuple((large,) for _ in range(11)) + ((small,),) * 4),))
        self.assertEqual(len(connection_module._content_wire_items(value.state())),
            connection_module.MAX_POST_OPEN_WIRE_BUNCHES)


if __name__ == '__main__':
    unittest.main()
