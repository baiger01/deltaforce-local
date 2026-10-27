"""Explicit admitted transport mode: real sends/positive ACKs and atomic mixed receipt."""
from dataclasses import replace
import hashlib
from pathlib import Path
import unittest

from dfserver.legacy_ds_control_connection import MAX_PC_STARTUP_RECEIPT_REPLIES
from dfserver.legacy_ds_control_fields import encode_message
from dfserver.legacy_ds_game_state_start import GameStateStartProfile
from dfserver.legacy_ds_guid_exports import GuidExportNode
from dfserver.legacy_ds_handshake_probe import PendingChallenge
from dfserver.legacy_ds_rep_layout_refs import build_empty_rep_layout_content
from dfserver.legacy_ds_scalar_serializers import SHIPPING_SHA256
from dfserver.legacy_ds_wire_codec import ChannelName, WireBunch, encode_observed_application
from tests.test_legacy_ds_actor_delivery import ActorDeliveryTests, actor_fields, decode
from tests.test_legacy_ds_control_probe import COOKIE, PEER
from tests.test_legacy_ds_pc_restart_rpc import PROFILE as RESTART
from tests.test_legacy_ds_pc_startup_rpc import PROFILE as STARTUP, rpc


class AdmittedActorReceiptTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ActorDeliveryTests()
        self.fixture.setUp()
        self.connection = self.fixture.connection
        self.ticket = self.fixture.ticket
        self.assertTrue(callable(getattr(self.connection, 'enable_admitted_actor_receipts', None)),
            'Explicit admitted reliable Actor receipt mode is missing')
        self.generation = PendingChallenge(1.0, COOKIE, 0.0, echoed=True,
            verified_at=0.0, last_valid_activity_at=0.0)
        self.connection._local_stage_generation_for_peer = lambda peer, state, transport: self.generation
        fields = tuple(actor_fields(channel_index=channel, actor_guid=guid)
            for channel, guid in ((2, 4), (3, 6), (4, 2), (5, 8), (12, 42), (13, 44)))
        fields += (dict(actor_kind='static', channel_index=8, actor_guid=57,
            exports=(GuidExportNode(57, 'FixtureDoor'),), references_resolvable=True,
            actor_open_hook_has_no_extra_fields=True),)
        self.actor_count = len(fields)
        plans = tuple(dict(channel_index=value['channel_index'], actor_guid=value['actor_guid'],
            content_blocks=(build_empty_rep_layout_content(),),
            **({'static_content_source_sha256': 'a' * 64} if value.get('actor_kind') == 'static' else {}))
            for value in fields)
        self.connection.queue_actor_opens(PEER, fields, post_open_actor_contents=plans)
        self.connection.set_pc_startup_profile(PEER, 2, 4, STARTUP)
        self.connection.set_game_state_start_profile(PEER, 3, 6,
            GameStateStartProfile('/Game/Fixture.GameState_C', 19, SHIPPING_SHA256, 'c' * 64,
                all_ready_handle=24, abseil_handle=107, map_id_handle=52, room_id_handle=53))
        self.connection.set_pc_restart_profile(PEER, 2, 4, 2, RESTART)
        self.seed = self.state().hello_sequence

    def state(self):
        return self.connection.control_peers[PEER]

    def send(self, bunches=(), *, now=.5, generation=None, history=(0xffffffff,)):
        transport = self.connection.peers[PEER]
        packet = replace(self.fixture.template, sequence=(transport.in_sequence + 1) & 16383,
            acknowledged_sequence=(transport.out_sequence - 1) & 16383,
            history=history, bunches=bunches)
        raw = b'opaque!!' + encode_observed_application(packet, max_packet_bytes=1024, received_by_server=True)
        return self.connection.handle(raw, PEER, now,
            verified_generation=self.generation if generation is None else generation)

    def deliver(self):
        transport = self.connection.peers[PEER]
        for now in (.1, .3):
            replies = self.connection.poll(now)
            self.assertEqual(len(replies), self.actor_count)
            for peer, event, body in replies:
                self.assertTrue(self.connection._note_actual_application_send(peer, body,
                    generation=self.generation, ticket=self.ticket, transport=transport, sent_at=now))
            self.send(now=now + .05)
        self.assertEqual(len(self.state().actual_actor_receipts), 2 * self.actor_count)

    def enable(self, channels=(5, 12, 13)):
        self.connection.enable_admitted_actor_receipts(PEER, owned_actor_channels=channels)

    def bunch(self, channel=4, sequence=None, payload=b'\x01', **flags):
        return WireBunch(channel, payload, len(payload) * 8, reliable=True,
            channel_sequence=self.seed if sequence is None else sequence,
            channel_name=ChannelName(hardcoded_index=102), **flags)

    def control(self, message_id, *fields, sequence=None):
        payload = encode_message(message_id, *fields)
        return replace(self.fixture.template.bunches[0], open=False,
            channel_sequence=self.state().expected_client_sequence if sequence is None else sequence,
            payload=payload, payload_bits=len(payload) * 8)

    def marker(self):
        event, body = self.send((rpc(self.seed, 79),), now=.4)
        self.assertEqual(event, 'pc_startup_packet_consumed')
        self.assertIsNotNone(body)

    def restore_captured_consumed_control(self, rows):
        # Only the four actual pre-join messages are already consumed. Native
        # post-join failure/GameSpecific messages must pass the real receiver.
        consumed = {b.channel_sequence: hashlib.sha256(b.payload).digest()
            for record, packet in rows if record['direction'] == 'received'
            for b in packet.bunches if b.channel_index == 0 and 528 <= b.channel_sequence <= 531}
        self.assertEqual(set(consumed), {528, 529, 530, 531})
        self.state().expected_client_sequence = 532
        self.state().consumed = consumed

    def test_default_mode_still_rejects_unknown_actor_bodies(self):
        self.deliver()
        self.assertFalse(self.state().admitted_actor_reliable_receipts)
        self.assertIsNone(self.send((self.bunch(),))[1])

    def test_rejection_reason_codes_preserve_whole_packet_rollback(self):
        self.deliver()
        self.enable()
        invalid = (
            (self.bunch(sequence=(self.seed + 256) % 1024), 'pawn_ledger_nonconsecutive_sequence'),
            (self.bunch(14), 'actor_channel_outside_owned_namespace'),
            (replace(self.bunch(2), reliable=False, channel_sequence=None, channel_name=None,
                partial=True), 'pc_ledger_unsupported_or_malformed_bunch'),
            (self.control(16, 2), 'control_actor_failure_outside_static_subset'),
        )
        for ordinal, (bunch, reason) in enumerate(invalid):
            with self.subTest(reason=reason):
                event, response = self.send((self.bunch(5), bunch), now=.5 + ordinal * .1)
                self.assertEqual(event, 'admitted_actor_reliable_packet_rejected')
                self.assertIsNone(response)
                self.assertEqual(self.state().admitted_actor_last_rejection[2], reason)
                self.assertEqual(self.state().admitted_actor_rejection_counts[reason], 1)
                self.assertIsNone(self.state().admitted_pawn_receipt)
                self.assertEqual(self.state().admitted_actor_receipt_ledgers, {})

    def test_prior_trial_plain_unreliable_pc_packets_are_now_transport_received(self):
        import runpy
        script = Path(__file__).resolve().parents[3] / 'work/audit_current_receipt_rejections_1792385022786009500.py'
        trial = script.parent / 'native-client-tests/1792385022786009500/game-server-packets/report.json'
        if not trial.exists():
            self.skipTest('Exact private current trial is not present')
        audit = runpy.run_path(str(script))
        _, digest, rows, _ = audit['load']()
        self.assertEqual(digest, '309319f33842462170b109f7c06a5e6ee23fa9300ed2e963cdcfd84d028b0f26')
        self.deliver()
        hello = next(b for r, p in rows if r['direction'] == 'received' for b in p.bunches
            if b.channel_index == 0 and b.open and b.payload and b.payload[0] == 0)
        self.state().hello_sequence = self.seed = hello.channel_sequence
        pre_sequences = {(self.seed + ordinal) % 1024 for ordinal in range(4)}
        self.state().consumed = {b.channel_sequence: hashlib.sha256(b.payload).digest()
            for r, p in rows if r['direction'] == 'received' for b in p.bunches
            if b.channel_index == 0 and b.channel_sequence in pre_sequences}
        self.state().expected_client_sequence = (self.seed + 4) % 1024
        from tests.test_legacy_ds_pc_ping_receiver import PROFILE as PING
        self.connection.set_pc_ping_profile(PEER, 2, 4, PING)
        self.enable()
        accepted_pawns = 0
        for ordinal, (record, packet) in enumerate(rows):
            if record['direction'] != 'received' or record['elapsed_seconds'] < 325.375:
                continue
            event, response = self.send(packet.bunches, now=.5 + ordinal * .02, history=(0,))
            if event == 'admitted_actor_reliable_packet_received':
                accepted_pawns += sum(b.channel_index == 4 for b in packet.bunches)
            elif packet.bunches:
                self.assertIsNone(response)
                self.assertEqual(self.state().admitted_actor_last_rejection[2], 'pc_unreliable_rpc_unsupported')
        self.assertEqual(accepted_pawns, 16)
        self.assertEqual(self.state().admitted_actor_rejection_counts, {})

    def test_actual_capture_shaped_mixed_pc_pawn_state_guns_control_duplicate_is_transport_acked(self):
        self.deliver()
        self.marker()
        self.enable()
        control = replace(self.fixture.template.bunches[0], open=False,
            channel_sequence=self.state().expected_client_sequence - 1,
            payload=encode_message(4, 25000) + encode_message(9))
        control = replace(control, payload_bits=len(control.payload) * 8)
        bunches = (control, rpc((self.seed + 1) % 1024, 200), self.bunch(),
            self.bunch(5), self.bunch(12), self.bunch(13))
        event, body = self.send(bunches)
        self.assertEqual(event, 'admitted_actor_reliable_packet_received')
        self.assertEqual(decode(body).history[0] & 1, 1)
        self.assertEqual(self.state().pc_opaque_receipt_count, 1)
        self.assertFalse(self.state().pc_startup_semantic_whole.get((self.seed + 1) % 1024, False))
        self.assertEqual(self.state().admitted_pawn_receipt.expected_sequence, (self.seed + 1) % 1024)
        event, body = self.send(bunches, now=.6)
        self.assertEqual(decode(body).history[0] & 1, 1)
        self.assertEqual(self.state().pc_opaque_receipt_count, 1)
        self.assertFalse(self.connection.summary()['admitted_actor_rpc_gameplay_handled'])

    def test_prepared_or_fake_delivered_actor_without_actual_full_send_receipts_is_refused(self):
        self.enable()
        self.assertIsNone(self.send((self.bunch(),))[1])
        for item in (*self.state().actor_opens.values(), *self.state().actor_contents.values()):
            item.delivered, item.transmissions, item.sent_packets = True, 1, (200,)
        self.assertIsNone(self.send((self.bunch(),), now=.6)[1])
        self.assertEqual(self.connection.peers[PEER].history & 1, 0)
        self.assertIsNone(self.state().admitted_pawn_receipt)

    def test_binding_scans_actual_receipts_once_for_all_prerequisites(self):
        class CountingReceipts(tuple):
            scans = 0
            def __iter__(self):
                self.scans += 1
                return super().__iter__()
        self.deliver()
        self.enable()
        state = self.state()
        receipts = state.actual_actor_receipts = CountingReceipts(state.actual_actor_receipts)
        self.connection._admitted_actor_receipt_binding(state, state, PEER,
            self.connection.peers[PEER], self.generation)
        self.assertEqual(receipts.scans, 1)

    def test_foreign_or_changed_receipt_cannot_complete_the_current_proof(self):
        self.deliver()
        self.enable()
        state = self.state()
        receipts = state.actual_actor_receipts
        first = receipts[0]
        transport = self.connection.peers[PEER]
        for changed in (replace(first, ticket=replace(first.ticket)),
                        replace(first, transport=replace(transport)),
                        replace(first, generation=replace(self.generation)),
                        replace(first, bunch=replace(first.bunch, payload=b'changed'))):
            with self.subTest(changed=changed is first):
                state.actual_actor_receipts = (changed, *receipts[1:])
                with self.assertRaisesRegex(ValueError, 'initial_delivery_proof_missing'):
                    self.connection._admitted_actor_receipt_binding(state, state, PEER,
                        transport, self.generation)
        state.actual_actor_receipts = receipts

    def test_generation_expired_admission_and_closed_peer_are_refused(self):
        self.deliver()
        self.enable()
        foreign = replace(self.generation)
        self.assertIsNone(self.send((self.bunch(),), generation=foreign)[1])
        self.assertIsNone(self.state().admitted_pawn_receipt)
        self.connection.admissions.revoke(self.ticket)
        self.assertIsNone(self.send((self.bunch(),), now=.6)[1])
        self.state().client_closed = True
        self.assertIsNone(self.send((self.bunch(),), now=.7)[1])

    def test_wrong_seed_and_unsupported_mixed_piece_reject_atomically(self):
        self.deliver()
        self.enable()
        self.assertIsNone(self.send((self.bunch(sequence=1),))[1])
        self.assertIsNone(self.state().admitted_pawn_receipt)
        event, body = self.send((self.bunch(), self.bunch(14)), now=.6)
        self.assertIsNone(body)
        self.assertIsNone(self.state().admitted_pawn_receipt)
        self.assertEqual(self.state().admitted_actor_opaque_journal, ())
        self.assertEqual(self.connection.peers[PEER].history & 1, 0)

    def test_malformed_unreliable_exports_and_unknown_control_do_not_gain_packet_ack(self):
        self.deliver()
        self.enable()
        unknown_control = replace(self.fixture.template.bunches[0], open=False,
            channel_sequence=self.state().expected_client_sequence, payload=b'\x0a', payload_bits=8)
        invalid = (replace(self.bunch(), reliable=False, channel_sequence=None, channel_name=None, partial=True),
            self.bunch(package_exports=True), self.bunch(must_be_mapped=True), unknown_control)
        for ordinal, bunch in enumerate(invalid):
            with self.subTest(bunch=bunch):
                self.assertIsNone(self.send((self.bunch(), bunch), now=.5 + ordinal * .1)[1])
                self.assertIsNone(self.state().admitted_pawn_receipt)

    def test_receipt_ack_is_not_subject_to_legacy_total_reply_limits(self):
        self.deliver()
        self.marker()
        self.enable()
        self.state().pc_startup_receipt_reply_count = MAX_PC_STARTUP_RECEIPT_REPLIES
        self.connection.peers[PEER].replies = self.connection.max_replies
        for ordinal in range(300):
            event, body = self.send((self.bunch(sequence=(self.seed + ordinal) % 1024),), now=.5 + ordinal * .02)
            self.assertIsNotNone(body, event)
            self.assertEqual(decode(body).history[0] & 1, 1)
        self.assertLessEqual(len(self.state().admitted_pawn_receipt.journal), 256)

    def test_enable_rejects_game_state_unopened_and_repeated_namespaces(self):
        for channels in ((3,), (99,), (4, 4)):
            with self.subTest(channels=channels), self.assertRaises(ValueError):
                self.connection.enable_admitted_actor_receipts(PEER, owned_actor_channels=channels)

    def test_pc_opaque_first_receipt_and_partial_pawn_use_trusted_hello_seed(self):
        self.deliver()
        self.enable()
        first = self.bunch(payload=b'A', partial=True, partial_initial=True)
        event, body = self.send((rpc(self.seed, 200), first))
        self.assertEqual(decode(body).history[0] & 1, 1)
        self.assertFalse(self.state().pc_possession_ack_received)
        self.assertEqual(self.state().pc_reliable_receipt.expected_sequence, (self.seed + 1) % 1024)
        final = replace(self.bunch(sequence=(self.seed + 1) % 1024, payload=b'\x05',
            partial=True, partial_final=True), payload_bits=3)
        event, body = self.send((final,), now=.6)
        self.assertEqual(decode(body).history[0] & 1, 1)
        self.assertEqual(self.state().admitted_pawn_receipt.journal[-1].ready[0].payload_bits, 11)

    def test_later_bad_pc_or_pawn_bunch_rolls_back_every_channel(self):
        self.deliver()
        self.enable()
        for invalid in (rpc((self.seed + 256) % 1024, 79),
                self.bunch(sequence=(self.seed + 257) % 1024),
                self.bunch(partial=True, partial_final=True)):
            with self.subTest(channel=invalid.channel_index):
                self.assertIsNone(self.send((self.bunch(5), self.bunch(), invalid))[1])
                self.assertIsNone(self.state().admitted_pawn_receipt)
                self.assertEqual(self.state().admitted_actor_receipt_ledgers, {})
                self.assertEqual(self.state().admitted_actor_opaque_journal, ())

    def test_foreign_peer_transport_and_changed_namespace_do_not_reuse_lease(self):
        self.deliver()
        self.enable()
        transport = self.connection.peers[PEER]
        self.connection.peers[PEER] = replace(transport)
        self.assertIsNone(self.send((self.bunch(),))[1])
        self.connection.peers[PEER] = transport
        self.connection.ticket_peers[self.ticket.cookie] = ('127.0.0.1', 31001)
        self.assertIsNone(self.send((self.bunch(),))[1])
        self.connection.ticket_peers[self.ticket.cookie] = PEER
        self.state().actor_opens[4].actor_guid = 80
        self.assertIsNone(self.send((self.bunch(),))[1])
        self.assertIsNone(self.state().admitted_pawn_receipt)

    def test_private_captured_pawn_retries_are_acked_without_possession_gate(self):
        trial = Path(__file__).resolve().parents[3] / 'work/native-client-tests/1792376752204334900'
        if not (trial / 'game-server-packets/report.json').exists():
            self.skipTest('Exact private local trial is not present')
        from audit_owned_pawn_receipts_20261019 import load_pawn_receipt_fixture
        self.deliver()
        self.state().hello_sequence = self.seed = 528
        self.enable()
        fixture = load_pawn_receipt_fixture(trial)
        self.assertEqual(len(fixture), 232)
        for ordinal, (record, bunch) in enumerate(fixture):
            event, body = self.send((bunch,), now=.5 + ordinal * .02)
            self.assertIsNotNone(body, event)
            self.assertEqual(decode(body).history[0] & 1, 1)
        self.assertEqual(self.state().admitted_pawn_receipt.expected_sequence, 546)
        self.assertEqual(len(self.state().admitted_pawn_receipt.journal), 18)
        self.assertFalse(self.state().pc_possession_ack_received)

    def test_exact_private_mixed_packet_receipts_control_pc_pawn_state_and_two_guns(self):
        trial = Path(__file__).resolve().parents[3] / 'work/native-client-tests/1792376752204334900'
        if not (trial / 'game-server-packets/report.json').exists():
            self.skipTest('Exact private local trial is not present')
        from audit_owned_pawn_receipts_20261019 import load_packet_fixture
        _, _, packets, _ = load_packet_fixture(trial)
        _, packet = next((record, packet) for record, packet in packets
            if record['direction'] == 'received' and
            {b.channel_index for b in packet.bunches} == {0, 2, 4, 5, 12, 13} and
            all(b.reliable for b in packet.bunches))
        self.deliver()
        self.state().hello_sequence = self.seed = 528
        self.restore_captured_consumed_control(packets)
        self.enable()
        event, body = self.send(packet.bunches)
        self.assertEqual(event, 'admitted_actor_reliable_packet_received')
        self.assertIsNotNone(body)
        self.assertEqual(decode(body).history[0] & 1, 1)
        self.assertEqual(self.state().admitted_pawn_receipt.expected_sequence, 529)
        self.assertEqual(set(self.state().admitted_actor_receipt_ledgers), {5, 12, 13})
        self.assertEqual(self.state().client_failed_actor_channels[8], 57)

    def test_actual_unseeded_post_join_packet_stream_receipts_every_saved_pawn_bunch(self):
        trial = Path(__file__).resolve().parents[3] / 'work/native-client-tests/1792376752204334900'
        if not (trial / 'game-server-packets/report.json').exists():
            self.skipTest('Exact private local trial is not present')
        from audit_owned_pawn_receipts_20261019 import load_packet_fixture
        from tests.test_legacy_ds_pc_ping_receiver import PROFILE as PING
        _, _, rows, _ = load_packet_fixture(trial)
        self.deliver()
        self.state().hello_sequence = self.seed = 528
        self.restore_captured_consumed_control(rows)
        self.connection.set_pc_ping_profile(PEER, 2, 4, PING)
        self.enable()
        pawn_received = 0
        for ordinal, (record, packet) in enumerate(rows):
            if record['direction'] != 'received' or record['elapsed_seconds'] < 176.469:
                continue
            event, body = self.send(packet.bunches, now=.5 + ordinal * .02, history=(0,))
            if any(b.channel_index == 4 for b in packet.bunches):
                self.assertEqual(event, 'admitted_actor_reliable_packet_received')
                self.assertIsNotNone(body)
                self.assertEqual(decode(body).history[0] & 1, 1)
                pawn_received += sum(b.channel_index == 4 for b in packet.bunches)
        self.assertEqual(pawn_received, 225)
        self.assertEqual(self.state().admitted_pawn_receipt.expected_sequence, 546)
        self.assertEqual(self.state().client_failed_actor_channels, {8: 57})
        self.assertTrue(self.state().client_begin_play_notified)
        self.assertEqual(self.state().client_begin_play_notification_count, 1)
        self.assertEqual(self.state().expected_client_sequence, 534)
        self.assertEqual(self.state().pc_reliable_receipt.expected_sequence, 555)
        self.assertFalse(self.connection.summary()['native_actor_resolution_verified'])

    def test_qualified_static_failure_stays_visible_preserves_proofs_and_stops_retries(self):
        from dfserver.legacy_ds_control_connection import _content_namespace
        self.deliver()
        self.enable()
        namespace = _content_namespace(self.state())
        proofs = self.state().actual_actor_receipts
        failure = self.control(16, 8)
        event, body = self.send((failure, self.bunch()))
        self.assertEqual(decode(body).history[0] & 1, 1)
        self.assertEqual(self.state().client_failed_actor_channels, {8: 57})
        self.assertEqual(self.state().actual_actor_receipts, proofs)
        self.assertEqual(_content_namespace(self.state()), namespace)
        self.assertFalse(self.state().client_begin_play_notified)
        self.assertIsNone(self.state().game_state_start)
        self.assertEqual(self.connection.summary()['client_failed_static_actor_channels'],
            [dict(channel_index=8, actor_guid=57)])
        self.assertEqual(decode(self.send((failure,), now=.6)[1]).history[0] & 1, 1)
        candidate = self.connection._clone(self.state())
        failed = candidate.actor_opens[8]
        failed.delivered, failed.transmissions, failed.sent_packets = False, 0, ()
        self.assertFalse(self.connection._stage_can_prepare(PEER, candidate,
            self.connection.peers[PEER], failed, 1.))

    def test_known_client_begin_play_is_a_deduplicated_notification_only(self):
        self.deliver()
        self.enable()
        begin_play = self.control(20, 0, '')
        for now in (.5, .6):
            event, body = self.send((begin_play,), now=now)
            self.assertEqual(decode(body).history[0] & 1, 1)
        self.assertTrue(self.state().client_begin_play_notified)
        self.assertEqual(self.state().client_begin_play_notification_count, 1)
        self.assertFalse(self.state().pc_ready_notification_received)
        self.assertFalse(self.state().pc_possession_ack_received)
        self.assertIsNone(self.state().game_state_start)

    def test_foreign_dynamic_owned_failures_and_other_game_specific_notifications_reject_atomically(self):
        self.deliver()
        self.enable()
        invalid = tuple(self.control(16, channel) for channel in (0, 2, 3, 4, 5, 12, 13, 99))
        invalid += tuple(self.control(20, subtype, '') for subtype in (1, 2, 255))
        invalid += (self.control(20, 0, 'unqualified'),
            self.control(16, 8, sequence=(self.state().expected_client_sequence + 1) % 1024))
        for ordinal, control in enumerate(invalid):
            with self.subTest(ordinal=ordinal):
                self.assertIsNone(self.send((self.bunch(), control), now=.5 + ordinal * .1)[1])
                self.assertEqual(self.state().client_failed_actor_channels, {})
                self.assertFalse(self.state().client_begin_play_notified)
                self.assertIsNone(self.state().admitted_pawn_receipt)

    def test_later_invalid_bunch_rolls_back_control_failure_and_begin_play_notification(self):
        self.deliver()
        self.enable()
        sequence = self.state().expected_client_sequence
        control = replace(self.control(16, 8), payload=encode_message(16, 8) + encode_message(20, 0, ''),
            payload_bits=88)
        self.assertIsNone(self.send((control, self.bunch(sequence=(self.seed + 256) % 1024)))[1])
        self.assertEqual(self.state().expected_client_sequence, sequence)
        self.assertEqual(self.state().client_failed_actor_channels, {})
        self.assertFalse(self.state().client_begin_play_notified)

    def test_each_initial_positive_receipt_and_exact_namespace_remains_mandatory(self):
        self.deliver()
        self.enable()
        receipts = self.state().actual_actor_receipts
        for missing in receipts:
            with self.subTest(channel=missing.bunch.channel_index):
                self.state().actual_actor_receipts = tuple(r for r in receipts if r is not missing)
                self.assertIsNone(self.send((self.bunch(),), history=(0,))[1])
                self.assertIsNone(self.state().admitted_pawn_receipt)
        self.state().actual_actor_receipts = receipts
        head = self.state().actor_contents[5]
        head.bunch = replace(head.bunch, payload=b'\x01', payload_bits=8)
        self.assertIsNone(self.send((self.bunch(),))[1])

    def test_opaque_journal_rolls_under_both_entry_and_byte_limits(self):
        self.deliver()
        self.enable()
        for ordinal in range(360):
            event, body = self.send((self.bunch(5, (self.seed + ordinal) % 1024,
                b'j' * 900),), now=.5 + ordinal * .02)
            self.assertIsNotNone(body, event)
        self.assertLessEqual(len(self.state().admitted_actor_opaque_journal), 256)
        self.assertLessEqual(self.state().admitted_actor_opaque_journal_bytes, 262144)

    def test_beyond_window_initial_sequence_cannot_seed_any_owned_channel(self):
        self.deliver()
        self.enable()
        for channel in (2, 4, 5, 12, 13):
            with self.subTest(channel=channel):
                self.assertIsNone(self.send((self.bunch(channel,
                    (self.seed + 256) % 1024),))[1])
                self.assertIsNone(self.state().admitted_pawn_receipt)
                self.assertIsNone(self.state().pc_reliable_receipt)
                self.assertEqual(self.state().admitted_actor_receipt_ledgers, {})

    def test_malformed_wire_packet_never_receipts_a_body(self):
        self.deliver()
        self.enable()
        event, response = self.connection.handle(b'opaque!!' + b'\x01' * 12,
            PEER, .5, verified_generation=self.generation)
        self.assertEqual(event, 'application_header_rejected')
        self.assertIsNone(response)
        self.assertIsNone(self.state().admitted_pawn_receipt)
        self.assertEqual(self.state().admitted_actor_opaque_journal, ())

    def test_private_initial_ack_gate_opens_while_first_pawn_sequence_still_retries(self):
        trial = Path(__file__).resolve().parents[3] / 'work/native-client-tests/1792376752204334900'
        if not (trial / 'game-server-packets/report.json').exists():
            self.skipTest('Exact private local trial is not present')
        from audit_owned_pawn_receipts_20261019 import load_packet_fixture, load_pawn_receipt_fixture
        _, _, rows, _ = load_packet_fixture(trial)
        received = [(r, p) for r, p in rows if r['direction'] == 'received']
        # The loader pins this exact trial. Its initial Actor series occupies
        # outbound packets 1571..1623, preceding the first startup reply.
        initial = [(r, p, b) for r, p in rows if r['direction'] == 'sent'
            for b in p.bunches if b.channel_index > 0 and b.reliable and 1571 <= p.sequence <= 1623]
        self.assertEqual((sum(b.open for _, _, b in initial),
            sum(not b.open for _, _, b in initial)), (12, 41))
        first_ack_times = []
        for sent, packet, bunch in initial:
            ack, _ = next((r, p) for r, p in received
                if r['elapsed_seconds'] >= sent['elapsed_seconds'] and
                (distance := (p.acknowledged_sequence - packet.sequence) & 16383) < len(p.history) * 32 and
                (p.history[distance // 32] >> (distance % 32)) & 1)
            first_ack_times.append(ack['elapsed_seconds'])
        all_initial_ack_at = max(first_ack_times)
        self.assertEqual(all_initial_ack_at, 176.469)
        self.deliver()
        self.state().hello_sequence = self.seed = 528
        self.enable()
        proofs = self.state().actual_actor_receipts
        self.state().actual_actor_receipts = proofs[:-1]
        rejected = accepted = 0
        for ordinal, (record, bunch) in enumerate(load_pawn_receipt_fixture(trial)):
            ready = record['elapsed_seconds'] >= all_initial_ack_at
            if ready:
                self.state().actual_actor_receipts = proofs
            event, body = self.send((bunch,), now=.5 + ordinal * .02, history=(0,))
            if ready:
                self.assertIsNotNone(body, event)
                self.assertEqual(decode(body).history[0] & 1, 1)
                accepted += 1
            else:
                self.assertIsNone(body)
                self.assertEqual(bunch.channel_sequence, 528)
                self.assertIsNone(self.state().admitted_pawn_receipt)
                rejected += 1
        self.assertEqual((rejected, accepted), (7, 225))
        self.assertEqual(self.state().admitted_pawn_receipt.expected_sequence, 546)


if __name__ == '__main__':
    unittest.main()
