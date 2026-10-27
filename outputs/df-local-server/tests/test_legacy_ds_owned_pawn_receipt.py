"""Pure owning-Pawn receipt gates, exact seed and actual private capture replay."""
from dataclasses import replace
import importlib
import importlib.util
from pathlib import Path
import unittest

from dfserver.legacy_ds_control_connection import ActorOpenDelivery, ControlConnection
from dfserver.legacy_ds_wire_codec import ChannelName, WireBunch

MODULE = 'dfserver.legacy_ds_owned_pawn_receipt'


class OwnedPawnReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = importlib.import_module(MODULE) if importlib.util.find_spec(MODULE) else None

    def setUp(self):
        self.assertIsNotNone(self.module, 'The pure qualified owning-Pawn receipt adapter is missing')
        self.state = ControlConnection(528, 540, 544, b'')
        self.state.ticket = object()
        self.state.client_join_observed = True
        self.state.pc_restart_ticket = self.state.ticket
        self.state.pc_restart_channel = 2
        self.state.pc_restart_actor_guid = 4
        self.state.pc_restart_pawn_channel = 4
        self.state.pc_restart_pawn_guid = 2
        self.state.actor_opens = {
            channel: ActorOpenDelivery(self.bunch(channel=channel), actor, delivered=True)
            for channel, actor in ((2, 4), (4, 2))}
        self.binding = self.module.OwnedPawnReceiptBinding(peer=('127.0.0.1', 31000),
            ticket=self.state.ticket, generation=object(), transport=object(),
            admission_active=True, configured_owner_current=True,
            pawn_open_full_send_acknowledged=True, all_initial_content_acknowledged=True)
        self.adapter = self.module.OwnedPawnReceiptAdapter(self.state, binding=self.binding)

    def bunch(self, sequence=528, *, channel=4, payload=b'\x01', bits=8, **flags):
        return WireBunch(channel, payload, bits, reliable=True, channel_sequence=sequence,
            channel_name=ChannelName(hardcoded_index=102), **flags)

    def receive(self, bunch, *, state=None, binding=None, adapter=None):
        return (adapter or self.adapter).receive(bunch, control_connection=state or self.state,
            binding=binding or self.binding)

    def test_seed_comes_from_trusted_control_hello_and_no_possession_ack_is_required(self):
        self.assertFalse(self.state.pc_possession_ack_received)
        result = self.receive(self.bunch())
        self.assertTrue(result.received)
        self.assertFalse(result.duplicate)
        self.assertEqual(result.expected_sequence, 529)
        self.assertEqual(result.ready, (self.bunch(),))
        self.assertFalse(result.gameplay_handled)
        self.assertFalse(result.packet_ack_granted)
        wrong = replace(self.state, hello_sequence=529)
        adapter = self.module.OwnedPawnReceiptAdapter(wrong, binding=self.binding)
        rejected = self.receive(self.bunch(), state=wrong, adapter=adapter)
        self.assertFalse(rejected.received)
        self.assertEqual(rejected.reason, 'nonconsecutive_sequence')

    def test_exact_duplicate_is_receipted_without_ready_or_duplicate_journal_write(self):
        first = self.receive(self.bunch())
        duplicate = self.receive(self.bunch())
        self.assertTrue(first.received and duplicate.received and duplicate.duplicate)
        self.assertEqual(duplicate.ready, ())
        self.assertEqual(len(self.adapter.journal), 1)
        self.assertEqual(self.adapter.journal[0].bunch, self.bunch())
        conflict = self.receive(self.bunch(payload=b'\x02'))
        self.assertFalse(conflict.received)
        self.assertEqual(conflict.reason, 'conflicting_reliable_digest')
        self.assertEqual(self.adapter.expected_sequence, 529)

    def test_foreign_generation_peer_transport_ticket_and_closed_state_fail_without_mutation(self):
        for foreign in (replace(self.binding, generation=object()),
                replace(self.binding, transport=object()), replace(self.binding, ticket=object()),
                replace(self.binding, peer=('127.0.0.1', 31001)),
                replace(self.binding, admission_active=False),
                replace(self.binding, configured_owner_current=False),
                replace(self.binding, pawn_open_full_send_acknowledged=False),
                replace(self.binding, all_initial_content_acknowledged=False)):
            with self.subTest(foreign=foreign):
                self.assertFalse(self.receive(self.bunch(), binding=foreign).received)
        self.assertFalse(self.receive(self.bunch(), state=replace(self.state, client_closed=True)).received)
        self.assertFalse(self.receive(self.bunch(), state=replace(self.state, client_join_observed=False)).received)
        self.assertEqual(self.adapter.expected_sequence, 528)
        self.assertEqual(self.adapter.journal, ())

    def test_constructor_rejects_missing_delivery_and_configured_owner_gate(self):
        for changes in (dict(pawn_open_full_send_acknowledged=False),
                dict(all_initial_content_acknowledged=False), dict(configured_owner_current=False)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.module.OwnedPawnReceiptAdapter(self.state, binding=replace(self.binding, **changes))
        self.state.actor_opens[4].delivered = False
        with self.assertRaises(ValueError):
            self.module.OwnedPawnReceiptAdapter(self.state, binding=self.binding)

    def test_uses_current_configured_channel_and_actor_without_hardcoded_values(self):
        state = replace(self.state, pc_restart_pawn_channel=9, pc_restart_pawn_guid=20,
            actor_opens={2: self.state.actor_opens[2],
                9: ActorOpenDelivery(self.bunch(channel=9), 20, delivered=True)})
        adapter = self.module.OwnedPawnReceiptAdapter(state, binding=self.binding)
        self.assertTrue(self.receive(self.bunch(channel=9), state=state, adapter=adapter).received)
        self.assertFalse(self.receive(self.bunch(), state=state, adapter=adapter).received)

    def test_nonreliable_foreign_channel_exports_flags_and_nonexact_payload_are_rejected(self):
        invalid = [replace(self.bunch(), reliable=False, channel_sequence=None, channel_name=None),
            self.bunch(channel=5), self.bunch(payload=b'\xff', bits=1)]
        invalid += [self.bunch(**{flag: True}) for flag in
            ('open', 'close', 'flag4', 'connection_flag', 'package_exports', 'must_be_mapped')]
        for bunch in invalid:
            with self.subTest(bunch=bunch):
                self.assertFalse(self.receive(bunch).received)
        self.assertEqual(self.adapter.expected_sequence, 528)

    def test_partial_assembly_is_bounded_opaque_and_pending_is_not_gameplay(self):
        initial = self.bunch(payload=b'A', partial=True, partial_initial=True)
        result = self.receive(initial)
        self.assertTrue(result.received and result.pending)
        self.assertEqual(result.ready, ())
        final = self.bunch(sequence=529, payload=b'\x05', bits=3, partial=True, partial_final=True)
        result = self.receive(final)
        self.assertTrue(result.received)
        self.assertFalse(result.pending)
        self.assertEqual((result.ready[0].payload, result.ready[0].payload_bits), (b'A\x05', 11))
        self.assertFalse(result.gameplay_handled)
        self.assertTrue(self.receive(final).duplicate)

    def test_body_and_journal_caps_reject_atomically_and_rolling_journal_stays_bounded(self):
        tiny = self.module.OwnedPawnReceiptAdapter(self.state, binding=self.binding,
            max_assembly_bytes=1, max_journal_bytes=1, max_journal_entries=8)
        result = self.receive(self.bunch(payload=b'AB', bits=16), adapter=tiny)
        self.assertFalse(result.received)
        self.assertEqual(tiny.expected_sequence, 528)
        self.assertEqual(tiny.journal, ())
        journal_tiny = self.module.OwnedPawnReceiptAdapter(self.state, binding=self.binding,
            max_journal_bytes=1, max_journal_entries=8)
        result = self.receive(self.bunch(payload=b'AB', bits=16), adapter=journal_tiny)
        self.assertFalse(result.received)
        self.assertEqual(result.reason, 'opaque_journal_body_limit')
        self.assertEqual(journal_tiny.expected_sequence, 528)
        rolling = self.module.OwnedPawnReceiptAdapter(self.state, binding=self.binding,
            max_journal_bytes=16, max_journal_entries=8)
        for ordinal in range(300):
            result = self.receive(self.bunch(sequence=(528 + ordinal) % 1024), adapter=rolling)
            self.assertTrue(result.received)
        self.assertLessEqual(len(rolling.journal), 8)
        self.assertLessEqual(rolling.journal_bytes, 16)

    def test_clone_supports_whole_packet_atomic_trial_without_mutating_original(self):
        candidate = self.adapter.clone()
        self.assertTrue(self.receive(self.bunch(), adapter=candidate).received)
        self.assertEqual(candidate.expected_sequence, 529)
        self.assertEqual(self.adapter.expected_sequence, 528)
        self.assertEqual(self.adapter.journal, ())

    def test_actual_private_capture_has_18_new_214_duplicates_and_seed528(self):
        trial = Path(__file__).resolve().parents[3] / 'work/native-client-tests/1792376752204334900'
        if not (trial / 'game-server-packets/report.json').exists():
            self.skipTest('Exact private local trial is not present')
        from audit_owned_pawn_receipts_20261019 import load_pawn_receipt_fixture
        fixture = load_pawn_receipt_fixture(trial)
        self.assertEqual(fixture[0][1].channel_sequence, 528)
        self.assertEqual(len(fixture), 232)
        fresh = duplicates = 0
        for record, bunch in fixture:
            result = self.receive(bunch)
            self.assertTrue(result.received, result.reason)
            duplicates += int(result.duplicate)
            fresh += int(not result.duplicate)
            self.assertFalse(result.gameplay_handled or result.packet_ack_granted)
        self.assertEqual((fresh, duplicates), (18, 214))
        self.assertEqual(self.adapter.expected_sequence, 546)


if __name__ == '__main__':
    unittest.main()
