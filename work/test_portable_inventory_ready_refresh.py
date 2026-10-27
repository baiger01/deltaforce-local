"""Actual empty ready field and original-item, ACK-committed refresh behavior."""
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
sys.path.insert(0, str(ROOT / 'work'))
from dfserver.legacy_ds_actor_fields import ClassFieldEnvelope, NormalClassFieldProfile, read_class_fields
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_inventory_gun import read_inventory_custom_delta
import portable_map_inventory as adapter
import portable_map_inventory_content as content


class ReadyRefreshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).with_name('portable_inventory_ready_refresh.py')
        cls.api = None
        if path.exists():
            spec = importlib.util.spec_from_file_location('portable_inventory_ready_refresh', path)
            cls.api = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = cls.api
            spec.loader.exec_module(cls.api)
        snapshot = json.loads((ROOT / 'work/native-client-tests/1792343957590810500/admitted-loadout-snapshot.json').read_bytes())
        cls.items = adapter.build_items(snapshot, owner_player_id=17)
        cls.foreign_items = adapter.build_items(snapshot, owner_player_id=18)

    def c(self):
        self.assertIsNotNone(self.api, 'The source-qualified ready refresh module is missing')
        return self.api

    def scope(self):
        return self.c().InventoryReadyScope('diagnostic-room', 17, 1, 2, 4, 2, 100)

    def received(self, field=None, **overrides):
        kwargs = dict(scope=self.scope(), channel_index=2, actor_guid=4, generation=1,
            reliable_sequence=75, reliable_receipt_admitted=True, current_pawn_bound=True)
        kwargs.update(overrides)
        return self.c().decode_field(field or ClassFieldEnvelope(225, b'', 0), **kwargs)

    def test_only_exact_empty_ready_rpc_in_current_admission_is_accepted(self):
        self.assertEqual(self.received().function_index, 225)
        cases = [(ClassFieldEnvelope(224, b'', 0), {}),
            (ClassFieldEnvelope(225, b'\0', 1), {}),
            (None, {'channel_index': 3}), (None, {'actor_guid': 6}),
            (None, {'generation': 2}), (None, {'reliable_receipt_admitted': False}),
            (None, {'current_pawn_bound': False})]
        for field, kwargs in cases:
            with self.subTest(field=field, kwargs=kwargs), self.assertRaises(ValueError):
                self.received(field, **kwargs)

    def test_refresh_preserves_original_element_and_advances_only_explicit_cursor(self):
        c = self.c()
        cursor = c.initial_cursor(self.scope(), self.items, acknowledged_array_key=15,
            initial_delivery_acknowledged=True)
        projected = c.project_refresh(self.received(), cursor=cursor, current_items=self.items,
            current_array_key=15, current_delivery_acknowledged=True)
        self.assertEqual(len(self.items), 52)
        self.assertEqual(cursor.array_key, 15)
        self.assertFalse(cursor.refresh_committed)
        self.assertEqual(projected.cursor_after_ack.array_key, 16)
        self.assertTrue(projected.cursor_after_ack.refresh_committed)
        update = projected.update
        self.assertFalse(update.has_rep_layout)
        fields = read_class_fields(BitReader(update.payload, bit_count=update.payload_bit_count),
            profile=NormalClassFieldProfile(53, False))
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0].rep_index, 7)
        reader = BitReader(fields[0].payload, bit_count=fields[0].payload_bit_count)
        delta = read_inventory_custom_delta(reader, profile=content.PROFILE)
        self.assertEqual(reader.remaining, 0)
        self.assertEqual((delta.array_replication_key, delta.base_replication_key, delta.deleted_ids), (16, 15, ()))
        self.assertEqual(len(delta.changed), 1)
        self.assertIn(delta.changed[0], self.items)
        self.assertEqual(projected, c.project_refresh(self.received(), cursor=cursor,
            current_items=self.items, current_array_key=15, current_delivery_acknowledged=True))
        self.assertIsNone(c.project_refresh(self.received(), cursor=projected.cursor_after_ack,
            current_items=self.items, current_array_key=16, current_delivery_acknowledged=True))

    def test_wrong_inventory_revision_foreign_scope_or_unacked_initial_state_is_rejected(self):
        c = self.c()
        with self.assertRaises(ValueError):
            c.initial_cursor(self.scope(), self.items, acknowledged_array_key=15,
                initial_delivery_acknowledged=False)
        with self.assertRaises(ValueError):
            c.initial_cursor(self.scope(), self.foreign_items, acknowledged_array_key=15,
                initial_delivery_acknowledged=True)
        cursor = c.initial_cursor(self.scope(), self.items, acknowledged_array_key=15,
            initial_delivery_acknowledged=True)
        cases = [dict(current_items=self.items[:-1], current_array_key=15, current_delivery_acknowledged=True),
            dict(current_items=self.items, current_array_key=14, current_delivery_acknowledged=True),
            dict(current_items=self.items, current_array_key=15, current_delivery_acknowledged=False)]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs.keys()), self.assertRaises(ValueError):
                c.project_refresh(self.received(), cursor=cursor, **kwargs)
        with self.assertRaises(ValueError):
            c.project_refresh(replace(self.received(), scope=replace(self.scope(), generation=2)),
                cursor=cursor, current_items=self.items, current_array_key=15,
                current_delivery_acknowledged=True)

    def test_source_contract_does_not_promote_candidate_to_native_ui_acceptance(self):
        c = self.c()
        binding = c.schema_binding()
        self.assertEqual(binding['function_index'], 225)
        self.assertEqual(binding['parameter_bits'], 0)
        self.assertFalse(binding['native_refresh_acceptance_verified'])
        self.assertFalse(binding['complete_received_rpc_225_saved'])
        self.assertIn('work/portable_inventory_ready_refresh.py', c.source_pins())

    def test_complete_component_packet_is_budgeted_without_sending(self):
        c = self.c()
        from dfserver.legacy_ds_wire_codec import WirePacket, decode_observed_application
        cursor = c.initial_cursor(self.scope(), self.items, acknowledged_array_key=15,
            initial_delivery_acknowledged=True)
        projected = c.project_refresh(self.received(), cursor=cursor, current_items=self.items,
            current_array_key=15, current_delivery_acknowledged=True)
        self.assertTrue(callable(getattr(c, 'preflight_packet', None)), 'Full packet preflight is missing')
        raw = c.preflight_packet(projected, pawn_channel=4, channel_sequence=1023,
            packet_template=WirePacket(16383, 17, (0xffffffff,), False, 0, None, (), 0),
            actor_guids=(2, 4, 6, 8), max_packet_bytes=1024)
        self.assertLessEqual(len(raw), 1024)
        decoded = decode_observed_application(raw, max_packet_bytes=1024, received_by_server=False)
        self.assertEqual((decoded.sequence, decoded.bunches[0].channel_sequence), (16383, 1023))
        with self.assertRaises(ValueError):
            c.preflight_packet(projected, pawn_channel=4, channel_sequence=0,
                packet_template=WirePacket(0, 17, (0xffffffff,), False, 0, None, (), 0),
                actor_guids=(2, 4, 6, 8), max_packet_bytes=32)


if __name__ == '__main__':
    unittest.main()
