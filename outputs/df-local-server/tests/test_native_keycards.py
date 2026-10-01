from pathlib import Path
from contextlib import contextmanager
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from dfserver import native_keycards as keys
from dfserver.core import Backend, DomainError
from dfserver.gcp_data import decode_data_frame
from dfserver.handshake_diagnostic import (
    _candidate_codec, _candidate_local_deposit_response, _candidate_local_equip_response)


ROOT = Path(__file__).resolve().parent.parent


class NativeKeycardsTests(unittest.TestCase):
    def test_original_card_id_map_and_durability(self):
        self.assertEqual(keys.keycard_fields(15050100001), {'health': 20, 'health_max': 20})
        self.assertTrue(keys.can_store(15050100001, 22))
        self.assertFalse(keys.can_store(15050100001, 19))
        self.assertEqual(len(keys.catalog()['keycards']), 334)

    def test_durability_preserves_used_card_and_rejects_invalid_values(self):
        self.assertEqual(keys.keycard_fields(15050100001, 3), {'health': 3, 'health_max': 20})
        self.assertEqual(keys.keycard_fields(15050100001, 0), {'health': 0, 'health_max': 20})
        for value in (-1, 21, True, 1.5):
            with self.assertRaises(ValueError):
                keys.keycard_fields(15050100001, value)
        self.assertEqual(keys.keycard_fields(15050199999), {})

    def test_native_prefix_exclusion_and_unknown_cards(self):
        self.assertIn('15059900002', keys.catalog()['keycards'])
        self.assertFalse(keys.can_store(15059900002, 22))
        self.assertFalse(keys.can_store(15080000001, 22))
        self.assertFalse(keys.can_store(15050199999, 22))

    def test_real_keychain_ids_and_no_fname_index_as_id(self):
        self.assertTrue(keys.is_keychain(11120000001))
        self.assertFalse(keys.is_keychain(11120000011))
        self.assertFalse(keys.is_keychain(11100200001))
        self.assertFalse(keys.is_keychain(19))
        with self.assertRaises(keys.UnverifiedKeychainLayout):
            keys.grid_spaces(11120000001)

    def test_keychain_raw_order_and_capacity_are_preserved(self):
        rows = keys.catalog()['raw_key_boxes']
        first = next(row for row in rows if row['Index'] == 1)
        self.assertEqual(first['ItemID_fname'], {'index': 19, 'number': 0})
        self.assertEqual((first['MapID'], first['DefaultSlotNum'], first['BoxLength']), (19, 4, 4))
        self.assertEqual(keys.catalog()['resolved_key_boxes'], [])

    def test_no_resolved_layout_is_exposed_as_empty_or_successful(self):
        with self.assertRaises(keys.UnverifiedKeychainLayout):
            keys.position_change(11120000001)
        with self.assertRaises(keys.UnverifiedKeychainLayout):
            keys.validate_location(11120000001, 15050100001, 22, 0, 0)

    def test_persisted_health_is_per_physical_owned_gid(self):
        with sqlite3.connect(':memory:') as connection:
            connection.execute('PRAGMA foreign_keys=ON')
            connection.execute('CREATE TABLE native_lobby_props '
                '(gid INTEGER PRIMARY KEY,player_id INTEGER,template_id INTEGER)')
            connection.executemany('INSERT INTO native_lobby_props VALUES (?,?,?)',
                [(1, 4, 15050100001), (2, 4, 15050100001), (3, 5, 15050100001)])
            connection.executescript(keys.SCHEMA)
            connection.executemany('INSERT INTO native_lobby_keycard_health VALUES (?,?,?)',
                                  [(1, 3, 20), (2, 0, 20), (3, 8, 20)])
            row = {'gid': 1, 'player_id': 4, 'template_id': 15050100001}
            self.assertEqual(keys.persisted_fields(connection, row), {'health': 3, 'health_max': 20})
            self.assertEqual(keys.persisted_fields(connection, {**row, 'gid': 2}),
                             {'health': 0, 'health_max': 20})
            with self.assertRaises(ValueError):
                keys.persisted_fields(connection, {**row, 'gid': 3})
            connection.execute('DELETE FROM native_lobby_props WHERE gid=1')
            self.assertIsNone(connection.execute('SELECT 1 FROM native_lobby_keycard_health WHERE gid=1').fetchone())

    def test_persisted_maximum_is_checked_against_original_table(self):
        with sqlite3.connect(':memory:') as connection:
            connection.execute('CREATE TABLE native_lobby_props '
                '(gid INTEGER PRIMARY KEY,player_id INTEGER,template_id INTEGER)')
            connection.execute('INSERT INTO native_lobby_props VALUES (1,4,15050100001)')
            connection.executescript(keys.SCHEMA)
            row = {'gid': 1, 'player_id': 4, 'template_id': 15050100001}
            self.assertEqual(keys.persisted_fields(connection, row), {'health': 20, 'health_max': 20})
            connection.execute('INSERT INTO native_lobby_keycard_health VALUES (1,21,30)')
            with self.assertRaises(ValueError):
                keys.persisted_fields(connection, row)

    def test_actual_wire_accepts_keycard_durability_and_map_ids(self):
        codec = _candidate_codec()
        fields = {'result': 0, 'extension_slots': [
            {'position': 116, 'capacity': 1, 'grid_space': [{'id': 1, 'length': 1, 'width': 1}],
             'load_props': []},
            {'position': 116001, 'src_prop_id': 0, 'capacity': 0, 'load_props': [], 'grid_space': []}]}
        self.assertEqual(codec.decode(codec.encode('CSDepositGetExtensionPropsRes', fields,
            sequence=23)).fields['extension_slots'][1]['position'], 116001)
        fields = {'id': 15050100001, 'gid': 6200000000000000099, 'num': 1,
                  'position': 2, **keys.keycard_fields(15050100001),
                  'loc': {'pos': 2, 'space_id': 1, 'start_x': 0, 'start_y': 0}}
        decoded = codec.codec.decode('pb.PropInfo', codec.codec.encode('pb.PropInfo', fields))
        self.assertEqual((decoded['health'], decoded['health_max']), (20, 20))


class NativeKeycardPersistenceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Path(directory.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('keycard-owner', 'local-password-123')['session']
        self.codec, self.key = _candidate_codec(), b'0123456789abcdef'
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={17020000010: 100000}, props=[
                {'gid': gid, 'template_id': 15050100001, 'quantity': 1,
                 'grid_page_id': 2, 'x': index, 'y': 0, 'length': 1, 'width': 1}
                for index, gid in enumerate((1001, 1002))])
        with self.backend.connection() as connection:
            connection.executemany('INSERT INTO native_lobby_keycard_health VALUES (?,?,?)',
                                  [(1001, 0, 20), (1002, 3, 20)])
            connection.commit()

    def reply(self, name, fields, handler):
        request = b'ABCD' + self.codec.encode(name, fields, sequence=81)
        frame = handler(request, self.backend, self.token, self.key,
                        header_word4=12, header_word9=81)
        return self.codec.decode(decode_data_frame(
            frame, self.key, direction='server_to_client', compression_method=1).messages[0]).fields

    def state(self):
        return {row['gid']: row for row in self.backend.native_lobby_profile(self.token)['props']}

    def test_used_zero_and_three_health_survive_move_wire_and_reopen(self):
        fields = self.reply('CSDepositGetPropsReq', {}, _candidate_local_deposit_response)
        cards = {int(row['gid']): row for row in fields['grid_pages'][0]['props']}
        self.assertEqual((cards[1001].get('health', 0), cards[1002]['health']), (0, 3))
        for gid, health, x in ((1001, 0, 3), (1002, 3, 4)):
            result = self.reply('CSDepositEquipPropReq', {'cmds': [{
                'prop_id': 15050100001, 'prop_gid': gid, 'src_pos': 2, 'target_pos': 2,
                'spec_loc': {'pos': 2, 'start_x': x, 'space_id': 1}}]}, _candidate_local_equip_response)
            self.assertEqual(result['result'], 0)
            prop = result['deposit_change']['prop_changes'][0]['prop']
            self.assertEqual((prop.get('health', 0), prop['health_max']), (health, 20))
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.assertEqual((self.state()[1001]['health'], self.state()[1002]['health']), (0, 3))

    def test_fresh_purchase_uses_original_maximum_without_healing_owned_cards(self):
        result = self.backend.native_lobby_purchase_warehouse_batch(self.token, currency_id=17020000010,
            items=[{'template_id': 15050100001, 'quantity': 1, 'unit_price': 10,
                    'length': 1, 'width': 1, 'max_stack_count': 1, 'target_position': 2}])
        bought = result['props'][0]['gid']
        self.assertEqual(self.state()[bought]['health'], 20)
        self.assertEqual((self.state()[1001]['health'], self.state()[1002]['health']), (0, 3))
        fields = self.reply('CSDepositGetPropsReq', {}, _candidate_local_deposit_response)
        prop = next(row for row in fields['grid_pages'][0]['props'] if int(row['gid']) == bought)
        self.assertEqual((prop['health'], prop['health_max']), (20, 20))

    def test_other_account_cannot_move_saved_health_gid(self):
        other = self.backend.register('keycard-other', 'local-password-456')['session']
        before = self.state()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(other, [{'prop_id': 15050100001,
                'prop_gid': 1002, 'src_pos': 2, 'target_pos': 2}])
        self.assertEqual(self.state(), before)
        self.assertEqual(self.backend.native_lobby_profile(other)['props'], [])

    def test_profile_returns_one_snapshot_when_a_card_is_sold_at_commit(self):
        original_connection = self.backend.connection
        sold = []

        class SaleAtCommit:
            def __init__(self, connection):
                self.connection = connection

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def commit(proxy):
                proxy.connection.commit()
                if not sold:
                    with patch.object(self.backend, 'connection', original_connection):
                        self.backend.native_lobby_sell(self.token,
                            items=[{'gid': 1002, 'template_id': 15050100001, 'quantity': 1}],
                            currency_id=17020000010, total_price=1)
                    sold.append(1002)

        @contextmanager
        def profile_connection():
            with original_connection() as connection:
                yield SaleAtCommit(connection)

        with patch.object(self.backend, 'connection', profile_connection):
            snapshot = self.backend.native_lobby_profile(self.token)
        cards = {row['gid']: row for row in snapshot['props']}
        self.assertEqual(cards[1002]['health'], 3)
        self.assertEqual(sold, [1002])
        self.assertNotIn(1002, self.state())


if __name__ == '__main__':
    unittest.main()
