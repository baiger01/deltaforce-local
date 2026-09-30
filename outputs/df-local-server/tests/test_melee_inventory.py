"""Client melee collection, equipped identity and persisted selection agree."""

from pathlib import Path
import tempfile
import unittest

from dfserver.core import Backend, DomainError
from dfserver.gcp_data import decode_data_frame
from dfserver.handshake_diagnostic import (
    _candidate_codec, _candidate_local_collection_response,
    _candidate_local_deposit_response, _candidate_local_equip_response)


ROOT = Path(__file__).resolve().parent.parent


class MeleeInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Path(temporary.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('melee-test', 'separate-test-password')['session']
        self.codec = _candidate_codec()
        self.key = b'0123456789abcdef'

    def reply(self, name, fields, handler):
        request = b'ABCD' + self.codec.encode(name, fields, sequence=81)
        frame = handler(request, self.backend, self.token, self.key,
                        header_word4=12, header_word9=81)
        return self.codec.decode(decode_data_frame(
            frame, self.key, direction='server_to_client', compression_method=1).messages[0]).fields

    def deposit(self):
        return self.reply('CSDepositGetPropsReq', {}, _candidate_local_deposit_response)

    def test_collection_before_deposit_has_matching_owned_melee_skins(self):
        collection = self.reply('CSCollectionLoadPropsReq', {}, _candidate_local_collection_response)
        deposit = self.deposit()
        owned = {int(row['id']) for row in collection.get('weapon_skin_props', [])}
        self.assertIn(28101200002, owned)
        self.assertEqual(len(owned), 15)
        weapons = deposit['melee_weapons']
        self.assertEqual(len(weapons), 15)
        self.assertNotIn(18100000001, {int(row['id']) for row in weapons})
        self.assertEqual(len({row['gid'] for row in weapons}), 15)
        self.assertTrue({28101250021, 28101250022, 28101250023}.isdisjoint(owned))
        for row in weapons:
            self.assertIn(int(row['weapon']['skin_id']), owned)
        slot = next(row for row in deposit['equiped_props'] if row['position'] == 113)
        self.assertEqual(int(slot['src_prop_id']), 18100000002)
        self.assertEqual(int(slot['load_props'][0]['weapon']['skin_id']), 28101200002)

    def test_spray_gun_migration_preserves_default_instance(self):
        legacy = self.backend.ensure_native_lobby_default_melee(self.token, 18100000001)
        deposit = self.deposit()
        default = next(row for row in deposit['melee_weapons'] if int(row['id']) == 18100000002)
        self.assertEqual(int(default['gid']), legacy['gid'])
        self.assertEqual(self.deposit(), deposit)

    def test_selection_uses_owned_instance_and_survives_reconnect(self):
        deposit = self.deposit()
        chosen = next(row for row in deposit['melee_weapons'] if int(row['id']) == 18100000008)
        command = {'prop_id': 18100000008, 'prop_gid': int(chosen['gid']), 'target_pos': 113}
        result = self.reply('CSDepositEquipPropReq', {'cmds': [command]}, _candidate_local_equip_response)
        self.assertEqual(result['result'], 0)
        changes = result['deposit_change']['prop_changes']
        self.assertEqual([row['change_type'] for row in changes], [2, 1])
        self.assertFalse(any(row['change_type'] == 5 and row['dest']['pos'] == 0 for row in changes))
        equipped = next(row['prop'] for row in changes if row['dest']['pos'] == 113)
        self.assertEqual(int(equipped['weapon']['skin_id']), 28101250003)
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        slot = next(row for row in self.deposit()['equiped_props'] if row['position'] == 113)
        self.assertEqual(int(slot['src_prop_id']), 18100000008)
        self.assertEqual(slot['load_props'][0]['gid'], chosen['gid'])
        repeated = self.reply('CSDepositEquipPropReq', {
            'cmds': [{'prop_id': 18100000008, 'target_pos': 113}]}, _candidate_local_equip_response)
        self.assertEqual(repeated['result'], 0)
        self.assertEqual([row['change_type'] for row in repeated['deposit_change']['prop_changes']], [3])
        other = self.backend.register('another-melee', 'separate-test-password')['session']
        self.backend.ensure_native_lobby_melee_collection(other)
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(other, [command])

    def test_invalid_command_rolls_back_melee_selection(self):
        self.deposit()
        before = self.backend.native_lobby_profile(self.token)
        chosen = next(row for row in before['melee_props'] if row['template_id'] == 18100000008)
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [
                {'prop_id': chosen['template_id'], 'prop_gid': chosen['gid'], 'target_pos': 113},
                {'prop_id': 18100000001, 'prop_gid': 1, 'target_pos': 113}])
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
