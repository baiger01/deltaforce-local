import tempfile
from pathlib import Path
import unittest

from dfserver.core import Backend, DomainError
from dfserver.gcp_data import decode_data_frame
from dfserver.handshake_diagnostic import (
    _candidate_codec, _candidate_local_deposit_sort_response)


ROOT = Path(__file__).resolve().parent.parent


class NativeDepositSortTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Path(temporary.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('sort-test', 'local-password-123')['session']
        self.codec = _candidate_codec()
        self.key = b'0123456789abcdef'
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            self.prop(1001, 15080050006, 7, 20),
            self.prop(1002, 15080050006, 5, 25),
            self.prop(1003, 14020000003, 3, 30),
            self.prop(1004, 11070005004, 0, 0, position=107),
        ])

    @staticmethod
    def prop(gid, item_id, x, y, *, position=2, length=1, width=1):
        return {'gid': gid, 'template_id': item_id, 'quantity': 1,
                'grid_page_id': position, 'x': x, 'y': y,
                'length': length, 'width': width}

    def state(self):
        return {p['gid']: p for p in self.backend.native_lobby_profile(self.token)['props']}

    def reply(self, name, fields):
        request = b'ABCD' + self.codec.encode(name, fields, sequence=81)
        frame = _candidate_local_deposit_sort_response(
            request, self.backend, self.token, self.key, header_word4=12, header_word9=81)
        return self.codec.decode(decode_data_frame(
            frame, self.key, direction='server_to_client', compression_method=1).messages[0]).fields

    def test_sort_moves_and_persists_items_instead_of_empty_success(self):
        before = self.state()
        result = self.reply('CSDepositSortMultiplePosReq', {'pos_id': [2]})
        self.assertEqual(result['result'], 0)
        self.assertEqual(len(result['changes']['prop_changes']), 3)
        after = self.state()
        self.assertEqual(set(before), set(after))
        self.assertEqual(after[1004], before[1004])
        self.assertEqual({(after[g]['x'], after[g]['y']) for g in (1001, 1002, 1003)},
                         {(0, 0), (1, 0), (2, 0)})
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.assertEqual(self.state(), after)
        repeated = self.reply('CSDepositSortPositionReq', {'pos_id': 2})
        self.assertEqual(repeated['result'], 0)
        self.assertFalse(repeated.get('changes', {}).get('prop_changes'))
        self.assertTrue(self.backend.native_lobby_profile(self.token)['sort_config']['has_sorted'])

    def test_real_common_config_request_persists_and_keeps_native_enum_values(self):
        config = {'sort_style': 1, 'sort_class_order': [4, 1, 3, 2, 5, 6, 7, 8],
                  'extension_first_class': [1, 3], 'sort_every_enter': True}
        result = self.reply('CSDepositSetCommonConfigReq', {'sort_config': config})
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['cur_sort_config']['sort_class_order'], config['sort_class_order'])
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        saved = self.backend.native_lobby_profile(self.token)['sort_config']
        for name, value in config.items():
            self.assertEqual(saved[name], value)

    def test_unavailable_sort_position_returns_error_and_keeps_all_items(self):
        before = self.state()
        result = self.reply('CSDepositSortMultiplePosReq', {'pos_id': [2, 999]})
        self.assertNotEqual(result['result'], 0)
        self.assertEqual(self.state(), before)

    def test_invalid_config_is_rejected_without_overwriting_previous_settings(self):
        self.backend.set_native_lobby_sort_config(self.token, {'sort_style': 0})
        before = self.backend.native_lobby_profile(self.token)['sort_config']
        for config in ({'sort_style': 7}, {'sort_class_order': [1, 1]},
                       {'extension_first_class': [99]}, {'sort_every_enter': 1}):
            with self.assertRaises(DomainError):
                self.backend.set_native_lobby_sort_config(self.token, config)
            self.assertEqual(self.backend.native_lobby_profile(self.token)['sort_config'], before)

    def test_failed_packing_rolls_back_all_positions_and_sort_flag(self):
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            self.prop(1001, 15080050006, 7, 20),
            self.prop(1002, 15080050006, 0, 0, length=50, width=50)])
        before = self.backend.native_lobby_profile(self.token)
        result = self.reply('CSDepositSortMultiplePosReq', {'pos_id': [2]})
        self.assertNotEqual(result['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_sort_preserves_components_loaded_ammo_and_unselected_pocket(self):
        bullet = self.prop(2002, 37190000001, 1, 0, position=199997)
        bullet['quantity'] = 60
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            self.prop(2001, 18020000003, 4, 15, length=4, width=2), bullet])
        self.backend.native_lobby_operate_bullets(self.token, [{
            'op_type': 1, 'bullet_id': 37190000001, 'bullet_gid': 2002, 'bullet_op_num': 17,
            'target_gun_rec_id': 18020000003, 'target_gun_rec_gid': 2001}])
        before = self.state()
        self.reply('CSDepositSortPositionReq', {'pos_id': 2})
        after = self.state()
        self.assertEqual(after[2001]['components'], before[2001]['components'])
        self.assertEqual(after[2001]['weapon'], before[2001]['weapon'])
        self.assertEqual(after[2002], before[2002])
        self.assertEqual((after[2001]['x'], after[2001]['y']), (0, 0))


if __name__ == '__main__':
    unittest.main()
