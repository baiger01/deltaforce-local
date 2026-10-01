from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dfserver import battle_pass
from dfserver.core import Backend, DomainError
from dfserver.handshake_diagnostic import _candidate_codec


ROOT = Path(__file__).resolve().parent.parent


class BattlePassTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend = Backend(Path(self.directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('battlepass', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, props=[],
            currencies={17888808888: 100000, 17888808889: 100000})
        with self.backend.connection() as connection:
            connection.executescript(battle_pass.SCHEMA)
        self.codec = _candidate_codec()

    def request(self, name, fields=None, changes=None):
        request = self.codec.decode(self.codec.encode(name, fields or {}, sequence=31))
        result = battle_pass.response_fields(request, self.backend, self.token, changes=changes)
        self.assertIsNotNone(result)
        self.codec.decode(self.codec.response(request, result))
        return result

    def test_real_query_season_and_complete_native_info_survive_restart(self):
        self.assertEqual(self.request('CSBattlePassBpGetSeasonIdReq')['season_id'], 202604)
        result = self.request('CSBattlePassGetInfoReq', {'get_info_type': 1})
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['info']['season_info']['season_id'], 202604)
        self.assertEqual(result['info']['main_line']['level_info']['curr_level'], 1)
        self.assertEqual(result['info']['pack']['pack_id'], 11)
        self.assertEqual(result['info']['archives'], [])
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.request('CSBattlePassGetInfoReq')['info'], result['info'])

    def test_verified_prices_enable_real_membership_purchase(self):
        result = self.request('CSBattlePassBpCountryPriceReq')
        self.assertEqual((result['sol_price'], result['mp_price'], result['universal_price']),
                         (520, 520, 720))
        self.assertEqual((result['level_price'], result['pack_price']), (100, 640))
        self.assertEqual(battle_pass.CATALOG['mapping_status'],
                         'verified_by_native_reflection_and_serialization')
        self.assertTrue(battle_pass.CATALOG['mutations_enabled'])
        self.assertTrue(battle_pass.mutations_enabled())
        before = self.backend.native_lobby_profile(self.token)
        changes = {}
        result = self.request('CSBattlePassBuyReq', {'buy_type': 4, 'binded_delta_coin': 720}, changes)
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['info']['type'], 4)
        after = self.backend.native_lobby_profile(self.token)
        before_coins = {row['currency_id']: row['amount'] for row in before['currencies']}
        after_coins = {row['currency_id']: row['amount'] for row in after['currencies']}
        bound_changes = [row for row in changes['currency_changes']
                         if row['currency_id'] == 17888808889]
        self.assertEqual([row['delta'] for row in bound_changes if row['delta'] < 0], [-720])
        self.assertEqual(after_coins[17888808889],
                         before_coins[17888808889] + sum(row['delta'] for row in bound_changes))
        self.assertEqual(bound_changes[-1]['current_num'], after_coins[17888808889])

    def test_disabled_mutation_gate_rolls_back_all_purchase_requests(self):
        self.request('CSBattlePassGetInfoReq')
        before = self.backend.native_lobby_profile(self.token)
        info = self.request('CSBattlePassGetInfoReq')['info']
        requests = [('CSBattlePassBuyReq', {'buy_type': 4, 'binded_delta_coin': 720}),
                    ('CSBattlePassBuyLevelReq', {'level': 2, 'binded_delta_coin': 200}),
                    ('CSBattlePassBuyPackReq', {'pack_id': 11, 'binded_delta_coin': 640})]
        with patch.object(battle_pass, 'CATALOG',
                {**battle_pass.CATALOG, 'mutations_enabled': False}):
            self.assertFalse(battle_pass.mutations_enabled())
            for name, fields in requests:
                with self.subTest(name=name):
                    changes = {}
                    self.assertEqual(self.request(name, fields, changes)['result'], 170001)
                    self.assertEqual(changes, {})
                    self.assertEqual(self.backend.native_lobby_profile(self.token), before)
                    self.assertEqual(self.request('CSBattlePassGetInfoReq')['info'], info)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute(
                'SELECT COUNT(*) FROM native_lobby_battle_pass_grants').fetchone()[0], 0)

    def test_unknown_query_type_and_unrecovered_clue_and_card_ids_are_rejected(self):
        self.assertEqual(self.request('CSBattlePassGetInfoReq', {'get_info_type': 99})['result'], 170001)
        before = self.backend.native_lobby_profile(self.token)
        for name, fields in [('CSBattlePassBuyClueReq', {'archive_id': 1, 'clue_id': 101}),
                ('CSBattlePassReceiveClueRewardReq', {'archive_id': 1, 'clue_id': 101}),
                ('CSBattlePassReceiveArchiveRewardReq', {'archive_id': 1}),
                ('CSBattlePassUseExprCardReq', {'card_id': 2147483647, 'num': 1}),
                ('CSBattlePassUseUnlockCardReq', {'card_id': 2147483647})]:
            with self.subTest(name=name):
                self.assertNotEqual(self.request(name, fields)['result'], 0)
                self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_membership_upgrade_charges_difference_and_deduplicates_rewards(self):
        changes = {}
        self.assertEqual(self.request('CSBattlePassBuyReq', {'buy_type': 2,
            'binded_delta_coin': 520}, changes)['info']['type'], 2)
        first = self.backend.native_lobby_profile(self.token)
        self.assertEqual(self.request('CSBattlePassBuyReq', {'buy_type': 2,
            'binded_delta_coin': 520})['result'], 170004)
        self.assertEqual(self.backend.native_lobby_profile(self.token), first)
        upgrade = {}
        self.assertEqual(self.request('CSBattlePassBuyReq', {'buy_type': 4,
            'unbinded_delta_coin': 200}, upgrade)['info']['type'], 4)
        self.assertTrue(changes['collection_changes'])
        self.assertTrue(upgrade['collection_changes'])
        self.assertEqual(sum(c['delta'] for c in upgrade['currency_changes']), -200)
        with self.backend.connection() as connection:
            grants = connection.execute('SELECT level,tier,slot FROM native_lobby_battle_pass_grants').fetchall()
        self.assertEqual(len(grants), len({tuple(row) for row in grants}))

    def test_level_is_increment_not_target_and_bad_quote_rolls_back(self):
        self.request('CSBattlePassBuyLevelReq', {'level': 2, 'binded_delta_coin': 200})
        result = self.request('CSBattlePassBuyLevelReq', {'level': 2, 'binded_delta_coin': 200})
        self.assertEqual(result['info']['main_line']['level_info']['curr_level'], 5)
        before = self.backend.native_lobby_profile(self.token)
        for fields in ({'level': 2, 'binded_delta_coin': 1},
                       {'level': 2, 'binded_delta_coin': -1, 'unbinded_delta_coin': 201},
                       {'level': 180, 'binded_delta_coin': 18000}):
            with self.subTest(fields=fields):
                self.assertNotEqual(self.request('CSBattlePassBuyLevelReq', fields)['result'], 0)
                self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertEqual(self.request('CSBattlePassGetInfoReq')['info']['main_line']['level_info']['curr_level'], 5)

    def test_pack_adds_levels_without_membership_and_persists_once(self):
        result = self.request('CSBattlePassBuyPackReq', {'pack_id': 11, 'binded_delta_coin': 640})
        self.assertEqual(result['info']['main_line']['level_info']['curr_level'], 21)
        self.assertEqual(result['info']['pack']['bought_pack_list'], [11])
        self.assertEqual(result['info']['type'], 0)
        self.assertFalse(result['info']['has_bought'])
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        before = self.backend.native_lobby_profile(self.token)
        self.assertEqual(self.request('CSBattlePassBuyPackReq',
            {'pack_id': 11, 'binded_delta_coin': 640})['result'], 170007)
        self.assertEqual(self.request('CSBattlePassBuyPackReq',
            {'pack_id': 10, 'binded_delta_coin': 640})['result'], 170015)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_pack_keeps_current_membership_and_rejects_levels_above_native_limit(self):
        self.request('CSBattlePassBuyReq', {'buy_type': 2, 'binded_delta_coin': 520})
        result = self.request('CSBattlePassBuyPackReq', {'pack_id': 11, 'binded_delta_coin': 640})
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['info']['type'], 2)
        self.assertEqual(result['info']['main_line']['level_info']['curr_level'], 21)
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_battle_pass SET level=161,bought_packs_json=?', ('[]',))
            connection.commit()
        before = self.backend.native_lobby_profile(self.token)
        info = self.request('CSBattlePassGetInfoReq')['info']
        changes = {}
        self.assertNotEqual(self.request('CSBattlePassBuyPackReq',
            {'pack_id': 11, 'binded_delta_coin': 640}, changes)['result'], 0)
        self.assertEqual(changes, {})
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertEqual(self.request('CSBattlePassGetInfoReq')['info'], info)

    def test_partial_debit_and_failed_grant_roll_back_every_state_change(self):
        self.request('CSBattlePassGetInfoReq')
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_currencies SET amount=0 WHERE currency_id=17888808888')
            connection.commit()
        before = self.backend.native_lobby_profile(self.token)
        changes = {}
        self.assertNotEqual(self.request('CSBattlePassBuyReq', {'buy_type': 4,
            'binded_delta_coin': 620, 'unbinded_delta_coin': 100}, changes)['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertEqual(changes, {})
        with patch.object(battle_pass.premium_shop, 'grant',
                side_effect=DomainError('INVALID_EQUIPMENT', 'Unrecovered test reward')):
            self.assertNotEqual(self.request('CSBattlePassBuyReq', {'buy_type': 4,
                'binded_delta_coin': 720}, changes)['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertEqual(changes, {})
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_battle_pass_grants').fetchone()[0], 0)
        self.assertEqual(self.request('CSBattlePassGetInfoReq')['info']['type'], 0)


if __name__ == '__main__':
    unittest.main()
