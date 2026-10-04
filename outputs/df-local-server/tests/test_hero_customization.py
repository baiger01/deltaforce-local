import json
import tempfile
import unittest
from pathlib import Path

from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec, _candidate_operator_base_fashions
from dfserver import hero_customization as hero
from dfserver.local_commerce import response_fields as commerce_response


ROOT = Path(__file__).resolve().parent.parent
HERO = 88000000025
VOICE = 38050050066
FASHION = 30000050013


class HeroCustomizationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend = Backend(Path(self.directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('hero-custom', 'local-password-123')['session']
        self.bases = _candidate_operator_base_fashions()
        self.codec = _candidate_codec()

    def request(self, name, fields=None):
        request = self.codec.decode(self.codec.encode(name, fields or {}, sequence=19))
        result = hero.response_fields(request, self.backend, self.token)
        self.assertIsNotNone(result, name)
        self.codec.response(request, result)
        return result

    def record(self, hero_id=HERO):
        return hero.hero_records(self.backend, self.token, [hero_id])[0]

    def grant(self, *ids):
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            for item_id in ids:
                connection.execute('INSERT INTO native_lobby_collection_props '
                    '(player_id,template_id,quantity) VALUES (?,?,1) '
                    'ON CONFLICT(player_id,template_id) DO UPDATE SET quantity=quantity+1',
                    (player_id, item_id))
            connection.commit()

    def test_fresh_catalog_contains_locked_fashions_and_voice_without_granting(self):
        record = self.record()
        self.assertEqual(record['fashion_list'][0]['fashion']['id'], self.bases[HERO])
        fashion = next(r for r in record['fashion_list'] if r['fashion']['id'] == FASHION)
        self.assertFalse(fashion['is_unlock'])
        voice = next(r for r in record['accessories'] if r['item']['prop_id'] == VOICE)
        self.assertFalse(voice['is_unlock'])
        self.assertEqual(self.backend.native_lobby_profile(self.token)['collection_props'], [])

    def test_mode_selection_does_not_replace_sol_room_operator_after_restart(self):
        sol, mp = sorted(hero.BASES)[:2]
        self.backend.set_native_selected_hero_for_mode(self.token, sol, 1)
        self.backend.set_native_selected_hero_for_mode(self.token, mp, 2)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        result = self.request('CSHeroLoadHeroListReq', {'filter_by_id': True,
            'hero_id_list': [mp]})
        self.assertEqual(result['sol_hero_selected'], sol)
        self.assertEqual(result['mp_hero_selected'], mp)
        self.assertEqual(result['hero_ids'], sorted(hero.BASES))
        self.assertEqual([row['hero_id'] for row in result['heros']], [mp])

    def test_owned_voice_equip_unequip_and_read_play_survive_restart(self):
        self.grant(VOICE)
        result = self.request('CSHeroSelectAccessoryReq', {'hero_id': HERO,
            'accessory_item': {'prop_id': VOICE, 'slot': 2}, 'mode': 1})
        self.assertEqual(result['result'], 0)
        selected = next(r for r in result['target_hero']['accessories'] if r['item']['prop_id'] == VOICE)
        self.assertTrue(selected['is_selected'])
        self.assertEqual(selected['item']['slot'], 2)
        self.assertEqual(self.request('CSHeroChangeAccessoryReadStatReq', {'prop_ids': [VOICE]})['succ_prop_ids'], [VOICE])
        self.assertEqual(self.request('CSHeroChangeAccessoryPlayStatReq', {'prop_ids': [VOICE]})['succ_prop_ids'], [VOICE])
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        selected = next(r for r in self.record()['accessories'] if r['item']['prop_id'] == VOICE)
        self.assertTrue(selected['is_selected'])
        self.assertTrue(selected['is_read'])
        self.assertTrue(selected['is_play'])
        self.assertEqual(self.request('CSHeroSelectAccessoryReq', {'hero_id': HERO,
            'accessory_item': {'prop_id': VOICE, 'slot': 2}, 'is_unequip': True})['result'], 0)
        self.assertFalse(next(r for r in self.record()['accessories'] if r['item']['prop_id'] == VOICE)['is_selected'])

    def test_unowned_wrong_hero_and_negative_slots_cannot_equip(self):
        self.assertNotEqual(self.request('CSHeroSelectAccessoryReq', {'hero_id': HERO,
            'accessory_item': {'prop_id': VOICE, 'slot': 0}})['result'], 0)
        self.grant(VOICE, FASHION)
        self.assertNotEqual(self.request('CSHeroSelectAccessoryReq', {'hero_id': 88000000027,
            'accessory_item': {'prop_id': VOICE, 'slot': 0}})['result'], 0)
        self.assertNotEqual(self.request('CSHeroSelectAccessoryReq', {'hero_id': HERO,
            'accessory_item': {'prop_id': VOICE, 'slot': -1}})['result'], 0)
        self.assertNotEqual(hero.equip_hero(self.backend, self.token, 88000000027,
            [{'slot': 0, 'id': FASHION}], self.bases)['result'], 0)

    def test_collection_ownership_unlocks_and_equips_actual_fashion(self):
        self.grant(FASHION, 30000060010)
        self.assertEqual(hero.equip_hero(self.backend, self.token, HERO,
            [{'slot': 0, 'id': FASHION}], self.bases)['result'], 0)
        self.assertEqual(hero.equip_hero(self.backend, self.token, 88000000029,
            [{'slot': 0, 'id': 30000060010}], self.bases)['result'], 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.record()['fashion_equipped'], [{'slot': 0, 'id': FASHION}])
        self.assertIn(HERO, hero.affected_heroes(VOICE))
        self.assertIn(88000000029, hero.affected_heroes(30000060010))

    def test_watch_catalog_is_present_without_marking_every_watch_owned(self):
        records = hero.hero_records(self.backend, self.token, self.bases)
        watches = [a for r in records for a in r['accessories'] if a['item']['prop_id'] // 10000000 % 100 == 7]
        self.assertTrue(watches)
        self.assertTrue(any(not a['is_unlock'] for a in watches))

    def test_all_verified_bases_and_alias_fashions_keep_correct_default_flags(self):
        self.assertEqual(hero.BASES, self.bases)
        for hero_id, alias in ((88000000027, 30000040006), (88000000029, 30000040007),
                               (88000000030, 30000040005), (88000000040, 30000050022)):
            record = self.record(hero_id)
            self.assertEqual(record['fashion_equipped'][0]['id'], self.bases[hero_id])
            fashion = next(r for r in record['fashion_list'] if r['fashion']['id'] == alias)
            self.assertFalse(fashion['is_unlock'])
            self.assertFalse(fashion['is_def'])

    def test_actual_flying_tiger_bundle_unlocks_its_four_voices(self):
        self.backend.set_native_lobby_profile(self.token, level=60, props=[],
            currencies={17888808889: 10000})
        ids = [FASHION, 38050050066, 38050050067, 38050050068, 38050050069]
        shop = json.loads((ROOT / 'protocol/premium_shop_catalog.json').read_text())
        offer = next(r for r in shop['recommendations'] if r['tab_id'] == 10104007)
        request = self.codec.decode(self.codec.encode('CSShopBuyHotRecommendationReq', {
            'tab_id': 10104007, 'banner_type': 1, 'item_ids': [r['id'] for r in offer['bundle_item_list']],
            'currency_type': 17888808889, 'price': 2690}, sequence=19))
        self.assertEqual(commerce_response(request, self.backend, self.token)['result'], 0)
        voices = {r['item']['prop_id']: r for r in self.record()['accessories']}
        self.assertTrue(all(voices[item_id]['is_unlock'] for item_id in ids[1:]))
        self.assertEqual(self.request('CSHeroSelectAccessoryReq', {'hero_id': HERO,
            'accessory_item': {'prop_id': VOICE, 'slot': 1}})['result'], 0)
        self.assertEqual(self.request('CSHeroSelectAccessoryReq', {'hero_id': HERO,
            'accessory_item': {'prop_id': 38070030001, 'slot': 0}})['result'], 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        selected = {r['item']['prop_id'] for r in self.record()['accessories'] if r['is_selected']}
        self.assertTrue({VOICE, 38070030001} <= selected)

    def test_native_self_badge_queries_and_grant_selection_persist(self):
        native_id = self.backend.native_identity(self.token)['native_id']
        self.assertEqual(self.request('CSHeroGetBadgeShowReq', {'player_id': native_id})['result'], 0)
        self.assertNotEqual(self.request('CSHeroGetBadgeShowReq', {'player_id': native_id + 1})['result'], 0)
        badge_id = next(r['id'] for r in hero.ACCESSORIES.values() if r['subtype'] == 8
                        and not r['default_unlock'] and not r['default_equip'])
        self.assertNotEqual(self.request('CSHeroSetBadgeShowReq', {'badge': {'prop_id': badge_id, 'slot': 0}})['result'], 0)
        self.grant(badge_id)
        self.assertEqual(self.request('CSHeroSetBadgeShowReq', {'badge': {'prop_id': badge_id, 'slot': 0}})['result'], 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.request('CSHeroGetBadgeShowReq', {'player_id': native_id})['badges'],
                         [{'prop_id': badge_id, 'slot': 0}])

    def test_native_prior_request_mode_persists_without_mixing_unknown_modes(self):
        self.assertEqual(self.request('CSHeroChangeFashionPriorReq', {'mode': 1,
            'is_fashion_prior': True, 'prior_settings': [{'category': 6, 'is_fashion_prior': True}]})['result'], 0)
        self.assertNotEqual(self.request('CSHeroChangeFashionPriorReq', {'mode': 5,
            'prior_settings': [{'category': 6, 'is_fashion_prior': False}]})['result'], 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(hero.load_fields(self.backend, self.token)['prior_settings'],
                         [{'category': 6, 'is_fashion_prior': True}])

    def test_load_filter_and_native_selected_hero_self_id(self):
        result = self.request('CSHeroLoadHeroListReq', {'hero_id_list': [HERO], 'filter_by_id': True})
        self.assertEqual([r['hero_id'] for r in result['heros']], [HERO])
        self.assertEqual(result['hero_ids'], sorted(hero.BASES))
        native_id = self.backend.native_identity(self.token)['native_id']
        self.assertEqual(self.request('CSHeroGetSelectedHeroReq', {'player_id': native_id, 'mode': 5})['hero_selected']['hero_id'], HERO)

    def test_stale_or_wrong_slot_unequip_preserves_current_equipment(self):
        self.grant(VOICE, VOICE + 1)
        for item_id in (VOICE, VOICE + 1):
            self.assertEqual(self.request('CSHeroSelectAccessoryReq', {'hero_id': HERO,
                'accessory_item': {'prop_id': item_id, 'slot': 1}})['result'], 0)
        for item_id, slot in ((VOICE, 1), (VOICE + 1, 2)):
            self.assertNotEqual(self.request('CSHeroSelectAccessoryReq', {'hero_id': HERO,
                'accessory_item': {'prop_id': item_id, 'slot': slot}, 'is_unequip': True})['result'], 0)
            selected = [r for r in self.record()['accessories'] if r['is_selected'] and r['item']['prop_id'] in (VOICE, VOICE + 1)]
            self.assertEqual([(r['item']['prop_id'], r['item']['slot']) for r in selected], [(VOICE + 1, 1)])

    def test_execution_requires_its_native_linked_fashion(self):
        execution, fashion = 38060060006, 30000060007
        self.grant(execution, fashion)
        fields = {'hero_id': HERO, 'accessory_item': {'prop_id': execution, 'slot': 0}}
        self.assertNotEqual(self.request('CSHeroSelectAccessoryReq', fields)['result'], 0)
        self.assertEqual(self.request('CSHeroEquipFashionReq', {'hero_id': HERO,
            'new_fashions': [{'slot': 0, 'id': fashion}]})['result'], 0)
        self.assertEqual(self.request('CSHeroSelectAccessoryReq', fields)['result'], 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertTrue(next(r for r in self.record()['accessories'] if r['item']['prop_id'] == execution)['is_selected'])


if __name__ == '__main__':
    unittest.main()
