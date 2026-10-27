import json
from pathlib import Path
import unittest
from extract_native_quest_weapon_presets import build_catalog


ROOT = Path(__file__).resolve().parent.parent
PROTOCOL = ROOT / 'outputs/df-local-server/protocol'


class NativeQuestWeaponPresetTests(unittest.TestCase):
    def catalog(self):
        if not hasattr(self.__class__, '_catalog'):
            self.__class__._catalog = build_catalog()
        return self.__class__._catalog

    def test_real_11001_variant_keeps_original_receiver_components_and_offsets(self):
        catalog = self.catalog()
        row = catalog['presets']['10010001050']
        self.assertEqual(row['receiver_id'], 18010000031)
        self.assertEqual(row['prop']['id'], 18010000031)
        self.assertEqual((row['prop']['length'], row['prop']['width']), (5, 2))
        self.assertEqual(row['node_row_offsets']['1'],
                         [1167615, 1168194, 1168773, 1169352, 1169931, 1170510])
        self.assertIn({'quest_id': 11001, 'reward_id': 1100103,
            'reward_source_row': 4672, 'reward_serialized_offset': 1065287,
            'number': 1, 'bind_type': 0}, row['reward_contexts'])
        children = {component['slot']: component['prop_data'] for component in row['prop']['components']}
        self.assertEqual(children[2]['id'], 13020000001)
        self.assertEqual(children[2]['components'][0]['prop_data']['id'], 13130000178)

    def test_ordinary_source_preset_rewards_are_resolved_or_explicitly_unavailable(self):
        catalog = self.catalog()
        quests = json.loads((PROTOCOL / 'native_quest_catalog.json').read_text(encoding='utf-8'))
        ordinary = {quests['enums']['QuestType']['values'][name] for name in ('Mission', 'Branch')}
        rewards = {row['RewardID']: row for row in quests['rewards']}
        requested = {rewards[value]['ItemID'] for quest in quests['quests']
            if quest['QuestType'] in ordinary for value in quest['RewardList']
            if rewards[value]['Type'] == 1 and str(rewards[value]['ItemID']).startswith('100')}
        self.assertTrue(requested)
        self.assertLessEqual({str(value) for value in requested},
                             catalog['presets'].keys() | catalog['unavailable_presets'].keys())
        self.assertTrue(all(row['reward_contexts'] for row in catalog['presets'].values()))

    def test_catalog_retains_original_sources_and_byte_identical_reextraction(self):
        catalog = self.catalog()
        self.assertEqual(catalog['sources']['gun_nodes']['sha256'],
            '0075368148ad3c2ffcaec020bfee36b1ac0bacd13506af1502c744ada5b137b5')
        self.assertEqual(catalog['sources']['item_base']['sha256'],
            '5361e9a383ca5f3a2b675704e464b414f4a4631f10d28e4798821eba2097e837')
        self.assertEqual(build_catalog(), catalog)


if __name__ == '__main__':
    unittest.main()
