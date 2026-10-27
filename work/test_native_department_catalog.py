"""Check relational inference boundaries; synthetic fixtures are not client data."""

from copy import deepcopy
import unittest

from extract_native_department_catalog import department_relations


def row(index, **values):
    return {'source_row': index, 'serialized_offset': 100 + index * 10, **values}


class DepartmentCatalogTests(unittest.TestCase):
    def setUp(self):
        self.tables = {
            'qualities': [row(0, QualityID=100001, QuestID=1004, Name={'serialized_hex': ''},
                              ImgPath='source-image', SpritePath='source-sprite', CoverImgPath='source-cover')],
            'lines': [row(0, QuestLineID=1004, RootQuestID=10, MerchantId=3)],
            'quests': [row(0, QuestID=10, QuestType=1, PreviousIDList=[], RewardList=[]),
                       row(1, QuestID=11, QuestType=1, PreviousIDList=[10], RewardList=[20])],
            'rewards': [row(0, RewardID=20, Type=4, ItemID=26020000002, Number=7)],
            'traders_primary': [row(0, TraderID=3, UnlockRepLv='100001:1')],
            'traders_variant': [row(0, TraderID=3, UnlockRepLv='100001:1')],
        }

    def test_reward_uses_quest_ancestor_instead_of_item_suffix(self):
        result = department_relations(self.tables, {100001: 1004})
        self.assertEqual(result['quality_rewards'][0]['quality_id'], 100001)
        self.assertEqual(result['quality_rewards'][0]['amount'], 7)
        self.assertEqual(result['departments'][0]['root_quest_id'], 10)
        self.assertEqual(result['departments'][0]['ImgPath'], 'source-image')

    def test_detached_reward_stays_unresolved(self):
        self.tables['quests'][1]['PreviousIDList'] = []
        result = department_relations(self.tables, {100001: 1004})
        self.assertEqual(result['quality_rewards'], [])
        self.assertEqual(result['unresolved_contexts'][0]['quest_id'], 11)
        self.assertNotIn('quality_id', result['unresolved_contexts'][0])

    def test_multiple_line_ancestors_stay_unresolved(self):
        self.tables['lines'].append(row(1, QuestLineID=9999, RootQuestID=12, MerchantId=4))
        self.tables['quests'].append(row(2, QuestID=12, QuestType=1, PreviousIDList=[], RewardList=[]))
        self.tables['quests'][1]['PreviousIDList'] = [10, 12]
        result = department_relations(self.tables, {100001: 1004})
        self.assertEqual(result['quality_rewards'], [])
        self.assertEqual(result['unresolved_contexts'][0]['quest_line_ids'], [1004, 9999])

    def test_unmapped_role_quality_does_not_become_department(self):
        extra = deepcopy(self.tables['qualities'][0])
        extra.update(QualityID=100005, QuestID=1005)
        self.tables['qualities'].append(extra)
        self.assertEqual(len(department_relations(self.tables, {100001: 1004})['departments']), 1)

    def test_contradicting_role_quality_is_rejected(self):
        self.tables['qualities'][0]['QuestID'] = 1001
        with self.assertRaisesRegex(ValueError, 'RoleQuality'):
            department_relations(self.tables, {100001: 1004})

    def test_each_trader_variant_must_corroborate_card(self):
        self.tables['traders_variant'][0]['UnlockRepLv'] = '100002:1'
        with self.assertRaisesRegex(ValueError, 'TraderInfo'):
            department_relations(self.tables, {100001: 1004})

    def test_prerequisite_cycle_is_rejected(self):
        self.tables['quests'][1]['PreviousIDList'] = [11]
        with self.assertRaisesRegex(ValueError, 'cycle'):
            department_relations(self.tables, {100001: 1004})

    def test_unknown_prerequisite_is_rejected(self):
        self.tables['quests'][1]['PreviousIDList'] = [999]
        with self.assertRaisesRegex(ValueError, 'prerequisite'):
            department_relations(self.tables, {100001: 1004})

    def test_duplicate_quest_ids_are_rejected(self):
        self.tables['quests'].append(deepcopy(self.tables['quests'][1]))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            department_relations(self.tables, {100001: 1004})


if __name__ == '__main__':
    unittest.main()
