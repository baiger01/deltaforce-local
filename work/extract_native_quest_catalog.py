"""Recover actual quest IDs and acceptance prerequisites from installed tables."""

import json
import re

from extract_native_safehouse_catalog import (
    EXPECTED_PE, PROTOCOL, consumer, extract_tables, lua_source,
)
from lua53_reader import listing


TABLES = {
    'quests': (6930, 49841929, 'QuestRow', 489435072, 413590352, 45),
    'lines': (6934, 49915001, 'QuestLineRow', 489434592, 413724352, 15),
    'rewards': (6940, 50054057, 'QuestRewardsRow', 489434672, 413704112, 6),
}


def enums():
    root, _ = lua_source('common_pb.lua')
    lines = listing(root).splitlines()
    result = {}
    for name, expected in (
            ('QuestState', {'Locked': 0, 'Unread': 1, 'Unaccepted': 2, 'Accepted': 3,
                            'Failed': 4, 'Paused': 5, 'Completed': 6, 'Rewarded': 7, 'Expired': 8}),
            ('QuestType', {'Mission': 1})):
        start = next(index for index, line in enumerate(lines) if repr(name) in line and 'LOADK' in line)
        end = next(index for index in range(start + 1, len(lines)) if 'SETTABUP' in lines[index])
        block = lines[start:end + 1]
        for key, value in expected.items():
            index = next(index for index, line in enumerate(block) if repr(key) in line)
            if re.search(r'\bSETTABLE\s+R2 R3 K\d+=' + str(value) + r'$', block[index + 1]) is None:
                raise ValueError('Actual native enum assignment changed: ' + name + '.' + key)
        result[name] = {'values': expected, 'instructions': block}
    return result


def main():
    sources, rows = extract_tables(TABLES)
    for group, key in (('quests', 'QuestID'), ('lines', 'QuestLineID'), ('rewards', 'RewardID')):
        ids = [row[key] for row in rows[group]]
        if len(ids) != len(set(ids)) or any(value <= 0 for value in ids):
            raise ValueError('Invalid/duplicate actual native ' + group + ' ID')
    quests = {row['QuestID'] for row in rows['quests']}
    rewards = {row['RewardID'] for row in rows['rewards']}
    for row in rows['quests']:
        if any(value not in quests for value in row['PreviousIDList']):
            raise ValueError('Quest prerequisite references an unavailable native ID')
        if any(value not in rewards for value in row['RewardList']):
            raise ValueError('Quest reward references an unavailable native ID')
    report = {'native_pe_sha256': EXPECTED_PE,
        'mapping_status': 'verified_by_native_reflection_and_serialization',
        'sources': sources, **rows, 'enums': enums(),
        'client_consumers': {
            'server': consumer('QuestServer.lua', {'0.23': ['Quest', 'QuestID', 'preQuestIdList'],
                '0.24': ['QuestLine', 'rootQuestId', 'Unaccepted'],
                '0.30': ['CSQuestAcceptReq', 'quest_id'],
                '0.39': ['Unread', 'Unaccepted', 'levelLimit', 'GetRemainToAcceptTime']}),
            'quest': consumer('QuestStruct.lua', {'0.0': ['PreviousIDList', 'AcceptRequiredLevel', 'FrozenTimeAfterPreQuestReward'],
                '0.24': ['IsPreQuestAllFinished', 'Unaccepted'], '0.47': ['Rewarded', 'preQuestIdList'],
                '0.48': ['GetPreRewardTime', 'lockTime', 60]}),
            'line': consumer('QuestLineStruct.lua', {'0.2': ['seasonLevel', 'openLevel', 'openLimits']}),
            'enums': consumer('common_pb.lua', {'0': ['QuestState', 'Locked', 'Unread',
                'Unaccepted', 'Accepted', 'Completed', 'Rewarded']})},
        'limitations': ['Season groups, show conditions, and specialised quest types need their own verified eligibility paths.',
                       'Acceptance persists progress only; objective completion and reward grants are not inferred.']}
    output = PROTOCOL / 'native_quest_catalog.json'
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print({key: len(value) for key, value in rows.items()})


if __name__ == '__main__':
    main()
