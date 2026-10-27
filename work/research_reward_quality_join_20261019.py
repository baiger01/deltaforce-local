"""Research context-specific quality grants by original quest-line relations.

This is a relational inference from configured mission lines. It does not claim
to recover an ItemUse or server item-effect table.
"""

from collections import Counter, defaultdict
from functools import lru_cache
import json
from pathlib import Path
import re

from extract_native_quest_catalog import TABLES as QUEST_TABLES
from extract_native_safehouse_catalog import (
    EXPECTED_PE, extract_tables, installed_export, source_structs,
)
from inspect_department_tables import rows as department_rows
from lua53_reader import Reader, listing


ROOT = Path(__file__).resolve().parent.parent
QUALITY_SPEC = {'qualities': (7046, 50304009, 'RoleQuality', 489440096, 413382416, 14)}
EXPECTED_QUALITY_HASH = '800bccdc9bc853b3010c46e896978489f6796e3452c0ef3b11b8ebd37e4ce601'
LUA_HASH = '9a454bfa2930d2c255bc0b41cae889002c2a3032eef5588405236ff3233233ec'
EXPECTED_RELATION = {100001: 1004, 100002: 1001, 100003: 1003,
                     100004: 1002, 100006: 1006}


def main():
    quest_sources, tables = extract_tables(QUEST_TABLES)
    original_catalog = json.loads((ROOT / 'outputs/df-local-server/protocol/'
        'native_quest_catalog.json').read_text(encoding='utf-8'))
    if any(tables[group] != original_catalog[group] for group in tables):
        raise ValueError('Existing quest catalog differs from the installed source')
    common_raw, common_source = installed_export(6645, 31748096,
        pak='pak-0-0-pakchunk1-WindowsClient.pak')
    if common_source['sha256'] != '81e071e35f33f0e5704d5098ac2a182c794bbe5b1e5a7e24f415a0473b40350b':
        raise ValueError('Original common enum source changed')
    common_lines = listing(Reader(common_raw, allow_client_format1=True).function()).splitlines()
    reward_enum_start = next(index for index, line in enumerate(common_lines)
        if "'QuestRewardType'" in line and 'LOADK' in line)
    reward_enum_end = next(index for index in range(reward_enum_start + 1, len(common_lines))
        if 'SETTABUP' in common_lines[index])
    reward_enum = common_lines[reward_enum_start:reward_enum_end + 1]
    reward_quality_line = next(index for index, line in enumerate(reward_enum)
        if "'RewardQualityValue'" in line)
    if not re.search(r'SETTABLE\s+R2 R3 K\d+=4$', reward_enum[reward_quality_line + 1]):
        raise ValueError('Native RewardQualityValue enum differs')
    reflected = source_structs(QUALITY_SPEC)['qualities']
    quality_raw, quality_source = installed_export(7046, 50304009)
    if quality_source['sha256'] != EXPECTED_QUALITY_HASH:
        raise ValueError('Original RoleQuality changed')
    qualities, quality_fields = department_rows(quality_raw, reflected['columns'])
    by_quality = {row['QualityID']: row for row in qualities}
    lua, lua_source = installed_export(2676, 13256704,
        pak='pak-0-0-pakchunk1-WindowsClient.pak')
    if lua_source['sha256'] != LUA_HASH:
        raise ValueError('Original BlackSiteConfig changed')
    root = Reader(lua, allow_client_format1=True).function()
    instructions = listing(root).splitlines()[651:658]
    expected_lines = [
        "0653 SETTABLE   R4 K217=100001 K135=1004",
        "0654 SETTABLE   R4 K218=100002 K129=1001",
        "0655 SETTABLE   R4 K219=100003 K133=1003",
        "0656 SETTABLE   R4 K220=100004 K131=1002",
        "0657 SETTABLE   R4 K221=100006 K139=1006",
        "0658 SETTABUP   U0 K216='EBlackSiteQualityID2QuestLineID' R4",
    ]
    if instructions[1:] != expected_lines:
        raise ValueError('Original explicit department-to-line assignments changed')
    if any(by_quality[quality]['QuestID'] != line for quality, line in EXPECTED_RELATION.items()):
        raise ValueError('RoleQuality and BlackSiteConfig disagree')
    line_quality = {line: quality for quality, line in EXPECTED_RELATION.items()}
    quests = {row['QuestID']: row for row in tables['quests']}
    rewards = {row['RewardID']: row for row in tables['rewards']}
    lines = {row['RootQuestID']: row for row in tables['lines']}
    by_line = {row['QuestLineID']: row for row in tables['lines']}

    @lru_cache(None)
    def ancestors(quest_id, trail=()):
        if quest_id in trail:
            raise ValueError('Native prerequisite cycle')
        if quest_id in lines:
            return frozenset([lines[quest_id]['QuestLineID']])
        return frozenset(line for parent in quests[quest_id]['PreviousIDList']
                         for line in ancestors(parent, trail + (quest_id,)))

    joined, unresolved, contexts = [], [], defaultdict(list)
    ordinary = [row for row in quests.values() if row['QuestType'] in (1, 2)]
    for quest in ordinary:
        quality_rewards = [rewards[ident] for ident in quest['RewardList']
                           if rewards[ident]['Type'] == 4]
        for reward in quality_rewards:
            resolved_lines = sorted(ancestors(quest['QuestID']))
            record = {'quest_id': quest['QuestID'], 'quest_type': quest['QuestType'],
                'quest_source_row': quest['source_row'],
                'quest_serialized_offset': quest['serialized_offset'],
                'reward_id': reward['RewardID'], 'item_id': reward['ItemID'],
                'number': reward['Number'], 'reward_source_row': reward['source_row'],
                'reward_serialized_offset': reward['serialized_offset'],
                'quest_line_ids': resolved_lines}
            cards = {line_quality[line] for line in resolved_lines if line in line_quality}
            if len(resolved_lines) != 1 or len(cards) != 1:
                unresolved.append({**record, 'reason': 'No unique active department quest-line ancestor'})
                continue
            line_id = resolved_lines[0]
            card_id = next(iter(cards))
            record.update(quality_id=card_id, merchant_id=by_line[line_id]['MerchantId'],
                line_source_row=by_line[line_id]['source_row'],
                line_serialized_offset=by_line[line_id]['serialized_offset'],
                quality_source_row=by_quality[card_id]['source_row'],
                quality_serialized_offset=by_quality[card_id]['serialized_offset'])
            joined.append(record)
            contexts[reward['ItemID']].append(record)
    bindings = []
    for template, records in sorted(contexts.items()):
        cards = {row['quality_id'] for row in records}
        line_ids = {line for row in records for line in row['quest_line_ids']}
        if len(cards) != 1 or len(line_ids) != 1:
            raise ValueError('Reward template has conflicting configured department contexts')
        bindings.append({'item_id': template, 'quality_id': next(iter(cards)),
            'quest_line_id': next(iter(line_ids)), 'reward_reference_count': len(records),
            'quest_count': len({row['quest_id'] for row in records}),
            'counts_by_quest_type': dict(Counter(row['quest_type'] for row in records)),
            'contexts': records})
    if len({row['quality_id'] for row in bindings}) != len(bindings):
        raise ValueError('Department quality has more than one reward template')
    if set(row['quality_id'] for row in bindings) != set(EXPECTED_RELATION):
        raise ValueError('Active configured departments are not completely covered')
    # TraderInfo has two native variants; both must agree for these merchant links.
    existing = json.loads((ROOT / 'work/evidence/department-table-candidates-20261019.json')
                          .read_text(encoding='utf-8'))['candidates']
    trader_witnesses = []
    for candidate in existing:
        if candidate['group'] != 'traders':
            continue
        source_raw, source = installed_export(candidate['entry'], candidate['pak_offset'])
        if source['sha256'] != candidate['sha256']:
            raise ValueError('Original TraderInfo variant changed')
        traders, _ = department_rows(source_raw, candidate['native']['columns'])
        if traders != candidate['rows']:
            raise ValueError('TraderInfo candidate differs from source')
        trader_map = {row['TraderID']: row for row in traders}
        anchors = []
        for card_id, line_id in EXPECTED_RELATION.items():
            merchant_id = by_line[line_id]['MerchantId']
            trader = trader_map[merchant_id]
            if int(trader['UnlockRepLv'].split(':')[0]) != card_id:
                raise ValueError('Merchant unlock reputation contradicts line relation')
            anchors.append({key: trader[key] for key in ('TraderID', 'UnlockRepLv',
                'source_row', 'serialized_offset')})
        trader_witnesses.append({**source, 'anchors': anchors})
    report = {'mapping_status': 'verified_source_relational_join',
        'interpretation': 'Context-specific inference for Type4 rewards on ordinary Mission/Branch quests with a unique active native quest-line ancestor; not an ItemUse effect table.',
        'native_pe_sha256': EXPECTED_PE,
        'sources': {**quest_sources, 'qualities': {**quality_source, **reflected,
            'serialized_field_indices': quality_fields}},
        'explicit_quality_to_line': EXPECTED_RELATION,
        'explicit_quality_to_line_consumer': {**lua_source, 'source': '@BlackSiteConfig.lua',
            'function': '0', 'instructions': instructions},
        'quality_reward_type_consumer': {**common_source, 'source': '@common_pb.lua',
            'function': '0', 'instructions': reward_enum},
        'merchant_corroboration': trader_witnesses,
        'counts': {'ordinary_quests': len(ordinary),
            'quality_reward_references': len(joined) + len(unresolved),
            'joined_quality_reward_references': len(joined),
            'unresolved_quality_reward_references': len(unresolved), 'bindings': len(bindings)},
        'bindings': bindings, 'unresolved_contexts': unresolved,
        'all_role_quality_rows': qualities,
        'limitations': ['Do not apply these bindings outside verified ordinary quest-line contexts.',
            'Twenty-nine detached Mission quests have no native quest-line ancestor and remain unresolved.',
            'No reward template-to-card relation was inferred from a numeric suffix.',
            'Native server item-effect tables and RoleQualityCard.is_unlock derivation were not recovered.']}
    target = ROOT / 'work/evidence/research-reward-quality-join-20261019.json'
    target.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report['counts']))
    for binding in bindings:
        print({key: value for key, value in binding.items() if key != 'contexts'})
    print('report', target)


if __name__ == '__main__':
    main()
