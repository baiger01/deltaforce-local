"""Extract source-bound department relations without inventing reputation curves.

Type 4 reward bindings apply only to ordinary quests with a unique native
department quest-line ancestor. They are not general item-use effects.
"""

from collections import defaultdict
from functools import lru_cache
import json
import re

from extract_native_quest_catalog import TABLES as QUEST_TABLES
from extract_native_safehouse_catalog import EXPECTED_PE, PROTOCOL, installed_export, source_structs
from inspect_department_tables import TABLES as DEPARTMENT_TABLES, rows as table_rows
from lua53_reader import Reader, instruction, listing, walk


TABLES = {
    **QUEST_TABLES,
    'qualities': (7046, 50304009, *DEPARTMENT_TABLES['qualities'][2:]),
    'traders_primary': (6296, 47973753, *DEPARTMENT_TABLES['traders'][2:]),
    'traders_variant': (7212, 50640249, *DEPARTMENT_TABLES['traders'][2:]),
}
TABLE_HASHES = {
    'quests': '0ab1e9ca0adc1435660542b521b8cbe3b30395ccb397007056adb2f687571a95',
    'lines': 'd69484ce8bdec2a2642a9b9dff95121ff3548f2743356a3dab3c952c4162e4ac',
    'rewards': '6378c4264af6c3b0487aedc73dc2e0770fe2768a4988aea3660e757f32d45af6',
    'qualities': '800bccdc9bc853b3010c46e896978489f6796e3452c0ef3b11b8ebd37e4ce601',
    'traders_primary': 'e972c06b949b1db407e694d342a444478f89b0cf4fcd68c6797e233205c684dc',
    'traders_variant': '725712f29ee78b9b18d6d5e7362a8861010ffc6cd7d3bdc3b3ab6bfde4b12b6c',
}
LUA_PAK = 'pak-0-0-pakchunk1-WindowsClient.pak'
LUA_SOURCES = {
    'blacksite_config': ('BlackSiteConfig.lua', 2676, 13256704,
        '9a454bfa2930d2c255bc0b41cae889002c2a3032eef5588405236ff3233233ec'),
    'common_enums': ('common_pb.lua', 6645, 31748096,
        '81e071e35f33f0e5704d5098ac2a182c794bbe5b1e5a7e24f415a0473b40350b'),
    'role_info_server': ('RoleInfoServer.lua', 6929, 34949120,
        'a6221ddd4f16c4c77be62be552b78eb275f06f9710aed57c3ec529e543eb7503'),
    'quality_protocol': ('cs_attribute_editor_pb.lua', 6656, 31989760,
        '67b37245246accdbf34c3058a1a272b988fab61624d3594ebfa0e6d039d4d4f1'),
    'prestige_usage_panel': ('PrestigeUsagePanel.lua', 6005, 28905472,
        '7608646e49513d73fa3ea514275d31efe56faaf70a8c58b65f61a7283e8be613'),
}


def source_ref(group, row):
    return {'source': group, 'source_row': row['source_row'],
            'serialized_offset': row['serialized_offset']}


def indexed(rows, key):
    result = {row[key]: row for row in rows}
    if len(result) != len(rows) or any(not isinstance(ident, int) or ident <= 0 for ident in result):
        raise ValueError('Invalid or duplicate native ' + key)
    return result


def department_relations(tables, quality_to_line):
    qualities = indexed(tables['qualities'], 'QualityID')
    lines = indexed(tables['lines'], 'QuestLineID')
    quests = indexed(tables['quests'], 'QuestID')
    rewards = indexed(tables['rewards'], 'RewardID')
    roots = indexed(tables['lines'], 'RootQuestID')
    line_quality = {line: quality for quality, line in quality_to_line.items()}
    if len(line_quality) != len(quality_to_line):
        raise ValueError('Department quest line has multiple quality cards')
    traders = {group: indexed(tables[group], 'TraderID')
               for group in ('traders_primary', 'traders_variant')}
    for quest in quests.values():
        if any(ident not in quests for ident in quest['PreviousIDList']):
            raise ValueError('Unknown native quest prerequisite')
        if any(ident not in rewards for ident in quest['RewardList']):
            raise ValueError('Unknown native quest reward')
    departments = []
    for card_id, line_id in sorted(quality_to_line.items()):
        quality = qualities[card_id]
        line = lines[line_id]
        if quality['QuestID'] != line_id:
            raise ValueError('RoleQuality and explicit BlackSiteConfig relation disagree')
        root = quests[line['RootQuestID']]
        merchant_id = line['MerchantId']
        witnesses = {}
        for group, records in traders.items():
            trader = records[merchant_id]
            match = re.fullmatch(r'(\d+):(\d+)', trader['UnlockRepLv'])
            if match is None or int(match[1]) != card_id:
                raise ValueError('TraderInfo unlock reputation contradicts department relation')
            witnesses[group] = {**source_ref(group, trader), 'UnlockRepLv': trader['UnlockRepLv']}
        departments.append({
            'card_id': card_id, 'quest_line_id': line_id,
            'root_quest_id': line['RootQuestID'], 'merchant_id': merchant_id,
            'Name': quality['Name'],
            **{key: quality[key] for key in ('ImgPath', 'SpritePath', 'CoverImgPath')},
            'source_refs': {'quality': source_ref('qualities', quality),
                'line': source_ref('lines', line), 'root_quest': source_ref('quests', root),
                'merchants': witnesses},
        })

    @lru_cache(None)
    def ancestor_lines(quest_id, trail=()):
        if quest_id in trail:
            raise ValueError('Native quest prerequisite cycle')
        if quest_id in roots:
            return frozenset([roots[quest_id]['QuestLineID']])
        return frozenset(line for parent in quests[quest_id]['PreviousIDList']
                         for line in ancestor_lines(parent, trail + (quest_id,)))

    joined, unresolved = [], []
    for quest in sorted(quests.values(), key=lambda value: value['QuestID']):
        if quest['QuestType'] not in (1, 2):
            continue
        for reward_id in quest['RewardList']:
            reward = rewards[reward_id]
            if reward['Type'] != 4:
                continue
            line_ids = sorted(ancestor_lines(quest['QuestID']))
            context = {'quest_id': quest['QuestID'], 'quest_type': quest['QuestType'],
                'reward_id': reward_id, 'item_id': reward['ItemID'], 'amount': reward['Number'],
                'source_refs': {'quest': source_ref('quests', quest),
                                'reward': source_ref('rewards', reward)}}
            if len(line_ids) != 1 or line_ids[0] not in line_quality:
                unresolved.append({**context, 'quest_line_ids': line_ids,
                    'reason': 'No unique active department quest-line ancestor'})
                continue
            joined.append({**context, 'quality_id': line_quality[line_ids[0]],
                           'quest_line_id': line_ids[0]})
    grouped = defaultdict(list)
    for context in joined:
        grouped[context['item_id']].append(context)
    bindings = []
    for item_id, contexts in sorted(grouped.items()):
        pairs = {(value['quality_id'], value['quest_line_id']) for value in contexts}
        if len(pairs) != 1:
            raise ValueError('Reward template has conflicting department contexts')
        quality_id, line_id = pairs.pop()
        bindings.append({'item_id': item_id, 'quality_id': quality_id,
            'quest_line_id': line_id, 'quest_count': len({value['quest_id'] for value in contexts}),
            'reward_reference_count': len(contexts)})
    return {'departments': departments, 'quality_rewards': joined,
            'context_reward_item_bindings': bindings, 'unresolved_contexts': unresolved}


def read_tables():
    reflected = source_structs(TABLES)
    sources, tables = {}, {}
    for group, (entry, pak_offset, *_) in TABLES.items():
        raw, source = installed_export(entry, pak_offset)
        if source['sha256'] != TABLE_HASHES[group]:
            raise ValueError('Installed native table hash changed: ' + group)
        records, fields = table_rows(raw, reflected[group]['columns'])
        structure = {key: value for key, value in reflected[group].items() if key != 'size'}
        sources[group] = {**source, **structure, 'struct_size': reflected[group]['size'],
            'row_count': len(records), 'serialized_field_indices': fields,
            'name_map_available': False}
        tables[group] = records
    return sources, tables


def read_lua(group):
    name, entry, offset, expected = LUA_SOURCES[group]
    raw, source = installed_export(entry, offset, pak=LUA_PAK)
    if source['sha256'] != expected:
        raise ValueError('Installed client Lua hash changed: ' + name)
    reader = Reader(raw, allow_client_format1=True)
    root = reader.function()
    if reader.at != len(raw) or root['source'] != '@' + name:
        raise ValueError('Installed client Lua identity or extent changed: ' + name)
    return {value['id']: value for value in walk(root)}, {'source': root['source'], **source}


def function_witness(function, *, start=None, stop=None):
    lines = listing(function).splitlines()
    return {'function': function['id'], 'serialized_offset': function['offset'],
        'first_line': function['first_line'], 'last_line': function['last_line'],
        'instructions': lines[start:stop]}


def client_relations():
    functions, source = read_lua('blacksite_config')
    root = functions['0']
    expected = [
        '0653 SETTABLE   R4 K217=100001 K135=1004',
        '0654 SETTABLE   R4 K218=100002 K129=1001',
        '0655 SETTABLE   R4 K219=100003 K133=1003',
        '0656 SETTABLE   R4 K220=100004 K131=1002',
        '0657 SETTABLE   R4 K221=100006 K139=1006',
        "0658 SETTABUP   U0 K216='EBlackSiteQualityID2QuestLineID' R4",
    ]
    if listing(root).splitlines()[652:658] != expected:
        raise ValueError('Explicit native department-to-line assignment changed')
    quality_to_line = {}
    for word in root['code'][652:657]:
        operands = instruction(word)
        quality_to_line[root['constants'][operands['b'] & 255]] = root['constants'][operands['c'] & 255]
    sources = {'blacksite_config': source}
    consumers = {'quality_to_quest_line': {'source': 'blacksite_config',
        **function_witness(root, start=651, stop=658)}}
    functions, source = read_lua('common_enums')
    lines = listing(functions['0']).splitlines()
    start = next(index for index, line in enumerate(lines)
                 if "'QuestRewardType'" in line and 'LOADK' in line)
    stop = next(index for index in range(start + 1, len(lines)) if 'SETTABUP' in lines[index]) + 1
    block = lines[start:stop]
    index = next(index for index, line in enumerate(block) if "'RewardQualityValue'" in line)
    if re.search(r'SETTABLE\s+R2 R3 K\d+=4$', block[index + 1]) is None:
        raise ValueError('Native RewardQualityValue enum changed')
    sources['common_enums'] = source
    consumers['quality_reward_type'] = {'source': 'common_enums',
        **function_witness(functions['0'], start=start, stop=stop)}
    requirements = {
        'role_info_server': {'0.57.0': ['quality_id', 'Name', 'ImgPath', 'SpritePath',
                                     'quality_usages', 'UsageList', 'Desc']},
        'quality_protocol': {'0.21': ['desc', 'type', 'target', 'addstr', 'addu32'],
                             '0.23': ['quality_id', 'quest_id', 'quality_usages', 'cover_img_path']},
        'prestige_usage_panel': {'0.13': ['quality_usages', 'DescriptionQuest', 'GetQuestLineInfoById'],
                                '0.13.0': ['quest_id', 'JumpByID'],
                                '0.13.1': ['type', 'Shop', 'SafeHouse', 'ShowMainPanel', 'Jump', 'target']},
    }
    for group, required in requirements.items():
        functions, source = read_lua(group)
        sources[group] = source
        for ident, constants in required.items():
            if not all(value in functions[ident]['constants'] for value in constants):
                raise ValueError('Native department consumer changed: ' + group + '/' + ident)
        consumers[group] = {'source': group,
            'functions': [function_witness(functions[ident]) for ident in required]}
    return sources, consumers, quality_to_line


def main():
    sources, tables = read_tables()
    lua_sources, consumers, quality_to_line = client_relations()
    relations = department_relations(tables, quality_to_line)
    counts = {'role_qualities': len(tables['qualities']),
        'departments': len(relations['departments']),
        'quality_reward_references': len(relations['quality_rewards']),
        'unresolved_quality_reward_references': len(relations['unresolved_contexts']),
        'context_reward_item_bindings': len(relations['context_reward_item_bindings'])}
    expected = {'role_qualities': 8, 'departments': 5, 'quality_reward_references': 309,
                'unresolved_quality_reward_references': 29, 'context_reward_item_bindings': 5}
    if counts != expected:
        raise ValueError('Native department extraction coverage changed: ' + repr(counts))
    if set(value['quality_id'] for value in relations['context_reward_item_bindings']) != set(quality_to_line):
        raise ValueError('Native active department rewards are incompletely covered')
    report = {
        'schema_version': 1, 'mapping_status': 'verified_source_relational_join',
        'native_pe_sha256': EXPECTED_PE, 'sources': {**sources, **lua_sources},
        'counts': counts, **relations, 'role_qualities': tables['qualities'],
        'client_consumers': consumers,
        'quality_usage_relation': {
            'status': 'client_consumer_verified_configured_values_unavailable',
            'protocol': {'source': 'quality_protocol', 'message': 'RoleQualityUsage',
                'encode_function': '0.21', 'fields': [
                    {'name': 'desc', 'number': 1, 'kind': 'str'},
                    {'name': 'type', 'number': 2, 'kind': 'str'},
                    {'name': 'target', 'number': 3, 'kind': 'u32'}]},
            'description_relation': 'RoleInfoServer 0.57.0 assigns RoleQuality.UsageList{1-based quality_usages position}Desc to each returned usage.desc.',
            'jump_consumers': {'Shop': 'Module.Shop:ShowMainPanel(target)',
                               'SafeHouse': 'Module.BlackSite:Jump(target, true)'},
            'configured_usages': None,
        },
        'reputation_curve': {'status': 'unavailable', 'level_thresholds': None,
            'max_level': None, 'reason': 'No source-bound department reputation score-to-level curve was recovered.'},
        'limitations': [
            'Quality reward bindings are restricted to the listed ordinary Mission/Branch quest/reward contexts; they are not an item-use mapping.',
            'Detached or ambiguous quality reward contexts remain unresolved and must not grant a department quality.',
            'All original RoleQuality fields are retained; unresolved FText string-table references are not replaced by guessed department names.',
            'Only the five explicit BlackSiteConfig quality-to-line assignments are active departments; the remaining RoleQuality rows are retained without activation.',
            'Per-card quality usage type/target values, reputation thresholds, maximum level and is_unlock derivation remain unavailable.',
        ],
    }
    output = PROTOCOL / 'native_department_catalog.json'
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(counts, sort_keys=True))
    print('catalog', output)


if __name__ == '__main__':
    main()
