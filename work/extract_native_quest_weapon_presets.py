"""Recover ordinary quest weapon rewards from their original preset node rows."""

from collections import defaultdict
import hashlib
import json
from pathlib import Path

from explore_weapon_nodes import SOURCE, rows
from extract_weapon_components_catalog import recover_tree
from lua53_reader import Reader, listing, walk


ROOT = Path(__file__).resolve().parent.parent
PROTOCOL = ROOT / 'outputs/df-local-server/protocol'
TARGET = PROTOCOL / 'native_quest_weapon_presets_catalog.json'
NODE_HASH = '0075368148ad3c2ffcaec020bfee36b1ac0bacd13506af1502c744ada5b137b5'
ITEM_BASE_HASH = '5361e9a383ca5f3a2b675704e464b414f4a4631f10d28e4798821eba2097e837'


def build_catalog():
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != NODE_HASH:
        raise ValueError('Original weapon preset node source changed')
    quest_bytes = (PROTOCOL / 'native_quest_catalog.json').read_bytes()
    item_bytes = (PROTOCOL / 'game_item_catalog.json').read_bytes()
    quests, items = json.loads(quest_bytes), json.loads(item_bytes)['rows']
    objectives = json.loads((PROTOCOL / 'native_quest_objectives.json').read_bytes())
    kinds = objectives['enums']['QuestRewardType']['values']
    ordinary = {quests['enums']['QuestType']['values'][name] for name in ('Mission', 'Branch')}
    rewards = {row['RewardID']: row for row in quests['rewards']}
    contexts = defaultdict(list)
    for quest in quests['quests']:
        if quest['QuestType'] not in ordinary:
            continue
        for reward_id in quest['RewardList']:
            reward = rewards[reward_id]
            if reward['Type'] == kinds['RewardProp']:
                contexts[reward['ItemID']].append({'quest_id': quest['QuestID'],
                    'reward_id': reward_id, 'reward_source_row': reward['source_row'],
                    'reward_serialized_offset': reward['serialized_offset'],
                    'number': reward['Number'], 'bind_type': reward['bindType']})
    groups = defaultdict(list)
    for offset, _, values, _ in rows():
        if values[0x7471] in contexts:
            groups[values[0x7471]].append((offset, values))
    presets, unavailable = {}, {}
    for preset, records in sorted(groups.items()):
        roots = {row[0x747c] for _, row in records if row[0x7482] == 0}
        try:
            if len(roots) != 1:
                raise ValueError('Reward preset does not have one original receiver')
            receiver = next(iter(roots))
            tree = recover_tree(preset, receiver, records, items)
            if not 1 <= tree['prop']['length'] <= 9 or not 1 <= tree['prop']['width'] <= 40:
                raise ValueError('Reward receiver has no supported physical dimensions')
        except ValueError as error:
            unavailable[str(preset)] = {'reason': str(error),
                'node_row_offsets': [offset for offset, _ in records], 'reward_contexts': contexts[preset]}
        else:
            presets[str(preset)] = {'receiver_id': receiver, **tree, 'reward_contexts': contexts[preset]}
    # Abstract weapon GameItem IDs use the same 100 prefix as the existing preset catalog.
    for preset in sorted(contexts):
        if str(preset).startswith('100') and preset not in groups:
            unavailable[str(preset)] = {'reason': 'No original source preset nodes',
                                       'reward_contexts': contexts[preset], 'node_row_offsets': []}
    item_base = ROOT / 'work/evidence/weapon_lua/ItemBase.lua'
    raw = item_base.read_bytes()
    if hashlib.sha256(raw).hexdigest() != ITEM_BASE_HASH:
        raise ValueError('Original ItemBase source changed')
    functions = {fn['id']: fn for fn in walk(Reader(raw, allow_client_format1=True).function())}
    function = functions['0.11']
    if function['constants'][17] != 1 or function['constants'][26] != 0:
        raise ValueError('Original nonstackable item constants changed')
    instructions = listing(function).splitlines()[150:160]
    if instructions[-1] != "0160 SETTABLE   R0 K34='maxStackCount' K17=1":
        raise ValueError('Original zero stack limit handling changed')
    return {'mapping_status': 'verified_by_original_preset_nodes_and_itembase_consumer',
        'scope': 'Ordinary Mission and Branch RewardProp presets; exact component trees, not receiver defaults',
        'sources': {'gun_nodes': {'pak': 'pak-0-0-pakchunk2-WindowsClient.pak',
            'entry': 4567, 'sha256': NODE_HASH},
            'quest_catalog': {'file': 'native_quest_catalog.json', 'sha256': hashlib.sha256(quest_bytes).hexdigest()},
            'game_items': {'file': 'game_item_catalog.json', 'sha256': hashlib.sha256(item_bytes).hexdigest()},
            'item_base': {'file': 'ItemBase.lua', 'pak': 'pak-0-0-pakchunk1-WindowsClient.pak',
                'entry': 1818, 'pak_offset': 8474624, 'sha256': ITEM_BASE_HASH,
                'function': '0.11', 'pcs': [151, 160], 'rk_constants': {'273': 1, '282': 0},
                'instructions': instructions},
            'component_serialization': {'file': 'WeaponAssemblyTool.lua', 'function': '0.11.0',
                'sha256': '3934cf763b87e4ea7cfc779b7db5541f913d321898143b1ff51293994a8d91c5'}},
        'presets': presets, 'unavailable_presets': unavailable}


def main():
    report = build_catalog()
    TARGET.write_text(json.dumps(report, ensure_ascii=True, separators=(',', ':')) + '\n', encoding='utf-8')
    print({'presets': len(report['presets']), 'unavailable_presets': len(report['unavailable_presets']),
           'sha256': hashlib.sha256(TARGET.read_bytes()).hexdigest(), 'output': str(TARGET)})


if __name__ == '__main__':
    main()
