"""Recover objective quantities and submission predicates from original client rows."""

import json
import hashlib
import re

from extract_native_safehouse_catalog import (
    EXPECTED_PE, PROTOCOL, consumer, installed_export, lua_source, source_structs,
)
from inspect_department_tables import rows
from lua53_reader import Reader, listing, walk


TABLES = {'objectives': (6938, 49951385, 'QuestObjectiveRow', 489434912, 413646960, 31)}


def enum_values(root, name):
    lines = listing(root).splitlines()
    start = next(i for i, line in enumerate(lines) if repr(name) in line and 'LOADK' in line)
    end = next(i for i in range(start + 1, len(lines)) if 'SETTABUP' in lines[i])
    block = lines[start:end + 1]
    values, key, register = {}, None, None
    for line in block[2:]:
        match = re.search(r"LOADK\s+R3 K\d+='([^']+)'$", line)
        if match:
            key = match[1]
        match = re.search(r'LOADK\s+R4 K\d+=(\d+)$', line)
        if match:
            register = int(match[1])
        match = re.search(r'SETTABLE\s+R2 R3 (?:K\d+=(\d+)|(R4))$', line)
        if match and key:
            values[key] = int(match[1]) if match[1] is not None else register
            key, register = None, None
    if not values or any(type(value) is not int for value in values.values()):
        raise ValueError('Original quest enum instructions are not fully resolved')
    return {'values': values, 'instructions': block}


def main():
    native = source_structs(TABLES)['objectives']
    raw, source = installed_export(6938, 49951385)
    recovered, fields = rows(raw, native['columns'])
    if len({row['ObjectiveID'] for row in recovered}) != len(recovered):
        raise ValueError('Duplicate source objective ID')
    quest_catalog = json.loads((PROTOCOL / 'native_quest_catalog.json').read_text(encoding='utf-8'))
    references = {value for quest in quest_catalog['quests'] for value in quest['ObjectiveList']}
    available = {row['ObjectiveID'] for row in recovered}
    root, _ = lua_source('common_pb.lua')
    additional = {}
    for name, entry, offset, expected, selected in (
            ('ItemBase.lua', 1818, 8474624,
             '5361e9a383ca5f3a2b675704e464b414f4a4631f10d28e4798821eba2097e837',
             {'0.2': (12, 14), '0.12': (27, 37)}),
            ('DFMGlobalConst.lua', 1882, 8687616,
             '4887a7f2b5265a5277c5c2553f4ff56ec08f1219a632220e3b2efa367baddcc4', {'0': (0, 1)}),
            ('WeaponRestrictionsComponent.lua', 4299, 21000192,
             'fa82c72d5c056cf5769907f2123e935972f7900fd57eaed87d5000f3cbcbef3f',
             {'0.6': (111, 156), '0.6.2': (0, 10)}),
            ('QuestObjectiveCompoDesc.lua', 5189, 25286656,
             '17d408d5365d95376f95b1e65a06a8e18fef91f0ae37c21081e9dc72c0743555',
             {'0.5': (92, 107)}),
            ('GunsmithMissionLogic.lua', 3794, 18571264,
             '95b611e812944dec73985a4c88ef6a479449d50d25bbf91cfda3dd7a34075ebd',
             {'0.8': (15, 47)})):
        data, witness = installed_export(entry, offset, pak='pak-0-0-pakchunk1-WindowsClient.pak')
        if witness['sha256'] != expected:
            raise ValueError('Original quest item consumer changed: ' + name)
        functions = {fn['id']: fn for fn in walk(Reader(data, allow_client_format1=True).function())}
        witness['functions'] = {ident: listing(functions[ident]).splitlines()[start:end]
                                for ident, (start, end) in selected.items()}
        additional[name] = witness
    if not any("'bindType' K4=1" in line for line in additional['ItemBase.lua']['functions']['0.2']):
        raise ValueError('Original omitted binding default changed')
    if additional['DFMGlobalConst.lua']['functions']['0'] != ["0001 SETTABUP   U0 K0='EXP_ID' K1=26010000001"]:
        raise ValueError('Original role EXP item changed')
    report = {'mapping_status': 'verified_by_native_reflection_and_serialization',
        'native_pe_sha256': EXPECTED_PE,
        'source': {**source, 'native_struct': native, 'serialized_field_indices': fields},
        'quest_catalog_sha256': hashlib.sha256(
            (PROTOCOL / 'native_quest_catalog.json').read_bytes()).hexdigest(),
        'objectives': recovered,
        'unresolved_quest_objectives': sorted(references - available),
        'enums': {name: enum_values(root, name) for name in ('QuestObjectiveType', 'QuestRewardType', 'PropBindingType')},
        'omitted_prop_binding_default': 1,
        'role_exp_item_id': 26010000001,
        'simple_submit_component_policy': 'require_each_ListParam_template_in_owned_weapon_tree',
        'client_consumers': {
            'quests': consumer('QuestServer.lua', {'0.31': ['CSQuestCompleteReq', 'quest_id'],
                '0.32': ['CSQuestGetRewardReq', 'quest_id'],
                '0.33': ['CSQuestSubmitPropReq', 'submit_list', 'obj_id', 'submit_props']}),
            'enums': consumer('common_pb.lua', {'0': ['QuestObjectiveType', 'QuestRewardType']}), **additional},
        'limitations': ['Match objective events must be supplied by the match integration.',
                       'Role reputation level thresholds are not part of this objective table.']}
    output = PROTOCOL / 'native_quest_objectives.json'
    output.write_text(json.dumps(report, ensure_ascii=True, separators=(',', ':')) + '\n', encoding='utf-8')
    print({'objectives': len(recovered), 'unresolved_quest_objectives': sorted(references - available),
           'output': str(output)})


if __name__ == '__main__':
    main()
