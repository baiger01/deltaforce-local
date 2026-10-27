"""Retain read-only reward and binding source witnesses for quest research."""

import hashlib
import json
from pathlib import Path
import re
import struct

from extract_native_safehouse_catalog import installed_export
from local_game_paths import game_paths
from lua53_reader import Reader, listing, walk
from scan_weapon_tables import parse_entry


ROOT = Path(__file__).resolve().parent.parent
PAK = 'pak-0-0-pakchunk1-WindowsClient.pak'
TARGETS = {
    1818: ('ItemBase.lua', ['0.2', '0.12', '0.39', '0.40', '0.79', '0.80', '0.81']),
    1833: ('QuestLineStruct.lua', ['0.2']),
    1834: ('QuestObjectiveStruct.lua', ['0.6']),
    1838: ('QuestStruct.lua', ['0.11', '0.12', '0.13', '0.15']),
    1882: ('DFMGlobalConst.lua', ['0']),
    2676: ('BlackSiteConfig.lua', ['0']),
    1846: ('MerchantStruct.lua', ['0.1', '0.8', '0.9']),
    4381: ('ASafeHouseDepartmentWrapper.lua', ['0']),
    4391: ('IrisSafeHouseConfig.lua', ['0']),
    5124: ('QuestLogic.lua', ['0.17.1', '0.18', '0.24.0']),
    6645: ('common_pb.lua', ['0']),
    6005: ('PrestigeUsagePanel.lua', ['0.13', '0.13.0']),
    6919: ('QuestServer.lua', ['0.33', '0.52', '0.53']),
    6929: ('RoleInfoServer.lua', ['0.1', '0.55.0', '0.56', '0.57.0', '0.63', '0.64']),
}


def main():
    path = game_paths()[0] / 'DeltaForce/Content/Paks' / PAK
    positions = {}
    with path.open('rb') as handle:
        handle.seek(-512, 2)
        tail = handle.read(512)
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        _, limit = struct.unpack_from('<IQ', tail, marker + 4)
        position = number = 0
        while number < max(TARGETS):
            try:
                try:
                    entry = parse_entry(handle, position, limit)
                except (ValueError, struct.error):
                    entry = parse_entry(handle, position, limit, variant='observed_permutation')
            except (ValueError, struct.error):
                aligned = (position + 2047) // 2048 * 2048
                handle.seek(position)
                if aligned >= limit or handle.read(aligned - position) != bytes(aligned - position):
                    raise ValueError('Unknown source PAK boundary')
                position = aligned
                entry = parse_entry(handle, position, limit, variant='observed_permutation')
            number += 1
            if number in TARGETS:
                positions[number] = position
            position = entry['next_pos']
    report = {}
    for number, (name, selected) in TARGETS.items():
        raw, source = installed_export(number, positions[number], pak=PAK)
        recovered = (ROOT / 'work/evidence/weapon_lua' / name).read_bytes()
        if recovered != raw:
            raise ValueError('Extracted source changed: ' + name)
        functions = {value['id']: value for value in walk(
            Reader(raw, allow_client_format1=True).function())}
        witnesses = {}
        for ident in selected:
            function = functions[ident]
            lines = listing(function).splitlines()
            if name == 'DFMGlobalConst.lua':
                lines = lines[:5]
            elif name == 'BlackSiteConfig.lua':
                lines = lines[651:658]
            elif name == 'common_pb.lua':
                lines = lines[511:520]
            elif name == 'IrisSafeHouseConfig.lua':
                lines = lines[1133:1168]
            witnesses[ident] = {'first_line': function['first_line'],
                'last_line': function['last_line'], 'instructions': lines}
        report[name] = {**source, 'functions': witnesses}
        print(name, number, positions[number], source['sha256'])
    raw, source = installed_export(0, 32858112, pak=PAK)
    functions = {value['id']: value for value in walk(
        Reader(raw, allow_client_format1=True).function())}
    report['ds_common_editor_pb.lua'] = {**source, 'functions': {
        '0.195': {'instructions': listing(functions['0.195']).splitlines()[80:94]},
        '0.194': {'instructions': listing(functions['0.194']).splitlines()[111:129]},
    }}
    target = ROOT / 'work/evidence/research-quest-reward-metadata-20261019.json'
    target.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print('evidence', target)


if __name__ == '__main__':
    main()
