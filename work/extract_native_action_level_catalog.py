"""Extract the original action level curve and its native Lua consumers."""

import argparse
import hashlib
import json
from pathlib import Path

from extract_native_safehouse_catalog import EXPECTED_PE, installed_export, source_structs
from inspect_department_tables import rows
from lua53_reader import Reader, listing, walk


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / 'outputs/df-local-server/protocol/native_action_level_catalog.json'
TABLES = {'action': (7084, 50371705, 'SeasonLevel', 489442048, 413285552, 5)}
EXPECTED_TABLE = '16389ea97f300742cd11bf3e346f5480ac94dbf9b7549865ea8a1a8c8505bac9'
LUA_PAK = 'pak-0-0-pakchunk1-WindowsClient.pak'
LUA = (
    ('GrowthRoadServer.lua', 6876, 34435072,
     '36197e4466335e0898c8d975e54939467ea8e54ebb357135f0f0025edb9f239f',
     {'0.15': (1, 33), '0.22': (1, 31)}),
    ('SeasonServer.lua', 6933, 35028992,
     '184deed9ba113a2ee24bb791541dd192e286c0d164204e71ef94bfb7a6de3520',
     {'0.8': (1, 21), '0.13': (1, 37)}),
    ('RoleInfoServer.lua', 6929, 34949120,
     'a6221ddd4f16c4c77be62be552b78eb275f06f9710aed57c3ec529e543eb7503',
     {'0.5': (37, 100), '0.13.0': (4, 119)}),
    ('SOLPathOfGrowthLevelUpPanel.lua', 5926, 28489728,
     '60f8545651ea4997c7cfe88d0ae72a969bcb5c1e5bdb4468325ba5b35e603355',
     {'0.1': (521, 539), '0.13': (1, 69)}),
    ('cs_account_pb.lua', 6649, 31827968,
     '9731dd75f9167e4edc22f6f22f85569822eb8a3ab232a0be72c4b931c87b6f8b',
     {'0': (22, 25)}),
    ('DFMGlobalConst.lua', 1882, 8687616,
     '4887a7f2b5265a5277c5c2553f4ff56ec08f1219a632220e3b2efa367baddcc4',
     {'0': (1, 1)}),
    ('common_editor_pb.lua', 6644, 31649792,
     '1248614d9907d1d8474efb58c3afffaf0bf0c93626b0865edf58e04fd5bd65d6',
     {'0.148': (1, 1000), '0.149': (1, 1000)}),
    ('cs_account_editor_pb.lua', 6648, 31813632,
     '9207df061e390303213bdf7a61f4a29e7301f1cc01b740238066f43c33fdb6aa',
     {'0.14': (1, 71), '0.15': (1, 62)}),
)


def validate_rows(recovered):
    if ([row['Level'] for row in recovered] != list(range(1, 61))
            or any(not row['Experience'].isascii() or not row['Experience'].isdecimal()
                   for row in recovered)
            or any(int(row['Experience']) <= 0 for row in recovered[:-1])
            or recovered[-1]['Experience'] != '0'
            or any(row[name] for row in recovered for name in ('LevelPrize', 'Unlock1', 'Unlock2'))):
        raise ValueError('Installed action level table no longer matches the verified complete curve')


def extract():
    native = source_structs(TABLES)['action']
    raw, source = installed_export(7084, 50371705)
    if source['sha256'] != EXPECTED_TABLE:
        raise ValueError('Original action level source hash changed')
    recovered, fields = rows(raw, native['columns'])
    validate_rows(recovered)
    consumers = {}
    for name, entry, offset, expected, selected in LUA:
        data, witness = installed_export(entry, offset, pak=LUA_PAK)
        if witness['sha256'] != expected:
            raise ValueError('Original action level consumer changed: ' + name)
        root = Reader(data, allow_client_format1=True).function()
        if root['source'] != '@' + name:
            raise ValueError('Original Lua identity differs: ' + name)
        functions = {fn['id']: fn for fn in walk(root)}
        witness['functions'] = {ident: {'serialized_offset': functions[ident]['offset'],
            'instructions': listing(functions[ident]).splitlines()[start - 1:end]}
            for ident, (start, end) in selected.items()}
        consumers[name] = witness
    return {
        'mapping_status': 'verified_by_native_reflection_and_serialization',
        'native_pe_sha256': EXPECTED_PE,
        'source': {**source, 'native': native, 'serialized_field_indices': fields},
        'levels': recovered,
        'role_exp_item_id': 26010000001,
        'notification_source': 0,
        'client_consumers': consumers,
        'experience_semantics': 'Experience is the cost from this level to the next. The terminal zero '
            'identifies the maximum. SeasonChangeInfo.exp and profile exp hold experience within the '
            'current level; total_exp and old_total_exp are separate cumulative fields.',
        'local_policy': [
            'Only action progression uses this curve; account, blast and fishing levels remain independent.',
            'A pre-existing saved action level with no action XP ledger starts an audited local baseline '
            'at that level floor only when a real reward is granted. This baseline is not earned XP.',
            'Newly tracked earned XP is separate from the existing players.xp receipt ledger.',
            'The caller owns the reward transaction and emits notifications only after commit.'
        ],
        'limitations': [
            'Original remote account initialization and experience reward evaluator are unavailable.',
            'The package header is encrypted. Binding uses complete native reflected field order and '
            'types, the unique complete serialized match, the native config name and original Lua consumers.',
            'The action curve does not prove a simultaneous account experience grant.',
            'The maximum level stops level advancement; this local ledger retains awarded XP without '
            'inventing an unsupported discard or experience cap.'
        ]
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    catalog = extract()
    serialized = json.dumps(catalog, ensure_ascii=True, indent=2) + '\n'
    if args.check:
        if OUTPUT.read_text(encoding='utf-8') != serialized:
            raise ValueError('Saved action level catalog differs from installed original source')
    else:
        OUTPUT.write_text(serialized, encoding='utf-8')
    print({'path': str(OUTPUT), 'levels': len(catalog['levels']),
           'source_sha256': catalog['source']['sha256'], 'checked': args.check})


if __name__ == '__main__':
    main()
