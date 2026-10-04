"""Recover battle-pass rows from read-only baseline PAK exports.

Field associations are rebuilt from independent original C++ property
registrations and checked against every serialized row. This supersedes
the earlier candidate mapping based on ordering and Lua consumers.
"""

import hashlib
import json
from pathlib import Path

from extract_cosmetic_catalogs import export, PAK, PROTOCOL
from verify_battle_pass_reflection_bindings import verify_bindings


TABLES = {'archives': 6358, 'bonuses': 6360, 'clues': 6362,
          'expr_cards': 6364, 'levels': 6368, 'packs': 6370, 'seasons': 6372}
REWARD_NAMES = {'free': ('FreeReward', 'FreeRewardNum', 3),
                'universal': ('UniversalReward', 'UniversalRewardNum', 2),
                'sol': ('SolReward', 'SolRewardNum', 2),
                'mp': ('MpReward', 'MpRewardNum', 2)}
SEASON_NAMES = {'season_id': 'ID', 'number': 'Number', 'level_expr': 'LevelExpr',
                'max_expr_limit': 'MaxExprLimit', 'week_expr_limit': 'WeekExprLimit',
                'cycle_start_level': 'CycleStartLevel', 'levels_per_cycle': 'LevelsPerCycle',
                'level_price': 'LevelPrice', 'sol_price': 'SolPrice', 'mp_price': 'MpPrice',
                'universal_price': 'UniversalPrice'}
PACK_NAMES = {'pack_id': 'ID', 'season_id': 'SeasonID', 'level': 'Level',
              'price': 'Price', 'original_price': 'OriginalPrice'}


def main():
    verification = verify_bindings()
    status = 'verified_by_native_reflection_and_serialization'
    if verification['binding_status'] != status or set(verification['tables']) != set(TABLES):
        raise ValueError('Complete current-original native field verification is required')
    bindings = {group: {field['name']: field['field_index'] for field in table['bindings']}
                for group, table in verification['tables'].items()}
    season_fields = {name: bindings['seasons'][native] for name, native in SEASON_NAMES.items()}
    pack_fields = {name: bindings['packs'][native] for name, native in PACK_NAMES.items()}
    level_fields = {name: bindings['levels'][native] for name, native in
                    {'row_id': 'ID', 'season_id': 'SeasonID', 'level': 'Level'}.items()}
    reward_fields = {tier: [(bindings['levels'][item + str(slot)],
                            bindings['levels'][count + str(slot)]) for slot in range(1, slots + 1)]
                     for tier, (item, count, slots) in REWARD_NAMES.items()}
    raw, sources = {}, {}
    for name, entry in TABLES.items():
        raw[name], sources[name] = export(entry)
        verified = verification['tables'][name]
        if entry != verified['entry'] or sources[name]['sha256'] != verified['export_sha256']:
            raise ValueError(f'{name}: extraction source differs from the verified current original')
    seasons = [{**{name: row['fields'][index] for name, index in season_fields.items()},
                'row': row['row'], 'offset': row['offset']} for row in raw['seasons']]
    levels = []
    for row in raw['levels']:
        fields = row['fields']
        rewards = {tier: [{'id': fields[item], 'num': fields[count], 'slot': slot}
                         for slot, (item, count) in enumerate(pairs, 1)
                         if fields[item] and fields[count] > 0]
                   for tier, pairs in reward_fields.items()}
        levels.append({**{name: fields[index] for name, index in level_fields.items()},
            'rewards': rewards,
            'row': row['row'], 'offset': row['offset']})
    packs = [{**{name: row['fields'][index] for name, index in pack_fields.items()},
              'row': row['row'], 'offset': row['offset']} for row in raw['packs']]
    latest = max(row['season_id'] for row in levels)
    active = sorted(row['level'] for row in levels if row['season_id'] == latest)
    if active != list(range(1, 181)) or latest not in {r['season_id'] for r in seasons}:
        raise ValueError('Expected matching installed season and 180 complete reward levels')
    report = {'source_pak': PAK, 'sources': sources,
        'mapping_status': status,
        'mutations_enabled': True, 'latest_installed_season_id': latest,
        'serialized_field_indices': {'seasons': season_fields, 'packs': pack_fields,
            'levels': {**level_fields, 'rewards': reward_fields}},
        'native_field_verification': {
            'reproduce': 'DF_LOCAL_SOURCE_GAME=<original game> python work/verify_battle_pass_reflection_bindings.py',
            'verifier_sha256': hashlib.sha256(Path(__file__).with_name(
                'verify_battle_pass_reflection_bindings.py').read_bytes()).hexdigest(),
            'pe_sha256': verification['pe_sha256'],
            'native_executable': verification['native_executable'],
            'scope': verification['scope'],
            'supersedes': 'inferred_from_serialization_order_and_client_consumers',
            'tables': {group: {key: value for key, value in table.items()
                if key not in ('all_rows', 'kind_indices', 'native_gen_flags')}
                for group, table in verification['tables'].items()}},
        'client_consumers': ['BattlePassServer.lua 0.8, 0.22, 0.24-0.32, 0.35-0.90',
            'BattlePassUnlock.lua 0.25, 0.27', 'BattlePassBuyLevel.lua 0.15.0, 0.17-0.18, 0.29, 0.31'],
        'pack_purchase_semantics': {
            'level': 'increment', 'membership': 'unchanged', 'repeat_purchase': 'rejected',
            'consumer_evidence': ['BattlePassServer.lua 0.28 @29154 writes only pack_id and coin amounts',
                'BattlePassBuyLevel.lua 0.31 @21979 summarizes current pay type rewards from current+1 to current+pack.level',
                'BattlePassServer.lua 0.90 @52338 caps eligibility at maxLevel-pack.level']},
        'verified_protocol_sources': ['pakchunk1 entry 6662 cs_battlepass_editor_pb.lua',
                                     'pakchunk1 entry 6663 cs_battlepass_pb.lua'],
        'consumer_sources': {name: hashlib.sha256((Path(__file__).resolve().parent /
            'evidence/weapon_lua' / name).read_bytes()).hexdigest() for name in (
                'BattlePassServer.lua', 'BattlePassUnlock.lua', 'BattlePassBuyLevel.lua',
                'cs_battlepass_editor_pb.lua', 'cs_battlepass_pb.lua')},
        'limitations': ['Encrypted package name maps remain unreadable; derived field names are independently bound through native reflection and serialization.',
            'The terminal inherited FName field is a constant None default, remains unnamed, and is not used in transactions.',
            'The latest installed season is not a verified official live season or schedule.',
            'Original membership and level price discounts are not recovered; the local display quotes are undiscounted.',
            'Baseline archives are for 202401 only; no archives are claimed for the selected season.',
            'Experience-card row names are encrypted; card IDs are not inferred from experience values.'],
        'seasons': seasons, 'levels': levels, 'packs': packs, 'raw_tables': raw}
    output = PROTOCOL / 'battle_pass_catalog.json'
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print({'latest_installed_season_id': latest, 'levels': len(active),
           'mapping_status': report['mapping_status'], 'mutations_enabled': report['mutations_enabled']})


if __name__ == '__main__':
    main()
