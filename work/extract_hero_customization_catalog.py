"""Recover native Hero cosmetic rows from independently captured clear exports.

Encrypted package name maps are not replaced with guessed names. Numeric FName
blocks are resolved against the clear Hero descriptions, GameItem names, and
original shop reward bundles. Ambiguous primary IDs remain in the report.
"""

import hashlib
import json
from pathlib import Path
import re
import struct

from explore_tagged_export import read_row
from extract_operator_avatar_catalog import name_map


ROOT = Path(__file__).resolve().parent.parent
PROTOCOL = ROOT / 'outputs/df-local-server/protocol'
EVIDENCE = ROOT / 'work/hero_custom_scan/evidence/matched_assets'
PAK = 'pak-0-0-pakchunk2-WindowsClient.pak'


def export(entry):
    source = next((EVIDENCE / f'{PAK}.entry-{entry}{suffix}'
                   for suffix in ('.bin', '.uexp')
                   if (EVIDENCE / f'{PAK}.entry-{entry}{suffix}').exists()))
    data = source.read_bytes()
    root = 29 if struct.unpack_from('<i', data, 37)[0] == 0 else 55
    none, instance, prefix, count = struct.unpack_from('<iiii', data, root)
    if instance or prefix:
        raise ValueError(f'Unexpected table root {entry}')
    offset, rows, kinds = root + 16, [], {}
    for index in range(count):
        start = offset
        fields, offset, layout = read_row(data, offset + 8, none, known_types=kinds)
        kinds = dict(layout)
        decoded = {}
        for field in fields:
            raw = data[field['value_start']:field['end']]
            decoded[field['field']] = {
                'raw': raw, 'meta': field['metadata_bytes'], 'size': field['size'],
                'bool': bool(data[field['offset'] + 24]) if field['metadata_bytes'] == 1 else None}
        rows.append({'row': index, 'offset': start, 'fields': decoded})
    if data[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError(f'Unparsed table {entry}')
    return rows, {'pak': PAK, 'entry': entry, 'sha256': hashlib.sha256(data).hexdigest(),
                  'row_count': count, 'name_map_available': False}


def raw(row, field):
    return row['fields'][field]['raw']


def text_id(row, field):
    match = re.search(rb'(?:300|380|381|880)[0-9]{8}', raw(row, field))
    return int(match.group()) if match else None


def fstring(row, field):
    data = raw(row, field)
    size = struct.unpack_from('<i', data)[0]
    if size <= 0 or size + 4 != len(data) or data[-1:] != b'\0':
        raise ValueError('Invalid FString ID')
    return int(data[4:-1])


def fnames(row, field):
    data = raw(row, field)
    count = struct.unpack_from('<i', data)[0]
    if len(data) != 4 + count * 8:
        raise ValueError('Unexpected FName array')
    result = []
    for offset in range(4, len(data), 8):
        name, instance = struct.unpack_from('<ii', data, offset)
        if instance:
            raise ValueError('Numeric relation has an FName instance')
        result.append(name)
    return result


def primary_fnames(rows, field, label_field, items, prefix):
    """Only emit IDs shared by every ordered matching of primary FNames."""
    ordered = sorted(rows, key=lambda r: struct.unpack('<ii', raw(r, field)))
    candidates = sorted({int(i) for i in items if i.startswith(prefix)} |
                        {text_id(r, label_field) for r in rows if text_id(r, label_field)})
    labels = [text_id(r, label_field) for r in ordered]
    def matches(i, j):
        item_id = candidates[j]
        key = items.get(str(item_id), {}).get('name_key') or ''
        # Shared localized labels are aliases, so they cannot anchor a primary ID.
        return labels[i] is None or labels.count(labels[i]) > 1 or labels[i] == item_id or key.split('_')[0] == str(labels[i])
    n, m = len(rows), len(candidates)
    prefix_dp = [[False] * (m + 1) for _ in range(n + 1)]
    prefix_dp[0] = [True] * (m + 1)
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            prefix_dp[i][j] = prefix_dp[i][j - 1] or (prefix_dp[i - 1][j - 1] and matches(i - 1, j - 1))
    suffix_dp = [[False] * (m + 1) for _ in range(n + 1)]
    suffix_dp[n] = [True] * (m + 1)
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            suffix_dp[i][j] = suffix_dp[i][j + 1] or (matches(i, j) and suffix_dp[i + 1][j + 1])
    result, unresolved = {}, []
    if not prefix_dp[n][m]:
        raise ValueError(f'No evidence-consistent primary ID mapping for {prefix}')
    for i, row in enumerate(ordered):
        possible = [candidates[j] for j in range(m) if matches(i, j)
                    and prefix_dp[i][j] and suffix_dp[i + 1][j + 1]]
        if len(possible) == 1:
            result[row['row']] = possible[0]
        else:
            unresolved.append({'row': row['row'], 'offset': row['offset'],
                               'primary_fname': struct.unpack('<ii', raw(row, field))[0],
                               'candidate_ids': possible})
    return result, unresolved


def main():
    items = json.loads((PROTOCOL / 'game_item_catalog.json').read_text(encoding='utf-8'))['rows']
    shop = json.loads((PROTOCOL / 'premium_shop_catalog.json').read_text(encoding='utf-8'))
    sources, tables = {}, {}
    specifications = {
        'CharacterAnimShowData': (6614, 3, 352, 354, 356, 366, 365, 'fname'),
        'HeroBadgeData': (6620, 8, 691, 694, 695, 705, 704, 'string'),
        'HeroCardData': (6624, 1, 1085, 1077, 879, 1088, 1087, 'fname'),
        'HeroDFWatchData': (6630, 7, 58, 61, 50, 67, 66, 'string'),
        'HeroExecutionData': (6632, 6, 58, 61, 51, 66, 65, 'string'),
        'HeroGestureData': (6636, 4, 164, 167, 157, 172, 171, 'string'),
        'HeroLinesData': (6648, 5, 682, 685, 670, 680, 679, 'string'),
        'HeroSprayPaintData': (6660, 2, 2195, 2198, 2173, 2183, 2182, 'string'),
        'HeroTitleData': (6662, 9, 16, 18, 8, 21, 20, 'string')}
    for name, spec in specifications.items():
        tables[name], sources[name] = export(spec[0])
        sources[name]['serialized_field_indices'] = dict(zip(
            ('id', 'label', 'belonged_heroes', 'default_unlock', 'default_equip'), spec[2:7]))
        sources[name]['field_label_status'] = 'Semantic roles recovered from property shape, localized keys, native helper consumers and numeric FName blocks; original encrypted field-name map unavailable.'
    fashion_rows, sources['HeroFashionData'] = export(6634)
    intro, sources['hero_description_entry_6650'] = export(6650)
    hero_data, sources['HeroData'] = export(6628)
    released_heroes = sorted(struct.unpack('<Q', raw(r, 116))[0] for r in intro)
    fashion_heroes = sorted({struct.unpack('<Q', raw(r, 333))[0] for r in fashion_rows} - {88000000033})
    # HeroData's named localized primary IDs independently verify the numeric
    # FName block's ordering for all released heroes and all fashion heroes.
    hero_anchor = sorted((struct.unpack('<ii', raw(r, 356))[0], text_id(r, 365))
                         for r in hero_data if text_id(r, 365) in fashion_heroes)
    if [h for _, h in hero_anchor] != fashion_heroes:
        raise ValueError('Hero numeric FName ordering did not match clear Hero IDs')
    maps = {
        'CharacterAnimShowData': {224: 0, **dict(zip(range(335, 352), released_heroes))},
        'HeroCardData': {546: 0, **dict(zip(range(855, 878), fashion_heroes))},
        'HeroLinesData': dict(zip(range(645, 668), fashion_heroes)),
        'HeroGestureData': {94: 0, **dict(zip(range(139, 156), released_heroes))},
        'HeroSprayPaintData': {1449: 0, **dict(zip(range(2155, 2172), released_heroes))},
        'HeroBadgeData': {457: 0}, 'HeroTitleData': {5: 0}}
    fashion_links = {r['fashion_id']: r['hero_id'] for r in shop['fashion_links']}
    reward_heroes, reward_fashions = {}, {}
    for lottery in shop['lotteries']:
        ids = [p['id'] for r in shop['lottery_rewards'] if r['lottery_id'] == lottery['lottery_id'] for p in r['props']]
        heroes = {fashion_links[i] for i in ids if i in fashion_links}
        if len(heroes) == 1:
            reward_heroes.update({i: next(iter(heroes)) for i in ids if str(i).startswith(('3806', '3807'))})
            fashion_ids = {i for i in ids if i in fashion_links}
            if len(fashion_ids) == 1:
                reward_fashions.update({i: next(iter(fashion_ids)) for i in ids if str(i).startswith('3806')})
    watch_map = {28: 0}
    execution_map = {24: 0}
    for name, mapping, prop_field, hero_field in [('HeroDFWatchData', watch_map, 58, 50),
                                                ('HeroExecutionData', execution_map, 58, 51)]:
        for row in tables[name]:
            item_id = fstring(row, prop_field)
            if item_id in reward_heroes:
                key, = fnames(row, hero_field)
                expected = reward_heroes[item_id]
                if key in mapping and mapping[key] != expected:
                    raise ValueError('Conflicting source reward and accessory relation')
                mapping[key] = expected
    # The remaining watch's numeric FName lies strictly between the independently
    # anchored hero 26 and hero 28; HeroData contains only hero 27 in that interval.
    if watch_map.get(42) != 88000000026 or watch_map.get(44) != 88000000028:
        raise ValueError('Missing watch relation anchors')
    watch_map[43] = 88000000027
    maps['HeroDFWatchData'], maps['HeroExecutionData'] = watch_map, execution_map
    execution_fashion_map = {24: 0}
    for row in tables['HeroExecutionData']:
        item_id = fstring(row, 58)
        if item_id in reward_fashions:
            index, = fnames(row, 50)
            if index in execution_fashion_map and execution_fashion_map[index] != reward_fashions[item_id]:
                raise ValueError('Conflicting execution fashion relation')
            execution_fashion_map[index] = reward_fashions[item_id]
    accessories, unresolved = [], {}
    for name, spec in specifications.items():
        entry, subtype, id_field, label_field, hero_field, unlock_field, equip_field, kind = spec
        primary, unknown = primary_fnames(tables[name], id_field, label_field, items, f'38{subtype:02}') if kind == 'fname' else ({r['row']: fstring(r, id_field) for r in tables[name]}, [])
        unresolved[name] = unknown
        for row in tables[name]:
            if row['row'] not in primary:
                continue
            ids = fnames(row, hero_field)
            if any(i not in maps[name] for i in ids):
                raise ValueError(f'Unresolved hero relation {name} {ids}')
            item_id = primary[row['row']]
            if item_id // 10000000 % 100 != subtype:
                raise ValueError('Accessory subtype disagrees with original enum')
            accessory = {'id': item_id, 'subtype': subtype,
                'hero_ids': [maps[name][i] for i in ids], 'hero_fnames': ids,
                'default_unlock': row['fields'][unlock_field]['bool'],
                'default_equip': row['fields'][equip_field]['bool'],
                'name_key': items.get(str(item_id), {}).get('name_key'),
                'source_table': name, 'row': row['row'], 'offset': row['offset']}
            if name == 'HeroExecutionData':
                accessory['fashion_fnames'] = fnames(row, 50)
                accessory['fashion_ids'] = [execution_fashion_map[i] for i in accessory['fashion_fnames']]
            accessories.append(accessory)
    # Resolve the primary Fashion FName using explicit FashionMallData links and
    # matching hero + localized name, including aliased names for recolors.
    fashions = []
    for item_id, hero_id in fashion_links.items():
        key_id = int((items.get(str(item_id), {}).get('name_key') or str(item_id)).split('_')[0])
        default = item_id < 30000040000
        matches = [r for r in fashion_rows if struct.unpack('<Q', raw(r, 333))[0] == hero_id
                   and bool(r['fields'][354]['bool']) == default
                   and (default or text_id(r, 357) in (item_id, key_id))]
        if len(matches) != 1:
            # Disambiguate variants via their order in the numeric primary block.
            nondefault = sorted([r for r in fashion_rows if struct.unpack('<Q', raw(r, 333))[0] == hero_id
                                 and not r['fields'][354]['bool']], key=lambda r: struct.unpack('<ii', raw(r, 344)))
            related = sorted(i for i, h in fashion_links.items() if h == hero_id and i >= 30000040000)
            if item_id in related and len(nondefault) == len(related):
                matches = [nondefault[related.index(item_id)]]
        if len(matches) != 1:
            raise ValueError(f'Ambiguous FashionMall relation {item_id}')
        row = matches[0]
        fashions.append({'id': item_id, 'hero_id': hero_id, 'slot': 0,
            'default_unlock': row['fields'][354]['bool'], 'default_equip': row['fields'][353]['bool'],
            'primary_fname': struct.unpack('<ii', raw(row, 344))[0],
            'name_key': items.get(str(item_id), {}).get('name_key'), 'source_table': 'HeroFashionData',
            'row': row['row'], 'offset': row['offset']})
    order_evidence = []
    for source in (ROOT / 'work/evidence').rglob('*.uasset'):
        payload = source.read_bytes()
        names = name_map(payload)
        numeric = [name for name in names if name.isdigit()]
        if numeric != sorted(numeric):
            raise ValueError(f'Numeric FName order differs: {source}')
        order_evidence.append({'file': str(source.relative_to(ROOT)),
            'sha256': hashlib.sha256(payload).hexdigest(), 'numeric_name_count': len(numeric),
            'numeric_names_lexical_order': True})
    by_id = {row['id']: row for row in accessories}
    groups = []
    for kind in ('recommendations', 'gifts'):
        for row in shop[kind]:
            ids = [prop['id'] for item in row['bundle_item_list'] for prop in item.get('item_list', [item])]
            groups.append((kind, row, ids))
    for lottery in shop['lotteries']:
        ids = [p['id'] for row in shop['lottery_rewards'] if row['lottery_id'] == lottery['lottery_id']
               for p in row['props']]
        groups.append(('lotteries', lottery, ids))
    anchors = {}
    for kind, source_row, ids in groups:
        heroes = {fashion_links[i] for i in ids if i in fashion_links}
        if len(heroes) != 1:
            continue
        hero_id = next(iter(heroes))
        for item_id in ids:
            accessory = by_id.get(item_id)
            if not accessory or 0 in accessory['hero_ids']:
                continue
            table = accessory['source_table']
            for name_index in accessory['hero_fnames']:
                if maps[table][name_index] != hero_id:
                    raise ValueError(f'Independent bundle contradicts {table} FName {name_index}')
                witness = {'hero_id': hero_id, 'item_id': item_id, 'source_catalog': kind,
                    'source_entry': shop['sources'][kind]['entry'], 'source_row': source_row['row'],
                    'source_offset': source_row['offset']}
                anchors.setdefault(table, {}).setdefault(str(name_index), []).append(witness)
    for row in accessories:
        confirmed = anchors.get(row['source_table'], {})
        row['hero_relation_resolution'] = ('independent_bundle_anchor' if row['hero_fnames']
            and all(str(i) in confirmed for i in row['hero_fnames']) else 'numeric_fname_order_reconstruction')
    report = {'scope': 'Native configured Hero cosmetics; ownership comes from account collection grants.',
        'sources': sources, 'fashion_links_source': shop['sources']['fashion_links'],
        'reward_relation_source': shop['sources']['lottery_rewards'],
        'game_item_sha256': hashlib.sha256((PROTOCOL / 'game_item_catalog.json').read_bytes()).hexdigest(),
        'fname_resolution': 'Numeric FName blocks cross-checked against clear HeroData localized IDs, HeroIntroduction UInt64 IDs, GameItem primary/name keys, and original skin/accessory reward bundles. Ambiguous primary IDs are retained under unresolved_primary_ids.',
        'fname_order_evidence': order_evidence,
        'hero_data_fname_anchors': [{'fname': index, 'hero_id': hero_id} for index, hero_id in hero_anchor],
        'independent_hero_relation_anchors': anchors,
        'limitations': 'Encrypted Hero package name maps were not decrypted. Relations labelled numeric_fname_order_reconstruction depend on this installation\'s independently observed lexical numeric FName ordering and exact contiguous relation ranges; independently anchored relations are labelled separately. No named HeroKillLineData export was recovered, so subtype10 is not emitted. SoldierProp skill equipment is outside this cosmetic catalog. Entry6650 has explicit UInt64 Hero IDs and localized birthday/height/weight fields; its original table name is unresolved.',
        'hero_fname_maps': maps, 'unresolved_primary_ids': unresolved,
        'execution_fashion_fname_map': execution_fashion_map,
        'client_consumers': {'fashion': 'HeroLogic.lua 0.27 lines444-493; HeroServer.lua 0.18.0 lines533-569',
            'accessories': 'HeroServer.lua 0.18.0 lines533-569; HeroLogic.lua 0.20 lines348-378',
            'watch': 'HeroWatchMainPanel.lua 0.2 lines101-110',
            'default': 'HeroHelperTool.lua 0.89; HeroLogic.lua 0.37'},
        'enums': {'EHeroAccessroy': {'Card': 1, 'SparyPaint': 2, 'AnimShow': 3, 'Gesture': 4,
            'Lines': 5, 'Execution': 6, 'Watch': 7, 'Badge': 8, 'Title': 9, 'KillaLines': 10, 'SoldierProp': 11},
            'eHeroFashionPosition': {'FashionSuit': 0, 'FashionHead': 1, 'FashionBag': 9}},
        'enum_sources': {'EHeroAccessroy': {'entry': 1882, 'file': '@DFMGlobalConst.lua',
            'sha256': '4887a7f2b5265a5277c5c2553f4ff56ec08f1219a632220e3b2efa367baddcc4', 'root_pcs': [1368, 1392]},
            'eHeroFashionPosition': {'entry': 6801, 'file': '@ds_common_pb.lua',
            'sha256': '6f1bec3a236dbd47c28d932a2702bc8cc386ecb6119312d71d57a62d6e8b8f6b', 'root_pcs': [535, 543]}},
        'fashions': sorted(fashions, key=lambda r: r['id']),
        'accessories': sorted(accessories, key=lambda r: r['id'])}
    target = PROTOCOL / 'hero_customization_catalog.json'
    target.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print('fashions', len(fashions), 'accessories', len(accessories),
          'unresolved', {k: len(v) for k, v in unresolved.items()})


if __name__ == '__main__':
    main()
