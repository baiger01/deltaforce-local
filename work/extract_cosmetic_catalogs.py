"""Recover cosmetic links and Mandel box records from local client exports."""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from explore_game_item import UASSET, UEXP, name_map
from explore_tagged_export import read_row
from extract_game_item_catalog import scalar
from extract_operator_avatar_catalog import tags


ROOT = Path(__file__).resolve().parent.parent
PROTOCOL = ROOT / 'outputs/df-local-server/protocol'
PAK = 'pak-0-0-pakchunk2-WindowsClient.pak'


def export(entry):
    source = ROOT / 'work/evidence/matched_assets' / f'{PAK}.entry-{entry}.bin'
    data = source.read_bytes()
    none_offset = 29 if struct.unpack_from('<i', data, 37)[0] == 0 else 55
    none, instance, prefix, count = struct.unpack_from('<iiii', data, none_offset)
    if instance or prefix:
        raise ValueError('Unexpected export root')
    rows, offset, kinds = [], none_offset + 16, {}
    for index in range(count):
        start = offset
        fields, offset, layout = read_row(data, offset + 8, none, known_types=kinds)
        kinds = dict(layout)
        values = {}
        for field in fields:
            raw = data[field['value_start']:field['end']]
            if field['size'] == 8 and field['metadata_bytes'] == 0:
                v = struct.unpack('<Q', raw)[0]
            elif field['size'] == 4 and field['metadata_bytes'] == 0:
                v = struct.unpack('<I', raw)[0]
            elif field['size'] == 0 and field['metadata_bytes'] == 1:
                v = bool(data[field['offset'] + 24])
            else:
                v = raw.hex()
            values[field['field']] = v
        rows.append({'row': index, 'offset': start, 'fields': values})
    if data[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError(f'Unparsed export {entry}')
    return rows, {'entry': entry, 'sha256': hashlib.sha256(data).hexdigest(),
                  'row_count': count, 'name_map_available': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--gun-skins-only', action='store_true')
    args = parser.parse_args()
    items = json.loads((PROTOCOL / 'game_item_catalog.json').read_text(encoding='utf-8'))['rows']
    skins, skin_source = export(7292)
    skin_rows = []
    for row in skins:
        f = row['fields']
        skin, weapon = f[1820], f[1792]
        # CollectionServer.lua 0.14 also treats subtype 15 as a firearm skin.
        if not str(skin).startswith(('280', '2815')) or str(skin) not in items:
            continue
        skin_rows.append({'skin_id': skin, 'weapon_id': weapon, 'preset_id': f[1794],
                          'open_collection': f[1812],
                          'is_mystical': str(skin)[4:6] == '00',
                          'name_key': items[str(skin)]['name_key'],
                          'row': row['row'], 'offset': row['offset']})
    if len({r['skin_id'] for r in skin_rows}) != len(skin_rows):
        raise ValueError('Duplicate skin')
    gun_report = {'source_pak': PAK, 'source': skin_source,
                  'serialized_field_indices': {'skin_id': 1820, 'weapon_id': 1792,
                                               'preset_id': 1794, 'open_collection': 1812},
                  'client_consumers': ['CollectionServer.lua 0.11.4',
                                       'ItemHelperTool.lua 0.40, 0.60'],
                  'local_policy': 'Provide client ordinary collection skins to the local test account; mystical instances come from draws',
                  'rows': skin_rows}
    (PROTOCOL / 'gun_skin_catalog.json').write_text(
        json.dumps(gun_report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if args.gun_skins_only:
        print('gun_skin_rows', len(skin_rows))
        return

    boxes, box_source = export(6764)
    groups, group_source = export(6766)
    rewards, reward_source = export(6768)
    stores, store_source = export(7152)
    keys, key_source = export(7134)
    data, names = UEXP.read_bytes(), name_map(UASSET.read_bytes())
    bricks = []
    for item_id, item in items.items():
        if not item_id.startswith('161100'):
            continue
        fields, _ = tags(data, item['serialized_uexp_offset'] + 8, names, len(data))
        values = {t['name']: scalar(data, t, names) for t in fields
                  if t['name'] in ('ConnectedPool', 'Name')}
        if values.get('ConnectedPool'):
            bricks.append({'item_id': int(item_id), 'box_id': values['ConnectedPool'],
                           'name_key': values['Name'], 'quality': item['quality'],
                           'offset': item['serialized_uexp_offset']})
    brick_ids = {r['item_id'] for r in bricks}
    store_rows = [{'lottery_id': r['fields'][106], 'lottery_type': r['fields'][112],
                   'item_id': r['fields'][114], 'key_id': r['fields'][108],
                   'row': r['row'], 'offset': r['offset']}
                  for r in stores if r['fields'][114] in brick_ids]
    key_rows = [{'present_item_id': r['fields'][19], 'currency_type': r['fields'][11],
                 'price': r['fields'][21], 'buy_item_id': r['fields'][9],
                 'present_num': r['fields'][20], 'row': r['row'], 'offset': r['offset']}
                for r in keys]
    report = {'source_pak': PAK,
              'sources': {'box': box_source, 'group': group_source,
                          'reward': reward_source, 'store': store_source, 'key': key_source,
                          'game_item_uexp_sha256': hashlib.sha256(data).hexdigest()},
              'client_consumers': ['StoreServer.lua 0.0, 0.126, 0.163, 0.169.0, 0.176',
                                   'RewardServer.lua 0.17, 0.17.0',
                                   'MandelDrawOnly.lua 0.5, 0.36',
                                   'StoreLotteryProbDistributionItem.lua 0.1, 0.2'],
              'limitations': 'Encrypted name maps and per-prize runtime weights are unavailable. Raw indices retained; local group-uniform draws and counter rules are diagnostic policy, not recovered official probabilities.',
              'bricks': bricks, 'store_lotteries': store_rows, 'key_offers': key_rows,
              'boxes': boxes, 'groups': groups, 'rewards': rewards}
    (PROTOCOL / 'mandel_box_catalog.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('gun_skin_rows', len(skin_rows), 'bricks', len(bricks), 'store_lotteries', len(store_rows))


if __name__ == '__main__':
    main()
