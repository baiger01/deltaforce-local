"""Generate source associations for direct premium bundle reward resources.

The preserved WeaponSkinDataTable export is a data input, not a shipped Python
dependency. No directories are inferred for its bare C= filenames. Exact avatar
row IDs follow the recorded client argument contract; loading, rendering and
package ownership are not established by these references.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from explore_tagged_export import read_row
from extract_operator_avatar_catalog import fname, name_map, tags, view
from local_game_paths import game_paths, project_path


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / 'outputs/df-local-server/protocol'
PAK = 'pak-0-0-pakchunk2-WindowsClient.pak'
GUN_SOURCE = (7292, '03929c8c36ef4bd21de0e6262809095a863f3e65d6e44e8eefcf6ac57a59cce7', 1781)
AVATAR_HEADER_SHA = 'fd3dea4bda6dbb41cf354e9cbf7b527c53e1e8b0081bbb0c5dafdf8460a1e496'
AVATAR_BODY_SHA = '336a7c5af693b6190e630e5360367a8129b3a426fdfc95319b2cbfbeda38e6b3'
BUNDLE_SOURCES = {
    'recommendations': (7142, 'bcf064ebee25d046e21712375adf8e68f80b71bedd9c5c65f1fcb6a6d771a1fc', 158),
    'gifts': (7156, '1b7640b1121e61e9fef64a8f986f5620588fb1e9a70822f8feae9898056b68d7', 61),
}
AVATAR_CONSUMER = {
    'source_pak_identity': 'Original PAK1',
    'entry_header_offset': 15683584,
    'lua_source': '@CharacterCaptureUtil.lua',
    'lua_payload_sha256': 'db1259fcaea601cc57d027cc8651f34709059efc11f867a63cc47defd7efdac6',
    'lua_payload_length': 26550,
    'functions': [
        {'function': '0.28', 'name': '_InitCharacterAvatar', 'function_offset': 18133,
         'source_lines': [501, 555], 'instruction_pcs': [19, 29],
         'contract': 'WarehouseMain and IsShowFashion: tostring(GetCurUsedHeroFashionId()) is passed to SetAvatarByFString'},
        {'function': '0.33', 'name': '_GetAvatarIDFromAppearanceFPP', 'function_offset': 22485,
         'source_lines': [635, 659],
         'contract': 'When IsShowFashion, GetCurrentFashionSuitId() supplies the returned avatar ID used by 0.28 SetAvatar'},
        {'function': '0.30', 'name': '_CheckAvatarIDValid', 'function_offset': 20364,
         'source_lines': [566, 578],
         'contract': 'CharacterAvatarData[tostring(avatar ID)] is checked for UI.CoreParts'},
    ],
    'verification_scope': 'Original client Lua argument and table-key contract, not a runtime rendering test',
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    data = path.read_bytes()
    return json.loads(data), {'file': path.name, 'sha256': digest(data)}


def fstring(raw):
    if len(raw) < 4:
        raise ValueError('Truncated source FString')
    count = struct.unpack_from('<i', raw)[0]
    width = 2 if count < 0 else 1
    if len(raw) != 4 + abs(count) * width:
        raise ValueError('Source FString length mismatch')
    if not count:
        return ''
    if raw[-width:] != bytes(width):
        raise ValueError('Source FString terminator mismatch')
    return raw[4:-width].decode('utf-16-le' if count < 0 else 'utf-8')


def gun_resources(path, catalog):
    data = path.read_bytes()
    source = catalog['source']
    if (source['entry'], source['sha256'], source['row_count']) != GUN_SOURCE:
        raise ValueError('Gun skin catalog source differs from the captured export version')
    if digest(data) != source['sha256']:
        raise ValueError('WeaponSkinDataTable export SHA256 mismatch')
    root = 29 if struct.unpack_from('<i', data, 37)[0] == 0 else 55
    none, instance, prefix, count = struct.unpack_from('<iiii', data, root)
    if instance or prefix or count != source['row_count']:
        raise ValueError('Unexpected WeaponSkinDataTable export root')
    published = {row['skin_id']: row for row in catalog['rows']}
    if len(published) != count:
        raise ValueError('Gun skin catalog has missing or duplicate source rows')
    result, offset, kinds = {}, root + 16, {}
    for index in range(count):
        start = offset
        fields, offset, layout = read_row(data, start + 8, none, known_types=kinds)
        kinds = dict(layout)
        by_field = {field['field']: field for field in fields}
        if len(by_field) != len(fields):
            raise ValueError('Duplicate serialized gun skin field')
        values = {}
        for key in (1820, 1792, 1794):
            field = by_field[key]
            values[key] = struct.unpack('<Q', data[field['value_start']:field['end']])[0]
        skin = values[1820]
        row = published[skin]
        if (row['row'], row['offset'], row['weapon_id'], row['preset_id']) != (
                index, start, values[1792], values[1794]):
            raise ValueError(f'Gun skin catalog mapping differs at source row {index}')
        strings = []
        for key in (1808, 1823):
            field = by_field[key]
            if field['kind'] != 1826 or field['metadata_bytes'] != 0:
                raise ValueError(f'Unexpected serialized FString type for field {key}')
            text = fstring(data[field['value_start']:field['end']])
            strings.append({'source_field_index': key, 'value_offset': field['value_start'],
                            'source_status': 'nonempty_in_source' if text else 'empty_in_source',
                            'value': text})
        if skin in result:
            raise ValueError('Duplicate WeaponSkinDataTable skin ID')
        result[skin] = {'row': index, 'row_offset': start,
                       'row_sha256': digest(data[start:offset]),
                       'weapon_id': values[1792], 'preset_id': values[1794],
                       'serialized_fstring_fields': strings}
    if data[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Unparsed WeaponSkinDataTable trailing bytes')
    return result


def avatar_views(catalog, ids, header=None, body=None):
    if (catalog['source_uasset_sha256'], catalog['source_uexp_sha256']) != (
            AVATAR_HEADER_SHA, AVATAR_BODY_SHA):
        raise ValueError('CharacterAvatarData catalog source differs from captured version')
    if bool(header) != bool(body):
        raise ValueError('Provide both --avatar-header and --avatar-body')
    if not header:
        return 'published_catalog_source_metadata'
    header_data, data = header.read_bytes(), body.read_bytes()
    if digest(header_data) != AVATAR_HEADER_SHA or digest(data) != AVATAR_BODY_SHA:
        raise ValueError('CharacterAvatarData preserved export SHA256 mismatch')
    names = name_map(header_data)
    for item_id in ids:
        row = catalog['rows'].get(str(item_id))
        if row is None:
            continue
        offset = row['serialized_uexp_offset']
        if fname(data, offset, names) != str(item_id):
            raise ValueError('CharacterAvatarData source row name mismatch')
        children, _ = tags(data, offset + 8, names, len(data))
        fields = {tag['name']: tag for tag in children}
        actual = {key: view(data, fields[key], names) for key in ('UI', 'TPP', 'FPP') if key in fields}
        if actual != row['views']:
            raise ValueError(f'CharacterAvatarData view references differ for {item_id}')
    return 'sha256_and_selected_tagged_rows_match'


def mesh_paths(views):
    for config in views.values():
        if config['master_mesh'] not in (None, 'None'):
            yield config['master_mesh']
        for key in ('core_parts', 'extra_parts'):
            for part in config[key]:
                if part.get('mesh_path') not in (None, 'None'):
                    yield part['mesh_path']


def build(shop, guns, avatars, items, melee, gun_rows, avatar_status):
    for table, expected in BUNDLE_SOURCES.items():
        source = shop['sources'][table]
        if (source['entry'], source['sha256'], source['row_count']) != expected:
            raise ValueError(f'Unexpected published {table} source metadata')
        if len(shop[table]) != expected[2]:
            raise ValueError(f'Incomplete {table} source catalog')
    fashions = {row['fashion_id']: row for row in shop['fashion_links']}
    melee_rows = {row['skin_id']: row for row in melee['rows']}
    entries, unique_rewards, unique_guns, unique_fashions = [], set(), set(), set()
    icon_ids, missing_item_ids, basename_rows, all_mesh_paths = set(), set(), {}, set()
    avatar_bundle_ids, basename_bundle_ids = set(), set()
    for table in BUNDLE_SOURCES:
        for bundle in shop[table]:
            id_key = 'tab_id' if table == 'recommendations' else 'goods_id'
            entry = {'table': table, id_key: bundle[id_key], 'row': bundle['row'],
                     'row_offset': bundle['offset'], 'rewards': []}
            for group_index, group in enumerate(bundle['bundle_item_list']):
                for item_index, prize in enumerate(group.get('item_list', [group])):
                    item_id = prize['id']
                    unique_rewards.add(item_id)
                    reward = {'id': item_id, 'num': prize['num'],
                              'source_bundle_group_index': group_index,
                              'source_group_item_index': item_index,
                              'native_resource_loading_and_rendering_verified': False}
                    game_item = items['rows'].get(str(item_id))
                    if game_item:
                        icon = game_item['mall_item_icon']
                        reward['game_item_resource'] = {
                            'source_row_name': str(item_id),
                            'row_offset': game_item['serialized_uexp_offset'],
                            'source_field': 'MallItemIcon', 'value': icon,
                            'source_status': 'nonempty_in_source' if icon else 'empty_in_source',
                            'cooked_package_owner_status': 'unresolved' if icon else 'not_applicable'}
                        if icon:
                            icon_ids.add(item_id)
                    else:
                        missing_item_ids.add(item_id)
                        reward['game_item_resource'] = {'source_status': 'missing_from_captured_GameItem_table'}
                    if item_id in gun_rows:
                        unique_guns.add(item_id)
                        row = gun_rows[item_id]
                        reward['weapon_skin_source'] = row
                        refs = []
                        for field in row['serialized_fstring_fields']:
                            if not field['value']:
                                continue
                            key = field['source_field_index']
                            ref = dict(field, role=f'unclassified_field_{key}',
                                       native_field_role_verified=False,
                                       native_resource_binding_verified=False)
                            if key == 1823:
                                ref.update(reference_form='bare_source_filename',
                                           directory_path_status='unknown_not_serialized_in_this_field')
                                basename_rows[item_id] = field['value']
                                basename_bundle_ids.add((table, bundle[id_key]))
                            else:
                                ref.update(reference_form='original_source_string',
                                           cooked_package_owner_status='unresolved')
                            refs.append(ref)
                        reward['weapon_skin_resource_references'] = refs
                        reward['weapon_model_path_status'] = 'not_recovered_from_serialized_FString_fields'
                    if item_id in melee_rows:
                        row = melee_rows[item_id]
                        reward['melee_skin_source'] = {
                            'row': row['serialized_row_index'], 'row_offset': row['serialized_uexp_offset'],
                            'skin_field_index': melee['serialized_skin_field_index'],
                            'weapon_field_index': melee['serialized_weapon_field_index'],
                            'weapon_id': row['weapon_id'], 'model_path_status': 'not_recovered_in_published_catalog'}
                    if item_id in fashions:
                        link = fashions[item_id]
                        reward['fashion_link_source'] = {'row': link['row'], 'row_offset': link['offset'],
                            'fashion_field_index': 112, 'hero_field_index': 113, 'hero_id': link['hero_id']}
                        avatar = avatars['rows'].get(str(item_id))
                        if avatar:
                            unique_fashions.add(item_id)
                            avatar_bundle_ids.add((table, bundle[id_key]))
                            all_mesh_paths.update(mesh_paths(avatar['views']))
                            reward['related_character_avatar_source'] = {
                                'source_row_name': str(item_id),
                                'row_offset': avatar['serialized_uexp_offset'],
                                'association_basis': 'Exact reward item ID equals captured CharacterAvatarData row name',
                                'source_verification_status': avatar_status,
                                'native_fashion_id_used_as_avatar_id_verified': True,
                                'native_binding_source': 'character_avatar_consumer_contract',
                                'cooked_mesh_package_ownership_verified': False,
                                'views': avatar['views']}
                        else:
                            reward['related_character_avatar_source'] = {'source_status': 'no_exact_row_ID_match'}
                    entry['rewards'].append(reward)
            entry['reward_resource_status'] = ('direct_rewards_recorded' if entry['rewards'] else
                                                'no_direct_rewards_in_source')
            entries.append(entry)
    return {'schema_version': 1, 'scope': 'Direct source bundle_item_list rewards in all captured recommendations and gifts',
        'native_reward_resource_loading_and_rendering_verified': False,
        'sources': {
            'bundle_tables': {name: shop['sources'][name] for name in BUNDLE_SOURCES},
            'weapon_skin': dict(guns['source'], source_pak=guns['source_pak'],
                raw_payload_verification_status='sha256_and_all_tagged_rows_match',
                serialized_field_indices=guns['serialized_field_indices'],
                serialized_fstring_field_indices=[1808, 1823]),
            'character_avatar': {key: avatars[key] for key in (
                'source_table', 'source_pak', 'source_uasset_sha256', 'source_uexp_sha256', 'row_count')},
            'character_avatar_consumer_contract': AVATAR_CONSUMER,
            'game_item': {key: items[key] for key in (
                'source_table', 'source_pak', 'source_uasset_sha256', 'source_uexp_sha256', 'row_count')},
            'fashion_links': dict(shop['sources']['fashion_links'], fashion_field_index=112, hero_field_index=113),
            'melee_skin': {key: melee[key] for key in (
                'source_pak', 'source_entry', 'source_uexp_sha256', 'row_count')},
        },
        'entries': entries,
        'summary': {'bundle_entry_count': len(entries),
            'direct_reward_occurrence_count': sum(len(e['rewards']) for e in entries),
            'unique_direct_reward_ids': len(unique_rewards),
            'no_direct_rewards_bundle_count': sum(not e['rewards'] for e in entries),
            'gun_skin_unique_reward_ids': len(unique_guns),
            'field_1823_nonempty_reward_skin_count': len(basename_rows),
            'field_1823_unique_source_filename_count': len(set(basename_rows.values())),
            'field_1823_associated_bundle_count': len(basename_bundle_ids),
            'exact_character_avatar_reward_row_count': len(unique_fashions),
            'exact_character_avatar_associated_bundle_count': len(avatar_bundle_ids),
            'unique_character_avatar_mesh_paths': len(all_mesh_paths),
            'game_item_nonempty_icon_unique_reward_ids': len(icon_ids),
            'missing_game_item_unique_reward_ids': sorted(missing_item_ids)},
        'limits': [
            'Source references are metadata; no images, meshes, movies or raw payload bytes are copied.',
            'Field 1823 preserves a bare filename. Its original field name, directory and native consumer role remain unknown.',
            'WeaponSkinDataTable FString fields contain no recovered weapon mesh or material paths; other serialized forms are not decoded as model bindings.',
            'CharacterCaptureUtil proves fashion-ID use as an avatar ID in the recorded capture branches; mounted table precedence, package ownership and actual resource rendering remain unverified.',
            'Source-empty MallItemIcon does not prove a reward lacks a client icon; native category-specific fallbacks are outside this metadata.',
            'Lottery rewards are not attached to a bundle unless present in its direct bundle_item_list; jump destinations are not inferred as reward ownership.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path)
    parser.add_argument('--gun-skin-export', type=Path, required=True,
                        help='Preserved decoded PAK2 entry 7292 export for the captured source SHA256')
    parser.add_argument('--avatar-header', type=Path)
    parser.add_argument('--avatar-body', type=Path)
    parser.add_argument('--game-root', type=Path)
    parser.add_argument('--shadow-root', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    installed, shadow = game_paths(args.game_root, args.shadow_root)
    output = project_path(args.output, PROTOCOL / 'premium_shop_reward_resources.json')
    if any(output.is_relative_to(root) for root in (installed, shadow)):
        parser.error('Reports must be outside installed and shadow game trees')
    try:
        shop, shop_input = load(project_path(args.catalog, PROTOCOL / 'premium_shop_catalog.json'))
        guns, _ = load(PROTOCOL / 'gun_skin_catalog.json')
        avatars, _ = load(PROTOCOL / 'operator_asset_catalog.json')
        items, _ = load(PROTOCOL / 'game_item_catalog.json')
        melee, _ = load(PROTOCOL / 'melee_weapon_catalog.json')
        raw_path = project_path(args.gun_skin_export, ROOT / 'work/evidence/matched_assets')
        gun_rows = gun_resources(raw_path, guns)
        fashion_ids = {r['fashion_id'] for r in shop['fashion_links']}
        reward_fashions = {p['id'] for table in BUNDLE_SOURCES for row in shop[table]
            for group in row['bundle_item_list'] for p in group.get('item_list', [group]) if p['id'] in fashion_ids}
        header = project_path(args.avatar_header, ROOT) if args.avatar_header else None
        body = project_path(args.avatar_body, ROOT) if args.avatar_body else None
        status = avatar_views(avatars, reward_fashions, header, body)
        report = build(shop, guns, avatars, items, melee, gun_rows, status)
        report['source_bundle_catalog'] = shop_input
        serialized = json.dumps(report, ensure_ascii=True, indent=2) + '\n'
        if re.search(r'[A-Za-z]:[\\/]|data:image|base64,', serialized):
            raise ValueError('Public metadata contains an absolute machine path or embedded image')
    except (KeyError, ValueError, OSError, struct.error) as exc:
        parser.error(str(exc))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(serialized, encoding='utf-8', newline='\n')
    print(json.dumps({'output_file': output.name, 'summary': report['summary']}))


if __name__ == '__main__':
    main()
