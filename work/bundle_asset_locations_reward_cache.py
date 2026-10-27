"""Match exact captured reward basenames against an observed local CDN corpus."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct

from bundle_asset_locations import native_cache_basename
from local_game_paths import game_paths, project_path


ROOT = Path(__file__).resolve().parents[1]
SKIN_SHA256 = '03929c8c36ef4bd21de0e6262809095a863f3e65d6e44e8eefcf6ac57a59cce7'


def sha_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def metadata(path):
    result = {'size': path.stat().st_size, 'sha256': sha_file(path)}
    with path.open('rb') as handle:
        data = handle.read(min(result['size'], 1024 * 1024))
    if data.startswith(b'\x89PNG\r\n\x1a\n') and data[12:16] == b'IHDR':
        result.update(format='PNG', dimensions=list(struct.unpack_from('>II', data, 16)),
                      dimensions_basis='PNG_IHDR', standard_image_decode_verified=False)
    elif len(data) >= 40 and data.startswith(b'\x89PNG\r\n\x1a\n'):
        result.update(format='native_serialized_image_with_png_signature',
                      dimensions_inferred_from_header_u32=list(struct.unpack_from('<II', data, 12)),
                      native_header_field_semantics_verified=False,
                      original_native_image_to_texture_semantics_verified=False)
    elif data.startswith(b'\xff\xd8'):
        result.update(format='JPEG', standard_image_decode_verified=False)
        cursor = 2
        while cursor + 4 <= len(data):
            if data[cursor] != 255:
                break
            while cursor < len(data) and data[cursor] == 255:
                cursor += 1
            if cursor >= len(data):
                break
            marker = data[cursor]
            cursor += 1
            if marker in (0xd9, 0xda):
                break
            if marker in (0x01, *range(0xd0, 0xd8)):
                continue
            if cursor + 2 > len(data):
                break
            length = struct.unpack_from('>H', data, cursor)[0]
            if length < 2 or cursor + length > len(data):
                break
            if marker in (0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7,
                          0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf) and length >= 8:
                height, width = struct.unpack_from('>HH', data, cursor + 3)
                result.update(dimensions=[width, height], dimensions_basis='JPEG_SOF')
                break
            cursor += length
    else:
        result['format'] = 'unparsed'
    return result


def reward_rows(manifest):
    source = manifest.get('sources', {}).get('weapon_skin', {})
    if source.get('entry') != 7292 or source.get('sha256') != SKIN_SHA256:
        raise ValueError('Reward manifest requires captured WeaponSkinDataTable entry 7292 and its verified SHA256')
    rows = {}
    for entry in manifest.get('entries', []):
        for reward in entry.get('rewards', []):
            skin = reward.get('weapon_skin_source')
            if not skin:
                continue
            for field in skin.get('serialized_fstring_fields', []):
                if field.get('source_field_index') != 1823 or not field.get('value'):
                    continue
                value = field['value']
                if len(value) > 128 or not re.fullmatch(r'C=[0-9A-F]+\.jpg', value):
                    raise ValueError(f'Unexpected captured field1823 basename in source row {skin.get("row")}')
                key = skin['row']
                item = {'row': key, 'row_offset': skin['row_offset'],
                        'row_sha256': skin['row_sha256'], 'source_field_index': 1823,
                        'value_offset': field['value_offset'], 'value': value,
                        'observed_store_transform_basename': native_cache_basename(value),
                        'source_field_role_verified': False, 'relative_prefix_inferred': False,
                        'native_loading_binding_verified': False, 'bundle_occurrences': []}
                existing = rows.setdefault(key, item)
                if any(existing[k] != item[k] for k in ('row_offset', 'row_sha256', 'value_offset', 'value')):
                    raise ValueError(f'Conflicting reward source metadata for WeaponSkinDataTable row {key}')
                id_field = 'tab_id' if entry['table'] == 'recommendations' else 'goods_id'
                occurrence = {'table': entry['table'], id_field: entry[id_field],
                              'row': entry['row'], 'reward_id': reward['id']}
                if occurrence not in existing['bundle_occurrences']:
                    existing['bundle_occurrences'].append(occurrence)
    return source, [rows[key] for key in sorted(rows)]


def main():
    installed, shadow = game_paths()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', default=str(installed))
    parser.add_argument('--shadow-root', default=str(shadow))
    parser.add_argument('--reward-manifest', default='outputs/df-local-server/protocol/premium_shop_reward_resources.json')
    parser.add_argument('--output', default='work/bundle_asset_locations_reward_cache.json')
    parser.add_argument('--public-output')
    args = parser.parse_args()
    manifest_path = project_path(args.reward_manifest, ROOT / 'outputs/df-local-server/protocol/premium_shop_reward_resources.json')
    if not manifest_path.is_file():
        parser.error('Reward manifest is missing; generate premium_shop_reward_resources.json first or pass --reward-manifest')
    try:
        source, rows = reward_rows(json.loads(manifest_path.read_text(encoding='utf-8')))
    except (ValueError, KeyError, TypeError) as exc:
        parser.error(f'Reward manifest source metadata is incompatible: {exc}')
    installed, shadow = game_paths(args.game_root, args.shadow_root)
    corpus, roots_status = [], []
    for identity, root in [('installed', installed), ('shadow', shadow)]:
        cdn = root / 'DeltaForce/Saved/Cdn'
        roots_status.append({'root': identity, 'cache_relative_path': 'DeltaForce/Saved/Cdn',
                             'status': 'observed_directory' if cdn.is_dir() else 'unknown_directory_not_available'})
        if not cdn.is_dir():
            continue
        for path in sorted(x for x in cdn.rglob('*') if x.is_file()):
            corpus.append({'root': identity, 'physical_path': path.as_posix(),
                           'physical_relative_path': path.relative_to(root).as_posix(),
                           'cache_subdirectory': path.relative_to(cdn).parent.as_posix(),
                           'cache_filename': path.name, **metadata(path)})
    matched_files, matched_names = set(), set()
    for row in rows:
        matches = [dict(item) for item in corpus if item['cache_filename'] == row['observed_store_transform_basename']]
        row['observed_cache_files'] = matches
        row['cache_status'] = ('exact_transformed_basename_observed' if matches else
                               'no_transformed_basename_match_in_observed_corpus' if corpus else
                               'unknown_no_cache_corpus_available')
        if matches:
            matched_names.add(row['value'])
            matched_files.update(item['physical_path'] for item in matches)
    report = {'schema_version': 1,
              'scope': 'Exact captured bare reward filenames compared with every file in available local CDN directories',
              'sources': {'reward_manifest': {'filename': manifest_path.name, 'sha256': sha_file(manifest_path)},
                          'weapon_skin': source},
              'transform_proof': 'Mathematical basename transform inferred from 47 exact historical Store cache matches; native algorithm not proved',
              'native_cache_mapping_and_loading_binding_verified': False,
              'relative_prefix_inferred': False, 'cache_roots': roots_status,
              'counts': {'distinct_source_skin_rows': len(rows),
                         'distinct_bare_source_filenames': len({row['value'] for row in rows}),
                         'observed_cache_files': len(corpus),
                         'cache_subdirectories': dict(Counter(item['cache_subdirectory'] for item in corpus)),
                         'matched_source_filenames': len(matched_names), 'matched_cache_files': len(matched_files)},
              'entries': rows, 'cache_corpus': corpus,
              'limits': ['No relative CDN prefix or URL base is inferred from bare filenames.',
                         'A zero match describes only this observed corpus, not global resource absence.',
                         'Dimensions are read from standard format headers or explicitly inferred native fields; images are not decoded.',
                         'No native code, network, process access, cache writes or game writes are performed.']}
    output = project_path(args.output, ROOT / 'work/bundle_asset_locations_reward_cache.json')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if args.public_output:
        public = json.loads(json.dumps(report))
        for entry in public['cache_corpus']:
            entry.pop('physical_path', None)
        for row in public['entries']:
            for entry in row['observed_cache_files']:
                entry.pop('physical_path', None)
        target = project_path(args.public_output, ROOT / 'work/bundle_asset_locations_reward_cache_public.json')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(public, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report['counts'], sort_keys=True))


if __name__ == '__main__':
    main()
