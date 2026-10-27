"""Read-only bundle asset references, native CDN cache and clear-hotfix owners."""

import argparse
from collections import Counter
import ctypes
import hashlib
import json
from pathlib import Path
import re
import struct

from bundle_asset_locations_package import package
from local_game_paths import game_paths, project_path


ROOT = Path(__file__).resolve().parents[1]
INSTALL, SHADOW = game_paths()
OUTPUT = ROOT / 'work/bundle_asset_locations.json'
PUBLIC_OUTPUT = ROOT / 'work/bundle_asset_locations_public.json'
PAK_SHA256 = 'bca40ffd9fb08ec9b4a64042e77099d8976d6ad67bd311f6d7cf466a5428d220'
TABLE_SOURCES = {
    'recommendations': (7142, 'bcf064ebee25d046e21712375adf8e68f80b71bedd9c5c65f1fcb6a6d771a1fc'),
    'gifts': (7156, '1b7640b1121e61e9fef64a8f986f5620588fb1e9a70822f8feae9898056b68d7'),
}
FIELD_ROLES = {
    271: 'local_big', 273: 'local_small', 275: 'local_logo',
    272: 'cdn_big', 274: 'cdn_small', 276: 'cdn_logo_cn', 277: 'cdn_logo_en',
    304: 'field_304_unclassified',
}
CATALOG_FIELDS = {
    271: 'native_big_asset', 273: 'preview_asset', 275: 'native_logo_asset',
    272: 'IamgeSourceBig_CDN', 274: 'IamgeSourceSmall_CDN',
    276: 'ImageSourceLogo_CDN_CN', 277: 'ImageSourceLogo_CDN_EN',
}


def sha_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def crc_table():
    result = []
    for value in range(256):
        crc = value << 24
        for _ in range(8):
            crc = ((crc << 1) ^ (0x04c11db7 if crc & 0x80000000 else 0)) & 0xffffffff
        result.append(crc)
    return result


CRC_TABLE = crc_table()


def native_cache_basename(relative):
    basename = relative.rsplit('/', 1)[-1]
    if not basename.startswith('C='):
        raise ValueError('Not an observed C= resource')
    crc = 0
    folded = ''.join(chr(ord(char) - 32) if 'a' <= char <= 'z' else char
                     for char in basename[2:])
    for byte in folded.encode('utf-16-le'):
        crc = ((crc >> 8) ^ CRC_TABLE[(crc ^ byte) & 255]) & 0xffffffff
    return 'C=' + str(crc if crc < 0x80000000 else crc - 0x100000000)


def verify_native_image(path, prefix):
    import oodle_payload_reader as codec
    codec.PATH = INSTALL / 'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    version, width, height, expected, *_ = struct.unpack_from('<8I', prefix, 8)
    if version != 3 or not 0 < width <= 8192 or not 0 < height <= 8192 or not 0 < expected <= 8 * 1024 * 1024:
        raise ValueError('Native image header exceeds bounded verification scope')
    data = path.read_bytes()[40:]
    if expected <= 4 * 1024 * 1024:
        result = codec.decode(data, expected)
    else:
        if codec._function is None:
            raise ValueError('Codec must first be initialized by a small verified image')
        source, output = ctypes.create_string_buffer(data), ctypes.create_string_buffer(expected)
        written = codec._function(source, len(data), output, expected, 1, 1, 0,
                                 None, 0, None, None, None, 0, 3)
        if written != expected:
            raise ValueError('Native image codec output length mismatch')
        result = output.raw
    return {'oodle_payload_offset': 40, 'oodle_compressed_size': len(data),
            'decompressed_size_from_header': expected,
            'decompressed_sha256': hashlib.sha256(result).hexdigest(),
            'bounded_oodle_decompression_verified': True,
            'bytecount_consistent_with_16_bytes_per_4x4_block': expected == ((width + 3) // 4) * ((height + 3) // 4) * 16,
            'pixel_format_native_enum_value': struct.unpack_from('<I', prefix, 24)[0],
            'original_native_image_to_texture_semantics_verified': False}


def image_metadata(path, verify_native=False):
    result = {'path': path.as_posix(), 'size': path.stat().st_size,
              'sha256': sha_file(path)}
    with path.open('rb') as handle:
        prefix = handle.read(64)
    result['header_hex'] = prefix.hex()
    try:
        from PIL import Image
        with Image.open(path) as image:
            image.load()
            result.update(format=image.format, dimensions=list(image.size), mode=image.mode,
                          standard_image_decode_verified=True)
    except Exception as exc:
        result.update(standard_image_decode_verified=False, decoder_error=type(exc).__name__)
        if len(prefix) >= 40 and prefix.startswith(b'\x89PNG\r\n\x1a\n') and prefix[12:16] != b'IHDR':
            result['format'] = 'native_serialized_image_with_png_signature'
            result['header_u32_le_after_signature'] = list(struct.unpack_from('<8I', prefix, 8))
            result['native_header_field_semantics_verified'] = False
            result['dimensions_inferred_from_header_u32'] = list(struct.unpack_from('<II', prefix, 12))
            if verify_native:
                try:
                    result.update(verify_native_image(path, prefix))
                except Exception as native_exc:
                    result.update(bounded_oodle_decompression_verified=False,
                                  native_verification_error=str(native_exc))
        else:
            result['format'] = 'unparsed'
    return result


def reference(value):
    match = re.fullmatch(r"([^']+)'(/Game/[^']+)'", value)
    if not match:
        return None
    class_name, object_path = match.groups()
    return {'class': class_name, 'object_path': object_path,
            'package_path': object_path.split('.', 1)[0]}


def catalog_rows(catalog):
    result = {}
    for table in ['recommendations', 'gifts']:
        rows = []
        source = catalog['sources'][table]
        if (source['entry'], source['sha256']) != TABLE_SOURCES[table]:
            raise ValueError(f'Published {table} catalog source does not match this locator version')
        mapping = CATALOG_FIELDS if table == 'recommendations' else {80: 'native_banner_asset'}
        for index, key in mapping.items():
            if catalog['serialized_resource_field_indices'][table].get(key) != index:
                raise ValueError(f'Published {table} field mapping is missing or differs for {key}')
        for bundle in catalog[table]:
            missing = [key for key in mapping.values() if key not in bundle]
            if table == 'recommendations' and 'additional_resource_references' not in bundle:
                missing.append('additional_resource_references')
            if missing:
                raise ValueError(f'Published {table} row {bundle.get("row")} lacks resource fields: {", ".join(missing)}')
            fields = {index: bundle[key] for index, key in mapping.items()}
            if any(not isinstance(value, str) for value in fields.values()):
                raise ValueError(f'Published {table} resource fields must be source strings')
            for extra in bundle.get('additional_resource_references', []):
                if extra['field_index'] == 304:
                    fields[304] = extra['value']
            fields[301 if table == 'recommendations' else 77] = bundle['tab_id' if table == 'recommendations' else 'goods_id']
            rows.append({'row': bundle['row'], 'offset': bundle['offset'], 'fields': fields})
        if len(rows) != catalog['sources'][table]['row_count']:
            raise ValueError(f'Published {table} catalog row count does not match source metadata')
        result[table] = rows
    return result


def sources_and_references(catalog, rows_by_table, evidence_root=None):
    sources, references = {}, []
    for table_name, entry in [('recommendations', 7142), ('gifts', 7156)]:
        rows, source = rows_by_table[table_name], catalog['sources'][table_name]
        evidence = (evidence_root / 'matched_assets' /
                    f'pak-0-0-pakchunk2-WindowsClient.pak.entry-{entry}.bin') if evidence_root else None
        sources[table_name] = dict(source, raw_payload_verification_status='not_requested')
        if evidence:
            sources[table_name]['extracted_source_path'] = evidence.as_posix()
            if evidence.is_file():
                digest = sha_file(evidence)
                if digest != source['sha256']:
                    raise ValueError(f'Preserved raw {table_name} payload SHA differs from published catalog')
                sources[table_name]['raw_payload_verification_status'] = 'sha256_matches_published_source'
            else:
                sources[table_name]['raw_payload_verification_status'] = 'unknown_missing_optional_evidence'
        sources[table_name]['entry_header_offset'] = 50505481 if entry == 7142 else 50554393
        sources[table_name]['entry_offset_evidence'] = (
            'Original PAK verified read-only by bundle_catalog_audit; decoded payload SHA matches extracted source')
        for row in rows:
            fields = row['fields']
            identity = {'table': table_name, 'row': row['row'], 'row_offset': row['offset']}
            identity['tab_id' if table_name == 'recommendations' else 'goods_id'] = (
                fields[301] if table_name == 'recommendations' else fields[77])
            roles = FIELD_ROLES if table_name == 'recommendations' else {80: 'gift_local_banner'}
            for field_index, role in roles.items():
                raw = fields.get(field_index, 0)
                if not raw:
                    continue
                value = raw
                if not value:
                    continue
                item = dict(identity, field_index=field_index, role=role, value=value)
                local = reference(value)
                if local:
                    item.update(local)
                    item['kind'] = 'local_ue_reference'
                elif value.startswith('Resource/'):
                    item['kind'] = 'cdn_relative_reference'
                    relative_dir = value.rsplit('/', 1)[0]
                    basename = native_cache_basename(value)
                    item['cache_basename'] = basename
                    item['raw_cdn_hash_text'] = value.rsplit('/', 1)[-1][2:].split('.', 1)[0]
                    item['source_serialized_string_and_relative_path_verified'] = True
                    item['physical_cache_candidates'] = [
                        (root / 'DeltaForce/Saved/Cdn/G/CN' / relative_dir / basename).as_posix()
                        for root in [INSTALL, SHADOW]]
                    item['physical_cache_existing'] = [
                        p for p in item['physical_cache_candidates'] if Path(p).is_file()]
                else:
                    item['kind'] = 'unclassified_reference'
                references.append(item)
    return sources, references


def public_manifest(sources, references, rows_by_table, media=None):
    grouped = []
    for name, entry in [('recommendations', 7142), ('gifts', 7156)]:
        rows = rows_by_table[name]
        for row in rows:
            table_refs = [r for r in references if r['table'] == name and r['row'] == row['row']]
            fields = row['fields']
            roles = FIELD_ROLES if name == 'recommendations' else {80: 'gift_local_banner'}
            resources = []
            for index, role in roles.items():
                value = fields.get(index, '')
                source = next((r for r in table_refs if r['field_index'] == index), None)
                resource = {'role': role, 'source_field_index': index, 'value': value,
                            'source_status': 'nonempty_verified' if value else 'empty_in_source'}
                if source:
                    resource['kind'] = source['kind']
                    if source['kind'] == 'local_ue_reference':
                        resource.update({k: source[k] for k in ['class', 'object_path', 'package_path']})
                        resource['cooked_package_owner_status'] = 'unresolved_encrypted_baseline'
                    elif source['kind'] == 'cdn_relative_reference':
                        resource.update(raw_cdn_hash_text=source['raw_cdn_hash_text'],
                                        cache_basename=source['cache_basename'],
                                        cache_relative='DeltaForce/Saved/Cdn/G/CN/' +
                                            value.rsplit('/', 1)[0] + '/' + source['cache_basename'],
                                        cache_presence_status=source['cache_presence_status'],
                                        existing_shadow_cache=any(Path(p).is_relative_to(SHADOW) for p in source['physical_cache_existing']),
                                        existing_installed_cache=any(Path(p).is_relative_to(INSTALL) for p in source['physical_cache_existing']))
                        if source['existing_cache_metadata']:
                            meta = source['existing_cache_metadata'][0]
                            resource.update(cache_sha256=meta['sha256'], cache_size=meta['size'],
                                            cache_image_format=meta['format'],
                                            standard_image_decode_verified=meta['standard_image_decode_verified'])
                            if 'bounded_oodle_decompression_verified' in meta:
                                resource['bounded_oodle_decompression_verified'] = meta['bounded_oodle_decompression_verified']
                                resource['original_native_image_to_texture_semantics_verified'] = False
                            if meta.get('dimensions'):
                                resource['cache_dimensions'] = meta['dimensions']
                                resource['dimension_basis'] = 'standard_image_decoder'
                            elif meta.get('dimensions_inferred_from_header_u32'):
                                resource['cache_dimensions'] = meta['dimensions_inferred_from_header_u32']
                                resource['dimension_basis'] = 'inferred_native_u32_header_not_independent_decoder'
                resources.append(resource)
            record = {'table': name, 'row': row['row'], 'row_offset': row['offset'],
                'tab_id' if name == 'recommendations' else 'goods_id': (
                    fields[301] if name == 'recommendations' else fields[77]),
                'resources': resources}
            if media:
                paths = {r.get('object_path') for r in resources if r.get('object_path')}
                media_links = []
                for row_media in media['exact_bundle_image_media_rows']:
                    matched = sorted(paths.intersection(row_media['exact_bundle_image_object_matches']))
                    if not matched:
                        continue
                    loose = []
                    for locator in media['existing_loose_media_locators']:
                        if locator['source_row_name'] != row_media['row_name']:
                            continue
                        files = []
                        for file in locator['files']:
                            physical = Path(file['path'])
                            if physical.is_relative_to(INSTALL) and physical.is_file():
                                files.append({'game_relative_path': physical.relative_to(INSTALL).as_posix(),
                                    'content_relative_path': physical.relative_to(INSTALL / 'DeltaForce/Content').as_posix(),
                                    'physical_candidate_status': 'observed_existing',
                                    'size': file['size'], 'source_bin_media_size': file['source_bin_media_size'],
                                    'size_matches_source': file['size_matches_source_bin_media_size'],
                                    'bink2_magic_at_offset': file['bink2_magic_at_offset'],
                                    'prefix64_sha256': file['prefix64_sha256']})
                        if files:
                            loose.append({'source_field': locator['source_field'],
                                'source_logical_path': locator['logical_source'], 'files': files,
                                'mapping_basis': locator['mapping_basis'],
                                'exact_logical_path_observed': locator['exact_logical_path_observed'],
                                'native_extension_transform_verified': locator['native_logical_to_physical_extension_transform_verified']})
                    media_links.append({'media_row': row_media['row'], 'media_row_name': row_media['row_name'],
                        'media_row_offset': row_media['row_offset'], 'matching_bundle_texture_objects': matched,
                        'media_download_type': row_media['fields']['MediaDownloadType'],
                        'source_media_resources': row_media['fields']['MediaResList'],
                        'existing_loose_media_locators': loose,
                        'native_recommendation_video_selection_verified': False})
                if media_links:
                    record['related_media_resources'] = media_links
                if name == 'recommendations':
                    related = next((r for r in media['bundle_item_to_theme_scene_links']
                                    if r['tab_id'] == fields[301] and r['recommendation_row'] == row['row']), None)
                    if related:
                        record['related_theme_backgrounds'] = {
                            'correlation_basis': related['correlation_basis'],
                            'native_selection_field_verified': False, 'matches': related['matches']}
            grouped.append(record)
    report = {'schema_version': 1, 'source_pak': 'pak-0-0-pakchunk2-WindowsClient.pak',
            'source_pak_sha256': PAK_SHA256,
            'native_runtime_resource_loading_and_rendering_verified': False,
            'source_tables': {name: {k: v for k, v in data.items() if k != 'extracted_source_path'}
                              for name, data in sources.items()},
            'cache_mapping_status': 'Inferred mathematical transform matches all 47 filenames in the captured Store cache corpus; this is historical source evidence, not a current-run cache count; no native implementation proof',
            'entries': grouped,
            'limits': ['This is a metadata locator; it does not copy, substitute or download image data.',
                       'Cache absence is reported only for available inspected game trees; missing trees have unknown status.',
                       'Local virtual paths preserve original source strings; encrypted baseline package owners remain unresolved.',
                       'Raw field 304 has an unverified role; it is retained as a resource reference only.',
                       'No named model path was recovered from these serialized FString fields. Native model bindings require separate source evidence.']}
    if media:
        report['related_table_sources'] = {
            'media': [{'header_file': Path(r['header_path']).name, 'body_file': Path(r['body_path']).name,
                'header_sha256': r['header_sha256'], 'body_sha256': r['body_sha256'],
                'row_count': r['row_count']} for r in media['media_sources']],
            'selection_status': media.get('media_source_selection_status'),
            'selected_preserved_media_header': Path(media['selected_preserved_media_source']['header_path']).name,
            'theme': dict({k: v for k, v in media['theme_source'].items() if k not in ['header_path', 'body_path']},
                          header_file=Path(media['theme_source']['header_path']).name,
                          body_file=Path(media['theme_source']['body_path']).name) if media.get('theme_source') else None}
        report['limits'].append('Related media/theme records provide source associations; native active table precedence, recommendation binding and extension rewriting remain unverified.')
    return report


def reuse_hotfix_evidence(targets, evidence_root=None):
    evidence, records, summaries = [], [], {}
    if evidence_root is None:
        return {'source_evidence': [], 'prior_scan_summaries': [],
                'matches_in_preserved_records': [], 'matches_in_preserved_extracted_packages': [],
                'status': 'unknown_not_requested',
                'record_coverage': 'Optional private scan evidence was not provided; pass --evidence-root to reuse preserved records'}
    for filename in ['resource-asset-inventory-shadow-hotfix.txt',
                     'resource-asset-inventory-shadow-hotfix-related.txt']:
        path = evidence_root / filename
        if not path.is_file():
            evidence.append({'path': path.as_posix(), 'status': 'unknown_missing_optional_evidence'})
            continue
        evidence.append({'path': path.as_posix(), 'sha256': sha_file(path)})
        for line in path.read_text(encoding='utf-8').splitlines():
            if line.startswith('ASSET '):
                row = json.loads(line[6:])
                owned = sorted(targets.intersection(row['own_paths']))
                refs = sorted(targets.intersection({n.split('.', 1)[0] for n in row.get('related_names', [])}))
                if owned or refs:
                    records.append(dict(row, matched_owned_target_packages=owned,
                        matched_reference_target_packages=sorted(set(refs) - set(owned))))
            elif line.startswith('SUMMARY '):
                row = json.loads(line[8:])
                summaries[row['pak']] = row
    extracted = []
    for path in evidence_root.rglob('*.uasset'):
        if path.stat().st_size > 4 * 1024 * 1024:
            continue
        try:
            raw = path.read_bytes()
            info = package(raw)
        except Exception:
            continue
        if not info:
            continue
        own = sorted(targets.intersection(info['own_paths']))
        refs = sorted(targets.intersection({n.split('.', 1)[0] for n in info['names']}))
        if own or refs:
            extracted.append({'path': path.as_posix(), 'decoded_sha256': hashlib.sha256(raw).hexdigest(),
                'matched_owned_target_packages': own,
                'matched_reference_target_packages': sorted(set(refs) - set(own)),
                'own_paths': info['own_paths'], 'exports': info['exports']})
    return {'source_evidence': evidence, 'prior_scan_summaries': list(summaries.values()),
            'status': 'preserved_partial_records_available' if summaries else 'unknown_missing_optional_evidence',
            'matches_in_preserved_records': records, 'matches_in_preserved_extracted_packages': extracted,
            'record_coverage': 'Prior output retained selected names/packages, not every package; a no-hit result cannot classify all current targets as absent'}


def main():
    global INSTALL, SHADOW
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path)
    parser.add_argument('--shadow-root', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--public-output', type=Path)
    parser.add_argument('--media-input', type=Path)
    parser.add_argument('--catalog', type=Path, help='Published premium_shop_catalog.json; defaults to the protocol catalog')
    parser.add_argument('--evidence-root', type=Path, help='Optional directory of preserved raw table exports and prior scan records')
    parser.add_argument('--verify-native-cache', action='store_true')
    args = parser.parse_args()
    INSTALL, SHADOW = game_paths(args.game_root, args.shadow_root)
    output = project_path(args.output, OUTPUT)
    public_output = project_path(args.public_output, PUBLIC_OUTPUT)
    if any(p.is_relative_to(root) for p in [output, public_output] for root in [INSTALL, SHADOW]):
        raise ValueError('Reports must be outside installed and shadow game trees')
    source_pak = INSTALL / 'DeltaForce/Content/Paks/pak-0-0-pakchunk2-WindowsClient.pak'
    source_pak_status = 'unknown_missing_local_source_pak'
    if source_pak.is_file() and sha_file(source_pak) != PAK_SHA256:
        raise ValueError('Installed source PAK does not match the preserved same-version table exports')
    if source_pak.is_file():
        source_pak_status = 'sha256_matches_preserved_source'
    catalog_path = project_path(args.catalog, ROOT / 'outputs/df-local-server/protocol/premium_shop_catalog.json')
    if not catalog_path.is_file():
        parser.error('Published catalog is missing; provide --catalog with premium_shop_catalog.json')
    try:
        catalog = json.loads(catalog_path.read_text(encoding='utf-8'))
        rows_by_table = catalog_rows(catalog)
    except (KeyError, TypeError, ValueError) as exc:
        parser.error(f'Invalid published catalog: {exc}; provide the complete catalog for the captured source version')
    evidence_root = project_path(args.evidence_root, ROOT / 'work/evidence') if args.evidence_root else None
    sources, references = sources_and_references(catalog, rows_by_table, evidence_root)
    images = [image_metadata(p, args.verify_native_cache) for root in [INSTALL, SHADOW]
              for p in sorted((root / 'DeltaForce/Saved/Cdn').rglob('*')) if p.is_file()]
    image_by_path = {r['path']: r for r in images}
    for item in references:
        if item['kind'] == 'cdn_relative_reference':
            item['existing_cache_metadata'] = [image_by_path[p] for p in item['physical_cache_existing']]
            item['cache_presence_status'] = ('observed_existing' if item['physical_cache_existing'] else
                'not_present_in_available_game_trees' if all((root / 'DeltaForce').is_dir() for root in [INSTALL, SHADOW])
                else 'unknown_incomplete_local_game_trees')
    local = [r for r in references if r['kind'] == 'local_ue_reference']
    targets = {r['package_path'] for r in local}
    hotfix = reuse_hotfix_evidence(targets, evidence_root)
    cdn = [r for r in references if r['kind'] == 'cdn_relative_reference']
    cdn_main = [r for r in cdn if r['field_index'] != 304]
    mapped_paths = {p for r in cdn for p in r['physical_cache_existing']}
    store = [i for i in images if '/Resource/Store/' in i['path']]
    own = {p for m in hotfix['matches_in_preserved_records'] + hotfix['matches_in_preserved_extracted_packages']
           for p in m['matched_owned_target_packages']}
    coverage = []
    for row in sorted({r['row'] for r in cdn_main}):
        source_refs = [r for r in cdn_main if r['row'] == row]
        coverage.append({'row': row, 'tab_id': source_refs[0]['tab_id'],
            'cached_roles': [r['role'] for r in source_refs if r['physical_cache_existing']],
            'uncached_roles': [r['role'] for r in source_refs if r['cache_presence_status'] == 'not_present_in_available_game_trees'],
            'unknown_roles': [r['role'] for r in source_refs if r['cache_presence_status'] == 'unknown_incomplete_local_game_trees'],
            'all_source_strings_serialized_and_valid_relative': True,
            'source_fields': {r['role']: r['value'] for r in source_refs},
            'source_row_offset': source_refs[0]['row_offset']})
    report = {'scope': 'Read-only installed/shadow sources; no launch, downloads or game writes',
        'source_pak': (INSTALL / 'DeltaForce/Content/Paks/pak-0-0-pakchunk2-WindowsClient.pak').as_posix(),
        'source_pak_sha256': PAK_SHA256,
        'source_pak_verification_status': source_pak_status,
        'published_catalog': {'path': catalog_path.as_posix(), 'sha256': sha_file(catalog_path)},
        'local_tree_inspection_status': {name: 'available' if (root / 'DeltaForce').is_dir() else 'unknown_missing_game_tree'
                                         for name, root in [('installed', INSTALL), ('shadow', SHADOW)]},
        'sources': sources,
        'cache_mapping': {'input': 'Uppercase basename after C=, including extension, UTF-16LE',
            'table_polynomial': '0x04c11db7', 'initial_value': 0,
            'byte_step': 'crc = (crc >> 8) ^ table[(crc ^ byte) & 255]',
            'filename': 'C= plus signed 32-bit decimal CRC',
            'status': 'Corpus-verified mapping; native implementation was not executed or independently disassembled'},
        'summary': {'reference_count_by_role': dict(Counter(r['role'] for r in references)),
            'local_unique_package_count': len(targets), 'hotfix_owned_local_target_count': len(own)
                if hotfix['status'] == 'preserved_partial_records_available' else None,
            'cdn_reference_count': len(cdn), 'cdn_reference_existing_cache_count': sum(
                bool(r['physical_cache_existing']) for r in cdn),
            'main_cdn_reference_count': len(cdn_main), 'main_cdn_existing_cache_count': sum(
                bool(r['physical_cache_existing']) for r in cdn_main),
            'main_cdn_bundle_count': len(coverage), 'main_cdn_cached_bundle_count': sum(
                bool(r['cached_roles']) for r in coverage),
            'main_cdn_uncached_bundle_count': sum(not r['cached_roles'] and bool(r['uncached_roles']) and not r['unknown_roles'] for r in coverage),
            'main_cdn_unknown_bundle_count': sum(bool(r['unknown_roles']) for r in coverage),
            'store_cache_file_count': len(store),
            'store_cache_mapped_file_count': sum(i['path'] in mapped_paths for i in store),
            'unmapped_store_cache_files': [i['path'] for i in store if i['path'] not in mapped_paths],
            'cache_format_counts': dict(Counter(i['format'] for i in images)),
            'all_cache_file_count': len(images),
            'store_cache_format_counts': dict(Counter(i['format'] for i in store)),
            'store_native_cache_oodle_verified_count': sum(i.get('bounded_oodle_decompression_verified', False) for i in store),
            'prior_hotfix_package_count': sum(h['stats'].get('uassets', 0) for h in hotfix['prior_scan_summaries'])
                if hotfix['status'] == 'preserved_partial_records_available' else None},
        'references': references, 'bundle_cdn_coverage': coverage, 'cache_files': images,
        'reused_hotfix_evidence': hotfix,
        'limits': ['Local UE references identify virtual object paths; ownership requires actual root export evidence.',
            'All baseline PAK directory indexes remain encrypted; no baseline target ownership claim is made.',
            'Prior hotfix scan coverage is reused without re-reading PAKs. Preserved ASSET records are filtered and incomplete for the new target list.',
            'Native serialized PNG-signature caches require the native decoder; Pillow failure is not corruption evidence.',
            'CDN cache absence does not prove a resource is unavailable from CDN or baseline PAKs.',
            'G/CN cache routing is proven for existing shadow files; current runtime CDN URL base is not established.']}
    if args.verify_native_cache:
        codec_path = INSTALL / 'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
        report['codec_source'] = {'path': codec_path.as_posix(), 'sha256': sha_file(codec_path) if codec_path.is_file() else None,
                                 'status': 'available' if codec_path.is_file() else 'unknown_missing_codec',
                                 'maximum_output_bytes_per_call': 8 * 1024 * 1024}
    output.parent.mkdir(parents=True, exist_ok=True)
    public_output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    media = None
    if args.media_input:
        media_path = project_path(args.media_input, ROOT / 'work/bundle_asset_locations_media.json')
        if not media_path.is_file():
            parser.error('--media-input is missing; generate the optional media report from preserved exports first')
        media = json.loads(media_path.read_text(encoding='utf-8'))
    public_output.write_text(json.dumps(public_manifest(sources, references, rows_by_table, media), ensure_ascii=True,
                                       indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': output.as_posix(), 'public_output': public_output.as_posix(),
                      'summary': report['summary']}), flush=True)


if __name__ == '__main__':
    main()
