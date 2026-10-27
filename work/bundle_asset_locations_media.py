"""Read preserved media/theme table exports and locate existing loose media."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from bundle_asset_locations import ROOT, INSTALL, reference, CATALOG_FIELDS
from extract_operator_avatar_catalog import fname, name_map, tags, property_tag
from local_game_paths import game_paths, project_path


def fstring(raw):
    count = struct.unpack_from('<i', raw)[0]
    if count == 0:
        if len(raw) != 4:
            raise ValueError('Unexpected empty FString trailing data')
        return ''
    size = abs(count) * (2 if count < 0 else 1)
    if len(raw) != 4 + size or raw[-(2 if count < 0 else 1):] != bytes(2 if count < 0 else 1):
        raise ValueError('Invalid FString size/termination')
    return raw[4:-2 if count < 0 else -1].decode('utf-16-le' if count < 0 else 'utf-8')


def field_value(data, tag, names):
    start, end, kind = tag['value_start'], tag['end'], tag['kind']
    raw = data[start:end]
    if kind == 'StrProperty':
        return fstring(raw)
    if kind == 'BoolProperty':
        return bool(data[start - 2])
    if kind in ('NameProperty', 'EnumProperty', 'ByteProperty') and len(raw) == 8:
        return fname(data, start, names)
    if kind == 'SoftObjectProperty' or (kind == 'StructProperty' and tag['meta'] == ['SoftObjectPath']):
        path = fname(data, start, names)
        subpath = fstring(raw[8:])
        return path if not subpath else path + ':' + subpath
    primitives = {'IntProperty': '<i', 'Int64Property': '<q', 'UInt64Property': '<Q',
                  'FloatProperty': '<f', 'ObjectProperty': '<i'}
    if kind in primitives:
        return struct.unpack(primitives[kind], raw)[0]
    if kind == 'ArrayProperty':
        count = struct.unpack_from('<i', raw)[0]
        if not 0 <= count <= 10000:
            raise ValueError('Invalid array count')
        if tag['meta'] == ['StructProperty']:
            inner = property_tag(data, start + 4, names, end)
            pos, result = inner['value_start'], []
            for _ in range(count):
                children, pos = tags(data, pos, names, end)
                result.append({t['name']: field_value(data, t, names) for t in children})
            if pos != end:
                raise ValueError('Unparsed struct array data')
            return result
        if tag['meta'] == ['Int64Property']:
            return list(struct.unpack('<' + 'q' * count, raw[4:]))
    return None


def read_table(header, body):
    raw_header, data = header.read_bytes(), body.read_bytes()
    names = name_map(raw_header)
    initial, offset = tags(data, 0, names, len(data))
    if [t['name'] for t in initial] != ['RowStruct']:
        raise ValueError('Unexpected table root')
    prefix, count = struct.unpack_from('<ii', data, offset)
    if prefix or not 0 < count <= 10000:
        raise ValueError('Unexpected table row count')
    offset += 8
    rows = []
    for index in range(count):
        start = offset
        name = fname(data, offset, names)
        children, offset = tags(data, offset + 8, names, len(data))
        rows.append({'row': index, 'row_name': name, 'row_offset': start,
                     'fields': {t['name']: field_value(data, t, names) for t in children}})
    if data[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Unexpected table trailing bytes')
    return {'header_path': header.as_posix(), 'body_path': body.as_posix(),
            'header_sha256': hashlib.sha256(raw_header).hexdigest(),
            'body_sha256': hashlib.sha256(data).hexdigest(),
            'row_count': count, 'complete_property_tag_walk_verified': True, 'rows': rows}


def values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from values(child)
    elif isinstance(value, list):
        for child in value:
            yield from values(child)


def existing_media_locator(url, contents):
    if not url.startswith('./'):
        return None
    logical = url[2:]
    exact = INSTALL / 'DeltaForce/Content' / logical
    if exact.is_file():
        candidates = [exact]
        basis = 'Exact stored content-relative path'
    else:
        source = Path(logical)
        candidates = [p for p in contents if p.stem.casefold() == source.stem.casefold()
                      and p.parent.relative_to(INSTALL / 'DeltaForce/Content').as_posix().casefold() ==
                      source.parent.as_posix().casefold()]
        basis = 'Observed existing same-directory/same-stem file; extension differs from logical source'
    if not candidates:
        return None
    result = []
    for path in candidates:
        with path.open('rb') as handle:
            prefix = handle.read(64)
        result.append({'path': path.as_posix(), 'size': path.stat().st_size,
                       'prefix64_sha256': hashlib.sha256(prefix).hexdigest(),
                       'prefix16_hex': prefix[:16].hex(),
                       'bink2_magic_at_offset': next((x for x in [0, 4] if prefix[x:x + 3] == b'KB2'), None),
                       'full_file_sha256_read': False})
    return {'logical_source': url, 'mapping_basis': basis, 'files': result,
            'exact_logical_path_observed': exact.is_file(),
            'native_logical_to_physical_extension_transform_verified': False}


def main():
    global INSTALL
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path)
    parser.add_argument('--shadow-root', type=Path)
    parser.add_argument('--evidence-root', type=Path, required=True,
                        help='Preserved decoded export directory; raw game tables are not scanned by this tool')
    parser.add_argument('--media-header', type=Path,
                        help='Select one preserved MediaResTable .uasset explicitly when several versions exist')
    parser.add_argument('--theme-header', type=Path)
    parser.add_argument('--catalog', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    INSTALL, _ = game_paths(args.game_root, args.shadow_root)
    evidence_root = project_path(args.evidence_root, ROOT / 'work/evidence')
    media_dir = evidence_root / 'hero-custom-bp-hotfix-assets'
    media_sources = []
    for head in sorted(media_dir.glob('*.uasset')):
        match = re.search(r'entry-(\d+)\.uasset$', head.name)
        entry = int(match.group(1))
        body = head.with_name(head.name.replace(f'entry-{entry}.uasset', f'entry-{entry + 1}.uexp'))
        if not body.is_file():
            parser.error(f'Preserved media body is missing: {body.name}; supply complete paired decoded exports')
        media_sources.append(read_table(head, body))
    if not media_sources:
        parser.error('No preserved MediaResTable exports found; provide --evidence-root containing hero-custom-bp-hotfix-assets/*.uasset and paired .uexp files')
    if args.media_header:
        selected_header = project_path(args.media_header, media_dir)
        media = next((source for source in media_sources if Path(source['header_path']) == selected_header), None)
        if media is None:
            parser.error('--media-header must identify a preserved export found under --evidence-root/hero-custom-bp-hotfix-assets')
    elif len(media_sources) == 1:
        media = media_sources[0]
    else:
        parser.error('Several preserved MediaResTable versions exist; pass --media-header to select the evidence version explicitly')
    theme_header = project_path(args.theme_header, evidence_root / 'matched_assets/1.101.37117.36.10_WindowsNoEditor_37127_P.pak.entry-229.uasset')
    if not theme_header.is_file() or not theme_header.with_suffix('.uexp').is_file():
        parser.error('Preserved ThemeBackgroundData export pair is missing; provide --theme-header with a decoded .uasset and paired .uexp')
    theme = read_table(theme_header, theme_header.with_suffix('.uexp'))
    catalog_path = project_path(args.catalog, ROOT / 'outputs/df-local-server/protocol/premium_shop_catalog.json')
    if not catalog_path.is_file():
        parser.error('Published catalog is missing; provide --catalog with premium_shop_catalog.json')
    catalog = json.loads(catalog_path.read_text(encoding='utf-8'))
    targets = {local['object_path'] for table, fields in [('recommendations', CATALOG_FIELDS.values()),
                                                       ('gifts', ['native_banner_asset'])]
               for bundle in catalog[table] for field in fields
               if (local := reference(bundle.get(field, '')))}
    relevant = []
    for row in media['rows']:
        matches = sorted(targets.intersection(set(values(row['fields']))))
        if matches:
            relevant.append(dict(row, exact_bundle_image_object_matches=matches))
    contents = [p for p in (INSTALL / 'DeltaForce/Content').rglob('*')
                if p.is_file() and p.suffix.lower() != '.pak']
    locators = []
    for row in media['rows']:
        for item in row['fields'].get('MediaResList', []):
            for key, size_key in [('MediaUrl', 'BinMediaSize'), ('MediaUrl_HD', 'BinMediaSize_HD'),
                                  ('MediaUrl_Console', 'BinMediaSize_Console')]:
                url = item.get(key, '')
                locator = existing_media_locator(url, contents)
                if locator:
                    for file in locator['files']:
                        file['source_bin_media_size'] = item.get(size_key)
                        file['size_matches_source_bin_media_size'] = file['size'] == item.get(size_key)
                    locators.append(dict(locator, source_row_name=row['row_name'], source_row_offset=row['row_offset'],
                                         source_field=key, source_media_download_type=row['fields'].get('MediaDownloadType')))
    theme_links = []
    for bundle in catalog['recommendations']:
        ids = {i['id'] for i in bundle['bundle_item_list']}
        matches = []
        for row in theme['rows']:
            declared = set(row['fields'].get('CollectionWeaponIds', []))
            overlap = sorted(ids.intersection(declared))
            if overlap:
                matches.append({'theme_source_row': row['row'], 'theme_row': row['row_name'], 'theme_row_offset': row['row_offset'],
                    'bundle_theme_id': row['fields']['BundleThemeId'],
                    'scene_bg_object_path': row['fields']['SceneBGPath'],
                    'declared_collection_item_ids': sorted(declared), 'overlapping_bundle_item_ids': overlap,
                    'complete_declared_item_set_in_bundle': declared.issubset(ids)})
        if matches:
            theme_links.append({'tab_id': bundle['tab_id'], 'recommendation_row': bundle['row'],
                                'correlation_basis': 'Exact numeric item ID intersection, not inferred theme-name matching',
                                'matches': matches, 'native_recommendation_to_theme_id_field_verified': False})
    source_identity = [{k: v for k, v in row.items() if k != 'rows'} for row in media_sources]
    selected_identity = {k: v for k, v in media.items() if k != 'rows'}
    row_differences = []
    first = {r['row_name']: r for r in media_sources[0]['rows']}
    for row in media['rows']:
        previous = first.get(row['row_name'])
        if not previous or row['fields'] != previous['fields']:
            row_differences.append({'row_name': row['row_name'], 'old': previous, 'new': row})
    bundle_media_names = {row['row_name'] for row in relevant}
    relevant_locators = [locator for locator in locators if locator['source_row_name'] in bundle_media_names]
    bundle_mismatches = [dict(source_row_name=locator['source_row_name'], source_field=locator['source_field'],
                             logical_source=locator['logical_source'], file=file)
                         for locator in relevant_locators for file in locator['files']
                         if not file['size_matches_source_bin_media_size']]
    report = {'scope': 'Read-only preserved exports and existing installed loose file metadata/prefixes; no PAK rescan or launch',
        'media_sources': source_identity, 'selected_preserved_media_source': selected_identity,
        'media_source_selection_status': 'Explicit preserved export selection; currently mounted native table precedence is unverified',
        'media_rows_changed_between_first_preserved_and_selected': row_differences,
        'theme_source': {k: v for k, v in theme.items() if k != 'rows'},
        'exact_bundle_image_media_rows': relevant, 'bundle_item_to_theme_scene_links': theme_links,
        'existing_loose_media_locators': locators,
        'bundle_media_size_mismatches': bundle_mismatches,
        'installed_content_status': 'available' if (INSTALL / 'DeltaForce/Content').is_dir() else 'unknown_missing_local_content_tree',
        'summary': {'media_row_counts': [r['row_count'] for r in media_sources],
            'theme_row_count': theme['row_count'], 'exact_bundle_image_media_rows': len(relevant),
            'linked_recommendation_rows_by_exact_item_overlap': len(theme_links),
            'existing_loose_media_locator_count': len(locators),
            'unique_loose_media_files': len({f['path'] for r in locators for f in r['files']}),
            'size_match_count': sum(f['size_matches_source_bin_media_size'] for r in locators for f in r['files']),
            'changed_media_row_count': len(row_differences)},
        'limits': ['Exact table texture references do not establish that those textures own the table package or exist in a PAK.',
            'Numeric bundle-item/theme intersections are evidence of resource association; the native recommendation theme selection field was not recovered.',
            'Same-stem .bin matches are observed physical candidates, supported by directory, size and Bink header, without independent proof of the native extension transform.',
            'MediaResTable differences do not establish which preserved hotfix is currently mounted or selected.',
            'No materials or mesh package ownership is recovered from these two clear tables.']}
    report['summary'].update(bundle_associated_loose_media_locators=len(relevant_locators),
        bundle_associated_unique_loose_media_files=len({file['path'] for locator in relevant_locators for file in locator['files']}),
        bundle_associated_size_mismatch_count=len(bundle_mismatches))
    target = project_path(args.output, ROOT / 'work/bundle_asset_locations_media.json')
    _, shadow = game_paths(args.game_root, args.shadow_root)
    if any(target.is_relative_to(root) for root in [INSTALL, shadow]):
        parser.error('Reports must be outside installed and shadow game trees')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': target.as_posix(), 'summary': report['summary']}))


if __name__ == '__main__':
    main()
