"""Resolve active Dam WorldSettings from previously extracted clear packages.

No client launch, encrypted entry decoding, process access, or game-file writes.
Identical companion copies are retained as equivalent evidence; distinct bodies
with the same extent remain ambiguous. Adjacency is never a pairing rule.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from extract_operator_avatar_catalog import fname
from inspect_dam_content_packages import name_maps
import recover_dam_gameplay_catalog as recovery


ROOT = Path(__file__).resolve().parent
MAGIC = b'\xc1\x83\x2a\x9e'
TARGETS = frozenset(('/Game/Maps/Dam_Iris_Level1/Dam_Iris_Level1',
                     '/Game/Maps/Dam_Iris_Level11/Dam_Iris_Level11'))


def checked_payload(root, row):
    name = row['evidence_file']
    if Path(name).name != name:
        raise ValueError('Evidence path leaves package directory')
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError('Evidence path leaves package directory')
    if not 0 < row['uncompressed_bytes'] <= 8 * 1024 * 1024:
        raise ValueError('Payload exceeds inspection bound')
    if path.stat().st_size != row['uncompressed_bytes']:
        raise ValueError('Payload hash or size differs from capture manifest')
    data = path.read_bytes()
    if len(data) != row['uncompressed_bytes'] or hashlib.sha256(data).hexdigest() != row['payload_sha256']:
        raise ValueError('Payload hash or size differs from capture manifest')
    return data


def equivalent_companions(root, rows, extent):
    matches = sorted((row for row in rows if row.get('kind') == 'companion_candidate'
                      and row['uncompressed_bytes'] == extent + 4), key=lambda row: row['entry'])
    if not matches:
        raise ValueError('Companion extent is missing')
    canonical = None
    for row in matches:
        body = checked_payload(root, row)
        if body[-4:] != MAGIC:
            raise ValueError('Companion package terminator is missing')
        if canonical is None:
            canonical = body
        elif body != canonical:
            raise ValueError('Companion extent is ambiguous: distinct content')
    return matches[0], matches


def import_reference(pkg, index, seen=None):
    if index == 0:
        return None
    if index > 0:
        return {'export_index': index, 'object_name': pkg.object(index)}
    seen = set() if seen is None else seen
    if index in seen or not 1 <= -index <= len(pkg.imports):
        raise ValueError('Import reference is cyclic or outside package')
    seen.add(index)
    field, _ = name_maps(pkg.header)
    import_offset = struct.unpack_from('<i', pkg.header, field + 28)[0]
    at = import_offset + (-index - 1) * 28
    name = fname(pkg.header, at + 20, pkg.names)
    outer = struct.unpack_from('<i', pkg.header, at + 16)[0]
    parent = import_reference(pkg, outer, seen)
    path = name if parent is None else parent.get('object_path', parent['object_name']) + '.' + name
    return {'import_index': -index, 'object_name': name, 'object_path': path,
            'class_package': fname(pkg.header, at, pkg.names),
            'class_name': fname(pkg.header, at + 8, pkg.names),
            'import_header_offset': at, 'outer': parent}


def property_evidence(pkg, tag):
    value = pkg.value(tag)
    if tag['kind'] == 'ObjectProperty' and tag['size'] == 4:
        value = {'serialized_package_index': value, 'reference': import_reference(pkg, value)}
    elif tag['kind'] == 'SoftObjectProperty':
        if tag['size'] < 12:
            raise ValueError('Soft reference is truncated')
        at = tag['value_start']
        path = fname(pkg.payload, at, pkg.names)
        subpath, end = recovery.string_at(pkg.payload, at + 8, tag['end'])
        if end != tag['end']:
            raise ValueError('Soft reference has unconsumed bytes')
        value = {'object_path': path, 'subpath': subpath}
    return {'property_name': tag['name'], 'property_type': tag['kind'],
            'payload_tag_offset': tag['start'], 'payload_value_offset': tag['value_start'],
            'serialized_value_size': tag['size'], 'value': value}


def inspect_package(root, row, manifest):
    header = checked_payload(root, row)
    field, names = name_maps(header)
    saved_names = json.loads((root / f"entry-{row['entry']}.names.json").read_text(encoding='utf-8'))
    if field != row['name_map_summary_offset'] or names != saved_names:
        raise ValueError('Saved name map differs from serialized header')
    ec, eo, ic, io, depends = struct.unpack_from('<5i', header, field + 16)
    if not 0 < ec <= 5000 or not 0 < ic <= 5000 or depends - eo != ec * 104 or eo - io != ic * 28:
        raise ValueError('Unexpected package table layout')
    extent = len(header)
    for i in range(ec):
        size, offset = struct.unpack_from('<qq', header, eo + i * 104 + 28)
        if not 0 <= size <= 8 * 1024 * 1024 or offset != extent:
            raise ValueError('Exports do not form a complete sequential extent')
        extent += size
    canonical, equivalent = equivalent_companions(root, manifest['records'], extent - len(header))
    filtered = dict(manifest, records=[canonical])
    # The existing package reader uses a module-scoped evidence directory.
    # Restore it after this synchronous inspection rather than change its API.
    previous = recovery.SOURCE
    try:
        recovery.SOURCE = root
        pkg = recovery.Package(row, filtered)
    finally:
        recovery.SOURCE = previous
    for export in pkg.exports:
        pkg.properties(export['index'])
    levels = [e for e in pkg.exports if e['outer_index'] == pkg.world_export
              and pkg.object(e['class_index']) == 'Level']
    if len(levels) != 1:
        raise ValueError('Root World does not own one Level')
    level = levels[0]
    active_tag = pkg.properties(level['index']).get('WorldSettings')
    if active_tag is None or active_tag['kind'] != 'ObjectProperty' or active_tag['size'] != 4:
        raise ValueError('Level has no typed WorldSettings reference')
    active_index = pkg.value(active_tag)
    if not 1 <= active_index <= len(pkg.exports):
        raise ValueError('Active WorldSettings is not a package export')
    active = pkg.exports[active_index - 1]
    if active['outer_index'] != level['index']:
        raise ValueError('Active WorldSettings belongs to another Level')
    settings = []
    for export in pkg.exports:
        cls = pkg.object(export['class_index'])
        if not cls or not cls.endswith('WorldSettings'):
            continue
        props = pkg.properties(export['index'])
        selected = [name for name in ('DefaultGameMode', 'MapType', 'bEnableLooting',
                    'SubsystemConfig', 'GameRuleSettingConfigClass') if name in props]
        settings.append({'export_index': export['index'], 'object_name': export['name'],
                         'class': import_reference(pkg, export['class_index']),
                         'active': export['index'] == active_index,
                         'properties': [property_evidence(pkg, props[name]) for name in selected]})
    active_settings = next(s for s in settings if s['active'])
    if not any(p['property_name'] == 'DefaultGameMode' for p in active_settings['properties']):
        raise ValueError('Active WorldSettings has no serialized DefaultGameMode')
    return dict(pkg.evidence(), equivalent_uexp_entries=[x['entry'] for x in equivalent],
                companion_association='complete_export_extent_identical_content_all_typed_export_tags',
                validated_export_tag_lists=len(pkg.exports), level_export=level['index'],
                level_world_settings=property_evidence(pkg, active_tag),
                world_settings_exports=settings, map_playable_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-directory', type=Path,
                        default=ROOT / 'evidence/dam_main_world_settings_20261005')
    parser.add_argument('--output', type=Path, default=ROOT / 'evidence/dam-active-world-settings-20261005.json')
    args = parser.parse_args()
    root = args.evidence_directory.resolve()
    evidence_root = (ROOT / 'evidence').resolve()
    if not root.is_relative_to(evidence_root) or not args.output.resolve().is_relative_to(evidence_root):
        raise ValueError('Input and output must stay inside the workspace evidence directory')
    raw_manifest = (root / 'manifest.json').read_bytes()
    manifest = json.loads(raw_manifest)
    results = []
    for row in manifest['records']:
        if row.get('kind') != 'uasset' or not TARGETS.intersection(row.get('package_references', [])):
            continue
        result = inspect_package(root, row, manifest)
        if result['package_path'] in TARGETS:
            results.append(result)
    if {r['package_path'] for r in results} != TARGETS or len(results) != len(TARGETS):
        raise ValueError('Expected Dam root packages are missing or duplicated')
    report = {'kind': 'typed_static_dam_active_world_settings',
              'manifest_sha256': hashlib.sha256(raw_manifest).hexdigest(),
              'source_archive_relative_path': manifest['archive_relative_path'],
              'source_archive_size': manifest['archive_size'], 'packages': results,
              'runtime_player_input_verified': False, 'map_playable_verified': False,
              'encrypted_entries_decoded': False, 'game_modified': False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'packages': len(results), 'typed_export_lists_verified': sum(
        p['validated_export_tag_lists'] for p in results), 'map_playable_verified': False}))


if __name__ == '__main__':
    main()
