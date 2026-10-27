"""Recheck only previously verified clear headers for exact object candidates."""

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re

from bundle_package_inventory import ROOT, source_targets, package
from scan_weapon_tables import parse_entry, decode_content
import oodle_payload_reader


INVENTORY = ROOT / 'work/evidence/bundle-all-pak-package-inventory-private.json'
OUTPUT = ROOT / 'work/evidence/bundle-pak-object-candidates-private.json'
SUMMARY = ROOT / 'work/evidence/bundle-pak-coverage-summary-20261005.json'
CDN_NAMES = re.compile(r'DefaultCDNUrl|CDNUrl_PC|CDNRoot|AppSetting|MapleSetting|CDNConfig|CDNPathConfig', re.I)


def main():
    raw = INVENTORY.read_bytes()
    report = json.loads(raw)
    if (report['complete'] is not True or report['pak_count_requested'] != 257
            or report['summary']['paks_to_data_limit'] != 257):
        raise ValueError('Incomplete installed package inventory')
    targets, references_hash = source_targets(ROOT / 'work/bundle_asset_locations.json')
    if report['references_sha256'] != references_hash or len(targets) != 497:
        raise ValueError('Reference manifest changed after inventory')
    source_directory = Path(report['source_directory']).resolve()
    oodle_payload_reader.PATH = source_directory.parent.parent / 'Binaries/Win64/oo2core_8_win64.dll'
    target_by_name = defaultdict(list)
    for target in targets:
        target_by_name[target.rsplit('/', 1)[-1].casefold()].append(target)
    results = {'source_inventory_sha256': hashlib.sha256(raw).hexdigest(),
        'scope': 'Re-read only verified clear package headers; no index payload or resource bodies saved',
        'object_candidates': [], 'basename_candidates': [], 'name_mentions': [],
        'cdn_configuration_name_candidates': [], 'errors': []}
    class_counts = Counter()
    class_package_sizes = defaultdict(list)
    verified = 0
    for pak in report['pak_results']:
        path = Path(pak['pak']).resolve()
        if path.parent != source_directory or path.stat().st_size != pak['size']:
            raise ValueError('Installed source PAK path/size changed')
        with path.open('rb') as handle:
            handle.seek(-512, 2)
            if hashlib.sha256(handle.read(512)).hexdigest() != pak['footer_sha256']:
                raise ValueError('Installed source PAK footer changed')
            for saved in pak.get('packages', []):
                try:
                    pos = saved['entry_header_offset']
                    try:
                        entry = parse_entry(handle, pos, pak['data_limit'])
                    except (ValueError, __import__('struct').error):
                        entry = parse_entry(handle, pos, pak['data_limit'], variant='observed_permutation')
                    if entry['flags'] & 1 or entry['uncompressed'] > report['max_decode_size']:
                        raise ValueError('Previously clear header range changed')
                    data = decode_content(handle, pos, entry, pak['compression_methods'], report['max_decode_size'])
                    if data is None or hashlib.sha256(data).hexdigest() != saved['payload_sha256']:
                        raise ValueError('Header payload SHA256 changed')
                    info = package(data)
                    if info is None or info['own_paths'] != saved['own_paths']:
                        raise ValueError('Parsed package header changed')
                    verified += 1
                    evidence = {'pak': path.name, 'entry': saved['entry'],
                        'entry_header_offset': pos, 'decoded_size': len(data),
                        'payload_sha256': saved['payload_sha256'], 'own_paths': info['own_paths']}
                    for class_name in set(saved['export_classes']):
                        class_counts[class_name] += 1
                        class_package_sizes[class_name].append(len(data))
                    for item in info['exports']:
                        matches = target_by_name.get(item['object'].casefold(), [])
                        if matches:
                            results['object_candidates'].append({**evidence,
                                'export_object': item, 'requested_paths': matches,
                                'requested_classes': sorted({r['class'] for target in matches
                                    for r in targets[target] if 'class' in r}),
                                'target_package_owner_verified': False})
                    for own in info['own_paths']:
                        matches = target_by_name.get(own.rsplit('/', 1)[-1].casefold(), [])
                        if matches:
                            results['basename_candidates'].append({**evidence,
                                'matched_actual_package': own, 'requested_paths': matches,
                                'target_package_owner_verified': False})
                    named = sorted({target for name in info['names']
                        for target in target_by_name.get(name.casefold(), [])})
                    if named:
                        results['name_mentions'].append({**evidence, 'requested_paths': named})
                    cdn_names = [name for name in info['names'] if CDN_NAMES.search(name)]
                    if cdn_names:
                        results['cdn_configuration_name_candidates'].append({**evidence, 'names': cdn_names})
                except Exception as error:
                    results['errors'].append({'pak': path.name, 'entry': saved['entry'],
                        'entry_header_offset': saved['entry_header_offset'],
                        'type': type(error).__name__, 'message': str(error)[:240]})
    expected = report['summary']['stats']['parsed_packages']
    if verified + len(results['errors']) != expected:
        raise ValueError('Header recheck accounting mismatch')
    OUTPUT.write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    sizes = {}
    for key in ('Texture2D', 'PaperSprite'):
        values = sorted(class_package_sizes[key])
        sizes[key] = {'count': len(values), 'maximum_size': max(values) if values else None,
                     'median_size': values[len(values) // 2] if values else None,
                     'scope': 'Only successfully parsed clear headers under the256KiB selection bound'}
    summary = {'scope': 'Installed Content/Paks header inventory, read-only,2026-10-05',
        'source_inventory_sha256': results['source_inventory_sha256'],
        'source_references_sha256': references_hash,
        'scan_region': 'Sequential serialized FPakEntry payloads from file offset0 to footer index_offset; encrypted index payload excluded',
        'package_header_definition': 'Payload with Unreal package tag and validated NameMap/ImportMap/ExportMap',
        'max_decoded_entry_size': report['max_decode_size'],
        'pak_count': 257, 'paks_reached_data_limit': 257, 'target_package_count': 497,
        'inventory_stats': report['summary']['stats'], 'verified_package_header_rechecks': verified,
        'object_candidate_count': len(results['object_candidates']),
        'package_basename_candidate_count': len(results['basename_candidates']),
        'name_mention_candidate_count': len(results['name_mentions']),
        'cdn_configuration_name_candidate_count': len(results['cdn_configuration_name_candidates']),
        'exact_fullpath_owner_count': report['summary']['owned_target_count'],
        'recheck_error_count': len(results['errors']), 'clear_header_class_package_counts': dict(class_counts),
        'observed_clear_image_header_sizes': sizes,
        'limitations': ['Encrypted payloads and clear entries above256KiB remain unresolved',
            'No target hit is not proof that a resource is absent',
            'Object-name/basename candidates do not prove target package ownership',
            'The package tag also occurs in compressed wrappers;855 unparsed tag matches are not counted as valid package headers',
            'No runtime loading or rendering was tested'],
        'private_candidate_report': OUTPUT.relative_to(ROOT).as_posix()}
    SUMMARY.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: summary[key] for key in (
        'verified_package_header_rechecks', 'object_candidate_count',
        'package_basename_candidate_count', 'name_mention_candidate_count',
        'cdn_configuration_name_candidate_count', 'recheck_error_count')}))
    print(json.dumps({'public_summary': SUMMARY.relative_to(ROOT).as_posix(),
                      'summary_sha256': hashlib.sha256(SUMMARY.read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()
