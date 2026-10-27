"""Read-only installed PAK header ownership inventory for bundle UE references.

This never decrypts entries, starts the client, writes game files, or saves
resource bodies. Skipped and incomplete ranges remain explicitly unresolved.
"""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct
import time
from urllib.parse import urlsplit

from bundle_asset_locations_package import package
from local_game_paths import game_paths, project_path
from scan_weapon_tables import decode_content, parse_entry
import oodle_payload_reader

ROOT = Path(__file__).resolve().parent.parent


MAGIC = b'\xc1\x83\x2a\x9e'
DEFAULT_LIMIT = 256 * 1024
PUBLIC_URL = re.compile(
    rb'https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~%+()=/,-]{0,2048})?', re.I)
URL_PATH_BYTES = frozenset(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~%+()=/,-')


def public_cdn_urls(data):
    """Match only static resource URLs, excluding query/fragment and other fields."""
    result = []
    for encoding, projected, stride, parity in (
            ('ascii', data, 1, 0), ('utf-16-le', data[::2], 2, 0),
            ('utf-16-le', data[1::2], 2, 1)):
        for match in PUBLIC_URL.finditer(projected):
            if match.end() < len(projected) and projected[match.end()] in URL_PATH_BYTES:
                continue
            start, end = parity + stride * match.start(), parity + stride * match.end()
            if stride == 2 and data[start + 1:end:2] != bytes(match.end() - match.start()):
                continue
            url = match.group().decode('ascii')
            parts = urlsplit(url)
            host, path = (parts.hostname or '').lower(), parts.path
            source_host = (host == 'df.qq.com' or host.endswith('.df.qq.com') or
                           host == 'dfmobile.com' or host.endswith('.dfmobile.com'))
            static_path = path.startswith(('/G/', '/Resource/', '/resource/',
                                           '/Store/', '/static/', '/assets/', '/images/'))
            cdn_root = path in ('', '/') and any(label in ('cdn', 'resource', 'assets')
                                                for label in host.split('.'))
            if not (path.startswith('/G/CN/Resource/') or source_host and (static_path or cdn_root)):
                continue
            result.append({'url_without_query_or_fragment': url, 'string_offset': start,
                           'string_encoding': encoding,
                           'native_consumer_role_status': 'unknown_source_string_only'})
    return sorted(result, key=lambda row: (row['string_offset'], row['url_without_query_or_fragment']))


def source_targets(path):
    raw = path.read_bytes()
    document = json.loads(raw)
    targets = defaultdict(list)
    if 'entries' in document:
        rows = []
        for entry in document['entries']:
            source = {key: entry[key] for key in (
                'table', 'row', 'row_offset', 'tab_id', 'goods_id') if key in entry}
            rows.extend(dict(source, **resource) for resource in entry['resources'])
    elif 'references' in document:
        rows = document['references']
    else:
        raise ValueError('Expected public entries/resources or preserved references manifest')
    for row in rows:
        if row.get('kind') == 'local_ue_reference' and row.get('package_path'):
            target = row['package_path']
            if not isinstance(target, str) or not target.startswith('/Game/') or '.' in target:
                raise ValueError('Invalid source local package path')
            reference = {key: row[key] for key in (
                'table', 'row', 'row_offset', 'tab_id', 'goods_id', 'field_index',
                'source_field_index', 'role', 'class', 'object_path') if key in row}
            if 'source_field_index' in reference:
                reference.setdefault('field_index', reference['source_field_index'])
            targets[target].append(reference)
    expected = document.get('summary', {}).get('local_unique_package_count')
    if expected is not None and len(targets) != expected:
        raise ValueError('Reference manifest package count mismatch')
    if not targets:
        raise ValueError('Reference manifest contains no local package targets')
    return dict(targets), hashlib.sha256(raw).hexdigest()


def target_set_sha256(targets):
    raw = json.dumps(sorted(targets), ensure_ascii=True, separators=(',', ':')).encode('ascii')
    return hashlib.sha256(raw).hexdigest()


def coverage_summary(report, inventory_sha256):
    return {
        'scope': 'Installed PAK package-header coverage; no resource bodies copied',
        'source_inventory_sha256': inventory_sha256,
        'source_references_sha256': report['references_sha256'],
        'source_target_set_sha256': report.get('target_set_sha256'),
        'source_target_set_hash_status': ('recorded_by_inventory' if 'target_set_sha256' in report
                                          else 'not_recorded_in_preserved_inventory'),
        'scan_region': 'Serialized FPakEntry payloads from offset 0 to footer index_offset; index payload excluded',
        'package_header_definition': 'Unreal tag with validated NameMap/ImportMap/ExportMap',
        'max_decoded_entry_size': report['max_decode_size'],
        'pak_count_requested': report['pak_count_requested'],
        'inventory_finished': report['complete'],
        'coverage': report['summary'],
        'limitations': report['limitations'],
    }


def scan(path, targets, maximum, progress, cdn_urls=False):
    stats = Counter()
    targets_by_folded_path = defaultdict(list)
    for target in targets:
        targets_by_folded_path[target.casefold()].append(target)
    result = {'pak': str(path), 'size': path.stat().st_size, 'stats': {},
              'packages': [], 'matches': [], 'errors': [], 'scan_complete_to_data_limit': False}
    if cdn_urls:
        result['cdn_url_candidates'] = []
    with path.open('rb') as handle:
        if result['size'] < 512:
            result['errors'].append({'type': 'short_archive'})
            return result
        handle.seek(-512, 2)
        tail = handle.read(512)
        result['footer_sha256'] = hashlib.sha256(tail).hexdigest()
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        if marker < 0 or marker + 16 > len(tail):
            result['errors'].append({'type': 'missing_or_short_pak_footer'})
            return result
        version, limit = struct.unpack_from('<IQ', tail, marker + 4)
        result.update(footer_version=version, data_limit=limit)
        if not 0 <= limit <= result['size']:
            result['errors'].append({'type': 'invalid_pak_data_limit'})
            return result
        methods = [m[:-1].decode('ascii') for m in re.findall(
            rb'(?:Oodle|Zlib|Gzip|LZ4|Zstd)\x00', tail)]
        result['compression_methods'] = methods
        pos = number = 0
        while pos < limit:
            try:
                try:
                    entry = parse_entry(handle, pos, limit)
                except (ValueError, struct.error):
                    entry = parse_entry(handle, pos, limit, variant='observed_permutation')
            except (ValueError, struct.error) as error:
                aligned = ((pos + 2047) // 2048) * 2048
                handle.seek(pos)
                if (aligned <= pos or aligned >= limit or
                        handle.read(aligned - pos) != bytes(aligned - pos)):
                    stats['invalid_header_stop'] += 1
                    result['errors'].append({'type': 'invalid_entry_header',
                        'offset': pos, 'message': str(error)})
                    break
                try:
                    entry = parse_entry(handle, aligned, limit, variant='observed_permutation')
                except (ValueError, struct.error) as aligned_error:
                    stats['invalid_aligned_header_stop'] += 1
                    result['errors'].append({'type': 'invalid_aligned_entry_header',
                        'offset': aligned, 'message': str(aligned_error)})
                    break
                stats['alignment_padding_bytes'] += aligned - pos
                pos = aligned
            number += 1
            stats['headers'] += 1
            if entry['flags'] & 1:
                stats['encrypted_payload_skipped'] += 1
                stats['encrypted_uncompressed_bytes'] += entry['uncompressed']
            elif entry['uncompressed'] > maximum:
                stats['large_payload_skipped'] += 1
                stats['large_uncompressed_bytes'] += entry['uncompressed']
            else:
                try:
                    # Clear raw non-package prefixes need no resource-body read.
                    if not entry['method'] and not cdn_urls:
                        handle.seek(pos + entry['header_size'])
                        prefix = handle.read(min(4, entry['compressed']))
                        if prefix != MAGIC:
                            stats['raw_non_package_prefix'] += 1
                            pos = entry['next_pos']
                            progress(path.name, number, stats)
                            continue
                    data = decode_content(handle, pos, entry, methods, maximum)
                    if data is None:
                        stats['decode_unavailable'] += 1
                    elif len(data) != entry['uncompressed']:
                        stats['decode_length_mismatch'] += 1
                    else:
                        stats['decoded_entries'] += 1
                        stats['decoded_bytes'] += len(data)
                        if cdn_urls:
                            candidates = public_cdn_urls(data)
                            if candidates:
                                digest = hashlib.sha256(data).hexdigest()
                                result['cdn_url_candidates'].extend(dict(candidate,
                                    pak=path.name, entry=number, entry_header_offset=pos,
                                    payload_offset=pos + entry['header_size'],
                                    decoded_size=len(data), payload_sha256=digest,
                                    compression_method=entry['method']) for candidate in candidates)
                                stats['cdn_url_candidates'] += len(candidates)
                        if not data.startswith(MAGIC):
                            stats['decoded_non_package'] += 1
                        else:
                            stats['uasset_magic'] += 1
                            info = package(data)
                            if not info:
                                stats['package_summary_unparsed'] += 1
                            else:
                                stats['parsed_packages'] += 1
                                stats['parsed_owner_paths'] += len(info['own_paths'])
                                digest = hashlib.sha256(data).hexdigest()
                                result['packages'].append({'entry': number,
                                    'entry_header_offset': pos, 'decoded_size': len(data),
                                    'payload_sha256': digest, 'own_paths': info['own_paths'],
                                    'export_classes': sorted({row['class'] for row in info['exports']
                                                              if row['class'] is not None}),
                                    'name_count': info['name_count']})
                                exact = sorted({target for name in info['own_paths']
                                    for target in targets_by_folded_path.get(name.casefold(), [])})
                                mentions = sorted({target for name in info['names']
                                    for target in targets_by_folded_path.get(name.casefold(), [])})
                                if exact or mentions:
                                    record = {'entry': number, 'entry_header_offset': pos,
                                        'payload_offset': pos + entry['header_size'],
                                        'decoded_size': len(data),
                                        'payload_sha256': digest,
                                        'compression_method': entry['method'],
                                        'own_paths': info['own_paths'],
                                        'exact_owned_targets': exact,
                                        'exact_named_targets': mentions,
                                        'exports': info['exports'], 'imports': info['imports'],
                                        'name_count': info['name_count']}
                                    result['matches'].append(record)
                                    stats['matching_owner_entries'] += bool(exact)
                                    stats['matching_name_entries'] += bool(mentions)
                except Exception as error:
                    stats['payload_error_' + type(error).__name__] += 1
                    if len(result['errors']) < 30:
                        result['errors'].append({'type': type(error).__name__,
                            'entry': number, 'offset': pos, 'message': str(error)[:240]})
            pos = entry['next_pos']
            progress(path.name, number, stats)
        result.update(final_data_offset=pos, scan_complete_to_data_limit=pos == limit,
                      stats=dict(stats))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--references', type=Path,
                        default=ROOT / 'outputs/df-local-server/protocol/premium_shop_resources.json')
    parser.add_argument('--output', type=Path,
                        default=ROOT / 'work/evidence/bundle-all-pak-package-inventory-private.json')
    parser.add_argument('--max-size', type=int, default=DEFAULT_LIMIT)
    parser.add_argument('--coverage-output', type=Path,
                        help='Optional compact public coverage metadata; no package or class lists')
    parser.add_argument('--cdn-url-candidates', action='store_true',
                        help='Search bounded clear entries for static public CDN URLs; queries/fragments excluded')
    parser.add_argument('--source-game', type=Path)
    parser.add_argument('--expected-pak-count', type=int, default=257)
    parser.add_argument('--pak-name', action='append')
    args = parser.parse_args()
    args.references = project_path(args.references, ROOT)
    args.output = project_path(args.output, ROOT)
    if args.coverage_output:
        args.coverage_output = project_path(args.coverage_output, ROOT)
    if not 0 < args.max_size <= 4 * 1024 * 1024:
        raise ValueError('Decode limit must be at most4 MiB')
    if args.output.resolve().parent != (ROOT / 'work/evidence').resolve():
        raise ValueError('Private generated report must stay in work/evidence')
    targets, source_hash = source_targets(args.references)
    source_root = game_paths(source=args.source_game)[0]
    directory = source_root / 'DeltaForce/Content/Paks'
    if not directory.is_dir():
        parser.error(f'Installed Content/Paks directory is unavailable: {directory}; use --source-game or DF_LOCAL_SOURCE_GAME')
    if args.coverage_output:
        _, shadow_root = game_paths(source=args.source_game)
        if any(args.coverage_output.is_relative_to(root) for root in (source_root, shadow_root)):
            raise ValueError('Coverage output must stay outside installed and shadow game trees')
        if args.coverage_output == args.output or args.coverage_output == args.references:
            raise ValueError('Coverage output must not replace the private report or source manifest')
    # The codec helper resolves its path at import; use the same explicit source.
    oodle_payload_reader.PATH = source_root / 'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    if not oodle_payload_reader.PATH.is_file():
        raise ValueError('The installed bounded decompression codec is unavailable')
    paths = sorted(directory.glob('*.pak'), key=lambda p: p.name)
    if args.pak_name:
        paths = [path for path in paths if path.name in args.pak_name]
        if len(paths) != len(set(args.pak_name)):
            raise ValueError('Requested PAK names did not match exact installed files')
    elif len(paths) != args.expected_pak_count:
        raise ValueError(f'Installed PAK count mismatch: {len(paths)} vs {args.expected_pak_count}')
    if not paths:
        raise ValueError('No installed PAK files selected')
    report = {'scope': 'Installed PAKs read-only; bounded clear package payloads only',
        'source_directory': str(directory), 'references_sha256': source_hash,
        'references_file': args.references.name, 'target_set_sha256': target_set_sha256(targets),
        'max_decode_size': args.max_size, 'target_count': len(targets),
        'pak_count_requested': len(paths), 'pak_results': [], 'owners': {},
        'cdn_url_search_enabled': args.cdn_url_candidates,
        'path_comparison': 'Full package path casefold equality; original names retained',
        'unresolved_targets': sorted(targets), 'complete': False,
        'limitations': ['Encrypted payloads are skipped',
            'Entries larger than max_decode_size are skipped',
            'An unresolved target is not evidence of absence',
            'Package-header ownership does not prove runtime load or rendering']}
    print(json.dumps({'start': True, 'paks': len(paths), 'targets': len(targets),
                      'max_decode_size': args.max_size}), flush=True)
    started = last_progress = time.monotonic()
    totals = Counter()

    def progress(name, number, stats):
        nonlocal last_progress
        now = time.monotonic()
        if now - last_progress >= 25:
            print(json.dumps({'progress_pak': name, 'entry': number,
                'completed_paks': len(report['pak_results']),
                'elapsed_seconds': round(now - started),
                'parsed_packages_this_pak': stats.get('parsed_packages', 0),
                'owned_target_count': len(report['owners'])}), flush=True)
            last_progress = now

    for index, path in enumerate(paths, 1):
        try:
            result = scan(path, targets, args.max_size, progress, args.cdn_url_candidates)
        except Exception as error:
            result = {'pak': str(path), 'stats': {}, 'packages': [], 'matches': [],
                'scan_complete_to_data_limit': False,
                'errors': [{'type': type(error).__name__, 'message': str(error)[:240]}]}
        report['pak_results'].append(result)
        totals.update(result['stats'])
        for match in result['matches']:
            for target in match['exact_owned_targets']:
                report['owners'].setdefault(target, []).append({
                    'pak': str(path), 'entry': match['entry'],
                    'entry_header_offset': match['entry_header_offset'],
                    'payload_sha256': match['payload_sha256'],
                    'exports': match['exports'], 'references': targets[target]})
        report['unresolved_targets'] = sorted(targets.keys() - report['owners'].keys())
        report['summary'] = {'paks_processed': len(report['pak_results']),
            'paks_to_data_limit': sum(row['scan_complete_to_data_limit'] for row in report['pak_results']),
            'owned_target_count': len(report['owners']),
            'unresolved_target_count': len(report['unresolved_targets']), 'stats': dict(totals)}
        report['elapsed_seconds'] = round(time.monotonic() - started, 2)
        report['complete'] = index == len(paths)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        if index % 10 == 0 or result['matches'] or index == len(paths):
            print(json.dumps({'completed_paks': index, 'total_paks': len(paths),
                'owned_target_count': len(report['owners']),
                'headers': totals['headers'], 'parsed_packages': totals['parsed_packages'],
                'encrypted_skipped': totals['encrypted_payload_skipped'],
                'large_skipped': totals['large_payload_skipped'],
                'paks_to_data_limit': report['summary']['paks_to_data_limit']}), flush=True)
    print(json.dumps({'report': str(args.output), 'summary': report['summary'],
                      'elapsed_seconds': report['elapsed_seconds']}), flush=True)
    if args.coverage_output:
        raw = args.output.read_bytes()
        coverage = coverage_summary(report, hashlib.sha256(raw).hexdigest())
        args.coverage_output.parent.mkdir(parents=True, exist_ok=True)
        args.coverage_output.write_text(json.dumps(coverage, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'coverage_report': str(args.coverage_output)}), flush=True)


if __name__ == '__main__':
    main()
