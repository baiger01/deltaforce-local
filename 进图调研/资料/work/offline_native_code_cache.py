"""Small offline code-range queries from the private image cache.

Validate the pinned disk-only plan, manifest coverage, block paths and hashes.
Unavailable ranges are rejected. No process APIs, reconstruction or complete
decode claim; a non-atomic cache remains a sample of executable image pages.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_ROOT = ROOT/'work/native-code-cache'
PLAN = ROOT/'work/evidence/native-image-code-cache-plan.json'
PLAN_SHA = '950ed8b43e98c20329f86ebf1c410b637cc90d861f46390d34b1d7500b4202aa'
MAX_PLAN_BYTES, MAX_MANIFEST_BYTES, MAX_QUERY_BYTES = 65536, 32*1024*1024, 8192
SOURCE_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path, maximum, expected_sha=None):
    size = path.stat().st_size
    if not 0 < size <= maximum:
        raise ValueError('Cache JSON size budget mismatch')
    with path.open('rb') as stream:
        raw = stream.read(maximum+1)
    if len(raw) != size or expected_sha is not None and sha(raw) != expected_sha:
        raise ValueError('Cache JSON identity mismatch')
    return json.loads(raw), sha(raw)


def validate_manifest(output_dir, expected_manifest_sha=None):
    folder = Path(output_dir).resolve()
    if folder.parent != CACHE_ROOT.resolve() or not folder.is_dir():
        raise ValueError('Only a single private code-cache directory is supported')
    manifest_path = folder/'manifest.json'
    if manifest_path.resolve().parent != folder:
        raise ValueError('Cache manifest path escaped private directory')
    plan, _ = read_json(PLAN, MAX_PLAN_BYTES, PLAN_SHA)
    manifest, manifest_sha = read_json(manifest_path, MAX_MANIFEST_BYTES, expected_manifest_sha)
    if (manifest.get('kind') != 'private_file_backed_executable_code_cache' or
            manifest.get('client_sha256') != SOURCE_SHA or manifest.get('plan') != plan or
            manifest.get('status') not in ('code_cache_complete', 'code_cache_partial', 'code_cache_known_sender_mismatch') or
            type(manifest.get('complete')) is not bool or
            manifest.get('snapshot_is_atomic') is not False or
            any(manifest.get(key) is not False for key in ('client_launched', 'elevation_requested',
                'process_memory_written', 'live_data_object_read', 'original_game_modified',
                'reconstructed_executable', 'native_complete_decode_claimed'))):
        raise ValueError('Cache manifest provenance/status mismatch')
    rows = manifest.get('sections')
    if not isinstance(rows, list) or len(rows) != len(plan['sections']):
        raise ValueError('Cache manifest executable section set mismatch')
    available, requested, RPM_count = 0, 0, 0
    for actual, expected in zip(rows, plan['sections']):
        first = int(expected['rva'], 16)
        length = expected['file_backed_code_bytes']
        if (actual.get('index') != expected['index'] or actual.get('rva') != hex(first) or
                actual.get('bytes') != length or not isinstance(actual.get('blocks'), list)):
            raise ValueError('Cache manifest section bounds mismatch')
        cursor, section_available = first, 0
        if len(actual['blocks']) > (length+4095)//4096:
            raise ValueError('Cache manifest block count budget exceeded')
        for block in actual['blocks']:
            amount = block.get('bytes')
            if (block.get('rva') != hex(cursor) or type(amount) is not int or
                    not 0 < amount <= plan['maximum_RPM_bytes'] or cursor+amount > first+length or
                    type(block.get('available')) is not bool):
                raise ValueError('Cache block coverage/order/budget mismatch')
            if block['available']:
                name = f'section_{expected["index"]:02d}_rva_{cursor:08x}.code'
                code_sha = block.get('code_sha256')
                if (block.get('file') != name or not isinstance(code_sha, str) or len(code_sha) != 64 or
                        any(c not in '0123456789abcdef' for c in code_sha) or
                        'unavailable_reason' in block):
                    raise ValueError('Cache block path/hash identity mismatch')
                section_available += amount
                RPM_count += 1
                requested += amount
            else:
                if (block.get('unavailable_reason') not in ('query_unavailable', 'invalid_region_boundary',
                    'invalid_region_alignment', 'page_not_committed_executable_image', 'read_failed_or_incomplete') or
                        'file' in block or 'code_sha256' in block):
                    raise ValueError('Cache missing-block identity mismatch')
                if block['unavailable_reason'] == 'read_failed_or_incomplete':
                    requested += amount
                    RPM_count += 1
            cursor += amount
        if (cursor != first+length or actual.get('available_bytes') != section_available or
                actual.get('unavailable_bytes') != length-section_available):
            raise ValueError('Cache section full coverage accounting mismatch')
        available += section_available
    if (manifest.get('saved_code_bytes') != available or
            manifest.get('unavailable_bytes') != plan['maximum_code_bytes']-available or
            manifest.get('actual_RPM_count') != RPM_count or manifest.get('RPM_requested_bytes') != requested or
            manifest.get('scope_coverage_complete') is not (available == plan['maximum_code_bytes'])):
        raise ValueError('Cache manifest read/coverage accounting mismatch')
    comparisons = manifest.get('known_sender_comparisons')
    if not isinstance(comparisons, list) or len(comparisons) != len(plan['known_sender_targets']):
        raise ValueError('Cache known-sender comparison count mismatch')
    for row, expected in zip(comparisons, plan['known_sender_targets']):
        if (any(row.get(key) != expected[key] for key in ('name', 'rva')) or
                row.get('bytes') != expected['code_bytes'] or
                row.get('expected_code_sha256') != expected['expected_code_sha256'] or
                row.get('extra_live_reads') != 0 or type(row.get('available')) is not bool or
                type(row.get('matches_saved_native_sample')) is not bool or
                row['matches_saved_native_sample'] is not
                    (row['available'] and row.get('cache_code_sha256') == expected['expected_code_sha256'])):
            raise ValueError('Cache known-sender comparison identity mismatch')
    anchors_match = all(r['matches_saved_native_sample'] for r in comparisons)
    coverage = available == plan['maximum_code_bytes']
    expected_status = ('code_cache_complete' if coverage and anchors_match else
        'code_cache_known_sender_mismatch' if coverage else 'code_cache_partial')
    if manifest['complete'] is not (coverage and anchors_match) or manifest['status'] != expected_status:
        raise ValueError('Cache complete/status qualification mismatch')
    return folder, manifest, manifest_sha


def read_cached_code(output_dir, rva, length, expected_manifest_sha=None):
    if type(rva) is not int or type(length) is not int or not 0 <= rva < rva+length or not 0 < length <= MAX_QUERY_BYTES:
        raise ValueError('Offline cache query must be an exact positive range of at most8192 bytes')
    folder, manifest, _ = validate_manifest(output_dir, expected_manifest_sha)
    matches = [r for r in manifest['sections'] if int(r['rva'], 16) <= rva < rva+length <= int(r['rva'], 16)+r['bytes']]
    if len(matches) != 1:
        raise ValueError('Cache query is outside one pinned file-backed executable section')
    result = bytearray()
    cursor, end = rva, rva+length
    for block in matches[0]['blocks']:
        first, size = int(block['rva'], 16), block['bytes']
        if first+size <= cursor or first >= end:
            continue
        if not block['available']:
            raise ValueError('Cache query overlaps an unavailable code interval')
        path = folder/block['file']
        if path.resolve().parent != folder or path.stat().st_size != size:
            raise ValueError('Cache code-block path/size mismatch')
        with path.open('rb') as stream:
            code = stream.read(size+1)
        if len(code) != size or sha(code) != block['code_sha256']:
            raise ValueError('Cache code-block SHA mismatch')
        high = min(first+size, end)
        result.extend(code[cursor-first:high-first])
        cursor = high
    if cursor != end or len(result) != length:
        raise ValueError('Cache query has missing code coverage')
    return bytes(result)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--rva', type=lambda v: int(v, 0), required=True)
    parser.add_argument('--bytes', type=int, required=True)
    parser.add_argument('--manifest-sha256')
    args = parser.parse_args()
    code = read_cached_code(args.cache, args.rva, args.bytes, args.manifest_sha256)
    print('Offline cache range verified: RVA'+hex(args.rva)+', bytes'+str(len(code))+', SHA256 '+sha(code))
