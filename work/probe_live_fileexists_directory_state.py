"""Read source-pinned directory buckets for twelve original shop image filenames."""

import hashlib
import json
from pathlib import Path
import struct

import probe_live_fileexists_hash_leaf as prior
from probe_live_fileexists_package_candidates import verify_previous_hash_leaf
from probe_live_fileexists_receiver import canonical
from probe_live_fileexists_target import main


getters = prior.getters
SOURCE_CAPTURE = getters.ROOT / 'work/evidence/live-package-fileexists-hash-leaf-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = 'd5f6265c69bd00c6f62e51c9f26a5b7ac0a53734af67d3187b2b5fbc83b9b0f6'
CANDIDATES = getters.ROOT / 'work/evidence/storehot-twelve-filename-candidates-v2-20261005.json'
CANDIDATES_SHA = '64ad1491485238058dc69b7cb55d17365d96d582ada045dcd7cbff0aad4c65e6'
ACCESSOR_SOURCE = getters.ROOT / 'work/native-client-tests/1790852498680017300/keybox-registration-readonly-185.json'
ACCESSOR_SOURCE_SHA = '5d4acbe72d2ee450a31c8fcd29c9805947cab0531f727a70fa28744b65033182'
ACCESSOR_SLOT, ACCESSOR_RVA = 0x1d59de58, 0xd968d0
EXTRA_SPANS = ((ACCESSOR_SLOT, 8), (ACCESSOR_RVA, 4))
MAX_DATA_BYTES, MAX_CHAIN, MAX_COUNT = 32768, 32, 65536
FIELDS = ((4, 4, 'mask'), (0x10, 8, 'buckets'), (0x18, 8, 'next'),
          (0x28, 8, 'sorted_keys'), (0x30, 4, 'sorted_count'),
          (0x38, 8, 'records'), (0x40, 4, 'record_count'),
          (0x48, 8, 'extras'), (0x50, 4, 'extra_count'),
          (0x58, 4, 'busy'), (0x68, 4, 'pending_count'), (0x94, 4, 'processed_count'))
verify_target = prior.verify_target
verify_previous_edges = prior.verify_previous_edges
verify_previous_continuations = prior.verify_previous_continuations
verify_previous_lookup = prior.verify_previous_lookup
verify_previous_lookup_body = prior.verify_previous_lookup_body
verify_previous_index_code = prior.verify_previous_index_code


def pinned(path, sha, maximum=65536):
    raw = Path(path).read_bytes()
    if not 0 < len(raw) <= maximum or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('directory_source_full_hash_changed')
    return json.loads(raw)


def source_filenames():
    d = pinned(CANDIDATES, CANDIDATES_SHA)
    if d['native_pe_sha256'] != getters.SOURCE_PE or d['candidate_count'] != 12:
        raise ValueError('directory_source_filename_coordinates_changed')
    result = {}
    for row in d['candidates']:
        name = row['relative_filename_candidate']
        if not name.startswith('../../../DeltaForce/Content/') or not name.endswith('.uasset') or '\x00' in name:
            raise ValueError('directory_original_filename_changed')
        directory = name[:max(name.rfind('/'), name.rfind('\\'))]
        result.setdefault(directory, []).append({'tab_id': row['source_tab_id'], 'role': row['role'], 'filename': name})
    if len(result) != 4:
        raise ValueError('directory_source_requires_four_families')
    return result


def load_source(path):
    d = pinned(path, SOURCE_CAPTURE_SHA)
    if (d.get('native_pe_sha256') != getters.SOURCE_PE or d.get('source_capture_sha256') != prior.SOURCE_CAPTURE_SHA
            or d.get('captured_bytes') != 3063 or d.get('data_qword_reads') != 6):
        raise ValueError('directory_source_code_chain_changed')
    verify_previous_hash_leaf({b['rva']: bytes.fromhex(b['bytes']) for b in d['hash_leaf_code'].values()})
    old = pinned(ACCESSOR_SOURCE, ACCESSOR_SOURCE_SHA, 2 * 1024 * 1024)
    accessor = old['fixed_data']['datatable_content_data_accessor']
    if (accessor['rva'] != ACCESSOR_SLOT or accessor['size'] != 8
            or bytes.fromhex(accessor['bytes']) != struct.pack('<Q', 0x140000000 + ACCESSOR_RVA)
            or old['config_map']['allocation_accessor_rva'] != ACCESSOR_RVA
            or bytes.fromhex(old['config_map']['allocation_accessor_code_hex'])[:4] != bytes.fromhex('488b01c3')):
        raise ValueError('directory_source_array_accessor_changed')
    source_filenames()
    return SOURCE_CAPTURE_SHA


def verify_original(path):
    return prior.verify_original(path)


def native_directory_hash(text):
    lower = ''.join(chr(ord(ch) + 32) if 'A' <= ch <= 'Z' else ch for ch in text)
    value = 0x100000001b3
    for byte in lower.encode('utf-16le'):
        value = ((value ^ byte) * 0xcbf29ce484222325) & 0xffffffffffffffff
    return value


def check_data_read(address, size, base, module_size, used):
    if size not in (4, 8, 16) or used + size > MAX_DATA_BYTES:
        raise ValueError('directory_typed_data_budget_exceeded')
    canonical(address, size)
    if address < base + module_size and address + size > base:
        raise ValueError('directory_data_read_in_module_refused')


def capture(read, query, base, module_size, *, source_digest, actual_created, expected_created, after_accessor=None):
    getters.local.verify_creation(actual_created, expected_created)
    if source_digest != SOURCE_CAPTURE_SHA:
        raise ValueError('pinned_directory_source_required')
    filenames = source_filenames()
    report = prior.capture(read, query, base, module_size, source_digest=prior.SOURCE_CAPTURE_SHA,
                           actual_created=actual_created, expected_created=expected_created)
    verify_previous_hash_leaf({b['rva']: bytes.fromhex(b['bytes']) for b in report['hash_leaf_code'].values()})
    if (read(base + ACCESSOR_SLOT, 8) != struct.pack('<Q', base + ACCESSOR_RVA)
            or read(base + ACCESSOR_RVA, 4) != bytes.fromhex('488b01c3')):
        raise ValueError('directory_fresh_array_accessor_changed')
    if after_accessor is not None:
        after_accessor(read, base)
    used, reads = 0, 0
    def data(address, size):
        nonlocal used, reads
        check_data_read(address, size, base, module_size, used)
        region = query(address)
        if (region.get('state') != 0x1000 or region.get('protect', 0) & (0x100 | 1)
                or not region['base'] <= address < address + size <= region['base'] + region['size']):
            raise ValueError('directory_typed_range_unreadable')
        raw = read(address, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError('short_directory_typed_read')
        used += size
        reads += 1
        return raw
    top = int(report['receiver_pointer'], 16)
    index_raw = data(top + 8, 8)
    index = struct.unpack('<Q', index_raw)[0]
    rows = []
    header = {}
    status = 'index_not_present'
    if index:
        def state():
            return {name: int.from_bytes(data(index + off, size), 'little') for off, size, name in FIELDS}
        header = state()
        if header['busy'] or header['sorted_count'] != header['record_count'] or header['pending_count'] > header['processed_count']:
            status = 'index_requires_native_initialization_or_is_busy'
        else:
            count = header['sorted_count']
            mask = header['mask']
            if not 0 <= count <= MAX_COUNT or not 0 <= mask < MAX_COUNT or (mask + 1) & mask:
                raise ValueError('directory_index_shape_outside_source_bounds')
            status = 'source_directory_buckets_observed'
            for directory, images in filenames.items():
                hashed = native_directory_hash(directory)
                bucket = (hashed & 0xffff) & mask
                current = struct.unpack('<i', data(header['buckets'] + bucket * 4, 4))[0]
                seen, records = set(), []
                while current != -1:
                    if not 0 <= current < MAX_COUNT or current in seen or len(seen) >= MAX_CHAIN:
                        raise ValueError('directory_bucket_chain_invalid_or_outside_bound')
                    seen.add(current)
                    start, length = 0, count
                    while length:
                        half = length // 2
                        mid = start + half
                        key = struct.unpack('<I', data(header['sorted_keys'] + mid * 4, 4))[0]
                        if current >= key:
                            start = mid + (length & 1)
                        length = half
                    if not 0 <= start < header['record_count']:
                        raise ValueError('directory_candidate_record_index_outside_array')
                    raw = data(header['records'] + start * 16, 16)
                    records.append({'chain_index': current, 'record_index': start,
                                    'priority': struct.unpack_from('<I', raw)[0],
                                    'shared_record_pointer': hex(struct.unpack_from('<Q', raw, 8)[0])})
                    current = struct.unpack('<i', data(header['next'] + current * 4, 4))[0]
                rows.append({'directory': directory, 'source_images': images, 'hash': hex(hashed),
                             'bucket': bucket, 'bucket_candidate_records': records,
                             'additional_unindexed_records': header['extra_count'],
                             'native_FileExists_result_observed': False})
                if state() != header:
                    raise ValueError('directory_index_changed_during_queries')
        if state() != header:
            raise ValueError('directory_index_header_recheck_changed')
    if data(top + 8, 8) != index_raw:
        raise ValueError('directory_index_receiver_changed')
    report.update(source_capture_sha256=source_digest, captured_bytes=3075 + used,
                  additional_typed_bytes=used, additional_typed_reads=reads,
                  directory_index_header=header, directory_queries=rows, directory_status=status,
                  native_FileExists_result_observed=False, actual_archive_entry_resolved=False,
                  actual_render_proven=False, arbitrary_heap_scanned=False,
                  scope=report['scope'] + '; exact source array accessor; four original directory buckets only')
    return report


if __name__ == '__main__':
    main(continuation=8)
