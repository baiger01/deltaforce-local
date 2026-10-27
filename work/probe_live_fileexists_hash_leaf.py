"""Read the two fixed code extents following the captured directory-index route."""

import hashlib
import json
from pathlib import Path
import struct

import probe_live_fileexists_index_code as prior


getters = prior.getters
SOURCE_CAPTURE = getters.ROOT / 'work/evidence/live-package-fileexists-index-code-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = '1510c3b028ed4700feae13540f0701078b9aa02da3276058e03815d4825ad5a2'
EXTRA_SPANS = ((0x12468ef1, 45), (0x10b08d50, 64))
INDEX_HASHES = {
    0x12468dbc: 'b3e7329b9ea379cdb2ae6656d08fd981320c4e2e03b93a62edb67035a0ab8025',
    0x12468e73: '170c167e7141b182c75ee0d64fac9904519d93758aac08da2427784947b741ab',
    0x1246d870: 'e8a24b5343a7a7961ce27130e99c7a9cd0cbc6ce316c297b255002597a9ce1bb',
    0x10b25360: '2e06ac1f9417270c5109eb4bc1fa33b735350c1074dfd625553db38ec7f335ff',
}
METADATA = (
    ('closing_pdata', 511490940, 'f18e46121e8f461278f5801c', '2b213550492b66b2adbc5d5f988c6c37a06319d2060d2a4dabbcfed4fd9a41e9'),
    ('closing_unwind', 478210424, '21000000408d4612658d4612244de41b', '0fcd7db892e4ece814598c21e7c3b6218cbf8395a0d1fb44d02964920f4c1f03'),
    ('previous_pdata', 510281928, '148db010488db010a4db701c', '8c2c28d8a30866ea7399e0472762a6fa3a85c82913105b2314d14d9d480bbcba'),
    ('next_pdata', 510281940, '908db010698eb010083ae01b', '44c66634559a237be46574fb5fa5b2ab96427d266d7b48c0d2f70e954cf30ec7'),
)
DISK = (
    ('closing', 306611441, 45, 'acc2f4ab61ce711c6ad6ec7747c88f675580dbe422d3573dbe8507c9e4329281'),
    ('hash_leaf', 280003408, 64, 'c30212c9e3e41fb5fd252412426f3d294d62efc5c625b6d41cb699662d78eee7'),
)
verify_target = prior.verify_target
verify_previous_edges = prior.verify_previous_edges
verify_previous_continuations = prior.verify_previous_continuations
verify_previous_lookup = prior.verify_previous_lookup
verify_previous_lookup_body = prior.verify_previous_lookup_body


def verify_previous_index_code(blocks):
    if set(blocks) != set(INDEX_HASHES):
        raise ValueError('hash_leaf_source_index_coordinates_changed')
    for rva, size in prior.EXTRA_SPANS:
        raw = blocks[rva]
        if (not isinstance(raw, bytes) or len(raw) != size
                or hashlib.sha256(raw).hexdigest() != INDEX_HASHES[rva]):
            raise ValueError('hash_leaf_fresh_source_index_hash_changed')
    raw = blocks[0x1246d870]
    off = 0x1246d940 - 0x1246d870
    if (raw[off:off + 5] != bytes.fromhex('e80bb469fe')
            or 0x1246d940 + 5 + struct.unpack_from('<i', raw, off + 1)[0] != 0x10b08d50):
        raise ValueError('hash_leaf_source_exact_call_changed')
    raw = blocks[0x12468e73]
    if (raw[-2:] != bytes.fromhex('7e23')
            or 0x12468eef + 2 + struct.unpack('<b', raw[-1:])[0] != 0x12468f14):
        raise ValueError('hash_leaf_source_closing_branch_changed')


def load_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_saved_hash_leaf_source_required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_CAPTURE_SHA:
        raise ValueError('saved_hash_leaf_source_full_hash_changed')
    d = json.loads(raw)
    if (d.get('native_pe_sha256') != getters.SOURCE_PE
            or d.get('source_capture_sha256') != prior.SOURCE_CAPTURE_SHA
            or d.get('captured_bytes') != 2954 or d.get('data_qword_reads') != 6):
        raise ValueError('saved_hash_leaf_source_chain_changed')
    verify_previous_index_code({b['rva']: bytes.fromhex(b['bytes']) for b in d['index_code'].values()})
    return SOURCE_CAPTURE_SHA


def verify_segment_metadata(read_at):
    rows = {}
    for name, off, expected, digest in METADATA:
        raw = read_at(off, len(bytes.fromhex(expected)))
        if not isinstance(raw, bytes) or raw.hex() != expected or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('original_hash_leaf_metadata_changed_' + name)
        rows[name] = {'file_offset': off, 'bytes': raw.hex(), 'sha256': digest}
    begin, end, _ = struct.unpack('<III', bytes.fromhex(rows['closing_pdata']['bytes']))
    _, previous_end, _ = struct.unpack('<III', bytes.fromhex(rows['previous_pdata']['bytes']))
    next_begin, _, _ = struct.unpack('<III', bytes.fromhex(rows['next_pdata']['bytes']))
    if (begin != EXTRA_SPANS[0][0] or end - begin != 45
            or not previous_end <= 0x10b08d50 < next_begin
            or next_begin != 0x10b08d50 + 64
            or bytes.fromhex(rows['closing_unwind']['bytes'])[-12:] != bytes.fromhex(prior.prior.prior.METADATA[0][2])):
        raise ValueError('original_hash_leaf_extent_changed')
    result = {'metadata': rows, 'hash_leaf_pdata_coverage': False,
              'hash_leaf_scope': 'exact source direct call to next adjacent pdata begin; not a function extent claim'}
    for name, off, size, digest in DISK:
        raw = read_at(off, size)
        if not isinstance(raw, bytes) or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('original_hash_leaf_disk_changed_' + name)
        result[name] = {'disk_code_offset': off, 'bytes': size, 'sha256': digest}
    return result


def verify_original(path):
    extents = prior.verify_original(path)
    with Path(path).open('rb') as stream:
        def read_at(off, size):
            stream.seek(off)
            return stream.read(size)
        extents['hash_leaf'] = verify_segment_metadata(read_at)
    return extents


def capture(read, query, base, module_size, *, source_digest, actual_created, expected_created):
    getters.local.verify_creation(actual_created, expected_created)
    if source_digest != SOURCE_CAPTURE_SHA:
        raise ValueError('pinned_saved_hash_leaf_source_required')
    if (type(base) is not int or type(module_size) is not int
            or any(not 0 <= rva < rva + size <= module_size for rva, size in EXTRA_SPANS)):
        raise ValueError('fixed_hash_leaf_extents_outside_module')
    report = prior.capture(read, query, base, module_size, source_digest=prior.SOURCE_CAPTURE_SHA,
                           actual_created=actual_created, expected_created=expected_created)
    verify_previous_index_code({b['rva']: bytes.fromhex(b['bytes']) for b in report['index_code'].values()})
    blocks = {}
    for name, (rva, size) in zip(('LookupClosing', 'HashLeaf'), EXTRA_SPANS):
        raw = read(base + rva, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError('short_fixed_hash_leaf_read')
        blocks[name] = {'rva': rva, 'size': size, 'bytes': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest(),
                        'function_complete': False, 'pdata_segment_complete': name == 'LookupClosing'}
    report.update(source_capture_sha256=source_digest, captured_bytes=3063, hash_leaf_code=blocks,
                  scope=report['scope'] + '; exact closing45B and source-selected hash leaf64B; no new data')
    return report


if __name__ == '__main__':
    prior.prior.prior.prior.prior.prior.main(continuation=6)
