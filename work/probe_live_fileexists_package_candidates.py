"""Read two exact candidate-consumer code segments of the source FileExists route."""

import hashlib
import json
from pathlib import Path
import struct

import probe_live_fileexists_hash_leaf as prior


getters = prior.getters
SOURCE_CAPTURE = getters.ROOT / 'work/evidence/live-package-fileexists-hash-leaf-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = 'd5f6265c69bd00c6f62e51c9f26a5b7ac0a53734af67d3187b2b5fbc83b9b0f6'
EXTRA_SPANS = ((0x12467d7d, 203), (0x12467e48, 21))
HASHES = {0x12468ef1: 'f9bfec9b70e2c090ec36ea616eda3c6a11753f6061a1e6308f662b0a26f2d6bd',
          0x10b08d50: '1afab9eda08b18002b7640b857e0a7be8da1771bc0da25ff47debe9a80ee4c36'}
METADATA = (
    ('fallback_pdata', 511490736, '7d7d4612487e461214f9801c', '37ef4f5a58d2fc0dc36925b5ecd97d70874eebf371cb47f55ce3dbc11402b569'),
    ('fallback_unwind', 478211348, '2108020008e41300b27c46127d7d4612fcf8801c', 'c56351e884df593a6a5197f07f99ca2d94f84d2a69ac19f15aa2ab9de0ac88a4'),
    ('candidate_pdata', 511490748, '487e46125d7e461228f9801c', '9da3129ad314e07523ff09ac0106ae38fee358d005f2ec09c43209132a535a56'),
    ('candidate_unwind', 478211368, '21000000b27c46127d7d4612fcf8801c', 'c0cad0bf2f700364aea29639cc975f305b61f50927f0fbd177b5f2086964c296'),
)
DISK = (
    ('fallback', 306606973, 203, 'be4364ae2339476bade7dbd2fe6c9833bf261a80841a9eb26c2f2b1e9448fe44'),
    ('candidate', 306607176, 21, '1624608ae7cc64cc7e083086c8e35c170199af26002dd98137f4c88527fa9b37'),
)
verify_target = prior.verify_target
verify_previous_edges = prior.verify_previous_edges
verify_previous_continuations = prior.verify_previous_continuations
verify_previous_lookup = prior.verify_previous_lookup
verify_previous_lookup_body = prior.verify_previous_lookup_body
verify_previous_index_code = prior.verify_previous_index_code


def verify_previous_hash_leaf(blocks):
    if set(blocks) != set(HASHES):
        raise ValueError('candidate_source_hash_leaf_coordinates_changed')
    for rva, size in prior.EXTRA_SPANS:
        raw = blocks[rva]
        if not isinstance(raw, bytes) or len(raw) != size or hashlib.sha256(raw).hexdigest() != HASHES[rva]:
            raise ValueError('candidate_fresh_hash_leaf_changed')


def load_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_saved_candidate_source_required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_CAPTURE_SHA:
        raise ValueError('saved_candidate_source_full_hash_changed')
    d = json.loads(raw)
    if (d.get('native_pe_sha256') != getters.SOURCE_PE or d.get('source_capture_sha256') != prior.SOURCE_CAPTURE_SHA
            or d.get('captured_bytes') != 3063 or d.get('data_qword_reads') != 6):
        raise ValueError('saved_candidate_source_chain_changed')
    verify_previous_hash_leaf({b['rva']: bytes.fromhex(b['bytes']) for b in d['hash_leaf_code'].values()})
    return SOURCE_CAPTURE_SHA


def verify_segment_metadata(read_at):
    rows = {}
    for name, off, expected, digest in METADATA:
        raw = read_at(off, len(bytes.fromhex(expected)))
        if not isinstance(raw, bytes) or raw.hex() != expected or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('original_candidate_metadata_changed_' + name)
        rows[name] = {'file_offset': off, 'bytes': raw.hex(), 'sha256': digest}
    for (name, off, size, digest), (rva, length) in zip(DISK, EXTRA_SPANS):
        begin, end, _ = struct.unpack('<III', bytes.fromhex(rows[name + '_pdata']['bytes']))
        raw = read_at(off, size)
        if begin != rva or end - begin != length or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('original_candidate_extent_or_disk_changed_' + name)
    return rows


def verify_original(path):
    extents = prior.verify_original(path)
    with Path(path).open('rb') as stream:
        def read_at(off, size):
            stream.seek(off)
            return stream.read(size)
        extents['package_candidate_consumer'] = verify_segment_metadata(read_at)
    return extents


def capture(read, query, base, module_size, *, source_digest, actual_created, expected_created):
    getters.local.verify_creation(actual_created, expected_created)
    if source_digest != SOURCE_CAPTURE_SHA:
        raise ValueError('pinned_saved_candidate_source_required')
    if any(not 0 <= rva < rva + size <= module_size for rva, size in EXTRA_SPANS):
        raise ValueError('fixed_candidate_extents_outside_module')
    report = prior.capture(read, query, base, module_size, source_digest=prior.SOURCE_CAPTURE_SHA,
                           actual_created=actual_created, expected_created=expected_created)
    verify_previous_hash_leaf({b['rva']: bytes.fromhex(b['bytes']) for b in report['hash_leaf_code'].values()})
    blocks = {}
    for name, (rva, size) in zip(('PackageFallback', 'CandidateConsumerEntry'), EXTRA_SPANS):
        raw = read(base + rva, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError('short_fixed_candidate_code_read')
        blocks[name] = {'rva': rva, 'size': size, 'bytes': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest(),
                        'function_complete': False, 'pdata_segment_complete': True}
    report.update(source_capture_sha256=source_digest, captured_bytes=3287, package_candidate_code=blocks,
                  scope=report['scope'] + '; exact fallback203B/candidate-consumer21B; no new data')
    return report


if __name__ == '__main__':
    prior.prior.prior.prior.prior.prior.prior.main(continuation=7)
