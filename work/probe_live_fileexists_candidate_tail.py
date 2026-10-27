"""Read the last exact source FileExists candidate-consumer code segment."""

import hashlib
import struct

import probe_live_fileexists_package_candidates as prior
from probe_live_fileexists_directory_state import pinned
from probe_live_fileexists_target import main


getters = prior.getters
SOURCE_CAPTURE = getters.ROOT / 'work/evidence/live-package-fileexists-candidate-consumer-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = '14fea8c378769561c19e4a15cc9e8974a0347228ab404ce1d90f5c721ecad76d'
EXTRA_SPANS = ((0x12467e5d, 73),)
HASHES = {0x12467d7d: 'b8af3bcaec551215a5c8a989ab84abcaed561d6ff309cc2a5efd61a27a76c39d',
          0x12467e48: '49e7dc707775e9658faf03be90e1e21172b11fc5e3083168cc8a7b7ecd367851'}
METADATA = (
    ('tail_pdata', 511490760, '5d7e4612a67e461238f9801c', 'f2755c5a11afb03a911a81fb6df0f29e1d22829d2b939c638f9ab5cd72059225'),
    ('tail_unwind', 478211384, '21000000a07c4612b27c4612ecf8801c', '9b67d3f38b3e9019808dcbd383423e6f44dc520220732a15ed02aa4965ef49d9'),
)
verify_target = prior.verify_target
verify_previous_edges = prior.verify_previous_edges
verify_previous_continuations = prior.verify_previous_continuations
verify_previous_lookup = prior.verify_previous_lookup
verify_previous_lookup_body = prior.verify_previous_lookup_body
verify_previous_index_code = prior.verify_previous_index_code
verify_previous_hash_leaf = prior.verify_previous_hash_leaf


def verify_previous_candidate(blocks):
    if set(blocks) != set(HASHES):
        raise ValueError('candidate_tail_source_coordinates_changed')
    for rva, size in prior.EXTRA_SPANS:
        raw = blocks[rva]
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != HASHES[rva]:
            raise ValueError('candidate_tail_fresh_source_changed')
    raw = blocks[0x12467e48]
    if raw[-2:] != bytes.fromhex('7409') or 0x12467e48 + len(raw) != EXTRA_SPANS[0][0]:
        raise ValueError('candidate_tail_source_branch_changed')


def load_source(path):
    d = pinned(path, SOURCE_CAPTURE_SHA)
    if d['captured_bytes'] != 3287 or d['native_pe_sha256'] != getters.SOURCE_PE:
        raise ValueError('candidate_tail_source_chain_changed')
    verify_previous_candidate({b['rva']: bytes.fromhex(b['bytes']) for b in d['package_candidate_code'].values()})
    return SOURCE_CAPTURE_SHA


def verify_original(path):
    extents = prior.verify_original(path)
    with open(path, 'rb') as f:
        for name, off, expected, digest in METADATA:
            f.seek(off); raw = f.read(len(bytes.fromhex(expected)))
            if raw.hex() != expected or hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError('candidate_tail_original_metadata_changed_' + name)
        f.seek(306607197); raw = f.read(73)
        if hashlib.sha256(raw).hexdigest() != '0b8d7e2015503856be68b85b952265466db3655d210bd2ae1c4f5e22064cd3d6':
            raise ValueError('candidate_tail_original_disk_changed')
    extents['candidate_tail'] = {'begin_rva': 0x12467e5d, 'end_exclusive_rva': 0x12467ea6, 'metadata': METADATA}
    return extents


def capture(read, query, base, module_size, *, source_digest, actual_created, expected_created):
    getters.local.verify_creation(actual_created, expected_created)
    if source_digest != SOURCE_CAPTURE_SHA or module_size < 0x12467ea6:
        raise ValueError('candidate_tail_source_or_scope_changed')
    report = prior.capture(read, query, base, module_size, source_digest=prior.SOURCE_CAPTURE_SHA,
                           actual_created=actual_created, expected_created=expected_created)
    verify_previous_candidate({b['rva']: bytes.fromhex(b['bytes']) for b in report['package_candidate_code'].values()})
    raw = read(base + 0x12467e5d, 73)
    if len(raw) != 73:
        raise ValueError('short_candidate_tail_read')
    report.update(source_capture_sha256=source_digest, captured_bytes=3360,
                  candidate_tail_code={'rva': 0x12467e5d, 'size': 73, 'bytes': raw.hex(),
                                       'sha256': hashlib.sha256(raw).hexdigest(), 'function_complete': False},
                  scope=report['scope'] + '; exact final candidate-consumer73B; no new data')
    return report


if __name__ == '__main__':
    main(continuation=9)
