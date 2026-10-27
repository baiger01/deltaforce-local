"""Read the exact source-selected per-package file lookup code family."""

import hashlib
import struct

import probe_live_fileexists_candidate_tail as prior
from probe_live_fileexists_directory_state import pinned
from probe_live_fileexists_target import main


getters = prior.getters
SOURCE_CAPTURE = getters.ROOT / 'work/evidence/live-package-fileexists-candidate-tail-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = '91f68d5f2d5732928de473c72f84f386844f02a9398f14e15658943ce0d5a209'
EXTRA_SPANS = ((0x12467eb0, 312), (0x12467fe8, 718))
METADATA = (
    ('entry_pdata', 511490772, 'b07e4612e87f4612c0f8801c', '0e7e7f2298ff653fe07a8a2548d1371f22602d42dcfbb53f5fa517d935493e35'),
    ('entry_unwind', 478211264, '01a30900a3740c0017c213f011e00fc00d600c500b300000', 'af416761ea4507e844fe7c4829b1634e46ee2b833be40fd301a1dc8a777b086e'),
    ('body_pdata', 511490784, 'e87f4612b6824612d8f8801c', '68f5edeb06c44b7fb280d140b1f6cc0d199e2a5f3f93aef5872d8b0c2bd64d72'),
    ('body_unwind', 478211288, '2105020005d40b00b07e4612e87f4612c0f8801c', 'a6c4a0eec1b0f1efc7cf8cfcc24a420cd7aaa58fe7e18e63bedd6c810355a3bc'),
)
DISK = ((306607280, 312, '306043467e44cbb481fab1e4929d253a4e524c833959161cbdaf2e67f2cbef25'),
        (306607592, 718, 'a6cecafd877d2d9c4a10230bb6f6c4295ca11717b7bd9737c338bc1a04464f13'))
verify_target = prior.verify_target
verify_previous_edges = prior.verify_previous_edges
verify_previous_continuations = prior.verify_previous_continuations
verify_previous_lookup = prior.verify_previous_lookup
verify_previous_lookup_body = prior.verify_previous_lookup_body
verify_previous_index_code = prior.verify_previous_index_code
verify_previous_hash_leaf = prior.verify_previous_hash_leaf
verify_previous_candidate = prior.verify_previous_candidate


def verify_previous_candidate_tail(raw):
    if len(raw) != 73 or hashlib.sha256(raw).hexdigest() != '9778bad98759c6c730ada0420c680b3c37fb196796c13e6fb033fb1cb6628099':
        raise ValueError('pak_lookup_fresh_source_tail_changed')
    off = 0x12467e7c - 0x12467e5d
    if raw[off] != 0xe8 or 0x12467e7c + 5 + struct.unpack_from('<i', raw, off + 1)[0] != 0x12467eb0:
        raise ValueError('pak_lookup_exact_source_call_changed')


def load_source(path):
    d = pinned(path, SOURCE_CAPTURE_SHA)
    if d['captured_bytes'] != 3360 or d['native_pe_sha256'] != getters.SOURCE_PE:
        raise ValueError('pak_lookup_source_chain_changed')
    verify_previous_candidate_tail(bytes.fromhex(d['candidate_tail_code']['bytes']))
    return SOURCE_CAPTURE_SHA


def verify_original(path):
    extents = prior.verify_original(path)
    with open(path, 'rb') as f:
        for name, off, expected, digest in METADATA:
            f.seek(off); raw = f.read(len(bytes.fromhex(expected)))
            if raw.hex() != expected or hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError('pak_lookup_original_metadata_changed_' + name)
        for off, size, digest in DISK:
            f.seek(off)
            if hashlib.sha256(f.read(size)).hexdigest() != digest:
                raise ValueError('pak_lookup_original_disk_changed')
    extents['pak_lookup'] = {'fixed_spans': EXTRA_SPANS, 'metadata': METADATA}
    return extents


def capture(read, query, base, module_size, *, source_digest, actual_created, expected_created):
    getters.local.verify_creation(actual_created, expected_created)
    if source_digest != SOURCE_CAPTURE_SHA or module_size < 0x124682b6:
        raise ValueError('pak_lookup_source_or_scope_changed')
    report = prior.capture(read, query, base, module_size, source_digest=prior.SOURCE_CAPTURE_SHA,
                           actual_created=actual_created, expected_created=expected_created)
    verify_previous_candidate_tail(bytes.fromhex(report['candidate_tail_code']['bytes']))
    blocks = {}
    for name, (rva, size) in zip(('PakLookupEntry', 'PakLookupBody'), EXTRA_SPANS):
        raw = read(base + rva, size)
        if len(raw) != size:
            raise ValueError('short_pak_lookup_code_read')
        blocks[name] = {'rva':rva, 'size':size, 'bytes':raw.hex(), 'sha256':hashlib.sha256(raw).hexdigest(),
                        'function_complete':False, 'pdata_segment_complete':True}
    report.update(source_capture_sha256=source_digest, captured_bytes=4390, pak_lookup_code=blocks,
                  scope=report['scope'] + '; exact source-selected per-package lookup312B+718B; no new data')
    return report


if __name__ == '__main__':
    main(continuation=10)
