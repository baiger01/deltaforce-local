"""Read two fixed code extents reached by the saved filename lookup entry."""

import hashlib
import json
from pathlib import Path
import struct

import probe_live_fileexists_lookup as prior


getters = prior.getters
SOURCE_CAPTURE = getters.ROOT / 'work/evidence/live-package-fileexists-lookup-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = '954a416eefd8eef779b7f999623ff35eea1310b2029f17ed5e395b0add9d73a9'
LOOKUP_BYTES = bytes.fromhex('405355574883ec30498bf8488bda488be9e85aba000084c075084883c4305f5d5bc3488bd3')
LOOKUP_SHA = '5a266561d6a2dad813e2e1eae3b06326fc0bd771eb01bad8a057570960b5ccc9'
EXTRA_SPANS = ((0x12468d65, 87), (0x124747b0, 297))
METADATA = (
    ('body_pdata', 511490904, '658d4612bc8d46123cf5801c',
     '3906031d9818712dc989bde1407c863ca57bf86fabb630e5d2efc70b0d56e363'),
    ('body_unwind', 478210364, '2105020005640a00408d4612658d4612244de41b',
     '5a8b81243243e0a1b2a2b3dc7eac834701fa5466ef16b46fcda1bf62bc8440b5'),
    ('callee_pdata', 511492968, 'b0474712d9484712d4f4801c',
     'bdc41c59c8e17461136c171bd8050d46c073dfeca18986bd51f611bceeff3dfe'),
    ('callee_unwind', 478210260, '0138070038341b0010011c000470036002500000',
     '06062a7c08c706628e006d7059e9fac0fbc114e099a5e45183f3e387430732d3'),
)
DISK = (
    ('body', 306611045, 87, '43ea06c9d831d7772b22061e62d0f5b0ff98c7b1720f699b0f4a0c43677e3817'),
    ('callee', 306658736, 297, '84986d245ed61e3322c7073ff1c237355a0f9029c095a8fbbdfe8b6a451f9a4f'),
)
verify_target = prior.verify_target
verify_previous_edges = prior.verify_previous_edges
verify_previous_continuations = prior.verify_previous_continuations


def verify_previous_lookup(raw):
    if (not isinstance(raw, bytes) or raw != LOOKUP_BYTES
            or hashlib.sha256(raw).hexdigest() != LOOKUP_SHA):
        raise ValueError('lookup_body_fresh_entry_hash_or_edge_changed')
    if (raw[17:22] != bytes.fromhex('e85aba0000')
            or 0x12468d51 + 5 + struct.unpack_from('<i', raw, 18)[0] != EXTRA_SPANS[1][0]
            or raw[-3:] != bytes.fromhex('488bd3')
            or prior.LOOKUP_RVA + len(raw) != EXTRA_SPANS[0][0]):
        raise ValueError('lookup_body_exact_call_and_fallthrough_changed')


def load_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_saved_lookup_entry_source_required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_CAPTURE_SHA:
        raise ValueError('saved_lookup_entry_source_full_hash_changed')
    d = json.loads(raw)
    if (d.get('native_pe_sha256') != getters.SOURCE_PE
            or d.get('source_capture_sha256') != prior.SOURCE_CAPTURE_SHA
            or d.get('captured_bytes') != 1628 or d.get('data_qword_reads') != 6):
        raise ValueError('saved_lookup_entry_source_chain_changed')
    verify_previous_lookup(bytes.fromhex(d['lookup_code']['bytes']))
    return SOURCE_CAPTURE_SHA


def verify_segment_metadata(read_at):
    rows = {}
    for name, off, expected, digest in METADATA:
        raw = read_at(off, len(bytes.fromhex(expected)))
        if (not isinstance(raw, bytes) or raw.hex() != expected
                or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('original_lookup_body_metadata_changed_' + name)
        rows[name] = {'file_offset': off, 'bytes': raw.hex(), 'sha256': digest}
    result = {}
    for (name, off, size, digest), (rva, length) in zip(DISK, EXTRA_SPANS):
        pdata = bytes.fromhex(rows[name + '_pdata']['bytes'])
        begin, end, _ = struct.unpack('<III', pdata)
        raw = read_at(off, size)
        if (begin != rva or end - begin != length or length != size
                or not isinstance(raw, bytes) or len(raw) != size
                or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('original_lookup_body_extent_or_disk_changed_' + name)
        result[name] = {'begin_rva': begin, 'end_exclusive_rva': end, 'segment_bytes': size,
                        'metadata': rows, 'disk_code_offset': off, 'disk_code_sha256': digest}
    if bytes.fromhex(rows['body_unwind']['bytes'])[-12:] != bytes.fromhex(prior.METADATA[0][2]):
        raise ValueError('lookup_body_CHAININFO_parent_changed')
    return result


def verify_original(path):
    extents = prior.verify_original(path)
    with Path(path).open('rb') as stream:
        def read_at(off, size):
            stream.seek(off)
            return stream.read(size)
        extents['lookup_body'] = verify_segment_metadata(read_at)
    return extents


def capture(read, query, base, module_size, *, source_digest, actual_created, expected_created):
    getters.local.verify_creation(actual_created, expected_created)
    if source_digest != SOURCE_CAPTURE_SHA:
        raise ValueError('pinned_saved_lookup_entry_source_required')
    if (type(base) is not int or type(module_size) is not int
            or any(not 0 <= rva < rva + size <= module_size for rva, size in EXTRA_SPANS)):
        raise ValueError('fixed_lookup_body_extents_outside_module')
    report = prior.capture(read, query, base, module_size, source_digest=prior.SOURCE_CAPTURE_SHA,
                           actual_created=actual_created, expected_created=expected_created)
    verify_previous_lookup(bytes.fromhex(report['lookup_code']['bytes']))
    blocks = {}
    for name, (rva, size) in zip(('LookupBody', 'LookupInitialization'), EXTRA_SPANS):
        raw = read(base + rva, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError('short_fixed_lookup_body_code_read')
        blocks[name] = {'rva': rva, 'size': size, 'bytes': raw.hex(),
                        'sha256': hashlib.sha256(raw).hexdigest(),
                        'function_complete': False, 'pdata_segment_complete': True}
    report.update(source_capture_sha256=source_digest, captured_bytes=2012, lookup_body_code=blocks,
                  scope=report['scope'] + '; exact lookup87B and initialization297B code extents; no new data')
    return report


if __name__ == '__main__':
    prior.prior.prior.prior.main(continuation=4)
