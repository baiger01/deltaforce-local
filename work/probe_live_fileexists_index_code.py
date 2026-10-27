"""Read exact source-backed filename normalization, hashing and index branches."""

import hashlib
import json
from pathlib import Path
import struct

import probe_live_fileexists_lookup_body as prior


getters = prior.getters
SOURCE_CAPTURE = getters.ROOT / 'work/evidence/live-package-fileexists-lookup-body-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = '40b424d5d49d6b1ad51d1d13a566176c09fdb82b33d9362228f8c662e3ea5405'
EXTRA_SPANS = ((0x12468dbc, 183), (0x12468e73, 126), (0x1246d870, 269), (0x10b25360, 364))
BODY_HASHES = {
    0x12468d65: '651bb31f97440d1280ca84ac44192495fe8cca53dc5a7c40a398b5496463a285',
    0x124747b0: '2c85c81a444d6d2903616d4d73f00474e8071b4d582e26de284ea0733f76547c',
}
METADATA = (
    ('chain_pdata', 511490916, 'bc8d4612738e461250f5801c', '3ac9ca6bfe5ac3239341e9c9212c7a0257b6fc7d389385d7b01f506d876e85cd'),
    ('chain_unwind', 478210384, '210a04000ae40b0005f40c00658d4612bc8d46123cf5801c', 'c10949cb5c529545084ec74bc4d304902d1f8fc162d9c75f020096b481a8966a'),
    ('tail_pdata', 511490928, '738e4612f18e461268f5801c', '69ac842b9407dc3e39931c97201789944bb60df9e9e76b6f2f3e7703f8b8d73c'),
    ('tail_unwind', 478210408, '21000000658d4612bc8d46123cf5801c', '0da149a9ba731306438f4ead092051f553eeb8dd77e3b31f83c91aa0dc064654'),
    ('hash_pdata', 511491996, '70d846127dd94612b8ee801c', 'ce62a98b523fbcc018611aa4ae7f3e090f057ab15c7bd3873fd2ade6211df8ff'),
    ('hash_unwind', 478208696, '1927090015544e0015344c00150148000ee00c700b600000ec929714', 'e7a677cce449cbac652313561f235da59030f7b4b25ddf2e8f34b1078a9ce45d'),
    ('normalize_pdata', 510289032, '6053b210cc54b2107403711c', '9a39ea922fe6872326063e98dc2fc41a6795f23579f37fd35489a14eba51aeec'),
    ('normalize_unwind', 477165428, '01a00a00a054080015740b0015640a0015340900155211e0', '8f2ecf55b70c525c368c6f5ed0437f48ca0e4af5b5d19e349536fd272e677a6f'),
)
DISK = (
    ('chain', 306611132, 183, '0d8bcaef21fbd46f12ec5ec22c5066b89133a74055dcb7b7b52f59d2e1b8b352'),
    ('tail', 306611315, 126, 'c11361b33bdf533f6c96e08046d201e6f3d6ad8d1424b3e80b5ae42ef6bd06bc'),
    ('hash', 306630256, 269, 'baab4c94f87ad5fee65b68c2bd4c754aa325ac9ca8b4d909f2808b1375567275'),
    ('normalize', 280119648, 364, '0b0922b6e805c5dda2bdd75600c99c98f0d4f45bb86f53423b30f821f63c79e0'),
)
verify_target = prior.verify_target
verify_previous_edges = prior.verify_previous_edges
verify_previous_continuations = prior.verify_previous_continuations
verify_previous_lookup = prior.verify_previous_lookup


def verify_previous_lookup_body(blocks):
    if set(blocks) != set(BODY_HASHES):
        raise ValueError('index_source_body_coordinates_changed')
    for rva, size in prior.EXTRA_SPANS:
        raw = blocks[rva]
        if (not isinstance(raw, bytes) or len(raw) != size
                or hashlib.sha256(raw).hexdigest() != BODY_HASHES[rva]):
            raise ValueError('index_fresh_source_body_hash_changed')
    raw = blocks[0x12468d65]
    for address, target, expected in (
            (0x12468d6f, 0x10b25360, 'e8ecc56bfe'),
            (0x12468d91, 0x1246d870, 'e8da4a0000')):
        off = address - 0x12468d65
        if (raw[off:off + 5] != bytes.fromhex(expected)
                or address + 5 + struct.unpack_from('<i', raw, off + 1)[0] != target):
            raise ValueError('index_source_exact_helper_call_changed')
    if (raw[-6:] != bytes.fromhex('0f84b7000000')
            or 0x12468db6 + 6 + struct.unpack_from('<i', raw, len(raw) - 4)[0] != 0x12468e73
            or 0x12468d65 + len(raw) != 0x12468dbc):
        raise ValueError('index_source_bucket_miss_and_fallthrough_changed')


def load_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_saved_index_code_source_required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_CAPTURE_SHA:
        raise ValueError('saved_index_code_source_full_hash_changed')
    d = json.loads(raw)
    if (d.get('native_pe_sha256') != getters.SOURCE_PE
            or d.get('source_capture_sha256') != prior.SOURCE_CAPTURE_SHA
            or d.get('captured_bytes') != 2012 or d.get('data_qword_reads') != 6):
        raise ValueError('saved_index_code_source_chain_changed')
    verify_previous_lookup_body({b['rva']: bytes.fromhex(b['bytes']) for b in d['lookup_body_code'].values()})
    return SOURCE_CAPTURE_SHA


def verify_segment_metadata(read_at):
    rows = {}
    for name, off, expected, digest in METADATA:
        raw = read_at(off, len(bytes.fromhex(expected)))
        if (not isinstance(raw, bytes) or raw.hex() != expected or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('original_index_metadata_changed_' + name)
        rows[name] = {'file_offset': off, 'bytes': raw.hex(), 'sha256': digest}
    result = {}
    for (name, off, size, digest), (rva, length) in zip(DISK, EXTRA_SPANS):
        begin, end, _ = struct.unpack('<III', bytes.fromhex(rows[name + '_pdata']['bytes']))
        raw = read_at(off, size)
        if (begin != rva or end - begin != size or size != length
                or not isinstance(raw, bytes) or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('original_index_extent_or_disk_changed_' + name)
        result[name] = {'begin_rva': begin, 'end_exclusive_rva': end, 'segment_bytes': size,
                        'metadata': rows, 'disk_code_offset': off, 'disk_code_sha256': digest}
    for name in ('chain', 'tail'):
        if bytes.fromhex(rows[name + '_unwind']['bytes'])[-12:] != bytes.fromhex(prior.METADATA[0][2]):
            raise ValueError('index_CHAININFO_parent_changed_' + name)
    return result


def verify_original(path):
    extents = prior.verify_original(path)
    with Path(path).open('rb') as stream:
        def read_at(off, size):
            stream.seek(off)
            return stream.read(size)
        extents['index_code'] = verify_segment_metadata(read_at)
    return extents


def capture(read, query, base, module_size, *, source_digest, actual_created, expected_created):
    getters.local.verify_creation(actual_created, expected_created)
    if source_digest != SOURCE_CAPTURE_SHA:
        raise ValueError('pinned_saved_index_code_source_required')
    if (type(base) is not int or type(module_size) is not int
            or any(not 0 <= rva < rva + size <= module_size for rva, size in EXTRA_SPANS)):
        raise ValueError('fixed_index_code_extents_outside_module')
    report = prior.capture(read, query, base, module_size, source_digest=prior.SOURCE_CAPTURE_SHA,
                           actual_created=actual_created, expected_created=expected_created)
    verify_previous_lookup_body({b['rva']: bytes.fromhex(b['bytes']) for b in report['lookup_body_code'].values()})
    blocks = {}
    for name, (rva, size) in zip(('LookupChain', 'LookupTail', 'FilenameHash', 'FilenameNormalize'), EXTRA_SPANS):
        raw = read(base + rva, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError('short_fixed_index_code_read')
        blocks[name] = {'rva': rva, 'size': size, 'bytes': raw.hex(),
                        'sha256': hashlib.sha256(raw).hexdigest(),
                        'function_complete': False, 'pdata_segment_complete': True}
    report.update(source_capture_sha256=source_digest, captured_bytes=2954, index_code=blocks,
                  scope=report['scope'] + '; exact index-chain183B/tail126B/hash269B/normalize364B code; no new data')
    return report


if __name__ == '__main__':
    prior.prior.prior.prior.prior.main(continuation=5)
