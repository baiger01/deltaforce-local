"""Observe only the exact direct-call and fallthrough edges of the saved target.

The fresh source-qualified receiver chain and target46B precede two original
runtime-function segments: fallthrough169B and direct callee18B. No new data.
"""

import hashlib
import json
from pathlib import Path
import struct

import probe_live_fileexists_target as prior


SOURCE_CAPTURE = prior.getters.ROOT / 'work/evidence/live-package-fileexists-target-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = '6651747d5d418721a5dacc02010e3bd3f20d551d85aa6481fc7228f9181ec6c5'
TARGET_SHA = 'fa8960398f7299e27b6ffd90358d153c8033d6da49a9ba606c88cc08a82efabc'
TARGET_BYTES = bytes.fromhex('48896c2418574883ec304533c94533c0488bfa488be9e8a504000084c0740db001488b6c24504883c4305fc333d2')
EXTRA_SPANS = ((0x1246780e, 169), (0x12467ca0, 18))
EDGE_METADATA = (
    ('fallthrough_pdata', 511490556, '0e784612b778461248f9801c',
     'e285275175b85047f9ac359acf98564f0348c772b958d6860f3712570e9c1d81'),
    ('fallthrough_unwind', 478211400, '210a04000a64090005340800e07746120e784612c482e61b',
     '4c1932252089e0c03d8465dd17ec8b34f2838e4f7725c78641318f697cc4f2f2'),
    ('callee_pdata', 511490712, 'a07c4612b27c4612ecf8801c',
     'cd45a028b93bbbc778af97eb7f0cd94846371901f5aeaf2159e3946560dd3ff1'),
    ('callee_unwind', 478211308, '0112060012920bf009d007c005300450',
     'bfe5b6f2259d55cf9743d0e0cb72d9628f0fc297c835a2d5d605a5f1507139fa'),
)
EDGE_DISK = (
    ('fallthrough', 306605582, 169, 'c2c40b9dbc572e9c289182ef7305042d5d1c5701139dd83b65e06e13c043e403'),
    ('direct_callee', 306606752, 18, 'efeeabcf8e823ff0e372e4f35bc23744e6123086548e15e2913559e719466f7d'),
)


def verify_target(raw):
    if (not isinstance(raw, bytes) or len(raw) != 46
            or hashlib.sha256(raw).hexdigest() != TARGET_SHA):
        raise ValueError('fileexists_edges_fresh_target_full_hash_changed')
    call, branch = raw[0x16:0x1b], raw[0x1d:0x1f]
    if (call != bytes.fromhex('e8a5040000')
            or 0x124677f6 + 5 + struct.unpack_from('<i', call, 1)[0] != EXTRA_SPANS[1][0]
            or branch != b'\x74\x0d' or 0x124677fd + 2 + branch[1] != 0x1246780c
            or raw[0x2c:] != b'\x33\xd2' or 0x1246780c + 2 != EXTRA_SPANS[0][0]):
        raise ValueError('fileexists_edges_exact_call_branch_fallthrough_witness_changed')


def load_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_saved_fileexists_target_source_required')
    with path.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != SOURCE_CAPTURE_SHA:
        raise ValueError('saved_fileexists_target_source_full_hash_changed')
    d = json.loads(raw)
    if (d.get('native_pe_sha256') != prior.getters.SOURCE_PE
            or d.get('source_capture_sha256') != prior.SOURCE_CAPTURE_SHA
            or d.get('virtual_target_rva') != prior.TARGET_RVA
            or d.get('data_qword_reads') != 6 or not d.get('receiver_chain_rechecked')):
        raise ValueError('saved_fileexists_edges_source_chain_changed')
    caller = d['source_code']
    if (caller['rva'], caller['size'], caller['sha256']) != (
            prior.getters.CALLER_RVA, 1024, prior.getters.CALLER_SHA):
        raise ValueError('saved_fileexists_edges_caller_coordinates_changed')
    prior.getters.verify_caller(bytes.fromhex(caller['bytes']))
    prior.prior.verify_virtual_callsite(bytes.fromhex(caller['bytes']))
    blocks = d['fixed_code']
    first, second = (blocks[n] for n in ('FileExistsFirstGetterLeaf', 'FileExistsSecondGetter'))
    if ((first['rva'], first['size'], first['sha256']) != (
            prior.getters.FIRST_RVA, 16, prior.prior.prior.FIRST_SHA)
            or (second['rva'], second['size'], second['sha256']) != (
                prior.getters.SECOND_RVA, 31, prior.prior.prior.SECOND_SHA)):
        raise ValueError('saved_fileexists_edges_getter_coordinates_changed')
    prior.prior.prior.verify_getters(bytes.fromhex(first['bytes']), bytes.fromhex(second['bytes']))
    target = d['target_code']
    if (target['rva'], target['size'], target['sha256']) != (prior.TARGET_RVA, 46, TARGET_SHA):
        raise ValueError('saved_fileexists_edges_target_coordinates_changed')
    verify_target(bytes.fromhex(target['bytes']))
    return SOURCE_CAPTURE_SHA


def verify_edge_metadata(read_at):
    rows = {}
    for name, offset, expected, digest in EDGE_METADATA:
        raw = read_at(offset, len(bytes.fromhex(expected)))
        if (not isinstance(raw, bytes) or raw.hex() != expected
                or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('original_fileexists_edge_metadata_changed_' + name)
        rows[name] = {'file_offset': offset, 'bytes': raw.hex(), 'sha256': digest}
    result = {}
    for (name, offset, size, digest), (selected, expected_size), pdata_name in zip(
            EDGE_DISK, EXTRA_SPANS, ('fallthrough_pdata', 'callee_pdata')):
        begin, end, _ = struct.unpack('<III', bytes.fromhex(rows[pdata_name]['bytes']))
        if not begin <= selected < end or end - begin != size or size != expected_size:
            raise ValueError('original_fileexists_selected_edge_not_in_exact_pdata_segment')
        raw = read_at(offset, size)
        if not isinstance(raw, bytes) or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('original_fileexists_edge_disk_code_changed_' + name)
        result[name] = {'selected_rva': selected, 'begin_rva': begin, 'end_exclusive_rva': end,
                        'segment_bytes': size, 'metadata': rows, 'disk_code_offset': offset,
                        'disk_code_sha256': digest, 'runtime_plaintext_hash': False}
    return result


def verify_original(path):
    extents = prior.verify_original(path)
    with Path(path).open('rb') as stream:
        def read_at(offset, size):
            stream.seek(offset)
            return stream.read(size)
        extents['code_edges'] = verify_edge_metadata(read_at)
    return extents


def capture(read, query, base, module_size, *, source_digest, actual_created, expected_created):
    prior.getters.local.verify_creation(actual_created, expected_created)
    if source_digest != SOURCE_CAPTURE_SHA:
        raise ValueError('pinned_saved_fileexists_target_source_required')
    if (type(base) is not int or type(module_size) is not int
            or any(not 0 <= rva < rva + size <= module_size for rva, size in EXTRA_SPANS)):
        raise ValueError('fixed_fileexists_edge_code_ranges_outside_module')
    report = prior.capture(read, query, base, module_size, source_digest=prior.SOURCE_CAPTURE_SHA,
                           actual_created=actual_created, expected_created=expected_created)
    verify_target(bytes.fromhex(report['target_code']['bytes']))
    edges = {}
    for name, (rva, size) in zip(('FileExistsFalseFallthrough', 'FileExistsDirectCalleeEntry'), EXTRA_SPANS):
        raw = read(base + rva, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError('short_fixed_fileexists_edge_code_read')
        edges[name] = {'rva': rva, 'size': size, 'end_exclusive_rva': rva + size,
                       'bytes': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest(),
                       'function_complete': False, 'pdata_segment_complete': True,
                       'extent_from_original_pdata': True}
    report.update(source_capture_sha256=source_digest, code_edges=edges,
                  captured_bytes=report['captured_bytes'] + sum(size for _, size in EXTRA_SPANS),
                  fresh_target_full_hash_verified=True, exact_code_edge_witnesses_verified=True,
                  scope=report['scope'] + '; exact witnessed false-fallthrough169B and direct-callee18B '
                        'original-pdata segments only; no new data or contained helpers followed')
    return report


if __name__ == '__main__':
    prior.main(continuation=True)
