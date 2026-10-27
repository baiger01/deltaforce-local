"""Observe two CHAININFO-linked segments reached by saved exact control-flow edges.

Fresh prior1352B code/receiver scope precedes only false-path tail36B and direct
callee body203B. The same six qwords remain the complete data scope. No calls.
"""

import hashlib
import json
from pathlib import Path
import struct

import probe_live_fileexists_edges as prior


SOURCE_CAPTURE = prior.prior.getters.ROOT / 'work/evidence/live-package-fileexists-edges-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = '9031c3184d3e99f1b66d66d4c4fb42b578357c3c6c92dd49c4bd9f1f0ef964d1'
EXTRA_SPANS = ((0x124678b7, 36), (0x12467cb2, 203))
PREVIOUS_HASHES = {
    0x1246780e: '4ada8ece1d0da9db047e5ceff9746f72885c62d05f49ca987d633f8a3f37c16d',
    0x12467ca0: '4f349185cb063d6114a870587d32fb709bf78191085650b826d149216bbe375c',
}
PREVIOUS_BYTES = {
    0x1246780e: bytes.fromhex('48895c244048897424488bca4032f6488954242048895424284885ff7468663917746348c7c3ffffffff0f1f84000000000048ffc36639145f75f7ffc385db7e148bd3488d4c2420e8654c8fee8b4c242c8b5424288d0413894424283bc17e0a488d4c2420e8684b8fee488d4c2420ff15d565130b4c63c3488bd74d03c0488bc8e89c345afe488d542420488bcde8df6d0000488d4c24200fb6d8e8b2498fee84db488b5c24407410'),
    0x12467ca0: bytes.fromhex('488bc45553415441554157488bec4883ec50'),
}
SEGMENT_METADATA = (
    ('false_tail_pdata', 511490568, 'b7784612db78461260f9801c',
     'ea3dadbd9ddcc2a3010bae7263d3633383468dd068726a30d69e169be5a97e47'),
    ('false_tail_unwind', 478211424, '2100020000640900e07746120e784612c482e61b',
     '842f4a2a9ff7e834dfba443adc2c0ea30aa8a41db4975701f9a20efd05e36a28'),
    ('callee_body_pdata', 511490724, 'b27c46127d7d4612fcf8801c',
     '0151c53f6e58e82ac55a39c29c1ea603f2bc2734d2935d80ee4e2e55b7c1257c'),
    ('callee_body_unwind', 478211324, '210d04000d74120004641100a07c4612b27c4612ecf8801c',
     'a2d33baa5250b3cad222c4c368b6a6700910367d25d66e54883aebc0e1c58ace'),
)
SEGMENT_DISK = (
    ('false_tail', 306605751, 36, '16b1f1c385015b76bb1ef1e9837c57565d93eec496bce1da61b3392ad03b8500'),
    ('callee_body', 306606770, 203, '7a6217a0a0195e738827d2f135538c027666882e0609be8dbec38e4532fcb0fb'),
)


def verify_target(raw):
    prior.verify_target(raw)


def verify_previous_edges(blocks):
    if set(blocks) != set(PREVIOUS_HASHES):
        raise ValueError('fileexists_continuation_previous_code_coordinates_changed')
    for rva, size in prior.EXTRA_SPANS:
        raw = blocks[rva]
        if (not isinstance(raw, bytes) or len(raw) != size
                or hashlib.sha256(raw).hexdigest() != PREVIOUS_HASHES[rva]):
            raise ValueError('fileexists_continuation_previous_full_segment_hash_changed')
    fallthrough, callee = blocks[0x1246780e], blocks[0x12467ca0]
    if (fallthrough[-2:] != b'\x74\x10'
            or 0x124678b5 + 2 + fallthrough[-1] != 0x124678c7
            or 0x1246780e + len(fallthrough) != EXTRA_SPANS[0][0]
            or callee != PREVIOUS_BYTES[0x12467ca0]
            or callee[-4:] != bytes.fromhex('4883ec50')
            or 0x12467ca0 + len(callee) != EXTRA_SPANS[1][0]):
        raise ValueError('fileexists_continuation_exact_JE_and_prologue_fallthrough_changed')


def load_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_saved_fileexists_edges_source_required')
    with path.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != SOURCE_CAPTURE_SHA:
        raise ValueError('saved_fileexists_edges_source_full_hash_changed')
    d = json.loads(raw)
    if (d.get('native_pe_sha256') != prior.prior.getters.SOURCE_PE
            or d.get('source_capture_sha256') != prior.SOURCE_CAPTURE_SHA
            or d.get('virtual_target_rva') != prior.prior.TARGET_RVA
            or d.get('data_qword_reads') != 6 or not d.get('receiver_chain_rechecked')):
        raise ValueError('saved_fileexists_continuation_source_chain_changed')
    caller = d['source_code']
    if (caller['rva'], caller['size'], caller['sha256']) != (
            prior.prior.getters.CALLER_RVA, 1024, prior.prior.getters.CALLER_SHA):
        raise ValueError('saved_fileexists_continuation_caller_coordinates_changed')
    prior.prior.getters.verify_caller(bytes.fromhex(caller['bytes']))
    prior.prior.prior.verify_virtual_callsite(bytes.fromhex(caller['bytes']))
    first, second = (d['fixed_code'][name] for name in ('FileExistsFirstGetterLeaf', 'FileExistsSecondGetter'))
    if ((first['rva'], first['size'], first['sha256']) != (
            prior.prior.getters.FIRST_RVA, 16, prior.prior.prior.prior.FIRST_SHA)
            or (second['rva'], second['size'], second['sha256']) != (
                prior.prior.getters.SECOND_RVA, 31, prior.prior.prior.prior.SECOND_SHA)):
        raise ValueError('saved_fileexists_continuation_getter_coordinates_changed')
    prior.prior.prior.prior.verify_getters(bytes.fromhex(first['bytes']), bytes.fromhex(second['bytes']))
    target = d['target_code']
    if (target['rva'], target['size'], target['sha256']) != (prior.prior.TARGET_RVA, 46, prior.TARGET_SHA):
        raise ValueError('saved_fileexists_continuation_target_coordinates_changed')
    verify_target(bytes.fromhex(target['bytes']))
    blocks = {}
    for block in d['code_edges'].values():
        rva, size = block['rva'], block['size']
        if (rva, size) not in prior.EXTRA_SPANS or block['sha256'] != PREVIOUS_HASHES[rva] or rva in blocks:
            raise ValueError('saved_fileexists_continuation_edge_coordinates_changed')
        blocks[rva] = bytes.fromhex(block['bytes'])
    verify_previous_edges(blocks)
    return SOURCE_CAPTURE_SHA


def verify_segment_metadata(read_at):
    rows = {}
    for name, offset, expected, digest in SEGMENT_METADATA:
        raw = read_at(offset, len(bytes.fromhex(expected)))
        if (not isinstance(raw, bytes) or raw.hex() != expected
                or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('original_fileexists_continuation_metadata_changed_' + name)
        rows[name] = {'file_offset': offset, 'bytes': raw.hex(), 'sha256': digest}
    result = {}
    for (name, offset, size, digest), (begin_expected, length_expected), pdata, unwind, selected, parent in zip(
            SEGMENT_DISK, EXTRA_SPANS, ('false_tail_pdata', 'callee_body_pdata'),
            ('false_tail_unwind', 'callee_body_unwind'),
            ((0x124678b7, 0x124678c7), (0x12467cb2,)),
            (prior.prior.TARGET_METADATA[0][2], prior.EDGE_METADATA[2][2])):
        begin, end, _ = struct.unpack('<III', bytes.fromhex(rows[pdata]['bytes']))
        uw = bytes.fromhex(rows[unwind]['bytes'])
        if (begin != begin_expected or end - begin != size or size != length_expected
                or any(not begin <= rva < end for rva in selected)
                or uw[0] >> 3 != 4 or uw[-12:] != bytes.fromhex(parent)):
            raise ValueError('original_fileexists_continuation_pdata_containment_or_CHAININFO_changed')
        raw = read_at(offset, size)
        if not isinstance(raw, bytes) or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('original_fileexists_continuation_disk_code_changed_' + name)
        result[name] = {'selected_rvas': list(selected), 'begin_rva': begin, 'end_exclusive_rva': end,
                        'segment_bytes': size, 'metadata': rows, 'CHAININFO_parent_verified': True,
                        'disk_code_offset': offset, 'disk_code_sha256': digest, 'runtime_plaintext_hash': False}
    return result


def verify_original(path):
    extents = prior.verify_original(path)
    with Path(path).open('rb') as stream:
        def read_at(offset, size):
            stream.seek(offset)
            return stream.read(size)
        extents['continuations'] = verify_segment_metadata(read_at)
    return extents


def capture(read, query, base, module_size, *, source_digest, actual_created, expected_created):
    prior.prior.getters.local.verify_creation(actual_created, expected_created)
    if source_digest != SOURCE_CAPTURE_SHA:
        raise ValueError('pinned_saved_fileexists_edges_source_required')
    if (type(base) is not int or type(module_size) is not int
            or any(not 0 <= rva < rva + size <= module_size for rva, size in EXTRA_SPANS)):
        raise ValueError('fixed_fileexists_continuation_code_ranges_outside_module')
    report = prior.capture(read, query, base, module_size, source_digest=prior.SOURCE_CAPTURE_SHA,
                           actual_created=actual_created, expected_created=expected_created)
    verify_previous_edges({b['rva']: bytes.fromhex(b['bytes']) for b in report['code_edges'].values()})
    continuations = {}
    for name, (rva, size) in zip(('FileExistsFalseTail', 'FileExistsDirectCalleeBody'), EXTRA_SPANS):
        raw = read(base + rva, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError('short_fixed_fileexists_continuation_code_read')
        continuations[name] = {'rva': rva, 'size': size, 'end_exclusive_rva': rva + size,
                               'bytes': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest(),
                               'function_complete': False, 'pdata_segment_complete': True,
                               'extent_from_original_pdata': True}
    report.update(source_capture_sha256=source_digest, code_continuations=continuations,
                  captured_bytes=report['captured_bytes'] + 239,
                  fresh_previous_segments_full_hash_verified=True,
                  exact_continuation_witnesses_verified=True, actual_render_proven=False,
                  scope=report['scope'] + '; exact source CHAININFO-linked false-tail36B and callee-body203B '
                        'after fresh previous segments; no new data or contained helper followed')
    return report


if __name__ == '__main__':
    prior.prior.main(continuation=2)
