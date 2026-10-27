"""Read the source-selected 37-byte filename-index lookup entry, without calls."""

import hashlib
import json
from pathlib import Path
import struct

import probe_live_fileexists_continuations as prior


getters = prior.prior.prior.getters
SOURCE_CAPTURE = getters.ROOT / 'work/evidence/live-package-fileexists-continuations-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = '83ce2ac84c8c7952577fffe812e681cfd9633c4dfcd70f07374e848b8f3f13b5'
LOOKUP_RVA, LOOKUP_SIZE = 0x12468d40, 37
CONTINUATION_HASHES = {
    0x124678b7: 'c75a7427fa2f74f8c6d95515d41b917fccc33d849465fd76fdca8cbc51523145',
    0x12467cb2: 'b8523d5b1ad2497c08860ca3a2fd680317ec1ef3e6257ca30a4086fb6a577ec9',
}
METADATA = (
    ('pdata', 511490892, '408d4612658d4612244de41b',
     '6ef83ba68cb2f0457deaae8b80baf93f89a87446a2796a519c1f352ec82cb208'),
    ('unwind', 467943716, '010804000852047003500230',
     '9dd2f55aeb52348b61370268efe1b8ac3cada79143f5d0f6cada925b19e8833e'),
)
DISK_OFFSET = 306611008
DISK_SHA = '9fd3c79557cfc27bf89bcdee34a21780cba256878ba874d0235ca171006a0fb9'


def verify_target(raw):
    prior.verify_target(raw)


def verify_previous_edges(blocks):
    prior.verify_previous_edges(blocks)


def verify_previous_continuations(blocks):
    if set(blocks) != set(CONTINUATION_HASHES):
        raise ValueError('lookup_prior_continuation_coordinates_changed')
    for rva, size in prior.EXTRA_SPANS:
        raw = blocks[rva]
        if (not isinstance(raw, bytes) or len(raw) != size
                or hashlib.sha256(raw).hexdigest() != CONTINUATION_HASHES[rva]):
            raise ValueError('lookup_prior_continuation_full_hash_changed')
    raw = blocks[0x12467cb2]
    edge = 0x12467d5f - 0x12467cb2
    witness = bytes.fromhex('488b4f084885c974154c8d45e0488d55f0e8cb0f0000')
    if raw[edge:edge + len(witness)] != witness:
        raise ValueError('lookup_top_plus8_arguments_and_direct_edge_changed')
    call = 0x12467d70 - 0x12467cb2
    if 0x12467d70 + 5 + struct.unpack_from('<i', raw, call + 1)[0] != LOOKUP_RVA:
        raise ValueError('lookup_direct_target_changed')


def load_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_saved_lookup_source_required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_CAPTURE_SHA:
        raise ValueError('saved_lookup_source_full_hash_changed')
    d = json.loads(raw)
    if (d.get('native_pe_sha256') != getters.SOURCE_PE
            or d.get('source_capture_sha256') != prior.SOURCE_CAPTURE_SHA
            or d.get('captured_bytes') != 1591 or d.get('data_qword_reads') != 6
            or not d.get('receiver_chain_rechecked')):
        raise ValueError('saved_lookup_source_chain_changed')
    verify_previous_continuations({b['rva']: bytes.fromhex(b['bytes'])
                                   for b in d['code_continuations'].values()})
    return SOURCE_CAPTURE_SHA


def verify_segment_metadata(read_at):
    rows = {}
    for name, offset, expected, digest in METADATA:
        raw = read_at(offset, len(bytes.fromhex(expected)))
        if (not isinstance(raw, bytes) or raw.hex() != expected
                or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('original_lookup_metadata_changed_' + name)
        rows[name] = {'file_offset': offset, 'bytes': raw.hex(), 'sha256': digest}
    begin, end, _ = struct.unpack('<III', bytes.fromhex(rows['pdata']['bytes']))
    if (begin, end) != (LOOKUP_RVA, LOOKUP_RVA + LOOKUP_SIZE):
        raise ValueError('original_lookup_segment_bounds_changed')
    raw = read_at(DISK_OFFSET, LOOKUP_SIZE)
    if not isinstance(raw, bytes) or len(raw) != LOOKUP_SIZE or hashlib.sha256(raw).hexdigest() != DISK_SHA:
        raise ValueError('original_lookup_disk_code_changed')
    return {'begin_rva': begin, 'end_exclusive_rva': end, 'segment_bytes': LOOKUP_SIZE,
            'metadata': rows, 'disk_code_offset': DISK_OFFSET, 'disk_code_sha256': DISK_SHA,
            'runtime_plaintext_hash': False}


def verify_original(path):
    extents = prior.verify_original(path)
    with Path(path).open('rb') as stream:
        def read_at(offset, size):
            stream.seek(offset)
            return stream.read(size)
        extents['lookup'] = verify_segment_metadata(read_at)
    return extents


def capture(read, query, base, module_size, *, source_digest, actual_created, expected_created):
    getters.local.verify_creation(actual_created, expected_created)
    if source_digest != SOURCE_CAPTURE_SHA:
        raise ValueError('pinned_saved_lookup_source_required')
    if (type(base) is not int or type(module_size) is not int
            or not 0 <= LOOKUP_RVA < LOOKUP_RVA + LOOKUP_SIZE <= module_size):
        raise ValueError('fixed_lookup_code_outside_module')
    report = prior.capture(read, query, base, module_size, source_digest=prior.SOURCE_CAPTURE_SHA,
                           actual_created=actual_created, expected_created=expected_created)
    verify_previous_continuations({b['rva']: bytes.fromhex(b['bytes'])
                                   for b in report['code_continuations'].values()})
    raw = read(base + LOOKUP_RVA, LOOKUP_SIZE)
    if not isinstance(raw, bytes) or len(raw) != LOOKUP_SIZE:
        raise ValueError('short_fixed_lookup_code_read')
    report.update(source_capture_sha256=source_digest, captured_bytes=1628,
                  lookup_code={'rva': LOOKUP_RVA, 'size': LOOKUP_SIZE, 'bytes': raw.hex(),
                               'sha256': hashlib.sha256(raw).hexdigest(),
                               'function_complete': False, 'pdata_segment_complete': True},
                  fresh_continuation_hashes_verified=True,
                  scope=report['scope'] + '; source top+8 filename lookup entry37B; no extra data or call')
    return report


if __name__ == '__main__':
    prior.prior.prior.main(continuation=3)
