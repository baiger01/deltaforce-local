"""Inspect source-qualified filename headers, a fixed accessor, or five typed strings.

String mode follows only current bounded UTF16 buffers after exact leaf/code gates.
No native calls, game launches, writes, scans or dynamic root-array traversal.
"""

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from local_game_paths import game_paths
import probe_live_package_path_cache as prior


CAPTURE = prior.ROOT / 'work/evidence/live-package-filename-root-state-bundle-20261005-private.json'
CAPTURE_SHA = '5d6190938f8cec1fbcd049d7994002772a89b56331c5612109fe122e0dff288c'
GETTER_SHA = '1b983f22dfd07ef7628526f29295fabfc1cc8ecefa4039e6b3ec2c3c82ce43e8'
STATE_RVA = 0x1e3406d0
GETTER_LEAS = ((0x10ccc069, bytes.fromhex('488d056046670d')),
               (0x10ccc08b, bytes.fromhex('488d1d3e46670d')))
HEADERS = {'first_root': STATE_RVA + 0x20, 'first_prefix': STATE_RVA + 0xb0,
           'second_root': STATE_RVA + 0x10, 'second_prefix': STATE_RVA + 0x70,
           'extension': prior.FILENAME_STATIC_RVA}
ACCESSOR_SLOT_RVA = 0x1d59de58
ACCESSOR_EDGE = (0x10ce8a9a, bytes.fromhex('ff15b8538b0c'))
HEADER_CAPTURE = prior.ROOT / 'work/evidence/live-package-filename-headers-bundle-20261005-private.json'
HEADER_CAPTURE_SHA = '8927ea011f23c1cf2d3764f71bcc4bdddb109b1b10e5ede6bfbe0197cca5078d'
ACCESSOR_TARGET_RVA = 0xd968d0
ACCESSOR_PREFIX_SIZE = 16
ORIGINAL_ACCESSOR_SLOT_OFFSET = 492424280
ORIGINAL_ACCESSOR_SLOT_BYTES = bytes.fromhex('d068d94001000000')
ORIGINAL_ACCESSOR_SLOT_SHA = '6d0f255fe211b1400ec09efe776b6baaa1cc640018ce248ed7aa1cf10064b940'
ACCESSOR_CAPTURE = prior.ROOT / 'work/evidence/live-package-filename-accessor-bundle-20261005-private.json'
ACCESSOR_CAPTURE_SHA = 'e76719698fb824b47eaaed5fffc0974d135d3eb015637ffa01e373558ed31bc1'
ACCESSOR_LEAF_BYTES = bytes.fromhex('488b01c3cccccccccccccccccccccccc')
ACCESSOR_LEAF_SHA = '58f45ef5284c6bb5e0b6ce75b72f789fc794749f0b859990bc202cff3edf0480'
MAX_STRING_UNITS = 256
STRING_CAPTURE = prior.ROOT / 'work/evidence/live-package-filename-root-strings-bundle-20261005-private.json'
STRING_CAPTURE_SHA = 'a2a9de116a5a4e54c7b5543ca77d0b4e083106faebd56f961350d0bc6d18ef9f'
MATCH_RVA = 0x109f87e0
MATCH_SIZE = 213
MATCH_EDGES = ((0x10ce88b2, bytes.fromhex('e829ffd0ff')),
               (0x10ce8c56, bytes.fromhex('e885fbd0ff')),
               (0x10ce900a, bytes.fromhex('e8d1f7d0ff')))
MATCH_ARGUMENT_WITNESSES = ((0x10ce889f, bytes.fromhex('41bc01000000')),
                            (0x10ce88a8, bytes.fromhex('458bc4')),
                            (0x10ce8c50, bytes.fromhex('458bc4')),
                            (0x10ce9001, bytes.fromhex('458bc4')))
MATCH_PDATA_OFFSET = 510226308
MATCH_PDATA_BYTES = bytes.fromhex('e0879f10b5889f1094b4dc1b')
MATCH_PDATA_SHA = '70e478ef9c83a39701548e4389b1e5eb73311dc29f69a70d095ea915ed3d7560'
MATCH_UNWIND_OFFSET = 467445908
MATCH_UNWIND_BYTES = bytes.fromhex('0114080014640800145407001434060014321070')
MATCH_UNWIND_SHA = 'bb13e6c6a983c02cdabcec0406ca34d45ce7d54834c1237440984006a1b7ffe2'
COPY_CAPTURE = prior.ROOT / 'work/evidence/live-package-filename-root-match-bundle-20261005-private.json'
COPY_CAPTURE_SHA = '946c20e5f0934a6280a649d051cc20d9957479fc8b797b310ecfc6277607dce3'
MATCH_FULL_SHA = '259513b3fe666c50661ec8f7e89d41da54b3cfb4dc4071242954a92de4df37ef'
COPY_TARGETS = {'PackageBoundedRootCompare': (0x10a139d0, 165),
                'PackageFilenameAppendEntry': (0x109ed8b0, 24),
                'PackageFilenameOutputMove': (0xd632b0, 123)}
COMPARE_FULL_SHA = '144f75637264e8caedea8a34ae9dafa4958c1856c33b537ed3a63f9e620ebf35'
COMPARE_CAPTURE = prior.ROOT / 'work/evidence/live-package-compare-bundle-20261005-private.json'
COMPARE_CAPTURE_SHA = 'a412582d25d1bfa12d727a735a8e16a1afd4083299e7986c7c7646ad70f47120'
COMPARE_CALL = (0x109f8849, bytes.fromhex('e882b10100'))
COPY_CALLS = ((0x10ce8aaa, bytes.fromhex('e8014ed0ff'), 0x109ed8b0),
              (0x10ce8ac3, bytes.fromhex('e8e84dd0ff'), 0x109ed8b0),
              (0x10ce8bba, bytes.fromhex('e8f14cd0ff'), 0x109ed8b0),
              (0x10ce8c25, bytes.fromhex('e886a607f0'), 0xd632b0))
COPY_METADATA = (
    (0x10a139d0, 165, 510233880, 'd039a110753aa11058dee21b',
     '9b5eef473c4c31f72f52f55e1d1df89e6a505c77c8c172535887ed111137eb15',
     467849816, '010f06000f7403000a64020005340100',
     '77705a89aa2f1549da76a3c97bbe061f19df1c037b09638fbe0cc2fc137a11a8'),
    (0x109ed8b0, 24, 510223272, 'b0d89e10c8d89e10b047e81b',
     'e636102f9b19d27871c6749f9144a729ff06ebf1d2ab42b58e1537a0521b9b8e',
     468204464, '01180600185409001834080018321460',
     '764278845f7d2f872aa78d7a747dc57c30c4a03bee807d5cb6e692f4f5709726'),
    (0xd632b0, 123, 499261896, 'b032d6002b33d60044b4dc1b',
     '5b0a2a3894b2f2745041fe9aabc8a68af9136d3b50339325a2e571be2e664a8b',
     467445828, '010a04000a3406000a320670',
     '39455c244cd3d4de53471a0adec96067c74300ddc0ba6db9733fe8f8e3a9ffc4'))


def verify_getter(code):
    if (len(code) != prior.ROOT_STATE_TARGET_SIZE
            or hashlib.sha256(code).hexdigest() != GETTER_SHA):
        raise ValueError('fresh_filename_header_getter_span_changed')
    for site, witness in GETTER_LEAS:
        offset = site - prior.ROOT_STATE_TARGET_RVA
        actual = code[offset:offset + len(witness)]
        if actual != witness or site + 7 + struct.unpack_from('<i', actual, 3)[0] != STATE_RVA:
            raise ValueError('fresh_filename_header_state_LEA_changed')


def verify_converter(code):
    if (len(code) != prior.ROOTS_TARGET_SIZE
            or hashlib.sha256(code).hexdigest() != prior.ROOT_STATE_SOURCE_SHA):
        raise ValueError('fresh_filename_header_converter_span_changed')
    prior.verify_root_state_call(code)
    site, witness = ACCESSOR_EDGE
    actual = code[site - prior.ROOTS_TARGET_RVA:site - prior.ROOTS_TARGET_RVA + 6]
    if actual != witness or site + 6 + struct.unpack_from('<i', actual, 2)[0] != ACCESSOR_SLOT_RVA:
        raise ValueError('fresh_filename_header_accessor_edge_changed')


def load_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_filename_header_saved_source_required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != CAPTURE_SHA:
        raise ValueError('filename_header_saved_source_full_hash_changed')
    report = json.loads(raw)
    if (report['native_pe_sha256'] != prior.SOURCE_PE
            or report['source_capture_sha256'] != prior.ROOT_STATE_CAPTURE_SHA):
        raise ValueError('filename_header_saved_source_chain_changed')
    specifications = ((report['source_code'], prior.SOURCE_RVA, 1024, prior.FILENAME_SOURCE_SHA),
                      (report['fixed_code']['PackageFilenameTransform'], prior.FILENAME_TARGET_RVA,
                       prior.FILENAME_TARGET_SIZE, prior.ROOTS_SOURCE_SHA),
                      (report['fixed_code']['PackageFilenameRoots'], prior.ROOTS_TARGET_RVA,
                       prior.ROOTS_TARGET_SIZE, prior.ROOT_STATE_SOURCE_SHA),
                      (report['fixed_code']['PackageFilenameRootStateGetter'], prior.ROOT_STATE_TARGET_RVA,
                       prior.ROOT_STATE_TARGET_SIZE, GETTER_SHA))
    decoded = []
    for block, rva, size, digest in specifications:
        data = bytes.fromhex(block['bytes'])
        if ((block['rva'], block['size'], block['sha256']) != (rva, size, digest)
                or len(data) != size or hashlib.sha256(data).hexdigest() != digest):
            raise ValueError('filename_header_saved_source_span_changed')
        decoded.append(data)
    prior.verify_filename_edges(decoded[0])
    prior.verify_roots_call(decoded[1])
    verify_converter(decoded[2])
    verify_getter(decoded[3])
    return CAPTURE_SHA


def load_accessor_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_filename_accessor_saved_source_required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != HEADER_CAPTURE_SHA:
        raise ValueError('filename_accessor_saved_source_full_hash_changed')
    report = json.loads(raw)
    if (report['native_pe_sha256'] != prior.SOURCE_PE
            or report['source_capture_sha256'] != CAPTURE_SHA):
        raise ValueError('filename_accessor_saved_source_chain_changed')
    for name, rva, size, digest in (
            ('PackageFilenameRoots', prior.ROOTS_TARGET_RVA, prior.ROOTS_TARGET_SIZE,
             prior.ROOT_STATE_SOURCE_SHA),
            ('PackageFilenameRootStateGetter', prior.ROOT_STATE_TARGET_RVA,
             prior.ROOT_STATE_TARGET_SIZE, GETTER_SHA)):
        block = report['fixed_code'][name]
        data = bytes.fromhex(block['bytes'])
        if ((block['rva'], block['size'], block['sha256']) != (rva, size, digest)
                or len(data) != size or hashlib.sha256(data).hexdigest() != digest):
            raise ValueError('filename_accessor_saved_source_span_changed')
        verify_converter(data) if name == 'PackageFilenameRoots' else verify_getter(data)
    slot = report['accessor_slot']
    raw_slot = bytes.fromhex(slot['bytes'])
    if ((slot['rva'], slot['size']) != (ACCESSOR_SLOT_RVA, 8)
            or raw_slot != ORIGINAL_ACCESSOR_SLOT_BYTES
            or slot['sha256'] != ORIGINAL_ACCESSOR_SLOT_SHA
            or hashlib.sha256(raw_slot).hexdigest() != ORIGINAL_ACCESSOR_SLOT_SHA
            or int(report['module_base'], 16) + ACCESSOR_TARGET_RVA != struct.unpack('<Q', raw_slot)[0]):
        raise ValueError('filename_accessor_saved_source_slot_changed')
    return HEADER_CAPTURE_SHA


def load_strings_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_filename_strings_saved_source_required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != ACCESSOR_CAPTURE_SHA:
        raise ValueError('filename_strings_saved_source_full_hash_changed')
    report = json.loads(raw)
    if (report['native_pe_sha256'] != prior.SOURCE_PE
            or report['source_capture_sha256'] != HEADER_CAPTURE_SHA):
        raise ValueError('filename_strings_saved_source_chain_changed')
    for name, rva, size, digest in (
            ('PackageFilenameRoots', prior.ROOTS_TARGET_RVA, prior.ROOTS_TARGET_SIZE,
             prior.ROOT_STATE_SOURCE_SHA),
            ('PackageFilenameRootStateGetter', prior.ROOT_STATE_TARGET_RVA,
             prior.ROOT_STATE_TARGET_SIZE, GETTER_SHA),
            ('FStringCharacterAccessorPrefix', ACCESSOR_TARGET_RVA, ACCESSOR_PREFIX_SIZE,
             ACCESSOR_LEAF_SHA)):
        block = report['fixed_code'][name]
        data = bytes.fromhex(block['bytes'])
        if ((block['rva'], block['size'], block['sha256']) != (rva, size, digest)
                or len(data) != size or hashlib.sha256(data).hexdigest() != digest):
            raise ValueError('filename_strings_saved_source_span_changed')
        if name == 'PackageFilenameRoots':
            verify_converter(data)
        elif name == 'PackageFilenameRootStateGetter':
            verify_getter(data)
        elif data != ACCESSOR_LEAF_BYTES:
            raise ValueError('filename_strings_saved_accessor_leaf_changed')
    slot = report['accessor_slot']
    slot_bytes = bytes.fromhex(slot['bytes'])
    if ((slot['rva'], slot['size']) != (ACCESSOR_SLOT_RVA, 8)
            or slot_bytes != ORIGINAL_ACCESSOR_SLOT_BYTES
            or slot['sha256'] != ORIGINAL_ACCESSOR_SLOT_SHA
            or hashlib.sha256(slot_bytes).hexdigest() != ORIGINAL_ACCESSOR_SLOT_SHA
            or int(report['module_base'], 16) + ACCESSOR_TARGET_RVA != struct.unpack('<Q', slot_bytes)[0]):
        raise ValueError('filename_strings_saved_accessor_slot_changed')
    return ACCESSOR_CAPTURE_SHA


def bounded_header(header_rva, data):
    if header_rva not in HEADERS.values() or not isinstance(data, bytes) or len(data) != 16:
        raise ValueError('source_fixed_filename_string_header_required')
    pointer, count, maximum = struct.unpack('<Qii', data)
    if not 0 <= count <= maximum <= MAX_STRING_UNITS:
        raise ValueError('filename_string_count_or_max_outside_bound')
    size = count * 2
    if count and (pointer < 0x10000 or pointer % 2
                  or not pointer < pointer + size <= 0x800000000000):
        raise ValueError('filename_string_pointer_alignment_canonical_or_overflow_invalid')
    return pointer, count, maximum, size


def decode_utf16(data, count):
    if not isinstance(data, bytes) or len(data) != count * 2:
        raise ValueError('short_bounded_filename_string_read')
    if not count:
        return ''
    if data[-2:] != b'\0\0' or any(data[index:index + 2] == b'\0\0'
                                    for index in range(0, len(data) - 2, 2)):
        raise ValueError('filename_string_requires_exact_terminal_NUL')
    try:
        return data[:-2].decode('utf-16-le', errors='strict')
    except UnicodeDecodeError as error:
        raise ValueError('filename_string_invalid_UTF16') from error


def verify_match_edges(code):
    for site, witness in MATCH_EDGES:
        actual = code[site - prior.ROOTS_TARGET_RVA:site - prior.ROOTS_TARGET_RVA + 5]
        if actual != witness or site + 5 + struct.unpack_from('<i', actual, 1)[0] != MATCH_RVA:
            raise ValueError('fresh_filename_root_match_edge_changed')
    for site, witness in MATCH_ARGUMENT_WITNESSES:
        actual = code[site - prior.ROOTS_TARGET_RVA:site - prior.ROOTS_TARGET_RVA + len(witness)]
        if actual != witness:
            raise ValueError('fresh_filename_root_match_argument_changed')


def load_match_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_filename_match_saved_source_required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != STRING_CAPTURE_SHA:
        raise ValueError('filename_match_saved_source_full_hash_changed')
    report = json.loads(raw)
    if (report['native_pe_sha256'] != prior.SOURCE_PE
            or report['source_capture_sha256'] != ACCESSOR_CAPTURE_SHA):
        raise ValueError('filename_match_saved_source_chain_changed')
    block = report['fixed_code']['PackageFilenameRoots']
    data = bytes.fromhex(block['bytes'])
    if ((block['rva'], block['size'], block['sha256']) !=
            (prior.ROOTS_TARGET_RVA, prior.ROOTS_TARGET_SIZE, prior.ROOT_STATE_SOURCE_SHA)):
        raise ValueError('filename_match_saved_source_span_changed')
    verify_converter(data)
    verify_match_edges(data)
    return STRING_CAPTURE_SHA


def verify_match_extent(original_pe):
    with Path(original_pe).open('rb') as stream:
        stream.seek(MATCH_PDATA_OFFSET)
        pdata = stream.read(12)
        stream.seek(MATCH_UNWIND_OFFSET)
        unwind = stream.read(20)
    if (pdata != MATCH_PDATA_BYTES or hashlib.sha256(pdata).hexdigest() != MATCH_PDATA_SHA
            or unwind != MATCH_UNWIND_BYTES or hashlib.sha256(unwind).hexdigest() != MATCH_UNWIND_SHA
            or struct.unpack('<III', pdata) != (MATCH_RVA, MATCH_RVA + MATCH_SIZE, 0x1bdcb494)):
        raise ValueError('filename_root_match_source_extent_changed')
    return dict(begin_rva=MATCH_RVA, end_exclusive_rva=MATCH_RVA + MATCH_SIZE,
                bytes=MATCH_SIZE, pdata_file_offset=MATCH_PDATA_OFFSET, pdata_sha256=MATCH_PDATA_SHA,
                unwind_file_offset=MATCH_UNWIND_OFFSET, unwind_sha256=MATCH_UNWIND_SHA)


def verify_copy_calls(converter, matcher):
    for code, begin, edges in ((converter, prior.ROOTS_TARGET_RVA, COPY_CALLS),
                                (matcher, MATCH_RVA, ((COMPARE_CALL[0], COMPARE_CALL[1], 0x10a139d0),))):
        for site, witness, target in edges:
            actual = code[site - begin:site - begin + len(witness)]
            if actual != witness or site + 5 + struct.unpack_from('<i', actual, 1)[0] != target:
                raise ValueError('filename_copy_source_direct_call_changed')


def load_copy_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('bounded_filename_copy_saved_source_required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != COPY_CAPTURE_SHA:
        raise ValueError('filename_copy_saved_source_full_hash_changed')
    report = json.loads(raw)
    if (report['native_pe_sha256'] != prior.SOURCE_PE
            or report['source_capture_sha256'] != STRING_CAPTURE_SHA
            or not report['fresh_match_edges_and_R8D1_verified']
            or not report['source_extents_verified'] or not report['process_creation_rechecked']):
        raise ValueError('filename_copy_saved_source_chain_changed')
    load_match_source(STRING_CAPTURE)
    load_source(CAPTURE)
    compare_raw = COMPARE_CAPTURE.read_bytes()
    if not 0 < len(compare_raw) <= 65536 or hashlib.sha256(compare_raw).hexdigest() != COMPARE_CAPTURE_SHA:
        raise ValueError('filename_copy_saved_compare_report_changed')
    compare_report = json.loads(compare_raw)
    compare_block = compare_report['fixed_code']['CacheFStringCompare']
    compare_bytes = bytes.fromhex(compare_block['bytes'])
    if (compare_report['native_pe_sha256'] != prior.SOURCE_PE
            or compare_block['rva'] != 0x10a137d0 or compare_block['size'] != 1024
            or len(compare_bytes) != 1024
            or hashlib.sha256(compare_bytes).hexdigest() != 'e25a9f37dd2f0049d09b5ba3ed0d4c047e15dbe674ef04682c19c0c3ebf9fba0'
            or hashlib.sha256(compare_bytes[0x200:0x2a5]).hexdigest() != COMPARE_FULL_SHA):
        raise ValueError('filename_copy_saved_complete_compare_changed')
    converter = bytes.fromhex(report['fixed_code']['PackageFilenameRoots']['bytes'])
    verify_converter(converter)
    verify_match_edges(converter)
    block = report['fixed_code']['PackageRootMatchHelper']
    matcher = bytes.fromhex(block['bytes'])
    if ((block['rva'], block['size'], block['sha256']) != (MATCH_RVA, MATCH_SIZE, MATCH_FULL_SHA)
            or len(matcher) != MATCH_SIZE or hashlib.sha256(matcher).hexdigest() != MATCH_FULL_SHA):
        raise ValueError('filename_copy_saved_matcher_span_changed')
    verify_copy_calls(converter, matcher)
    return COPY_CAPTURE_SHA


def verify_copy_extents(original_pe):
    result = {}
    with Path(original_pe).open('rb') as stream:
        for rva, size, po, ph, ps, uo, uh, us in COPY_METADATA:
            stream.seek(po)
            pdata = stream.read(12)
            stream.seek(uo)
            unwind = stream.read(len(bytes.fromhex(uh)))
            if (pdata != bytes.fromhex(ph) or hashlib.sha256(pdata).hexdigest() != ps
                    or struct.unpack('<III', pdata)[:2] != (rva, rva + size)
                    or unwind != bytes.fromhex(uh) or hashlib.sha256(unwind).hexdigest() != us):
                raise ValueError('filename_copy_exact_source_extent_changed')
            result[hex(rva)] = dict(begin_rva=rva, end_exclusive_rva=rva + size, bytes=size,
                                   pdata_file_offset=po, pdata_sha256=ps,
                                   unwind_file_offset=uo, unwind_sha256=us)
    return result


def allowed_spans(*, accessor_prefix=False, root_strings=False, root_match_helper=False,
                  filename_copy_helpers=False):
    if sum(bool(mode) for mode in (accessor_prefix, root_strings, root_match_helper, filename_copy_helpers)) > 1:
        raise ValueError('filename_header_modes_are_exclusive')
    if filename_copy_helpers:
        return {*prior.ROOTS_CHUNKS, (prior.ROOT_STATE_TARGET_RVA, prior.ROOT_STATE_TARGET_SIZE),
                (MATCH_RVA, MATCH_SIZE), *COPY_TARGETS.values()}
    if root_match_helper:
        return {*prior.ROOTS_CHUNKS, (MATCH_RVA, MATCH_SIZE)}
    if root_strings:
        return {*prior.ROOTS_CHUNKS, (prior.ROOT_STATE_TARGET_RVA, prior.ROOT_STATE_TARGET_SIZE),
                *((rva, 16) for rva in HEADERS.values()), (ACCESSOR_SLOT_RVA, 8),
                (ACCESSOR_TARGET_RVA, ACCESSOR_PREFIX_SIZE)}
    if accessor_prefix:
        return {*prior.ROOTS_CHUNKS, (prior.ROOT_STATE_TARGET_RVA, prior.ROOT_STATE_TARGET_SIZE),
                (ACCESSOR_SLOT_RVA, 8), (ACCESSOR_TARGET_RVA, ACCESSOR_PREFIX_SIZE)}
    return {*prior.ROOTS_CHUNKS, (prior.ROOT_STATE_TARGET_RVA, prior.ROOT_STATE_TARGET_SIZE),
            *((rva, 16) for rva in HEADERS.values()), (ACCESSOR_SLOT_RVA, 8)}


def capture(read, base, module_size, *, source_digest, actual_created, expected_created,
            accessor_prefix=False, root_strings=False, read_characters=None, root_match_helper=False,
            filename_copy_helpers=False):
    if sum(bool(mode) for mode in (accessor_prefix, root_strings, root_match_helper, filename_copy_helpers)) > 1:
        raise ValueError('filename_header_modes_are_exclusive')
    if root_strings and not callable(read_characters):
        raise ValueError('bounded_filename_character_reader_required')
    prior.local.verify_creation(actual_created, expected_created)
    if source_digest != (COPY_CAPTURE_SHA if filename_copy_helpers else STRING_CAPTURE_SHA if root_match_helper else
                         ACCESSOR_CAPTURE_SHA if root_strings else
                         HEADER_CAPTURE_SHA if accessor_prefix else CAPTURE_SHA):
        raise ValueError('pinned_filename_header_source_required')
    spans = allowed_spans(accessor_prefix=accessor_prefix, root_strings=root_strings,
                          root_match_helper=root_match_helper, filename_copy_helpers=filename_copy_helpers)
    if (type(base) is not int or type(module_size) is not int or base <= 0 or module_size <= 0
            or base + module_size >= 0x800000000000
            or any(not 0 <= rva < rva + size <= module_size for rva, size in spans)):
        raise ValueError('fixed_filename_header_ranges_outside_module')
    total = 0
    def fixed(rva, size):
        nonlocal total
        if (rva, size) not in spans or not 0 < size <= 1024:
            raise ValueError('read_outside_fixed_filename_header_scope')
        raw = read(base + rva, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError('short_fixed_filename_header_read')
        total += size
        return {'rva': rva, 'size': size, 'bytes': raw.hex(),
                'sha256': hashlib.sha256(raw).hexdigest()}
    chunks = [fixed(rva, size) for rva, size in prior.ROOTS_CHUNKS]
    converter_bytes = b''.join(bytes.fromhex(chunk['bytes']) for chunk in chunks)
    verify_converter(converter_bytes)
    if root_match_helper:
        verify_match_edges(converter_bytes)
        helper = fixed(MATCH_RVA, MATCH_SIZE)
        return {'native_pe_sha256': prior.SOURCE_PE, 'source_capture_sha256': source_digest,
                'fixed_code': {'PackageFilenameRoots': {'rva': prior.ROOTS_TARGET_RVA,
                'size': len(converter_bytes), 'bytes': converter_bytes.hex(),
                'sha256': hashlib.sha256(converter_bytes).hexdigest(), 'chunk_spans': chunks},
                'PackageRootMatchHelper': helper}, 'root_match_helper': True,
                'captured_bytes': total, 'fresh_converter_full_span_verified': True,
                'fresh_match_edges_and_R8D1_verified': True, 'heap_read': False,
                'pointer_followed': False, 'native_called': False, 'game_launched': False,
                'actual_filename_proven': False,
                'scope': 'Fresh complete converter2653B and its original-pdata-bounded213B '
                         'direct root matcher, exact threeE8/R8D1 source witnesses; code-only, '
                         'no contained-call follows or actual filename/texture claim'}
    getter = fixed(prior.ROOT_STATE_TARGET_RVA, prior.ROOT_STATE_TARGET_SIZE)
    verify_getter(bytes.fromhex(getter['bytes']))
    if filename_copy_helpers:
        verify_match_edges(converter_bytes)
        matcher = fixed(MATCH_RVA, MATCH_SIZE)
        matcher_bytes = bytes.fromhex(matcher['bytes'])
        if matcher['sha256'] != MATCH_FULL_SHA:
            raise ValueError('fresh_filename_copy_complete_matcher_changed')
        verify_copy_calls(converter_bytes, matcher_bytes)
        targets = {}
        for name, (rva, size) in COPY_TARGETS.items():
            targets[name] = fixed(rva, size)
            if name == 'PackageBoundedRootCompare' and targets[name]['sha256'] != COMPARE_FULL_SHA:
                raise ValueError('fresh_filename_copy_complete_compare_changed')
        return dict(native_pe_sha256=prior.SOURCE_PE, source_capture_sha256=source_digest,
                    fixed_code={'PackageFilenameRoots': dict(rva=prior.ROOTS_TARGET_RVA,
                    size=len(converter_bytes), bytes=converter_bytes.hex(),
                    sha256=hashlib.sha256(converter_bytes).hexdigest(), chunk_spans=chunks),
                    'PackageFilenameRootStateGetter': getter, 'PackageRootMatchHelper': matcher, **targets},
                    filename_copy_helpers=True, captured_bytes=total,
                    fresh_code_and_direct_edges_verified=True, fresh_compare_full_span_verified=True,
                    append_entry_complete_function_claim=False,
                    heap_read=False, pointer_followed=False, native_called=False, game_launched=False,
                    actual_filename_proven=False,
                    scope='Fresh converter2653B/getter123B/matcher213B, then source-qualified fixed '
                          'compare165B/append entry24B/output move123B; code only, no contained-call follows')
    if accessor_prefix or root_strings:
        slot = fixed(ACCESSOR_SLOT_RVA, 8)
        if struct.unpack('<Q', bytes.fromhex(slot['bytes']))[0] != base + ACCESSOR_TARGET_RVA:
            raise ValueError('fresh_filename_accessor_slot_does_not_match_source_fixed_target')
        prefix = fixed(ACCESSOR_TARGET_RVA, ACCESSOR_PREFIX_SIZE)
        if root_strings:
            if (bytes.fromhex(prefix['bytes']) != ACCESSOR_LEAF_BYTES
                    or prefix['sha256'] != ACCESSOR_LEAF_SHA):
                raise ValueError('fresh_filename_string_accessor_leaf_changed')
            headers = {name: fixed(rva, 16) for name, rva in HEADERS.items()}
            layouts = {name: bounded_header(block['rva'], bytes.fromhex(block['bytes']))
                       for name, block in headers.items()}
            strings = {}
            for name, block in headers.items():
                pointer, count, maximum, size = layouts[name]
                raw = (read_characters(block['rva'], bytes.fromhex(block['bytes'])) if count else b'')
                total += size
                value = decode_utf16(raw, count)
                strings[name] = dict(header=block, character_pointer=hex(pointer), count=count,
                                     maximum=maximum, bytes=raw.hex(),
                                     sha256=hashlib.sha256(raw).hexdigest(), value=value)
            for block in headers.values():
                repeated = fixed(block['rva'], 16)
                if repeated['bytes'] != block['bytes']:
                    raise ValueError('filename_string_header_changed_during_read')
            for name, block in headers.items():
                pointer, count, maximum, size = layouts[name]
                raw = (read_characters(block['rva'], bytes.fromhex(block['bytes'])) if count else b'')
                total += size
                decode_utf16(raw, count)
                if raw.hex() != strings[name]['bytes']:
                    raise ValueError('filename_string_characters_changed_during_read')
            repeated = fixed(ACCESSOR_SLOT_RVA, 8)
            if repeated['bytes'] != slot['bytes']:
                raise ValueError('filename_string_accessor_slot_changed_during_read')
            return {'native_pe_sha256': prior.SOURCE_PE, 'source_capture_sha256': source_digest,
                    'fixed_code': {'PackageFilenameRoots': {'rva': prior.ROOTS_TARGET_RVA,
                    'size': len(converter_bytes), 'bytes': converter_bytes.hex(),
                    'sha256': hashlib.sha256(converter_bytes).hexdigest(), 'chunk_spans': chunks},
                    'PackageFilenameRootStateGetter': getter, 'FStringCharacterAccessorPrefix': prefix},
                    'accessor_slot': slot, 'strings': strings, 'state_rva': STATE_RVA,
                    'root_strings': True, 'captured_bytes': total,
                    'character_read_bytes': sum(layout[3] * 2 for layout in layouts.values()),
                    'maximum_captured_bytes': 8088, 'fresh_code_full_spans_verified': True,
                    'headers_characters_and_slot_rechecked': True,
                    'character_pointer_contract_proven': True,
                    'heap_read': any(layout[1] for layout in layouts.values()),
                    'pointer_followed': any(layout[1] for layout in layouts.values()),
                    'native_called': False, 'game_launched': False,
                    'dynamic_root_array_read': False, 'actual_filename_proven': False,
                    'scope': 'Source-qualified five fixedFString headers and their current UTF16 '
                             'buffers only, max256codeunits each, exact leaf accessor/full code '
                             'gates and header/character/IAT stability; no root-array traversal '
                             'or native conversion/texture/physicalentry claim'}
        repeated = fixed(ACCESSOR_SLOT_RVA, 8)
        if repeated['bytes'] != slot['bytes']:
            raise ValueError('filename_accessor_slot_changed_during_prefix_read')
        return {'native_pe_sha256': prior.SOURCE_PE, 'source_capture_sha256': source_digest,
                'fixed_code': {'PackageFilenameRoots': {'rva': prior.ROOTS_TARGET_RVA,
                'size': len(converter_bytes), 'bytes': converter_bytes.hex(),
                'sha256': hashlib.sha256(converter_bytes).hexdigest(), 'chunk_spans': chunks},
                'PackageFilenameRootStateGetter': getter, 'FStringCharacterAccessorPrefix': prefix},
                'accessor_slot': slot, 'accessor_slot_rechecked': True,
                'accessor_prefix': True, 'captured_bytes': total,
                'fresh_code_full_spans_verified': True, 'heap_read': False,
                'pointer_followed': False, 'native_called': False, 'game_launched': False,
                'character_pointer_contract_proven': False, 'accessor_function_complete': False,
                'actual_filename_proven': False,
                'scope': 'Source-pinned converter2653B/getter123B, fresh source-named8B IAT '
                         'equal to base+fixedcandidate d968d0, candidate16B prefix and8B slot '
                         'recheck; no complete-function, character-pointer or filename claim'}
    headers = {name: fixed(rva, 16) for name, rva in HEADERS.items()}
    slot = fixed(ACCESSOR_SLOT_RVA, 8)
    for block in [*headers.values(), slot]:
        repeated = fixed(block['rva'], block['size'])
        if repeated['bytes'] != block['bytes']:
            raise ValueError('filename_header_or_accessor_slot_changed_during_read')
    for block in headers.values():
        first, count, maximum = struct.unpack('<Qii', bytes.fromhex(block['bytes']))
        block.update(first_qword=hex(first), count=count, maximum=maximum,
                     character_pointer_contract_proven=False, characters_read=False)
    return {'native_pe_sha256': prior.SOURCE_PE, 'source_capture_sha256': source_digest,
            'fixed_code': {'PackageFilenameRoots': {'rva': prior.ROOTS_TARGET_RVA,
            'size': len(converter_bytes), 'bytes': converter_bytes.hex(),
            'sha256': hashlib.sha256(converter_bytes).hexdigest(), 'chunk_spans': chunks},
            'PackageFilenameRootStateGetter': getter}, 'fixed_headers': headers,
            'accessor_slot': slot, 'state_rva': STATE_RVA, 'captured_bytes': total,
            'fresh_code_full_spans_verified': True, 'headers_and_slot_rechecked': True,
            'heap_read': False, 'pointer_followed': False, 'native_called': False,
            'game_launched': False, 'character_pointer_contract_proven': False,
            'actual_filename_proven': False,
            'scope': 'Complete source-pinned converter2653B/getter123B, five fixed16B module '
                     'headers and one source-named8B accessor slot, followed by88B stability '
                     'recheck; first qwords recorded without interpreting/following them'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--expected-create-time', type=float, required=True)
    parser.add_argument('--source-game', type=Path, required=True)
    parser.add_argument('--shadow-game', type=Path, required=True)
    parser.add_argument('--source-capture', type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--accessor-prefix', action='store_true',
                        help='Read only a source-fixed16B accessor prefix after fresh IAT equality')
    modes.add_argument('--root-strings', action='store_true',
                       help='Read only five source-fixed FString UTF16 buffers after fresh leaf gates')
    modes.add_argument('--root-match-helper', action='store_true',
                       help='Read source-pinned converter and its213B direct root matcher, code only')
    modes.add_argument('--filename-copy-helpers', action='store_true',
                       help='Read fixed comparator165B/append entry24B/move123B after fresh source code gates')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.pid <= 0 or ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error('explicit_native_x64_shadow_PID_required')
    source_capture = args.source_capture or (COPY_CAPTURE if args.filename_copy_helpers else STRING_CAPTURE if args.root_match_helper else
                                            ACCESSOR_CAPTURE if args.root_strings else
                                            HEADER_CAPTURE if args.accessor_prefix else CAPTURE)
    source_digest = (load_copy_source(source_capture) if args.filename_copy_helpers else load_match_source(source_capture) if args.root_match_helper else
                     load_strings_source(source_capture) if args.root_strings else
                     load_accessor_source(source_capture) if args.accessor_prefix
                     else load_source(source_capture))
    installed_root, shadow_root = game_paths(args.source_game, args.shadow_game)
    output = prior.local.output_path(args.output, installed_root, shadow_root)
    installed = installed_root / prior.local.source.CLIENT_RELATIVE_PATH
    shadow = shadow_root / prior.local.source.CLIENT_RELATIVE_PATH
    prior.local.source.verify_shadow_executable(shadow, shadow, installed)
    with installed.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != prior.SOURCE_PE:
            raise ValueError('original_source_executable_sha256_mismatch')
    extents = {'converter': prior.verify_roots_extent(installed)}
    if args.root_match_helper or args.filename_copy_helpers:
        extents['root_match_helper'] = verify_match_extent(installed)
    if not args.root_match_helper:
        extents['getter'] = prior.verify_root_state_extent(installed)
    if args.filename_copy_helpers:
        extents['copy_helpers'] = verify_copy_extents(installed)
    if args.accessor_prefix or args.root_strings:
        with installed.open('rb') as stream:
            stream.seek(ORIGINAL_ACCESSOR_SLOT_OFFSET)
            slot = stream.read(8)
        if (slot != ORIGINAL_ACCESSOR_SLOT_BYTES
                or hashlib.sha256(slot).hexdigest() != ORIGINAL_ACCESSOR_SLOT_SHA):
            raise ValueError('original_filename_accessor_slot_changed')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    kernel.K32EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                           ctypes.POINTER(wintypes.DWORD)]
    kernel.K32GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                             ctypes.POINTER(prior.local.source.ModuleInfo), wintypes.DWORD]
    kernel.K32GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                            wintypes.LPWSTR, wintypes.DWORD]
    kernel.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    handle = kernel.OpenProcess(0x0410, False, args.pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        def created():
            times = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
                raise ctypes.WinError(ctypes.get_last_error())
            ticks = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            return ticks / 10000000 - 11644473600
        creation = created()
        prior.local.verify_creation(creation, args.expected_create_time)
        modules, needed = (wintypes.HMODULE * 1024)(), wintypes.DWORD()
        if not kernel.K32EnumProcessModules(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not needed.value or needed.value > ctypes.sizeof(modules):
            raise ValueError('unexpected_native_module_count')
        path = ctypes.create_unicode_buffer(32768)
        if not kernel.K32GetModuleFileNameExW(handle, modules[0], path, len(path)):
            raise ctypes.WinError(ctypes.get_last_error())
        if Path(path.value).resolve() != shadow.resolve():
            raise ValueError('PID_does_not_identify_authorized_shadow_executable')
        info = prior.local.source.ModuleInfo()
        if not kernel.K32GetModuleInformation(handle, modules[0], ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.size != prior.MODULE_SIZE:
            raise ValueError('source_module_size_changed')
        spans = allowed_spans(accessor_prefix=args.accessor_prefix, root_strings=args.root_strings,
                              root_match_helper=args.root_match_helper, filename_copy_helpers=args.filename_copy_helpers)
        observed_fixed = {}
        def read(address, size):
            if ((address - info.base, size) not in spans or not 0 < size <= 1024
                    or not info.base <= address < address + size <= info.base + info.size):
                raise ValueError('process_read_outside_fixed_filename_header_scope')
            raw, actual = ctypes.create_string_buffer(size), ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, raw, size, ctypes.byref(actual)):
                raise ctypes.WinError(ctypes.get_last_error())
            if actual.value != size:
                raise ValueError('short_filename_header_adapter_read')
            observed_fixed[address - info.base] = raw.raw
            return raw.raw
        class MemoryBasicInformation(ctypes.Structure):
            _fields_ = [('base', ctypes.c_void_p), ('allocation_base', ctypes.c_void_p),
                        ('allocation_protect', wintypes.DWORD), ('partition', wintypes.WORD),
                        ('region_size', ctypes.c_size_t), ('state', wintypes.DWORD),
                        ('protect', wintypes.DWORD), ('kind', wintypes.DWORD)]
        kernel.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                         ctypes.POINTER(MemoryBasicInformation), ctypes.c_size_t]
        kernel.VirtualQueryEx.restype = ctypes.c_size_t
        character_calls = {}
        def read_characters(header_rva, header):
            pointer, count, maximum, size = bounded_header(header_rva, header)
            if (not args.root_strings or not count or observed_fixed.get(header_rva) != header
                    or observed_fixed.get(ACCESSOR_TARGET_RVA) != ACCESSOR_LEAF_BYTES
                    or observed_fixed.get(ACCESSOR_SLOT_RVA) != struct.pack('<Q', info.base + ACCESSOR_TARGET_RVA)):
                raise ValueError('character_read_requires_fresh_source_fixed_header_and_leaf')
            verify_converter(b''.join(observed_fixed.get(rva, b'') for rva, size in prior.ROOTS_CHUNKS))
            verify_getter(observed_fixed.get(prior.ROOT_STATE_TARGET_RVA, b''))
            character_calls[header_rva] = character_calls.get(header_rva, 0) + 1
            if character_calls[header_rva] > 2:
                raise ValueError('source_fixed_filename_character_read_limit_exceeded')
            region = MemoryBasicInformation()
            if kernel.VirtualQueryEx(handle, pointer, ctypes.byref(region), ctypes.sizeof(region)) != ctypes.sizeof(region):
                raise ctypes.WinError(ctypes.get_last_error())
            if (region.state != 0x1000 or region.protect & 0x101
                    or region.protect & 0xff not in (0x02, 0x04, 0x08, 0x20, 0x40, 0x80)
                    or not region.base <= pointer < pointer + size <= region.base + region.region_size):
                raise ValueError('source_fixed_filename_characters_not_in_readable_committed_region')
            raw, actual = ctypes.create_string_buffer(size), ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, pointer, raw, size, ctypes.byref(actual)):
                raise ctypes.WinError(ctypes.get_last_error())
            if actual.value != size:
                raise ValueError('short_source_fixed_filename_character_adapter_read')
            return raw.raw
        report = capture(read, info.base, info.size, source_digest=source_digest,
                         actual_created=creation, expected_created=args.expected_create_time,
                         accessor_prefix=args.accessor_prefix, root_strings=args.root_strings,
                         read_characters=read_characters if args.root_strings else None,
                         root_match_helper=args.root_match_helper, filename_copy_helpers=args.filename_copy_helpers)
        prior.local.verify_creation(created(), creation)
        report.update(source_extents=extents, source_extents_verified=True, pid=args.pid,
                      module_base=hex(info.base), module_size=info.size,
                      process_created_unix=creation, process_creation_rechecked=True,
                      shadow_executable=str(shadow.resolve()), process_accessed=True,
                      captured_at_utc=datetime.now(timezone.utc).isoformat())
        with output.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'captured_bytes': report['captured_bytes'], 'heap_read': report['heap_read'],
                          'pointer_followed': report['pointer_followed'], 'report': str(output)}))
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    main()
