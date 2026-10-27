"""Read two source-witnessed package-cache helpers and one fixed module slot.

Requires an explicit shadow PID and its previously observed creation time.
No launches, native calls, heap reads, hooks, writes to the game or pointer follows.
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
import probe_live_local_image_loader as local
from read_keybox_manager_interface import MODULE_SIZE


ROOT = Path(__file__).resolve().parent.parent
SOURCE_PE = local.source.EXPECTED_PE
SOURCE_CAPTURE_SHA = '01f326632251d583a7db7eefa63929caceacc6ec9d7dc0a72612da1c97d35d09'
SOURCE_CAPTURE = ROOT / 'work/evidence/live-local-image-package-brush-bundle-20261005-private.json'
SOURCE_RVA = 0x10ecd110
CODE_SIZE = 1024
CALL_EDGES = (
    (0x10ecd3a0, 0x109f2ea0, bytes.fromhex('e8fb5ab2ff')),
    (0x10ecd45d, 0x10ecd9a0, bytes.fromhex('e83e050000')),
)
TARGETS = {'PathSplit': 0x109f2ea0, 'CacheChildLookup': 0x10ecd9a0}
DELIMITER_SLOT_RVA = 0x1d5ad108
CHILD_CAPTURE_SHA = 'c6d1d36b83f9621dd982bc63fa90c72637e6cc896b6db3d6869515e0dd987f02'
CHILD_CAPTURE = ROOT / 'work/evidence/live-package-path-cache-bundle-20261005-private.json'
CHILD_SOURCE_RVA = 0x10ecd9a0
CHILD_SOURCE_SHA = '79a5418c4aaadd1b66e2ce28d7c11a4608bda702cbc4147dcef222d41b51dc47'
CHILD_CALL_SITE = 0x10ecd9cd
CHILD_CALL_BYTES = bytes.fromhex('e85ea1eeef')
CHILD_TARGETS = {'CacheChildMapFind': 0xdb7b30}
COMPARE_CAPTURE_SHA = '5f4d2c18050a5ea11969ccd8fd18289522aa5339e9eb9794ae79f66942294e3b'
COMPARE_CAPTURE = ROOT / 'work/evidence/live-package-child-map-bundle-20261005-private.json'
COMPARE_SOURCE_RVA = 0xdb7b30
COMPARE_SOURCE_SHA = '029a56a4e81bc1c48fcd2e2960e1211dbc8d15e3e280d561ab69555e1760546c'
COMPARE_CALL_SITE = 0xdb7c0e
COMPARE_CALL_BYTES = bytes.fromhex('e8bdbbc50f')
COMPARE_TARGETS = {'CacheFStringCompare': 0x10a137d0}
FILENAME_SOURCE_SHA = 'a577995db5aa053db3a4aca176bd0352d104530972184f531822d1ad0ad96635'
FILENAME_TARGET_RVA = 0x10cd47f0
FILENAME_TARGET_SIZE = 130
FILENAME_STATIC_RVA = 0x1e340388
FILENAME_CALL_EDGES = (
    (0x10ecd1ea, FILENAME_TARGET_RVA, bytes.fromhex('e80176e0ff')),
    (0x10ecd282, FILENAME_TARGET_RVA, bytes.fromhex('e86975e0ff')),
)
FILENAME_STATIC_EDGE = (0x10ecd273, FILENAME_STATIC_RVA, bytes.fromhex('4c8d050e31470d'))
# Original immutable .pdata and unwind rows bound this callee, excluding neighbors.
FILENAME_PDATA_OFFSET = 510366036
FILENAME_PDATA_HEX = 'f047cd107248cd10a0b8dc1b'
FILENAME_PDATA_SHA = '43fd18abb6f1665e0be693660dbd6dcf8801d831184424040ce5efe8c49013ac'
FILENAME_UNWIND_OFFSET = 467446944
FILENAME_UNWIND_HEX = '010a04000a3408000a520670'
FILENAME_UNWIND_SHA = '95a10c6d2d751622a4535e1f8c8bdca6a784f9865cf0e1039457f8b7b56c3dae'
ROOTS_CAPTURE = ROOT / 'work/evidence/live-package-filename-transform-bundle-20261005-private.json'
ROOTS_CAPTURE_SHA = 'a91145bea6fb87c45fe31a79d9c34ab13a26a4505f49bb402a9e86a089f7069d'
ROOTS_SOURCE_SHA = 'e468901e3a9e2c7c23c40ae4f453a74a621ea7c965cf6a4965b32a6919629b83'
ROOTS_CALL_SITE = 0x10cd480f
ROOTS_CALL_BYTES = bytes.fromhex('e85c400100')
ROOTS_TARGET_RVA = 0x10ce8870
ROOTS_TARGET_SIZE = 2653
ROOTS_CHUNKS = ((ROOTS_TARGET_RVA, 1024), (ROOTS_TARGET_RVA + 1024, 1024),
                (ROOTS_TARGET_RVA + 2048, 605))
ROOTS_PDATA_OFFSET = 510369180
ROOTS_PDATA_HEX = '7088ce10cd92ce102c30721c'
ROOTS_PDATA_SHA = 'd6a8c2b17c50d23860fc1b57b6c0de11036e78b727e10a830c02803d0cdb1e06'
ROOTS_UNWIND_OFFSET = 477242412
ROOTS_UNWIND_HEX = '01240c0024741700246416002434140024d21df01be019d017c01550'
ROOTS_UNWIND_SHA = '3c07582ce63e539fe02d6601c409623c8cc4e0ce9d0de336cedb16fa2349e0d0'
ROOT_STATE_CAPTURE = ROOT / 'work/evidence/live-package-filename-roots-bundle-20261005-private.json'
ROOT_STATE_CAPTURE_SHA = 'cb5c826b72479ef6c5583def7d2cc252d392cf4aa14dfce4ac89923cebefad4e'
ROOT_STATE_SOURCE_SHA = '96b0cffc40775053776d87f87f792fa2f0365f88c1427786be6f2459edcc0649'
ROOT_STATE_CALL_SITE = 0x10ce889a
ROOT_STATE_CALL_BYTES = bytes.fromhex('e8a137feff')
ROOT_STATE_TARGET_RVA = 0x10ccc040
ROOT_STATE_TARGET_SIZE = 123
ROOT_STATE_PDATA_OFFSET = 510364476
ROOT_STATE_PDATA_HEX = '40c0cc10bbc0cc10acb3dc1b'
ROOT_STATE_PDATA_SHA = '6382c6a7af875c636c312498f748e6b1d818d40881b1ffb679514622f4570bdc'
ROOT_STATE_UNWIND_OFFSET = 467445676
ROOT_STATE_UNWIND_HEX = '0106020006320230'
ROOT_STATE_UNWIND_SHA = 'eb874a2d5756386f3a7d463290a08f132ac00fa4e4080cfb811bafc05b2569b2'


def verify_followup_modes(child_map_followup, compare_followup, filename_transform_followup,
                          filename_roots_followup=False, filename_root_state_followup=False):
    if sum(bool(mode) for mode in (child_map_followup, compare_followup,
                                  filename_transform_followup, filename_roots_followup,
                                  filename_root_state_followup)) > 1:
        raise ValueError('package_cache_followup_modes_are_exclusive')


def verify_filename_extent(original_pe):
    with Path(original_pe).open('rb') as source:
        source.seek(FILENAME_PDATA_OFFSET)
        pdata = source.read(12)
        source.seek(FILENAME_UNWIND_OFFSET)
        unwind = source.read(12)
    if (pdata.hex() != FILENAME_PDATA_HEX or hashlib.sha256(pdata).hexdigest() != FILENAME_PDATA_SHA
            or unwind.hex() != FILENAME_UNWIND_HEX
            or hashlib.sha256(unwind).hexdigest() != FILENAME_UNWIND_SHA
            or struct.unpack('<III', pdata) != (FILENAME_TARGET_RVA, 0x10cd4872, 0x1bdcb8a0)):
        raise ValueError('package_filename_source_extent_changed')
    return {'begin_rva': FILENAME_TARGET_RVA, 'end_exclusive_rva': 0x10cd4872,
            'bytes': FILENAME_TARGET_SIZE, 'pdata_file_offset': FILENAME_PDATA_OFFSET,
            'pdata_sha256': FILENAME_PDATA_SHA, 'unwind_file_offset': FILENAME_UNWIND_OFFSET,
            'unwind_sha256': FILENAME_UNWIND_SHA}


def verify_filename_edges(code):
    for site, target, expected in FILENAME_CALL_EDGES:
        offset = site - SOURCE_RVA
        witness = code[offset:offset + 5]
        if (witness != expected or site + 5 + struct.unpack_from('<i', witness, 1)[0] != target):
            raise ValueError('fresh_package_filename_call_changed')
    site, target, expected = FILENAME_STATIC_EDGE
    offset = site - SOURCE_RVA
    witness = code[offset:offset + 7]
    if (witness != expected or site + 7 + struct.unpack_from('<i', witness, 3)[0] != target):
        raise ValueError('fresh_package_filename_static_LEA_changed')


def verify_roots_call(code):
    offset = ROOTS_CALL_SITE - FILENAME_TARGET_RVA
    witness = code[offset:offset + 5]
    if (witness != ROOTS_CALL_BYTES
            or ROOTS_CALL_SITE + 5 + struct.unpack_from('<i', witness, 1)[0] != ROOTS_TARGET_RVA):
        raise ValueError('fresh_package_filename_roots_call_changed')


def verify_root_state_call(code):
    offset = ROOT_STATE_CALL_SITE - ROOTS_TARGET_RVA
    witness = code[offset:offset + 5]
    if (witness != ROOT_STATE_CALL_BYTES
            or ROOT_STATE_CALL_SITE + 5 + struct.unpack_from('<i', witness, 1)[0]
            != ROOT_STATE_TARGET_RVA):
        raise ValueError('fresh_package_filename_root_state_call_changed')


def verify_root_state_extent(original_pe):
    with Path(original_pe).open('rb') as source:
        source.seek(ROOT_STATE_PDATA_OFFSET)
        pdata = source.read(12)
        source.seek(ROOT_STATE_UNWIND_OFFSET)
        unwind = source.read(8)
    if (pdata.hex() != ROOT_STATE_PDATA_HEX
            or hashlib.sha256(pdata).hexdigest() != ROOT_STATE_PDATA_SHA
            or unwind.hex() != ROOT_STATE_UNWIND_HEX
            or hashlib.sha256(unwind).hexdigest() != ROOT_STATE_UNWIND_SHA
            or struct.unpack('<III', pdata) != (ROOT_STATE_TARGET_RVA, 0x10ccc0bb, 0x1bdcb3ac)):
        raise ValueError('package_filename_root_state_source_extent_changed')
    return {'begin_rva': ROOT_STATE_TARGET_RVA, 'end_exclusive_rva': 0x10ccc0bb,
            'bytes': ROOT_STATE_TARGET_SIZE, 'pdata_file_offset': ROOT_STATE_PDATA_OFFSET,
            'pdata_sha256': ROOT_STATE_PDATA_SHA, 'unwind_file_offset': ROOT_STATE_UNWIND_OFFSET,
            'unwind_sha256': ROOT_STATE_UNWIND_SHA}


def verify_roots_extent(original_pe):
    with Path(original_pe).open('rb') as source:
        source.seek(ROOTS_PDATA_OFFSET)
        pdata = source.read(12)
        source.seek(ROOTS_UNWIND_OFFSET)
        unwind = source.read(28)
    if (pdata.hex() != ROOTS_PDATA_HEX or hashlib.sha256(pdata).hexdigest() != ROOTS_PDATA_SHA
            or unwind.hex() != ROOTS_UNWIND_HEX
            or hashlib.sha256(unwind).hexdigest() != ROOTS_UNWIND_SHA
            or struct.unpack('<III', pdata) != (ROOTS_TARGET_RVA, 0x10ce92cd, 0x1c72302c)):
        raise ValueError('package_filename_roots_source_extent_changed')
    return {'begin_rva': ROOTS_TARGET_RVA, 'end_exclusive_rva': 0x10ce92cd,
            'bytes': ROOTS_TARGET_SIZE, 'pdata_file_offset': ROOTS_PDATA_OFFSET,
            'pdata_sha256': ROOTS_PDATA_SHA, 'unwind_file_offset': ROOTS_UNWIND_OFFSET,
            'unwind_sha256': ROOTS_UNWIND_SHA}


def verify_calls(code):
    for site, target, expected in CALL_EDGES:
        offset = site - SOURCE_RVA
        witness = code[offset:offset + 5]
        if (witness != expected
                or site + 5 + struct.unpack_from('<i', witness, 1)[0] != target):
            raise ValueError('fresh_package_cache_call_changed: ' + hex(site))


def verify_child_call(code):
    offset = CHILD_CALL_SITE - CHILD_SOURCE_RVA
    witness = code[offset:offset + 5]
    if (witness != CHILD_CALL_BYTES
            or CHILD_CALL_SITE + 5 + struct.unpack_from('<i', witness, 1)[0]
            != CHILD_TARGETS['CacheChildMapFind']):
        raise ValueError('fresh_child_map_call_changed')


def verify_compare_call(code):
    offset = COMPARE_CALL_SITE - COMPARE_SOURCE_RVA
    witness = code[offset:offset + 5]
    if (witness != COMPARE_CALL_BYTES
            or COMPARE_CALL_SITE + 5 + struct.unpack_from('<i', witness, 1)[0]
            != COMPARE_TARGETS['CacheFStringCompare']):
        raise ValueError('fresh_cache_compare_call_changed')


def load_source(path, *, child_map_followup=False, compare_followup=False,
                filename_transform_followup=False, filename_roots_followup=False,
                filename_root_state_followup=False):
    verify_followup_modes(child_map_followup, compare_followup, filename_transform_followup,
                          filename_roots_followup, filename_root_state_followup)
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('existing_bounded_package_cache_source_required')
    with path.open('rb') as stream:
        raw = stream.read(65537)
    digest = hashlib.sha256(raw).hexdigest()
    expected_digest = (ROOT_STATE_CAPTURE_SHA if filename_root_state_followup else
                       ROOTS_CAPTURE_SHA if filename_roots_followup else
                       COMPARE_CAPTURE_SHA if compare_followup else
                       CHILD_CAPTURE_SHA if child_map_followup else SOURCE_CAPTURE_SHA)
    if len(raw) > 65536 or digest != expected_digest:
        raise ValueError('package_cache_source_full_sha256_changed')
    report = json.loads(raw)
    if report.get('native_pe_sha256') != SOURCE_PE:
        raise ValueError('source_package_cache_PE_changed')
    if filename_roots_followup or filename_root_state_followup:
        expected_chain = ROOTS_CAPTURE_SHA if filename_root_state_followup else SOURCE_CAPTURE_SHA
        if report.get('source_capture_sha256') != expected_chain:
            raise ValueError('package_filename_roots_source_chain_changed')
        wrapper = report['fixed_code']['PackageFilenameTransform']
        data = bytes.fromhex(wrapper['bytes'])
        if ((wrapper['rva'], wrapper['size'], wrapper['sha256']) !=
                (FILENAME_TARGET_RVA, FILENAME_TARGET_SIZE, ROOTS_SOURCE_SHA)
                or len(data) != FILENAME_TARGET_SIZE
                or hashlib.sha256(data).hexdigest() != ROOTS_SOURCE_SHA):
            raise ValueError('package_filename_roots_source_wrapper_changed')
        verify_roots_call(data)
        if filename_root_state_followup:
            roots = report['fixed_code']['PackageFilenameRoots']
            root_bytes = bytes.fromhex(roots['bytes'])
            if ((roots['rva'], roots['size'], roots['sha256']) !=
                    (ROOTS_TARGET_RVA, ROOTS_TARGET_SIZE, ROOT_STATE_SOURCE_SHA)
                    or len(root_bytes) != ROOTS_TARGET_SIZE
                    or hashlib.sha256(root_bytes).hexdigest() != ROOT_STATE_SOURCE_SHA):
                raise ValueError('package_filename_root_state_source_helper_changed')
            verify_root_state_call(root_bytes)
            chunks = roots.get('chunk_spans', [])
            if [(part['rva'], part['size']) for part in chunks] != list(ROOTS_CHUNKS):
                raise ValueError('package_filename_root_state_source_chunks_changed')
            for part in chunks:
                offset = part['rva'] - ROOTS_TARGET_RVA
                if hashlib.sha256(root_bytes[offset:offset + part['size']]).hexdigest() != part['sha256']:
                    raise ValueError('package_filename_root_state_source_chunks_changed')
        block = report['source_code']
        expected_rva = SOURCE_RVA
    elif compare_followup:
        if report.get('source_capture_sha256') != CHILD_CAPTURE_SHA:
            raise ValueError('cache_compare_source_chain_changed')
        block = report['fixed_code']['CacheChildMapFind']
        expected_rva = COMPARE_SOURCE_RVA
    elif child_map_followup:
        if report.get('source_capture_sha256') != SOURCE_CAPTURE_SHA:
            raise ValueError('child_map_source_chain_changed')
        block = report['fixed_code']['CacheChildLookup']
        expected_rva = CHILD_SOURCE_RVA
    else:
        block = report['package_brush']['PackagePathPredicate']
        expected_rva = SOURCE_RVA
    code = bytes.fromhex(block['bytes'])
    if (block['rva'] != expected_rva or block['size'] != CODE_SIZE or len(code) != CODE_SIZE
            or hashlib.sha256(code).hexdigest() != block['sha256']):
        raise ValueError('source_package_cache_span_changed')
    if compare_followup:
        if block['sha256'] != COMPARE_SOURCE_SHA:
            raise ValueError('cache_compare_source_map_sha256_changed')
        verify_compare_call(code)
    elif child_map_followup:
        if block['sha256'] != CHILD_SOURCE_SHA:
            raise ValueError('child_map_source_lookup_sha256_changed')
        verify_child_call(code)
    elif filename_transform_followup or filename_roots_followup or filename_root_state_followup:
        if block['sha256'] != FILENAME_SOURCE_SHA:
            raise ValueError('package_filename_source_span_changed')
        verify_filename_edges(code)
    else:
        verify_calls(code)
    return digest


def allowed_spans(*, child_map_followup=False, compare_followup=False,
                  filename_transform_followup=False, filename_roots_followup=False,
                  filename_root_state_followup=False):
    verify_followup_modes(child_map_followup, compare_followup, filename_transform_followup,
                          filename_roots_followup, filename_root_state_followup)
    if filename_root_state_followup:
        return {(SOURCE_RVA, CODE_SIZE), (FILENAME_TARGET_RVA, FILENAME_TARGET_SIZE),
                *ROOTS_CHUNKS, (ROOT_STATE_TARGET_RVA, ROOT_STATE_TARGET_SIZE)}
    if filename_roots_followup:
        return {(SOURCE_RVA, CODE_SIZE), (FILENAME_TARGET_RVA, FILENAME_TARGET_SIZE),
                (FILENAME_STATIC_RVA, 16), *ROOTS_CHUNKS}
    if filename_transform_followup:
        return {(SOURCE_RVA, CODE_SIZE), (FILENAME_TARGET_RVA, FILENAME_TARGET_SIZE),
                (FILENAME_STATIC_RVA, 16)}
    if compare_followup:
        return {(COMPARE_SOURCE_RVA, CODE_SIZE),
                *((rva, CODE_SIZE) for rva in COMPARE_TARGETS.values())}
    if child_map_followup:
        return {(CHILD_SOURCE_RVA, CODE_SIZE),
                *((rva, CODE_SIZE) for rva in CHILD_TARGETS.values())}
    return {(SOURCE_RVA, CODE_SIZE), (DELIMITER_SLOT_RVA, 8),
            *((rva, CODE_SIZE) for rva in TARGETS.values())}


def capture(read, base, module_size, *, source_capture_digest, actual_created, expected_created,
            child_map_followup=False, compare_followup=False, filename_transform_followup=False,
            filename_roots_followup=False, filename_root_state_followup=False):
    verify_followup_modes(child_map_followup, compare_followup, filename_transform_followup,
                          filename_roots_followup, filename_root_state_followup)
    local.verify_creation(actual_created, expected_created)
    expected_digest = (ROOT_STATE_CAPTURE_SHA if filename_root_state_followup else
                       ROOTS_CAPTURE_SHA if filename_roots_followup else
                       COMPARE_CAPTURE_SHA if compare_followup else
                       CHILD_CAPTURE_SHA if child_map_followup else SOURCE_CAPTURE_SHA)
    if source_capture_digest != expected_digest:
        raise ValueError('pinned_package_cache_source_required')
    spans = allowed_spans(child_map_followup=child_map_followup, compare_followup=compare_followup,
                          filename_transform_followup=filename_transform_followup,
                          filename_roots_followup=filename_roots_followup,
                          filename_root_state_followup=filename_root_state_followup)
    if (type(base) is not int or type(module_size) is not int or base <= 0 or module_size <= 0
            or base + module_size >= 0x800000000000
            or any(not 0 <= rva < rva + size <= module_size for rva, size in spans)):
        raise ValueError('fixed_package_cache_ranges_outside_module')
    total = 0

    def fixed(rva, size):
        nonlocal total
        if (rva, size) not in spans or not 0 < size <= CODE_SIZE:
            raise ValueError('read_not_in_fixed_package_cache_scope')
        raw = read(base + rva, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError('short_package_cache_code_read')
        total += size
        return {'rva': rva, 'size': size, 'bytes': raw.hex(),
                'sha256': hashlib.sha256(raw).hexdigest()}

    if filename_roots_followup or filename_root_state_followup:
        source = fixed(SOURCE_RVA, CODE_SIZE)
        verify_filename_edges(bytes.fromhex(source['bytes']))
        if source['sha256'] != FILENAME_SOURCE_SHA:
            raise ValueError('fresh_package_filename_source_span_changed')
        wrapper = fixed(FILENAME_TARGET_RVA, FILENAME_TARGET_SIZE)
        verify_roots_call(bytes.fromhex(wrapper['bytes']))
        if wrapper['sha256'] != ROOTS_SOURCE_SHA:
            raise ValueError('fresh_package_filename_roots_wrapper_span_changed')
        chunks = [fixed(rva, size) for rva, size in ROOTS_CHUNKS]
        raw = b''.join(bytes.fromhex(chunk['bytes']) for chunk in chunks)
        if len(raw) != ROOTS_TARGET_SIZE:
            raise ValueError('package_filename_roots_chunk_accounting_changed')
        helper = {'rva': ROOTS_TARGET_RVA, 'size': len(raw), 'bytes': raw.hex(),
                  'sha256': hashlib.sha256(raw).hexdigest(),
                  'chunk_spans': [{key: chunk[key] for key in ('rva', 'size', 'sha256')}
                                  for chunk in chunks]}
        if filename_root_state_followup:
            verify_root_state_call(raw)
            if helper['sha256'] != ROOT_STATE_SOURCE_SHA:
                raise ValueError('fresh_package_filename_root_state_helper_span_changed')
            getter = fixed(ROOT_STATE_TARGET_RVA, ROOT_STATE_TARGET_SIZE)
            return {'native_pe_sha256': SOURCE_PE, 'source_capture_sha256': source_capture_digest,
                    'source_code': source, 'fixed_code': {'PackageFilenameTransform': wrapper,
                    'PackageFilenameRoots': helper, 'PackageFilenameRootStateGetter': getter},
                    'filename_root_state_followup': True, 'fresh_direct_calls_verified': True,
                    'fresh_roots_full_span_verified': True, 'captured_bytes': total,
                    'heap_read': False, 'native_called': False, 'game_launched': False,
                    'pointer_followed': False, 'root_state_type_proven': False,
                    'actual_filename_proven': False, 'cache_schema_verified': False,
                    'scope': 'Pinned caller1024B/wrapper130B, complete converter2653B and '
                             'its original-pdata-bounded direct state getter123B; code-only, '
                             'no root/extension strings, pointer follows or actual filename claim'}
        static = fixed(FILENAME_STATIC_RVA, 16)
        return {'native_pe_sha256': SOURCE_PE, 'source_capture_sha256': source_capture_digest,
                'source_code': source,
                'fixed_code': {'PackageFilenameTransform': wrapper, 'PackageFilenameRoots': helper},
                'filename_roots_followup': True, 'static_extension_header': static,
                'static_header_type_proven': False, 'fresh_direct_calls_verified': True,
                'fresh_static_LEA_verified': True, 'captured_bytes': total,
                'heap_read': False, 'native_called': False, 'game_launched': False,
                'pointer_followed': False, 'cache_schema_verified': False,
                'scope': 'Pinned caller1024B, wrapper130B, original-pdata-bounded direct converter '
                         '2653B in3 chunks, and caller-named static16B header; no contained-call '
                         'or heap follows, no actual filename or texture existence claim'}
    if filename_transform_followup:
        source = fixed(SOURCE_RVA, CODE_SIZE)
        verify_filename_edges(bytes.fromhex(source['bytes']))
        if source['sha256'] != FILENAME_SOURCE_SHA:
            raise ValueError('fresh_package_filename_source_span_changed')
        code = {'PackageFilenameTransform': fixed(FILENAME_TARGET_RVA, FILENAME_TARGET_SIZE)}
        static = fixed(FILENAME_STATIC_RVA, 16)
        return {'native_pe_sha256': SOURCE_PE, 'source_capture_sha256': source_capture_digest,
                'source_code': source, 'fixed_code': code, 'filename_transform_followup': True,
                'static_extension_header': static, 'static_header_type_proven': False,
                'fresh_direct_calls_verified': True, 'fresh_static_LEA_verified': True,
                'captured_bytes': total, 'heap_read': False, 'native_called': False,
                'game_launched': False, 'pointer_followed': False, 'cache_schema_verified': False,
                'scope': 'One pinned1024B caller, its original-pdata-bounded130B direct transform '
                         'callee, and the caller-named16B static header; no contained calls or '
                         'header pointer follows, no filename or texture existence claim'}
    if compare_followup:
        source = fixed(COMPARE_SOURCE_RVA, CODE_SIZE)
        verify_compare_call(bytes.fromhex(source['bytes']))
        if source['sha256'] != COMPARE_SOURCE_SHA:
            raise ValueError('fresh_cache_compare_source_span_changed')
        code = {name: fixed(rva, CODE_SIZE) for name, rva in COMPARE_TARGETS.items()}
        return {'native_pe_sha256': SOURCE_PE, 'source_capture_sha256': source_capture_digest,
                'source_map_span_sha256': COMPARE_SOURCE_SHA,
                'source_code': source, 'fixed_code': code, 'compare_followup': True,
                'fresh_direct_calls_verified': True, 'captured_bytes': total,
                'heap_read': False, 'native_called': False, 'game_launched': False,
                'pointer_followed': False, 'cache_schema_verified': False,
                'scope': 'One fixed1024B map-find prefix, one source-gated1024B direct FString '
                         'comparator prefix; no heap reads or contained-call follows'}
    if child_map_followup:
        source = fixed(CHILD_SOURCE_RVA, CODE_SIZE)
        verify_child_call(bytes.fromhex(source['bytes']))
        if source['sha256'] != CHILD_SOURCE_SHA:
            raise ValueError('fresh_child_map_source_span_changed')
        code = {name: fixed(rva, CODE_SIZE) for name, rva in CHILD_TARGETS.items()}
        return {'native_pe_sha256': SOURCE_PE, 'source_capture_sha256': source_capture_digest,
                'source_lookup_span_sha256': CHILD_SOURCE_SHA,
                'source_code': source, 'fixed_code': code, 'child_map_followup': True,
                'fresh_direct_calls_verified': True, 'captured_bytes': total,
                'heap_read': False, 'native_called': False, 'game_launched': False,
                'pointer_followed': False, 'cache_schema_verified': False,
                'scope': 'One fixed1024B lookup prefix, one source-gated1024B direct child-map '
                         'helper prefix; no heap reads or contained-call follows'}
    source = fixed(SOURCE_RVA, CODE_SIZE)
    # Both fresh E8 witnesses must match before either helper or the slot is read.
    verify_calls(bytes.fromhex(source['bytes']))
    code = {name: fixed(rva, CODE_SIZE) for name, rva in TARGETS.items()}
    delimiter = fixed(DELIMITER_SLOT_RVA, 8)
    return {'native_pe_sha256': SOURCE_PE, 'source_capture_sha256': source_capture_digest,
            'source_code': source, 'fixed_code': code, 'delimiter_slot': delimiter,
            'fresh_direct_calls_verified': True, 'captured_bytes': total,
            'heap_read': False, 'native_called': False, 'game_launched': False,
            'pointer_followed': False, 'cache_schema_verified': False,
            'scope': 'One fixed1024B source prefix, two source-gated1024B helper prefixes, '
                     'one fixed8B module slot; slot value and contained calls are not followed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--expected-create-time', type=float, required=True)
    parser.add_argument('--source-game', type=Path, required=True)
    parser.add_argument('--shadow-game', type=Path, required=True)
    parser.add_argument('--source-capture', type=Path)
    followup = parser.add_mutually_exclusive_group()
    followup.add_argument('--child-map-followup', action='store_true',
                          help='Read only the pinned fresh lookup prefix and its direct map-find helper')
    followup.add_argument('--compare-followup', action='store_true',
                          help='Read only the pinned fresh map-find prefix and its direct comparator')
    followup.add_argument('--filename-transform-followup', action='store_true',
                          help='Read only the pinned package caller,130B transform and static16B header')
    followup.add_argument('--filename-roots-followup', action='store_true',
                          help='Read pinned caller/wrapper,2653B direct converter and static16B header')
    followup.add_argument('--filename-root-state-followup', action='store_true',
                          help='Read pinned caller/wrapper/converter and its123B direct state getter')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.pid <= 0 or ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error('explicit_native_x64_shadow_PID_required')
    local.verify_creation(args.expected_create_time, args.expected_create_time)
    source_capture = args.source_capture or (ROOT_STATE_CAPTURE if args.filename_root_state_followup else
                                            ROOTS_CAPTURE if args.filename_roots_followup else
                                            COMPARE_CAPTURE if args.compare_followup else
                                            CHILD_CAPTURE if args.child_map_followup else SOURCE_CAPTURE)
    source_digest = load_source(source_capture, child_map_followup=args.child_map_followup,
                                compare_followup=args.compare_followup,
                                filename_transform_followup=args.filename_transform_followup,
                                filename_roots_followup=args.filename_roots_followup,
                                filename_root_state_followup=args.filename_root_state_followup)
    installed_root, shadow_root = game_paths(args.source_game, args.shadow_game)
    output = local.output_path(args.output, installed_root, shadow_root)
    installed = installed_root / local.source.CLIENT_RELATIVE_PATH
    shadow = shadow_root / local.source.CLIENT_RELATIVE_PATH
    local.source.verify_shadow_executable(shadow, shadow, installed)
    with installed.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != SOURCE_PE:
            raise ValueError('original_source_executable_sha256_mismatch')
    filename_extent = (verify_filename_extent(installed)
                       if args.filename_transform_followup or args.filename_roots_followup
                       or args.filename_root_state_followup else None)
    roots_extent = (verify_roots_extent(installed)
                    if args.filename_roots_followup or args.filename_root_state_followup else None)
    root_state_extent = (verify_root_state_extent(installed)
                         if args.filename_root_state_followup else None)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.K32EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.K32EnumProcessModules.restype = wintypes.BOOL
    kernel.K32GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE, ctypes.POINTER(local.source.ModuleInfo), wintypes.DWORD]
    kernel.K32GetModuleInformation.restype = wintypes.BOOL
    kernel.K32GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
    kernel.K32GetModuleFileNameExW.restype = wintypes.DWORD
    kernel.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel.ReadProcessMemory.restype = wintypes.BOOL
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
        local.verify_creation(creation, args.expected_create_time)
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
        info = local.source.ModuleInfo()
        if not kernel.K32GetModuleInformation(handle, modules[0], ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.size != MODULE_SIZE:
            raise ValueError('source_module_size_changed')
        spans = allowed_spans(child_map_followup=args.child_map_followup,
                              compare_followup=args.compare_followup,
                              filename_transform_followup=args.filename_transform_followup,
                              filename_roots_followup=args.filename_roots_followup,
                              filename_root_state_followup=args.filename_root_state_followup)
        def read(address, size):
            if ((address - info.base, size) not in spans or not 0 < size <= CODE_SIZE
                    or not info.base <= address < address + size <= info.base + info.size):
                raise ValueError('process_read_not_in_fixed_package_cache_module_scope')
            raw, actual = ctypes.create_string_buffer(size), ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, raw, size, ctypes.byref(actual)):
                raise ctypes.WinError(ctypes.get_last_error())
            if actual.value != size:
                raise ValueError('short_package_cache_adapter_read')
            return raw.raw
        report = capture(read, info.base, info.size, source_capture_digest=source_digest,
                         actual_created=creation, expected_created=args.expected_create_time,
                         child_map_followup=args.child_map_followup,
                         compare_followup=args.compare_followup,
                         filename_transform_followup=args.filename_transform_followup,
                         filename_roots_followup=args.filename_roots_followup,
                         filename_root_state_followup=args.filename_root_state_followup)
        local.verify_creation(created(), creation)
        if filename_extent is not None:
            report.update(source_function_extent=filename_extent, source_function_extent_verified=True)
        if roots_extent is not None:
            report.update(source_roots_extent=roots_extent, source_roots_extent_verified=True)
        if root_state_extent is not None:
            report.update(source_root_state_extent=root_state_extent,
                          source_root_state_extent_verified=True)
        report.update(pid=args.pid, module_base=hex(info.base), module_size=info.size,
                      process_created_unix=creation, process_creation_rechecked=True,
                      shadow_executable=str(shadow.resolve()), process_accessed=True,
                      captured_at_utc=datetime.now(timezone.utc).isoformat())
        with output.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'captured_bytes': report['captured_bytes'],
                          'helper_ranges': len(report['fixed_code']),
                          'heap_read': False, 'report': str(output)}))
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    main()
