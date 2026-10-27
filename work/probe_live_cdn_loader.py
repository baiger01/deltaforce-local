"""Read fixed CDN registrations and named code prefixes from a running shadow.

Diagnostic only. No client launch, memory writes, hooks, native calls, heap
reads or indirect pointer traversal. Optional implementation reads require
fixed callback, prefix and instruction witnesses. The composition option
follows four additional exact direct calls and ten exact RIP-relative scalar
operands. All ranges remain fixed module code or data; no pointers are followed.
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import struct

from local_game_paths import game_paths
import probe_live_resource_loader as source_probe


ROOT = Path(__file__).resolve().parent.parent
# Original PE packed-pointer records; all six fields are verified at runtime.
REGISTRATIONS = {
    'MapleRow_GetCDNUrl': (0x14ee2440, 'GetCDNUrl',
        (0x14ee2eb8, 0xe07e90, 0xe01410, 0x14edf408, 0x1c9ff488, 1)),
    'AppRow_GetCDNUrl': (0x14ee3da0, 'GetCDNUrl',
        (0x14ee2eb8, 0xe08030, 0xe01410, 0x14edf408, 0x1c9ff768, 1)),
    'AppSetting_GetCDNUrl': (0x14ee5e30, 'GetCDNUrl',
        (0x14ee2eb8, 0xe082c0, 0xdfded0, 0x14edf408, 0x1db35410, 0x100000000)),
    'IconManager_GetCDNUrl': (0x15040340, 'GetCDNUrl',
        (0x14ee2eb8, 0x11f0830, 0x1162d70, 0x14edf408, 0x1ca2e2c8, 2)),
    'IconManager_GetFinalDiskPath': (0x15040370, 'GetFinalDiskPath',
        (0x15040c50, 0x11f0850, 0x1162d70, 0x14edf408, 0x1ca2e2d8, 2)),
    'CDNConfig_GetCDNUrl': (0x1898a960, 'GetCDNUrl',
        (0x14ee2eb8, 0xd189650, 0xe01410, 0x14edf408, 0x1d275fb8, 1)),
}
FIXED_CODE = {
    **{name + '_callback': (row[1], 160)
       for name, (_, _, row) in REGISTRATIONS.items()},
    'FString_row_binding': (0xe01410, 512),
    'FString_static_binding': (0xdfded0, 512),
    'FString_manager_binding': (0x1162d70, 512),
}
IMPLEMENTATION_CALLS = {
    'MapleRow_GetCDNUrl': (0xe07ea2, 0xdbcfb0, 512),
    'AppRow_GetCDNUrl': (0xe08042, 0xdbcd20, 640),
    'AppSetting_GetCDNUrl': (0xe082c9, 0xdbd170, 512),
    'IconManager_GetCDNUrl': (0x11f0842, 0x11e5c70, 1024),
    'IconManager_GetFinalDiskPath': (0x11f0862, 0x11e6200, 512),
    'CDNConfig_GetCDNUrl': (0xd189660, 0xd61ec0, 256),
}
IMPLEMENTATION_PREFIXES = {
    'MapleRow_GetCDNUrl': bytes.fromhex('48895c2408555657'),
    'AppRow_GetCDNUrl': bytes.fromhex('40555357488bec48'),
    'AppSetting_GetCDNUrl': bytes.fromhex('405356574883ec30'),
    'IconManager_GetCDNUrl': bytes.fromhex('48895c2418555657'),
    'IconManager_GetFinalDiskPath': bytes.fromhex('48895c2418555657'),
    'CDNConfig_GetCDNUrl': bytes.fromhex('48895c2408488974'),
}
CONFIGURATION_CALLS = {
    'AppSetting_ConfigValid': ('AppSetting_GetCDNUrl', 0xdbd278, 0x10ed02c0, 512,
                             bytes.fromhex('e843301110')),
    'AppSetting_ConfigAccess': ('AppSetting_GetCDNUrl', 0xdbd2ce, 0x10ecea20, 512,
                              bytes.fromhex('e84d171110')),
    'IconManager_AppRowAccess': ('IconManager_GetCDNUrl', 0x11e5deb, 0xdba370, 512,
                               bytes.fromhex('e88045bdff')),
}
STATIC_CONFIGURATION = {
    'AppSetting_descriptor_operand': ('AppSetting_GetCDNUrl', 0xdbd26f, 0x1c9fe7b0, 64,
                                     bytes.fromhex('488d0d3a15c41b')),
    'AppSetting_default_row_operand': ('AppSetting_GetCDNUrl', 0xdbd312, 0x1db33050, 64,
                                      bytes.fromhex('488d05375dd71c')),
}
FINAL_DISK_BRANCHES = (
    (0x11e62dc, 0x11e6798, bytes.fromhex('e9b7040000')),
    (0x11e62ee, 0x11e67af, bytes.fromhex('0f8ebb040000')),
    (0x11e6317, 0x11e67af, bytes.fromhex('0f8492040000')),
)
FINAL_DISK_TAIL = (0x11e6400, 1024)
COMPOSITION_CALLS = {
    'URL_StringProcess': ('IconManager_GetCDNUrl', 0x11e5ee3, 0x109f6860, 1024,
                         bytes.fromhex('e87809810f')),
    'URL_StringConstruct': ('IconManager_GetCDNUrl', 0x11e5fa0, 0xd5f420, 512,
                           bytes.fromhex('e87b94b7ff')),
    'URL_StringAppend': ('IconManager_GetCDNUrl', 0x11e5fbc, 0x109f31b0, 1024,
                        bytes.fromhex('e8efd1800f')),
    'Disk_PathBase': ('IconManager_GetFinalDiskPath_tail', 0x11e657f, 0x11e6c10, 512,
                      bytes.fromhex('e88c060000')),
}
# Each scalar's address is the exact displacement of the listed current code
# instruction, independently matched to the saved fixed code witness.
COMPOSITION_SCALARS = {
    'app_override_enabled': ('AppRow_GetCDNUrl', 0xdbcd2b, 0x1db35660,
                             bytes.fromhex('0fb6052e89d71c'), 3),
    'app_url_override': ('AppRow_GetCDNUrl', 0xdbcd40, 0x1db35674,
                        bytes.fromhex('803d2d89d71c00'), 2),
    'maple_url_override': ('AppRow_GetCDNUrl', 0xdbce19, 0x1db35672,
                          bytes.fromhex('803d5288d71c00'), 2),
    'default_url_override': ('AppRow_GetCDNUrl', 0xdbcf27, 0x1db3567c,
                            bytes.fromhex('803d4e87d71c00'), 2),
    'pc_url_selector': ('AppRow_GetCDNUrl', 0xdbced5, 0x1d59de40,
                        bytes.fromhex('803d640f7e1c00'), 2),
    'app_row_override': ('IconManager_AppRowAccess', 0xdba386, 0x1db35679,
                         bytes.fromhex('803decb2d71c00'), 2),
    'app_row_fallback_override': ('IconManager_AppRowAccess', 0xdba43e, 0x1db3567a,
                                  bytes.fromhex('803d35b2d71c00'), 2),
    'manager_override_enabled': ('IconManager_GetCDNUrl', 0x11e5c88, 0x1db47a60,
                                 bytes.fromhex('803dd11d961c00'), 2),
    'manager_url_override': ('IconManager_GetCDNUrl', 0x11e5ca5, 0x1db47a96,
                             bytes.fromhex('803dea1d961c00'), 2),
    'manager_input_override': ('IconManager_GetCDNUrl', 0x11e5ef0, 0x1db47a97,
                               bytes.fromhex('381da11b961c'), 2),
}
IMAGE_REGISTRATIONS = {
    'SetCDNImage': (0x169b6930,
        (0x169b6e28, 0x6403500, 0x6405810, 0x14edf3dc, 0x1cda5020, 4)),
    'ReqCdnDownload': (0x15040430,
        (0x15040cb8, 0x11f08a0, 0x11eea10, 0x14edf3dc, 0x1ca2e308, 3)),
    'LoadDiskImage': (0x15040730,
        (0x15040de0, 0x11f0980, 0x11ef580, 0x15040b70, 0x1ca2e418, 0x100000001)),
    'DecodeImageData': (0x15040850,
        (0x15040e68, 0x11f09f0, 0x11efd00, 0x15040b70, 0x1ca2e4d0, 0x100000002)),
}
IMAGE_CALLBACK_SIZE = 160
IMAGE_IMPLEMENTATION_CALLS = {
    'SetCDNImage': (0x640353b, 0x63c5ad0, 1024, bytes.fromhex('e89025fcff')),
    'ReqCdnDownload': (0x11f08a0, 0x11ec480, 1024, bytes.fromhex('e9dbbbffff')),
    'LoadDiskImage': (0x11f0989, 0x11e8a90, 1024, bytes.fromhex('e80281ffff')),
    'DecodeImageData': (0x11f09f9, 0x11e33a0, 1024, bytes.fromhex('e8a229ffff')),
}
IMAGE_CALLBACK_PREFIXES = {
    'SetCDNImage': bytes.fromhex('48895c240848896c'),
    'ReqCdnDownload': bytes.fromhex('e9dbbbffffcccccc'),
    'LoadDiskImage': bytes.fromhex('40534883ec20488b'),
    'DecodeImageData': bytes.fromhex('40534883ec20488b'),
}
IMAGE_IMPLEMENTATION_PREFIXES = {
    'SetCDNImage': bytes.fromhex('405553564155488d'),
    'ReqCdnDownload': bytes.fromhex('4c8bdc49895b0849'),
    'LoadDiskImage': bytes.fromhex('4055535657415648'),
    'DecodeImageData': bytes.fromhex('4053555641544156'),
}
IMAGE_STORAGE_CALLS = {
    'Disk_ImagePath': ('LoadDiskImage', 0x11e8b43, 0x11ed5b0, 1024,
                       bytes.fromhex('e8684a0000')),
    'Disk_LoadBytes': ('LoadDiskImage', 0x11e8b6e, 0x10b072b0, 1024,
                       bytes.fromhex('e83de7910f')),
}
IMAGE_STORAGE_PREFIXES = {
    'Disk_ImagePath': bytes.fromhex('405553574157488d'),
    'Disk_LoadBytes': bytes.fromhex('48895c240848896c'),
}
IMAGE_PROCESSING_CALLS = {
    'Req_Worker': ('ReqCdnDownload', 0x11ec50a, 0x11ec580, 1024,
                   bytes.fromhex('e871000000')),
    'Req_InputPath': ('ReqCdnDownload', 0x11ec6df, 0x11e6ee0, 1024,
                      bytes.fromhex('e8fca7ffff')),
    'Disk_SplitEquals': ('Disk_ImagePath', 0x11ed718, 0xdf6680, 512,
                         bytes.fromhex('e8638fc0ff')),
    'Disk_BasenameHash': ('Disk_ImagePath', 0x11ed74c, 0xd61370, 512,
                          bytes.fromhex('e81f3cb7ff')),
    'Disk_IntegerString': ('Disk_ImagePath', 0x11ed75f, 0x109ed950, 256,
                           bytes.fromhex('e8ec01800f')),
}
SET_IMAGE_TAILS = ((0x63c5ed0, 1024), (0x63c62d0, 1024), (0x63c66d0, 1024))
SET_IMAGE_BRANCHES = (
    (0x63c5b6d, 0x63c69a0, bytes.fromhex('e92e0e0000')),
    (0x63c5ba3, 0x63c6990, bytes.fromhex('0f8ee70d0000')),
    (0x63c5bce, 0x63c6990, bytes.fromhex('0f84bc0d0000')),
)
DISK_HASH_SCALAR = (0x11ed65c, 0x1ca2e143, bytes.fromhex('803de00a841b00'))
DISK_MANAGER_SCALAR = (0x11ed5c2, 0x1db47a60, bytes.fromhex('803d97a4951c00'))
DISK_IMAGE_TAIL = (0x11ed9b0, 128)
DISK_IMAGE_TAIL_BRANCH = (0x11ed64e, 0x11ed9f8, bytes.fromhex('e9a5030000'))
IMAGE_CRC_TABLE = (0xd61381, 0x1d59ba40, 1024, bytes.fromhex('488d1db8a6831c'))
IMAGE_CRC_PREFIX = bytes.fromhex('4883ec0833c04c8b')
IMAGE_CRC_SOURCE_SHA256 = '0053f121cdcaf9f510a940ba891fb2bccd41487953c5a4c0048c4a3ccdec782e'
IMAGE_REQUEST_CALLS = {
    'Request_PathComponent': (0x11ec687, 0x10b24930, 1024, bytes.fromhex('e8a482930f')),
    'Request_SplitPath': (0x11ec6ab, 0x10b34760, 1024, bytes.fromhex('e8b080940f')),
    'Request_Dispatch': (0x11ec948, 0x11e74c0, 1024, bytes.fromhex('e873abffff')),
}
IMAGE_REQUEST_TAIL = (0x11ec980, 256)
IMAGE_REQUEST_BRANCH = (0x11ec614, 0x11ec9d2, bytes.fromhex('0f8eb8030000'))
IMAGE_REQUEST_SCALARS = {
    'request_extension_gate': (0x11ec6b6, 0x1db478e9, 1, bytes.fromhex('381d2db2951c'), 2),
    'request_quality_gate': (0x11ec6c2, 0x1db478ea, 1, bytes.fromhex('381d22b2951c'), 2),
    'request_quality_enum': (0x11ec6c8, 0x1ca2e154, 4, bytes.fromhex('8b15861a841b'), 2),
    'request_quality_alternate_enum': (0x11ec6d0, 0x1ca2e14c, 4, bytes.fromhex('8b05761a841b'), 2),
}
IMAGE_REQUEST_QUALITY_TABLE = (0x11e6f59, 0x1503f370, 32, bytes.fromhex('488d0d1084e513'))
IMAGE_COMPONENT_CALLS = {
    'Request_CleanComponent': ('Request_PathComponent', 0x10b2494c, 0x10b23ec0, 1024, bytes.fromhex('e86ff5ffff')),
    'Request_BaseComponent': ('Request_SplitPath', 0x10b347ad, 0x10b23a90, 1024, bytes.fromhex('e8def2feff')),
}
IMAGE_COMPONENT_PREFIXES = {
    'Request_PathComponent': bytes.fromhex('48895c2418488974'),
    'Request_SplitPath': bytes.fromhex('48895c240848896c'),
    'Request_Dispatch': bytes.fromhex('4c894c24204c8944'),
    'Disk_SplitEquals': bytes.fromhex('48897c24184c894c'),
    'Disk_IntegerString': bytes.fromhex('48895c2410574883'),
}
IMAGE_COMPONENT_TAILS = {
    'Request_Dispatch': (0x11e78c0, 512, 0x11e7555, 0x11e79b4, bytes.fromhex('0f8459040000')),
    'Disk_SplitEquals': (0xdf6880, 256, 0xdf66e1, 0xdf6942, bytes.fromhex('e95c020000')),
}
IMAGE_COMPONENT_DATA = {
    'Request_Dot': ('Request_PathComponent', 0x10b24962, 0x14ec37d4, 4, bytes.fromhex('488d156bee3904')),
    'Disk_DecimalDigits': ('Disk_IntegerString', 0x109ed96c, 0x1aad7c58, 38, bytes.fromhex('488d3de5a20e0a')),
}
IMAGE_QUEUE_CALL = (0x11e78f4, 0x11eda10, 1024, bytes.fromhex('e817610000'))
READ_POLICY = ('Six original-PE verified 48-byte registration rows, two fixed '
    '32-byte names, six named 160-byte callbacks and three 512-byte bindings; '
    'no other ranges, heap data, pointer traversal, SDK access, writes, hooks, '
    'client function calls, launch or process stop')


def allowed_spans(implementations=False, composition=False, image_path=False, image_implementations=False, image_storage=False, image_processing=False, image_crc_table=False, image_request_processing=False, image_request_components=False, image_request_queue=False):
    spans = {(rva, 48) for rva, _, _ in REGISTRATIONS.values()}
    spans.update((row[0], 32) for _, _, row in REGISTRATIONS.values())
    spans.update(FIXED_CODE.values())
    if implementations:
        spans.update((target, size) for _, target, size in IMPLEMENTATION_CALLS.values())
        spans.update((target, size) for _, _, target, size, _ in CONFIGURATION_CALLS.values())
        spans.update((target, size) for _, _, target, size, _ in STATIC_CONFIGURATION.values())
        spans.add(FINAL_DISK_TAIL)
    if composition:
        if not implementations:
            raise ValueError('Composition witnesses require --implementations')
        spans.update((target, size) for _, _, target, size, _ in COMPOSITION_CALLS.values())
        spans.update((target, 1) for _, _, target, _, _ in COMPOSITION_SCALARS.values())
    if image_path:
        spans.update((rva, 48) for rva, _ in IMAGE_REGISTRATIONS.values())
        spans.update((row[0], 32) for _, row in IMAGE_REGISTRATIONS.values())
        spans.update((row[1], IMAGE_CALLBACK_SIZE) for _, row in IMAGE_REGISTRATIONS.values())
    if image_implementations:
        if not image_path:
            raise ValueError('Image implementation witnesses require --image-path')
        spans.update((target, size) for _, target, size, _ in IMAGE_IMPLEMENTATION_CALLS.values())
    if image_storage:
        if not image_implementations:
            raise ValueError('Image storage witnesses require --image-implementations')
        spans.update((target, size) for _, _, target, size, _ in IMAGE_STORAGE_CALLS.values())
    if image_processing:
        if not image_storage:
            raise ValueError('Image processing witnesses require --image-storage')
        spans.update((target, size) for _, _, target, size, _ in IMAGE_PROCESSING_CALLS.values())
        spans.update(SET_IMAGE_TAILS)
        spans.add((DISK_HASH_SCALAR[1], 1))
        spans.add((DISK_MANAGER_SCALAR[1], 1))
        spans.add(DISK_IMAGE_TAIL)
    if image_crc_table:
        if not image_processing:
            raise ValueError('Image CRC table witness requires --image-processing')
        spans.add((IMAGE_CRC_TABLE[1], IMAGE_CRC_TABLE[2]))
    if image_request_processing:
        if not image_processing:
            raise ValueError('Image request processing requires --image-processing')
        spans.update((target, size) for _, target, size, _ in IMAGE_REQUEST_CALLS.values())
        spans.add(IMAGE_REQUEST_TAIL)
        spans.update((target, size) for _, target, size, _, _ in IMAGE_REQUEST_SCALARS.values())
        spans.add((IMAGE_REQUEST_QUALITY_TABLE[1], IMAGE_REQUEST_QUALITY_TABLE[2]))
    if image_request_components:
        if not image_request_processing:
            raise ValueError('Image request components require --image-request-processing')
        spans.update((target, size) for _, _, target, size, _ in IMAGE_COMPONENT_CALLS.values())
        spans.update((rva, size) for rva, size, _, _, _ in IMAGE_COMPONENT_TAILS.values())
        spans.update((target, size) for _, _, target, size, _ in IMAGE_COMPONENT_DATA.values())
    if image_request_queue:
        if not image_request_components:
            raise ValueError('Image request queue requires --image-request-components')
        spans.add((IMAGE_QUEUE_CALL[1], IMAGE_QUEUE_CALL[2]))
    return spans


def capture(read, base, module_size, implementations=False, composition=False, image_path=False, image_implementations=False, image_storage=False, image_processing=False, image_crc_table=False, image_request_processing=False, image_request_components=False, image_request_queue=False):
    spans = allowed_spans(implementations, composition, image_path, image_implementations, image_storage, image_processing, image_crc_table, image_request_processing, image_request_components, image_request_queue)
    if (not isinstance(base, int) or base <= 0 or not isinstance(module_size, int)
            or module_size <= 0 or base + module_size >= 1 << 64
            or any(rva < 0 or rva + size > module_size for rva, size in spans)):
        raise ValueError('CDN witness is outside the native module')
    captured_bytes = 0
    seen = {}

    def fixed_read(rva, size, refresh=False):
        nonlocal captured_bytes
        if (rva, size) not in spans:
            raise ValueError('Not an approved fixed CDN witness range')
        if refresh or (rva, size) not in seen:
            value = read(base + rva, size)
            if not isinstance(value, bytes) or len(value) != size:
                raise ValueError('CDN witness read length differs from its fixed bound')
            seen[(rva, size)] = value
            captured_bytes += size
        return seen[(rva, size)]

    report = {'native_pe_sha256': source_probe.EXPECTED_PE, 'module_base': base,
              'module_size': module_size, 'read_policy': READ_POLICY,
              'registrations': {}, 'fixed_code': {}}
    for label, (rva, name, source_row) in REGISTRATIONS.items():
        actual = struct.unpack('<6Q', fixed_read(rva, 48))
        expected = tuple(base + value for value in source_row[:5]) + (source_row[5],)
        if actual != expected:
            raise ValueError(f'Loaded {label} registration differs from original PE')
        if fixed_read(source_row[0], 32).split(b'\0', 1)[0] != name.encode('ascii'):
            raise ValueError(f'Loaded {label} name differs from original PE')
        report['registrations'][label] = {
            'registration_rva': rva, 'name': name, 'name_rva': source_row[0],
            'callback_rva': source_row[1], 'binding_rva': source_row[2],
            'return_descriptor_rva': source_row[3],
            'argument_descriptor_rva': source_row[4], 'argument_flags': source_row[5],
            'all_fields_verified': True,
        }
    for name, (rva, size) in FIXED_CODE.items():
        code = fixed_read(rva, size)
        report['fixed_code'][name] = {
            'rva': rva, 'size': size, 'bytes': code.hex(),
            'sha256': hashlib.sha256(code).hexdigest(),
            'scope': 'Fixed code prefix; contained branch/call targets are not followed',
        }
    if implementations:
        # Each edge is witnessed in the current named callback, before reading
        # its fixed target. Packed or different code must fail this check.
        for name, (call_rva, target, size) in IMPLEMENTATION_CALLS.items():
            block = report['fixed_code'][name + '_callback']
            offset = call_rva - block['rva']
            code = bytes.fromhex(block['bytes'])
            if (not 0 <= offset <= len(code) - 5 or code[offset] != 0xe8
                    or call_rva + 5 + struct.unpack_from('<i', code, offset + 1)[0] != target):
                raise ValueError(f'{name} is not the witnessed direct implementation call')
        report['implementations'] = {}
        report['read_policy'] = READ_POLICY + ('; also six verified direct-call targets with '
            'fixed 256-1024 byte bounds, then three explicitly witnessed code targets of '
            '512 bytes each and two RIP-relative module data operands of 64 bytes each; '
            'plus a 1024-byte disk-path code tail after three exact direct branch '
            'witnesses; all preceding instruction witnesses must pass before the final ranges, '
            'no heap or pointer traversal and no targets inside final code are followed')
        for name, (call_rva, target, size) in IMPLEMENTATION_CALLS.items():
            code = fixed_read(target, size)
            report['implementations'][name] = {
                'witnessed_callback_call_rva': call_rva,
                'direct_call_target_verified': True, 'rva': target, 'size': size,
                'bytes': code.hex(), 'sha256': hashlib.sha256(code).hexdigest(),
                'scope': 'Fixed directly witnessed implementation; only the three listed configuration calls and two listed module data operands may be followed',
            }
        for name, expected in IMPLEMENTATION_PREFIXES.items():
            if not bytes.fromhex(report['implementations'][name]['bytes']).startswith(expected):
                raise ValueError(f'{name} differs from the witnessed plaintext implementation prefix')
        for name, (owner, site, target, size, expected) in CONFIGURATION_CALLS.items():
            block = report['implementations'][owner]
            offset = site - block['rva']
            code = bytes.fromhex(block['bytes'])
            if (not 0 <= offset <= len(code) - 5 or code[offset:offset + 5] != expected
                    or expected[0] != 0xe8
                    or site + 5 + struct.unpack_from('<i', expected, 1)[0] != target):
                raise ValueError(f'{name} is not the witnessed configuration direct call')
        for name, (owner, site, target, size, expected) in STATIC_CONFIGURATION.items():
            block = report['implementations'][owner]
            offset = site - block['rva']
            code = bytes.fromhex(block['bytes'])
            if (not 0 <= offset <= len(code) - 7 or code[offset:offset + 7] != expected
                    or expected[:3] not in (b'\x48\x8d\x0d', b'\x48\x8d\x05')
                    or site + 7 + struct.unpack_from('<i', expected, 3)[0] != target):
                raise ValueError(f'{name} is not the witnessed static module operand')
        disk = report['implementations']['IconManager_GetFinalDiskPath']
        disk_bytes = bytes.fromhex(disk['bytes'])
        tail_rva, tail_size = FINAL_DISK_TAIL
        for site, target, expected in FINAL_DISK_BRANCHES:
            offset = site - disk['rva']
            opcode_size = 1 if expected[:1] == b'\xe9' else 2
            if (not 0 <= offset <= len(disk_bytes) - len(expected)
                    or disk_bytes[offset:offset + len(expected)] != expected
                    or expected[:opcode_size] not in (b'\xe9', b'\x0f\x8e', b'\x0f\x84')
                    or site + len(expected) + struct.unpack_from('<i', expected, opcode_size)[0] != target
                    or not tail_rva <= target < tail_rva + tail_size):
                raise ValueError('Disk-path branch differs from the witnessed fixed tail target')
        report['configuration_accessors'] = {}
        for name, (owner, site, target, size, expected) in CONFIGURATION_CALLS.items():
            code = fixed_read(target, size)
            report['configuration_accessors'][name] = {
                'source_implementation': owner, 'witnessed_call_rva': site,
                'call_instruction_hex': expected.hex(), 'direct_call_target_verified': True,
                'rva': target, 'size': size, 'bytes': code.hex(),
                'sha256': hashlib.sha256(code).hexdigest(),
                'scope': 'Final fixed code prefix; contained targets are not followed',
            }
        report['static_configuration_operands'] = {}
        for name, (owner, site, target, size, expected) in STATIC_CONFIGURATION.items():
            data = fixed_read(target, size)
            report['static_configuration_operands'][name] = {
                'source_implementation': owner, 'witnessed_lea_rva': site,
                'lea_instruction_hex': expected.hex(), 'rip_relative_target_verified': True,
                'rva': target, 'size': size, 'bytes': data.hex(),
                'sha256': hashlib.sha256(data).hexdigest(),
                'scope': 'Fixed module data operand; pointer fields are not followed and configuration type remains unverified',
            }
        tail = fixed_read(tail_rva, tail_size)
        report['fixed_tails'] = {'IconManager_GetFinalDiskPath': {
            'source_implementation': 'IconManager_GetFinalDiskPath',
            'branch_witnesses': [{'site_rva': site, 'target_rva': target,
                                 'instruction_hex': expected.hex()}
                                for site, target, expected in FINAL_DISK_BRANCHES],
            'direct_branch_targets_verified': True, 'rva': tail_rva, 'size': tail_size,
            'bytes': tail.hex(), 'sha256': hashlib.sha256(tail).hexdigest(),
            'scope': 'Final fixed module code tail; contained targets are not followed',
        }}
    if composition:
        owners = {**report['implementations'], **report['configuration_accessors'],
                  'IconManager_GetFinalDiskPath_tail':
                      report['fixed_tails']['IconManager_GetFinalDiskPath']}
        # Verify every additional edge and scalar operand before reading any of
        # their targets. The private report records values separately from proof.
        for name, (owner, site, target, size, expected) in COMPOSITION_CALLS.items():
            block = owners[owner]
            code = bytes.fromhex(block['bytes'])
            offset = site - block['rva']
            if (not 0 <= offset <= len(code) - 5 or code[offset:offset + 5] != expected
                    or expected[0] != 0xe8
                    or site + 5 + struct.unpack_from('<i', expected, 1)[0] != target):
                raise ValueError(f'{name} is not the witnessed composition direct call')
        for name, (owner, site, target, expected, displacement_offset) in COMPOSITION_SCALARS.items():
            block = owners[owner]
            code = bytes.fromhex(block['bytes'])
            offset = site - block['rva']
            if (not 0 <= offset <= len(code) - len(expected)
                    or code[offset:offset + len(expected)] != expected
                    or expected[:displacement_offset] not in (b'\x0f\xb6\x05', b'\x80\x3d', b'\x38\x1d')
                    or site + len(expected) + struct.unpack_from('<i', expected, displacement_offset)[0] != target):
                raise ValueError(f'{name} is not the witnessed RIP-relative scalar operand')
        first_values = {name: fixed_read(target, 1)[0]
                        for name, (_, _, target, _, _) in COMPOSITION_SCALARS.items()}
        report['composition_helpers'] = {}
        for name, (owner, site, target, size, expected) in COMPOSITION_CALLS.items():
            code = fixed_read(target, size)
            report['composition_helpers'][name] = {
                'source_implementation': owner, 'witnessed_call_rva': site,
                'call_instruction_hex': expected.hex(), 'direct_call_target_verified': True,
                'rva': target, 'size': size, 'bytes': code.hex(),
                'sha256': hashlib.sha256(code).hexdigest(),
                'scope': 'Final fixed module code prefix; contained targets are not followed',
            }
        report['composition_scalars'] = {}
        for name, (owner, site, target, expected, _) in COMPOSITION_SCALARS.items():
            final_value = fixed_read(target, 1, refresh=True)[0]
            report['composition_scalars'][name] = {
                'source_implementation': owner, 'instruction_rva': site,
                'instruction_hex': expected.hex(), 'rip_relative_target_verified': True,
                'rva': target, 'size': 1, 'value': first_values[name],
                'value_recheck': final_value, 'stable': first_values[name] == final_value,
                'scope': 'Fixed module scalar; no pointers or adjacent data are read',
            }
        report['composition_scalars_stable'] = all(
            row['stable'] for row in report['composition_scalars'].values())
        report['read_policy'] += ('; composition option follows four further exact E8 '
            'targets with fixed 512-1024 byte bounds and ten exact RIP-relative module '
            'bytes, rechecked after code capture; all composition instructions verified '
            'before any additional target read, no heap or pointer traversal')
    if image_path:
        report['image_registrations'] = {}
        for name, (rva, source_row) in IMAGE_REGISTRATIONS.items():
            actual = struct.unpack('<6Q', fixed_read(rva, 48))
            expected = tuple(base + value for value in source_row[:5]) + (source_row[5],)
            if actual != expected:
                raise ValueError(f'Loaded {name} image registration differs from original PE')
            if fixed_read(source_row[0], 32).split(b'\0', 1)[0] != name.encode('ascii'):
                raise ValueError(f'Loaded {name} image name differs from original PE')
            report['image_registrations'][name] = {
                'registration_rva': rva, 'name_rva': source_row[0],
                'callback_rva': source_row[1], 'binding_rva': source_row[2],
                'return_descriptor_rva': source_row[3],
                'argument_descriptor_rva': source_row[4], 'argument_flags': source_row[5],
                'all_fields_verified': True, 'class_owner_verified': False,
            }
        report['image_callbacks'] = {}
        for name, (_, source_row) in IMAGE_REGISTRATIONS.items():
            rva = source_row[1]
            code = fixed_read(rva, IMAGE_CALLBACK_SIZE)
            report['image_callbacks'][name] = {
                'rva': rva, 'size': IMAGE_CALLBACK_SIZE, 'bytes': code.hex(),
                'sha256': hashlib.sha256(code).hexdigest(),
                'scope': 'Fixed named callback prefix; no contained targets are followed',
            }
        report['read_policy'] += ('; image-path option verifies all four additional original-PE '
            '48-byte registration rows and 32-byte names before four fixed 160-byte callback '
            'prefixes; no callback targets, data pointers or heap are followed')
    if image_implementations:
        for name, (site, target, size, expected) in IMAGE_IMPLEMENTATION_CALLS.items():
            block = report['image_callbacks'][name]
            code = bytes.fromhex(block['bytes'])
            offset = site - block['rva']
            if (not code.startswith(IMAGE_CALLBACK_PREFIXES[name])
                    or not 0 <= offset <= len(code) - 5
                    or code[offset:offset + 5] != expected
                    or expected[0] not in (0xe8, 0xe9)
                    or site + 5 + struct.unpack_from('<i', expected, 1)[0] != target):
                raise ValueError(f'{name} is not the witnessed image implementation edge')
        report['image_implementations'] = {}
        for name, (site, target, size, expected) in IMAGE_IMPLEMENTATION_CALLS.items():
            code = fixed_read(target, size)
            report['image_implementations'][name] = {
                'witnessed_callback_instruction_rva': site,
                'instruction_hex': expected.hex(), 'direct_edge_target_verified': True,
                'rva': target, 'size': size, 'bytes': code.hex(),
                'sha256': hashlib.sha256(code).hexdigest(),
                'scope': 'Fixed named callback callee prefix; no contained targets are followed',
            }
        report['read_policy'] += ('; image-implementations option verifies all four plaintext '
            'callback prefixes and exact direct E8/E9 edges before four fixed 1024-byte '
            'callee prefixes; no contained targets, pointers or heap are followed')
    if image_storage:
        for name, expected in IMAGE_IMPLEMENTATION_PREFIXES.items():
            if not bytes.fromhex(report['image_implementations'][name]['bytes']).startswith(expected):
                raise ValueError(f'{name} differs from the witnessed image implementation prefix')
        for name, (owner, site, target, size, expected) in IMAGE_STORAGE_CALLS.items():
            block = report['image_implementations'][owner]
            code = bytes.fromhex(block['bytes'])
            offset = site - block['rva']
            if (not 0 <= offset <= len(code) - 5 or code[offset:offset + 5] != expected
                    or expected[0] != 0xe8
                    or site + 5 + struct.unpack_from('<i', expected, 1)[0] != target):
                raise ValueError(f'{name} is not the witnessed image storage direct call')
        report['image_storage_helpers'] = {}
        for name, (owner, site, target, size, expected) in IMAGE_STORAGE_CALLS.items():
            code = fixed_read(target, size)
            report['image_storage_helpers'][name] = {
                'source_implementation': owner, 'witnessed_call_rva': site,
                'instruction_hex': expected.hex(), 'direct_call_target_verified': True,
                'rva': target, 'size': size, 'bytes': code.hex(),
                'sha256': hashlib.sha256(code).hexdigest(),
                'scope': 'Fixed image storage callee prefix; no contained targets are followed',
            }
        report['read_policy'] += ('; image-storage option verifies all four observed implementation '
            'prefixes and both exact file-path/file-read E8 instructions before two fixed '
            '1024-byte callee prefixes; no contained targets, pointers or heap are followed')
    if image_processing:
        owners = {**report['image_implementations'], **report['image_storage_helpers']}
        for name, expected in IMAGE_STORAGE_PREFIXES.items():
            if not bytes.fromhex(owners[name]['bytes']).startswith(expected):
                raise ValueError(f'{name} differs from the witnessed image storage prefix')
        req = owners['ReqCdnDownload']
        req_code = bytes.fromhex(req['bytes'])
        worker_offset = 0x11ec580 - req['rva']
        if req_code[worker_offset:worker_offset + 8] != bytes.fromhex('4c894c242048894c'):
            raise ValueError('Request worker differs from its witnessed inline code prefix')
        for name, (owner, site, target, size, expected) in IMAGE_PROCESSING_CALLS.items():
            block = owners[owner]
            code = bytes.fromhex(block['bytes'])
            offset = site - block['rva']
            if (not 0 <= offset <= len(code) - 5 or code[offset:offset + 5] != expected
                    or expected[0] != 0xe8
                    or site + 5 + struct.unpack_from('<i', expected, 1)[0] != target):
                raise ValueError(f'{name} is not the witnessed image processing direct call')
        setter = owners['SetCDNImage']
        setter_code = bytes.fromhex(setter['bytes'])
        for site, target, expected in SET_IMAGE_BRANCHES:
            offset = site - setter['rva']
            opcode_size = 1 if expected[:1] == b'\xe9' else 2
            if (not 0 <= offset <= len(setter_code) - len(expected)
                    or setter_code[offset:offset + len(expected)] != expected
                    or expected[:opcode_size] not in (b'\xe9', b'\x0f\x8e', b'\x0f\x84')
                    or site + len(expected) + struct.unpack_from('<i', expected, opcode_size)[0] != target
                    or not any(rva <= target < rva + size for rva, size in SET_IMAGE_TAILS)):
                raise ValueError('Set-image branch differs from the witnessed fixed tail target')
        disk = owners['Disk_ImagePath']
        code = bytes.fromhex(disk['bytes'])
        for site, target, expected in (DISK_HASH_SCALAR, DISK_MANAGER_SCALAR):
            offset = site - disk['rva']
            if (not 0 <= offset <= len(code) - 7 or code[offset:offset + 7] != expected
                    or expected[:2] != b'\x80\x3d'
                    or site + 7 + struct.unpack_from('<i', expected, 2)[0] != target):
                raise ValueError('Disk hash selector differs from its witnessed module byte operand')
        site, target, expected = DISK_IMAGE_TAIL_BRANCH
        offset = site - disk['rva']
        if (not 0 <= offset <= len(code) - 5 or code[offset:offset + 5] != expected
                or expected[0] != 0xe9
                or site + 5 + struct.unpack_from('<i', expected, 1)[0] != target
                or not DISK_IMAGE_TAIL[0] <= target < sum(DISK_IMAGE_TAIL)):
            raise ValueError('Disk-image branch differs from its witnessed fixed tail target')
        first_values = [fixed_read(target, 1)[0]
                        for _, target, _ in (DISK_HASH_SCALAR, DISK_MANAGER_SCALAR)]
        report['image_processing_helpers'] = {}
        for name, (owner, call_site, call_target, size, instruction) in IMAGE_PROCESSING_CALLS.items():
            code = fixed_read(call_target, size)
            report['image_processing_helpers'][name] = {
                'source_implementation': owner, 'witnessed_call_rva': call_site,
                'instruction_hex': instruction.hex(), 'direct_call_target_verified': True,
                'rva': call_target, 'size': size, 'bytes': code.hex(),
                'sha256': hashlib.sha256(code).hexdigest(),
                'scope': 'Fixed image processing callee prefix; no contained targets are followed',
            }
        tail_blocks = []
        for rva, size in SET_IMAGE_TAILS:
            code = fixed_read(rva, size)
            tail_blocks.append({'rva': rva, 'size': size, 'bytes': code.hex(),
                                'sha256': hashlib.sha256(code).hexdigest()})
        combined = setter_code + b''.join(bytes.fromhex(row['bytes']) for row in tail_blocks)
        report['image_processing_tails'] = {'SetCDNImage': {
            'branch_witnesses': [{'site_rva': s, 'target_rva': t, 'instruction_hex': e.hex()}
                                 for s, t, e in SET_IMAGE_BRANCHES],
            'direct_branch_targets_verified': True, 'tail_read_spans': tail_blocks,
            'rva': setter['rva'], 'size': len(combined), 'bytes': combined.hex(),
            'sha256': hashlib.sha256(combined).hexdigest(),
            'scope': 'Original prefix plus three fixed contiguous tails; concatenated before disassembly because a read boundary may split an instruction',
        }}
        rva, size = DISK_IMAGE_TAIL
        tail = fixed_read(rva, size)
        combined = bytes.fromhex(disk['bytes']) + tail
        report['image_processing_tails']['Disk_ImagePath'] = {
            'branch_witnesses': [{'site_rva': DISK_IMAGE_TAIL_BRANCH[0],
                                 'target_rva': DISK_IMAGE_TAIL_BRANCH[1],
                                 'instruction_hex': DISK_IMAGE_TAIL_BRANCH[2].hex()}],
            'direct_branch_targets_verified': True,
            'tail_read_spans': [{'rva': rva, 'size': size, 'bytes': tail.hex(),
                                 'sha256': hashlib.sha256(tail).hexdigest()}],
            'rva': disk['rva'], 'size': len(combined), 'bytes': combined.hex(),
            'sha256': hashlib.sha256(combined).hexdigest(),
            'scope': 'Original prefix plus one fixed contiguous code tail; concatenated before disassembly',
        }
        for name, witness, first_value in zip(('disk_hash_branch_byte', 'disk_manager_override_byte'),
                                             (DISK_HASH_SCALAR, DISK_MANAGER_SCALAR), first_values):
            site, target, expected = witness
            final_value = fixed_read(target, 1, refresh=True)[0]
            report[name] = {
                'instruction_rva': site, 'instruction_hex': expected.hex(),
                'rip_relative_target_verified': True, 'rva': target, 'size': 1,
                'value': first_value, 'value_recheck': final_value,
                'stable': first_value == final_value,
                'scope': 'Fixed module branch byte; native property name is unverified',
            }
        report['read_policy'] += ('; image-processing option verifies the two storage prefixes, '
            'request worker prefix, five exact E8 instructions, three exact setter branches and '
            'two exact RIP byte operands and a disk-path branch before five fixed callee prefixes, '
            'three 1024-byte setter tails, one 128-byte disk-path tail and two rechecked module '
            'bytes; no heap, pointers or contained targets followed')
    if image_crc_table:
        block = report['image_processing_helpers']['Disk_BasenameHash']
        code = bytes.fromhex(block['bytes'])
        site, target, size, expected = IMAGE_CRC_TABLE
        offset = site - block['rva']
        if (not code.startswith(IMAGE_CRC_PREFIX)
                or not 0 <= offset <= len(code) - 7
                or code[offset:offset + 7] != expected
                or expected[:3] != b'\x48\x8d\x1d'
                or site + 7 + struct.unpack_from('<i', expected, 3)[0] != target):
            raise ValueError('Image CRC table differs from its witnessed module LEA')
        data = fixed_read(target, size)
        digest = hashlib.sha256(data).hexdigest()
        report['image_crc_table'] = {
            'source_implementation': 'Disk_BasenameHash', 'instruction_rva': site,
            'instruction_hex': expected.hex(), 'rip_relative_target_verified': True,
            'rva': target, 'size': size, 'bytes': data.hex(), 'sha256': digest,
            'original_pe_table_sha256': IMAGE_CRC_SOURCE_SHA256,
            'matches_original_pe_table': digest == IMAGE_CRC_SOURCE_SHA256,
            'scope': 'One fixed module table; no pointers, adjacent data or heap read',
        }
        report['read_policy'] += ('; image-crc-table option verifies the hash routine prefix '
            'and exact RIP-relative LEA before one fixed 1024-byte module table')
    if image_request_processing:
        block = report['image_processing_helpers']['Req_Worker']
        code = bytes.fromhex(block['bytes'])
        if not code.startswith(bytes.fromhex('4c894c242048894c')):
            raise ValueError('Request processing worker differs from witnessed prefix')
        for name, (site, target, size, expected) in IMAGE_REQUEST_CALLS.items():
            offset = site - block['rva']
            if (not 0 <= offset <= len(code) - 5 or code[offset:offset + 5] != expected
                    or expected[0] != 0xe8
                    or site + 5 + struct.unpack_from('<i', expected, 1)[0] != target):
                raise ValueError(f'{name} differs from witnessed request direct call')
        site, target, expected = IMAGE_REQUEST_BRANCH
        offset = site - block['rva']
        if (code[offset:offset + 6] != expected or expected[:2] != b'\x0f\x8e'
                or site + 6 + struct.unpack_from('<i', expected, 2)[0] != target
                or not IMAGE_REQUEST_TAIL[0] <= target < sum(IMAGE_REQUEST_TAIL)):
            raise ValueError('Request tail branch differs from witnessed target')
        for name, (site, target, size, expected, disp) in IMAGE_REQUEST_SCALARS.items():
            offset = site - block['rva']
            if (code[offset:offset + len(expected)] != expected
                    or expected[:2] not in (b'\x38\x1d', b'\x8b\x15', b'\x8b\x05')
                    or site + len(expected) + struct.unpack_from('<i', expected, disp)[0] != target):
                raise ValueError(f'{name} differs from witnessed request scalar')
        quality = report['image_processing_helpers']['Req_InputPath']
        quality_code = bytes.fromhex(quality['bytes'])
        site, target, size, expected = IMAGE_REQUEST_QUALITY_TABLE
        offset = site - quality['rva']
        if (not quality_code.startswith(bytes.fromhex('4c8bdc49895b0889'))
                or quality_code[offset:offset + 7] != expected
                or expected[:3] != b'\x48\x8d\x0d'
                or site + 7 + struct.unpack_from('<i', expected, 3)[0] != target):
            raise ValueError('Request quality table differs from witnessed LEA')
        first = {name: fixed_read(target, size)
                 for name, (_, target, size, _, _) in IMAGE_REQUEST_SCALARS.items()}
        report['image_request_helpers'] = {}
        for name, (site, target, size, expected) in IMAGE_REQUEST_CALLS.items():
            data = fixed_read(target, size)
            report['image_request_helpers'][name] = {
                'rva': target, 'size': size, 'bytes': data.hex(),
                'sha256': hashlib.sha256(data).hexdigest(), 'instruction_rva': site,
                'instruction_hex': expected.hex(), 'direct_call_target_verified': True,
                'scope': 'Fixed request callee prefix; contained targets not followed',
            }
        rva, size = IMAGE_REQUEST_TAIL
        tail = fixed_read(rva, size)
        combined = code + tail
        report['image_request_tails'] = {'Req_Worker': {
            'rva': block['rva'], 'size': len(combined), 'bytes': combined.hex(),
            'sha256': hashlib.sha256(combined).hexdigest(),
            'tail_read_rva': rva, 'tail_read_size': size,
            'branch_target_verified': True, 'scope': 'Fixed contiguous worker tail',
        }}
        site, target, size, expected = IMAGE_REQUEST_QUALITY_TABLE
        data = fixed_read(target, size)
        report['image_request_quality_table'] = {
            'rva': target, 'size': size, 'bytes': data.hex(),
            'sha256': hashlib.sha256(data).hexdigest(),
            'instruction_rva': site, 'instruction_hex': expected.hex(),
            'rip_relative_target_verified': True,
        }
        report['image_request_scalars'] = {}
        for name, (site, target, size, expected, _) in IMAGE_REQUEST_SCALARS.items():
            final = fixed_read(target, size, refresh=True)
            report['image_request_scalars'][name] = {
                'rva': target, 'size': size, 'value': int.from_bytes(first[name], 'little'),
                'value_recheck': int.from_bytes(final, 'little'), 'stable': first[name] == final,
                'instruction_rva': site, 'instruction_hex': expected.hex(),
                'rip_relative_target_verified': True,
                'scope': 'Fixed module request scalar; property name unverified',
            }
        report['read_policy'] += ('; image-request-processing option verifies three E8 calls, '
            'one tail branch, four scalar operands and one table LEA before fixed code/data '
            'ranges, each at most 1024 bytes; scalars rechecked, no heap/pointer traversal')
    if image_request_components:
        owners = {**report['image_request_helpers'], **report['image_processing_helpers']}
        for owner, prefix in IMAGE_COMPONENT_PREFIXES.items():
            if not bytes.fromhex(owners[owner]['bytes']).startswith(prefix):
                raise ValueError(f'{owner} differs from witnessed component prefix')
        for name, (owner, site, target, size, expected) in IMAGE_COMPONENT_CALLS.items():
            code = bytes.fromhex(owners[owner]['bytes'])
            offset = site - owners[owner]['rva']
            if (not 0 <= offset <= len(code) - 5 or code[offset:offset + 5] != expected
                    or expected[0] != 0xe8
                    or site + 5 + struct.unpack_from('<i', expected, 1)[0] != target):
                raise ValueError(f'{name} differs from witnessed component call')
        for owner, (rva, size, site, target, expected) in IMAGE_COMPONENT_TAILS.items():
            code = bytes.fromhex(owners[owner]['bytes'])
            offset = site - owners[owner]['rva']
            opcode_size = 1 if expected[:1] == b'\xe9' else 2
            if (not 0 <= offset <= len(code) - len(expected)
                    or code[offset:offset + len(expected)] != expected
                    or expected[:opcode_size] not in (b'\xe9', b'\x0f\x84')
                    or site + len(expected) + struct.unpack_from('<i', expected, opcode_size)[0] != target
                    or not rva <= target < rva + size):
                raise ValueError(f'{owner} differs from witnessed component tail branch')
        for name, (owner, site, target, size, expected) in IMAGE_COMPONENT_DATA.items():
            code = bytes.fromhex(owners[owner]['bytes'])
            offset = site - owners[owner]['rva']
            if (not 0 <= offset <= len(code) - 7 or code[offset:offset + 7] != expected
                    or expected[:3] not in (b'\x48\x8d\x15', b'\x48\x8d\x3d')
                    or site + 7 + struct.unpack_from('<i', expected, 3)[0] != target):
                raise ValueError(f'{name} differs from witnessed component data LEA')
        report['image_component_helpers'] = {}
        for name, (owner, site, target, size, expected) in IMAGE_COMPONENT_CALLS.items():
            data = fixed_read(target, size)
            report['image_component_helpers'][name] = {
                'rva': target, 'size': size, 'bytes': data.hex(),
                'sha256': hashlib.sha256(data).hexdigest(), 'source_implementation': owner,
                'instruction_rva': site, 'instruction_hex': expected.hex(),
                'direct_call_target_verified': True,
                'scope': 'Fixed component callee prefix; no contained targets followed',
            }
        report['image_component_tails'] = {}
        for owner, (rva, size, site, target, expected) in IMAGE_COMPONENT_TAILS.items():
            data = fixed_read(rva, size)
            combined = bytes.fromhex(owners[owner]['bytes']) + data
            report['image_component_tails'][owner] = {
                'rva': owners[owner]['rva'], 'size': len(combined), 'bytes': combined.hex(),
                'sha256': hashlib.sha256(combined).hexdigest(),
                'tail_read_rva': rva, 'tail_read_size': size, 'instruction_rva': site,
                'instruction_hex': expected.hex(), 'branch_target_verified': True,
                'scope': 'Original prefix plus fixed contiguous component tail',
            }
        report['image_component_data'] = {}
        for name, (owner, site, target, size, expected) in IMAGE_COMPONENT_DATA.items():
            data = fixed_read(target, size)
            report['image_component_data'][name] = {
                'rva': target, 'size': size, 'bytes': data.hex(),
                'sha256': hashlib.sha256(data).hexdigest(), 'source_implementation': owner,
                'instruction_rva': site, 'instruction_hex': expected.hex(),
                'rip_relative_target_verified': True, 'scope': 'Fixed module literal; no pointers followed',
            }
        report['read_policy'] += ('; image-request-components verifies five callee prefixes, '
            'two E8 calls, two tail branches and two literal LEAs before fixed module reads '
            'of at most 1024 bytes; no heap or pointers followed')
    if image_request_queue:
        block = report['image_component_tails']['Request_Dispatch']
        code = bytes.fromhex(block['bytes'])
        site, target, size, expected = IMAGE_QUEUE_CALL
        offset = site - block['rva']
        if (not code.startswith(IMAGE_COMPONENT_PREFIXES['Request_Dispatch'])
                or not 0 <= offset <= len(code) - 5
                or code[offset:offset + 5] != expected or expected[0] != 0xe8
                or site + 5 + struct.unpack_from('<i', expected, 1)[0] != target):
            raise ValueError('Request queue scheduling differs from witnessed direct call')
        data = fixed_read(target, size)
        report['image_queue_helper'] = {
            'rva': target, 'size': size, 'bytes': data.hex(),
            'sha256': hashlib.sha256(data).hexdigest(),
            'instruction_rva': site, 'instruction_hex': expected.hex(),
            'direct_call_target_verified': True,
            'scope': 'One fixed queue callee prefix; no contained targets or pointers followed',
        }
        report['read_policy'] += ('; image-request-queue verifies the completed dispatch prefix '
            'and exact E8 before one fixed 1024-byte queue callee; no heap or pointers followed')
    report['captured_bytes'] = captured_bytes
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--implementations', action='store_true',
                        help='Also verify fixed implementation/configuration call and LEA witnesses before their bounded module ranges')
    parser.add_argument('--composition', action='store_true',
                        help='With --implementations, verify four further calls and ten module byte operands before fixed reads')
    parser.add_argument('--image-path', action='store_true',
                        help='Verify four additional image method registrations before their fixed callback prefixes')
    parser.add_argument('--image-implementations', action='store_true',
                        help='With --image-path, verify four callback direct edges before fixed 1024-byte callee prefixes')
    parser.add_argument('--image-storage', action='store_true',
                        help='With --image-implementations, verify two image storage calls before fixed callee prefixes')
    parser.add_argument('--image-processing', action='store_true',
                        help='With --image-storage, verify fixed request/hash calls, setter tails and one module branch byte')
    parser.add_argument('--image-crc-table', action='store_true',
                        help='With --image-processing, verify the hash routine LEA before its fixed 1024-byte module table')
    parser.add_argument('--image-request-processing', action='store_true',
                        help='With --image-processing, verify request calls, tail, quality table and fixed module scalars')
    parser.add_argument('--image-request-components', action='store_true',
                        help='With --image-request-processing, verify component calls, final tails and module literals')
    parser.add_argument('--image-request-queue', action='store_true',
                        help='With --image-request-components, verify the queue scheduling call before one fixed callee prefix')
    parser.add_argument('--output', type=Path,
                        default=ROOT / 'work/evidence/live-cdn-loader-private.json')
    args = parser.parse_args()
    if args.pid <= 0 or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ValueError('Expected an explicit native x64 client PID')
    source_root, shadow_root = game_paths()
    expected_shadow = shadow_root / source_probe.CLIENT_RELATIVE_PATH
    source_executable = source_root / source_probe.CLIENT_RELATIVE_PATH
    source_probe.verify_shadow_executable(expected_shadow, expected_shadow, source_executable)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.K32EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.K32EnumProcessModules.restype = wintypes.BOOL
    kernel.K32GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                             ctypes.POINTER(source_probe.ModuleInfo), wintypes.DWORD]
    kernel.K32GetModuleInformation.restype = wintypes.BOOL
    kernel.K32GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                            wintypes.LPWSTR, wintypes.DWORD]
    kernel.K32GetModuleFileNameExW.restype = wintypes.DWORD
    kernel.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel.ReadProcessMemory.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x0410, False, args.pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        modules = (wintypes.HMODULE * 1024)()
        needed = wintypes.DWORD()
        if not kernel.K32EnumProcessModules(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not needed.value or needed.value > ctypes.sizeof(modules):
            raise ValueError('Unexpected native module count')
        image = modules[0]
        path_buffer = ctypes.create_unicode_buffer(32768)
        if not kernel.K32GetModuleFileNameExW(handle, image, path_buffer, len(path_buffer)):
            raise ctypes.WinError(ctypes.get_last_error())
        if Path(path_buffer.value).resolve() != expected_shadow.resolve():
            raise ValueError('PID does not identify the authorized shadow executable')
        info = source_probe.ModuleInfo()
        if not kernel.K32GetModuleInformation(handle, image, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        allowed = allowed_spans(args.implementations, args.composition, args.image_path, args.image_implementations, args.image_storage, args.image_processing, args.image_crc_table, args.image_request_processing, args.image_request_components, args.image_request_queue)

        def read(address, size):
            if ((address - info.base, size) not in allowed or not 0 < size <= 1024
                    or not info.base <= address < address + size <= info.base + info.size):
                raise ValueError('Read is outside the approved fixed CDN module witness')
            buffer = ctypes.create_string_buffer(size)
            count = ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, buffer, size, ctypes.byref(count)):
                raise ctypes.WinError(ctypes.get_last_error())
            if count.value != size:
                raise ValueError('ReadProcessMemory returned a different witness length')
            return buffer.raw

        report = capture(read, info.base, info.size, args.implementations, args.composition, args.image_path, args.image_implementations, args.image_storage, args.image_processing, args.image_crc_table, args.image_request_processing, args.image_request_components, args.image_request_queue)
        report['pid'] = args.pid
        report['shadow_executable'] = str(expected_shadow.resolve())
        from probe_live_keybox_registration import capstone_module
        capstone = capstone_module()
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for block in (*report['fixed_code'].values(), *report.get('implementations', {}).values(),
                      *report.get('configuration_accessors', {}).values(),
                      *report.get('fixed_tails', {}).values(),
                      *report.get('composition_helpers', {}).values(),
                      *report.get('image_callbacks', {}).values(),
                      *report.get('image_implementations', {}).values(),
                      *report.get('image_storage_helpers', {}).values(),
                      *report.get('image_processing_helpers', {}).values(),
                      *report.get('image_processing_tails', {}).values(),
                      *report.get('image_request_helpers', {}).values(),
                      *report.get('image_request_tails', {}).values(),
                      *report.get('image_component_helpers', {}).values(),
                      *report.get('image_component_tails', {}).values(),
                      *([report['image_queue_helper']] if 'image_queue_helper' in report else [])):
            block['instructions'] = [
                {'rva': item.address - info.base, 'op': item.mnemonic, 'args': item.op_str}
                for item in decoder.disasm(bytes.fromhex(block['bytes']), info.base + block['rva'])]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'registrations_verified': len(report['registrations']),
            'fixed_code_ranges': len(report['fixed_code']),
            'implementation_ranges': len(report.get('implementations', {})),
            'configuration_accessor_ranges': len(report.get('configuration_accessors', {})),
            'static_module_data_ranges': len(report.get('static_configuration_operands', {})),
            'fixed_code_tail_ranges': len(report.get('fixed_tails', {})),
            'composition_helper_ranges': len(report.get('composition_helpers', {})),
            'composition_scalar_ranges': len(report.get('composition_scalars', {})),
            'image_callback_ranges': len(report.get('image_callbacks', {})),
            'image_implementation_ranges': len(report.get('image_implementations', {})),
            'image_storage_helper_ranges': len(report.get('image_storage_helpers', {})),
            'image_processing_helper_ranges': len(report.get('image_processing_helpers', {})),
            'image_processing_tail_ranges': len(report.get('image_processing_tails', {})),
            'captured_bytes': report['captured_bytes'], 'report': str(args.output)}))
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    main()
