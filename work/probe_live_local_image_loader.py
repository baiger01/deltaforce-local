"""Read three named local-image registrations and two witnessed implementations.

Requires an explicit shadow PID and its previously observed creation timestamp.
Reads fixed main-module code/data only; no launches, client calls, writes, hooks,
heap reads, network requests, or indirect pointer traversal.
"""

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import struct

from local_game_paths import game_paths
import probe_live_resource_loader as source


ROOT = Path(__file__).resolve().parent.parent
REGISTRATIONS = {
    'SetBackgroundImage': (0x169b6960,
        (0x15acb7b8, 0x6403560, 0xe05150, 0x14edf3dc, 0x1cda5040, 3)),
    'SetBackgroundImageForWaterfall': (0x169b6990,
        (0x169b6e48, 0x6403570, 0xe05150, 0x14edf3dc, 0x1cda5058, 3)),
    'CheckPathValid': (0x18bdef80,
        (0x18be0000, 0xd50bd20, 0x11ee900, 0x14ee4878, 0x1d2d87f8, 2)),
}
SOURCE_RECORDS = {
    'SetBackgroundImage': (379280736, '7fb41598a71942f5dfd6cb7172416b8fb9eb5a59ad9d6b59d1a1bb7a953d9c99'),
    'SetBackgroundImageForWaterfall': (379280784, 'a4f919b5c12e7ac573230ef8180ab9f915e50f3f26d99593b3f71fae20654329'),
    'CheckPathValid': (415097728, '05292b9b72b447738ba324c633ab6a38f5703bbabc40331c05277876aab847ee'),
}
CALLBACKS = {'background_callback_region': (0x6403500, 160),
             'CheckPathValid_callback': (0xd50bd20, 160)}
BACKGROUND_PREFIX = bytes.fromhex('48895c240848896c')
IMPLEMENTATIONS = {
    'SetBackgroundImage': (0x6403560, 0x63c43e0, bytes.fromhex('e97b0efcff')),
    'SetBackgroundImageForWaterfall': (0x6403570, 0x63c4620, bytes.fromhex('e9ab10fcff')),
}
IMPLEMENTATION_SIZE = 1024
SOURCE_CALLBACK_CAPTURE = 'live-cdn-image-components-trial3-bundle-20261005-private.json'
SOURCE_CALLBACK_CAPTURE_SHA = '6b24a730c4b74fb5f0833022cc3f1c67318dd4846c99db7528be8c12ca83a9f9'
SOURCE_CALLBACK_SPAN_SHA = '0896bef7d1520a08ae661e09223f4b2bc2dbc723ead8aac655faba46e75aa94b'
ROUTE_SOURCE_SHA = 'b5b1e08823015d801c997a2f6d5ecc27ebcfbf224bb7b59ab7ad46cf996e622e'
ROUTE_EDGES = (
    ('callbacks', 'CheckPathValid_callback', 0xd50bd40, 0xd4c47d0, bytes.fromhex('e88b8afbff'), 1),
    ('implementations', 'SetBackgroundImage', 0x63c456e, 0x122abd90, bytes.fromhex('e81d78ee0b'), 1),
    ('implementations', 'SetBackgroundImageForWaterfall', 0x63c48ae, 0x122abd90, bytes.fromhex('e8dd74ee0b'), 1),
    ('implementations', 'SetBackgroundImage', 0x63c4545, 0x6382160, bytes.fromhex('488d0d14dcfbff'), 3),
    ('implementations', 'SetBackgroundImageForWaterfall', 0x63c4885, 0x6382160, bytes.fromhex('488d0dd4d8fbff'), 3),
)
ROUTE_TARGETS = {'CheckPathValid': 0xd4c47d0, 'SharedAsyncDispatcher': 0x122abd90,
                 'SharedLocalImageFunctor': 0x6382160}
PREDICATE_FUNCTOR_SOURCE_SHA = '8fc41e76c72882dc57d71e5684ad62bf7abfe48ed6abdbed6cdb2e3aa5cb82f5'
PREDICATE_FUNCTOR_EDGES = (
    ('CheckPathValid', 0xd4c4a2c, 0xdac3d0, bytes.fromhex('e89f798ef3')),
    ('SharedLocalImageFunctor', 0x6382160, 0x63727f0, bytes.fromhex('e98b06ffff')),
)
PREDICATE_FUNCTOR_TARGETS = {'PathPredicate': 0xdac3d0, 'LocalImageFunctorBody': 0x63727f0}
PACKAGE_BRUSH_SOURCE_SHA = '4703e7429f4e18b48a72e6be65613cfaefd843dd85ef303695fa6b9caa588909'
PACKAGE_BRUSH_EDGES = (
    ('PathPredicate', 0xdac474, 0x10ecd110, bytes.fromhex('e8970c1210')),
    ('LocalImageFunctorBody', 0x6372983, 0x63c89a0, bytes.fromhex('e818600500')),
)
PACKAGE_BRUSH_TARGETS = {'PackagePathPredicate': 0x10ecd110, 'LocalImageBrushSetter': 0x63c89a0}


def read_route_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('local_route_requires_existing_bounded_prior_capture')
    with path.open('rb') as evidence:
        raw = evidence.read(65537)
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) > 65536 or digest != ROUTE_SOURCE_SHA:
        raise ValueError('local_route_prior_capture_full_sha256_mismatch')
    report = json.loads(raw)
    if report.get('native_pe_sha256') != source.EXPECTED_PE:
        raise ValueError('local_route_prior_capture_source_PE_mismatch')
    return digest


def read_predicate_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('predicate_functor_requires_existing_bounded_prior_capture')
    with path.open('rb') as evidence:
        raw = evidence.read(65537)
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) > 65536 or digest != PREDICATE_FUNCTOR_SOURCE_SHA:
        raise ValueError('predicate_functor_prior_capture_full_sha256_mismatch')
    report = json.loads(raw)
    if report.get('native_pe_sha256') != source.EXPECTED_PE:
        raise ValueError('predicate_functor_prior_capture_source_PE_mismatch')
    return digest


def read_package_brush_source(path):
    path = Path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError('package_brush_requires_existing_bounded_prior_capture')
    with path.open('rb') as evidence:
        raw = evidence.read(65537)
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) > 65536 or digest != PACKAGE_BRUSH_SOURCE_SHA:
        raise ValueError('package_brush_prior_capture_full_sha256_mismatch')
    report = json.loads(raw)
    if report.get('native_pe_sha256') != source.EXPECTED_PE:
        raise ValueError('package_brush_prior_capture_source_PE_mismatch')
    return digest


def verify_creation(actual, expected):
    if (type(actual) not in (int, float) or type(expected) not in (int, float)
            or not math.isfinite(actual) or not math.isfinite(expected)
            or actual <= 0 or expected <= 0 or abs(actual - expected) > 0.001):
        raise ValueError('explicit_process_creation_timestamp_mismatch')


def output_path(output, installed, shadow, *, evidence_root=ROOT / 'work/evidence'):
    target = Path(output).resolve()
    installed, shadow, evidence_root = (Path(value).resolve() for value in (installed, shadow, evidence_root))
    if (target.is_relative_to(installed) or target.is_relative_to(shadow)
            or target == evidence_root or not target.is_relative_to(evidence_root)):
        raise ValueError('output_must_be_in_project_work_evidence_outside_game_roots')
    if target.exists():
        raise ValueError('existing_evidence_output_must_be_preserved')
    return target


def allowed_spans(local_route=False, local_predicate_functor=False, package_brush=False):
    spans = {(rva, 48) for rva, _ in REGISTRATIONS.values()}
    spans.update((row[0], 32) for _, row in REGISTRATIONS.values())
    spans.update(CALLBACKS.values())
    spans.update((target, IMPLEMENTATION_SIZE) for _, target, _ in IMPLEMENTATIONS.values())
    if local_route:
        spans.update((target, IMPLEMENTATION_SIZE) for target in ROUTE_TARGETS.values())
    if local_predicate_functor:
        spans.update((target, IMPLEMENTATION_SIZE) for target in PREDICATE_FUNCTOR_TARGETS.values())
    if package_brush:
        spans.update((target, IMPLEMENTATION_SIZE) for target in PACKAGE_BRUSH_TARGETS.values())
    return spans


def capture(read, base, module_size, actual_created, expected_created, *, local_route=False,
            route_source_digest=None, route_source_pe=None, local_predicate_functor=False,
            predicate_source_digest=None, predicate_source_pe=None, package_brush=False,
            package_brush_source_digest=None, package_brush_source_pe=None):
    verify_creation(actual_created, expected_created)
    if local_route and (route_source_digest != ROUTE_SOURCE_SHA or route_source_pe != source.EXPECTED_PE):
        raise ValueError('local_route_requires_pinned_prior_capture_and_source_PE')
    if local_predicate_functor and (not local_route
            or predicate_source_digest != PREDICATE_FUNCTOR_SOURCE_SHA
            or predicate_source_pe != source.EXPECTED_PE):
        raise ValueError('predicate_functor_requires_local_route_and_pinned_capture_and_source_PE')
    if package_brush and (not local_predicate_functor
            or package_brush_source_digest != PACKAGE_BRUSH_SOURCE_SHA
            or package_brush_source_pe != source.EXPECTED_PE):
        raise ValueError('package_brush_requires_predicate_functor_and_pinned_capture_and_source_PE')
    spans = allowed_spans(local_route, local_predicate_functor, package_brush)
    if (type(base) is not int or type(module_size) is not int or base <= 0
            or module_size <= 0 or base + module_size >= 1 << 64
            or any(rva < 0 or rva + size > module_size for rva, size in spans)):
        raise ValueError('fixed_local_image_ranges_outside_main_module')
    count = 0

    def fixed(rva, size):
        nonlocal count
        if (rva, size) not in spans or not 0 < size <= 1024:
            raise ValueError('read_not_in_fixed_local_image_scope')
        raw = read(base + rva, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError('short_local_image_witness_read')
        count += size
        return raw

    report = {'native_pe_sha256': source.EXPECTED_PE, 'module_base': base,
              'module_size': module_size, 'process_created_unix': actual_created,
              'expected_process_created_unix': expected_created,
              'process_creation_verified': True, 'registrations': {},
              'callbacks': {}, 'implementations': {},
              'source_callback_capture': SOURCE_CALLBACK_CAPTURE,
              'source_callback_capture_sha256': SOURCE_CALLBACK_CAPTURE_SHA,
              'source_callback_span_sha256': SOURCE_CALLBACK_SPAN_SHA,
              'scope': 'Three named registration rows/names, two fixed160B callback ranges, '
                       'and two exact1024B E9 targets; no CheckPathValid target follows, '
                       'heap reads, client calls, writes, hooks, or network requests'}
    for name, (rva, row) in REGISTRATIONS.items():
        actual = struct.unpack('<6Q', fixed(rva, 48))
        if actual != tuple(base + value for value in row[:5]) + (row[5],):
            raise ValueError('named_local_image_registration_mismatch_' + name)
        raw_name = fixed(row[0], 32)
        if b'\0' not in raw_name or raw_name.split(b'\0', 1)[0] != name.encode('ascii'):
            raise ValueError('named_local_image_name_mismatch_' + name)
        report['registrations'][name] = {
            'registration_rva': rva, 'name_rva': row[0], 'callback_rva': row[1],
            'binding_rva': row[2], 'return_descriptor_rva': row[3],
            'argument_descriptor_rva': row[4], 'argument_flags': row[5],
            'source_record_file_offset': SOURCE_RECORDS[name][0],
            'source_record_sha256': SOURCE_RECORDS[name][1], 'all_fields_verified': True}
    for name, (rva, size) in CALLBACKS.items():
        raw = fixed(rva, size)
        report['callbacks'][name] = {'rva': rva, 'size': size, 'bytes': raw.hex(),
                                    'sha256': hashlib.sha256(raw).hexdigest()}
    block = report['callbacks']['background_callback_region']
    code = bytes.fromhex(block['bytes'])
    if not code.startswith(BACKGROUND_PREFIX):
        raise ValueError('background_callback_region_prefix_changed')
    # Both source-proven jumps must match before either target is read.
    for name, (site, target, expected) in IMPLEMENTATIONS.items():
        raw = code[site - block['rva']:site - block['rva'] + 5]
        if raw != expected or site + 5 + struct.unpack_from('<i', raw, 1)[0] != target:
            raise ValueError('background_direct_jump_changed_' + name)
    for name, (site, target, _) in IMPLEMENTATIONS.items():
        raw = fixed(target, IMPLEMENTATION_SIZE)
        report['implementations'][name] = {
            'source_jump_rva': site, 'rva': target, 'size': IMPLEMENTATION_SIZE,
            'bytes': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest(),
            'direct_jump_verified': True,
            'scope': 'Fixed code prefix; contained targets and pointers are not followed'}
    if local_route:
        # Every fresh source edge is verified before any of the three extra reads.
        for group, owner, site, target, expected, displacement in ROUTE_EDGES:
            block = report[group][owner]
            code = bytes.fromhex(block['bytes'])
            offset = site - block['rva']
            witness = code[offset:offset + len(expected)]
            if (witness != expected
                    or site + len(expected) + struct.unpack_from('<i', witness, displacement)[0] != target):
                raise ValueError('local_route_source_instruction_changed_' + owner)
        report['local_route_source_sha256'] = route_source_digest
        report['local_route'] = {}
        for name, target in ROUTE_TARGETS.items():
            raw = fixed(target, IMPLEMENTATION_SIZE)
            report['local_route'][name] = {
                'rva': target, 'size': IMPLEMENTATION_SIZE, 'bytes': raw.hex(),
                'sha256': hashlib.sha256(raw).hexdigest(), 'all_source_edges_verified': True,
                'scope': 'Fixed module code only; contained calls and pointers are not followed'}
        report['scope'] += '; optional three source-gated1024B local-route code ranges'
    if local_predicate_functor:
        # Both fresh predecessor instructions must match before either new range.
        for owner, site, target, expected in PREDICATE_FUNCTOR_EDGES:
            block = report['local_route'][owner]
            code = bytes.fromhex(block['bytes'])
            offset = site - block['rva']
            witness = code[offset:offset + len(expected)]
            if (witness != expected
                    or site + len(expected) + struct.unpack_from('<i', witness, 1)[0] != target):
                raise ValueError('predicate_functor_source_instruction_changed_' + owner)
        report['local_predicate_functor_source_sha256'] = predicate_source_digest
        report['local_predicate_functor'] = {}
        for name, target in PREDICATE_FUNCTOR_TARGETS.items():
            raw = fixed(target, IMPLEMENTATION_SIZE)
            report['local_predicate_functor'][name] = {
                'rva': target, 'size': IMPLEMENTATION_SIZE, 'bytes': raw.hex(),
                'sha256': hashlib.sha256(raw).hexdigest(), 'all_source_edges_verified': True,
                'scope': 'Fixed module code only; contained calls and pointers are not followed'}
        report['scope'] += '; optional two source-gated1024B predicate/functor code ranges'
    if package_brush:
        # Verify both freshly read direct calls before either final code prefix.
        for owner, site, target, expected in PACKAGE_BRUSH_EDGES:
            block = report['local_predicate_functor'][owner]
            code = bytes.fromhex(block['bytes'])
            offset = site - block['rva']
            witness = code[offset:offset + len(expected)]
            if (witness != expected
                    or site + len(expected) + struct.unpack_from('<i', witness, 1)[0] != target):
                raise ValueError('package_brush_source_instruction_changed_' + owner)
        report['package_brush_source_sha256'] = package_brush_source_digest
        report['package_brush'] = {}
        for name, target in PACKAGE_BRUSH_TARGETS.items():
            raw = fixed(target, IMPLEMENTATION_SIZE)
            report['package_brush'][name] = {
                'rva': target, 'size': IMPLEMENTATION_SIZE, 'bytes': raw.hex(),
                'sha256': hashlib.sha256(raw).hexdigest(), 'all_source_edges_verified': True,
                'scope': 'Fixed module code only; contained calls and pointers are not followed'}
        report['scope'] += '; optional two source-gated1024B package/brush code ranges'
    report['captured_bytes'] = count
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--expected-create-time', type=float, required=True,
                        help='Previously observed Unix process creation timestamp')
    parser.add_argument('--source-game', type=Path,
                        help='Explicit installed source directory; survives elevation without inherited environment')
    parser.add_argument('--shadow-game', type=Path,
                        help='Explicit independent shadow directory')
    parser.add_argument('--local-route', action='store_true',
                        help='After five exact source edges verify, read three fixed1024B local-route code ranges')
    parser.add_argument('--source-capture', type=Path,
                        help='Required with --local-route: pinned prior local-image capture')
    parser.add_argument('--local-predicate-functor', action='store_true',
                        help='After two fresh exact E8/E9 witnesses verify, read two fixed1024B code ranges')
    parser.add_argument('--predicate-source-capture', type=Path,
                        help='Required with --local-predicate-functor: pinned preserved local-route report')
    parser.add_argument('--package-brush', action='store_true',
                        help='After two fresh exact E8 witnesses verify, read final two fixed1024B code ranges')
    parser.add_argument('--package-brush-source-capture', type=Path,
                        help='Required with --package-brush: pinned preserved predicate/functor report')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.pid <= 0 or ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error('explicit_native_x64_shadow_PID_required')
    verify_creation(args.expected_create_time, args.expected_create_time)
    if args.local_route and args.source_capture is None:
        parser.error('--local-route requires --source-capture pointing to the preserved local-image report')
    route_source_digest = read_route_source(args.source_capture) if args.local_route else None
    if args.local_predicate_functor and (not args.local_route or args.predicate_source_capture is None):
        parser.error('--local-predicate-functor requires --local-route and --predicate-source-capture')
    predicate_source_digest = (read_predicate_source(args.predicate_source_capture)
                               if args.local_predicate_functor else None)
    if args.package_brush and (not args.local_predicate_functor or args.package_brush_source_capture is None):
        parser.error('--package-brush requires --local-predicate-functor and --package-brush-source-capture')
    package_brush_source_digest = (read_package_brush_source(args.package_brush_source_capture)
                                   if args.package_brush else None)
    game_root, shadow_root = game_paths(args.source_game, args.shadow_game)
    output = output_path(args.output, game_root, shadow_root)
    installed = game_root / source.CLIENT_RELATIVE_PATH
    shadow = shadow_root / source.CLIENT_RELATIVE_PATH
    source.verify_shadow_executable(shadow, shadow, installed)
    digest = hashlib.sha256()
    with installed.open('rb') as original:
        for chunk in iter(lambda: original.read(8 * 1024 * 1024), b''):
            digest.update(chunk)
    if digest.hexdigest() != source.EXPECTED_PE:
        raise ValueError('original_source_executable_sha256_mismatch')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.K32EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.K32EnumProcessModules.restype = wintypes.BOOL
    kernel.K32GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                             ctypes.POINTER(source.ModuleInfo), wintypes.DWORD]
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
        def created():
            times = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
                raise ctypes.WinError(ctypes.get_last_error())
            ticks = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            return ticks / 10000000 - 11644473600
        creation = created()
        verify_creation(creation, args.expected_create_time)
        modules = (wintypes.HMODULE * 1024)()
        needed = wintypes.DWORD()
        if not kernel.K32EnumProcessModules(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not needed.value or needed.value > ctypes.sizeof(modules):
            raise ValueError('unexpected_native_module_count')
        path = ctypes.create_unicode_buffer(32768)
        if not kernel.K32GetModuleFileNameExW(handle, modules[0], path, len(path)):
            raise ctypes.WinError(ctypes.get_last_error())
        if Path(path.value).resolve() != shadow.resolve():
            raise ValueError('PID_does_not_identify_authorized_shadow_executable')
        info = source.ModuleInfo()
        if not kernel.K32GetModuleInformation(handle, modules[0], ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        spans = allowed_spans(args.local_route, args.local_predicate_functor, args.package_brush)
        def read(address, size):
            if (address - info.base, size) not in spans or not 0 < size <= 1024:
                raise ValueError('process_read_not_in_fixed_local_image_scope')
            if not info.base <= address < address + size <= info.base + info.size:
                raise ValueError('process_read_outside_main_module')
            raw, actual = ctypes.create_string_buffer(size), ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, address, raw, size, ctypes.byref(actual)):
                raise ctypes.WinError(ctypes.get_last_error())
            if actual.value != size:
                raise ValueError('process_returned_short_local_image_witness')
            return raw.raw
        report = capture(read, info.base, info.size, creation, args.expected_create_time,
                         local_route=args.local_route, route_source_digest=route_source_digest,
                         route_source_pe=source.EXPECTED_PE if args.local_route else None,
                         local_predicate_functor=args.local_predicate_functor,
                         predicate_source_digest=predicate_source_digest,
                         predicate_source_pe=source.EXPECTED_PE if args.local_predicate_functor else None,
                         package_brush=args.package_brush,
                         package_brush_source_digest=package_brush_source_digest,
                         package_brush_source_pe=source.EXPECTED_PE if args.package_brush else None)
        verify_creation(created(), creation)
        report.update(pid=args.pid, shadow_executable=str(shadow.resolve()),
                      process_creation_rechecked=True,
                      captured_at_utc=datetime.now(timezone.utc).isoformat())
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('x', encoding='utf-8') as evidence:
            evidence.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'registrations_verified': 3, 'implementation_ranges': 2,
                          'local_route_ranges': len(report.get('local_route', {})),
                          'predicate_functor_ranges': len(report.get('local_predicate_functor', {})),
                          'package_brush_ranges': len(report.get('package_brush', {})),
                          'captured_bytes': report['captured_bytes'], 'report': str(output)}))
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    main()
