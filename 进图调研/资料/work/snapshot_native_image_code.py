"""Private, bounded snapshot of file-backed executable sections only.

Default CLI validates immutable disk metadata. Explicit --collect requires the
already running unique shadow client, exact PID/create time, and ordinary read
permissions. No launch, elevation, patch, object graph, data/heap/stack read,
reconstructed executable, or disassembly-completeness claim is made.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import json
import math
import mmap
import os
from pathlib import Path

import pefile
import psutil

ROOT = Path(__file__).resolve().parent.parent
CACHE_ROOT = ROOT/'work/native-code-cache'
SHADOW_ROOT = Path('D:/个人工作区/DeltaForce-local-client')
EXECUTABLE_RELATIVE = Path('DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
SOURCE_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
HEADER_SHA = '683ce652da328fbb05743e755090b86d616dfebb67d47a6dd4cc183c854c291e'
FILE_BYTES, IMAGE_SIZE, HEADER_BYTES = 514156152, 536408064, 1536
CHUNK_BYTES, PAGE_BYTES, MAX_MODULES = 1048576, 4096, 4096
TOTAL_BYTES = 349562443
# Section index, RVA, virtual length, raw length, raw offset, raw-backed SHA.
SECTIONS = (
    (0, 0x1000, 349183051, 349183488, 1536,
     'baa71f378b167d9f24250b8795c3be9f2d187cf13b40e3b9945eebb322217430'),
    (8, 0x1f4aa000, 11300864, 379392, 513647616,
     '5aa09dbaf51fafc18c827733d049fa15b6d48f87c5e221d5be8b75b2e7424337'),
)
KNOWN_SENDERS = (
    ('SendBunch.complete_wrapper', 0x5bfbfd0, 36,
     'c0c824a5e685328a9310cf98569c920432cf65f28cf6b958280c225741939279'),
    ('Control.SendBunch.static_slot_candidate', 0x1286d3a0, 463,
     '93764563d5585389fffeaf4ca71e83f0cc09aeb6461dd305bdd6742fe6fafcfb'),
    ('Channel.SendBunch.actor_static_slot_candidate', 0x1286c6f0, 3238,
     'd17ac55a6775612277f174d5c1513a7b715ed2912d363430363415d28d37412a'),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def normalized(path):
    return os.path.normcase(str(Path(path).resolve()))


def save_json(path, value):
    temporary = path.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    temporary.replace(path)


def validate_plan(game_root):
    """Static only: no kernel API, process enumeration, or memory access."""
    executable = Path(game_root)/EXECUTABLE_RELATIVE
    if executable.stat().st_size != FILE_BYTES:
        raise ValueError('Pinned executable file size mismatch')
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        if sha(raw) != SOURCE_SHA:
            raise ValueError('Pinned executable SHA mismatch')
        pe = pefile.PE(data=raw, fast_load=True)
        if (pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20b or
                pe.OPTIONAL_HEADER.SizeOfImage != IMAGE_SIZE or
                pe.OPTIONAL_HEADER.SizeOfHeaders != HEADER_BYTES or sha(raw[:HEADER_BYTES]) != HEADER_SHA):
            raise ValueError('Pinned PE header identity mismatch')
        actual = [i for i, s in enumerate(pe.sections) if s.Characteristics & 0x20000000]
        if actual != [row[0] for row in SECTIONS]:
            raise ValueError('Executable section set mismatch')
        rows = []
        for index, rva, virtual, backing, offset, disk_sha in SECTIONS:
            s = pe.sections[index]
            length = min(virtual, backing)
            if ((s.VirtualAddress, s.Misc_VirtualSize, s.SizeOfRawData, s.PointerToRawData,
                 s.Characteristics, s.Name.rstrip(b'\0')) !=
                    (rva, virtual, backing, offset, 0x60000020, b'.std') or
                    not 0 <= offset < offset+length <= len(raw) or
                    not 0 <= rva < rva+length <= IMAGE_SIZE or
                    sha(raw[offset:offset+length]) != disk_sha):
                raise ValueError('Pinned executable section bounds/SHA mismatch')
            rows.append({'index': index, 'name': '.std', 'rva': hex(rva),
                'file_backed_code_bytes': length, 'virtual_size': virtual,
                'raw_size': backing, 'raw_backed_sha256': disk_sha,
                'excluded_virtual_only_bytes': max(0, virtual-backing)})
    if sum(r['file_backed_code_bytes'] for r in rows) != TOTAL_BYTES:
        raise ValueError('Code snapshot byte budget mismatch')
    return {'kind': 'fixed_private_native_image_code_plan', 'status': 'offline_plan_validated',
        'client_sha256': SOURCE_SHA, 'client_relative_to_game_root': EXECUTABLE_RELATIVE.as_posix(),
        'immutable_image_size_bytes': IMAGE_SIZE, 'sections': rows,
        'maximum_code_bytes': TOTAL_BYTES, 'maximum_RPM_bytes': CHUNK_BYTES,
        'fixed_1MiB_chunk_count': sum((r['file_backed_code_bytes']+CHUNK_BYTES-1)//CHUNK_BYTES for r in rows),
        'maximum_region_split_RPM_count': sum((r['file_backed_code_bytes']+PAGE_BYTES-1)//PAGE_BYTES for r in rows),
        'private_cache_only': True, 'whole_executable_dump': False,
        'process_memory_read': False, 'live_data_object_read': False, 'reconstructed_executable': False,
        'native_complete_decode_claimed': False, 'known_sender_targets': [
            {'name': label, 'rva': hex(rva), 'code_bytes': length, 'expected_code_sha256': expected}
            for label, rva, length, expected in KNOWN_SENDERS]}


class Module(C.Structure):
    _fields_ = [('dwSize', W.DWORD), ('th32ModuleID', W.DWORD), ('th32ProcessID', W.DWORD),
        ('GlblcntUsage', W.DWORD), ('ProccntUsage', W.DWORD), ('modBaseAddr', C.c_void_p),
        ('modBaseSize', W.DWORD), ('hModule', W.HMODULE), ('szModule', W.WCHAR*256), ('szExePath', W.WCHAR*260)]


class Memory(C.Structure):
    _fields_ = [('BaseAddress', C.c_void_p), ('AllocationBase', C.c_void_p),
        ('AllocationProtect', W.DWORD), ('PartitionId', W.WORD), ('RegionSize', C.c_size_t),
        ('State', W.DWORD), ('Protect', W.DWORD), ('Type', W.DWORD)]


def kernel():
    api = C.WinDLL('kernel32', use_last_error=True)
    definitions = {
        'OpenProcess': ([W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
        'CloseHandle': ([W.HANDLE], W.BOOL), 'GetProcessId': ([W.HANDLE], W.DWORD),
        'CreateToolhelp32Snapshot': ([W.DWORD, W.DWORD], W.HANDLE),
        'Module32FirstW': ([W.HANDLE, C.POINTER(Module)], W.BOOL),
        'Module32NextW': ([W.HANDLE, C.POINTER(Module)], W.BOOL),
        'VirtualQueryEx': ([W.HANDLE, C.c_void_p, C.POINTER(Memory), C.c_size_t], C.c_size_t),
        'ReadProcessMemory': ([W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)], W.BOOL),
    }
    for name, (args, result) in definitions.items():
        function = getattr(api, name)
        function.argtypes, function.restype = args, result
    return api


def verified_pids(executable):
    expected, found = normalized(executable), []
    for process in psutil.process_iter(['pid', 'name', 'exe']):
        if (process.info['name'] or '').lower() == executable.name.lower():
            path = process.info['exe']
            if path and normalized(path) == expected:
                found.append(process.info['pid'])
    return sorted(found)


def process_identity(api, handle, pid, executable, created):
    if api.GetProcessId(handle) != pid:
        raise RuntimeError('Opened PID identity changed')
    process = psutil.Process(pid)
    if process.create_time() != created or normalized(process.exe()) != normalized(executable):
        raise RuntimeError('Pinned process creation time or path changed')


def verified_module(api, pid, executable):
    snapshot = api.CreateToolhelp32Snapshot(0x18, pid)
    if not snapshot or snapshot == C.c_void_p(-1).value:
        raise RuntimeError('Module snapshot unavailable')
    try:
        item = Module()
        item.dwSize = C.sizeof(item)
        matches, count = [], 0
        ok = api.Module32FirstW(snapshot, C.byref(item))
        while ok:
            count += 1
            if count > MAX_MODULES:
                raise RuntimeError('Module snapshot entry budget exceeded')
            if normalized(item.szExePath) == normalized(executable):
                matches.append((item.modBaseAddr, item.modBaseSize))
            ok = api.Module32NextW(snapshot, C.byref(item))
        if len(matches) != 1 or not matches[0][0] or matches[0][1] != IMAGE_SIZE:
            raise RuntimeError('Pinned executable module identity/size mismatch')
        return matches[0]
    finally:
        api.CloseHandle(snapshot)


def private_output(output_dir):
    folder, private = Path(output_dir).resolve(), CACHE_ROOT.resolve()
    if folder.parent != private or folder.name in ('', '.', '..') or folder.exists():
        raise ValueError('Output must be a new single private code-cache child directory')
    return folder


def region_slice(api, handle, base, rva, remaining):
    """No read; return bounded safe interval or bounded unavailable interval."""
    address, info = base+rva, Memory()
    next_page = PAGE_BYTES-(rva % PAGE_BYTES)
    missing = min(remaining, next_page)
    if api.VirtualQueryEx(handle, address, C.byref(info), C.sizeof(info)) != C.sizeof(info):
        return missing, 'query_unavailable'
    start, region_size = info.BaseAddress or 0, info.RegionSize
    if start > address or region_size <= 0 or not start <= address < start+region_size:
        return missing, 'invalid_region_boundary'
    length = min(remaining, CHUNK_BYTES, start+region_size-address)
    # Windows VirtualQuery intervals have page-aligned bounds; no arbitrary
    # byte-split loop that could create unbounded reads is permitted.
    if start % PAGE_BYTES or region_size % PAGE_BYTES or length <= 0:
        return missing, 'invalid_region_alignment'
    if (info.State != 0x1000 or info.Type != 0x1000000 or info.AllocationBase != base or
            info.Protect & 0x100 or info.Protect & ~0x7ff or
            info.Protect & 0xff not in (0x10, 0x20, 0x40, 0x80)):
        return length, 'page_not_committed_executable_image'
    return length, None


def snapshot_sections(api, handle, base, plan, folder, identity_check):
    rows, read_count, requested, saved = [], 0, 0, 0
    known = [bytearray(length) for _, _, length, _ in KNOWN_SENDERS]
    known_seen = [bytearray(length) for _, _, length, _ in KNOWN_SENDERS]
    for section in plan['sections']:
        first, length = int(section['rva'], 16), section['file_backed_code_bytes']
        end, cursor, blocks = first+length, first, []
        while cursor < end:
            identity_check()
            amount, reason = region_slice(api, handle, base, cursor, end-cursor)
            row = {'rva': hex(cursor), 'bytes': amount, 'available': False}
            if reason is None:
                if (read_count >= plan['maximum_region_split_RPM_count'] or
                        requested+amount > plan['maximum_code_bytes'] or not 0 < amount <= CHUNK_BYTES):
                    raise RuntimeError('Code snapshot read/byte budget exceeded')
                buffer, copied = (C.c_ubyte*amount)(), C.c_size_t()
                read_count += 1
                requested += amount
                ok = api.ReadProcessMemory(handle, base+cursor, buffer, amount, C.byref(copied))
                identity_check()
                if not ok or copied.value != amount:
                    reason = 'read_failed_or_incomplete'
                else:
                    code = bytes(buffer)
                    filename = f'section_{section["index"]:02d}_rva_{cursor:08x}.code'
                    (folder/filename).write_bytes(code)
                    row.update(available=True, code_sha256=sha(code), file=filename)
                    saved += amount
                    for index, (_, target, target_bytes, _) in enumerate(KNOWN_SENDERS):
                        low, high = max(cursor, target), min(cursor+amount, target+target_bytes)
                        if low < high:
                            known[index][low-target:high-target] = code[low-cursor:high-cursor]
                            known_seen[index][low-target:high-target] = b'\1'*(high-low)
            else:
                identity_check()
            if reason is not None:
                row['unavailable_reason'] = reason
            blocks.append(row)
            cursor += amount
        rows.append({'index': section['index'], 'rva': section['rva'], 'bytes': length, 'blocks': blocks,
            'available_bytes': sum(r['bytes'] for r in blocks if r['available']),
            'unavailable_bytes': sum(r['bytes'] for r in blocks if not r['available'])})
    comparisons = []
    for index, (label, rva, length, expected) in enumerate(KNOWN_SENDERS):
        complete = all(known_seen[index])
        actual = sha(known[index]) if complete else None
        comparisons.append({'name': label, 'rva': hex(rva), 'bytes': length,
            'available': complete, 'expected_code_sha256': expected, 'cache_code_sha256': actual,
            'matches_saved_native_sample': complete and actual == expected,
            'extra_live_reads': 0})
    return {'sections': rows, 'actual_RPM_count': read_count, 'RPM_requested_bytes': requested,
        'saved_code_bytes': saved, 'unavailable_bytes': plan['maximum_code_bytes']-saved,
        'known_sender_comparisons': comparisons}


def collect(game_root, output_dir, expected_pid, expected_create_time):
    if (type(expected_pid) is not int or expected_pid <= 0 or
            isinstance(expected_create_time, bool) or not isinstance(expected_create_time, (int, float)) or
            not math.isfinite(expected_create_time) or expected_create_time <= 0):
        raise ValueError('Exact positive PID/create time required')
    if normalized(game_root) != normalized(SHADOW_ROOT):
        raise ValueError('Live snapshot is restricted to fixed shadow game root')
    folder = private_output(output_dir)
    plan = validate_plan(game_root)
    executable = Path(game_root)/EXECUTABLE_RELATIVE
    if verified_pids(executable) != [expected_pid]:
        raise RuntimeError('Pinned shadow executable process is not unique')
    api = kernel()
    handle = api.OpenProcess(0x1010, False, expected_pid)
    if not handle:
        raise RuntimeError('Ordinary process read permission unavailable')
    report = {'kind': 'private_file_backed_executable_code_cache', 'client_sha256': SOURCE_SHA,
        'pid': expected_pid, 'process_create_time': expected_create_time, 'plan': plan,
        'complete': False, 'status': 'initializing', 'sections': [],
        'client_launched': False, 'elevation_requested': False, 'process_memory_written': False,
        'live_data_object_read': False, 'original_game_modified': False,
        'reconstructed_executable': False, 'native_complete_decode_claimed': False,
        'snapshot_is_atomic': False, 'observed_at_utc': datetime.now(timezone.utc).isoformat()}
    try:
        check = lambda: process_identity(api, handle, expected_pid, executable, expected_create_time)
        check()
        base, size = verified_module(api, expected_pid, executable)
        if size != IMAGE_SIZE or validate_plan(game_root) != plan:
            raise RuntimeError('Pinned disk plan or executable module changed')
        check()
        folder.mkdir(parents=True, exist_ok=False)
        save_json(folder/'manifest.json', report)
        report.update(snapshot_sections(api, handle, base, plan, folder, check))
        check()
        if verified_module(api, expected_pid, executable) != (base, size):
            raise RuntimeError('Pinned executable module changed after snapshot')
        if validate_plan(game_root) != plan:
            raise RuntimeError('Pinned source executable changed after snapshot')
        check()
        coverage = report['saved_code_bytes'] == TOTAL_BYTES and report['unavailable_bytes'] == 0
        anchors = all(r['matches_saved_native_sample'] for r in report['known_sender_comparisons'])
        report.update(complete=coverage and anchors, scope_coverage_complete=coverage,
            status='code_cache_complete' if coverage and anchors else
                   'code_cache_known_sender_mismatch' if coverage else 'code_cache_partial')
    except Exception as error:
        report.update(status='code_cache_failed', complete=False, error_type=type(error).__name__)
        # Do not serialize arbitrary OS exception strings or addresses.
        if isinstance(error, (RuntimeError, ValueError)):
            report['error_reason'] = str(error)
        if not folder.exists():
            raise
    finally:
        api.CloseHandle(handle)
    save_json(folder/'manifest.json', report)
    return report


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--validate-plan', action='store_true')
    mode.add_argument('--collect', action='store_true')
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--expected-pid', type=int)
    parser.add_argument('--expected-create-time', type=float)
    return parser


if __name__ == '__main__':
    parser = argument_parser()
    args = parser.parse_args()
    if args.collect:
        if any(v is None for v in (args.output_dir, args.expected_pid, args.expected_create_time)):
            parser.error('--collect requires output directory and exact PID/create time')
        result = collect(args.game_root, args.output_dir, args.expected_pid, args.expected_create_time)
        print(result['status'])
        raise SystemExit(0 if result['complete'] else 1)
    if any(v is not None for v in (args.output_dir, args.expected_pid, args.expected_create_time)):
        parser.error('Live options require explicit --collect')
    plan = validate_plan(args.game_root)
    print('Offline private code plan validated: 2 sections,349562443 bytes,335 fixed 1MiB chunks. No process access.')
