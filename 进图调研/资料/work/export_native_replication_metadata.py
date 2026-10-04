"""Export existing replication metadata from one verified client process.

Only the source-pinned object registry, class/name metadata, existing driver
tables and one fixed diagnostic CVar scalar are read. This does not call a native getter, create layouts, read player
property values, inject code, modify memory or launch a game.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import struct
import subprocess
import sys
import time


def initialize_worker_diagnostics():
    """Capture failures before optional imports or argument validation run."""
    if '--elevated-source-pins' not in sys.argv or '--output' not in sys.argv:
        return
    index = sys.argv.index('--output')
    if index + 1 >= len(sys.argv):
        return
    folder = Path(sys.argv[index + 1]).resolve()
    work = Path(__file__).resolve().parent.parent / 'work'
    if not folder.is_relative_to(work.resolve()):
        return
    folder.mkdir(parents=True, exist_ok=True)
    log = (folder / 'worker-console.log').open('a', encoding='utf-8', buffering=1)
    sys.stdout = sys.stderr = log
    import faulthandler
    faulthandler.enable(file=log)
    (folder / 'worker-startup.json').write_text(json.dumps({
        'status': 'python_worker_started_before_reader_imports',
        'pid': os.getpid(), 'python': sys.executable, 'python_version': sys.version,
        'process_memory_read': False, 'game_launched': False,
    }, indent=2) + '\n', encoding='utf-8')


initialize_worker_diagnostics()

import psutil

from native_metadata_names import object_name, resolve_name, SHIPPING_SHA256
from native_metadata_objects import iter_object_records, validate_object_record
from native_metadata_paths import object_path
from native_replication_metadata_core import (
    MetadataSession, MAX_SINGLE_READ, span, export_existing_driver_class,
)

ROOT = Path(__file__).resolve().parent.parent
EXECUTABLE_RELATIVE = Path('DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
TARGET_CLASSES = frozenset(('BP_DFMPlayerController_C', 'BP_DFMCharacter_C', 'BP_GameState_PVPVE_C'))
MAX_CLASS_DEPTH = 32
MAX_CLASS_DESCRIPTORS = 32768
MAX_SELECTED_CLASSES = 32
MAX_DRIVERS = 16
MAX_DURATION_SECONDS = 120
# Scheduling policy only, not a native timing contract or a deadline extension.
LOADING_RESCAN_COST_FACTOR = 1.25
LOADING_RESCAN_EXPORT_RESERVE_SECONDS = 5.0
SHIPPING_IMAGE_SIZE = 536408064  # SizeOfImage in the SHA-pinned PE32+ build.
ACTOR_CHANNEL_OPEN_SLOT = 0x3d8
PROPERTY_SERIALIZER_SLOT = 0x90
PROPERTY_SCALAR_LEAF_SLOT = 0x88
GENERIC_NUMERIC_SERIALIZER_RVA = 0x10e5ce20
DYNAMIC_ADDRESS_SWITCH_CVAR_RVA = 0x1cba32f0
DYNAMIC_ADDRESS_SWITCH_CVAR_SOURCE_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'


def observe_dynamic_address_switch_cvar(session, module_base, *, source_sha256):
    """Observe only the source-qualified int32 reference; never follow a pointer.

    Registration321476 and Tick2f9d7b6/2f9dca2 prove this direct four-byte value;
    see work/evidence/native-dynamic-address-switch-cvar.json. The supplied
    session retains its existing read budget and backend deadline. A refused
    optional observation does not accept partial metadata or break its export.
    """
    observation = {'rva': hex(DYNAMIC_ADDRESS_SWITCH_CVAR_RVA),
                   'value': None, 'status': 'not_attempted'}
    if source_sha256 != DYNAMIC_ADDRESS_SWITCH_CVAR_SOURCE_SHA256:
        observation['status'] = 'unqualified_source'
        return observation
    try:
        span(module_base, SHIPPING_IMAGE_SIZE)
        if not 0 <= DYNAMIC_ADDRESS_SWITCH_CVAR_RVA <= SHIPPING_IMAGE_SIZE - 4:
            raise ValueError('Diagnostic CVar is outside the source-pinned image')
        raw = session.stable(module_base + DYNAMIC_ADDRESS_SWITCH_CVAR_RVA, 4)
        observation.update(value=struct.unpack('<i', raw)[0], status='observed_stable_int32')
    except ValueError:
        observation['status'] = 'read_refused'
    except Exception:
        observation['status'] = 'read_failed'
    return observation


def observed_virtual_method(session, module_base, object_address, slot):
    """Observe one source-selected slot; never invoke it or classify its body.

    Only a vtable inside the pinned image is followed. Target module identity
    means its address is inside that same image, not native acceptance or an
    executable-page check. A missing or foreign table remains explicit metadata.
    """
    if slot not in (ACTOR_CHANNEL_OPEN_SLOT, PROPERTY_SERIALIZER_SLOT, PROPERTY_SCALAR_LEAF_SLOT):
        raise ValueError('Only source-selected metadata method slots are supported')
    vtable = session.pointer(object_address)
    row = {'slot': slot, 'vtable_address': vtable, 'vtable_rva': None, 'target_address': None,
           'target_rva': None, 'target_module_sha256': None,
           'inside_pinned_image': False, 'identity_rechecked': False}
    if not vtable:
        row['status'] = 'missing_vtable'
    elif not module_base <= vtable <= module_base + SHIPPING_IMAGE_SIZE - slot - 8:
        row['status'] = 'vtable_outside_pinned_image'
    else:
        row['vtable_rva'] = vtable - module_base
        target = session.pointer(vtable + slot)
        row['target_address'] = target
        if not target:
            row['status'] = 'null_method'
        elif not module_base <= target < module_base + SHIPPING_IMAGE_SIZE:
            row['status'] = 'target_outside_pinned_image'
        else:
            row.update(target_rva=target - module_base,
                       target_module_sha256=SHIPPING_SHA256,
                       inside_pinned_image=True, status='observed_pinned_image_method')
    return row


def recheck_virtual_method(session, module_base, object_address, method):
    expected = {**method, 'identity_rechecked': False}
    if observed_virtual_method(session, module_base, object_address, method['slot']) != expected:
        raise ValueError('Selected metadata virtual method binding changed')
    method['identity_rechecked'] = True


def source_pins(*, actor_interface_only=False):
    dependencies = (
        'work/export_native_replication_metadata.py', 'work/native_metadata_objects.py',
        'work/native_metadata_names.py', 'work/native_metadata_paths.py',
        'work/native_replication_metadata_core.py',
        'outputs/df-local-server/dfserver/legacy_ds_class_net_cache.py')
    if actor_interface_only:
        dependencies += ('work/native_actor_interface_metadata.py',)
    return {relative: digest(ROOT / relative) for relative in dependencies}


def request_read_only_elevation(args):
    """Normal UAC for this same bounded reader; do not launch another client."""
    executable, _ = validate_source(args.game_root)
    process = psutil.Process(args.pid)
    if (process.create_time() != args.created_at or
            _path_identity(process.exe()) != _path_identity(executable)):
        raise ValueError('Requested client identity changed before normal UAC')
    if not args.output.resolve().is_relative_to((ROOT / 'work').resolve()):
        raise ValueError('Elevated reader output must be inside the project work directory')
    interface_only = getattr(args, 'actor_interface_only', False)
    pins = source_pins(actor_interface_only=interface_only)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'launch-request.json').write_text(json.dumps({
        'requested_at_utc': datetime.now(timezone.utc).isoformat(),
        'pid': args.pid, 'created_at': args.created_at,
        'observation_mode': 'pawn_interface_only' if interface_only else 'replication_metadata',
        'source_pins': pins,
    }, indent=2) + '\n', encoding='utf-8')

    class ShellInfo(C.Structure):
        _fields_ = [('cbSize', W.DWORD), ('fMask', W.ULONG), ('hwnd', W.HWND), ('lpVerb', W.LPCWSTR),
            ('lpFile', W.LPCWSTR), ('lpParameters', W.LPCWSTR), ('lpDirectory', W.LPCWSTR), ('nShow', C.c_int),
            ('hInstApp', W.HINSTANCE), ('lpIDList', C.c_void_p), ('lpClass', W.LPCWSTR), ('hkeyClass', W.HKEY),
            ('dwHotKey', W.DWORD), ('hIcon', W.HANDLE), ('hProcess', W.HANDLE)]

    # Resolve cleanup APIs before creating a helper handle.
    api = kernel()
    shell = C.WinDLL('shell32', use_last_error=True).ShellExecuteExW
    shell.argtypes, shell.restype = [C.POINTER(ShellInfo)], W.BOOL
    info = ShellInfo()
    info.cbSize, info.fMask, info.lpVerb = C.sizeof(info), 0x140, 'runas'
    info.lpFile, info.lpDirectory, info.nShow = sys.executable, str(ROOT), 0
    parameters = [str(Path(__file__).resolve()), '--game-root', str(args.game_root.resolve()),
        '--output', str(args.output.resolve()), '--pid', str(args.pid), '--created-at', str(args.created_at),
        '--elevated-source-pins', json.dumps(pins, separators=(',', ':'))]
    if interface_only:
        parameters.append('--actor-interface-only')
    info.lpParameters = subprocess.list2cmdline(parameters)
    print('Requesting normal Windows UAC for the existing client metadata reader only.', flush=True)
    if not shell(C.byref(info)):
        code = C.get_last_error()
        save(args.output, {'status': 'metadata_reader_uac_not_granted', 'windows_error': code,
                          'process_memory_written': False, 'game_launched': False,
                          'playable_map_verified': False})
        raise OSError(code, 'Normal Windows authorization was not granted')
    try:
        if not info.hProcess:
            raise OSError('Windows accepted the request but returned no helper identity handle')
        helper_pid = api.GetProcessId(info.hProcess)
        if not helper_pid:
            raise OSError(C.get_last_error(), 'Windows helper identity could not be confirmed')
        print(json.dumps({'status': 'metadata_reader_authorized',
                          'helper_pid': helper_pid, 'game_launched': False}), flush=True)
        outcome = monitor_reader_exit(api, info.hProcess, args.output, helper_pid)
        if (outcome['status'] != 'metadata_reader_exited' or outcome['exit_code'] != 0 or
                outcome.get('reader_result_status') != 'metadata_export_complete'):
            raise RuntimeError('Metadata reader did not complete; see helper-exit.json and worker-console.log')
    finally:
        if info.hProcess:
            api.CloseHandle(info.hProcess)


def monitor_reader_exit(api, handle, folder, helper_pid):
    """Keep the launch job alive and persist the actual Windows helper exit."""
    started = time.monotonic()
    deadline = started + MAX_DURATION_SECONDS + 60
    while True:
        wait = api.WaitForSingleObject(handle, 1000)
        if wait == 0:
            code = W.DWORD()
            if not api.GetExitCodeProcess(handle, C.byref(code)):
                raise OSError(C.get_last_error(), 'Cannot query metadata reader exit code')
            result = {'status': 'metadata_reader_exited', 'helper_pid': helper_pid,
                      'exit_code': code.value, 'exit_code_hex': hex(code.value)}
            break
        if wait != 0x102:
            raise OSError(C.get_last_error(), 'Cannot wait for metadata reader')
        if time.monotonic() >= deadline:
            result = {'status': 'metadata_reader_still_running_after_deadline',
                      'helper_pid': helper_pid, 'exit_code': None}
            break
    reader_status = None
    try:
        value = json.loads((Path(folder) / 'result.json').read_text(encoding='utf-8'))
        reader_status = value.get('status') if type(value) is dict else 'invalid_result'
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        reader_status = 'unreadable_result'
    result.update(elapsed_seconds=round(time.monotonic() - started, 3),
                  result_file_exists=(Path(folder) / 'result.json').is_file(),
                  reader_result_status=reader_status,
                  game_launched=False)
    (Path(folder) / 'helper-exit.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result), flush=True)
    return result


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate_source(game_root):
    executable = (Path(game_root).resolve() / EXECUTABLE_RELATIVE).resolve()
    if digest(executable) != SHIPPING_SHA256:
        raise ValueError('Client version hash does not match the metadata sources')
    # Read only PE headers for the loaded image size, not a second whole image.
    with executable.open('rb') as stream:
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b'MZ':
            raise ValueError('Pinned executable has no DOS header')
        pe_offset = struct.unpack_from('<I', dos, 0x3c)[0]
        if not 64 <= pe_offset <= 1024 * 1024:
            raise ValueError('Pinned executable has an invalid PE header offset')
        stream.seek(pe_offset)
        header = stream.read(24 + 64)
    if (len(header) != 88 or header[:4] != b'PE\0\0' or
            struct.unpack_from('<H', header, 4)[0] != 0x8664 or
            struct.unpack_from('<H', header, 24)[0] != 0x20b):
        raise ValueError('Metadata reader requires the pinned PE32+ x64 image')
    image_size = struct.unpack_from('<I', header, 24 + 56)[0]
    if image_size != SHIPPING_IMAGE_SIZE:
        raise ValueError('Pinned PE module size differs from the source-selected metadata image')
    return executable, image_size


def _path_identity(path):
    return os.path.normcase(str(Path(path).resolve()))


class Module(C.Structure):
    _fields_ = [('dwSize', W.DWORD), ('th32ModuleID', W.DWORD), ('th32ProcessID', W.DWORD),
                ('GlblcntUsage', W.DWORD), ('ProccntUsage', W.DWORD), ('modBaseAddr', C.c_void_p),
                ('modBaseSize', W.DWORD), ('hModule', W.HMODULE), ('szModule', W.WCHAR * 256),
                ('szExePath', W.WCHAR * 260)]


class Memory(C.Structure):
    _fields_ = [('BaseAddress', C.c_void_p), ('AllocationBase', C.c_void_p),
                ('AllocationProtect', W.DWORD), ('PartitionId', W.WORD), ('RegionSize', C.c_size_t),
                ('State', W.DWORD), ('Protect', W.DWORD), ('Type', W.DWORD)]


def kernel():
    api = C.WinDLL('kernel32', use_last_error=True)
    definitions = {
        'OpenProcess': ([W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
        'CloseHandle': ([W.HANDLE], W.BOOL),
        'CreateToolhelp32Snapshot': ([W.DWORD, W.DWORD], W.HANDLE),
        'Module32FirstW': ([W.HANDLE, C.POINTER(Module)], W.BOOL),
        'Module32NextW': ([W.HANDLE, C.POINTER(Module)], W.BOOL),
        'VirtualQueryEx': ([W.HANDLE, C.c_void_p, C.POINTER(Memory), C.c_size_t], C.c_size_t),
        'ReadProcessMemory': ([W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)], W.BOOL),
        'WaitForSingleObject': ([W.HANDLE, W.DWORD], W.DWORD),
        'GetProcessId': ([W.HANDLE], W.DWORD),
        'GetExitCodeProcess': ([W.HANDLE, C.POINTER(W.DWORD)], W.BOOL),
    }
    for name, (arguments, result) in definitions.items():
        function = getattr(api, name)
        function.argtypes, function.restype = arguments, result
    return api


def readable_region(memory, address, size):
    """Admit committed readable data only; guard/no-access pages stop the read."""
    span(address, size)
    base, region_size = memory.BaseAddress, memory.RegionSize
    if (not base or region_size <= 0 or memory.State != 0x1000 or
            memory.Type not in (0x20000, 0x40000, 0x1000000) or
            memory.Protect & (0x100 | 0x01) or
            memory.Protect & 0xff not in (0x02, 0x04, 0x08, 0x20, 0x40, 0x80) or
            not base <= address < base + region_size):
        raise ValueError('Metadata root reaches an unreadable or uncommitted page')
    return min(size, base + region_size - address)


class Win32MetadataReader:
    """One read-only handle tied to the exact PID, creation time and executable."""
    def __init__(self, executable, image_size, pid, created_at):
        if (type(pid) is not int or pid <= 0 or type(created_at) not in (int, float) or
                not math.isfinite(created_at) or created_at <= 0):
            raise ValueError('An exact PID and finite creation time are required')
        self.executable, self.image_size = Path(executable).resolve(), image_size
        self.pid, self.created_at = pid, float(created_at)
        self.api, self.handle, self.module_base = kernel(), None, None
        self.deadline = time.monotonic() + MAX_DURATION_SECONDS
        self.verify_identity()
        # VirtualQueryEx requires QUERY_INFORMATION; the retained handle also
        # requires SYNCHRONIZE for exit checks. No process write rights requested.
        self.handle = self.api.OpenProcess(0x100410, False, pid)  # SYNCHRONIZE | QUERY_INFORMATION | VM_READ
        if not self.handle:
            raise OSError(C.get_last_error(), 'Read-only client process access was denied')
        try:
            if self.api.GetProcessId(self.handle) != pid:
                raise ValueError('Opened process handle does not match the requested PID')
            self.module_base = self.find_module()
            span(self.module_base, image_size)
            self.verify_identity()
        except Exception:
            self.close()
            raise

    def verify_identity(self):
        process = psutil.Process(self.pid)
        if (process.create_time() != self.created_at or
                _path_identity(process.exe()) != _path_identity(self.executable)):
            raise ValueError('Client process identity changed')
        if self.handle and self.api.WaitForSingleObject(self.handle, 0) != 0x102:
            raise ValueError('The verified client process has exited')

    def find_module(self):
        snapshot = self.api.CreateToolhelp32Snapshot(0x18, self.pid)
        if not snapshot or snapshot == C.c_void_p(-1).value:
            raise OSError(C.get_last_error(), 'Client module snapshot failed')
        try:
            entry = Module()
            entry.dwSize = C.sizeof(entry)
            matched = []
            available = self.api.Module32FirstW(snapshot, C.byref(entry))
            while available:
                if _path_identity(entry.szExePath) == _path_identity(self.executable):
                    if entry.modBaseSize != self.image_size:
                        raise ValueError('Loaded client module size differs from its pinned PE')
                    matched.append(entry.modBaseAddr)
                available = self.api.Module32NextW(snapshot, C.byref(entry))
            if len(matched) != 1:
                raise ValueError('Exactly one matching client image module is required')
            return matched[0]
        finally:
            self.api.CloseHandle(snapshot)

    def read_exact(self, address, size):
        span(address, size)
        if size > MAX_SINGLE_READ:
            raise ValueError('Metadata backend accepts only small bounded reads')
        if time.monotonic() > self.deadline:
            raise ValueError('Metadata collection time budget exhausted')
        # The retained handle cannot silently switch to a later reuse of the PID.
        if self.api.WaitForSingleObject(self.handle, 0) != 0x102:
            raise ValueError('Verified client exited during metadata collection')
        parts, remaining, at = [], size, address
        while remaining:
            memory = Memory()
            if self.api.VirtualQueryEx(self.handle, C.c_void_p(at), C.byref(memory), C.sizeof(memory)) != C.sizeof(memory):
                raise OSError(C.get_last_error(), 'Metadata page query failed')
            length = readable_region(memory, at, remaining)
            buffer, received = (C.c_ubyte * length)(), C.c_size_t()
            if (not self.api.ReadProcessMemory(self.handle, C.c_void_p(at), buffer, length, C.byref(received)) or
                    received.value != length):
                raise OSError(C.get_last_error(), 'Metadata read did not return the requested bytes')
            parts.append(bytes(buffer))
            remaining -= length
            at += length
        return b''.join(parts)

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


def discover_roots(session, module_base, *, _state=None, start_index=0, stop_index=None):
    """Discover named classes, matching template metadata and NetDriver instances.

    Registry identity and Class ancestry bind every admitted root. Other object
    payloads are not read. Own names are read only for class descriptors and objects
    of a target class whose Outer is that class or its observed package Outer.
    Results are discarded
    when the registry iterator observes changes; a partial scan is not a root proof.
    """
    if _state is not None and type(_state) is not dict:
        raise ValueError('Discovery continuation state must be a private dictionary')
    continuing = bool(_state)
    if not continuing and (start_index != 0 or stop_index is not None):
        raise ValueError('An explicit discovery tail requires checked first-pass state')
    if continuing:
        if _state.get('session') is not session or _state.get('module_base') != module_base:
            raise ValueError('Discovery continuation must retain the same session and module')
        if start_index != _state['stop_index'] or stop_index is None:
            raise ValueError('Discovery continuation must be a contiguous frozen tail')
        descriptors = _state['descriptors']
        descriptor_tokens = _state['descriptor_tokens']
        descriptors_seen = _state['descriptors_seen']
        selected, drivers = _state['selected'], _state['drivers']
        archetypes, archetype_tokens = _state['archetypes'], _state['archetype_tokens']
        class_outers = _state['class_outers']
        records_scanned = _state['records_scanned']
    else:
        descriptors, descriptor_tokens, selected, drivers, records_scanned = {}, {}, {}, [], 0
        descriptors_seen = set()
        archetypes, archetype_tokens, class_outers = {}, {}, {}

    def record_identity(address):
        record = validate_object_record(session.read, module_base, address)
        return {'object_index': record.index, 'serial': record.serial,
                'key': struct.pack('<iI', record.index, record.serial).hex() if record.serial else None}

    def check_identity(candidate):
        identity = record_identity(candidate['address'])
        # A zero serial has no native weak identity. Native weak-key creation can
        # initialize it while loading without changing the registry slot. Bind
        # the final initialized record; the following Class/name/parent/Outer
        # checks still have to prove the same metadata semantics. Never refresh
        # an already-initialized serial or an object whose index changed.
        if (identity['object_index'] == candidate['object_index'] and
                candidate['serial'] == 0 and identity['serial'] > 0):
            candidate.update(identity)
            candidate['native_serial_initialized_during_scan'] = True
            candidate['native_serial_continuity_proved'] = False
            return
        if any(identity[field] != candidate[field] for field in ('object_index', 'serial', 'key')):
            error = ValueError('Selected metadata root identity changed after discovery')
            error.metadata_failure_context = {
                'phase': 'selected_root_identity_recheck',
                'address': candidate['address'],
                'expected_object_index': candidate['object_index'],
                'observed_object_index': identity['object_index'],
                'expected_serial': candidate['serial'],
                'observed_serial': identity['serial'],
            }
            raise error

    def class_descriptor(address):
        if address not in descriptors:
            if address not in descriptors_seen and len(descriptors_seen) >= MAX_CLASS_DESCRIPTORS:
                raise ValueError('Class descriptor discovery exceeds local bound')
            identity = record_identity(address)
            token = session.stable(address + 0x1c, 8)
            name = resolve_name(session.read, module_base, token)
            parent = session.pointer(address + 0x48)
            if session.read(address + 0x1c, 8) != token:
                raise ValueError('Class descriptor name changed during discovery')
            descriptors[address] = {'address': address, 'name': name.display_text,
                                    **identity, 'parent_address': parent}
            descriptor_tokens[address] = token
            descriptors_seen.add(address)
        return descriptors[address]

    def ancestry(address):
        chain, seen = [], set()
        while address:
            if address in seen or len(chain) >= MAX_CLASS_DEPTH:
                raise ValueError('Class ancestry is cyclic or exceeds local bound')
            seen.add(address)
            descriptor = class_descriptor(address)
            chain.append(descriptor)
            address = descriptor['parent_address']
        return chain

    def recheck_admitted():
        # Required first-pass roots are never trusted merely because their old
        # registry range is skipped. The same proof runs before and after a tail.
        for candidate in list(selected.values()) + drivers:
            check_identity(candidate)
            bound_class = candidate.get('metaclass_address', candidate.get('class_address'))
            if session.pointer(candidate['address'] + 8) != bound_class:
                raise ValueError('Selected object class binding changed after discovery')
            if ('asset_path' in candidate and
                    object_path(session.read, module_base, candidate['address']) != candidate['asset_path']):
                raise ValueError('Selected class metadata path changed after discovery')
        required_descriptors = set()
        seeds = [item['metaclass_address'] for item in selected.values()]
        seeds += [item['class_address'] for item in drivers]
        seeds += [item['address'] for item in selected.values()]
        for address in seeds:
            while address and address not in required_descriptors:
                required_descriptors.add(address)
                address = descriptors[address]['parent_address']
        for address in sorted(required_descriptors):
            descriptor = descriptors[address]
            check_identity(descriptor)
            if (session.read(address + 0x1c, 8) != descriptor_tokens[address] or
                    session.pointer(address + 0x48) != descriptor['parent_address']):
                raise ValueError('Class descriptor changed during the complete registry scan')
        for candidate in archetypes.values():
            check_identity(candidate)
            if candidate['class_address'] not in selected:
                raise ValueError('Named template candidate is not bound to a selected UClass')
            if (session.pointer(candidate['address'] + 8) != candidate['class_address'] or
                    session.pointer(candidate['address'] + 0x10) != candidate['outer_address'] or
                    session.read(candidate['address'] + 0x1c, 8) != archetype_tokens[candidate['address']] or
                    session.pointer(candidate['class_address'] + 0x10) != candidate['class_outer_address']):
                raise ValueError('Named template candidate binding changed during discovery')
            if object_path(session.read, module_base, candidate['address']) != candidate['asset_path']:
                raise ValueError('Named template candidate path changed during discovery')
            if (object_path(session.read, module_base, candidate['outer_address']) != candidate['outer_path'] or
                    object_path(session.read, module_base, candidate['class_outer_address']) != candidate['class_outer_path']):
                raise ValueError('Named template candidate Outer path changed during discovery')
            if 'actor_channel_open_hook' in candidate:
                recheck_virtual_method(session, module_base, candidate['address'], candidate['actor_channel_open_hook'])
        for candidate in selected.values():
            candidate['class_ancestry'] = [{**descriptors[item['address']]}
                                          for item in candidate['class_ancestry']]
        return required_descriptors

    if continuing:
        required = recheck_admitted()
        # Transient, unrelated old descriptors may have recycled. Drop them,
        # rather than using cached classification for any newly appended object.
        for address in set(descriptors) - required:
            del descriptors[address]
            del descriptor_tokens[address]
    pass_records_scanned = 0
    scan_metadata = {}
    range_options = {'start_index': start_index, 'stop_index': stop_index} if continuing else {}
    for record in iter_object_records(session.read, module_base, scan_metadata=scan_metadata, **range_options):
        records_scanned += 1
        pass_records_scanned += 1
        klass = session.pointer(record.object_address + 8)
        chain = ancestry(klass)
        chain_names = {item['name'] for item in chain}
        if 'Class' in chain_names:
            # Only class-descriptor objects may have their own names read.
            candidate = class_descriptor(record.object_address)
            if candidate['name'] in TARGET_CLASSES:
                if len(selected) >= MAX_SELECTED_CLASSES and record.object_address not in selected:
                    raise ValueError('Target class descriptor count exceeds local bound')
                selected[record.object_address] = {**candidate,
                    'asset_path': object_path(session.read, module_base, record.object_address),
                    'metaclass_address': klass,
                    'metaclass_chain': [item['name'] for item in chain],
                    'class_ancestry': [{**item} for item in ancestry(record.object_address)]}
        if 'NetDriver' in chain_names:
            if len(drivers) >= MAX_DRIVERS:
                raise ValueError('NetDriver instance count exceeds local bound')
            identity = record_identity(record.object_address)
            drivers.append({'address': record.object_address, **identity,
                            'class_address': klass, 'class_chain': [item['name'] for item in chain]})
        if chain and chain[0]['name'] in TARGET_CLASSES:
            # SerializeNewActor references a template object, not its UClass.
            # Observe a named candidate without guessing the UClass CDO offset,
            # allocating a native default object or reading player properties.
            class_outer = session.pointer(klass + 0x10)
            if klass in class_outers and class_outers[klass] != class_outer:
                raise ValueError('Target class Outer changed between template candidates')
            outer = session.pointer(record.object_address + 0x10)
            if outer == klass or (class_outer and outer == class_outer):
                token = session.stable(record.object_address + 0x1c, 8)
                name = resolve_name(session.read, module_base, token).display_text
                if name == 'Default__' + chain[0]['name']:
                    if len(archetypes) >= MAX_SELECTED_CLASSES:
                        raise ValueError('Named template candidate count exceeds local bound')
                    archetypes[record.object_address] = {
                        'address': record.object_address, **record_identity(record.object_address),
                        'name': name, 'class_address': klass, 'class_name': chain[0]['name'],
                        'outer_address': outer, 'class_outer_address': class_outer,
                        'outer_path': object_path(session.read, module_base, outer),
                        'class_outer_path': object_path(session.read, module_base, class_outer),
                        'outer_relation': 'class' if outer == klass else 'same_outer_as_class',
                        'asset_path': object_path(session.read, module_base, record.object_address),
                        'selection_kind': 'name_class_outer_metadata_candidate',
                        'class_default_object_flags_verified': False,
                        'package_map_resolution_verified': False,
                    }
                    archetype_tokens[record.object_address] = token
                    class_outers[klass] = class_outer
                    # Observe the actual derived slot for both admitted template
                    # roles. The Pawn hook may differ from the proven base PC
                    # implementation; observing it never qualifies a tail format.
                    if chain[0]['name'] in ('BP_DFMPlayerController_C', 'BP_DFMCharacter_C'):
                        archetypes[record.object_address]['actor_channel_open_hook'] = observed_virtual_method(
                            session, module_base, record.object_address, ACTOR_CHANNEL_OPEN_SLOT)
    recheck_admitted()
    if continuing:
        scan_metadata['combined_index_ranges'] = [[0, start_index], [start_index, stop_index]]
        scan_metadata['prior_selected_roots_rechecked'] = True
    if _state is not None:
        _state.update(session=session, module_base=module_base, descriptors=descriptors,
            descriptor_tokens=descriptor_tokens, descriptors_seen=descriptors_seen,
            selected=selected, drivers=drivers,
            archetypes=archetypes, archetype_tokens=archetype_tokens, class_outers=class_outers,
            records_scanned=records_scanned, stop_index=scan_metadata['initial_index_range'][1])
    return {'records_scanned': records_scanned, 'unique_class_descriptors_read': len(descriptors_seen),
            'pass_records_scanned': pass_records_scanned,
            'registry_scan': scan_metadata, 'complete_global_inventory': False,
            'selected_roots_rechecked': True,
            'classes': list(selected.values()), 'drivers': drivers,
            'named_template_candidates': list(archetypes.values()),
            'missing_named_templates': sorted({item['address'] for item in selected.values()} -
                {item['class_address'] for item in archetypes.values()}),
            'missing_target_classes': sorted(TARGET_CLASSES - {item['name'] for item in selected.values()})}


def discover_roots_with_loading_compensation(session, module_base, *,
                                           diagnostics=None, before_rescan=None,
                                           remaining_time=None):
    """At most one frozen tail after a completed, growing registry scan.

    Both passes use the caller's existing session/backend/deadline. Admitted
    first-pass identities, names and bindings are rechecked before and after
    the tail; unchecked JSON roots are never merged. A refused tail propagates
    its error rather than committing old roots.
    Before starting it, measured first-pass cost and count growth estimate the
    next cost with a policy margin and export reserve. Insufficient or unknown
    remaining time skips the unstarted pass and retains the checked first roots.
    The tail ends at the first pass's final observed count. Further growth is
    recorded but never chased, and old empty/recycled slots are not reinventoried.
    This neither promises an atomic inventory nor a complete global inventory.
    """
    if diagnostics is None:
        diagnostics = {}
    if type(diagnostics) is not dict or diagnostics:
        raise ValueError('Loading compensation diagnostics require an empty dictionary')
    if before_rescan is not None and not callable(before_rescan):
        raise ValueError('Loading compensation identity check must be callable')
    if remaining_time is not None and not callable(remaining_time):
        raise ValueError('Loading compensation remaining time must be callable')
    diagnostics.update(policy='one_frozen_registry_tail_with_admitted_root_rechecks', maximum_additional_scans=1,
                       additional_scan_attempted=False, selected_attempt=None, attempts=[])

    def completed_summary(roots, duration):
        scan = roots['registry_scan']
        return {'status': 'discovery_complete', 'duration_seconds': round(duration, 6),
                'registry_scan': {**scan, 'initial_index_range': list(scan['initial_index_range'])},
                'records_scanned': roots['records_scanned'],
                'pass_records_scanned': roots.get('pass_records_scanned', roots['records_scanned']),
                'selected_class_count': len(roots['classes']),
                'driver_count': len(roots['drivers']),
                'named_template_candidate_count': len(roots['named_template_candidates']),
                'missing_named_templates': list(roots['missing_named_templates']),
                'missing_target_classes': list(roots['missing_target_classes'])}

    def remaining_budget():
        value = remaining_time()
        if type(value) not in (int, float) or not math.isfinite(value):
            raise ValueError('Loading compensation remaining time must be finite seconds')
        return max(0.0, value)

    started = time.monotonic()
    continuation_state = {}
    roots = discover_roots(session, module_base, _state=continuation_state)
    first_duration = time.monotonic() - started
    diagnostics['attempts'].append(completed_summary(roots, first_duration))
    diagnostics['first_duration_seconds'] = round(first_duration, 6)
    scan = roots['registry_scan']
    if ((roots['missing_target_classes'] or roots['missing_named_templates']) and
            scan['final_observed_count'] > scan['initial_count']):
        tail_start, tail_stop = scan['initial_count'], scan['final_observed_count']
        diagnostics['frozen_tail_index_range'] = [tail_start, tail_stop]
        skip_reason = None
        if remaining_time is None:
            skip_reason = 'remaining_time_unavailable'
        elif scan['initial_count'] <= 0 or first_duration <= 0:
            skip_reason = 'additional_scan_cost_unestimated'
        else:
            ratio = (tail_stop - tail_start) / scan['initial_count']
            estimated_scan = first_duration * ratio * LOADING_RESCAN_COST_FACTOR
            required = estimated_scan + LOADING_RESCAN_EXPORT_RESERVE_SECONDS
            remaining = remaining_budget()
            diagnostics.update(estimation_count_ratio=ratio,
                estimation_cost_factor=LOADING_RESCAN_COST_FACTOR,
                export_reserve_seconds=LOADING_RESCAN_EXPORT_RESERVE_SECONDS,
                estimated_additional_scan_seconds=round(estimated_scan, 6),
                estimated_additional_required_seconds=round(required, 6),
                remaining_time_before_additional_scan_seconds=round(remaining, 6),
                estimate_is_deadline_guarantee=False)
            if required > remaining:
                skip_reason = 'insufficient_remaining_time_for_estimated_scan_and_export'
            else:
                # Revalidate the retained PID/create-time/path before a new pass.
                # Time consumed by that check does not reset the original clock.
                if before_rescan is not None:
                    before_rescan()
                remaining = remaining_budget()
                diagnostics['remaining_time_after_identity_check_seconds'] = round(remaining, 6)
                if required > remaining:
                    skip_reason = 'insufficient_remaining_time_after_identity_check'
        if skip_reason is not None:
            diagnostics['additional_scan_skip_reason'] = skip_reason
            diagnostics['selected_attempt'] = 0
        else:
            diagnostics['additional_scan_attempted'] = True
            started = time.monotonic()
            roots = discover_roots(session, module_base, _state=continuation_state,
                                   start_index=tail_start, stop_index=tail_stop)
            diagnostics['attempts'].append(completed_summary(roots, time.monotonic() - started))
            diagnostics['selected_attempt'] = 1
    else:
        diagnostics['selected_attempt'] = 0
    roots['loading_compensation'] = diagnostics
    return roots


def export_metadata(session, module_base, *, discovery_diagnostics=None,
                    before_loading_rescan=None, remaining_time=None):
    roots = discover_roots_with_loading_compensation(session, module_base,
        diagnostics=discovery_diagnostics, before_rescan=before_loading_rescan,
        remaining_time=remaining_time)
    exports = []
    for driver in roots['drivers']:
        for klass in roots['classes']:
            if klass['key'] is None:
                exports.append({'class_name': klass['name'], 'class_address': klass['address'],
                    'driver_address': driver['address'], 'class_key': None,
                    'class_key_status': 'missing_uninitialized_native_serial',
                    'cache_status': 'missing', 'layout_status': 'missing',
                    'native_getter_invoked': False, 'player_spawn_verified': False})
                continue
            result = export_existing_driver_class(session, driver['address'], bytes.fromhex(klass['key']))
            result['class_name'] = klass['name']
            result['class_address'] = klass['address']
            for node in result.get('cache_nodes', []):
                for field in node['fields']:
                    # These are descriptor labels, not a guessed property type or
                    # data value. A refused descriptor name stops this export.
                    field['descriptor_name'] = object_name(session.read, module_base,
                        field['descriptor_address'], field_representation=field['descriptor_representation']).display_text
            for parent in result.get('layout', {}).get('parents', []):
                parent['descriptor_name'] = object_name(session.read, module_base,
                    parent['descriptor_address'], field_representation=0).display_text
                parent['record_name'] = resolve_name(session.read, module_base,
                    bytes.fromhex(parent['name_token'])).display_text
            for command in result.get('layout', {}).get('commands', []):
                if command.get('dispatch_opcode') == 1:
                    if command['descriptor_address']:
                        raise ValueError('Native empty special record has a nonnull descriptor')
                    command['descriptor_name_status'] = 'native_empty_special_record'
                elif command['descriptor_address']:
                    command['descriptor_name'] = object_name(session.read, module_base,
                        command['descriptor_address'], field_representation=0).display_text
                    command['property_serializer_hook'] = observed_virtual_method(
                        session, module_base, command['descriptor_address'], PROPERTY_SERIALIZER_SLOT)
                    if command['property_serializer_hook']['target_rva'] == GENERIC_NUMERIC_SERIALIZER_RVA:
                        command['property_scalar_leaf_hook'] = observed_virtual_method(
                            session, module_base, command['descriptor_address'], PROPERTY_SCALAR_LEAF_SLOT)
                else:
                    command['descriptor_name_status'] = 'null_descriptor_unclassified_opcode'
            selected_class = validate_object_record(session.read, module_base, klass['address'])
            if (selected_class.index, selected_class.serial) != (klass['object_index'], klass['serial']):
                raise ValueError('Selected class key changed during driver table export')
            selected_driver = validate_object_record(session.read, module_base, driver['address'])
            if (selected_driver.index, selected_driver.serial) != (driver['object_index'], driver['serial']):
                raise ValueError('Selected NetDriver key changed during table export')
            if (session.pointer(klass['address'] + 8) != klass['metaclass_address'] or
                    session.pointer(driver['address'] + 8) != driver['class_address']):
                raise ValueError('Selected object class binding changed during table export')
            for command in result.get('layout', {}).get('commands', []):
                if 'property_serializer_hook' in command:
                    recheck_virtual_method(session, module_base, command['descriptor_address'],
                                           command['property_serializer_hook'])
                if 'property_scalar_leaf_hook' in command:
                    recheck_virtual_method(session, module_base, command['descriptor_address'],
                                           command['property_scalar_leaf_hook'])
            exports.append(result)
    return {'roots': roots, 'driver_class_exports': exports,
            'class_cache_exports': sum(item['cache_status'] == 'exported_existing' for item in exports),
            'replication_layout_exports': sum(item['layout_status'] == 'exported_existing' for item in exports)}


def export_actor_interface_metadata(session, module_base):
    """Observe the one qualified Pawn template interface, without driver tables.

    Registry discovery remains identity checked. This opt-in path does not read
    a player's properties or invoke an interface method. The implementation
    observer supplies its own source-qualified offsets and repeated bindings.
    """
    from native_actor_interface_metadata import observe_actor_interface

    roots = discover_roots(session, module_base)
    candidates = [row for row in roots['named_template_candidates']
                  if row['class_name'] == 'BP_DFMCharacter_C']
    if len(candidates) != 1:
        raise ValueError('Exactly one loaded Pawn template is required for the interface observation')
    candidate = candidates[0]
    classes = [row for row in roots['classes'] if row['address'] == candidate['class_address']]
    if len(classes) != 1:
        raise ValueError('Pawn template requires one identity-checked class root')
    observation = observe_actor_interface(session, module_base, candidate, classes[0])
    return {'roots': roots, 'actor_interface_observations': [observation],
            'driver_class_exports': [], 'class_cache_exports': 0, 'replication_layout_exports': 0,
            'driver_tables_read': False, 'player_property_values_read': False}


def save(folder, report):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'result.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def collect(game_root, folder, *, pid, created_at, actor_interface_only=False):
    report = {'kind': 'existing_native_replication_metadata_export', 'client_sha256': SHIPPING_SHA256,
              'client_relative_to_game_root': EXECUTABLE_RELATIVE.as_posix(),
              'observed_at_utc': datetime.now(timezone.utc).isoformat(),
              'requested_pid': pid, 'game_modified': False, 'process_memory_written': False,
              'native_getter_invoked': False, 'credential_memory_read': False,
              'player_property_values_read': False, 'snapshot_atomic': False,
              'player_spawn_verified': False, 'playable_map_verified': False,
              'dynamic_address_switch_cvar_observation': {
                  'rva': hex(DYNAMIC_ADDRESS_SWITCH_CVAR_RVA), 'value': None, 'status': 'not_attempted'},
              'status': 'preflight', 'maximum_duration_seconds': MAX_DURATION_SECONDS}
    report['observation_mode'] = ('pawn_interface_only' if actor_interface_only else 'replication_metadata')
    reader, session = None, None
    discovery_diagnostics = {}
    started = time.monotonic()
    try:
        executable, image_size = validate_source(game_root)
        reader = Win32MetadataReader(executable, image_size, pid, created_at)
        session = MetadataSession(reader.read_exact)
        if actor_interface_only:
            result = export_actor_interface_metadata(session, reader.module_base)
        else:
            report['dynamic_address_switch_cvar_observation'] = observe_dynamic_address_switch_cvar(
                session, reader.module_base, source_sha256=SHIPPING_SHA256)
            result = export_metadata(session, reader.module_base,
                discovery_diagnostics=discovery_diagnostics, before_loading_rescan=reader.verify_identity,
                remaining_time=lambda: reader.deadline - time.monotonic())
        reader.verify_identity()
        if reader.find_module() != reader.module_base:
            raise ValueError('Loaded client module root changed during export')
        report.update(result)
        report['status'] = 'metadata_export_complete'
        report['runtime_class_cache_recovered'] = result['class_cache_exports'] > 0
        report['runtime_replication_layout_recovered'] = result['replication_layout_exports'] > 0
        report['property_serializer_schema_recovered'] = False
    except (ValueError, OSError, psutil.Error) as error:
        # No partial scan/table results are accepted or reported as recovered.
        report.update(status='metadata_export_refused', error_type=type(error).__name__, reason=str(error),
                      runtime_class_cache_recovered=False, runtime_replication_layout_recovered=False)
        context = getattr(error, 'metadata_failure_context', None)
        if type(context) is dict:
            report['failure_context'] = context
    except Exception as error:
        report.update(status='metadata_export_failed', error_type=type(error).__name__, reason=str(error),
                      runtime_class_cache_recovered=False, runtime_replication_layout_recovered=False)
    finally:
        if reader:
            reader.close()
        if session:
            report.update(read_calls=session.calls, attempted_read_bytes=session.bytes_read)
        if discovery_diagnostics:
            report['loading_compensation'] = discovery_diagnostics
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        save(folder, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--pid', type=int)
    parser.add_argument('--created-at', type=float)
    parser.add_argument('--validate-only', action='store_true')
    parser.add_argument('--actor-interface-only', action='store_true',
                        help='Only observe the source-qualified Pawn template interface binding; no driver tables')
    parser.add_argument('--elevate', action='store_true', help='Request normal UAC for this reader; leave the game running')
    parser.add_argument('--elevated-source-pins', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.validate_only:
        _, image_size = validate_source(args.game_root)
        print(json.dumps({'status': 'source_identity_validated', 'client_sha256': SHIPPING_SHA256,
                          'image_size': image_size, 'process_memory_read': False}))
        return
    if not args.output or args.pid is None or args.created_at is None:
        parser.error('Export requires --output, --pid and --created-at')
    if args.elevate and args.elevated_source_pins:
        parser.error('Choose the parent elevation request or its worker, not both')
    if args.elevate:
        request_read_only_elevation(args)
        return
    if args.elevated_source_pins:
        scoped_output = args.output.resolve().is_relative_to((ROOT / 'work').resolve())
        def refuse_preflight(reason):
            if scoped_output:
                save(args.output, {'status': 'metadata_reader_preflight_refused',
                    'reason': reason, 'requested_pid': args.pid,
                    'process_memory_read': False, 'process_memory_written': False,
                    'game_launched': False, 'playable_map_verified': False})
            parser.error(reason)
        try:
            expected_pins = json.loads(args.elevated_source_pins)
        except (ValueError, TypeError):
            refuse_preflight('Elevated metadata reader source pins are not valid JSON')
        if not scoped_output:
            refuse_preflight('Elevated metadata reader output scope changed')
        if not C.windll.shell32.IsUserAnAdmin():
            refuse_preflight('Elevated metadata reader has no Windows administrator token')
        try:
            actual_pins = source_pins(actor_interface_only=args.actor_interface_only)
        except OSError:
            refuse_preflight('Elevated metadata reader dependency could not be verified')
        if expected_pins != actual_pins:
            refuse_preflight('Elevated metadata reader source identity changed after launch preparation')
    options = {'actor_interface_only': True} if args.actor_interface_only else {}
    result = collect(args.game_root, args.output, pid=args.pid, created_at=args.created_at, **options)
    print(json.dumps({key: result.get(key) for key in
                     ('status', 'reason', 'class_cache_exports', 'replication_layout_exports', 'elapsed_seconds')}))
    if result['status'] != 'metadata_export_complete':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
