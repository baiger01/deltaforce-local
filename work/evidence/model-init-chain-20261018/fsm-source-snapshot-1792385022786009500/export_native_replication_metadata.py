"""Export existing replication metadata from one verified client process.

The default reads the source-pinned registry, class/name metadata, existing
driver tables and a fixed diagnostic CVar. An opt-in binding observation reads
only the documented connection pointers and one local-player-index byte. It
never calls native methods, creates layouts, injects code or modifies memory.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
from dataclasses import asdict
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
from native_metadata_objects import iter_object_records, validate_object_record, weak_object_key
from native_metadata_paths import object_path
from native_replication_metadata_core import (
    MetadataSession, MAX_SINGLE_READ, span, export_existing_driver_class,
    lookup_weak_key_table, export_cache_graph, export_replayout,
)

ROOT = Path(__file__).resolve().parent.parent
EXECUTABLE_RELATIVE = Path('DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
TARGET_CLASSES = frozenset(('BP_DFMPlayerController_C', 'BP_DFMCharacter_C', 'BP_GameState_PVPVE_C'))
CONNECTION_CLASS_CACHE_TARGETS = frozenset(('BP_DFMPlayerController_C', 'BP_GameState_PVPVE_C'))
# Exact PC ClassNetCache mappings observed in trial1791208572984445800. These
# numbers select metadata, never RPC parameter values or a guessed wire schema.
CONNECTION_RPC_LAYOUT_TARGETS = {
    79: 'ServerShortTimeout', 131: 'ClientAckSeamlessLoginReady',
    138: 'ClientReturnPing', 141: 'NotifySeamlessLoginReady', 150: 'Server_RcvACWorldTime',
    151: 'ServerBouncePing', 216: 'ServerFieldOfView',
}
RPC_FUNCTION_FLAGS_OFFSET = 0xc0  # ReceivedRPC1289307e; raw uint32, not enum inference.
RPC_LAYOUT_TABLE_OFFSET = 0x430  # GetFunctionRepLayout12b90978, function weak key.
RPC_LAYOUT_SOURCE = 'work/evidence/map-entry-next-20261005/scoped-pc-rpc-layout-export-source.json'
RPC_LAYOUT_SOURCE_SHA256 = 'fbb9029fda3f4f6038aa83aaa0ce33593bda7e4b9a91ae9e2f7e9805de7245a3'
MAX_CLASS_DEPTH = 32
MAX_CLASS_DESCRIPTORS = 32768
MAX_SELECTED_CLASSES = 32
MAX_DRIVERS = 16
MAX_DURATION_SECONDS = 180
MAX_CONNECTION_CLASS_CACHE_SECONDS = 180
MAX_CONFIGURED_DURATION_SECONDS = 600
# Scheduling policy only, not a native timing contract or a deadline extension.
LOADING_RESCAN_COST_FACTOR = 1.25
LOADING_RESCAN_EXPORT_RESERVE_SECONDS = 5.0
SHIPPING_IMAGE_SIZE = 536408064  # SizeOfImage in the SHA-pinned PE32+ build.
ACTOR_CHANNEL_OPEN_SLOT = 0x3d8
# Exact Outer observed in native-map-trial-1791082007292269400 and sealed in
# connection-binding-sources.json; this does not identify an Actor GUID.
BINDING_LEVEL_PATH = '/Game/Maps/Iris_Entry/Iris_Entry.Iris_Entry:PersistentLevel'
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


def qualified_rpc_layout_source_pins():
    """Seal the fixed static ledger before optional RPC metadata observations.

    Original private source hashes in this ledger record the audited offline
    cache, not a request to follow arbitrary disk paths or a runtime schema.
    """
    path = (ROOT / RPC_LAYOUT_SOURCE).resolve(strict=True)
    if not path.is_relative_to(ROOT.resolve()) or not path.is_file() or path.stat().st_size > 128 * 1024:
        raise ValueError('Invalid scoped RPC source ledger path or size')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != RPC_LAYOUT_SOURCE_SHA256:
        raise ValueError('Scoped RPC source ledger identity changed')
    ledger = json.loads(raw)
    if (ledger.get('kind') != 'source_backed_scoped_pc_function_layout_export' or
            ledger.get('client_sha256') != SHIPPING_SHA256 or
            ledger.get('driver_layout_table_offset') != RPC_LAYOUT_TABLE_OFFSET or
            ledger.get('function_flags_offset') != RPC_FUNCTION_FLAGS_OFFSET or
            ledger.get('function_representation') != 1):
        raise ValueError('Scoped RPC source qualification differs from the fixed reader')
    return {RPC_LAYOUT_SOURCE: RPC_LAYOUT_SOURCE_SHA256}


def source_pins(*, actor_interface_only=False, connection_binding_only=False,
                connection_rpc_layouts=False, connection_guid_mappings=False,
                connection_first_player_state=False, connection_world_context=False,
                bootstrap_templates_only=False):
    dependencies = (
        'work/export_native_replication_metadata.py', 'work/native_metadata_objects.py',
        'work/native_metadata_names.py', 'work/native_metadata_paths.py',
        'work/native_replication_metadata_core.py',
        'outputs/df-local-server/dfserver/legacy_ds_class_net_cache.py')
    if actor_interface_only or bootstrap_templates_only:
        dependencies += ('work/native_actor_interface_metadata.py',)
    if bootstrap_templates_only:
        dependencies += ('work/native_actor_bootstrap.py',)
    pins = {relative: digest(ROOT / relative) for relative in dependencies}
    if connection_binding_only:
        from native_connection_binding import qualified_connection_binding_source_pins
        pins.update(qualified_connection_binding_source_pins(ROOT))
    if connection_rpc_layouts:
        pins.update(qualified_rpc_layout_source_pins())
    if connection_guid_mappings:
        from native_guid_object_metadata import guid_mapping_source_pins
        pins.update(guid_mapping_source_pins(ROOT))
    if connection_first_player_state:
        from native_gp_first_player_state import qualified_first_player_source_pins
        pins.update(qualified_first_player_source_pins(ROOT))
    if connection_world_context:
        from native_world_settings_context import qualified_world_settings_context_source_pins
        pins.update(qualified_world_settings_context_source_pins(ROOT))
        from native_loading_subworld_context import qualified_subworld_context_source_pins
        pins.update(qualified_subworld_context_source_pins(ROOT))
    return pins


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
    bootstrap_only = getattr(args, 'bootstrap_templates_only', False)
    binding_only = getattr(args, 'connection_binding_only', False)
    class_cache = getattr(args, 'connection_class_net_cache', False)
    rpc_layouts = getattr(args, 'connection_rpc_layouts', False)
    guid_mappings = getattr(args, 'connection_guid_mappings', False)
    duration = collection_duration(getattr(args, 'maximum_seconds', None),
                                   connection_tables=class_cache or guid_mappings)
    pin_options = {'actor_interface_only': interface_only}
    if bootstrap_only:
        pin_options['bootstrap_templates_only'] = True
    if binding_only:
        pin_options['connection_binding_only'] = True
    if rpc_layouts:
        pin_options['connection_rpc_layouts'] = True
    if guid_mappings:
        pin_options['connection_guid_mappings'] = True
    pins = source_pins(**pin_options)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'launch-request.json').write_text(json.dumps({
        'requested_at_utc': datetime.now(timezone.utc).isoformat(),
        'pid': args.pid, 'created_at': args.created_at,
        'observation_mode': ('bootstrap_templates_only' if bootstrap_only else
                             'connection_binding_only' if binding_only else
                             'pawn_interface_only' if interface_only else 'replication_metadata'),
        'source_pins': pins,
        'maximum_duration_seconds': duration,
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
    parameters += ['--maximum-seconds', str(duration)]
    if interface_only:
        parameters.append('--actor-interface-only')
    if bootstrap_only:
        parameters.append('--bootstrap-templates-only')
    if binding_only:
        parameters.append('--connection-binding-only')
    if class_cache:
        parameters.append('--connection-class-net-cache')
    if rpc_layouts:
        parameters.append('--connection-rpc-layouts')
    if guid_mappings:
        parameters.append('--connection-guid-mappings')
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
        outcome = monitor_reader_exit(api, info.hProcess, args.output, helper_pid,
                                      maximum_seconds=duration)
        if (outcome['status'] != 'metadata_reader_exited' or outcome['exit_code'] != 0 or
                outcome.get('reader_result_status') != 'metadata_export_complete'):
            raise RuntimeError('Metadata reader did not complete; see helper-exit.json and worker-console.log')
    finally:
        if info.hProcess:
            api.CloseHandle(info.hProcess)


def monitor_reader_exit(api, handle, folder, helper_pid, *, maximum_seconds=None):
    """Keep the launch job alive and persist the actual Windows helper exit."""
    started = time.monotonic()
    deadline = started + collection_duration(maximum_seconds) + 60
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
    def __init__(self, executable, image_size, pid, created_at, *, maximum_seconds=None):
        if (type(pid) is not int or pid <= 0 or type(created_at) not in (int, float) or
                not math.isfinite(created_at) or created_at <= 0):
            raise ValueError('An exact PID and finite creation time are required')
        duration = collection_duration(maximum_seconds)
        self.executable, self.image_size = Path(executable).resolve(), image_size
        self.pid, self.created_at = pid, float(created_at)
        self.api, self.handle, self.module_base = kernel(), None, None
        self.deadline = time.monotonic() + duration
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


def discover_roots(session, module_base, *, _state=None, start_index=0, stop_index=None,
                   connection_binding_only=False, _binding_identity_sink=None,
                   first_player_state=False, unpublished_batch_retry=False, subworld_context=False,
                   bootstrap_templates=False, _player_start_candidates=None):
    """Discover named classes, matching template metadata and NetDriver instances.

    Registry identity and Class ancestry bind every admitted root. Other object
    payloads are not read. Own names are read only for class descriptors and objects
    of a target class whose Outer is that class or its observed package Outer.
    Results are discarded
    when the registry iterator observes changes; a partial scan is not a root proof.
    """
    if _state is not None and type(_state) is not dict:
        raise ValueError('Discovery continuation state must be a private dictionary')
    if _player_start_candidates is not None and (type(_player_start_candidates) is not list or
            _player_start_candidates or not connection_binding_only):
        raise ValueError('PlayerStart metadata requires an empty private sink and typed binding mode')
    if (type(bootstrap_templates) is not bool or
            bootstrap_templates and (connection_binding_only or first_player_state or subworld_context)):
        raise ValueError('Bootstrap templates require an isolated metadata discovery mode')
    if type(first_player_state) is not bool or first_player_state and not connection_binding_only:
        raise ValueError('First-player class discovery requires the typed binding mode')
    if type(unpublished_batch_retry) is not bool:
        raise ValueError('Unpublished batch retry requires an explicit boolean')
    if type(subworld_context) is not bool or subworld_context and not connection_binding_only:
        raise ValueError('Subworld cache discovery requires typed binding mode')
    target_classes = TARGET_CLASSES
    if bootstrap_templates:
        from native_actor_bootstrap import ROLE_CLASSES
        target_classes = frozenset(ROLE_CLASSES.values())
    if first_player_state:
        from native_gp_first_player_state import MOVEMENT_CLASS, PLAYER_STATE_CLASS
        target_classes = TARGET_CLASSES | {MOVEMENT_CLASS, PLAYER_STATE_CLASS}
    if subworld_context:
        from native_loading_subworld_context import CLASS_NAME as subworld_class
        target_classes = target_classes | {subworld_class}
    subworld_instances = []
    if connection_binding_only and (_state is not None or start_index or stop_index is not None):
        raise ValueError('Binding observation requires one bounded registry pass')
    if (_binding_identity_sink is not None and
            (type(_binding_identity_sink) is not dict or not connection_binding_only)):
        raise ValueError('A private binding identity sink requires the binding observation mode')
    controllers = []
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

    # Binding/world-context mode also uses unpublished retries; it retains its
    # original behavior. Only full-metadata bootstrap uses these optimizations.
    bootstrap_fast_class_metadata = unpublished_batch_retry and not connection_binding_only
    # Explicit existing bootstrap opt-in only. The cache belongs to this one
    # discovery pass and admits only successful complete-token resolutions.
    class_name_cache = {}
    fast_class_metadata = {'current_checked_record_identities_reused': 0,
        'fresh_descriptor_identity_reads': 0, 'class_name_cache_hits': 0,
        'class_name_cache_misses': 0, 'admitted_class_names_freshly_resolved': 0}

    def class_descriptor(address, *, current_record=None):
        if address not in descriptors:
            if address not in descriptors_seen and len(descriptors_seen) >= MAX_CLASS_DESCRIPTORS:
                raise ValueError('Class descriptor discovery exceeds local bound')
            if bootstrap_fast_class_metadata and current_record is not None:
                # iter_object_records has not yielded ANY member of a batch
                # until its complete registry double read and index checks pass.
                # Only this currently yielded record can supply the initial
                # identity; final admitted-root checks still read fresh state.
                if current_record.object_address != address or current_record.class_address is None:
                    raise ValueError('Bootstrap descriptor requires its current checked object record')
                identity = {'object_index': current_record.index, 'serial': current_record.serial,
                    'key': struct.pack('<iI', current_record.index, current_record.serial).hex()
                    if current_record.serial else None}
                fast_class_metadata['current_checked_record_identities_reused'] += 1
            else:
                identity = record_identity(address)
                if bootstrap_fast_class_metadata:
                    fast_class_metadata['fresh_descriptor_identity_reads'] += 1
            token = session.stable(address + 0x1c, 8)
            if bootstrap_fast_class_metadata and token in class_name_cache:
                name = class_name_cache[token]
                fast_class_metadata['class_name_cache_hits'] += 1
            else:
                name = resolve_name(session.read, module_base, token)
                if bootstrap_fast_class_metadata:
                    if len(class_name_cache) >= MAX_CLASS_DESCRIPTORS:
                        raise ValueError('Bootstrap class-name cache exceeds the descriptor bound')
                    class_name_cache[token] = name
                    fast_class_metadata['class_name_cache_misses'] += 1
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

    def binding_object_identity(address, expected_base_class):
        """Prove a typed UObject before following a diagnostic member pointer.

        A template, recycled slot or changed name/class is refused. Registry
        serial0 can precede native weak-key allocation; stable slot metadata
        permits explicitly weak-qualified observations without creating a key.
        Class/Outer metadata is read, never arbitrary UObject payload. Repeated
        reads are not an atomic snapshot and cannot prove a method executed.
        """
        before = record_identity(address)
        klass = struct.unpack('<Q', session.stable(address + 8, 8))[0]
        chain = ancestry(klass)
        chain_names = [item['name'] for item in chain]
        if expected_base_class not in chain_names:
            raise ValueError('Diagnostic object does not have the required class ancestry')
        token = session.stable(address + 0x1c, 8)
        name = resolve_name(session.read, module_base, token).display_text
        if name.startswith('Default__'):
            raise ValueError('A named default object cannot qualify an instance binding')
        outer = struct.unpack('<Q', session.stable(address + 0x10, 8))[0]
        outer_class = None
        outer_chain = []
        outer_identity = None
        outer_path = None
        # Identity belongs to the actual object, not the requested base view.
        # A bound PC is also visited as its connection's Actor owner.
        if 'PlayerController' in chain_names:
            outer_identity = record_identity(outer)
            outer_class = struct.unpack('<Q', session.stable(outer + 8, 8))[0]
            outer_chain = ancestry(outer_class)
            if 'Level' not in {row['name'] for row in outer_chain}:
                raise ValueError('PlayerController instance requires a Level Outer')
            outer_path = object_path(session.read, module_base, outer)
            if outer_path != BINDING_LEVEL_PATH:
                raise ValueError('PlayerController Level Outer is outside the evidenced entry level')
        for row in chain + outer_chain:
            check_identity(row)
            if (session.stable(row['address'] + 0x1c, 8) != descriptor_tokens[row['address']] or
                    struct.unpack('<Q', session.stable(row['address'] + 0x48, 8))[0] != row['parent_address']):
                raise ValueError('Diagnostic class ancestry changed')
        if (record_identity(address) != before or session.stable(address + 8, 8) != struct.pack('<Q', klass) or
                session.stable(address + 0x1c, 8) != token or
                struct.unpack('<Q', session.stable(address + 0x10, 8))[0] != outer):
            raise ValueError('Diagnostic instance identity or binding changed')
        if outer_identity is not None and (record_identity(outer) != outer_identity or
                struct.unpack('<Q', session.stable(outer + 8, 8))[0] != outer_class or
                object_path(session.read, module_base, outer) != outer_path):
            raise ValueError('Diagnostic Level Outer identity changed')
        return {'address': hex(address), **before, 'name': name, 'class_address': hex(klass),
                'class_ancestry': chain_names, 'outer_address': hex(outer),
                'outer_path': outer_path,
                'outer_class_ancestry': [row['name'] for row in outer_chain], 'is_cdo': False}

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
            if bootstrap_fast_class_metadata:
                # An unchanged UObject token must not hide mutated NamePool
                # bytes behind the per-pass cache. Every admitted ancestry name
                # receives the original source-qualified resolver afresh.
                if (resolve_name(session.read, module_base, descriptor_tokens[address]).display_text != descriptor['name'] or
                        session.read(address + 0x1c, 8) != descriptor_tokens[address]):
                    raise ValueError('Admitted class name changed during bootstrap discovery')
                fast_class_metadata['admitted_class_names_freshly_resolved'] += 1
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
        for candidate in subworld_instances:
            check_identity(candidate)
            if (session.pointer(candidate['address'] + 8) != candidate['class_address'] or
                    session.pointer(candidate['address'] + 0x10) != candidate['outer_address']):
                raise ValueError('Selected subworld context class or Outer changed')
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
    progress_callback = getattr(session, 'discovery_progress_callback', None)
    if progress_callback is not None and not callable(progress_callback):
        raise ValueError('Discovery progress callback must be callable')
    last_progress_at = 0.0
    last_live_index = None
    discovery_status = 'scanning_registry'

    def current_discovery_progress():
        progress = {'status': discovery_status, 'live_records_seen': pass_records_scanned,
            'last_live_registry_index': last_live_index,
            'frozen_registry_index_range': scan_metadata.get('initial_index_range'),
            'initial_registry_count': scan_metadata.get('initial_count'),
            'selected_classes': len(selected), 'selected_template_candidates': len(archetypes),
            'range_exhausted': discovery_status == 'selected_roots_rechecked',
            'complete_global_inventory': False, 'snapshot_atomic': False}
        if bootstrap_fast_class_metadata:
            progress['unique_class_descriptors_read'] = len(descriptors_seen)
            progress['bootstrap_class_metadata_optimization'] = {
                **fast_class_metadata, 'class_name_cache_entries': len(class_name_cache)}
        return progress

    if progress_callback is not None:
        # Final reporting can retain the exact last counters after a backend
        # timeout, even if the two-second disk progress interval has not elapsed.
        session.discovery_progress_snapshot = current_discovery_progress

    def publish_discovery_progress(status, *, force=False):
        nonlocal last_progress_at, discovery_status
        discovery_status = status
        if progress_callback is None:
            return
        now = time.monotonic()
        if force or now - last_progress_at >= 2.0:
            progress_callback(current_discovery_progress())
            last_progress_at = now

    publish_discovery_progress('scanning_registry', force=True)
    range_options = {'start_index': start_index, 'stop_index': stop_index} if continuing else {}
    if connection_binding_only or unpublished_batch_retry:
        # Same proven metadata fields as the ordinary path, combined with the
        # iterator's +0x24 index check to avoid a second tiny per-object read.
        # Final admitted roots/type/name/Outer checks below remain fresh.
        range_options['include_class_pointer'] = True
        if unpublished_batch_retry:
            range_options['unpublished_batch_attempts'] = 2
    for record in iter_object_records(session.read, module_base, scan_metadata=scan_metadata, **range_options):
        records_scanned += 1
        pass_records_scanned += 1
        last_live_index = record.index
        publish_discovery_progress('scanning_registry')
        klass = (record.class_address if record.class_address is not None
                 else session.pointer(record.object_address + 8))
        chain = ancestry(klass)
        chain_names = {item['name'] for item in chain}
        if _player_start_candidates is not None and 'PlayerStart' in chain_names:
            if len(_player_start_candidates) >= 512:
                raise ValueError('Loaded PlayerStart metadata exceeds its local bound')
            _player_start_candidates.append(dict(address=record.object_address,
                object_index=record.index, serial=record.serial,
                class_address=klass, asset_path=object_path(session.read, module_base, record.object_address)))
        if 'Class' in chain_names:
            # Only class-descriptor objects may have their own names read.
            candidate = class_descriptor(record.object_address,
                **({'current_record': record} if bootstrap_fast_class_metadata else {}))
            if candidate['name'] in target_classes:
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
        if chain and chain[0]['name'] in target_classes:
            # SerializeNewActor references a template object, not its UClass.
            # Observe a named candidate without guessing the UClass CDO offset,
            # allocating a native default object or reading player properties.
            class_outer = session.pointer(klass + 0x10)
            if klass in class_outers and class_outers[klass] != class_outer:
                raise ValueError('Target class Outer changed between template candidates')
            outer = session.pointer(record.object_address + 0x10)
            if subworld_context and chain[0]['name'] == subworld_class and outer not in (klass, class_outer):
                if len(subworld_instances) >= 16:
                    raise ValueError('Subworld context instance count exceeds its bound')
                subworld_instances.append({'address': record.object_address,
                    **record_identity(record.object_address), 'class_address': klass,
                    'outer_address': outer})
            if connection_binding_only and chain[0]['name'] == 'BP_DFMPlayerController_C' and outer:
                outer_class = session.pointer(outer + 8)
                if 'Level' in {row['name'] for row in ancestry(outer_class)}:
                    if len(controllers) >= 16:
                        raise ValueError('PlayerController instance count exceeds the diagnostic bound')
                    controllers.append({'address': record.object_address,
                        **record_identity(record.object_address), 'class_address': klass,
                        'outer_path': object_path(session.read, module_base, outer)})
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
                    if chain[0]['name'] in ('BP_DFMPlayerController_C', 'BP_DFMCharacter_C',
                                          'BP_SOLPlayerState_C', 'MovementReplicationActor'):
                        archetypes[record.object_address]['actor_channel_open_hook'] = observed_virtual_method(
                            session, module_base, record.object_address, ACTOR_CHANNEL_OPEN_SLOT)
    publish_discovery_progress('rechecking_selected_roots', force=True)
    recheck_admitted()
    publish_discovery_progress('selected_roots_rechecked', force=True)
    if continuing:
        scan_metadata['combined_index_ranges'] = [[0, start_index], [start_index, stop_index]]
        scan_metadata['prior_selected_roots_rechecked'] = True
    if _state is not None:
        _state.update(session=session, module_base=module_base, descriptors=descriptors,
            descriptor_tokens=descriptor_tokens, descriptors_seen=descriptors_seen,
            selected=selected, drivers=drivers,
            archetypes=archetypes, archetype_tokens=archetype_tokens, class_outers=class_outers,
            records_scanned=records_scanned, stop_index=scan_metadata['initial_index_range'][1])
    result = {'records_scanned': records_scanned, 'unique_class_descriptors_read': len(descriptors_seen),
            'pass_records_scanned': pass_records_scanned,
            'registry_scan': scan_metadata, 'complete_global_inventory': False,
            'selected_roots_rechecked': True,
            'classes': list(selected.values()), 'drivers': drivers,
            'named_template_candidates': list(archetypes.values()),
            'missing_named_templates': sorted({item['address'] for item in selected.values()} -
                {item['class_address'] for item in archetypes.values()}),
            'missing_target_classes': sorted(target_classes - {item['name'] for item in selected.values()})}
    if bootstrap_fast_class_metadata:
        result['bootstrap_class_metadata_optimization'] = {
            'enabled': True, **fast_class_metadata,
            'class_name_cache_entries': len(class_name_cache),
            'maximum_class_name_cache_entries': MAX_CLASS_DESCRIPTORS,
            'cache_scope': 'one_discovery_pass_successfully_resolved_complete_tokens',
            'selected_root_identity_type_name_outer_rechecks_retained': True,
            'global_read_budgets_changed': False, 'deadline_extended': False}
    if subworld_context:
        result['subworld_context_instance_candidates'] = subworld_instances
    if connection_binding_only:
        from native_connection_binding import observe_connection_bindings
        identity_callback = binding_object_identity
        if _binding_identity_sink is not None:
            observed_facts = {}

            def identity_callback(address, base_class):
                row = binding_object_identity(address, base_class)
                key = (address, base_class)
                if key in observed_facts and observed_facts[key] != row:
                    raise ValueError('Diagnostic object identity changed after its binding observation')
                observed_facts[key] = row
                return row

            _binding_identity_sink['callback'] = identity_callback
            _binding_identity_sink['recheck_roots'] = recheck_admitted
        result['connection_binding_observations'] = observe_connection_bindings(
            session, module_base, drivers, controllers, object_identity=identity_callback)
        result['controller_instance_candidates'] = controllers
    return result


def discover_roots_with_loading_compensation(session, module_base, *,
                                           diagnostics=None, before_rescan=None,
                                           remaining_time=None,
                                           bootstrap_registry_batch_retry=False):
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
    if type(bootstrap_registry_batch_retry) is not bool:
        raise ValueError('Bootstrap registry batch retry requires an explicit boolean')
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
    if bootstrap_registry_batch_retry:
        diagnostics['bootstrap_registry_batch_retry'] = {
            'enabled': True, 'mode': 'replication_metadata',
            'maximum_batch_attempts': 2, 'maximum_retried_batches_per_pass': 8,
            'replacement_same_frozen_range_required': True,
            'replacement_initial_blob_matches_previous_checked_blob_required': True,
            'replacement_complete_double_read_required': True,
            'discarded_batch_records_merged': False, 'unstable_slots_skipped': False,
            'selected_root_and_table_checks_unchanged': True, 'deadline_extended': False}

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
    roots = discover_roots(session, module_base, _state=continuation_state,
        **({'unpublished_batch_retry': True} if bootstrap_registry_batch_retry else {}))
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
                start_index=tail_start, stop_index=tail_stop,
                **({'unpublished_batch_retry': True} if bootstrap_registry_batch_retry else {}))
            diagnostics['attempts'].append(completed_summary(roots, time.monotonic() - started))
            diagnostics['selected_attempt'] = 1
    else:
        diagnostics['selected_attempt'] = 0
    roots['loading_compensation'] = diagnostics
    return roots


def export_metadata(session, module_base, *, discovery_diagnostics=None,
                    before_loading_rescan=None, remaining_time=None,
                    bootstrap_registry_batch_retry=False):
    if type(bootstrap_registry_batch_retry) is not bool:
        raise ValueError('Bootstrap registry batch retry requires an explicit boolean')
    roots = discover_roots_with_loading_compensation(session, module_base,
        diagnostics=discovery_diagnostics, before_rescan=before_loading_rescan,
        remaining_time=remaining_time,
        **({'bootstrap_registry_batch_retry': True} if bootstrap_registry_batch_retry else {}))
    exports = []
    driver_tables_read = False
    for driver in roots['drivers']:
        for klass in roots['classes']:
            if klass['key'] is None:
                exports.append({'class_name': klass['name'], 'class_address': klass['address'],
                    'driver_address': driver['address'], 'class_key': None,
                    'class_key_status': 'missing_uninitialized_native_serial',
                    'cache_status': 'missing', 'layout_status': 'missing',
                    'native_getter_invoked': False, 'player_spawn_verified': False})
                continue
            driver_tables_read = True
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
            'driver_tables_read': driver_tables_read,
            'class_cache_exports': sum(item['cache_status'] == 'exported_existing' for item in exports),
            'replication_layout_exports': sum(item['layout_status'] == 'exported_existing' for item in exports)}


def export_bootstrap_template_metadata(session, module_base):
    """Read five template identities and the Pawn header binding, without a match.

    Historical capture files are not inputs. Missing loaded classes remain
    explicitly missing; they are never replaced with invented CDO identities.
    """
    from native_actor_interface_metadata import observe_actor_interface

    roots = discover_roots(session, module_base, bootstrap_templates=True)
    if roots.get('selected_roots_rechecked') is not True:
        raise ValueError('Bootstrap template roots must be rechecked')
    candidates = [row for row in roots['named_template_candidates']
                  if row.get('class_name') == 'BP_DFMCharacter_C']
    if len(candidates) > 1:
        raise ValueError('Pawn template metadata is ambiguous')
    observations = []
    if candidates:
        classes = [row for row in roots['classes']
                   if row.get('address') == candidates[0].get('class_address')]
        if len(classes) != 1:
            raise ValueError('Pawn template requires one checked class root')
        observations.append(observe_actor_interface(session, module_base, candidates[0], classes[0]))
    return {'roots': roots, 'actor_interface_observations': observations,
            'driver_class_exports': [], 'class_cache_exports': 0, 'replication_layout_exports': 0,
            'driver_tables_read': False, 'player_property_values_read': False,
            'historical_process_pointers_reused': False}


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



_CURRENT_GP_OWNER_SELECTION_ISSUER = object()


def _qualified_bound_gp_driver_candidates(roots, observations):
    eligible = []
    for driver in roots['drivers']:
        if 'GPNetDriver' not in driver['class_chain']:
            continue
        matches = [row for row in observations['drivers']
            if row.get('address') == hex(driver['address'])
            and row.get('object_index') == driver['object_index']
            and row.get('status') == 'observed'
            and row.get('identity_and_fields_rechecked') is True
            and row.get('connection_back_driver_matches') is True]
        if len(matches) > 1:
            raise ValueError('Current GPNetDriver has ambiguous binding observations')
        if matches:
            connection = int(matches[0]['primary_connection'], 16)
            if connection:
                eligible.append((driver, connection, matches[0]))
    return eligible


import weakref as _gp_owner_weakref
_CURRENT_GP_OWNER_SELECTION_RECORDS = _gp_owner_weakref.WeakKeyDictionary()


class _CurrentOwnedGPDriverSelection:
    """Private factory-issued route; caller mutation never qualifies a new owner."""
    __slots__ = ('choice', 'player_controller', 'context', '_callback', '__weakref__')

    def __init__(self, choice, player_controller, recheck, session, module_base, roots, observations,
            object_identity, recheck_roots):
        # Construction alone does not issue a qualified selection.
        self.choice, self.player_controller, self._callback = choice, player_controller, recheck
        self.context = (session, module_base, roots, observations, object_identity, recheck_roots)

    def _record(self):
        record = _CURRENT_GP_OWNER_SELECTION_RECORDS.get(self)
        if type(self) is not _CurrentOwnedGPDriverSelection or record is None:
            raise ValueError('Factory-issued current GP owner selection required')
        original_choice, original_pc, callback, context = record
        if (self.choice != original_choice or self.player_controller != original_pc or
                self._callback is not callback or type(self.context) is not tuple or len(self.context) != 6 or
                self.context[1] != context[1] or
                any(self.context[i] is not context[i] for i in (0, 2, 3, 4, 5))):
            raise ValueError('Original current GP selection capsule changed')
        return record

    def recheck(self):
        self._record()[2]()

    def require_same_context(self, session, module_base, roots, observations, object_identity, recheck_roots):
        supplied = (session, module_base, roots, observations, object_identity, recheck_roots)
        self._record()
        if (self.context[1] != module_base or any(self.context[i] is not supplied[i] for i in (0,2,3,4,5))):
            raise ValueError('Current GP owner selector belongs to a different original session')
        self.recheck()
        return self.choice


def _prepare_current_owned_gp_driver_selection(session, module_base, roots, observations, *,
        object_identity, recheck_roots):
    """Only resolve multi-GP ambiguity through the original typed local PC graph.

    The six existing qualified offsets are from native_connection_binding and
    the existing current primary PC/Pawn selector. No Pawn/first-state dependency
    is added before GUID observation. Zero/single eligible paths are unchanged.
    """
    from native_connection_binding import _identity, _pointer
    import copy
    eligible = _qualified_bound_gp_driver_candidates(roots, observations)
    if len(eligible) <= 1:
        return None
    if not callable(object_identity) or not callable(recheck_roots):
        raise ValueError('Current GP owner selector requires original typed callbacks')
    pairs = {(driver['address'], connection):(driver,connection,observed)
        for driver,connection,observed in eligible}
    selected = [row for row in observations['player_controllers']
        if row.get('status') == 'observed' and row.get('identity_and_fields_rechecked') is True
        and row.get('driver_primary_matches_original_connection') is True
        and row.get('connection_pc_is_this_pc') is True and row.get('connection_owner_is_this_pc') is True
        and type(row.get('local_player_index_field')) is int and row['local_player_index_field'] == 0
        and (int(row['driver'],16),int(row['connection'],16)) in pairs]
    if len(selected) != 1:
        raise ValueError('Current owned primary GP controller is missing or ambiguous; eligible_gp_drivers=' + str(min(len(eligible),65535)) + '; owned_primary_controllers=' + str(min(len(selected),65535)))
    original_pc = copy.deepcopy(selected[0])
    pc, connection, driver_address = map(_pointer,(int(original_pc['address'],16),
        int(original_pc['connection'],16),int(original_pc['driver'],16)))
    if len({pc,connection,driver_address}) != 3:
        raise ValueError('Distinct original current GP owner objects required')
    driver,_,observed_driver = pairs[(driver_address,connection)]
    original_driver, original_observed = copy.deepcopy(driver), copy.deepcopy(observed_driver)

    def identify(address, base_class):
        value = _identity(object_identity(address,base_class),address,base_class)
        if value[2] == 0 and base_class not in ('NetDriver','NetConnection'):
            raise ValueError('Current PC weak identity is uninitialized')
        return value

    recheck_roots()
    expected = {(address,kind):identify(address,kind) for address,kind in (
        (pc,'PlayerController'),(connection,'NetConnection'),(driver_address,'NetDriver'))}
    if ('GPNetDriver' not in expected[(driver_address,'NetDriver')][4] or
            'GPNetConnection' not in expected[(connection,'NetConnection')][4]):
        raise ValueError('Current owned route requires typed GP ancestry')
    for address,kind in ((pc,'PlayerController'),(connection,'NetConnection'),(driver_address,'NetDriver')):
        rows = [row for row in original_pc.get('identity_qualification',[])
            if row.get('address') == hex(address) and row.get('expected_base_class') == kind]
        if (len(rows) != 1 or (rows[0].get('object_index'),rows[0].get('serial')) != expected[(address,kind)][1:3]):
            raise ValueError('Original current GP owner registry identity changed')
    if ((original_driver.get('object_index'),original_driver.get('serial'),original_driver.get('class_address')) !=
            expected[(driver_address,'NetDriver')][1:4]):
        raise ValueError('Original selected GP driver root changed')
    def recheck():
        recheck_roots()
        current_eligible = _qualified_bound_gp_driver_candidates(roots,observations)
        current_pairs = {(d['address'],c):(d,c,o) for d,c,o in current_eligible}
        candidates = [row for row in observations['player_controllers']
            if row.get('status') == 'observed' and row.get('identity_and_fields_rechecked') is True
            and row.get('driver_primary_matches_original_connection') is True
            and row.get('connection_pc_is_this_pc') is True and row.get('connection_owner_is_this_pc') is True
            and type(row.get('local_player_index_field')) is int and row['local_player_index_field'] == 0
            and (int(row['driver'],16),int(row['connection'],16)) in current_pairs]
        if (len(candidates) != 1 or candidates[0] != original_pc or
                (driver_address,connection) not in current_pairs or
                current_pairs[(driver_address,connection)][0] != original_driver or
                current_pairs[(driver_address,connection)][2] != original_observed):
            raise ValueError('Original current GP owner metadata changed; reselection refused')
        for (address,kind),old in expected.items():
            if identify(address,kind) != old:
                raise ValueError('Original current GP owner identity changed')
        if (session.pointer(driver_address+0x98) != connection or session.pointer(connection+0x58) != driver_address
                or session.pointer(pc+0x568) != connection or session.read(pc+0x524,1) != b'\0'
                or session.pointer(connection+0x30) != pc or session.pointer(connection+0xa8) != pc):
            raise ValueError('Original current GP owner route changed')
    recheck()
    selection = _CurrentOwnedGPDriverSelection((original_driver,connection,original_observed),original_pc,recheck,
        session,module_base,roots,observations,object_identity,recheck_roots)
    _CURRENT_GP_OWNER_SELECTION_RECORDS[selection] = (copy.deepcopy(selection.choice), copy.deepcopy(original_pc), recheck, selection.context)
    return selection


def _use_current_owned_gp_driver_selection(selection, session, module_base, roots, observations, *,
        object_identity, recheck_roots):
    if selection is None:
        selection = _prepare_current_owned_gp_driver_selection(session,module_base,roots,observations,
            object_identity=object_identity,recheck_roots=recheck_roots)
    if selection is not None:
        if type(selection) is not _CurrentOwnedGPDriverSelection:
            raise ValueError('Exact private current GP owner selection required')
        selection.require_same_context(session,module_base,roots,observations,object_identity,recheck_roots)
    return selection


def export_bound_connection_class_caches(session, module_base, roots, observations, *,
                                        object_identity, recheck_roots, rpc_layouts=False, _current_owned_gp_selection=None):
    """Read PC/GS cache metadata only from one observed primary GPNetDriver.

    The manager+8 weak-key lookup and cache-node decoder are the existing
    source-qualified readers. The optional RPC branch looks up existing layouts
    for seven exact PC function mappings only. No getter, parameter value or
    native method is read/executed and no missing layout is allocated.
    """
    if type(rpc_layouts) is not bool:
        raise ValueError('RPC layouts require an explicit boolean mode')
    eligible = _qualified_bound_gp_driver_candidates(roots, observations)
    scope = {'target_classes': sorted(CONNECTION_CLASS_CACHE_TARGETS),
             'driver_selection': 'missing_observed_primary_gp_net_driver',
             'driver_tables_read': False,
             'replication_layout_tables_read': False, 'native_getter_invoked': False,
             **({'rpc_layout_targets': dict(CONNECTION_RPC_LAYOUT_TARGETS),
                 'rpc_parameter_values_read': False} if rpc_layouts else {})}
    if not eligible:
        return [], scope
    selection = _use_current_owned_gp_driver_selection(_current_owned_gp_selection, session, module_base, roots, observations,
        object_identity=object_identity, recheck_roots=recheck_roots)
    if selection is not None:
        eligible = [selection.choice]
    if len(eligible) != 1:
        raise ValueError('Current primary GPNetDriver is ambiguous')
    driver, connection, observed_driver = eligible[0]
    if not callable(object_identity) or not callable(recheck_roots):
        raise ValueError('Current connection cache export requires the original typed identity callback')
    identities = [row for row in observed_driver.get('identity_qualification', [])
                  if row.get('address') == hex(connection) and row.get('expected_base_class') == 'NetConnection']
    if len(identities) != 1:
        raise ValueError('Current connection has no unique observed registry identity')
    observed_connection = identities[0]
    scope.update(driver_selection='one_observed_primary_gp_net_driver',
                 driver_address=driver['address'])

    def recheck(klass=None):
        if selection is not None:
            selection.recheck()
        connection_identity = object_identity(connection, 'NetConnection')
        if (connection_identity['object_index'], connection_identity['serial']) != (
                observed_connection['object_index'], observed_connection['serial']):
            raise ValueError('Current connection registry identity changed during cache export')
        for row, class_field in ((driver, 'class_address'), (klass, 'metaclass_address')):
            if row is None:
                continue
            record = validate_object_record(session.read, module_base, row['address'])
            if (record.index, record.serial) != (row['object_index'], row['serial']):
                raise ValueError('Selected class or NetDriver identity changed during cache export')
            if session.pointer(row['address'] + 8) != row[class_field]:
                raise ValueError('Selected class or NetDriver type changed during cache export')
        if (session.pointer(driver['address'] + 0x98) != connection or
                session.pointer(connection + 0x58) != driver['address']):
            raise ValueError('Selected primary connection changed during cache export')

    exports = []
    selected_classes = []
    rpc_final_rechecks, rpc_cache_final_checks = [], []
    recheck_roots()
    recheck()
    for name in sorted(CONNECTION_CLASS_CACHE_TARGETS):
        classes = [row for row in roots['classes'] if row['name'] == name]
        if len(classes) > 1:
            raise ValueError('Selected connection cache class is ambiguous')
        result = {'class_name': name, 'driver_address': driver['address'],
                  'cache_status': 'missing', 'layout_status': 'not_requested',
                  'native_getter_invoked': False, 'snapshot_atomic': False,
                  'player_spawn_verified': False}
        if not classes:
            result['class_key_status'] = 'missing_current_class'
            exports.append(result)
            continue
        klass = classes[0]
        selected_classes.append(klass)
        result.update(class_address=klass['address'], class_key=klass['key'])
        recheck(klass)
        if klass['key'] is None:
            result['class_key_status'] = 'missing_uninitialized_native_serial'
            exports.append(result)
            continue
        key = bytes.fromhex(klass['key'])
        manager = session.pointer(driver['address'] + 0x170)
        if manager:
            scope['driver_tables_read'] = True
        selected = lookup_weak_key_table(session, manager + 8, key,
                                        value_kind='cache') if manager else None
        if selected and selected['value_address']:
            graph = export_cache_graph(session, selected['value_address'], expected_key=key)
            nodes = [{**asdict(node), 'opaque_object_key': node.opaque_object_key.hex()}
                     for node in graph.nodes]
            for node in nodes:
                for field in node['fields']:
                    if not field['descriptor_address'] or field['incompatible']:
                        field.update(descriptor_name=None, descriptor_name_status=(
                            'null_descriptor' if not field['descriptor_address'] else 'incompatible_field'))
                    else:
                        field['descriptor_name'] = object_name(session.read, module_base,
                            field['descriptor_address'],
                            field_representation=field['descriptor_representation']).display_text
            repeated = export_cache_graph(session, selected['value_address'], expected_key=key)
            if repeated.nodes != graph.nodes:
                raise ValueError('Class cache changed during descriptor-name export')
            for node in nodes:
                for field in node['fields']:
                    if field['descriptor_name'] is not None and object_name(session.read, module_base,
                            field['descriptor_address'],
                            field_representation=field['descriptor_representation']).display_text != field['descriptor_name']:
                        raise ValueError('Class cache descriptor name changed during export')
            result.update(cache_status='exported_existing', cache_nodes=nodes,
                          exclusive_index_maximum=graph.exclusive_index_maximum)
            if rpc_layouts and name == 'BP_DFMPlayerController_C':
                result['rpc_functions'] = export_existing_pc_rpc_layouts(
                    session, module_base, driver['address'], nodes,
                    object_identity=object_identity, _final_recheck_sink=rpc_final_rechecks)
                rpc_cache_final_checks.append((manager, key, selected, graph, nodes))
                scope['replication_layout_tables_read'] = any(
                    row.get('layout_table_read') is True for row in result['rpc_functions'])
                # RPC reads must not change the selected ClassNetCache mapping,
                # field descriptors or names that qualified the function inputs.
                if export_cache_graph(session, selected['value_address'], expected_key=key).nodes != graph.nodes:
                    raise ValueError('Class cache changed during RPC layout export')
                for node in nodes:
                    for field in node['fields']:
                        if field['descriptor_name'] is not None and object_name(session.read, module_base,
                                field['descriptor_address'], field_representation=field['descriptor_representation']).display_text != field['descriptor_name']:
                            raise ValueError('Class cache descriptor name changed during RPC layout export')
        if session.pointer(driver['address'] + 0x170) != manager:
            raise ValueError('Driver cache-manager root changed during cache export')
        if manager and lookup_weak_key_table(session, manager + 8, key,
                                            value_kind='cache') != selected:
            raise ValueError('Selected class cache mapping changed during export')
        recheck(klass)
        exports.append(result)
    # GS lookup occurs after PC in this loop. Preserve PC's original mapping and
    # function facts until all scoped table reads have completed, not just until
    # the earlier PC iteration returned.
    for manager, key, selected, graph, nodes in rpc_cache_final_checks:
        if (session.pointer(driver['address'] + 0x170) != manager or
                lookup_weak_key_table(session, manager + 8, key, value_kind='cache') != selected or
                export_cache_graph(session, selected['value_address'], expected_key=key).nodes != graph.nodes):
            raise ValueError('PC ClassNetCache mapping changed at final RPC recheck')
        for node in nodes:
            for field in node['fields']:
                if field['descriptor_name'] is not None and object_name(session.read, module_base,
                        field['descriptor_address'], field_representation=field['descriptor_representation']).display_text != field['descriptor_name']:
                    raise ValueError('PC ClassNetCache field name changed at final RPC recheck')
    for final_recheck in rpc_final_rechecks:
        final_recheck()
    for klass in selected_classes:
        recheck(klass)
    recheck_roots()
    recheck()
    scope['selected_roots_rechecked'] = True
    return exports, scope


def export_existing_pc_rpc_layouts(session, module_base, driver_address, cache_nodes, *, object_identity,
                                  _final_recheck_sink=None):
    """Observe existing layouts for exact compatible UObject/Function fields.

    GetFunctionRepLayout12b90940 makes the function weak key with109929f0 then
    looks up driver+430 via d8caf0 (32-byte shared-pointer entries). ReceivedRPC
    reads that same function's flags at+c0 before12b90940/12db93c0. This inverse
    read-only lookup never follows the native missing-layout producer branch.
    The caller retains the current-driver/root final checks and original deadline.
    """
    if not callable(object_identity):
        raise ValueError('RPC metadata needs the original typed object identity callback')
    if _final_recheck_sink is not None and type(_final_recheck_sink) is not list:
        raise ValueError('Final RPC rechecks require a private list sink')
    exports = []
    final_checks = []
    fields = [field for node in cache_nodes for field in node['fields']]
    for index, name in sorted(CONNECTION_RPC_LAYOUT_TARGETS.items()):
        matches = [field for field in fields if field['rep_index'] == index]
        result = {'network_index': index, 'function_name': name,
                  'layout_status': 'missing', 'layout_table_read': False,
                  'native_getter_invoked': False, 'parameter_values_read': False,
                  'rpc_parameter_codec_recovered': False}
        if not matches:
            result['status'] = 'missing_current_cache_field'
            exports.append(result)
            continue
        if len(matches) != 1:
            raise ValueError('Selected RPC cache field is ambiguous')
        field = matches[0]
        if (field['descriptor_representation'] != 1 or field['incompatible'] or
                not field['descriptor_address'] or field.get('descriptor_name') != name):
            raise ValueError('Selected RPC field is not the exact compatible Function mapping')
        address = field['descriptor_address']
        identity = object_identity(address, 'Function')
        result.update(descriptor_address=address, descriptor_representation=1,
                      identity_qualification=identity, status='observed_existing_function')
        if identity['serial'] == 0:
            result['status'] = 'missing_uninitialized_native_serial'
            final_checks.append((address, name, identity, None, None, None, None))
            exports.append(result)
            continue
        key = weak_object_key(session.read, module_base, address)
        flags = session.stable(address + RPC_FUNCTION_FLAGS_OFFSET, 4)
        result.update(function_key=key.hex(), flags_raw_u32=struct.unpack('<I', flags)[0],
                      flags_source_offset=RPC_FUNCTION_FLAGS_OFFSET)
        selected = lookup_weak_key_table(session, driver_address + RPC_LAYOUT_TABLE_OFFSET,
                                        key, value_kind='layout')
        result['layout_table_read'] = True
        if selected and selected['value_address']:
            layout = export_replayout(session, selected['value_address'])
            named = []
            hooks = []
            for parent in layout['parents']:
                if parent['descriptor_address']:
                    parent['descriptor_name'] = object_name(session.read, module_base,
                        parent['descriptor_address'], field_representation=0).display_text
                    named.append((parent['descriptor_address'], parent['descriptor_name']))
                else:
                    parent.update(descriptor_name=None, descriptor_name_status='null_descriptor')
                parent['record_name'] = resolve_name(session.read, module_base,
                    bytes.fromhex(parent['name_token'])).display_text
            for command in layout['commands']:
                descriptor = command['descriptor_address']
                if command['dispatch_opcode'] == 1:
                    if descriptor:
                        raise ValueError('Native empty RPC layout command has a nonnull descriptor')
                    command['descriptor_name_status'] = 'native_empty_special_record'
                elif descriptor:
                    command['descriptor_name'] = object_name(session.read, module_base,
                        descriptor, field_representation=0).display_text
                    named.append((descriptor, command['descriptor_name']))
                    command['property_serializer_hook'] = observed_virtual_method(
                        session, module_base, descriptor, PROPERTY_SERIALIZER_SLOT)
                    hooks.append((descriptor, command['property_serializer_hook']))
                    if command['property_serializer_hook']['target_rva'] == GENERIC_NUMERIC_SERIALIZER_RVA:
                        command['property_scalar_leaf_hook'] = observed_virtual_method(
                            session, module_base, descriptor, PROPERTY_SCALAR_LEAF_SLOT)
                        hooks.append((descriptor, command['property_scalar_leaf_hook']))
                else:
                    command['descriptor_name_status'] = 'null_descriptor_unclassified_opcode'
            repeated = export_replayout(session, selected['value_address'])
            # Compare the raw metadata shape, before locally added labels/hooks.
            for key_name in ('parents_sha256', 'commands_sha256', 'parent_count', 'command_count'):
                if repeated[key_name] != layout[key_name]:
                    raise ValueError('RPC RepLayout changed during metadata export')
            for descriptor, expected_name in named:
                if object_name(session.read, module_base, descriptor, field_representation=0).display_text != expected_name:
                    raise ValueError('RPC parameter descriptor name changed during metadata export')
            for parent in layout['parents']:
                if resolve_name(session.read, module_base, bytes.fromhex(parent['name_token'])).display_text != parent['record_name']:
                    raise ValueError('RPC layout parent name changed during metadata export')
            for descriptor, hook in hooks:
                recheck_virtual_method(session, module_base, descriptor, hook)
            result.update(layout=layout, layout_status='exported_existing')
        if lookup_weak_key_table(session, driver_address + RPC_LAYOUT_TABLE_OFFSET,
                                 key, value_kind='layout') != selected:
            raise ValueError('RPC function layout mapping changed during export')
        if (object_identity(address, 'Function') != identity or
                weak_object_key(session.read, module_base, address) != key or
                session.read(address + RPC_FUNCTION_FLAGS_OFFSET, 4) != flags or
                object_name(session.read, module_base, address, field_representation=1).display_text != name):
            raise ValueError('RPC Function identity, flags or name changed during metadata export')
        result['identity_and_fields_rechecked'] = True
        final_checks.append((address, name, identity, key, flags, selected,
                             result.get('layout')))
        exports.append(result)
    # A later function's export cannot silently invalidate an earlier function.
    # No metadata is published until this whole scoped set has passed its tail.
    def final_recheck():
        for address, name, identity, key, flags, selected, layout in final_checks:
            if (object_identity(address, 'Function') != identity or
                    object_name(session.read, module_base, address, field_representation=1).display_text != name):
                raise ValueError('RPC Function identity or name changed at final recheck')
            if key is not None:
                if (weak_object_key(session.read, module_base, address) != key or
                        session.read(address + RPC_FUNCTION_FLAGS_OFFSET, 4) != flags or
                        lookup_weak_key_table(session, driver_address + RPC_LAYOUT_TABLE_OFFSET,
                            key, value_kind='layout') != selected):
                    raise ValueError('RPC Function flags or layout mapping changed at final recheck')
                if layout is not None:
                    repeated = export_replayout(session, selected['value_address'])
                    if any(repeated[field] != layout[field] for field in (
                            'parents_sha256', 'commands_sha256', 'parent_count', 'command_count')):
                        raise ValueError('RPC RepLayout changed at final recheck')
                    for parent in layout['parents']:
                        if resolve_name(session.read, module_base, bytes.fromhex(parent['name_token'])).display_text != parent['record_name']:
                            raise ValueError('RPC layout parent name changed at final recheck')
                    for row in layout['parents'] + layout['commands']:
                        if row.get('descriptor_name') is not None and object_name(
                                session.read, module_base, row['descriptor_address'],
                                field_representation=0).display_text != row['descriptor_name']:
                            raise ValueError('RPC parameter descriptor name changed at final recheck')
                        for hook_name in ('property_serializer_hook', 'property_scalar_leaf_hook'):
                            if hook_name in row:
                                recheck_virtual_method(session, module_base, row['descriptor_address'], row[hook_name])
    final_recheck()
    if _final_recheck_sink is not None:
        _final_recheck_sink.append(final_recheck)
    return exports


def export_bound_connection_guid_mappings(session, module_base, roots, observations, *,
                                          object_identity, recheck_roots,
                                          additional_static_guids=(), _current_owned_gp_selection=None):
    """Observe existing GUID2/4/6 associations of the original typed primary C/D.

    Selection matches the cache branch's current GPNetDriver qualifications.
    Its callbacks recheck admitted metadata only; no second registry scan or
    native GetObjectFromNetGUID invocation is performed.
    """
    from native_guid_object_metadata import observe_connection_guid_mappings
    eligible = _qualified_bound_gp_driver_candidates(roots, observations)
    if not eligible:
        return {'status': 'missing_observed_primary_gp_net_driver',
                'fixed_dynamic_guids': [2, 4, 6], 'mappings': [],
                'native_getter_invoked': False, 'native_spawn_verified': False,
                'actor_role_or_ownership_inferred': False, 'snapshot_atomic': False}
    selection = _use_current_owned_gp_driver_selection(_current_owned_gp_selection, session, module_base, roots, observations,
        object_identity=object_identity, recheck_roots=recheck_roots)
    if selection is not None:
        eligible = [selection.choice]
    if len(eligible) != 1:
        raise ValueError('Current primary GPNetDriver is ambiguous for GUID observation')
    if not callable(object_identity) or not callable(recheck_roots):
        raise ValueError('GUID observation requires the original typed identity callbacks')
    driver, connection, observed = eligible[0]
    identities = [row for row in observed.get('identity_qualification', [])
                  if row.get('address') == hex(connection)
                  and row.get('expected_base_class') == 'NetConnection']
    if len(identities) != 1:
        raise ValueError('Current GUID connection has no unique observed registry identity')
    original_connection = identities[0]

    def recheck():
        if selection is not None:
            selection.recheck()
        recheck_roots()
        identity = object_identity(connection, 'NetConnection')
        if (identity['object_index'], identity['serial']) != (
                original_connection['object_index'], original_connection['serial']):
            raise ValueError('Current GUID connection registry identity changed')
        record = validate_object_record(session.read, module_base, driver['address'])
        if (record.index, record.serial) != (driver['object_index'], driver['serial']):
            raise ValueError('Current GUID driver registry identity changed')
        if session.pointer(driver['address'] + 8) != driver['class_address']:
            raise ValueError('Current GUID driver type changed')

    result = observe_connection_guid_mappings(session, module_base,
        driver_address=driver['address'], connection_address=connection,
        recheck_binding=recheck,
        **({'additional_static_guids': additional_static_guids} if additional_static_guids else {}))

    if selection is not None:
        selection.recheck()
    return result


def export_bound_connection_gp_bind_gate(session, module_base, roots, observations, mapping, *,
                                         object_identity, recheck_roots, _current_owned_gp_selection=None):
    """Observe the small native GP bind state of the current mapped typed PC.

    The GUID and typed-root callbacks retain the original session and identities.
    This does not execute the open hook or infer its earlier return value.
    """
    from native_gp_bind_gate import observe_gp_bind_gate
    refused = {'status': 'not_observed', 'native_dispatch_executed': False,
               'binding_verified': False, 'snapshot_atomic': False}
    if mapping.get('status') != 'existing_guid_associations_observed':
        return {**refused, 'reason': 'current_primary_connection_guid_mapping_missing'}
    guid_rows = [row for row in mapping.get('mappings', []) if row.get('guid') == 4]
    if len(guid_rows) != 1:
        raise ValueError('Current GUID4 association is ambiguous for GP bind observation')
    guid4 = guid_rows[0]
    if guid4.get('status') != 'existing_object_observed':
        return {**refused, 'reason': 'current_guid4_object_missing_or_weak_unresolved'}
    candidates = [row for row in observations.get('player_controllers', [])
                  if row.get('status') == 'observed'
                  and row.get('identity_and_fields_rechecked') is True
                  and row.get('address') == hex(guid4['object_address'])
                  and row.get('object_index') == guid4['object_index']]
    if not candidates:
        return {**refused, 'reason': 'guid4_has_no_matching_typed_pc_observation'}
    if len(candidates) != 1:
        raise ValueError('Current GUID4 typed PC observation is ambiguous')
    pc = candidates[0]
    driver = mapping['driver_address']
    connection = mapping['connection_address']
    if (pc.get('driver') != hex(driver) or pc.get('connection') != hex(connection) or
            pc.get('driver_primary_connection') != hex(connection)):
        raise ValueError('Current mapped PC disagrees with the original primary connection')
    required = ((driver, 'NetDriver'), (connection, 'NetConnection'),
                (guid4['object_address'], 'PlayerController'))
    identities = {}
    for address, base_class in required:
        matching = [row for row in pc.get('identity_qualification', [])
                    if row.get('address') == hex(address)
                    and row.get('expected_base_class') == base_class]
        if len(matching) != 1:
            raise ValueError('GP bind observation lacks an original typed identity')
        identities[address, base_class] = matching[0]
    if identities[guid4['object_address'], 'PlayerController']['serial'] != guid4['serial']:
        raise ValueError('Current GUID4 PC serial disagrees with the typed observation')
    if not callable(object_identity) or not callable(recheck_roots):
        raise ValueError('GP bind observation requires original typed root callbacks')

    def checked_identity(address, base_class):
        recheck_roots()
        expected = identities.get((address, base_class))
        if expected is None:
            raise ValueError('GP bind reader requested an unqualified object')
        current = object_identity(address, base_class)
        if (current['object_index'], current['serial']) != (
                expected['object_index'], expected['serial']):
            raise ValueError('GP bind object identity changed')
        return current

    def recheck_guid4():
        current = export_bound_connection_guid_mappings(session, module_base, roots, observations,
            object_identity=object_identity, recheck_roots=recheck_roots,
            _current_owned_gp_selection=_current_owned_gp_selection)
        if (current.get('status') != 'existing_guid_associations_observed' or
                current.get('driver_address') != driver or
                current.get('connection_address') != connection):
            raise ValueError('GP bind current primary connection changed')
        rows = [row for row in current.get('mappings', []) if row.get('guid') == 4]
        if len(rows) != 1:
            raise ValueError('GP bind current GUID4 association is ambiguous')
        return rows[0]

    return observe_gp_bind_gate(session, module_base, driver_address=driver,
        connection_address=connection, pc_address=guid4['object_address'],
        object_identity=checked_identity, recheck_guid4_mapping=recheck_guid4)


def export_bound_first_player_state(session, module_base, roots, observations, *, object_identity,
                                    recheck_roots, _current_owned_gp_selection=None):
    from native_gp_first_player_state import observe_first_player_state
    candidates = [row for row in observations['player_controllers']
        if row.get('status') == 'observed' and row.get('identity_and_fields_rechecked') is True
        and row.get('driver_primary_matches_original_connection') is True
        and type(row.get('local_player_index_field')) is int
        and row['local_player_index_field'] == 0]
    selection = None
    if _current_owned_gp_selection is not None:
        selection = _use_current_owned_gp_driver_selection(_current_owned_gp_selection, session, module_base, roots, observations,
            object_identity=object_identity, recheck_roots=recheck_roots)
        candidates = [selection.player_controller]
    if len(candidates) != 1 or not callable(object_identity) or not callable(recheck_roots):
        return {'status': 'not_observed', 'reason': 'unique_current_primary_pc_required'}
    pc = candidates[0]
    recheck_roots()
    result = observe_first_player_state(session, module_base,
        driver_address=int(pc['driver'], 16), connection_address=int(pc['connection'], 16),
        pc_address=int(pc['address'], 16), object_identity=object_identity)
    if result['status'] == 'observed':
        # Resolve class metadata of the typed, rechecked PlayerState reference.
        # It may be absent in our three-Actor bootstrap. No class path is guessed.
        for key, expected in (('pc_player_state_reference', 'PlayerState'),
                              ('pc_pawn_reference', 'Pawn')):
            ref = result[key]
            if ref['status'] == 'typed_existing_reference':
                before = object_identity(ref['address'], expected)
                ref['class_asset_path'] = object_path(session.read, module_base, ref['class_address'])
                if object_identity(ref['address'], expected) != before:
                    raise ValueError('First-player Actor reference changed during class-path read')
        repeated = observe_first_player_state(session, module_base,
            driver_address=int(pc['driver'], 16), connection_address=int(pc['connection'], 16),
            pc_address=int(pc['address'], 16), object_identity=object_identity)
        comparable = lambda row: {k: v for k, v in row.items() if k not in ('read_calls', 'read_bytes')}
        original = {**result}
        original['pc_player_state_reference'] = {k: v for k, v in result['pc_player_state_reference'].items()
                                               if k != 'class_asset_path'}
        original['pc_pawn_reference'] = {k: v for k, v in result['pc_pawn_reference'].items()
                                       if k != 'class_asset_path'}
        if comparable(original) != comparable(repeated):
            raise ValueError('First-player state changed while exporting class paths')
    recheck_roots()
    if selection is not None:
        selection.recheck()
    return result


def export_bound_controller_world_settings(session, roots, observations, *, object_identity, recheck_roots, _current_owned_gp_selection=None):
    """Select an actual primary GP controller before following its owning Level."""
    from native_world_settings_context import observe_controller_world_settings
    drivers = {row['address'] for row in roots['drivers'] if 'GPNetDriver' in row['class_chain']}
    selected = [row for row in observations['player_controllers']
        if row.get('status') == 'observed' and row.get('identity_and_fields_rechecked') is True
        and row.get('driver_primary_matches_original_connection') is True
        and row.get('connection_pc_is_this_pc') is True
        and type(row.get('local_player_index_field')) is int and row['local_player_index_field'] == 0
        and int(row['driver'], 16) in drivers]
    selection = None
    if _current_owned_gp_selection is not None:
        if type(_current_owned_gp_selection) is not _CurrentOwnedGPDriverSelection:
            raise ValueError('Exact private current GP owner selection required')
        selection = _use_current_owned_gp_driver_selection(_current_owned_gp_selection, session,
            _current_owned_gp_selection.context[1], roots, observations,
            object_identity=object_identity, recheck_roots=recheck_roots)
        selected = [selection.player_controller]
    if len(selected) != 1 or not callable(object_identity) or not callable(recheck_roots):
        return {'status': 'not_observed', 'reason': 'unique_current_primary_gp_controller_required'}
    recheck_roots()
    result = observe_controller_world_settings(session, pc_address=int(selected[0]['address'], 16),
        object_identity=object_identity)
    recheck_roots()
    if selection is not None:
        selection.recheck()
    return result


def export_connection_binding_metadata(session, module_base, *, class_net_cache=False,
                                       rpc_layouts=False, guid_mappings=False,
                                       first_player_state=False, world_context=False,
                                       _diagnostic_sink=None, _phase_callback=None):
    """One registry pass, optional existing associations and current PC/GS caches."""
    if (type(class_net_cache) is not bool or type(rpc_layouts) is not bool or
            type(guid_mappings) is not bool or type(first_player_state) is not bool
            or type(world_context) is not bool
            or rpc_layouts and not class_net_cache):
        raise ValueError('Connection cache observation requires an explicit boolean mode')
    if _diagnostic_sink is not None and (type(_diagnostic_sink) is not dict or _diagnostic_sink):
        raise ValueError('GUID diagnostics require a private empty dictionary sink')
    if _phase_callback is not None and not callable(_phase_callback):
        raise ValueError('Collection phase diagnostics require an internal callback')
    phase = _phase_callback or (lambda name, completed: None)
    identity_sink = {}
    phase('binding_root_discovery', False)
    roots = discover_roots(session, module_base, connection_binding_only=True,
        **({'first_player_state': True} if first_player_state else {}),
        **({'unpublished_batch_retry': True} if world_context else {}),
        **({'subworld_context': True} if world_context else {}),
        **({'_binding_identity_sink': identity_sink}
           if class_net_cache or guid_mappings or first_player_state or world_context else {}))
    observations = roots.pop('connection_binding_observations')
    phase('binding_root_discovery', True)
    current_owned_gp_selection = _prepare_current_owned_gp_driver_selection(session, module_base, roots, observations,
        object_identity=identity_sink.get('callback'), recheck_roots=identity_sink.get('recheck_roots')) if class_net_cache or guid_mappings else None
    subworld_context_observation = None
    if world_context:
        from native_loading_subworld_context import observe_subworld_contexts
        phase('subworld_context_observation', False)
        subworld_context_observation = observe_subworld_contexts(session,
            roots.get('subworld_context_instance_candidates', []),
            object_identity=identity_sink.get('callback'),
            resolve_fname=lambda token: resolve_name(session.read, module_base, token).display_text)
        identity_sink['recheck_roots']()
        phase('subworld_context_observation', True)
    controller_world_settings = None
    if world_context or first_player_state and guid_mappings and class_net_cache:
        phase('controller_world_settings_observation', False)
        controller_world_settings = export_bound_controller_world_settings(session, roots, observations,
            object_identity=identity_sink.get('callback'), recheck_roots=identity_sink.get('recheck_roots'), _current_owned_gp_selection=current_owned_gp_selection)
        phase('controller_world_settings_observation', True)
    first_player_observation = None
    pawn_world_settings = None
    if first_player_state:
        phase('first_player_state_observation', False)
        first_player_observation = export_bound_first_player_state(session, module_base, roots,
            observations, object_identity=identity_sink.get('callback'),
            recheck_roots=identity_sink.get('recheck_roots'), _current_owned_gp_selection=current_owned_gp_selection)
        phase('first_player_state_observation', True)
        if (world_context or guid_mappings and class_net_cache) and first_player_observation.get('status') == 'observed':
            pawn = first_player_observation.get('pc_pawn_reference', {})
            if pawn.get('status') == 'typed_existing_reference':
                from native_world_settings_context import observe_actor_level_world_settings
                phase('pawn_world_settings_observation', False)
                pawn_world_settings = observe_actor_level_world_settings(session,
                    actor_address=pawn['address'], actor_base_class='Pawn',
                    object_identity=identity_sink.get('callback'))
                phase('pawn_world_settings_observation', True)
    mapping, gate_observation, world_settings_context = None, None, None
    static_guids = ()
    if first_player_state and guid_mappings and class_net_cache:
        from native_static_world_settings import LOCAL_GUID
        static_guids = (LOCAL_GUID,)
    if guid_mappings:
        phase('guid_mapping_first', False)
        mapping = export_bound_connection_guid_mappings(session, module_base, roots, observations,
            object_identity=identity_sink.get('callback'),
            recheck_roots=identity_sink.get('recheck_roots'),
            **({'additional_static_guids': static_guids} if static_guids else {}), _current_owned_gp_selection=current_owned_gp_selection)
        phase('guid_mapping_first', True)
        if (_diagnostic_sink is not None and
                mapping['status'] == 'existing_guid_associations_observed'):
            # This separately completed observation remains an earlier diagnostic
            # if later table reads fail. It is never a partially accepted profile
            # and does not claim that the mapping is still current at refusal.
            _diagnostic_sink.update(accepted_as_profile=False,
                observation_stage='before_class_cache_or_rpc_tables',
                current_at_refusal_verified=False, observation=mapping)
        phase('gp_bind_gate_observation', False)
        gate_observation = export_bound_connection_gp_bind_gate(session, module_base, roots,
            observations, mapping, object_identity=identity_sink.get('callback'),
            recheck_roots=identity_sink.get('recheck_roots'), _current_owned_gp_selection=current_owned_gp_selection)
        phase('gp_bind_gate_observation', True)
        if _diagnostic_sink is not None and _diagnostic_sink:
            _diagnostic_sink['gp_bind_gate_observation'] = gate_observation
        if static_guids:
            from native_world_settings_context import observe_world_settings_context
            phase('world_settings_context_observation', False)
            world_settings_context = observe_world_settings_context(session, mapping,
                object_identity=identity_sink.get('callback'))
            phase('world_settings_context_observation', True)
    exports, scope = [], None
    if class_net_cache:
        phase('class_cache_rpc_layouts', False)
        exports, scope = export_bound_connection_class_caches(session, module_base, roots, observations,
            object_identity=identity_sink.get('callback'),
            recheck_roots=identity_sink.get('recheck_roots'),
            **({'rpc_layouts': True} if rpc_layouts else {}), _current_owned_gp_selection=current_owned_gp_selection)
        phase('class_cache_rpc_layouts', True)
    game_state_start = None
    if first_player_state and guid_mappings and class_net_cache:
        from native_game_state_start_observation import observe_game_state_start
        phase('game_state_begin_play_observation', False)
        game_state_start = observe_game_state_start(session, module_base, root=ROOT,
            roots=roots, exports=exports, mapping=mapping,
            object_identity=identity_sink.get('callback'))
        phase('game_state_begin_play_observation', True)
    if guid_mappings:
        phase('guid_mapping_final', False)
        repeated = export_bound_connection_guid_mappings(session, module_base, roots, observations,
            object_identity=identity_sink.get('callback'),
            recheck_roots=identity_sink.get('recheck_roots'),
            **({'additional_static_guids': static_guids} if static_guids else {}), _current_owned_gp_selection=current_owned_gp_selection)
        semantic = lambda row: {key: value for key, value in row.items()
                                if key not in ('read_calls', 'read_bytes')}
        if semantic(repeated) != semantic(mapping):
            raise ValueError('Current GUID association changed during later metadata export')
        mapping = repeated
        phase('guid_mapping_final', True)
    if current_owned_gp_selection is not None:
        current_owned_gp_selection.recheck()
    return {'roots': roots, 'connection_binding_observations': observations,
            **({'subworld_context_observation': subworld_context_observation}
               if subworld_context_observation is not None else {}),
            **({'controller_world_settings_observation': controller_world_settings}
               if controller_world_settings is not None else {}),
            **({'pawn_world_settings_observation': pawn_world_settings}
               if pawn_world_settings is not None else {}),
            **({'first_player_state_observation': first_player_observation}
               if first_player_state else {}),
            **({'game_state_begin_play_observation': game_state_start}
               if game_state_start is not None else {}),
            **({'world_settings_context_observation': world_settings_context}
               if world_settings_context is not None else {}),
            **({'connection_guid_mapping_observation': mapping} if guid_mappings else {}),
            **({'connection_binding_gate_observation': gate_observation} if guid_mappings else {}),
            'driver_class_exports': exports,
            'class_cache_exports': sum(item['cache_status'] == 'exported_existing' for item in exports),
            'replication_layout_exports': 0,
            **({'rpc_function_layout_exports': sum(function['layout_status'] == 'exported_existing'
                    for row in exports for function in row.get('rpc_functions', [])),
                'rpc_parameter_values_read': False} if rpc_layouts else {}),
            **({'connection_class_net_cache_scope': scope} if class_net_cache else {}),
            'driver_tables_read': bool(class_net_cache and scope['driver_tables_read']),
            'diagnostic_binding_fields_read': True,
            'local_player_index_read': True, 'player_property_values_read': True,
            'arbitrary_player_property_values_read': False}


def save(folder, report):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'result.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def collection_duration(maximum_seconds=None, *, connection_tables=False):
    """One bounded policy for both the report and the read-only backend."""
    value = ((MAX_CONNECTION_CLASS_CACHE_SECONDS if connection_tables else MAX_DURATION_SECONDS)
             if maximum_seconds is None else maximum_seconds)
    if type(value) is not int or not 10 <= value <= MAX_CONFIGURED_DURATION_SECONDS:
        raise ValueError('Metadata collection duration must be an integer from 10 to 600 seconds')
    return value


def collect(game_root, folder, *, pid, created_at, actor_interface_only=False,
            connection_binding_only=False, reference_conditions=False,
            connection_class_net_cache=False, connection_rpc_layouts=False,
            connection_guid_mappings=False, connection_first_player_state=False,
            maximum_seconds=None, connection_world_context=False,
            bootstrap_registry_batch_retry=False, bootstrap_templates_only=False):
    report = {'kind': 'existing_native_replication_metadata_export', 'client_sha256': SHIPPING_SHA256,
              'client_relative_to_game_root': EXECUTABLE_RELATIVE.as_posix(),
              'observed_at_utc': datetime.now(timezone.utc).isoformat(),
              'requested_pid': pid, 'game_modified': False, 'process_memory_written': False,
              'native_getter_invoked': False, 'credential_memory_read': False,
              'player_property_values_read': False, 'snapshot_atomic': False,
              'player_spawn_verified': False, 'playable_map_verified': False,
              'dynamic_address_switch_cvar_observation': {
                  'rva': hex(DYNAMIC_ADDRESS_SWITCH_CVAR_RVA), 'value': None, 'status': 'not_attempted'},
              'status': 'preflight', 'maximum_duration_seconds': None}
    report['observation_mode'] = ('bootstrap_templates_only' if bootstrap_templates_only else
                                 'connection_binding_class_net_cache_and_rpc_layouts' if connection_rpc_layouts else
                                 'connection_binding_and_class_net_cache' if connection_class_net_cache else
                                 'connection_binding_only' if connection_binding_only else
                                'pawn_interface_only' if actor_interface_only else 'replication_metadata')
    if connection_guid_mappings:
        report['connection_guid_mappings_requested'] = True
    if connection_binding_only:
        report.update(diagnostic_binding_fields_requested=True, player_property_values_read=None,
                      diagnostic_binding_fields_read=None, local_player_index_read=None,
                      arbitrary_player_property_values_read=False)
    reader, session = None, None
    discovery_diagnostics = {}
    guid_diagnostics = {}
    started = time.monotonic()
    last_discovery_progress = {}
    phase_diagnostics = {'last_phase': None, 'completed_phases': []}
    phase_start = None

    def phase(name, completed=False):
        nonlocal phase_start
        calls, amount = (session.calls, session.bytes_read) if session else (0, 0)
        if not completed:
            phase_diagnostics['last_phase'] = name
            phase_start = (name, time.monotonic(), calls, amount)
        else:
            if phase_start is None or phase_start[0] != name:
                raise ValueError('Internal collection phase order changed')
            _, stamp, initial_calls, initial_bytes = phase_start
            finished = time.monotonic()
            phase_diagnostics['completed_phases'].append({
                'phase': name, 'start_elapsed_seconds': round(stamp - started, 6),
                'end_elapsed_seconds': round(finished - started, 6),
                'elapsed_seconds': round(finished - stamp, 6),
                'read_calls': calls - initial_calls, 'read_bytes': amount - initial_bytes,
                'cumulative_read_calls': calls, 'cumulative_read_bytes': amount})
            phase_start = None

    def discovery_progress(value):
        # Counts only: no object pointers, names, account fields or partial roots.
        last_discovery_progress.clear()
        last_discovery_progress.update(value)
        last_discovery_progress.update(elapsed_seconds=round(time.monotonic() - started, 3),
            read_calls=session.calls, attempted_read_bytes=session.bytes_read,
            maximum_duration_seconds=report['maximum_duration_seconds'],
            collection_status=report['status'])
        path = Path(folder) / 'scan-progress.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix('.json.tmp')
        temporary.write_text(json.dumps(last_discovery_progress, indent=2) + '\n', encoding='utf-8')
        os.replace(temporary, path)

    phase('source_preflight')
    try:
        if (type(bootstrap_templates_only) is not bool or bootstrap_templates_only and any((
                actor_interface_only, connection_binding_only, connection_class_net_cache,
                connection_rpc_layouts, connection_guid_mappings, connection_first_player_state,
                connection_world_context, reference_conditions, bootstrap_registry_batch_retry))):
            raise ValueError('Bootstrap template collection cannot be combined with another mode')
        if (type(bootstrap_registry_batch_retry) is not bool or
                bootstrap_registry_batch_retry and (actor_interface_only or connection_binding_only)):
            raise ValueError('Bootstrap registry batch retry requires a boolean and normal full metadata mode')
        duration = collection_duration(maximum_seconds,
            connection_tables=bool(connection_class_net_cache or connection_guid_mappings))
        report['maximum_duration_seconds'] = duration
        if actor_interface_only and connection_binding_only:
            raise ValueError('Choose one optional metadata observation mode')
        if (type(connection_world_context) is not bool or
                connection_world_context and not connection_binding_only):
            raise ValueError('World context requires the typed binding observation mode')
        if connection_world_context:
            from native_world_settings_context import qualified_world_settings_context_source_pins
            report['world_context_source_pins'] = qualified_world_settings_context_source_pins(ROOT)
            from native_loading_subworld_context import qualified_subworld_context_source_pins
            report['world_context_source_pins'].update(qualified_subworld_context_source_pins(ROOT))
        if (type(connection_first_player_state) is not bool or
                connection_first_player_state and not connection_binding_only):
            raise ValueError('First-player state requires the typed binding observation mode')
        if connection_first_player_state:
            from native_gp_first_player_state import qualified_first_player_source_pins
            report['first_player_state_source_pins'] = qualified_first_player_source_pins(ROOT)
        if (type(connection_guid_mappings) is not bool or
                connection_guid_mappings and not connection_binding_only):
            raise ValueError('GUID mappings require the typed binding observation mode')
        if connection_guid_mappings:
            from native_guid_object_metadata import qualified_guid_mapping_source_pins
            report['guid_mapping_source_qualification'] = qualified_guid_mapping_source_pins(ROOT)
            from native_gp_bind_gate import qualified_gp_bind_gate_source_pins
            report['gp_bind_gate_source_pins'] = qualified_gp_bind_gate_source_pins(ROOT)
        if (type(connection_class_net_cache) is not bool or
                connection_class_net_cache and not connection_binding_only):
            raise ValueError('Connection class caches require the typed binding observation mode')
        if (type(connection_rpc_layouts) is not bool or
                connection_rpc_layouts and not connection_class_net_cache):
            raise ValueError('RPC layouts require the current connection class-cache observation mode')
        if connection_rpc_layouts:
            report['rpc_layout_source_pins'] = qualified_rpc_layout_source_pins()
        if type(reference_conditions) is not bool or reference_conditions and not connection_binding_only:
            raise ValueError('Reference conditions require the typed binding observation mode')
        if reference_conditions:
            from native_initial_associations import qualified_initial_association_source_pins
            report['reference_condition_source_pins'] = qualified_initial_association_source_pins(ROOT)
        if connection_binding_only:
            # Qualify offsets and their immutable original proofs before opening
            # a process handle. The runner also seals these sources around UAC.
            from native_connection_binding import qualified_connection_binding_source_pins
            report['binding_source_pins'] = qualified_connection_binding_source_pins(ROOT)
        executable, image_size = validate_source(game_root)
        reader = Win32MetadataReader(executable, image_size, pid, created_at,
                                     maximum_seconds=duration)
        # Include source preflight in the same budget; never leave an older
        # mode-specific 50-second limit underneath a longer declared duration.
        reader.deadline = started + duration
        session = MetadataSession(reader.read_exact)
        session.discovery_progress_callback = discovery_progress
        phase('source_preflight', True)
        if connection_binding_only:
            session.module_sha256, session.module_size = SHIPPING_SHA256, image_size
            session.reference_conditions_requested = reference_conditions
            result = export_connection_binding_metadata(session, reader.module_base,
                **({'world_context': True} if connection_world_context else {}),
                **({'class_net_cache': True} if connection_class_net_cache else {}),
                **({'rpc_layouts': True} if connection_rpc_layouts else {}),
                **({'first_player_state': True} if connection_first_player_state else {}),
                **({'guid_mappings': True, '_diagnostic_sink': guid_diagnostics}
                   if connection_guid_mappings else {}), _phase_callback=phase)
        elif bootstrap_templates_only:
            phase('bootstrap_template_observation')
            result = export_bootstrap_template_metadata(session, reader.module_base)
            phase('bootstrap_template_observation', True)
        elif actor_interface_only:
            phase('actor_interface_observation')
            result = export_actor_interface_metadata(session, reader.module_base)
            phase('actor_interface_observation', True)
        else:
            phase('replication_metadata_observation')
            report['dynamic_address_switch_cvar_observation'] = observe_dynamic_address_switch_cvar(
                session, reader.module_base, source_sha256=SHIPPING_SHA256)
            result = export_metadata(session, reader.module_base,
                discovery_diagnostics=discovery_diagnostics, before_loading_rescan=reader.verify_identity,
                remaining_time=lambda: reader.deadline - time.monotonic(),
                **({'bootstrap_registry_batch_retry': True} if bootstrap_registry_batch_retry else {}))
            phase('replication_metadata_observation', True)
        phase('final_identity_recheck')
        reader.verify_identity()
        if reader.find_module() != reader.module_base:
            raise ValueError('Loaded client module root changed during export')
        phase('final_identity_recheck', True)
        report.update(result)
        report['status'] = 'metadata_export_complete'
        report['collection_process_identity'] = {
            'pid': pid, 'created_at': float(created_at),
            'client_sha256': SHIPPING_SHA256,
            'executable_and_creation_time_rechecked': True,
            'loaded_module_rechecked': True,
        }
        report['runtime_class_cache_recovered'] = result['class_cache_exports'] > 0
        report['runtime_replication_layout_recovered'] = result['replication_layout_exports'] > 0
        report['property_serializer_schema_recovered'] = False
        if connection_rpc_layouts:
            report['runtime_rpc_layout_metadata_recovered'] = result['rpc_function_layout_exports'] > 0
            report['rpc_parameter_codec_recovered'] = False
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
            progress_snapshot = getattr(session, 'discovery_progress_snapshot', None)
            if callable(progress_snapshot):
                try:
                    discovery_progress(progress_snapshot())
                except OSError as error:
                    # A progress-file failure must not hide the collection result.
                    report['progress_write_error_type'] = type(error).__name__
        if discovery_diagnostics:
            report['loading_compensation'] = discovery_diagnostics
            if bootstrap_registry_batch_retry:
                retry_counts = [item['registry_scan']['retried_batches']
                    for item in discovery_diagnostics['attempts']]
                report['bootstrap_registry_batch_retry'] = {
                    **discovery_diagnostics['bootstrap_registry_batch_retry'],
                    'completed_discovery_passes': len(retry_counts),
                    'retried_batches_by_completed_pass': retry_counts,
                    'retried_batches_in_completed_passes': sum(retry_counts),
                    'counts_cover_completed_passes_only': True}
        if guid_diagnostics and report['status'] != 'metadata_export_complete':
            report['guid_mapping_diagnostic_before_refusal'] = guid_diagnostics
        report['collection_phase_diagnostics'] = phase_diagnostics
        if last_discovery_progress:
            report['registry_discovery_progress'] = dict(last_discovery_progress)
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        save(folder, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--pid', type=int)
    parser.add_argument('--created-at', type=float)
    parser.add_argument('--maximum-seconds', type=int, default=None,
                        help='Bounded metadata export budget, 10..600 seconds (default 180)')
    parser.add_argument('--validate-only', action='store_true')
    parser.add_argument('--actor-interface-only', action='store_true',
                        help='Only observe the source-qualified Pawn template interface binding; no driver tables')
    parser.add_argument('--bootstrap-templates-only', action='store_true',
                        help='Read five bootstrap template identities and the Pawn interface, without historical captures')
    parser.add_argument('--connection-binding-only', action='store_true',
                        help='Observe typed connection/PlayerController binding pointers and the local-player index byte')
    parser.add_argument('--connection-class-net-cache', action='store_true',
                        help='Read existing PC/GS caches from the qualified current primary driver')
    parser.add_argument('--connection-rpc-layouts', action='store_true',
                        help='Also observe seven exact PC functions and existing parameter layouts, without parameter values')
    parser.add_argument('--connection-guid-mappings', action='store_true',
                        help='Only observe existing GUID2/4/6 associations of the same qualified primary connection')
    parser.add_argument('--elevate', action='store_true', help='Request normal UAC for this reader; leave the game running')
    parser.add_argument('--elevated-source-pins', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.bootstrap_templates_only and any((args.actor_interface_only, args.connection_binding_only,
            args.connection_class_net_cache, args.connection_rpc_layouts, args.connection_guid_mappings)):
        parser.error('Bootstrap template collection cannot be combined with another mode')
    if args.actor_interface_only and args.connection_binding_only:
        parser.error('Choose one optional metadata observation mode')
    if args.connection_class_net_cache and not args.connection_binding_only:
        parser.error('Class caches require --connection-binding-only')
    if args.connection_rpc_layouts and not args.connection_class_net_cache:
        parser.error('RPC layouts require --connection-class-net-cache')
    if args.connection_guid_mappings and not args.connection_binding_only:
        parser.error('GUID mappings require --connection-binding-only')
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
            pin_options = {'actor_interface_only': args.actor_interface_only}
            if args.bootstrap_templates_only:
                pin_options['bootstrap_templates_only'] = True
            if args.connection_binding_only:
                pin_options['connection_binding_only'] = True
            if args.connection_rpc_layouts:
                pin_options['connection_rpc_layouts'] = True
            if args.connection_guid_mappings:
                pin_options['connection_guid_mappings'] = True
            actual_pins = source_pins(**pin_options)
        except (OSError, ValueError):
            refuse_preflight('Elevated metadata reader dependency could not be verified')
        if expected_pins != actual_pins:
            refuse_preflight('Elevated metadata reader source identity changed after launch preparation')
    options = {'actor_interface_only': True} if args.actor_interface_only else {}
    if args.bootstrap_templates_only:
        options['bootstrap_templates_only'] = True
    if args.maximum_seconds is not None:
        options['maximum_seconds'] = args.maximum_seconds
    if args.connection_binding_only:
        options['connection_binding_only'] = True
    if args.connection_class_net_cache:
        options['connection_class_net_cache'] = True
    if args.connection_rpc_layouts:
        options['connection_rpc_layouts'] = True
    if args.connection_guid_mappings:
        options['connection_guid_mappings'] = True
    result = collect(args.game_root, args.output, pid=args.pid, created_at=args.created_at, **options)
    print(json.dumps({key: result.get(key) for key in
                     ('status', 'reason', 'class_cache_exports', 'replication_layout_exports', 'elapsed_seconds')}))
    if result['status'] != 'metadata_export_complete':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
