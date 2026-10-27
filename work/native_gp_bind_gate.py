"""Source-qualified, callback-only observation of GP's client-player bind gate.

No process/native APIs, calls, writes or registry scan. The caller supplies the
same MetadataSession and independently rechecked typed roots and GUID4 mapping.
Repeated reads are a current diagnostic window, never an atomic or historical
dispatch proof. Special World and instrumentation branches remain unobserved.
"""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct

from native_connection_binding import (
    SHIPPING_SHA256, IMAGE_SIZE, MAX_ADDRESS, _Budget, _View, _pointer,
    ConnectionBindingObservationError,
)


SOURCE_LEDGER = 'work/evidence/map-entry-next-20261005/native-gp-bind-gate-sources.json'
SOURCE_LEDGER_SHA256 = '26f39eff25d9b8f495d2587888121d9f55d303b6d101e0da5df4db787cab8fa5'
MODULE_RELATIVE_PATH = 'work/native_gp_bind_gate.py'
DEPENDENCIES = ('work/native_connection_binding.py',)
GP_BIND_RVA = 0x49b7010
PC_OPEN_RVA = 0x12d4ddb0
MAX_FIXED_READS = 64
MAX_FIXED_BYTES = 512
MAX_IDENTITIES = 32


class GPBindGateObservationError(ConnectionBindingObservationError):
    pass


class _GateBudget(_Budget):
    def read(self, address, size):
        if self.calls >= MAX_FIXED_READS or self.bytes_read + size > MAX_FIXED_BYTES:
            raise GPBindGateObservationError('gp_gate_fixed_read_budget_exhausted')
        return super().read(address, size)

    def identity(self, address, base_class):
        if self.identity_calls >= MAX_IDENTITIES:
            raise GPBindGateObservationError('gp_gate_identity_budget_exhausted')
        return super().identity(address, base_class)


def _guid4(callback):
    try:
        row = callback()
    except (ValueError, OSError):
        raise GPBindGateObservationError('guid4_mapping_callback_refused') from None
    if (type(row) is not dict or type(row.get('guid')) is not int or row['guid'] != 4 or
            row.get('status') != 'existing_object_observed' or
            row.get('weak_identity_initialized') is not True):
        raise GPBindGateObservationError('guid4_current_existing_mapping_required')
    address = _pointer(row.get('object_address'))
    index, serial = row.get('object_index'), row.get('serial')
    if (type(index) is not int or not 0 <= index < (1 << 31) or
            type(serial) is not int or not 1 <= serial < (1 << 32)):
        raise GPBindGateObservationError('guid4_initialized_identity_required')
    return address, index, serial


def _observe(view, driver, connection, pc, guid_callback):
    # These callback class names match the existing collector's typed closure.
    view.object(driver, 'NetDriver')
    cidentity = view.object(connection, 'NetConnection')
    pidentity = view.object(pc, 'PlayerController')
    if 'GPNetConnection' not in cidentity[4]:
        raise GPBindGateObservationError('typed_gp_connection_ancestry_required')
    mapped = _guid4(guid_callback)
    if mapped != (pc, pidentity[1], pidentity[2]):
        raise GPBindGateObservationError('guid4_does_not_match_selected_pc')
    if view.ptr(driver + 0x98) != connection or view.ptr(connection + 0x58) != driver:
        raise GPBindGateObservationError('primary_connection_driver_relation_mismatch')
    if view.ptr(pc + 0x568) != connection:
        raise GPBindGateObservationError('pc_original_connection_relation_mismatch')
    if view.keep(pc + 0x524, 1)[0] != 0:
        raise GPBindGateObservationError('primary_local_player_index_zero_required')
    chook = view.method(connection, 0x2c0, GP_BIND_RVA)
    phook = view.method(pc, 0x3d8, PC_OPEN_RVA)
    if not chook['matches_saved_base_body'] or not phook['matches_saved_base_body']:
        raise GPBindGateObservationError('saved_gp_and_pc_dispatch_targets_required')
    # Current C fields may have changed since the earlier full-cache export.
    current_pc, owner = view.ptr(connection + 0x30), view.ptr(connection + 0xa8)
    if current_pc and current_pc != pc:
        view.object(current_pc, 'PlayerController')
    if owner and owner != pc:
        view.object(owner, 'Actor')
    # Qualification precedes both state reads. These are inline interface bytes,
    # not pointers, wire flags, player property values or a setter invocation.
    gate = view.keep(connection + 0x21d1, 1)[0]
    flags = view.keep(connection + 0x20b8, 1)[0]
    view.finish()
    if _guid4(guid_callback) != mapped:
        raise GPBindGateObservationError('guid4_mapping_changed')
    # A mapping callback can itself read fields; end with another bounded
    # root/field check so its execution cannot leave stale published relations.
    view.finish()
    return {
        'status': 'observed', 'driver_address': driver, 'connection_address': connection,
        'player_controller_address': pc, 'guid4_matches_selected_pc_identity': True,
        'connection_back_driver_matches': True, 'driver_primary_matches': True,
        'pc_original_connection_matches': True, 'local_player_index': 0,
        'connection_bind_hook': chook, 'player_controller_actor_open_hook': phook,
        'current_connection_player_controller': current_pc, 'current_connection_owner': owner,
        'current_connection_player_controller_equals_selected_pc': current_pc == pc,
        'current_connection_owner_equals_selected_pc': owner == pc,
        'current_connection_pc_and_owner_null': current_pc == 0 and owner == 0,
        'inline_interface_offset': 0x20b0, 'state_gate_offset': 0x21d1,
        'state_gate_raw': gate, 'flags_offset': 0x20b8, 'flags_raw': flags,
        'flags_mask4_set': bool(flags & 4),
        'ordinary_branch_if_special_and_instrumentation_inactive':
            'allows_base_call' if gate == 0 or flags & 4 else 'returns_false',
        'special_world_branch': 'unobserved', 'instrumentation_branch': 'unobserved',
        'overall_helper_result': 'unknown', 'historical_actor_open_dispatch': 'unknown',
        'identities_relations_fields_and_guid4_rechecked': True,
        'identity_qualification': view.identity_qualification(),
    }


def observe_gp_bind_gate(session, module_base, *, driver_address, connection_address,
                         pc_address, object_identity, recheck_guid4_mapping):
    """Return observed/refused diagnostic without relaxing the shared session.

    object_identity(address, base_class) must freshly verify the registry slot,
    exact selected Class/ancestry, non-CDO, Name and Outer. Class names passed are
    NetDriver/NetConnection/PlayerController (plus Actor for a different Owner).
    recheck_guid4_mapping() returns the CURRENT mapper row for GUID4, from the
    same session and connection, including initialized object_index/serial.
    The module requires GPNetConnection ancestry and both saved virtual targets.
    No native result, historical execution or binding success is reproduced.
    """
    budget = None
    try:
        base = _pointer(module_base)
        if base + IMAGE_SIZE - 1 > MAX_ADDRESS:
            raise GPBindGateObservationError('invalid_pinned_image_span')
        if (getattr(session, 'module_sha256', None) != SHIPPING_SHA256 or
                type(getattr(session, 'module_size', None)) is not int or
                session.module_size != IMAGE_SIZE):
            raise GPBindGateObservationError('pinned_image_qualification_missing_or_mismatched')
        if (not callable(getattr(session, 'read', None)) or not callable(object_identity) or
                not callable(recheck_guid4_mapping)):
            raise GPBindGateObservationError('explicit_read_identity_and_guid4_callbacks_required')
        driver, connection, pc = map(_pointer, (driver_address, connection_address, pc_address))
        if len({driver, connection, pc}) != 3:
            raise GPBindGateObservationError('distinct_typed_roots_required')
        budget = _GateBudget(session, object_identity)
        row = _observe(_View(budget, base), driver, connection, pc, recheck_guid4_mapping)
    except (ValueError, OSError) as error:
        row = {'status': 'refused', 'refusal_reason': str(error) if isinstance(
            error, ConnectionBindingObservationError) else 'read_or_identity_refused'}
    row.update(kind='source_qualified_gp_bind_gate_observation',
        source_ledger_relative_path=SOURCE_LEDGER, source_ledger_sha256=SOURCE_LEDGER_SHA256,
        source_image_sha256=SHIPPING_SHA256, read_calls=budget.calls if budget else 0,
        read_bytes=budget.bytes_read if budget else 0,
        identity_callback_calls=budget.identity_calls if budget else 0,
        atomic_snapshot=False, binding_verified=False, native_dispatch_executed=False,
        native_setter_invoked=False, process_opened_by_module=False,
        process_memory_written=False, playable_map_verified=False)
    return row


def qualified_gp_bind_gate_source_pins(root):
    """Disk-only opt-in: verify the fixed ledger and return every actual hash pin."""
    try:
        root = Path(root).resolve(strict=True)
        if not root.is_dir():
            raise GPBindGateObservationError('source_root_not_directory')
        total = 0

        def read(relative_path):
            nonlocal total
            if (type(relative_path) is not str or not 1 <= len(relative_path) <= 512 or
                    any(c in relative_path for c in ('\\', ':', '\x00')) or
                    PurePosixPath(relative_path).is_absolute() or
                    any(p in ('', '.', '..') for p in relative_path.split('/'))):
                raise GPBindGateObservationError('invalid_relative_source_path')
            path = (root / relative_path).resolve(strict=True)
            if root not in path.parents or not path.is_file():
                raise GPBindGateObservationError('source_path_outside_root_or_not_file')
            before = path.stat()
            if before.st_size > 256 * 1024 or total + before.st_size > 1024 * 1024:
                raise GPBindGateObservationError('source_byte_budget_exceeded')
            raw = path.read_bytes()
            after = path.stat()
            if (len(raw) != before.st_size or
                    (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
                raise GPBindGateObservationError('source_changed_during_read')
            total += len(raw)
            return raw

        raw = read(SOURCE_LEDGER)
        if hashlib.sha256(raw).hexdigest() != SOURCE_LEDGER_SHA256:
            raise GPBindGateObservationError('source_ledger_sha256_mismatch')
        ledger = json.loads(raw)
        if (ledger.get('kind') != 'source_qualified_gp_connection_bind_gate_ledger' or
                ledger.get('client_sha256') != SHIPPING_SHA256 or ledger.get('module_size') != IMAGE_SIZE or
                type(ledger.get('sources')) is not list or len(ledger['sources']) != 8):
            raise GPBindGateObservationError('source_ledger_identity_or_count_mismatch')
        pins = {SOURCE_LEDGER: SOURCE_LEDGER_SHA256}
        for relative in (MODULE_RELATIVE_PATH,) + DEPENDENCIES:
            contents = read(relative)
            if relative == MODULE_RELATIVE_PATH and contents != Path(__file__).read_bytes():
                raise GPBindGateObservationError('source_module_contents_mismatch')
            pins[relative] = hashlib.sha256(contents).hexdigest()
        for source in ledger['sources']:
            if type(source) is not dict:
                raise GPBindGateObservationError('invalid_source_record')
            relative, digest = source.get('relative_path'), source.get('sha256')
            if (relative in pins or type(digest) is not str or
                    re.fullmatch('[0-9a-f]{64}', digest) is None):
                raise GPBindGateObservationError('invalid_or_duplicate_source_record')
            contents = read(relative)
            if hashlib.sha256(contents).hexdigest() != digest:
                raise GPBindGateObservationError('source_file_sha256_mismatch')
            if source.get('format') in ('dfcode', 'raw_code'):
                code = contents
                if source['format'] == 'dfcode':
                    if len(contents) < 32:
                        raise GPBindGateObservationError('invalid_source_code_header')
                    magic, version, rva, length, preferred = struct.unpack('<4sIQQQ', contents[:32])
                    if (magic != b'DCDE' or version != 1 or preferred != 0x140000000 or
                            rva != int(source['root_rva'], 16) or length != source['code_bytes']):
                        raise GPBindGateObservationError('invalid_source_code_header')
                    code = contents[32:]
                if len(code) != source['code_bytes'] or hashlib.sha256(code).hexdigest() != source.get(
                        'code_sha256', digest):
                    raise GPBindGateObservationError('source_code_length_or_sha256_mismatch')
            pins[relative] = digest
        return pins
    except OSError:
        raise GPBindGateObservationError('source_file_missing_or_unreadable') from None
    except (TypeError, KeyError, UnicodeDecodeError, json.JSONDecodeError):
        raise GPBindGateObservationError('invalid_source_root_or_ledger') from None
