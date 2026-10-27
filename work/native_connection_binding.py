"""Bounded callback-only observations of the native client-player binding gates.

The caller verifies the process, pinned Shipping image and each UObject's actual
class/Outer/registry identity. This module opens no process, executes no native
method, and writes no memory. Repeated field reads are not an atomic snapshot.
No channel array or possession/RPC layout is assumed.
"""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct


SHIPPING_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
IMAGE_SIZE = 536408064
SOURCE_LEDGER = 'work/evidence/map-entry-next-20261005/connection-binding-sources.json'
SOURCE_LEDGER_SHA256 = '748285b96f454abf449cb5257c9d4f26457062a43b0f83fb22446ab23a909dad'
MODULE_RELATIVE_PATH = 'work/native_connection_binding.py'
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 4 * 1024 * 1024
PC_OPEN_BASE_RVA = 0x12d4ddb0
CONNECTION_BIND_BASE_RVA = 0x12b91a80
PC_OPEN_SLOT = 0x3d8
CONNECTION_BIND_SLOT = 0x2c0
MAX_ROOTS = 16
MAX_READ_CALLS = 4096
MAX_READ_BYTES = 128 * 1024
MAX_IDENTITY_CALLS = 512
MAX_ADDRESS = (1 << 47) - 1


class ConnectionBindingObservationError(ValueError):
    """A fixed observation or caller qualification could not be established."""


def qualified_connection_binding_source_pins(root):
    """Verify the sealed disk ledger and its 14 original source files, opt-in.

    This helper performs disk reads only when called. The observer below does
    not call it, and imports do not access files or processes. Paths are project
    relative; resolved symlinks may not escape the supplied project root.
    """
    try:
        return _qualified_source_pins(root)
    except OSError:
        raise ConnectionBindingObservationError('source_file_missing_or_unreadable') from None
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        raise ConnectionBindingObservationError('invalid_source_root_or_ledger') from None


def _qualified_source_pins(root):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ConnectionBindingObservationError('source_root_not_directory')
    total = 0

    def read_source(relative_path, maximum=MAX_SOURCE_FILE_BYTES):
        nonlocal total
        if (type(relative_path) is not str or not 1 <= len(relative_path) <= 512 or
                '\\' in relative_path or ':' in relative_path or '\x00' in relative_path):
            raise ConnectionBindingObservationError('invalid_relative_source_path')
        relative = PurePosixPath(relative_path)
        if (relative.is_absolute() or any(part in ('', '.', '..') for part in relative_path.split('/'))):
            raise ConnectionBindingObservationError('invalid_relative_source_path')
        path = (root / relative_path).resolve(strict=True)
        if root not in path.parents or not path.is_file():
            raise ConnectionBindingObservationError('source_path_outside_root_or_not_file')
        before = path.stat()
        if before.st_size > maximum or total + before.st_size > MAX_SOURCE_TOTAL_BYTES:
            raise ConnectionBindingObservationError('source_byte_budget_exceeded')
        with path.open('rb') as stream:
            raw = stream.read(maximum + 1)
        after = path.stat()
        if (len(raw) != before.st_size or len(raw) > maximum or
                (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
            raise ConnectionBindingObservationError('source_changed_or_oversized')
        total += len(raw)
        return raw

    ledger_raw = read_source(SOURCE_LEDGER, 128 * 1024)
    if hashlib.sha256(ledger_raw).hexdigest() != SOURCE_LEDGER_SHA256:
        raise ConnectionBindingObservationError('source_ledger_sha256_mismatch')
    ledger = json.loads(ledger_raw)
    if (type(ledger) is not dict or
            ledger.get('kind') != 'source_backed_map_entry_connection_binding_ledger' or
            ledger.get('client_sha256') != SHIPPING_SHA256):
        raise ConnectionBindingObservationError('source_ledger_identity_mismatch')
    sources = ledger.get('sources')
    if type(sources) is not list or len(sources) != 14:
        raise ConnectionBindingObservationError('source_ledger_requires_14_sources')
    pins = {SOURCE_LEDGER: SOURCE_LEDGER_SHA256}
    module_raw = read_source(MODULE_RELATIVE_PATH, 128 * 1024)
    with Path(__file__).open('rb') as stream:
        actual_module = stream.read(128 * 1024 + 1)
    if len(actual_module) > 128 * 1024:
        raise ConnectionBindingObservationError('source_module_oversized')
    if module_raw != actual_module:
        raise ConnectionBindingObservationError('source_module_contents_mismatch')
    pins[MODULE_RELATIVE_PATH] = hashlib.sha256(module_raw).hexdigest()
    for row in sources:
        if type(row) is not dict:
            raise ConnectionBindingObservationError('invalid_source_ledger_row')
        relative_path, digest = row.get('relative_path'), row.get('sha256')
        if (type(digest) is not str or re.fullmatch(r'[0-9a-f]{64}', digest) is None or
                type(relative_path) is not str or relative_path in pins):
            raise ConnectionBindingObservationError('invalid_or_duplicate_source_ledger_row')
        raw = read_source(relative_path)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ConnectionBindingObservationError('source_file_sha256_mismatch')
        pins[relative_path] = digest
    return pins


def _pointer(value, *, allow_null=False):
    if type(value) is str and re.fullmatch(r'0x[0-9a-fA-F]{1,16}', value):
        value = int(value, 16)
    if type(value) is not int:
        raise ConnectionBindingObservationError('invalid_pointer_value')
    if allow_null and value == 0:
        return value
    if not 0x10000 <= value <= MAX_ADDRESS or value % 8:
        raise ConnectionBindingObservationError('invalid_object_pointer')
    return value


def _uint(value, maximum, label):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ConnectionBindingObservationError('invalid_' + label)
    return value


def _identity(row, address, expected_base_class):
    if type(row) is not dict:
        raise ConnectionBindingObservationError('identity_callback_record_required')
    if _pointer(row.get('address')) != address:
        raise ConnectionBindingObservationError('identity_address_mismatch')
    index = _uint(row.get('object_index'), (1 << 31) - 1, 'object_index')
    serial = _uint(row.get('serial'), (1 << 32) - 1, 'serial')
    klass = _pointer(row.get('class_address'))
    if row.get('is_cdo') is not False:
        raise ConnectionBindingObservationError('actual_instance_not_qualified')
    chain = row.get('class_ancestry')
    if type(chain) not in (list, tuple) or not 1 <= len(chain) <= 32:
        raise ConnectionBindingObservationError('class_ancestry_not_qualified')
    names = []
    for entry in chain:
        name = entry.get('name') if type(entry) is dict else entry
        if type(name) is not str or not 1 <= len(name) <= 256 or any(
                char in name for char in '\x00\r\n'):
            raise ConnectionBindingObservationError('class_ancestry_not_qualified')
        names.append(name)
    if expected_base_class not in names:
        raise ConnectionBindingObservationError('expected_base_class_missing')
    name = row.get('name')
    if (type(name) is not str or not 1 <= len(name) <= 256 or
            any(char in name for char in '\x00\r\n')):
        raise ConnectionBindingObservationError('object_name_not_qualified')
    outer = _pointer(row.get('outer_address'), allow_null=True)
    outer_path = row.get('outer_path')
    if outer_path is not None and (type(outer_path) is not str or len(outer_path) > 4096 or
                                  any(char in outer_path for char in '\x00\r\n')):
        raise ConnectionBindingObservationError('object_outer_path_not_qualified')
    # Keep only metadata identity; never retain arbitrary callback account data.
    return (address, index, serial, klass, tuple(names), name, outer, outer_path)


class _Budget:
    def __init__(self, session, callback):
        self.session, self.callback = session, callback
        self.calls = self.bytes_read = self.identity_calls = 0
        self.object_facts = {}
        self.changed_objects = set()

    def read(self, address, size):
        if (type(address) is not int or type(size) is not int or
                size not in (1, 8) or not 0x10000 <= address <= MAX_ADDRESS or
                address + size - 1 > MAX_ADDRESS):
            raise ConnectionBindingObservationError('invalid_fixed_read_span')
        if self.calls >= MAX_READ_CALLS or self.bytes_read + size > MAX_READ_BYTES:
            raise ConnectionBindingObservationError('observation_read_budget_exhausted')
        self.calls += 1
        self.bytes_read += size
        raw = self.session.read(address, size)
        if type(raw) is not bytes or len(raw) != size:
            raise ConnectionBindingObservationError('incomplete_fixed_read')
        return raw

    def identity(self, address, base_class):
        if address in self.changed_objects:
            raise ConnectionBindingObservationError('object_identity_changed')
        if self.identity_calls >= MAX_IDENTITY_CALLS:
            raise ConnectionBindingObservationError('observation_identity_budget_exhausted')
        self.identity_calls += 1
        try:
            row = self.callback(address, base_class)
        except (ValueError, OSError):
            raise ConnectionBindingObservationError('object_identity_callback_refused') from None
        value = _identity(row, address, base_class)
        if address in self.object_facts and self.object_facts[address] != value:
            self.changed_objects.add(address)
            raise ConnectionBindingObservationError('object_identity_changed')
        self.object_facts[address] = value
        return value


class _View:
    def __init__(self, budget, module_base):
        self.budget, self.base = budget, module_base
        self.fields, self.objects = {}, {}

    def keep(self, address, size):
        raw = self.budget.read(address, size)
        key = (address, size)
        if key in self.fields and raw != self.fields[key]:
            raise ConnectionBindingObservationError('pointer_or_field_changed')
        self.fields[key] = raw
        return raw

    def ptr(self, address):
        return _pointer(struct.unpack('<Q', self.keep(address, 8))[0], allow_null=True)

    def object(self, address, base_class, selected=None):
        address = _pointer(address)
        value = self.budget.identity(address, base_class)
        key = (address, base_class)
        if key in self.objects and self.objects[key] != value:
            raise ConnectionBindingObservationError('object_identity_changed')
        if selected is not None:
            if (selected['object_index'] != value[1] or selected['serial'] != value[2]):
                raise ConnectionBindingObservationError('selected_object_identity_changed')
            if 'class_address' in selected and selected['class_address'] != value[3]:
                raise ConnectionBindingObservationError('selected_object_class_changed')
        self.objects[key] = value
        return value

    def method(self, address, slot, known_rva):
        table = self.ptr(address)
        if not table:
            raise ConnectionBindingObservationError('null_vtable')
        if not self.base <= table <= self.base + IMAGE_SIZE - slot - 8:
            raise ConnectionBindingObservationError('vtable_outside_pinned_image')
        # Function pointers need not be aligned like UObject/vtable pointers.
        target = struct.unpack('<Q', self.keep(table + slot, 8))[0]
        if not target:
            raise ConnectionBindingObservationError('null_virtual_target')
        if not self.base <= target < self.base + IMAGE_SIZE:
            raise ConnectionBindingObservationError('virtual_target_outside_pinned_image')
        rva = target - self.base
        return {'slot': slot, 'target_rva': rva,
                'matches_saved_base_body': rva == known_rva,
                'inside_pinned_image': True, 'executable_image_verified': False,
                'dispatch_executed': False}

    def finish(self):
        for (address, base_class), expected in self.objects.items():
            if self.budget.identity(address, base_class) != expected:
                raise ConnectionBindingObservationError('object_identity_changed')
        for (address, size), raw in self.fields.items():
            if self.budget.read(address, size) != raw:
                raise ConnectionBindingObservationError('pointer_or_field_changed')

    def identity_qualification(self):
        # Registry-live serial0 is observable, but is not a native weak key.
        # Equality of our bounded repeated reads proves no serial continuity.
        return [{'address': hex(value[0]), 'object_index': value[1],
                 'serial': value[2], 'expected_base_class': base_class,
                 'weak_identity_initialized': value[2] != 0,
                 'native_serial_continuity_proved': False}
                for (_, base_class), value in self.objects.items()]


def _root(row, *, require_class=False):
    if type(row) is not dict:
        raise ConnectionBindingObservationError('selected_root_record_required')
    result = {'address': _pointer(row.get('address')),
              'object_index': _uint(row.get('object_index'), (1 << 31) - 1, 'object_index'),
              'serial': _uint(row.get('serial'), (1 << 32) - 1, 'serial')}
    if require_class or 'class_address' in row:
        result['class_address'] = _pointer(row.get('class_address'))
    return result


def _driver(view, root):
    driver = root['address']
    view.object(driver, 'NetDriver', root)
    connection = view.ptr(driver + 0x98)
    row = {'address': hex(driver), 'object_index': root['object_index'],
           'primary_connection': hex(connection), 'status': 'observed'}
    if not connection:
        row.update(status='unavailable', refusal_reason='primary_connection_null',
                   diagnostic_branch='no_primary_connection_field_observed')
        return row
    view.object(connection, 'NetConnection')
    back_driver = view.ptr(connection + 0x58)
    if back_driver != driver:
        raise ConnectionBindingObservationError('primary_connection_has_foreign_driver')
    current_pc, owner = view.ptr(connection + 0x30), view.ptr(connection + 0xa8)
    if current_pc:
        view.object(current_pc, 'PlayerController')
    if owner:
        view.object(owner, 'Actor')
    row.update(connection_back_driver_matches=True, player_controller=hex(current_pc),
               owner=hex(owner), player_controller_equals_owner=bool(current_pc and current_pc == owner),
               connection_bind_hook=view.method(connection, CONNECTION_BIND_SLOT, CONNECTION_BIND_BASE_RVA),
               diagnostic_branch=('connection_pc_and_owner_null' if not current_pc and not owner
                                  else 'connection_fields_observed'))
    if getattr(view.budget.session, 'reference_conditions_requested', False):
        from native_reference_conditions import observe_reference_conditions
        try:
            row['reference_conditions'] = observe_reference_conditions(view, connection)
        except ValueError:
            # Preserve independent PC binding facts while refusing an unqualified
            # PackageMap variant. Final repeated reads still reject changed data.
            row['reference_conditions'] = {'status': 'refused',
                'reason': 'reference_receiver_conditions_not_qualified',
                'native_reference_assignment_verified': False}
    return row


def _pc(view, root, selected_driver_addresses):
    pc = root['address']
    view.object(pc, 'PlayerController', root)
    index = view.keep(pc + 0x524, 1)[0]
    connection = view.ptr(pc + 0x568)
    row = {'address': hex(pc), 'object_index': root['object_index'], 'status': 'observed',
           'local_player_index_field': index, 'connection': hex(connection),
           'actor_open_hook': view.method(pc, PC_OPEN_SLOT, PC_OPEN_BASE_RVA)}
    if not connection:
        row.update(status='unavailable', refusal_reason='pc_connection_null',
                   diagnostic_branch='pc_connection_field_null')
        return row
    view.object(connection, 'NetConnection')
    driver = view.ptr(connection + 0x58)
    if not driver:
        raise ConnectionBindingObservationError('pc_connection_driver_null')
    if driver not in selected_driver_addresses:
        raise ConnectionBindingObservationError('pc_connection_has_unselected_driver')
    view.object(driver, 'NetDriver')
    primary = view.ptr(driver + 0x98)
    current_pc, owner = view.ptr(connection + 0x30), view.ptr(connection + 0xa8)
    if current_pc:
        view.object(current_pc, 'PlayerController')
    if owner:
        view.object(owner, 'Actor')
    same_primary = primary == connection
    row.update(driver=hex(driver), driver_primary_connection=hex(primary),
               driver_primary_matches_original_connection=same_primary,
               connection_pc_is_this_pc=current_pc == pc, connection_owner_is_this_pc=owner == pc,
               connection_bind_hook=view.method(connection, CONNECTION_BIND_SLOT, CONNECTION_BIND_BASE_RVA),
               diagnostic_branch=('saved_base_hook_primary_connection_gate_would_return'
                                  if not same_primary else 'nonzero_index_uses_child_connection_branch'
                                  if index else 'saved_base_primary_index_zero_gate_fields_observed'))
    return row


def observe_connection_bindings(session, module_base, drivers, player_controllers, *, object_identity):
    """Observe source-backed fields on caller-qualified actual instances only.

    session.module_sha256/module_size must reflect the caller's actual pinned PE
    validation. object_identity(address, expected_base_class) rechecks registry,
    non-CDO/type/Outer/name ancestry and returns address/index/serial/class facts,
    name and outer_address. An optional outer_path is also stability checked.
    Registry-live serial0 is allowed and explicitly marked as weak identity not
    initialized; exact serial changes, including 0-to-nonzero, are refused.
    Results never certify native serial continuity, dispatch, gameplay readiness,
    possession or atomicity. No native serial allocation is performed.
    """
    base = _pointer(module_base)
    if base + IMAGE_SIZE - 1 > MAX_ADDRESS:
        raise ConnectionBindingObservationError('invalid_pinned_image_span')
    if (getattr(session, 'module_sha256', None) != SHIPPING_SHA256 or
            type(getattr(session, 'module_size', None)) is not int or session.module_size != IMAGE_SIZE):
        raise ConnectionBindingObservationError('pinned_image_qualification_missing_or_mismatched')
    if not callable(getattr(session, 'read', None)) or not callable(object_identity):
        raise ConnectionBindingObservationError('explicit_read_and_identity_callbacks_required')
    for roots in (drivers, player_controllers):
        if type(roots) not in (list, tuple) or len(roots) > MAX_ROOTS:
            raise ConnectionBindingObservationError('invalid_bounded_root_list')
    budget = _Budget(session, object_identity)
    normalized = [[], []]
    results = [[], []]
    for group, roots in enumerate((drivers, player_controllers)):
        seen = set()
        for candidate in roots:
            try:
                root = _root(candidate, require_class=group == 1)
                if root['address'] in seen:
                    raise ConnectionBindingObservationError('duplicate_selected_object')
                seen.add(root['address'])
                normalized[group].append(root)
            except ConnectionBindingObservationError as error:
                results[group].append({'status': 'refused', 'refusal_reason': str(error)})
    driver_addresses = {root['address'] for root in normalized[0]}
    pending = []
    for group, roots in enumerate(normalized):
        for root in roots:
            view = _View(budget, base)
            try:
                row = (_driver(view, root) if group == 0 else _pc(view, root, driver_addresses))
                pending.append((view, row))
            except (ValueError, OSError) as error:
                row = {'address': hex(root['address']), 'object_index': root['object_index'],
                       'status': 'refused', 'refusal_reason': str(error) if isinstance(
                           error, ConnectionBindingObservationError) else 'read_or_identity_refused'}
            results[group].append(row)
    # Final rechecks apply only to observations we would publish. A failed root
    # cannot invalidate an unrelated observed root, nor publish partial bindings.
    for view, row in pending:
        try:
            view.finish()
            row['identity_and_fields_rechecked'] = True
            row['identity_qualification'] = view.identity_qualification()
            row['weak_identity_uninitialized_addresses'] = sorted({
                item['address'] for item in row['identity_qualification']
                if not item['weak_identity_initialized']})
        except (ValueError, OSError) as error:
            address, index = row['address'], row['object_index']
            row.clear()
            row.update(address=address, object_index=index, status='refused',
                       refusal_reason=str(error) if isinstance(error, ConnectionBindingObservationError)
                       else 'read_or_identity_refused')
    return {'kind': 'source_qualified_connection_binding_observation',
            'source_ledger_relative_path': SOURCE_LEDGER, 'source_image_sha256': SHIPPING_SHA256,
            'drivers': results[0], 'player_controllers': results[1],
            'weak_identity_uninitialized_addresses': sorted({
                address for rows in results for row in rows
                for address in row.get('weak_identity_uninitialized_addresses', [])}),
            'read_calls': budget.calls, 'read_bytes': budget.bytes_read,
            'identity_callback_calls': budget.identity_calls,
            'atomic_snapshot': False, 'binding_verified': False,
            'native_dispatch_executed': False, 'native_spawn_verified': False,
            'process_opened_by_module': False}
