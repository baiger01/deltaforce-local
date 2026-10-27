"""Bounded callback-only metadata for the current component's FSM class."""
import hashlib
import struct

from fsm_readonly_scope import ROOT, CLIENT, FOLDER, PATHS, sealed
from native_metadata_names import resolve_name
from native_metadata_paths import object_path

CLASS_PATH = PATHS['instance']
CDO_PATH = CLASS_PATH.rsplit('.', 1)[0]+'.Default__DFMCharacterFSM_Main_C'
DEFAULT_SOURCE = FOLDER+'native-current-fsm-object-class-default-selection-v1.json'
PINS = {
    DEFAULT_SOURCE: 'b48468bb89444bf9bf161097e872b57b33a3b1665c74788148fc21045de70f7a',
    FOLDER+'native-current-fsm-instance-creation-contract-v1.json':
        'd9f30139583e9c40fb320590279de021d500356eb65fa14aacbab7d504639fad',
    FOLDER+'native-current-fsm-instance-network-vtables-v1.json':
        '690f18299a3590b00083b63bd8d95e30713f44b4e2650ee76d103e946081a95b',
}


def contract():
    docs = {path: sealed(path, digest) for path, digest in PINS.items()}
    for doc in docs.values():
        if doc.get('client_sha256') != CLIENT or doc.get('process_access') is not False:
            raise ValueError('The generated FSM class source is not qualified')
    ins = {i['rva']: i for f in docs[DEFAULT_SOURCE]['functions'] for i in f['instructions']}
    for at, mnemonic, operands in (
        ('0x10eabae6', 'mov', 'r15, rcx'),
        ('0x10eac0c0', 'cmp', 'qword ptr [r15 + 0x140], 0'),
        ('0x10eac0d6', 'mov', 'rsi, qword ptr [r15 + 0x140]')):
        if (ins[at]['mnemonic'], ins[at]['operands']) != (mnemonic, operands):
            raise ValueError('The generated FSM CDO pointer source changed')
    creation = docs[FOLDER+'native-current-fsm-instance-creation-contract-v1.json']
    gate = creation['native_base_networking_virtual']
    if gate['slot'] != 0x1d0 or gate['target_rva'] != '0xd5c5d0' or gate['returns_true'] is not True:
        raise ValueError('The generated FSM native networking source changed')
    return dict(class_default_object_pointer_offset=0x140, networking_virtual_slot=0x1d0,
        native_networking_target_rva='0xd5c5d0', native_get_default_object_called=False)


def source_pins():
    contract()
    result = dict(PINS)
    for relative in ('work/fsm_generated_class_scope.py', 'work/native_actor_interface_metadata.py',
            'work/native_metadata_objects.py', 'work/native_metadata_names.py',
            'work/native_metadata_paths.py'):
        result[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return result


def observe_class_metadata(observation, klass, *, image_size):
    """Read an existing CDO only; the caller must finish/recheck the observation."""
    source = contract()
    ob = observation
    if type(klass) is not int or not klass or image_size != 536408064:
        raise ValueError('One current typed class and the exact pinned image are required')
    path = object_path(ob.read, ob.base, klass)
    if path != CLASS_PATH:
        raise ValueError('The current component class differs from the cooked main FSM')
    ancestry, seen, cursor = [], set(), klass
    while cursor:
        if cursor in seen or len(seen) >= 32:
            raise ValueError('The FSM class ancestry exceeds its bounded scope')
        seen.add(cursor)
        descriptor = ob.class_identity(cursor)
        ancestry.append(dict(name=descriptor['name'], class_path=object_path(ob.read, ob.base, cursor)))
        cursor = descriptor['parent']
    names = [r['name'] for r in ancestry]
    if 'SMInstance' not in names or names[-1] != 'Object':
        raise ValueError('The generated class has no current SMInstance to Object ancestry')
    actor_or_component = any(n in ('Actor', 'ActorComponent') for n in names)
    if actor_or_component:
        raise ValueError('The generated FSM instance unexpectedly inherits Actor/component')
    cdo = ob.ptr(klass+source['class_default_object_pointer_offset'])
    result = dict(status='missing_existing_pointer', class_field_offset=0x140,
        native_get_default_object_called=False)
    if cdo:
        record = ob.record(cdo)
        flags, = struct.unpack('<I', ob.keep(cdo+0x18, 4))
        name = resolve_name(ob.read, ob.base, ob.keep(cdo+0x1c, 8)).display_text
        cdo_path = object_path(ob.read, ob.base, cdo)
        if (ob.ptr(cdo+8) != klass or not flags & 0x10 or
                name != 'Default__DFMCharacterFSM_Main_C' or cdo_path != CDO_PATH):
            raise ValueError('The existing FSM CDO class/name/path/flags changed')
        table = ob.ptr(cdo)
        if not ob.base <= table <= ob.base+image_size-source['networking_virtual_slot']-8:
            raise ValueError('The existing FSM CDO vtable is outside the pinned module')
        target = ob.ptr(table+source['networking_virtual_slot'])
        if not ob.base <= target < ob.base+image_size:
            raise ValueError('The existing FSM networking virtual is outside the pinned module')
        result = dict(status='existing_cdo_identity_verified', class_field_offset=0x140,
            name=name, object_path=cdo_path, flags=hex(flags), class_matches_selected=True,
            object_index=record.index, serial=record.serial,
            outer_path=object_path(ob.read, ob.base, ob.ptr(cdo+0x10)),
            vtable_rva=hex(table-ob.base), networking_virtual_slot=0x1d0,
            networking_virtual_target_rva=hex(target-ob.base),
            networking_supported_by_exact_native_target=target-ob.base == 0xd5c5d0,
            native_get_default_object_called=False)
    return dict(status='observed', class_path=path, ancestry=ancestry,
        is_actor_or_component=actor_or_component, existing_cdo=result,
        reference_origin='component.StateMachineClass', metadata_recheck_required=True,
        native_methods_invoked=False, process_memory_written=False)
