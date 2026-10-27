"""Read current character readiness separately from generic FSM Initialize/Start."""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent.parent
CLIENT = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
CLASS = '/Game/BluePrints/Characters/CharacterFSM/DFMCharacterFSM_Main.DFMCharacterFSM_Main_C'
CAPTURE = 'work/native-client-tests/1792478435036855300/owned-fsm-metadata.json'
BOARD_CLASS = '/Script/DFMGameplay.DFMBlackboardComponent'
ROOT_ACTIVITY_SOURCE = 'work/evidence/skill-flow-research-20261020-v1/native-local-fsm-root-activity-v1.json'
PINS = {
    ROOT_ACTIVITY_SOURCE: 'e0e7dfade0e34e1b4856a7da377a1102b6c8a809a0fbe2a1eba83c836282e771',
    CAPTURE: '1cecf3eb9b10a2cdb21370d7257af9a11c98ceed6504db488d30adb9a5891590',
    'work/evidence/skill-flow-research-20261020-v1/native-gpfsm-inited-writer.json':
        '94e0a59c42b44ecb05c26c630b3a08c328a2a05597ed2c8fff901e835282874e',
    'work/evidence/model-init-chain-20261018/native-current-fsm-databoard-network-initializer-v1.json':
        '3d5ecc8191f6c4c9a4ee93a5508f1dd3ad659fe453fc263f2cca695c4dcf5fdd',
    'work/evidence/skill-flow-research-20261020-v1/native-local-fsm-prediction-prerequisites-v1.json':
        'b299f75e87767fb7330564b1133edc5b5c5337df33e03ca3ef622e72afada7c8',
    'work/evidence/model-init-chain-20261018/native-current-fsm-instance-notify-class-bodies-v1.json':
        '5e23fef2ee4fd300f4b90682e8d75a31b987a1955baca46782cc10a8c2138f6d',
    'work/evidence/model-init-chain-20261018/native-current-fsm-databoard-dfm-constructor-body-v1.json':
        'f8ca56f0eca1a8667975f2114f09d79496885fbf2f42e293df16a5ebe0570b89',
}
FIELDS = ('bFSMIsInited', 'GPActor', 'GPIdentity', 'Blackboard', 'GPCharacter', 'GPFSMComponent',
          'RootStateMachine')
NETWORK_FIELDS = ('bDataboardIsInited', 'IsServer', 'isAutonomous')
SIGNATURE = ('declaring_class', 'name', 'storage_offset', 'element_bytes',
    'array_dimension', 'property_flags', 'field_vtable_rva', 'native_property_type',
    'declared_native_class', 'declared_native_class_path')


def _sealed(relative):
    raw = (ROOT / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != PINS[relative]:
        raise ValueError('Character readiness source changed: ' + relative)
    return json.loads(raw)


def source_record():
    capture = _sealed(CAPTURE)
    if (capture.get('client_sha256') != CLIENT or
            capture.get('identities_and_fields_rechecked') is not True or
            capture.get('process_memory_written') is not False or
            capture.get('native_methods_invoked') is not False):
        raise ValueError('An exact rechecked character readiness declaration is required')
    row, = [o for o in capture['objects'] if o['class_path'] == CLASS]
    return row


def _field(record, name):
    row, = [dict(f, declaring_class=d['class_name']) for d in record['declarations']
            for f in d['fields'] if f['name'] == name]
    return row


def qualified_field(record, name):
    if record.get('class_path') != CLASS:
        raise ValueError('Current character readiness class differs')
    if name not in FIELDS:
        raise ValueError('The field is outside character readiness scope')
    field, expected = _field(record, name), _field(source_record(), name)
    if any(field.get(k) != expected.get(k) for k in SIGNATURE):
        raise ValueError('Current character readiness declaration differs: ' + name)
    return field


def read_ready(read, instance, record):
    field = qualified_field(record, 'bFSMIsInited')
    raw = read(instance + field['storage_offset'], 1)
    if raw not in (b'\x00', b'\x01'):
        raise ValueError('Character readiness native boolean is not canonical')
    return dict(status='observed', field=field, value=bool(raw[0]), raw_hex=raw.hex(),
        native_writer_rva='0x48a2920', generic_initialization_substituted=False,
        authority_initialization_inferred=False)


def source_pins():
    source_record()
    for relative in PINS:
        if relative != CAPTURE:
            _sealed(relative)
    return dict(PINS, **{'work/fsm_character_readiness_scope.py':
        hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})


def read_databoard(read, board, record):
    # GPNetworkComponent.Initialize 0x3fd5a5b writes +0x100; InitCharacter
    # 0x48a28fa / 0x48a2917 tests +0x100 and +0x102 independently.
    if record.get('class_path') != BOARD_CLASS:
        raise ValueError('Current databoard class differs')
    expected, = [o for o in _sealed(CAPTURE)['objects'] if o['class_path'] == BOARD_CLASS]
    fields = {}
    for name in NETWORK_FIELDS:
        field, source = _field(record, name), _field(expected, name)
        if any(field.get(k) != source.get(k) for k in SIGNATURE):
            raise ValueError('Current databoard declaration differs: ' + name)
        fields[name] = field
    initialized, server, autonomous = (read(board + fields[name]['storage_offset'], 1)
                                       for name in NETWORK_FIELDS)
    if any(raw not in (b'\x00', b'\x01') for raw in (initialized, server, autonomous)):
        raise ValueError('Databoard readiness flags are not canonical')
    return dict(status='observed', network_initialized=bool(initialized[0]),
        server_identity=bool(server[0]), raw_initialized=initialized.hex(),
        raw_server_identity=server.hex(), autonomous_identity=bool(autonomous[0]),
        raw_autonomous_identity=autonomous.hex(),
        autonomous_identity_field=fields['isAutonomous'], character_readiness_inferred=False)


def read_component_back_reference(observation, instance, record, current_component_identity):
    field = qualified_field(record, 'GPFSMComponent')
    value = observation.reference(instance, field, expected_base='GPFSMStateMachineComponent')
    if value['status'] in ('typed_existing_reference', 'typed_reference_weak_identity_uninitialized'):
        value['is_current_pawn_fsm_component'] = (
            value['status'] == 'typed_existing_reference' and
            isinstance(current_component_identity, dict) and
            type(current_component_identity.get('serial')) is int and
            current_component_identity['serial'] > 0 and
            value['identity'] == current_component_identity)
    value['prediction_execution_inferred'] = False
    return value


def read_root_activity(read, instance, record):
    """Read inline local storage, without traversing nodes or using fallback getters."""
    from fsm_readonly_scope import array_header
    field = qualified_field(record, 'RootStateMachine')
    if (field['storage_offset'], field['element_bytes'], field['field_vtable_rva']) != (
            0x220, 0x358, 0x15a86f40):
        raise ValueError('The inline root declaration differs from the native start body')
    source = _sealed(ROOT_ACTIVITY_SOURCE)
    if source.get('client_sha256') != CLIENT or source.get('process_access') is not False:
        raise ValueError('The local root source belongs to another client')
    instructions = {i['rva']: i for f in source['functions'] for i in f['instructions']}
    for at, code in (
            ('0x1058fe8', '488d8f20020000'),
            ('0x106c597', '8b8768020000'), ('0x106c59d', '3b8794020000'),
            ('0x106c6ed', '4038b932010000'), ('0x106c6f6', '4038b958010000'),
            ('0x106c6ff', '4038b948010000'), ('0x105f46c', '488b8930030000'),
            ('0x105f48d', '83b85802000000'), ('0x105f494', 'b940020000'),
            ('0x105f49e', 'bb50020000')):
        if instructions[at]['bytes'] != code:
            raise ValueError('A native root activity instruction changed')
    root = instance + field['storage_offset']
    flags = {}
    for name, offset in (('local_active', 0x132), ('reentry_gate_148', 0x148),
                         ('reentry_gate_158', 0x158)):
        raw = read(root + offset, 1)
        if raw not in (b'\x00', b'\x01'):
            raise ValueError('A local root boolean is not canonical')
        flags[name] = bool(raw[0])
    default_entries = array_header(read(root + 0x240, 16))
    override_entries = array_header(read(root + 0x250, 16))
    slots, = struct.unpack('<i', read(root + 0x268, 4))
    free, = struct.unpack('<i', read(root + 0x294, 4))
    if not 0 <= free <= slots <= 4096:
        raise ValueError('The local root active set counters exceed this observation scope')
    referenced, = struct.unpack('<Q', read(root + 0x330, 8))
    if referenced and (not 0x10000 <= referenced < 1 << 47 or referenced & 7):
        raise ValueError('The local root referenced instance address is invalid')
    return dict(status='observed', field=field, **flags,
        active_set_slots=slots, active_set_free=free, active_set_count=slots-free,
        default_entry_candidates=default_entries, override_entry_candidates=override_entries,
        referenced_instance_nonnull=bool(referenced), local_inline_storage_only=True,
        active_nodes_identified=False, fallback_getters_invoked=False,
        gameplay_execution_inferred=False)
