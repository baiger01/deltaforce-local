"""Source-selected FSM observation scope; no process or native-call API."""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent.parent
CLIENT = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
FOLDER = 'work/evidence/model-init-chain-20261018/'
CONTRACT = FOLDER+'native-current-skill-fsm-remaining-gate-contract-v1.json'
CONTRACT_SHA256 = '644072d9cc7cea7479bec0b04a05030de7ac1e5e50a069406747772e97f75835'
CAPTURE = 'work/native-client-tests/1792376752204334900/owned-vitals-metadata.json'
CAPTURE_SHA256 = '86f88b614a6023a3544430a5a40c293741fc82d8adf13be6faf786e8fd227993'
STARTED_CAPTURE = 'work/native-client-tests/1792385022786009500/owned-fsm-layout-followup-exclusive.json'
STARTED_CAPTURE_SHA256 = '52f0fbe4fbdf2540103259b8e5425ef4f6d1ec0c42cbe8852b4838b8b70b771a'
EXTRA = {
    FOLDER+'native-current-character-fsm-class-declaration-v1.json':
        '7f44fdb538b6e5476561539977b80122f949fc510f0ac5c0b58a89ef32d20f22',
    FOLDER+'native-current-fsm-property-construction-flags-v1.json':
        '9ab92773cdb640e04e7e95e64b961371fc96184b7f053973810804ee377aeb12',
}
SIGNATURE = ('declaring_class', 'name', 'storage_offset', 'element_bytes', 'array_dimension',
    'property_flags', 'field_vtable_rva', 'native_property_type', 'declared_native_class',
    'declared_native_class_path')
PATHS = {
    'pawn': '/Game/BluePrints/Characters/BP_DFMCharacter.BP_DFMCharacter_C',
    'blackboard': '/Script/DFMGameplay.DFMBlackboardComponent',
    'component': '/Script/GPGameplay.GPFSMStateMachineComponent',
    'instance': '/Game/BluePrints/Characters/CharacterFSM/DFMCharacterFSM_Main.DFMCharacterFSM_Main_C',
}


def sealed(relative, expected):
    path = (ROOT/relative).resolve()
    if not path.is_relative_to(ROOT.resolve()):
        raise ValueError('The FSM source escaped the project')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('The sealed FSM source changed: '+relative)
    return json.loads(raw)


def contract():
    result = sealed(CONTRACT, CONTRACT_SHA256)
    if result.get('client_sha256') != CLIENT or result.get('process_access') is not False:
        raise ValueError('The FSM contract is not the qualified offline source')
    return result


def source_pins():
    from observe_owned_vitals_metadata import source_pins as vitals_pins
    from fsm_generated_class_scope import source_pins as generated_class_pins
    from sprint_transient_input_guard import source_pins as input_guard_pins
    from fsm_created_instance_scope import source_pins as created_instance_pins
    from fsm_character_readiness_scope import source_pins as character_readiness_pins
    from fsm_update_progress_readonly_scope import source_qualification as update_progress_sources
    result = vitals_pins()
    result.update(generated_class_pins())
    result.update(input_guard_pins())
    from operate_gate_readonly_scope import source_pins as operation_gate_pins
    result.update(operation_gate_pins())
    result.update(created_instance_pins())
    result.update(character_readiness_pins())
    result.update(update_progress_sources()[1])
    from fsm_startup_tree_readonly_scope import source_pins as startup_tree_sources
    result.update(startup_tree_sources())
    doc = contract()
    result.update({CONTRACT: CONTRACT_SHA256, CAPTURE: CAPTURE_SHA256,
        STARTED_CAPTURE: STARTED_CAPTURE_SHA256, **EXTRA})
    for row in doc['source_pins']:
        result[row['relative_path']] = row['sha256']
    for relative, digest in result.items():
        if hashlib.sha256((ROOT/relative).read_bytes()).hexdigest() != digest:
            raise ValueError('The FSM dependency source changed: '+relative)
    capture_record('pawn')
    for relative in ('work/fsm_readonly_scope.py', 'work/observe_owned_fsm_metadata.py',
            'work/observe_owned_skill_entity_metadata.py', 'work/observe_owned_emptyhand_class_metadata.py'):
        path = ROOT/relative
        if path.exists():
            result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def capture_record(scope):
    if scope not in ('pawn', 'blackboard'):
        raise ValueError('The FSM capture scope is not selected')
    doc = sealed(CAPTURE, CAPTURE_SHA256)
    if (doc.get('client_sha256') != CLIENT or doc.get('identities_and_fields_rechecked') is not True
            or doc.get('process_memory_written') is not False or doc.get('native_methods_invoked') is not False):
        raise ValueError('The current FSM root source lacks identity checks')
    target = 'current_pawn' if scope == 'pawn' else 'current_pawn.Blackboard'
    records = [r for r in doc['objects'] if r['scope'] == target and r['class_path'] == PATHS[scope]]
    if len(records) != 1:
        raise ValueError('One exact current FSM capture record is required')
    return records[0]


def named(record, name):
    rows = [dict(f, declaring_class=d['class_name']) for d in record['declarations']
        for f in d['fields'] if f['name'] == name]
    if len(rows) != 1:
        raise ValueError('The current FSM field declaration is ambiguous: '+name)
    return rows[0]


def source_field(scope, name):
    fixed = contract()['exact_next_readonly_scope']
    if scope == 'component':
        rows = fixed['component_field_declarations']
        if name in ('GPOwner', 'GPActor'):
            doc = sealed(FOLDER+'native-current-character-fsm-class-declaration-v1.json',
                EXTRA[FOLDER+'native-current-character-fsm-class-declaration-v1.json'])
            rows = doc['declarations'][0]['selected_fields']
    elif scope == 'instance':
        rows = fixed['instance_field_declarations']
    else:
        raise ValueError('The static FSM field scope is not selected')
    rows = [r for r in rows if r['name'] == name]
    if len(rows) != 1:
        raise ValueError('The requested field is outside the sealed FSM scope')
    return rows[0]


def constructor_flags(source, table):
    """Exact constructor masks, checked from the pinned native constructor body."""
    doc = sealed(FOLDER+'native-current-fsm-property-construction-flags-v1.json',
        EXTRA[FOLDER+'native-current-fsm-property-construction-flags-v1.json'])
    ins = {i['rva']: i for f in doc['functions'] for i in f['instructions']}
    kind = int(source['native_gen_flags'], 16) & 0x3f
    flags = int(source['property_flags'], 16)
    if kind in (0xc, 0x12):
        rva = '0x10ea438a' if kind == 0x12 else '0x10ea39ec'
        if ins[rva]['operands'] != 'rcx, 0x8001040000200':
            raise ValueError('The FSM native scalar/object constructor mask changed')
        return flags | 0x8001040000200
    if kind == 0x16:
        if ins['0x10ea4ec9']['operands'] != 'rax, 9':
            raise ValueError('The FSM native array constructor mask changed')
        return flags | 0x200
    if kind == 0x11:
        if (ins['0x10ea49c0']['operands'] != 'rcx, 0x8001040000200' or
                ins['0x10ea49f0']['operands'] != 'rax, [rip + 0x9cbce09]'):
            raise ValueError('The FSM native FClassProperty constructor changed')
        return flags | 0x8001040000200
    if kind == 0x23:
        if ins['0x10ea4792']['operands'] != 'rcx, 0x8000000000000':
            raise ValueError('The FSM native encrypted-object constructor mask changed')
        return flags | 0x8000000000000
    raise ValueError('The selected FSM native property kind is unsupported')


def qualified_field(record, scope, name):
    if scope not in PATHS or record['class_path'] != PATHS[scope]:
        raise ValueError('The selected FSM owner class differs')
    field = named(record, name)
    if scope in ('pawn', 'blackboard'):
        if name not in (('FSMComponent', 'Blackboard') if scope == 'pawn' else ('FSMComponent', 'bIsCheckingSkill')):
            raise ValueError('The requested FSM captured field is outside scope')
        before = named(capture_record(scope), name)
        if any(field.get(k) != before.get(k) for k in SIGNATURE):
            raise ValueError('The exact runtime FSM root declaration changed: '+name)
    else:
        source = source_field(scope, name)
        kind = int(source['native_gen_flags'], 16) & 0x3f
        size, table = {0x12: (8, 0x15a86b80), 0x23: (8, 0x1ab613b0),
            0xc: (1, 0x15a868a0), 0x16: (16, 0x1ab5b730),
            0x11: (8, 0x1ab61800)}[kind]
        expected_owner = 'GPFSMStateMachineComponent' if name in ('GPOwner', 'GPActor') else (
            'SMStateMachineComponent' if scope == 'component' else 'SMInstance')
        if name == 'R_bHasStarted':
            # This packed FBoolProperty has its own constructor and one-byte
            # declaration; the source native HasStarted operation reads a word.
            actual = sealed(STARTED_CAPTURE, STARTED_CAPTURE_SHA256)['generated_instance_class']
            before = named(actual, name)
            if any(field.get(k) != before.get(k) for k in SIGNATURE):
                raise ValueError('The actual packed FSM bool declaration changed: '+name)
            expected_flags = int(before['property_flags'], 16)
        else:
            expected_flags = constructor_flags(source, table)
        if (field['declaring_class'] != expected_owner or
                field['storage_offset'] != int(source['native_member_offset'], 16) or
                field['element_bytes'] != size or field['array_dimension'] != 1 or
                table is not None and field['field_vtable_rva'] != table or
                int(field['property_flags'], 16) != expected_flags):
            raise ValueError('The source-qualified current FSM declaration differs: '+name)
    for slot in ('0x88', '0x90'):
        hook = field.get('hooks', {}).get(slot, {})
        if (hook.get('target_module_sha256') != CLIENT or hook.get('inside_pinned_image') is not True
                or hook.get('identity_rechecked') is not True):
            raise ValueError('The FSM property hook is not rechecked in the pinned module')
    return field


def array_header(raw):
    if type(raw) is not bytes or len(raw) != 16:
        raise ValueError('An exact FSM array header is required')
    data, count, capacity = struct.unpack('<Qii', raw)
    if (not 0 <= count <= capacity <= 4096 or capacity and not data or
            data and (not 0x10000 <= data < 1 << 47 or data & 7)):
        raise ValueError('The current FSM array header exceeds its bounded scope')
    return dict(raw_hex=raw.hex(), count=count, capacity=capacity,
        data_pointer_nonnull=bool(data), elements_read=False, element_layout_inferred=False)


def started_value(raw):
    if type(raw) is not bytes or len(raw) != 4:
        raise ValueError('The source FSM started word requires exactly four bytes')
    return dict(value=bool(struct.unpack('<I', raw)[0] & 8), raw_hex=raw.hex(),
        storage_offset=0x664, storage_bytes=4, native_mask=8,
        native_setbit_rva='0x106fe60', native_hasstarted_rva='0x10688e0')


def read_field(row, name, operation):
    try:
        result = operation()
    except (ValueError, OSError) as error:
        result = dict(status='refused', reason=str(error), error_type=type(error).__name__,
            instance_value_published=False)
    row.setdefault('state', {})[name] = result
    accepted = (None, 'observed', 'typed_existing_reference', 'typed_reference_weak_identity_uninitialized',
        'null_reference')
    row['status'] = 'partial' if any(r.get('status') not in accepted for r in row['state'].values()) else 'observed'
    return result
