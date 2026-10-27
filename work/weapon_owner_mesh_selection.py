"""Pure normal GetMesh selection and bounded direct-reference observation.

The native getter selects FPPMesh only when Blackboard.bUndderFPP is set.
Encrypted representations requiring callbacks remain refused. No native getter,
reference rewrite, selected mesh mutation, or packet emission is reproduced.
"""
import hashlib
import json
from pathlib import Path

import observe_owned_weapon_state as old
import weapon_appearance_readonly_scope as appearance
from observe_owned_gameplay_metadata import address


ROOT = old.ROOT
CAPTURE = 'work/native-client-tests/1792401899578422100/owned-vitals-metadata.json'
CAPTURE_SHA = 'b5b95c21db554e0e91c44e655afa9a03c61f30362830d0ad9bd956aceb36d3b4'
FIELDS = {'Blackboard': ('GPCharacterBase', 0x1020, 8, 'FEncryptedObjectProperty', 'GPBlackboardComponent'),
    'bUndderFPP': ('GPBlackboardComponent', 0x379, 1, None, None),
    'FPPMesh': ('CharacterBase', 0xaa8, 8, 'FEncryptedObjectProperty', 'SkeletalMeshComponent'),
    'Mesh': ('CHARACTER', 0x3d0, 8, 'FObjectProperty', 'SkeletalMeshComponent')}


def source_schema():
    raw = (ROOT/CAPTURE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != CAPTURE_SHA:
        raise ValueError('The native owner mesh current typed declaration source changed')
    document = json.loads(raw)
    result = {}
    for name, (owner, offset, size, kind, target) in FIELDS.items():
        scope = 'current_pawn.Blackboard' if name == 'bUndderFPP' else 'current_pawn'
        rows = [dict(f, declaring_class=c['class_name']) for o in document['objects']
            if o['scope'] == scope for c in o['declarations'] for f in c['fields']
            if c['class_name'] == owner and f['name'] == name]
        if (len(rows) != 1 or
                (rows[0]['storage_offset'], rows[0]['element_bytes'], rows[0]['array_dimension'],
                 rows[0].get('native_property_type'), rows[0].get('declared_native_class')) !=
                (offset, size, 1, kind, target)):
            raise ValueError('The native owner mesh declaration source differs: '+name)
        result[name] = rows[0]
    return result


def source_pins():
    source_schema()
    getter = appearance.document(appearance.BASE+'native-weapon-isvisible-owner-component-getter-v1.json')
    instructions = {i['rva']: i for f in getter['functions'] for i in f['instructions']}
    for at, mnemonic, operands in (
            ('0x4bcd476', 'mov', 'rbx, qword ptr [rsi + 0x1020]'),
            ('0x4bcdd55', 'cmp', 'byte ptr [rbx + 0x379], 0'),
            ('0x4bcdd5c', 'je', '0x4bcea6b'),
            ('0x4bcdd62', 'mov', 'rdi, qword ptr [rsi + 0xaa8]'),
            ('0x4bceabc', 'mov', 'rax, qword ptr [rsi + 0x3d0]')):
        if (instructions[at]['mnemonic'], instructions[at]['operands']) != (mnemonic, operands):
            raise ValueError('The normal native GetMesh selection branch changed: '+at)
    return {CAPTURE: CAPTURE_SHA, 'work/weapon_owner_mesh_selection.py':
        hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def select_mesh_property(blackboard_present, under_fpp):
    if (type(blackboard_present) is not bool or
            (blackboard_present and type(under_fpp) is not bool) or
            (not blackboard_present and under_fpp is not None)):
        raise ValueError('The native owner mesh selector requires explicit current booleans')
    return 'FPPMesh' if blackboard_present and under_fpp else 'Mesh'


def select_field(record, name):
    expected = source_schema()[name]
    rows = [dict(f, declaring_class=c['class_name']) for c in record['declarations']
        for f in c['fields'] if c['class_name'] == expected['declaring_class'] and f['name'] == name]
    if len(rows) != 1 or any(rows[0].get(key) != expected.get(key)
            for key in (*old.FIELD_KEYS, 'declaring_class')):
        raise ValueError('The current selected owner mesh declaration differs: '+name)
    return rows[0]


def _reference(pointer, record, name, *, fields, observation):
    selected = select_field(record, name)
    actual = fields.field(address(record['identity']['class_address']), selected)
    fields.hook(actual['descriptor_address'], 0x10e8ed20)
    fields.hook(actual['descriptor_address'],
        0x10e93f30 if selected['native_property_type'] == 'FEncryptedObjectProperty' else 0x10e95370,
        slot=0x88)
    return observation.reference(pointer, selected, expected_base=selected['declared_native_class'])


def observe(pawn_record, *, fields, facts, observation, metadata):
    pawn = address(pawn_record['identity']['address'])
    result = dict(native_get_mesh_rva='0x4bcd400', native_is_visible_rva='0x58ae3c0',
        native_method_invoked=False, encrypted_callback_invoked=False,
        process_memory_written=False, rendering_verified=False,
        native_getter_side_effects_reproduced=False)
    blackboard = _reference(pawn, pawn_record, 'Blackboard', fields=fields, observation=observation)
    result['blackboard_reference'] = blackboard
    under = None
    present = blackboard['status'] == 'typed_existing_reference'
    if blackboard['status'] not in ('typed_existing_reference', 'null_reference'):
        return dict(result, status='owner_mesh_selection_refused')
    if present:
        identity = blackboard['identity']
        if identity.get('is_cdo') is not False or address(identity['outer_address']) != pawn:
            raise ValueError('The native owner mesh Blackboard is outside the current Pawn')
        pointer = address(identity['address'])
        record = metadata(pointer, 'GPBlackboardComponent')
        if record['identity'] != identity:
            raise ValueError('The native owner mesh Blackboard identity changed')
        selected = select_field(record, 'bUndderFPP')
        actual = fields.field(address(identity['class_address']), selected)
        value = fields.boolean(pointer, actual)
        raw = facts.fact(pointer+0x379, 1)
        if raw not in (b'\0', b'\1') or value['value'] is not bool(raw[0]):
            raise ValueError('The current native bUndderFPP is not a canonical complete bool')
        under = value['value']
        result['bUndderFPP'] = value
    name = select_mesh_property(present, under)
    link = _reference(pawn, pawn_record, name, fields=fields, observation=observation)
    result.update(selected_property=name, selected_mesh=link)
    if link['status'] == 'null_reference':
        return dict(result, status='observed_no_selected_mesh', native_default_body_visible=True)
    if link['status'] != 'typed_existing_reference':
        return dict(result, status='owner_mesh_selection_refused')
    identity = link['identity']
    if identity.get('is_cdo') is not False or address(identity['outer_address']) != pawn:
        raise ValueError('The native selected owner mesh is outside the current Pawn')
    value = facts.fact(address(identity['address'])+0x8c8, 1)[0]
    return dict(result, status='observed_selected_mesh_predicate',
        native_mesh_member_offset=0x8c8, native_mesh_member_mask=1,
        native_mesh_byte_hex=hex(value), native_default_body_visible=bool(value & 1),
        reflected_property_name_inferred=False, net_property=False)
