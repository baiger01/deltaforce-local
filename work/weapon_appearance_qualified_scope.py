"""Source-qualified replacement scope for a future read-only weapon observer.

No existing runtime source is changed. Callers may use this module as the
appearance_scope dependency of observe_weapon_mesh_followup in their own process.
"""
import hashlib
import json
from pathlib import Path
import struct

import observe_owned_weapon_state as old
import weapon_appearance_readonly_scope as original
import weapon_owner_mesh_selection as owner_mesh
import weapon_function_appearance_scope as function_scope
from observe_owned_gameplay_metadata import address
from portable_native_code_cache import CodeCache


ROOT = old.ROOT
INNER_SOURCE = original.BASE+'native-weapon-appearance-inner-object-serializer-v1.json'
INNER_SOURCE_SHA = '9124d0f690b4796fa682eacb6aaa080699798df001af6d6d2c976f06aee8b556'


def source_pins(game_root):
    pins = original.source_pins(game_root)
    raw = (ROOT/INNER_SOURCE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != INNER_SOURCE_SHA:
        raise ValueError('The qualified view-array inner serializer source changed')
    cache = CodeCache(ROOT/'work/native-code-cache/1792259162856698600',
        old.MANIFEST_SHA256, game_root)
    document = json.loads(raw)
    functions = document.get('functions', ())
    if [f['span_start'] for f in functions] != ['0x10e96570', '0x10e95370']:
        raise ValueError('The view-array inner/scalar source function selection changed')
    for function in functions:
        first, size = int(function['span_start'], 16), function['span_bytes']
        if type(size) is not int or not 1 <= size <= 4096:
            raise ValueError('The view-array serializer source exceeds its fixed extent')
        if hashlib.sha256(cache.read(first, size)).hexdigest() != function['code_sha256']:
            raise ValueError('The qualified view-array serializer bytes changed')
    pins[INNER_SOURCE] = INNER_SOURCE_SHA
    pins = old.merge_source_pins(pins, owner_mesh.source_pins())
    pins = old.merge_source_pins(pins, function_scope.source_pins(game_root))
    pins['work/weapon_appearance_qualified_scope.py'] = hashlib.sha256(
        Path(__file__).read_bytes()).hexdigest()
    return pins


def read_view_list(actor, field, *, fields, facts):
    if (field['field_vtable_rva'], field['element_bytes'], field['array_dimension']) != (0x1ab5b730, 16, 1):
        raise ValueError('The weapon view list is not the qualified native array')
    descriptor = field['descriptor_address']
    inner = address(struct.unpack('<Q', facts.fact(descriptor+0x90, 8))[0])
    raw = facts.fact(inner, 0x60)
    if struct.unpack_from('<ii', raw, 0x3c) != (1, 8) or struct.unpack_from('<i', raw, 0x54)[0] != 0:
        raise ValueError('The weapon view list has an unqualified inner extent')
    fields.hook(inner, 0x10e8ed20)
    fields.hook(inner, 0x10e96570, slot=0x88)
    declared = address(struct.unpack('<Q', facts.fact(inner+0x90, 8))[0])
    if fields.identity(declared, 'Class')['name'] != 'GPWeaponViewComponentBase':
        raise ValueError('The actual view array does not contain GPWeaponViewComponentBase')
    raw = facts.fact(actor+field['storage_offset'], 16)
    header = old.array_header(raw, 8)
    payload = facts.fact(header['data'], header['count']*8) if header['count'] else b''
    pointers = [address(at) for (at,) in struct.iter_unpack('<Q', payload) if at]
    if len(set(pointers)) != len(pointers):
        raise ValueError('The actual weapon view component list contains duplicate references')
    return dict(**header, field=field, header_hex=raw.hex(), inner_descriptor_address=hex(inner),
        declared_native_class='GPWeaponViewComponentBase',
        native_inner_serializer_rva='0x10e96570'), pointers


class _TypedFields:
    def __init__(self, fields):
        self.fields = fields

    def __getattr__(self, name):
        return getattr(self.fields, name)

    def field(self, root, expected):
        actual = self.fields.field(root, expected)
        # Validation precedes carrying the source-qualified declared type forward.
        return dict(actual, **{key: expected[key] for key in
            ('native_property_type', 'declared_native_class') if key in expected})


def visibility_predicate(record, *, pawn_record, fields, facts, observation, metadata):
    result = original.visibility_predicate(record, pawn_record=pawn_record,
        fields=_TypedFields(fields), facts=facts, observation=observation, metadata=metadata)
    result['typed_declarations_preserved_after_descriptor_recheck'] = True
    if result['status'] == 'native_mesh_override_requires_qualified_resolver' and metadata is not None:
        selected = owner_mesh.observe(pawn_record, fields=fields, facts=facts,
            observation=observation, metadata=metadata)
        result['owner_mesh_selection'] = selected
        result['status'] = selected['status']
        if 'native_default_body_visible' in selected:
            result['native_default_body_visible'] = selected['native_default_body_visible']
            result.pop('missing_current_predicate', None)
    return result


def read_appearance(record, *, actor, fields, facts, observation):
    return original.read_appearance(record, actor=actor, fields=_TypedFields(fields),
        facts=facts, observation=observation)


def observe_actor(record, *, fields, facts, observation, metadata):
    actor = address(record['identity']['address'])
    field = fields.field(address(record['identity']['class_address']), original.view_list_field(record))
    header, pointers = read_view_list(actor, field, fields=fields, facts=facts)
    entries = []
    for pointer in pointers:
        identity = observation.identify(pointer, 'GPWeaponViewComponentBase')
        if identity.get('is_cdo') is not False or address(identity['outer_address']) != actor:
            raise ValueError('The current view component belongs to a different weapon Actor')
        entries.append(identity)

    result = dict(view_component_list=dict(**header, entries=entries), status='observed',
        source='current_typed_GPWeaponViewComponentList', historical_pointers_reused=False,
        encrypted_cache_decoded=False, rendering_verified=False, gameplay_verified=False,
        final_rechecks_complete=False)

    def refused(stage, expected, index=None):
        context = dict(stage=stage, expected_class=expected)
        if index is not None:
            context['component_index'] = index
        return dict(status='refused', reason='The qualified appearance observation stage was refused',
            failure_context=context)

    data = [(index, identity) for index, identity in enumerate(entries)
        if original.COMPONENT in identity.get('class_ancestry', ())]
    for key, expected in (('appearance', original.COMPONENT),
            ('function_appearance', function_scope.COMPONENT)):
        matches = [(index, identity) for index, identity in enumerate(entries)
            if expected in identity.get('class_ancestry', ())]
        if len(matches) != 1:
            result[key] = dict(refused('component_selection', expected),
                selected_component_count=len(matches))
            continue
        index, identity = matches[0]
        try:
            current = metadata(address(identity['address']), expected)
        except ValueError:
            result[key] = refused('component_metadata', expected, index)
            continue
        if current['identity'] != identity:
            result[key] = refused('metadata_identity', expected, index)
            continue
        if key == 'function_appearance' and len(data) != 1:
            result[key] = refused('data_component_selection', original.COMPONENT)
            continue
        try:
            if key == 'appearance':
                result[key] = read_appearance(current, actor=actor, fields=fields,
                    facts=facts, observation=observation)
            else:
                result[key] = function_scope.observe(current, actor=actor,
                    data_identity=data[0][1], fields=fields, facts=facts,
                    observation=observation, metadata=metadata)
        except ValueError:
            result[key] = refused('component_state', expected, index)
    if any(result[key]['status'] != 'observed' for key in ('appearance', 'function_appearance')):
        result['status'] = 'partial'
    return result
