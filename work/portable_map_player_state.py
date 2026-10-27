"""Qualify fresh same-build receiver metadata and encode admitted player state.

This uses the normal network receiver. It never writes process memory, invokes
native methods, substitutes a default operator, or copies historical pointers.
"""
import hashlib
import json
from pathlib import Path
from copy import deepcopy

from portable_player_appearance import avatar_ids_for_selection
from dfserver.legacy_ds_byte_scalar import NativeByteEnumBinding, ByteEnumField
from dfserver.legacy_ds_player_state_human_appearance_content import (
    build_player_state_human_appearance_content, PROPERTY_TABLES, HANDLES)
from dfserver.legacy_ds_scalar_serializers import NativeScalarBinding, SHIPPING_SHA256
from dfserver.legacy_ds_scalar_serializers import write_uint64_value
from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitWriter

PS_CLASS = 'BP_SOLPlayerState_C'
PAWN_CLASS = 'BP_DFMCharacter_C'
PS_PATH = '/Game/BluePrints/GameModes/TestGame/BP_SOLPlayerState.BP_SOLPlayerState_C'


def _export_schema(export):
    layout = export['layout']
    if export.get('layout_status') != 'exported_existing' or export.get('native_getter_invoked') is not False:
        raise ValueError('An existing, uninvoked class layout is required')
    commands, parents = layout['commands'], layout['parents']
    if len(commands) != layout['command_count'] or len(parents) != layout['parent_count']:
        raise ValueError('A complete current class layout is required')
    clean = []
    for i, command in enumerate(commands):
        if command.get('command_index') != i:
            raise ValueError('The current command sequence changed')
        parent = parents[command['parent_index']]
        direct = (command.get('descriptor_address') is not None and
                  command.get('descriptor_address') == parent.get('descriptor_address'))
        record = {k: command[k] for k in ('command_index', 'descriptor_name', 'data_offset',
            'relative_handle', 'parent_index', 'dispatch_opcode', 'record_sha256') if k in command}
        record['direct_parent_descriptor_verified'] = direct
        for key in ('property_serializer_hook', 'property_scalar_leaf_hook'):
            if key in command:
                record[key] = {k: v for k, v in command[key].items() if k not in
                               ('vtable_address', 'target_address')}
        clean.append(record)
    return dict(class_name=export['class_name'], class_asset_path=export['class_asset_path'],
        layout=dict(command_count=len(commands), parent_count=len(parents), commands=clean))


def derive_schema(capture):
    """Drop pointers only after the owned current receiver has been qualified."""
    if (capture.get('kind') != 'portable_owned_map_runtime_observation' or
            capture.get('client_sha256') != SHIPPING_SHA256 or capture.get('status') != 'observed' or
            capture.get('process_identity_rechecked') is not True or
            capture.get('selected_roots_rechecked') is not True or
            capture.get('process_memory_written') is not False or
            capture.get('native_methods_invoked') is not False):
        raise ValueError('A rechecked owned current runtime observation is required')
    views = capture['primary_controller_views']
    if len(views) != 1:
        raise ValueError('One primary local controller is required')
    view = views[0]
    first = view['first_player_state']
    if (first.get('identity_and_fields_rechecked') is not True or
            first.get('connection_pc_equals_selected_pc') is not True or
            first.get('connection_owner_equals_selected_pc') is not True):
        raise ValueError('The typed controller must own the current connection')
    for field, base, expected in (('pc_pawn_reference', 'Pawn', PAWN_CLASS),
                                   ('pc_player_state_reference', 'PlayerState', PS_CLASS)):
        ref = first[field]
        if (ref.get('status') != 'typed_existing_reference' or ref.get('required_base_class') != base or
                ref.get('class_ancestry', [None])[0] != expected or base not in ref['class_ancestry']):
            raise ValueError('The current typed Pawn and PlayerState are required')
    schema = dict(kind='portable_current_player_receiver_schema', client_sha256=SHIPPING_SHA256,
        pawn=_export_schema(view['pawn_replication_metadata']),
        player_state=_export_schema(view['player_state_replication_metadata']),
        role=deepcopy(view['pawn_role_metadata']), process_pointers_reused=False,
        official_team_visibility_policy_recovered=False)
    qualify_schema(schema)
    return schema


def _field(export, name, opcode, serializer, parent=None):
    from portable_map_bootstrap import property_handle
    handle = property_handle(export, name, opcode=opcode, serializer=serializer, parent=parent)
    matches = [c for c in export['layout']['commands'] if c.get('descriptor_name') == name and
               (parent is None or c['parent_index'] == parent)]
    if len(matches) != 1 or matches[0].get('direct_parent_descriptor_verified') is not True:
        raise ValueError('A direct outer property declaration is required: ' + name)
    return handle, matches[0]


def qualify_schema(schema):
    if (schema.get('kind') != 'portable_current_player_receiver_schema' or
            schema.get('client_sha256') != SHIPPING_SHA256 or schema.get('process_pointers_reused') is not False):
        raise ValueError('A same-build pointer-free receiver schema is required')
    pawn, state, role = schema['pawn'], schema['player_state'], schema['role']
    if (pawn['class_name'] != PAWN_CLASS or state['class_name'] != PS_CLASS or
            state['class_asset_path'] != PS_PATH or
            (pawn['layout']['command_count'], pawn['layout']['parent_count']) != (198, 108) or
            (state['layout']['command_count'], state['layout']['parent_count']) != (688, 115) or
            role.get('status') != 'observed' or role.get('normal_receiver_remap_enabled') is not True or
            role.get('identities_and_fields_rechecked') is not True or
            role.get('source') != 'current_owned_pawn_existing_layout_and_typed_enum' or
            role.get('process_memory_written') is not False):
        raise ValueError('The typed receiver layout or normal Role remap changed')
    for name, other in (('Role', 'RemoteRole'), ('RemoteRole', 'Role')):
        handle, command = _field(pawn, name, 6, 0x10e8ec50)
        _, destination = _field(pawn, other, 6, 0x10e8ec50)
        row = role['fields'][name]
        values = row['enum_values']
        if (row['wire_handle'] != handle or row['source_offset'] != command['data_offset'] or
                row['destination_field'] != other or row['destination_offset'] != destination['data_offset'] or
                row['serializer_target_rva'] != 0x10e8ec50 or
                set(values) != {'ROLE_None', 'ROLE_SimulatedProxy', 'ROLE_AutonomousProxy', 'ROLE_Authority', 'ROLE_MAX'} or
                any(type(v) is not int or not 0 <= v <= 256 for v in values.values()) or
                len(set(values.values())) != len(values) or row['enum_maximum'] != max(values.values()) or
                row['wire_bit_count'] != (row['enum_maximum'] - 1).bit_length()):
            raise ValueError('The current Role destination or typed enum changed')
    remote = role['fields']['RemoteRole']
    binding = NativeByteEnumBinding(SHIPPING_SHA256, remote['serializer_target_rva'],
                                    True, remote['enum_maximum'])
    local_control = ByteEnumField(remote['wire_handle'], remote['enum_values']['ROLE_AutonomousProxy'], binding)
    bindings = []
    for name, opcode, parent, expected_handle, table in zip(
            ('HeroId', 'CurrSameTeamAvatarId', 'CurrDiffTeamAvatarId'), (2, 20, 20),
            (71, 73, 74), HANDLES, PROPERTY_TABLES):
        handle, command = _field(state, name, opcode, 0x10e5ce20, parent)
        leaf = command.get('property_scalar_leaf_hook', {})
        hook = command['property_serializer_hook']
        if (handle != expected_handle or hook.get('vtable_rva') != table or
                leaf.get('vtable_rva') != table or leaf.get('target_rva') != 0x286c000 or
                leaf.get('slot') != 0x88 or leaf.get('target_module_sha256') != SHIPPING_SHA256 or
                leaf.get('identity_rechecked') is not True or leaf.get('inside_pinned_image') is not True):
            raise ValueError('The typed signed/unsigned avatar scalar binding changed')
        bindings.append(NativeScalarBinding(SHIPPING_SHA256, hook['target_rva'], leaf['target_rva'], table))
    return local_control, tuple(bindings)


def appearance_content(schema, hero_id, fashion_id, hero_catalog, avatar_catalog):
    _, bindings = qualify_schema(schema)
    hero, same, different = avatar_ids_for_selection(hero_id, fashion_id, hero_catalog, avatar_catalog)
    return build_player_state_human_appearance_content(hero_id=hero, same_team_avatar_id=same,
        diff_team_avatar_id=different, bindings=bindings, no_byteswap=True, normal_actor_receive_contract=True)


def identity_content(schema, player_id):
    """Bind the PlayerState to this admission before avatar notifications run."""
    qualify_schema(schema)
    handle, command = _field(schema['player_state'], 'Uin', 20, 0x10e5ce20, parent=22)
    serializer = command['property_serializer_hook']
    leaf = command.get('property_scalar_leaf_hook', {})
    if (handle != 28 or serializer.get('vtable_rva') != 0x1ab60db0 or
            leaf.get('vtable_rva') != 0x1ab60db0 or leaf.get('target_rva') != 0x286c000 or
            leaf.get('identity_rechecked') is not True or leaf.get('inside_pinned_image') is not True or
            leaf.get('target_module_sha256') != SHIPPING_SHA256 or
            type(player_id) is not int or not 0 < player_id < 1 << 64):
        raise ValueError('A qualified uint64 identity and positive admitted player ID are required')
    binding = NativeScalarBinding(SHIPPING_SHA256, serializer['target_rva'], leaf['target_rva'], 0x1ab60db0)
    writer = BitWriter(maximum_bits=81)
    writer.write_bool(False)
    writer.write_packed_int(handle)
    write_uint64_value(writer, player_id, binding=binding, no_byteswap=True)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    opts = parser.parse_args()
    raw = opts.capture.read_bytes()
    capture = json.loads(raw)
    root = Path(__file__).resolve().parent.parent
    for relative, digest in capture['reader_source_pins'].items():
        if hashlib.sha256((root / relative).read_bytes()).hexdigest() != digest:
            raise ValueError('Observation reader changed: ' + relative)
    schema = derive_schema(capture)
    schema['source_capture_sha256'] = hashlib.sha256(raw).hexdigest()
    schema['source_reader_pins'] = capture['reader_source_pins']
    output = (json.dumps(schema, indent=2, sort_keys=True) + '\n').encode()
    opts.output.parent.mkdir(parents=True, exist_ok=True)
    if opts.output.exists():
        if opts.output.read_bytes() != output:
            raise ValueError('Refusing to replace a different published receiver schema')
    else:
        with opts.output.open('xb') as stream:
            stream.write(output)
    print(json.dumps(dict(output=str(opts.output), sha256=hashlib.sha256(output).hexdigest())))
