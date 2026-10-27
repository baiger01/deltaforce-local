"""Public Modular Actor fields from its own observed passive cache and layout."""
import argparse
import hashlib
import json
from pathlib import Path

from export_owned_weapon_actor_schema import _field, _command, _one
from owned_weapon_values_codec import CLIENT_SHA, actor_schema_binding
from portable_carried_weapon_selection import binding as selection_binding

ROOT = Path(__file__).resolve().parent.parent
CAPTURE = 'work/native-client-tests/1792314937287546900/owned-gameplay-metadata.json'
CAPTURE_SHA256 = '399d896dda740b768feb8e9e7bad40eab8d2798d27806731577a708704ca2873'
OUTPUT = ROOT/'work/evidence/map-system-audit-20261018/modular-weapon-actor-schema-v1.json'


def derive():
    baseline = actor_schema_binding()
    selection = selection_binding()
    raw = (ROOT/CAPTURE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != CAPTURE_SHA256:
        raise ValueError('The actual Modular layout observation changed')
    capture = json.loads(raw)
    if (capture['client_sha256'] != CLIENT_SHA or capture['status'] != 'observed' or
            not all(capture[k] is True for k in (
                'identities_and_fields_rechecked', 'selected_roots_rechecked', 'process_identity_rechecked')) or
            any(capture[k] is not False for k in (
                'native_methods_invoked', 'native_layouts_constructed', 'process_memory_written',
                'packets_sent', 'code_sampled', 'historical_process_pointers_reused'))):
        raise ValueError('A rechecked read-only Modular layout observation is required')
    path = selection['modular_actor']['class_path']
    actor = _one([o for o in capture['loaded_named_classes'] if o['class_path'] == path], 'Modular class')
    manager = _one([o for o in capture['objects'] if o['identity']['name'] == 'WeaponManager'], 'manager')
    for obj in (actor, manager):
        cache = obj['existing_driver_class']
        if cache['cache_status'] != 'exported_existing' or cache['layout_status'] != 'exported_existing':
            raise ValueError('The actual Modular/manager passive layout is missing')
    fields = {}
    for name in ('Owner', 'WeaponID', 'WeaponGuid', 'WeaponEquipPosition', 'WeaponSlot', 'CharacterOwner'):
        before = baseline['actor']['fields'][name]
        field = _field(actor, name)
        command = _command(actor, name, offset=before['storage_offset'])
        if (command['relative_handle'] != before['ordinary_handle'] or
                command['dispatch_opcode'] != before['dispatch_opcode'] or
                any(field[k] != before[k] for k in (
                    'storage_offset', 'storage_bytes', 'serializer_rva', 'archive_serializer_rva',
                    'property_vtable_rva', 'declaring_class'))):
            raise ValueError('The observed Modular property differs: '+name)
        field.update({k: before[k] for k in ('ordinary_handle', 'dispatch_opcode', 'wire_bits', 'wire')})
        field.update(command_sha256=command['record_sha256'], parent_index=command['parent_index'],
                     command_index=command['command_index'])
        fields[name] = field
    identity = _field(actor, 'ServerWeaponIdentity')
    command = _command(actor, 'UniqueId', offset=identity['storage_offset'], parent=28)
    if ((identity['storage_offset'], identity['storage_bytes'], command['relative_handle'],
            command['dispatch_opcode']) != (0x9e0, 4, 40, 9)):
        raise ValueError('The observed Modular WeaponIdentity differs')
    identity.update(inner_name='UniqueId', inner_handle=40, wire_bits=32,
        wire='raw_little_endian_bits', command_sha256=command['record_sha256'],
        inner_native_uht_generation=6, inner_serializer_rva='0x10e5ce20',
        inner_archive_serializer_rva='0x286bf70')
    fields['ServerWeaponIdentity'] = identity
    arrays = {}
    for name, before in baseline['manager']['arrays'].items():
        field = _field(manager, name)
        command = _command(manager, name, offset=before['storage_offset'])
        commands = manager['existing_driver_class']['layout']['commands']
        inner, end = commands[command['command_index']+1:command['command_index']+3]
        if (any(field[k] != before[k] for k in (
                'storage_offset', 'storage_bytes', 'serializer_rva', 'archive_serializer_rva',
                'property_vtable_rva', 'declaring_class')) or
                (command['relative_handle'], command['dispatch_opcode'], inner['relative_handle'],
                inner['dispatch_opcode'], end['dispatch_opcode']) !=
                (before['ordinary_handle'], 0, 1, before['inner_opcode'], 1)):
            raise ValueError('The observed complete manager array differs: '+name)
        arrays[name] = dict(before, command_sha256=command['record_sha256'],
                            inner_command_sha256=inner['record_sha256'])
    slot = _field(manager, 'WeaponSlot')
    slot_command = _command(manager, 'WeaponSlot', offset=0x1c8)
    if (slot['storage_bytes'], slot_command['dispatch_opcode']) != (1, 6):
        raise ValueError('The observed manager WeaponSlot is not its native byte property')
    slot['ordinary_handle'] = slot_command['relative_handle']
    return dict(kind='client_source_derived_modular_weapon_actor_initialization_v1',
        client_sha256=CLIENT_SHA,
        sources=dict(baseline['sources'], **selection['sources'], **{CAPTURE: CAPTURE_SHA256}),
        actor=dict(class_path=path, cdo_path=selection['modular_actor']['cdo_path'],
            cache_exclusive_maximum=actor['existing_driver_class']['exclusive_index_maximum'],
            layout_commands_sha256=actor['existing_driver_class']['layout']['commands_sha256'], fields=fields),
        manager=dict(class_path=manager['class_path'], arrays=arrays, slot=slot,
            empty_hand_handle=baseline['manager']['empty_hand_handle']),
        slot_value_origin='current_typed_manager_WeaponSlot_only',
        equip_position_mapping_qualified=False, current_manager_slot_value=None,
        local_identity_is_inventory_gid=False, complete_binding_lists_required=True,
        native_gameplay_verified=False, public_schema_contains_process_addresses=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    raw = (json.dumps(derive(), indent=2, sort_keys=True)+'\n').encode()
    with args.output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=str(args.output), sha256=hashlib.sha256(raw).hexdigest())))
