"""Public weapon Actor initialization fields from an existing current layout."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from owned_weapon_values_codec import CLIENT_SHA, SCHEMA_PATH, SCHEMA_SHA256, schema_binding

ROOT = Path(__file__).resolve().parent.parent
BASE = 'work/evidence/map-system-audit-20261018/'
CAPTURE = 'work/native-client-tests/1792304896147723900/owned-gameplay-metadata.json'
PINS = {
    CAPTURE: '71a25ea64f873ba51b68a28b412755c92252d361498916eb0e5618e0add92827',
    BASE+'native-owning-weapon-actor-property-serializers-v1.json':
        'dd600b28177bccef60437b6c4fa1db516271adfbfe383ea7f720dd6a9e648158',
    BASE+'native-owning-weapon-actor-scalar-archive-v1.json':
        '35633aa498c7d9a03284d6cfcf8f4a66b3f40fbd98307fc648a57747edb89141',
    BASE+'native-owning-weapon-packaged-gpweapon-settings.json':
        '50eeedcc2190dd0bb80ade3b4b7d737aad8de6f84c3120bcbc262dfa39c7a89d',
    BASE+'native-owning-weapon-manager-uht-declarations.json':
        '0569188ebaa5b9549abad6a4e327fe2fc041e6f9de9566da75a6b175b925e313',
    BASE+'native-array-property-receive.json':
        '90a2f91c29934c8bfd4d109ef515c7383d23d1ac76770fd383c455d3f01f21ae',
    BASE+'native-recursive-property-array-walk.json':
        '7dce23dcd1363cec1c3ac6476e5fe0ebf1bdb0ec970c8cec0917692ccfd02fe1',
}


def _one(values, label):
    if len(values) != 1:
        raise ValueError('Ambiguous actual weapon source '+label)
    return values[0]


def _field(obj, name):
    declaration, field = _one([(d, f) for d in obj['declarations'] for f in d['fields']
        if f['name'] == name], name)
    hook = field['hooks']['0x90']
    if (field['array_dimension'] != 1 or not int(field['property_flags'], 16) & 0x20 or
            any(h['inside_pinned_image'] is not True or h['identity_rechecked'] is not True or
                h['target_module_sha256'] != CLIENT_SHA for h in field['hooks'].values())):
        raise ValueError('Unqualified actual weapon property '+name)
    cache = obj['existing_driver_class']
    entry = _one([f for n in cache['cache_nodes'] for f in n['fields']
        if f.get('descriptor_name') == name and f['descriptor_representation'] == 0], name+' cache')
    return dict(name=name, declaring_class=declaration['class_name'],
        storage_offset=field['storage_offset'], storage_bytes=field['element_bytes'],
        property_flags=field['property_flags'], declared_rep_index=field['declared_rep_index'],
        class_cache_index=entry['rep_index'], property_vtable_rva=hex(field['field_vtable_rva']),
        serializer_rva=hex(hook['target_rva']), archive_serializer_rva=hex(field['hooks']['0x88']['target_rva']))


def _command(obj, name, *, offset, parent=None):
    return _one([c for c in obj['existing_driver_class']['layout']['commands']
        if c.get('descriptor_name') == name and c['data_offset'] == offset and
        (parent is None or c['parent_index'] == parent)], name+' command')


def derive():
    baseline = schema_binding()
    docs = {}
    for relative, expected in PINS.items():
        raw = (ROOT/relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Changed weapon Actor source '+relative)
        docs[relative] = json.loads(raw)
        if docs[relative]['client_sha256'] != CLIENT_SHA:
            raise ValueError('Changed weapon Actor source build')
    capture = docs[CAPTURE]
    if (capture['status'] != 'observed' or not all(capture[k] is True for k in (
            'identities_and_fields_rechecked', 'selected_roots_rechecked', 'process_identity_rechecked')) or
            any(capture[k] is not False for k in ('process_memory_written', 'native_methods_invoked',
                'native_layouts_constructed', 'packets_sent', 'code_sampled', 'historical_process_pointers_reused'))):
        raise ValueError('Weapon Actor metadata was not a rechecked read-only observation')
    actor = _one([x for x in capture['loaded_named_classes']
        if x['class_path'] == baseline['empty_hand_actor']['class_path']], 'EmptyHand class')
    manager = _one([x for x in capture['objects'] if x['identity']['name'] == 'WeaponManager'], 'manager')
    for obj in (actor, manager):
        cache = obj['existing_driver_class']
        if cache['cache_status'] != 'exported_existing' or cache['layout_status'] != 'exported_existing':
            raise ValueError('Existing weapon Actor or manager layout missing')
    expected = {
        'Owner': (0x120, 14, 8, 8), 'WeaponID': (0x838, 17, 20, 64),
        'WeaponGuid': (0x840, 18, 20, 64), 'WeaponEquipPosition': (0x848, 19, 9, 32),
        'WeaponSlot': (0x84c, 20, 6, 8), 'CharacterOwner': (0xa60, 41, 8, 8),
    }
    fields = {}
    for name, (offset, handle, opcode, width) in expected.items():
        field = _field(actor, name)
        command = _command(actor, name, offset=offset)
        if field['storage_offset'] != offset or (command['relative_handle'], command['dispatch_opcode']) != (handle, opcode):
            raise ValueError('Current Actor field differs '+name)
        field.update(ordinary_handle=handle, dispatch_opcode=opcode,
            wire_bits=None if opcode == 8 else width,
            wire='packed_net_guid' if opcode == 8 else 'raw_little_endian_bits',
            command_sha256=command['record_sha256'])
        fields[name] = field
    identity = _field(actor, 'ServerWeaponIdentity')
    command = _command(actor, 'UniqueId', offset=0x9e0, parent=28)
    if (identity['storage_offset'], identity['storage_bytes'], command['relative_handle'], command['dispatch_opcode']) != (0x9e0, 4, 40, 9):
        raise ValueError('Current Actor WeaponIdentity differs')
    identity.update(inner_name='UniqueId', inner_handle=40, wire_bits=32,
        wire='raw_little_endian_bits', command_sha256=command['record_sha256'])
    fields['ServerWeaponIdentity'] = identity
    arrays = {}
    for name, offset, handle, opcode, width in (
            ('WeaponList', 0x198, 3, 8, None), ('WeaponIdentityList', 0x1a8, 4, 9, 32),
            ('WeaponIDList', 0x1b8, 5, 20, 64)):
        field = _field(manager, name)
        command = _command(manager, name, offset=offset)
        commands = manager['existing_driver_class']['layout']['commands']
        inner = commands[command['command_index']+1]
        end = commands[command['command_index']+2]
        if ((command['relative_handle'], command['dispatch_opcode'], inner['relative_handle'],
                inner['dispatch_opcode'], end['dispatch_opcode']) != (handle, 0, 1, opcode, 1)):
            raise ValueError('Current manager array differs '+name)
        field.update(ordinary_handle=handle, inner_handle=1, inner_opcode=opcode,
            element_wire_bits=width, command_sha256=command['record_sha256'],
            inner_command_sha256=inner['record_sha256'])
        arrays[name] = field
    manager_uht = docs[BASE+'native-owning-weapon-manager-uht-declarations.json']
    records = [row for klass in manager_uht['classes'] for row in klass['properties']]
    for name, generation in (('WeaponList', '0x12'), ('WeaponIdentityList', '0x19'), ('WeaponIDList', '0x7')):
        inner = _one([r for r in records if r['name'] == name and r['native_offset'] == '0x0'], name+' UHT inner')
        if inner['generation_low8'] != generation:
            raise ValueError('Actual manager array inner type differs '+name)
    instructions = {i['rva']: i['bytes'] for d in docs.values()
        for f in d.get('functions', ()) for i in f['instructions']}
    for rva, expected_bytes in {'0x10e5ce75': 'ff9088000000',
            '0x286c014': '488d4208', '0x286c01e': '488b02', '0x286c021': '498900',
            '0x286bf84': '488d4204', '0x286bf8e': '8b02', '0x286bf90': '418900',
            '0x12dbae7c': '488d4202', '0x12dbae86': '0fb702',
            '0x12dbaf6d': 'ff5078', '0x12dbb0a2': 'e849fcffff'}.items():
        if instructions.get(rva) != expected_bytes:
            raise ValueError('Actual raw scalar serializer changed '+rva)
    settings = docs[BASE+'native-owning-weapon-packaged-gpweapon-settings.json']
    recid = _one([(source, row) for source in settings['sources'] for row in source['settings']
        if row['section'] == '[/Script/GPWeaponRuntime.GPWeaponGlobals]' and
        re.fullmatch(r'EmptyHandRecId=\d+', row['setting'])], 'EmptyHandRecId')
    common = _one([int(k) for k, path in baseline['fast_class_path']['ids_to_paths'].items()
        if path == actor['class_path']], 'EmptyHand common class ID')
    return dict(kind='client_source_derived_owned_weapon_actor_initialization_v1', client_sha256=CLIENT_SHA,
        sources=dict(baseline['sources'], **{SCHEMA_PATH: SCHEMA_SHA256}, **PINS),
        actor=dict(class_path=actor['class_path'],
            cache_exclusive_maximum=actor['existing_driver_class']['exclusive_index_maximum'], fields=fields,
            layout_commands_sha256=actor['existing_driver_class']['layout']['commands_sha256']),
        manager=dict(class_path=manager['class_path'], arrays=arrays, empty_hand_handle=7,
            array_count_wire_bits=16, scalar_element_handle_stride=1, array_terminal_handle=0),
        empty_hand=dict(rec_id=int(recid[1]['setting'].split('=')[1]), common_class_id=common,
            rec_id_origin='source_packaged_gp_weapon_globals', source_config=recid[0]['path'],
            source_config_sha256=recid[0]['decoded_sha256'], source_line=recid[1]['line_number'],
            runtime_ini_override_precedence_qualified=False, inventory_gid_assigned=False),
        local_policy=dict(identity_origin='ticket_cookie_and_exact_frozen_loadout_sha256_nonzero_uint32',
            identity_is_inventory_gid=False, empty_hand_activation_requires_explicit_opt_in=True,
            manager_lists_are_complete_replacements=True),
        limitations=['Ordinary gun/melee Actor class, CDO, RecID and equipment-slot mapping remain unqualified.',
            'Packaged EmptyHand defaults are an explicit baseline; runtime INI precedence is not recovered.',
            'Transport delivery and these source-derived values do not prove native weapon initialization.'],
        public_schema_contains_process_addresses=False, native_gameplay_verified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = (json.dumps(derive(), indent=2, sort_keys=True)+'\n').encode()
    with args.output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=str(args.output), sha256=hashlib.sha256(raw).hexdigest())))
