"""Native Actor role initialization shared by admitted weapon producers.

RemoteRole is remapped to Role by the ordinary receiver. The local server
replicates weapon Actors as SimulatedProxy; ownership remains a separate field.
"""
import hashlib
import json
from pathlib import Path

from portable_source_guard import cached_qualification


ROOT = Path(__file__).resolve().parents[1]
CAPTURE = 'work/native-client-tests/1792746695779188800/owned-weapon-mesh-followup.json'
CAPTURE_SHA = '11cc8c252e3d927b9cd2b7acf6f72b80abfe9e6dc13315d306bc785cc51be61d'
ROLE_SCHEMA = 'outputs/df-local-server/protocol/portable-map-spawn/player-receiver-schema.json'
ROLE_SCHEMA_SHA = '88eb799aa4dbc9667a320c8b95ba30af1b84fc5635a73a58bf3c7dd0ab56fe40'


def _pins():
    return {CAPTURE: CAPTURE_SHA, ROLE_SCHEMA: ROLE_SCHEMA_SHA,
        'work/weapon_actor_network_role.py': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


@cached_qualification(ROOT, extra_pins=_pins)
def role_binding():
    documents = {}
    for relative, expected in ((CAPTURE, CAPTURE_SHA), (ROLE_SCHEMA, ROLE_SCHEMA_SHA)):
        raw = (ROOT/relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('The native weapon role source changed: '+relative)
        documents[relative] = json.loads(raw)
    capture, schema = documents[CAPTURE], documents[ROLE_SCHEMA]
    from portable_map_player_state import qualify_schema
    qualify_schema(schema)
    if (capture.get('client_sha256') != schema['client_sha256'] or
            not all(capture.get(k) is True for k in ('identities_and_fields_rechecked',
                'selected_roots_rechecked', 'process_identity_rechecked')) or
            any(capture.get(k) is not False for k in ('process_memory_written',
                'native_methods_invoked', 'native_layouts_constructed', 'historical_process_pointers_reused'))):
        raise ValueError('A rechecked same-build weapon role observation is required')
    paths = ('/Game/BluePrints/Weapons/WeaponBP/MeleeWeaponBP/BP_EmptyHand.BP_EmptyHand_C',
             '/Game/BluePrints/Weapons/WeaponBP/BP_WeaponModular.BP_WeaponModular_C')
    remote = schema['role']['fields']['RemoteRole']
    for path in paths:
        rows = [a for a in capture['actual_manager_weapon_actors'] if a.get('class_path') == path]
        if len(rows) != 1 or rows[0]['existing_driver_class']['layout_status'] != 'exported_existing':
            raise ValueError('The actual weapon Role layout is missing: '+path)
        actor = rows[0]
        for name in ('Role', 'RemoteRole'):
            source = schema['role']['fields'][name]
            commands = [c for c in actor['existing_driver_class']['layout']['commands']
                        if c.get('descriptor_name') == name]
            fields = [(d['class_name'], f) for d in actor['declarations']
                      for f in d['fields'] if f['name'] == name]
            state = actor['state']['actor_fields'][name]
            values = {e['name']: e['value'] for e in state['enum']['entries']}
            if (len(commands) != 1 or len(fields) != 1 or fields[0][0] != 'Actor' or
                    (commands[0]['relative_handle'], commands[0]['data_offset'],
                     commands[0]['dispatch_opcode'], fields[0][1]['storage_offset'],
                     fields[0][1]['element_bytes']) !=
                    (source['wire_handle'], source['source_offset'], 6, source['source_offset'], 1) or
                    fields[0][1]['hooks']['0x90']['target_rva'] != source['serializer_target_rva'] or
                    values != source['enum_values']):
                raise ValueError('The inherited weapon Actor Role declaration differs: '+name)
    return dict(handle=remote['wire_handle'], value=remote['enum_values']['ROLE_SimulatedProxy'],
                wire_bits=remote['wire_bit_count'], sources=_pins())


def source_pins():
    return dict(role_binding()['sources'])


def write_network_role(writer):
    binding = role_binding()
    writer.write_packed_int(binding['handle'])
    writer.write_bits(binding['value'], binding['wire_bits'])
