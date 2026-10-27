"""Frozen real-row initial owner SkillState ordinary replication producer.

No RPC, native call, ability object fabrication, account write or transport.
Normal native OnRep consumes the array and creates its actual skill entities.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'outputs/df-local-server'))
from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitWriter, UINT32_MAX
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_scalar_serializers import NativeScalarBinding, write_int32_value, write_bool_value
from portable_map_skill_player_index import (InitialSkillPlayerAssignment,
    build_skill_player_index_content, schema_binding as index_schema_binding)

CLIENT = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
SCHEMA_PATH = 'work/evidence/model-init-chain-20261018/native-skill-initial-state-wire-contract-v3.json'
SCHEMA_SHA256 = '1ba99f60b484de242df4ea4954a2b0e2065b5589e549ff385597aa974a6b53e3'


def qualify_schema(schema):
    if (type(schema) is not dict or schema.get('client_sha256') != CLIENT
            or hashlib.sha256((json.dumps(schema, indent=2, sort_keys=True)+'\n').encode()).hexdigest()
            != SCHEMA_SHA256):
        raise ValueError('The exact actual SkillState wire contract is required')
    return schema


def schema_binding(root=ROOT):
    root = Path(root).resolve()
    raw = (root/SCHEMA_PATH).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError('The source SkillState wire contract changed')
    schema = qualify_schema(json.loads(raw))
    for relative, digest in schema['sources'].items():
        path = (root/relative).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('The SkillState source changed: '+relative)
    return schema


def select_source_plan(schema, hero_id):
    qualify_schema(schema)
    if type(hero_id) is not int:
        raise ValueError('The actual admitted hero template ID is required')
    key = str(hero_id)
    plan = schema['hero_plans'].get(key)
    if plan is None:
        reason = schema['unsupported_hero_bindings'].get(key, {}).get('reason', 'unknown_hero_source')
        raise ValueError('The actual hero has no qualified SOL skill binding: '+reason)
    return plan


def required_entity_id_count(schema, hero_id):
    return select_source_plan(schema, hero_id)['required_entity_id_count']


@dataclass(frozen=True)
class FrozenInitialSkillGrant:
    room_id: str
    participant_uid: int
    hero_id: int
    skill_player_index: int
    all_entries: tuple
    owner_entries: tuple
    schema_sha256: str


def freeze_initial_grant(schema, *, assignment, hero_id, first_entity_unique_id):
    qualify_schema(schema)
    if type(assignment) is not InitialSkillPlayerAssignment:
        raise ValueError('The frozen initial one-participant assignment is required')
    build_skill_player_index_content(index_schema_binding(), assignment=assignment)
    rows = select_source_plan(schema, hero_id)['source_row_plan']
    if (type(first_entity_unique_id) is not int or not 0 < first_entity_unique_id
            <= 0x7fffffff-len(rows)+1):
        raise ValueError('Real qualified hero and bounded positive local instance counter required')
    entries = tuple((row['skill_id'], first_entity_unique_id+i) for i, row in enumerate(rows))
    owner = tuple(entry for entry, row in zip(entries, rows)
                  if row['ordinary_owner_state_required_by_bit1'])
    return FrozenInitialSkillGrant(assignment.room_id, assignment.participant_uid, hero_id,
                                  assignment.skill_player_index, entries, owner, SCHEMA_SHA256)


def _validate_grant(schema, grant):
    qualify_schema(schema)
    if (type(grant) is not FrozenInitialSkillGrant or grant.schema_sha256 != SCHEMA_SHA256
            or type(grant.room_id) is not str or not 0 < len(grant.room_id) <= 256
            or type(grant.participant_uid) is not int or not 0 < grant.participant_uid < 1 << 64
            or type(grant.hero_id) is not int
            or type(grant.skill_player_index) is not int or grant.skill_player_index != 0
            or type(grant.all_entries) is not tuple or not grant.all_entries
            or any(type(entry) is not tuple or len(entry) != 2
                   or any(type(value) is not int for value in entry) for entry in grant.all_entries)):
        raise ValueError('The actual frozen initial skill assignment is required')
    rows = select_source_plan(schema, grant.hero_id)['source_row_plan']
    first = grant.all_entries[0][1]
    if not 0 < first <= 0x7fffffff-len(rows)+1:
        raise ValueError('The local skill entity counter is invalid')
    expected = tuple((row['skill_id'], first+i) for i, row in enumerate(rows))
    owner = tuple(entry for entry, row in zip(expected, rows)
                  if row['ordinary_owner_state_required_by_bit1'])
    if grant.all_entries != expected or grant.owner_entries != owner or not owner:
        raise ValueError('The frozen skill rows, order or local entity IDs differ')


def _binding(command):
    hook = command['property_serializer_hook']
    leaf = command.get('property_scalar_leaf_hook')
    return NativeScalarBinding(CLIENT, hook['target_rva'],
        leaf['target_rva'] if leaf else None, hook['vtable_rva'])


def build_owner_initial_content(schema, *, grant):
    _validate_grant(schema, grant)
    array = schema['arrays']['owner']
    top, *commands = array['commands']
    writer = BitWriter(maximum_bits=8192)
    writer.write_bool(False)
    writer.write_packed_int(top['relative_handle'])
    writer.write_bytes(len(grant.owner_entries).to_bytes(2, 'little'))
    # Native12dbacf0 keeps one child counter across the complete array.
    for index, (skill_id, unique_id) in enumerate(grant.owner_entries):
        values = {'SkillId': skill_id, 'SkillEntityUniqueID': unique_id,
                  **schema['initial_values']}
        for command in commands:
            writer.write_packed_int(index*array['child_handle_count']+command['relative_handle'])
            name = command['descriptor_name']
            if name == 'ExcueteDatas':
                writer.write_bytes(bytes(2))
                writer.write_packed_int(0)
            elif command['dispatch_opcode'] == 21:
                write_bool_value(writer, values[name], binding=_binding(command))
            else:
                write_int32_value(writer, values[name], binding=_binding(command), no_byteswap=True)
    writer.write_packed_int(0)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)


def owner_initial_update(schema, *, grant, room_id, participant_uid, hero_id, pawn_guid,
        component_guid, pawn_open_acknowledged, component_metadata_acknowledged,
        skill_context_acknowledged):
    block = build_owner_initial_content(schema, grant=grant)
    if (room_id != grant.room_id or type(participant_uid) is not int
            or participant_uid != grant.participant_uid or type(hero_id) is not int
            or hero_id != grant.hero_id or pawn_open_acknowledged is not True
            or component_metadata_acknowledged is not True or skill_context_acknowledged is not True
            or any(type(guid) is not int or not 2 <= guid <= UINT32_MAX or guid & 1
                   for guid in (pawn_guid, component_guid)) or pawn_guid == component_guid):
        raise ValueError('Actual admitted identity and preceding real Pawn/component/context ACKs required')
    return DefaultSubobjectUpdate(pawn_guid, component_guid, schema['component']['name'],
        SCHEMA_SHA256, block.payload, block.payload_bit_count, has_rep_layout=True)
