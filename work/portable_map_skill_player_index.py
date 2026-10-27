"""Pure initial one-participant SkillPlayerIndex update; no ability grant."""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from portable_map_skill_initialization import CLIENT_SHA256 as CLIENT
from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitWriter, UINT32_MAX
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_scalar_serializers import NativeScalarBinding, write_int32_value

ROOT=Path(__file__).resolve().parent.parent
SCHEMA_PATH='outputs/df-local-server/protocol/portable-map-spawn/skill-player-index-schema.json'
SCHEMA_SHA256='b268cfefb902dad939df020525b788baeeca58cb3aa2d62b070c8a4de043481f'


def qualify_schema(schema):
    if type(schema) is not dict:
        raise ValueError('The source-qualified skill-player schema is required')
    raw=(json.dumps(schema,indent=2,sort_keys=True)+'\n').encode()
    if (hashlib.sha256(raw).hexdigest()!=SCHEMA_SHA256 or schema.get('client_sha256')!=CLIENT or
            schema.get('kind')!='client_source_derived_skill_player_index_schema'):
        raise ValueError('The source-qualified skill-player schema is required')
    return schema


def schema_binding(root=ROOT):
    root=Path(root).resolve()
    raw=(root/SCHEMA_PATH).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SCHEMA_SHA256:
        raise ValueError('The skill-player schema changed')
    schema=qualify_schema(json.loads(raw))
    for relative,digest in schema['sources'].items():
        path=(root/relative).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('The skill-player source changed: '+relative)
    return schema


@dataclass(frozen=True)
class InitialSkillPlayerAssignment:
    room_id: str
    participant_uid: int
    skill_player_index: int
    schema_sha256: str


def initial_assignment(schema, *, room_id, participant_uids, existing_native_slots):
    """First append writes old empty array count=0; UID is a service binding label."""
    qualify_schema(schema)
    if (type(room_id) is not str or not 0<len(room_id)<=256 or
            type(participant_uids) is not tuple or len(participant_uids)!=1 or
            type(participant_uids[0]) is not int or not 0<participant_uids[0]<1<<64 or
            type(existing_native_slots) is not tuple or existing_native_slots):
        raise ValueError('One frozen admitted participant and an initially empty room roster are required')
    return InitialSkillPlayerAssignment(room_id,participant_uids[0],0,SCHEMA_SHA256)


def build_skill_player_index_content(schema, *, assignment):
    qualify_schema(schema)
    if (type(assignment) is not InitialSkillPlayerAssignment or
            assignment.schema_sha256!=SCHEMA_SHA256 or assignment.skill_player_index!=0 or
            type(assignment.participant_uid) is not int or not 0<assignment.participant_uid<1<<64 or
            type(assignment.room_id) is not str or not 0<len(assignment.room_id)<=256):
        raise ValueError('A frozen source-qualified initial participant assignment is required')
    field=schema['field']
    writer=BitWriter(maximum_bits=49)
    writer.write_bool(False)
    writer.write_packed_int(field['ordinary_handle'])
    write_int32_value(writer,assignment.skill_player_index,binding=NativeScalarBinding(CLIENT,
        int(field['serializer_rva'],16),int(field['scalar_leaf_rva'],16),
        int(field['property_vtable_rva'],16)),no_byteswap=True)
    writer.write_packed_int(0)
    if writer.bit_count!=49: raise ValueError('The qualified skill-player stream width changed')
    return ActorContentBlock(True,writer.to_bytes(),writer.bit_count)


def skill_player_index_update(schema, *, assignment, room_id, participant_uid, pawn_guid,
        component_guid, pawn_open_acknowledged, component_metadata_acknowledged):
    block=build_skill_player_index_content(schema,assignment=assignment)
    if (room_id!=assignment.room_id or type(participant_uid) is not int or
            participant_uid!=assignment.participant_uid or pawn_open_acknowledged is not True or
            component_metadata_acknowledged is not True or
            any(type(g) is not int or not 2<=g<=UINT32_MAX or g&1 for g in (pawn_guid,component_guid)) or
            pawn_guid==component_guid):
        raise ValueError('Actual matching admission, distinct GUIDs and preceding real ACKs are required')
    return DefaultSubobjectUpdate(pawn_guid,component_guid,schema['component']['name'],
        SCHEMA_SHA256,block.payload,block.payload_bit_count,has_rep_layout=True)
