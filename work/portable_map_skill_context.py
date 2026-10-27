"""One ordinary DFMSkill context block with three source-qualified leaves."""
import hashlib
import json
from pathlib import Path

from portable_map_skill_detail import (qualify_schema as qualify_detail,
    build_skill_detail_content,CLIENT,ROOT)
from portable_map_skill_player_index import (qualify_schema as qualify_index,
    skill_player_index_update as validate_assignment_update)
from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_bit_archive import BitWriter
from dfserver.legacy_ds_scalar_serializers import NativeScalarBinding,write_int32_value,write_bool_value

SCHEMA_PATH='outputs/df-local-server/protocol/portable-map-spawn/skill-context-schema.json'
SCHEMA_SHA256='48510d0390b3070835b70d6f8abc8f091f36dc976b5af0f151d00ee0bc78f18c'


def schema_binding(root=ROOT):
    root=Path(root).resolve()
    raw=(root/SCHEMA_PATH).read_bytes()
    schema=json.loads(raw)
    if (hashlib.sha256(raw).hexdigest()!=SCHEMA_SHA256 or schema.get('client_sha256')!=CLIENT or
            schema.get('kind')!='client_source_derived_combined_skill_context_schema'):
        raise ValueError('The combined skill-context receiver schema changed')
    for relative,digest in schema['sources'].items():
        path=(root/relative).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('The combined skill-context source changed: '+relative)
    return schema


def build_skill_context_content(detail_schema,index_schema,*,assignment,hero_id):
    qualify_detail(detail_schema)
    qualify_index(index_schema)
    if (detail_schema['component']!=index_schema['component'] or
            detail_schema['archive_profile']!=index_schema['archive_profile']):
        raise ValueError('Skill leaves require the same source-qualified component/archive')
    build_skill_detail_content(detail_schema,hero_id=hero_id)
    from portable_map_skill_player_index import build_skill_player_index_content
    build_skill_player_index_content(index_schema,assignment=assignment)
    values={**detail_schema['hero_values'][str(hero_id)],'SkillPlayerIndex':assignment.skill_player_index}
    fields=[(name,field) for name,field in detail_schema['fields'].items()]
    fields.append(('SkillPlayerIndex',index_schema['field']))
    fields.sort(key=lambda row:row[1]['ordinary_handle'])
    if [field['ordinary_handle'] for _,field in fields]!=[4,5,6]:
        raise ValueError('The actual ordinary skill handles changed')
    writer=BitWriter(maximum_bits=98)
    writer.write_bool(False)
    for name,field in fields:
        writer.write_packed_int(field['ordinary_handle'])
        if field['dispatch_opcode']==21:
            write_bool_value(writer,values[name],binding=NativeScalarBinding(CLIENT,
                int(field['serializer_rva'],16)))
        else:
            write_int32_value(writer,values[name],binding=NativeScalarBinding(CLIENT,
                int(field['serializer_rva'],16),int(field['scalar_leaf_rva'],16),
                int(field['property_vtable_rva'],16)),no_byteswap=True)
    writer.write_packed_int(0)
    if writer.bit_count!=98:raise ValueError('The combined source-derived skill width changed')
    return ActorContentBlock(True,writer.to_bytes(),writer.bit_count)


def skill_context_update(detail_schema,index_schema,*,assignment,hero_id,room_id,participant_uid,
        pawn_guid,component_guid,pawn_open_acknowledged,component_metadata_acknowledged):
    validate_assignment_update(index_schema,assignment=assignment,room_id=room_id,
        participant_uid=participant_uid,pawn_guid=pawn_guid,component_guid=component_guid,
        pawn_open_acknowledged=pawn_open_acknowledged,
        component_metadata_acknowledged=component_metadata_acknowledged)
    block=build_skill_context_content(detail_schema,index_schema,assignment=assignment,hero_id=hero_id)
    return DefaultSubobjectUpdate(pawn_guid,component_guid,detail_schema['component']['name'],
        SCHEMA_SHA256,block.payload,block.payload_bit_count,has_rep_layout=True)
