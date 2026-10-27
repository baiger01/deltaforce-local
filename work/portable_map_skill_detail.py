"""Pure normal SkillDetailInfo content for an acknowledged real default component.

This selects ExpertId through the installed Hero binding. It grants no dynamic
ability, creates no SkillDataFlow and changes no health or speed attribute.
"""
import hashlib
import json
from pathlib import Path

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitWriter, UINT32_MAX
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_scalar_serializers import (NativeScalarBinding,
    write_int32_value, write_bool_value)


ROOT=Path(__file__).resolve().parent.parent
CLIENT='4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
SCHEMA_PATH='outputs/df-local-server/protocol/portable-map-spawn/skill-detail-schema.json'
SCHEMA_SHA256='eb1b9a9e1c4641476c9faf80ba8d3485c14661a0e69fe30acf80db7e5eab1fcf'


def qualify_schema(schema):
    if type(schema) is not dict:
        raise ValueError('The actual captured SkillDetailInfo receiver schema is required')
    raw=(json.dumps(schema,indent=2,sort_keys=True)+'\n').encode()
    if (hashlib.sha256(raw).hexdigest()!=SCHEMA_SHA256 or schema.get('client_sha256')!=CLIENT or
            schema.get('kind')!='client_source_derived_skill_detail_receiver_schema'):
        raise ValueError('The actual captured SkillDetailInfo receiver schema is required')
    return schema


def schema_binding(root=ROOT):
    root=Path(root).resolve()
    raw=(root/SCHEMA_PATH).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SCHEMA_SHA256:
        raise ValueError('The SkillDetailInfo receiver schema file changed')
    schema=qualify_schema(json.loads(raw))
    for relative,digest in schema['sources'].items():
        path=(root/relative).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('The SkillDetailInfo source changed: '+relative)
    return schema


def build_skill_detail_content(schema, *, hero_id):
    """Normal option=false, handle4/int32, handle5/bool, terminal handle0.

    The normal v13 archive has no byte swap and no internal ACK/checksum branch.
    Call only for the HeroId frozen in this admitted ticket. Configuration IDs
    remain separate from all service-created ability or network identities.
    """
    qualify_schema(schema)
    if type(hero_id) is not int or not 0<hero_id<1<<64:
        raise ValueError('The admitted numeric HeroId is required')
    value=schema['hero_values'].get(str(hero_id))
    if value is None:
        raise ValueError('No supported installed Hero-to-Expert binding: '+str(hero_id))
    writer=BitWriter(maximum_bits=58)
    writer.write_bool(False)
    expert=schema['fields']['ExpertId']
    writer.write_packed_int(expert['ordinary_handle'])
    write_int32_value(writer,value['ExpertId'],binding=NativeScalarBinding(CLIENT,
        int(expert['serializer_rva'],16),int(expert['scalar_leaf_rva'],16),
        int(expert['property_vtable_rva'],16)),no_byteswap=True)
    sliding=schema['fields']['CanSlidingTackle']
    writer.write_packed_int(sliding['ordinary_handle'])
    write_bool_value(writer,value['CanSlidingTackle'],binding=NativeScalarBinding(CLIENT,
        int(sliding['serializer_rva'],16)))
    writer.write_packed_int(0)
    if writer.bit_count!=58:
        raise ValueError('The qualified SkillDetailInfo stream width changed')
    return ActorContentBlock(True,writer.to_bytes(),writer.bit_count)


def skill_detail_update(schema, *, hero_id, pawn_guid, component_guid,
        pawn_open_acknowledged, component_metadata_acknowledged):
    """Return one typed update; allocation, transport and retry state belong to caller."""
    qualify_schema(schema)
    if (pawn_open_acknowledged is not True or component_metadata_acknowledged is not True or
            any(type(g) is not int or not 2<=g<=UINT32_MAX or g&1
                for g in (pawn_guid,component_guid)) or pawn_guid==component_guid):
        raise ValueError('Distinct current Pawn/component GUIDs and preceding real ACKs are required')
    block=build_skill_detail_content(schema,hero_id=hero_id)
    return DefaultSubobjectUpdate(pawn_guid,component_guid,schema['component']['name'],
        SCHEMA_SHA256,block.payload,block.payload_bit_count,has_rep_layout=True)
