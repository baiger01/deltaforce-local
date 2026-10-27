"""Normal one-object ServerOpenPickupBox request decoding for admitted callers.

The source is one present FObjectProperty parameter and the same generic native
RPC/object branch used by the existing Pawn-reference RPC codec. Missing native
Function weak serial/layout is retained as a qualification limit. GameplayTag
and ItemMoveCmd decoding are deliberately outside this proven one-field grammar.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

import portable_loot_box_codec as boxes
from dfserver.legacy_ds_actor_fields import ClassFieldEnvelope
from dfserver.legacy_ds_bit_archive import BitReader

ROOT=boxes.ROOT
RPC_SOURCE='work/evidence/map-system-audit-20261018/native-economy-interaction-normal-rpc-object-receive-v1.json'
RPC_SOURCE_SHA='70a2014b8e805279607b5b417b4b9151bd2d30c51baf7ae4210114cff2a0eb41'
PC_CLASS='/Game/BluePrints/Characters/BP_DFMPlayerController.BP_DFMPlayerController_C'
BOX_CLASS='/Script/DFMGameplay.InventoryPickup_OpenBox'
PC_EXCLUSIVE_MAX=245
RPC_INDEX=226
MAX_PARAMETER_BITS=41


@dataclass(frozen=True)
class OpenBoxRequest:
    recipient_scope: tuple[str,int]
    box_guid: int
    binding: boxes.LootBoxBinding


def source_pins():
    pins=boxes.source_pins()
    raw=(ROOT/RPC_SOURCE).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=RPC_SOURCE_SHA:
        raise ValueError('Changed generic native RPC/object receive source')
    source=json.loads(raw)
    anchors={(row['rva'],row['mnemonic'],row['operands'])
        for function in source['functions'] for row in function['instructions']}
    if (source.get('client_sha256')!=boxes.CLIENT_SHA256 or source.get('process_access') is not False or
            not {('0x12db9679','shr','rcx, 0x11'),
                 ('0x12db96cf','inc','qword ptr [r13 + 0xa8]'),
                 ('0x12db96e1','je','0x12db98ad'),
                 ('0x10e8ed76','call','qword ptr [rax + 0x260]')}<=anchors):
        raise ValueError('The normal RPC presence/object source qualification changed')
    capture=boxes._sources()[boxes.RPC_CAPTURE]
    owners=[row for row in capture['owners'] if row['scope']=='controller']
    if len(owners)!=1 or owners[0]['class_path']!=PC_CLASS or owners[0]['existing_driver_class']['exclusive_index_maximum']!=PC_EXCLUSIVE_MAX:
        raise ValueError('The actual current controller RPC receiver changed')
    functions=[row for row in owners[0]['rpc_functions'] if row['function_name']=='ServerOpenPickupBox']
    if len(functions)!=1 or functions[0]['network_index']!=RPC_INDEX:
        raise ValueError('The actual Box-opening RPC index changed')
    params=functions[0]['parameter_declarations']
    if len(params)!=1:
        raise ValueError('Only the exact one-Box-parameter native function is supported')
    parameter=params[0]
    field=parameter['field']
    if ((field['name'],field['element_bytes'],field['storage_offset'],field['field_vtable_rva'])!=
            ('Box',8,0,0x15a86b80) or parameter['serializer_hook']['target_rva']!=0x10e8ed20 or
            parameter['declared_native_class_path']!=BOX_CLASS):
        raise ValueError('The actual Box object parameter or serializer differs')
    pins[RPC_SOURCE]=RPC_SOURCE_SHA
    for relative in ('work/portable_loot_box_request.py',
            'outputs/df-local-server/dfserver/legacy_ds_pc_restart_rpc.py',
            'outputs/df-local-server/dfserver/legacy_ds_scalar_serializers.py'):
        pins[relative]=hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def decode_field(field,*,bindings_by_guid,references_resolved,exports_acknowledged,recipient_scope):
    """Decode an already-admitted controller field; never dispatch by payload alone."""
    if references_resolved is not True or exports_acknowledged is not True:
        raise ValueError('Current type-compatible GUID mappings and their actual export receipts are required')
    return decode_reference_field(field, bindings_by_guid=bindings_by_guid, recipient_scope=recipient_scope)


def decode_reference_field(field, *, bindings_by_guid, recipient_scope):
    """Parse one admitted reference use; this grants no resolution or mutation authority."""
    source_pins()
    if type(field) is not ClassFieldEnvelope or field.rep_index!=RPC_INDEX:
        raise ValueError('Only the exact observed controller ServerOpenPickupBox field is supported')
    if (type(recipient_scope) is not tuple or len(recipient_scope)!=2 or
            type(recipient_scope[0]) is not str or not 1<=len(recipient_scope[0])<=256 or
            type(recipient_scope[1]) is not int or not 0<recipient_scope[1]<1<<64):
        raise ValueError('The current admitted match/player RPC namespace is required')
    if type(bindings_by_guid) is not dict or not 1<=len(bindings_by_guid)<=3:
        raise ValueError('A bounded actual existing Box GUID dictionary is required')
    paths=set()
    for guid,binding in bindings_by_guid.items():
        if type(guid) is not int or not 3<=guid<1<<32 or not guid&1:
            raise ValueError('Only already-mapped static existing Box GUIDs are qualified')
        boxes.qualify_binding(binding)
        if binding.object_path in paths:
            raise ValueError('The actual Box mapping dictionary has aliased object paths')
        paths.add(binding.object_path)
    if type(field.payload_bit_count) is not int or not 1<=field.payload_bit_count<=MAX_PARAMETER_BITS:
        raise ValueError('The single-object RPC parameter bit extent is invalid')
    reader=BitReader(field.payload,bit_count=field.payload_bit_count)
    if not reader.read_bool():
        raise ValueError('A box-open action requires its present object parameter')
    guid=reader.read_packed_int()
    if guid not in bindings_by_guid or reader.remaining:
        raise ValueError('The request is not one exact mapped static Box reference')
    return OpenBoxRequest(recipient_scope,guid,bindings_by_guid[guid])
