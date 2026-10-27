"""Pure ordinary dynamic UObject creation for the source main Pawn FSM.

An empty creation does not bind R_Instance or initialize/start a state graph.
Current generated class metadata and real transport receipts gate admission.
"""
from dataclasses import dataclass
import hashlib
import json

from dfserver.legacy_ds_bit_archive import BitWriter, UINT32_MAX
from dfserver.legacy_ds_guid_exports import GuidExportNode
from dfserver.legacy_ds_dynamic_object_creation import (DynamicObjectCreation,
    SOURCE_SHA256, write_creation)
from fsm_readonly_scope import ROOT, CLIENT, FOLDER, PATHS, sealed
from fsm_generated_class_scope import source_pins as class_sources, contract as class_contract

CLASS_PATH = PATHS['instance']
PINS = {
    FOLDER+'native-current-skill-dynamic-subobject-receive-header-v1.json':
        '027ef34cb7fce8aa76a8e663b0e4e8ffe7486bae51fee5934d72742ee286770c',
    FOLDER+'native-current-fsm-instance-creation-contract-v1.json':
        'd9f30139583e9c40fb320590279de021d500356eb65fa14aacbab7d504639fad',
    FOLDER+'native-current-fsm-instance-initialization-contract-v1.json':
        '4099a2257715a7acf13661d7904785f510b5c697036611d262d1177f07a83b68',
}


FSMInstanceCreation = DynamicObjectCreation


@dataclass(frozen=True)
class FSMInstanceCreationContent:
    payload: bytes
    payload_bit_count: int


def qualification():
    docs = {path: sealed(path, digest) for path, digest in PINS.items()}
    class_contract()
    creation = docs[FOLDER+'native-current-fsm-instance-creation-contract-v1.json']
    if (creation['factory']['outer_is_context'] is not True or
            creation['factory']['outer_is_component'] is not False):
        raise ValueError('The normal FSM instance Outer source changed')
    source = docs[FOLDER+'native-current-skill-dynamic-subobject-receive-header-v1.json']
    ins = {i['rva']: i for f in source['functions'] for i in f['instructions']}
    for at, mnemonic, operands in (
        ('0x128647a5', 'mov', 'rbx, qword ptr [r13 + 0x70]'),
        ('0x128647d6', 'mov', 'rdx, rbx'), ('0x128647de', 'mov', 'rcx, rdi'),
        ('0x128647f5', 'call', '0x10ebd0a0'),
        ('0x12864809', 'call', 'qword ptr [r8 + 0x2b0]')):
        if (ins[at]['mnemonic'], ins[at]['operands']) != (mnemonic, operands):
            raise ValueError('The normal dynamic UObject creation receiver changed')
    return dict(kind='source_qualified_empty_main_fsm_instance_creation_v1',
        client_sha256=CLIENT, instance_class_path=CLASS_PATH, outer='current_channel_Pawn',
        connection_network_version=13, archive_network_version=13,
        stably_named=False, class_guid_export_required=True, instance_path_exported=False,
        new_object_name='NAME_None', explicit_object_flags=0,
        property_handles=[], actual_class_metadata_required=True,
        current_pawn_and_class_export_ACK_required=True, fsm_kickoff_ACK_required=True,
        exact_creation_ACK_required_before_dependent_fields=True,
        fsm_instance_initialized_claimed=False, native_acceptance_verified=False,
        remaining=['actual component R_Instance handle/serializer and current instance reference',
            'actual generated instance R_StateMachineContext handle/serializer and Pawn reference',
            'actual generated instance R_bHasStarted serializer/handle and RepNotify arrival order'])


def source_pins():
    qualification()
    pins = dict(class_sources(), **PINS)
    for relative in ('work/portable_map_fsm_instance.py',
            'outputs/df-local-server/dfserver/legacy_ds_dynamic_object_creation.py',
            'outputs/df-local-server/dfserver/legacy_ds_bit_archive.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def _schema_sha():
    return hashlib.sha256((json.dumps(qualification(), indent=2, sort_keys=True)+'\n').encode()).hexdigest()


def project_instance_class_export(*, package_guid, class_guid, allocated_guids):
    """Export the class asset; the dynamic instance receives no name/path export."""
    qualification()
    if (type(allocated_guids) is not tuple or not 1 <= len(allocated_guids) <= 65536 or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX for g in allocated_guids) or
            len(set(allocated_guids)) != len(allocated_guids) or
            any(type(g) is not int or not 3 <= g <= UINT32_MAX or not g & 1
                for g in (package_guid, class_guid)) or package_guid == class_guid or
            package_guid in allocated_guids or class_guid in allocated_guids):
        raise ValueError('Two distinct fresh static asset GUIDs outside the complete namespace are required')
    package_path, class_name = CLASS_PATH.rsplit('.',1)
    return GuidExportNode(class_guid, class_name, GuidExportNode(package_guid, package_path))


def project_instance_creation(*, pawn_guid, class_guid, instance_guid, allocated_guids):
    qualification()
    if (type(allocated_guids) is not tuple or not 1 <= len(allocated_guids) <= 65536 or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX for g in allocated_guids) or
            len(set(allocated_guids)) != len(allocated_guids) or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX or g & 1 for g in (pawn_guid, instance_guid)) or
            type(class_guid) is not int or not 3 <= class_guid <= UINT32_MAX or not class_guid & 1 or
            pawn_guid not in allocated_guids or class_guid not in allocated_guids or instance_guid in allocated_guids):
        raise ValueError('The exact current Pawn/class namespace and a fresh dynamic instance GUID are required')
    if _schema_sha() != SOURCE_SHA256:
        raise ValueError('The pinned dynamic UObject protocol creation schema changed')
    return FSMInstanceCreation(pawn_guid, instance_guid, class_guid, CLASS_PATH, SOURCE_SHA256)


def build_instance_creation(*, current_pawn_bound, pawn_open_acknowledged,
        pawn_content_acknowledged, class_export_acknowledged, fsm_kickoff_acknowledged,
        generated_class_metadata, class_export=None, **kwargs):
    row = generated_class_metadata
    if (type(row) is not dict or row.get('status') != 'observed' or row.get('class_path') != CLASS_PATH or
            row.get('reference_origin') != 'component.StateMachineClass' or
            row.get('metadata_recheck_required') is not False or
            row.get('identities_and_fields_rechecked') is not True or row.get('is_actor_or_component') is not False or
            row.get('existing_cdo', {}).get('status') != 'existing_cdo_identity_verified' or
            row['existing_cdo'].get('networking_supported_by_exact_native_target') is not True or
            row['existing_cdo'].get('networking_virtual_target_rva') != '0xd5c5d0' or
            row['existing_cdo'].get('networking_virtual_slot') != 0x1d0):
        raise ValueError('The current rechecked generated FSM class metadata is required')
    package_path, class_name = CLASS_PATH.rsplit('.', 1)
    if (type(class_export) is not GuidExportNode or class_export.guid != kwargs['class_guid'] or
            class_export.path != class_name or type(class_export.outer) is not GuidExportNode or
            class_export.outer.path != package_path or class_export.outer.outer is not None or
            class_export.outer.guid not in kwargs['allocated_guids'] or
            class_export.outer.guid == class_export.guid or not class_export.outer.guid & 1):
        raise ValueError('The exact current generated FSM package/class export binding is required')
    if not all(v is True for v in (current_pawn_bound, pawn_open_acknowledged,
            pawn_content_acknowledged, class_export_acknowledged, fsm_kickoff_acknowledged)):
        raise ValueError('The current Pawn and exact parent/class/FSM kickoff ACKs are required')
    return project_instance_creation(**kwargs)


def build_instance_creation_content(update):
    if (type(update) is not FSMInstanceCreation or update.class_path != CLASS_PATH or
            update.source_sha256 != _schema_sha() or update.payload != b'\0\0' or
            update.payload_bit_count != 9):
        raise ValueError('Only the source-qualified empty FSM instance creation is supported')
    project_instance_creation(pawn_guid=update.outer_guid, class_guid=update.class_guid,
        instance_guid=update.guid, allocated_guids=(update.outer_guid, update.class_guid))
    writer = BitWriter(maximum_bits=256)
    write_creation(writer, update, actor_guids=(update.outer_guid,),
        exported_class_bindings=((update.class_guid, update.class_path),),
        allocated_guids=(update.outer_guid, update.class_guid))
    return FSMInstanceCreationContent(writer.to_bytes(), writer.bit_count)
