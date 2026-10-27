"""Qualified context/bind/start projection for the actual created main FSM."""
from hashlib import sha256
import json
from pathlib import Path

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_dynamic_object_update import DynamicObjectUpdate
from dfserver.legacy_ds_scalar_serializers import NativeScalarBinding, write_bool_value
from dfserver.legacy_ds_rep_layout_refs import ObjectReference, build_object_reference_content
from dfserver.legacy_ds_rep_layout_refs import read_object_reference_content
from dfserver.legacy_ds_actor_content import ActorContentBlock

ROOT = Path(__file__).resolve().parent.parent
CLIENT = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
CAPTURE = 'work/native-client-tests/1792401899578422100/owned-fsm-metadata.json'
COMPONENT = '/Script/GPGameplay.GPFSMStateMachineComponent'
INSTANCE = '/Game/BluePrints/Characters/CharacterFSM/DFMCharacterFSM_Main.DFMCharacterFSM_Main_C'
BASE = 'work/evidence/model-init-chain-20261018/'
PINS = {
    CAPTURE: '023f0fe5948a40df42578c1b3d88c1cb973e8113271d922d3b0c8941ad099c29',
    BASE + 'native-current-fsm-instance-initialization-contract-v1.json':
        '4099a2257715a7acf13661d7904785f510b5c697036611d262d1177f07a83b68',
    BASE + 'native-current-skill-dynamic-subobject-receive-header-v1.json':
        '027ef34cb7fce8aa76a8e663b0e4e8ffe7486bae51fee5934d72742ee286770c',
}


def sealed(relative):
    raw = (ROOT / relative).read_bytes()
    if sha256(raw).hexdigest() != PINS[relative]:
        raise ValueError('The exact current FSM source changed: ' + relative)
    return json.loads(raw)


def derive_schema():
    capture = sealed(CAPTURE)
    if (capture.get('status') != 'observed' or capture.get('client_sha256') != CLIENT or
            capture.get('identities_and_fields_rechecked') is not True or
            capture.get('process_identity_rechecked') is not True or
            capture.get('process_memory_written') is not False or
            capture.get('native_methods_invoked') is not False):
        raise ValueError('Actual rechecked native main FSM metadata is required')
    scopes = capture['scopes']
    observed = scopes['component']['state']['exact_creation_guid_instance']
    if (observed.get('status') != 'typed_existing_reference' or
            observed.get('outer_is_current_pawn') is not True or
            observed.get('selected_class_matches_current_main_fsm') is not True or
            scopes['instance'].get('reference_origin') != 'current_connection_exact_creation_guid'):
        raise ValueError('The instance must have actually resolved under the current Pawn')
    rows = {}
    for path in (COMPONENT, INSTANCE):
        row, = [o for o in capture['objects'] if o['class_path'] == path]
        driver = row['existing_driver_class']
        if driver.get('layout_status') != 'exported_existing' or driver.get('cache_status') != 'exported_existing':
            raise ValueError('The exact ordinary class layout must exist')
        rows[path] = row
    fields = {}
    for name, path, offset, opcode, serializer in (
            ('R_Instance', COMPONENT, 424, 8, 0x10e8ed20),
            ('R_StateMachineContext', INSTANCE, 1400, 8, 0x10e8ed20),
            ('R_bHasStarted', INSTANCE, 1636, 3, 0x10e8ebe0)):
        layout = rows[path]['existing_driver_class']['layout']
        command, = [c for c in layout['commands'] if c.get('descriptor_name') == name]
        declaration, hook = command['current_property_declaration'], command['property_serializer_hook']
        parent = layout['parents'][command['parent_index']]
        if (command['data_offset'] != offset or declaration['storage_offset'] != offset or
                command['dispatch_opcode'] != opcode or parent['descriptor_name'] != name or
                int(declaration['property_flags'], 16) & 0x20 == 0 or
                hook.get('status') != 'observed_pinned_image_method' or
                hook.get('inside_pinned_image') is not True or hook.get('identity_rechecked') is not True or
                hook.get('target_module_sha256') != CLIENT or hook.get('target_rva') != serializer or
                type(command['relative_handle']) is not int or not 1 <= command['relative_handle'] <= 65535):
            raise ValueError('The actual current FSM ordinary field differs: ' + name)
        fields[name] = dict(class_path=path, ordinary_handle=command['relative_handle'],
            storage_offset=offset, command_index=command['command_index'],
            parent_index=command['parent_index'], dispatch_opcode=opcode,
            serializer_rva=hex(serializer), command_sha256=command['record_sha256'],
            property_flags=declaration['property_flags'])
    contract = sealed(BASE + 'native-current-fsm-instance-initialization-contract-v1.json')
    if (contract.get('client_sha256') != CLIENT or
            contract['initialize'].get('initialized_flag_is_not_an_input') is not True or
            contract['start'].get('start_notify_waits_for_initialized_byte') is not True):
        raise ValueError('The native Initialize/Start receiver contract changed')
    header = sealed(BASE + 'native-current-skill-dynamic-subobject-receive-header-v1.json')
    instructions = {i['rva']: i for f in header['functions'] for i in f['instructions']}
    for at, mnemonic, operands in (
            ('0x128646e7', 'cmp', 'qword ptr [rsp + 0x70], r14'),
            ('0x128646ec', 'jne', '0x128648d7')):
        if (instructions[at]['mnemonic'], instructions[at]['operands']) != (mnemonic, operands):
            raise ValueError('The actual existing dynamic UObject followup branch changed')
    return dict(kind='source_qualified_main_fsm_replica_initialization_v1', client_sha256=CLIENT,
        sources=PINS, component_class_path=COMPONENT, instance_class_path=INSTANCE,
        component_name='GPFSMStateMachine', fields=fields,
        order=['instance_context', 'component_instance', 'instance_started'],
        dynamic_instance_creation_ack_required=True, each_stage_positive_ack_required=True,
        context_origin='this_admission_current_Pawn_GUID', start_value=True,
        initialized_byte_written=False, permission_bits_written=False,
        native_gameplay_verified=False)


def schema_sha(schema):
    return sha256((json.dumps(schema, indent=2, sort_keys=True) + '\n').encode()).hexdigest()


def schema_binding():
    return derive_schema()


def source_pins():
    result = dict(PINS)
    derive_schema()
    from fsm_character_readiness_scope import source_pins as character_sources
    result.update(character_sources())
    from portable_main_fsm_startup import source_pins as startup_sources
    result.update(startup_sources())
    for relative in ('work/portable_fsm_replica_initialization.py',
            'outputs/df-local-server/dfserver/legacy_ds_dynamic_object_update.py',
            'outputs/df-local-server/dfserver/legacy_ds_rep_layout_refs.py',
            'outputs/df-local-server/dfserver/legacy_ds_scalar_serializers.py'):
        result[relative] = sha256((ROOT / relative).read_bytes()).hexdigest()
    return result


def character_ready_schema():
    from fsm_character_readiness_scope import source_record
    row = source_record()
    layout = row['existing_driver_class']['layout']
    command, = [c for c in layout['commands'] if c.get('descriptor_name') == 'bFSMIsInited']
    declaration, hook = command['current_property_declaration'], command['property_serializer_hook']
    parent = layout['parents'][command['parent_index']]
    if (command['data_offset'] != 0x728 or declaration['storage_offset'] != 0x728 or
            command['dispatch_opcode'] != 21 or command['relative_handle'] != 6 or
            parent['descriptor_name'] != 'bFSMIsInited' or
            int(declaration['property_flags'], 16) & 0x20 == 0 or
            hook.get('status') != 'observed_pinned_image_method' or
            hook.get('identity_rechecked') is not True or hook.get('inside_pinned_image') is not True or
            hook.get('target_module_sha256') != CLIENT or hook.get('target_rva') != 0x10e8ebe0):
        raise ValueError('The source-qualified ordinary character readiness field changed')
    return dict(class_path=INSTANCE, ordinary_handle=command['relative_handle'],
        storage_offset=command['data_offset'], dispatch_opcode=command['dispatch_opcode'],
        command_sha256=command['record_sha256'], serializer_rva=hook['target_rva'])


def publish_character_ready(receipt, context):
    """Publish committed local InitCharacter state in the preceding context block.

    This adds no continuation stage: the existing positive-ACK dependencies still
    deliver context/readiness before R_Instance Initialize and then Started.
    """
    from portable_character_initialization import CharacterInitializationReceipt
    if type(receipt) is not CharacterInitializationReceipt:
        raise ValueError('A committed character initialization receipt is required')
    receipt.validate_committed()
    if (receipt.fsm_ready is not True or type(context) is not DynamicObjectUpdate or
            (context.actor_guid, context.guid, context.class_guid, context.class_path) !=
            (receipt.pawn_guid, receipt.instance_guid, receipt.class_guid, INSTANCE) or
            context.source_sha256 != schema_sha(derive_schema())):
        raise ValueError('The exact initialized character context namespace is required')
    fields = read_object_reference_content(ActorContentBlock(True,
        context.payload, context.payload_bit_count))
    context_handle = derive_schema()['fields']['R_StateMachineContext']['ordinary_handle']
    if [(f.handle, f.actor_guid) for f in fields] != [(context_handle, receipt.pawn_guid)]:
        raise ValueError('Only the exact initial Pawn context can publish character readiness')
    ready = character_ready_schema()
    writer = BitWriter(maximum_bits=128)
    writer.write_bool(False)
    writer.write_packed_int(context_handle)
    writer.write_packed_int(receipt.pawn_guid)
    writer.write_packed_int(ready['ordinary_handle'])
    write_bool_value(writer, receipt.fsm_ready,
        binding=NativeScalarBinding(CLIENT, ready['serializer_rva']))
    writer.write_packed_int(0)
    return DynamicObjectUpdate(context.actor_guid, context.guid, context.class_guid,
        context.class_path, schema_sha(dict(context_schema=derive_schema(), readiness=ready)),
        writer.to_bytes(), writer.bit_count)


def initialize_admitted_character(store, ticket, manifests, plans):
    """Commit one admission's modeled initialization, then publish its result."""
    receipt = store.materialize(ticket=ticket, manifests=manifests, plans=plans)
    receipt.validate_binding(ticket=ticket, manifests=manifests, plans=plans)
    changed, starts, result = 0, 0, []
    schema = derive_schema()
    context_handle = schema['fields']['R_StateMachineContext']['ordinary_handle']
    for plan in plans:
        tails = []
        startup_tails = []
        for group in plan.get('continuations', ()):
            updates = []
            follows_start = False
            for update in group:
                if (type(update) is DynamicObjectUpdate and update.guid == receipt.instance_guid and
                        update.source_sha256 == schema_sha(schema)):
                    header = BitReader(update.payload, bit_count=update.payload_bit_count)
                    if not header.read_bool() and header.read_packed_int() == context_handle:
                        update = publish_character_ready(receipt, update)
                        changed += 1
                    else:
                        started = BitReader(update.payload, bit_count=update.payload_bit_count)
                        if (not started.read_bool() and started.read_packed_int() ==
                                schema['fields']['R_bHasStarted']['ordinary_handle']):
                            if (not started.read_bool() or started.read_packed_int() != 0 or
                                    started.remaining != 0):
                                raise ValueError('The initial FSM start publication differs')
                            starts += 1
                            follows_start = True
                updates.append(update)
            tails.append(tuple(updates))
            if follows_start:
                from portable_main_fsm_startup import (commit_startup, commit_operational_startup,
                    build_content, build_dictionary_contents)
                startup = commit_startup(receipt)
                operational = commit_operational_startup(receipt)
                for content in (*build_dictionary_contents(startup),
                                build_content(startup), build_content(operational)):
                    startup_tails.append((DynamicObjectUpdate(receipt.pawn_guid, receipt.instance_guid,
                        receipt.class_guid, INSTANCE, startup.source_sha256,
                        content.payload, content.payload_bit_count),))
        if 'continuations' in plan:
            entry = dict(plan, continuations=tuple(tails + startup_tails))
            if 'continuation_after_content_stages' in entry:
                entry['continuation_after_content_stages'] += tuple(() for _ in startup_tails)
            result.append(entry)
        else:
            result.append(dict(plan))
    if changed != 1 or starts != 1:
        raise ValueError('Exactly one initial character context and start publication is required')
    result = tuple(result)
    receipt.validate_binding(ticket=ticket, manifests=manifests, plans=result)
    return result


def project_updates(*, pawn_guid, component_guid, instance_guid, class_guid, allocated_guids):
    schema = derive_schema()
    if (type(allocated_guids) is not tuple or len(set(allocated_guids)) != len(allocated_guids) or
            not 4 <= len(allocated_guids) <= 65536 or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX for g in allocated_guids) or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX or g & 1
                for g in (pawn_guid, component_guid, instance_guid)) or
            len({pawn_guid, component_guid, instance_guid}) != 3 or
            type(class_guid) is not int or not 3 <= class_guid <= UINT32_MAX or not class_guid & 1 or
            not {pawn_guid, component_guid, instance_guid, class_guid} <= set(allocated_guids)):
        raise ValueError('The exact already allocated Pawn, component, instance and class namespace is required')
    source = schema_sha(schema)
    fields = schema['fields']
    context = build_object_reference_content((ObjectReference(
        fields['R_StateMachineContext']['ordinary_handle'], pawn_guid),))
    binding = build_object_reference_content((ObjectReference(
        fields['R_Instance']['ordinary_handle'], instance_guid),))
    started = BitWriter(maximum_bits=64)
    started.write_bool(False)
    started.write_packed_int(fields['R_bHasStarted']['ordinary_handle'])
    write_bool_value(started, True, binding=NativeScalarBinding(CLIENT,
        int(fields['R_bHasStarted']['serializer_rva'], 16)))
    started.write_packed_int(0)
    return (
        DynamicObjectUpdate(pawn_guid, instance_guid, class_guid, INSTANCE, source,
            context.payload, context.payload_bit_count),
        DefaultSubobjectUpdate(pawn_guid, component_guid, schema['component_name'], source,
            binding.payload, binding.payload_bit_count),
        DynamicObjectUpdate(pawn_guid, instance_guid, class_guid, INSTANCE, source,
            started.to_bytes(), started.bit_count),
    )
