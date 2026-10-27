"""Qualified GS template/index value encoding; no lifecycle flags or transport.

The observed index descriptors are FInt64Property, not FUInt64Property. Both
transfer eight raw bytes through the same leaf, but have different value ranges.
Template records use the installed class's normal local-collect branch only.
Encoding data does not establish an authoritative materialization or client ready.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX
from dfserver.legacy_ds_skill_template import SkillTemplateUpdate
from portable_source_guard import cached_qualification

ROOT = Path(__file__).resolve().parent.parent
CLIENT = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
COMPONENT = '/Script/DFMAbility.DFMAbilityGameStateComponent'
CAPTURE = 'work/native-client-tests/1792460999986794500/owned-skill-entity-metadata.json'
CAPTURE_SHA256 = '4f8becd08f296f36a219cdb31f9498d4e9b301fca74495f2f43def17a7ac2e29'
BASE = 'work/evidence/skill-template-replication-20261020-v1/'
COVERAGE_CATALOG = 'work/evidence/skill-template-coverage-20261020-v2/configured-program-catalog-v3.json'
PINS = {
    COVERAGE_CATALOG: '304a6ab4e30c80ebec4bbc61f7a0b8c9ee4d489fd046b433b12671069cee7dcd',
    CAPTURE: CAPTURE_SHA256,
    BASE + 'configured-template-defaults-v3.json': 'd7bdd6fe831b81be50a11f3afcf649e4055f079a0bfc6f267c841aa275be1de5',
    BASE + 'template-native-constructor.json': '604d7f390f9a9260367cdedb99297db304f34bdb7a333abac02bc2164d9303c9',
    BASE + 'template-native-class-registration.json': 'c16fd6ac974b50d4871f571c9e6cc2f60bc6d14b7be46b0c3290e087aac46c69',
    BASE + 'template-native-ctor-thunk.json': '83e3bb6310cd44e27c128acadbf4eb34773375138d78ccea4ffe6cbfa6dcf7a2',
    BASE + 'template-repdata-native-constructor.json': '97581b71e936e6741305a6b79fd72ba624761e075e0840a98334a40edea5d94b',
    BASE + 'index-int64-scalar-source-v2.json': '9a67aa61b2344288729cc33b56ada1fa3732979b369b8e65c35cf518d41972ab',
    'work/evidence/model-init-chain-20261018/native-current-skill-dynamic-subobject-receive-header-v1.json':
        '027ef34cb7fce8aa76a8e663b0e4e8ffe7486bae51fee5934d72742ee286770c',
    'work/evidence/skill-flow-research-20261020-v1/native-template-ds-initialization-ready-and-index.json':
        '317bf437d1cc849ac1ce94f9f1ece293e5997375ce575f986c4bc090a8d49adb',
    'work/evidence/model-init-chain-20261018/native-skill-initial-state-wire-contract-v3.json':
        '1ba99f60b484de242df4ea4954a2b0e2065b5589e549ff385597aa974a6b53e3',
}


def _sealed(relative, expected):
    path = (ROOT / relative).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError('A repository source is required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('The pinned skill template source changed: ' + relative)
    return json.loads(raw)


def load_observed_capture():
    return _sealed(CAPTURE, CAPTURE_SHA256)


def qualify_capture(capture):
    if type(capture) is not dict or schema_sha(capture) != schema_sha(load_observed_capture()):
        raise ValueError('The exact pinned GS template capture is required')
    if (capture.get('status') != 'observed' or capture.get('client_sha256') != CLIENT or
            capture.get('identities_and_fields_rechecked') is not True or
            capture.get('native_methods_invoked') is not False or
            capture.get('process_memory_written') is not False):
        raise ValueError('The rechecked non-mutating GS template capture is required')
    obj, = [o for o in capture['objects'] if o.get('class_path') == COMPONENT]
    driver = obj['existing_driver_class']
    if driver['layout_status'] != 'exported_existing' or driver['cache_status'] != 'exported_existing':
        raise ValueError('The actual GS template layout must already exist')
    return driver['layout']


def _field(command):
    hook, leaf = command['property_serializer_hook'], command['property_scalar_leaf_hook']
    for row in (hook, leaf):
        if (row.get('status') != 'observed_pinned_image_method' or
                row.get('target_module_sha256') != CLIENT or
                row.get('inside_pinned_image') is not True or row.get('identity_rechecked') is not True):
            raise ValueError('The observed GS property serializer identity changed')
    return dict(name=command['descriptor_name'], ordinary_handle=command['relative_handle'],
                command_index=command['command_index'], parent_index=command['parent_index'],
                storage_offset=command['data_offset'], dispatch_opcode=command['dispatch_opcode'],
                serializer_rva=hook['target_rva'], scalar_leaf_rva=leaf['target_rva'],
                property_vtable_rva=hook['vtable_rva'], command_sha256=command['record_sha256'])


def source_schema():
    """Return the actual frozen GS layout, preserving every nested command."""
    layout = qualify_capture(load_observed_capture())
    grammar = _sealed('work/evidence/model-init-chain-20261018/native-skill-initial-state-wire-contract-v3.json',
                      PINS['work/evidence/model-init-chain-20261018/native-skill-initial-state-wire-contract-v3.json'])
    if grammar['stream'] != dict(alignment=False, array_count='raw uint16 LE', checksums=False,
                                  child_counter_reset_per_element=False,
                                  child_handle_formula='element_index*child_handle_count+child_relative_handle',
                                  option_bit=False, whole_array_terminal_handle=0):
        raise ValueError('The source qualified ordinary dynamic-array grammar changed')
    scalar = _instructions(BASE + 'index-int64-scalar-source-v2.json')
    if (scalar['0x286c03d']['operands'] != 'r8d, 8' or
            scalar['0x286c043']['operands'] != 'qword ptr [rax + 0x60]' or
            scalar['0x10e5ce75']['operands'] != 'qword ptr [rax + 0x88]'):
        raise ValueError('The observed raw eight-byte numeric serializer changed')
    if (layout['parent_count'], layout['command_count']) != (8, 48):
        raise ValueError('The actual GS template layout changed')
    commands = layout['commands']
    top = _field(commands[16])
    if (top['name'], top['ordinary_handle'], top['storage_offset'], top['dispatch_opcode']) != (
            'AbilityTemplateRepData', 6, 0x418, 0):
        raise ValueError('The actual GS template array changed')
    children = [_field(c) for c in commands[17:44] if c['dispatch_opcode'] != 1]
    outer = {c['ordinary_handle']: c for c in children
             if c['command_index'] in (17, 18, 28, 29, 30, 33, 34, 37, 38, 39, 40, 41, 42, 43)}
    if sorted(outer) != list(range(1, 15)):
        raise ValueError('The actual template element handle scope changed')
    index = {}
    for ci, name, handle, offset in ((45, 'AbilityIndexRam', 7, 0x428),
                                    (46, 'AbilityIndexRam2', 8, 0x430)):
        field = _field(commands[ci])
        if (field['name'], field['ordinary_handle'], field['storage_offset'], field['dispatch_opcode'],
                field['serializer_rva'], field['scalar_leaf_rva'], field['property_vtable_rva']) != (
                name, handle, offset, 2, 0x10e5ce20, 0x286c000, 0x15a86560):
            raise ValueError('The observed signed-int64 index binding changed')
        index[name] = dict(field, native_type='FInt64Property', wire_bits=64)
    return dict(kind='observed_gs_skill_template_replication_schema_v1', client_sha256=CLIENT,
                capture_sha256=CAPTURE_SHA256, layout_commands_sha256=layout['commands_sha256'],
                template_array=dict(top, child_handle_count=14, native_element_bytes=704,
                                    commands=children, element_fields=outer),
                index_fields=index, option_bit=False, array_count_bits=16,
                array_handle_formula='element_index*14+child_relative_handle',
                archive_profile=dict(internal_ack=False, checksums=False, byte_swapping=False),
                initial_snapshot_only=True, native_gameplay_verified=False)


def _qualify_schema(schema):
    if type(schema) is not dict or schema_sha(schema) != schema_sha(source_schema()):
        raise ValueError('The exact source-qualified GS template layout is required')


def build_index_content(schema, *, ability_index_ram, ability_index_ram2):
    """Encode caller-owned authority index state; allocate or choose no IDs."""
    _qualify_schema(schema)
    values = (ability_index_ram, ability_index_ram2)
    if any(type(v) is not int or not -(1 << 63) <= v < (1 << 63) for v in values):
        raise ValueError('Explicit signed-int64 authority index values are required')
    writer = BitWriter(maximum_bits=153)
    writer.write_bool(False)
    for name, value in zip(('AbilityIndexRam', 'AbilityIndexRam2'), values):
        writer.write_packed_int(schema['index_fields'][name]['ordinary_handle'])
        # The observed FInt64Property table uses the qualified raw eight-byte leaf.
        writer.write_bytes(value.to_bytes(8, 'little', signed=True))
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)


@dataclass(frozen=True)
class SourceTemplateRecord:
    skill_id: int
    template_class: str
    source_table: str
    source_row_uexp: int
    use_ds_rep_data: bool
    client_predict: bool
    source_binding_sha256: str


def _instructions(relative):
    data = _sealed(relative, PINS[relative])
    return {i['rva']: i for f in data['functions'] for i in f['instructions']}


def source_template_profiles():
    """Qualify installed defaults, actual native constructor and producer mode.

    The false branch does not serialize task nodes on the normal server. It
    notifies an already configured client template to collect its authored graph.
    The true branch requires a different actual node-data projection and is not
    silently converted to this branch.
    """
    native = _instructions(BASE + 'template-native-constructor.json')
    registration = _instructions(BASE + 'template-native-class-registration.json')
    thunk = _instructions(BASE + 'template-native-ctor-thunk.json')
    record = _instructions(BASE + 'template-repdata-native-constructor.json')
    producer = _instructions('work/evidence/skill-flow-research-20261020-v1/native-template-ds-initialization-ready-and-index.json')
    for table, rva, mnemonic, operands in (
        (native, '0x808f510', 'mov', 'word ptr [rbx + 0x510], 0x100'),
        (thunk, '0x808f1ce', 'jmp', '0x808f380'),
        (record, '0x7eb4300', 'xor', 'eax, eax'),
        (record, '0x7eb430a', 'mov', 'word ptr [rcx + 0x18], ax'),
        (producer, '0x7ec8d09', 'je', '0x7ec8dbe'),
        (producer, '0x7ec8dc5', 'je', '0x7ec915e'),
    ):
        if (table[rva]['mnemonic'], table[rva]['operands']) != (mnemonic, operands):
            raise ValueError('The normal template producer mode changed')
    if registration['0x808e4f5']['rip_references'][0]['rva'] != '0x808f1c0':
        raise ValueError('The actual native template class constructor changed')
    defaults = _sealed(COVERAGE_CATALOG, PINS[COVERAGE_CATALOG])
    profiles, common_base = {}, None
    for package in defaults['packages']:
        for source in package['source_files']:
            path = (ROOT / source['relative_path']).resolve()
            if (not path.is_relative_to(ROOT) or
                    hashlib.sha256(path.read_bytes()).hexdigest() != source['sha256']):
                raise ValueError('The configured template cooked source changed')
        metadata = _sealed(package['metadata_path'], package['metadata_sha256'])
        cdo, = [r for r in metadata['selected_defaults'] if r['export']['name'].startswith('Default__')]
        if cdo['tags_decoded'] is not True:
            raise ValueError('Complete template CDO tagged properties are required')
        if any(p['name'] == 'bUseDsRepData' for p in cdo['properties']):
            raise ValueError('A template overrides the qualified native collect mode')
        cls, = [e for e in metadata['exports'] if e['index'] == cdo['export']['class_index']]
        relative = package['source_files'][0]['relative_path']
        game_path = '/Game/' + relative.split('/DeltaForce/Content/', 1)[1].rsplit('.', 1)[0]
        class_path = game_path + '.' + cls['name']
        if class_path != package['class_path'] or cls['super_path'] != package['parent_class']:
            raise ValueError('The configured package/class identity changed')
        if cls['super_path'] == '/Script/DFMAbility.DFMAbilityLogicTemplate':
            if cls['super_path'] != '/Script/DFMAbility.DFMAbilityLogicTemplate':
                raise ValueError('The configured template native inheritance changed')
            common_base = class_path
        else:
            profiles[class_path] = dict(parent_class=cls['super_path'], use_ds_rep_data=False,
                                       client_predict=False, node_data=(),
                                       cdo_uexp=cdo['export']['offset'],
                                       package_sources=package['source_files'])
    if not common_base or not profiles or any(p['parent_class'] != common_base for p in profiles.values()):
        raise ValueError('The qualified configured template inheritance chains are required')
    return profiles


@cached_qualification(ROOT)
def _qualified_record_catalog():
    from skill_initial_state_values import schema_binding
    state = schema_binding()
    profiles = source_template_profiles()
    binding = hashlib.sha256((json.dumps(dict(sources=PINS, profiles=profiles),
                                         sort_keys=True) + '\n').encode()).hexdigest()
    catalog = {}
    for plan in state['hero_plans'].values():
        for row in plan['source_row_plan']:
            path = row['configured_template_class']
            if path not in profiles:
                continue
            profile = profiles[path]
            record = SourceTemplateRecord(row['skill_id'], path, row['source_table'],
                                          row['serialized_uexp_offset'], profile['use_ds_rep_data'],
                                          profile['client_predict'], binding)
            if record.skill_id in catalog and catalog[record.skill_id] != record:
                raise ValueError('Conflicting configured template source rows')
            catalog[record.skill_id] = record
    return dict(records=catalog,
                sources={path.replace('\\', '/'): digest
                         for path, digest in source_pins().items()})


def _record_catalog():
    return _qualified_record_catalog()['records']


def template_records_for_grant(grant, *, materialized_skill_ids):
    """Project source records for the authority's explicit materialized subset.

    This validates membership and source values. It does not itself establish
    that authority graph materialization has occurred; the owning service must
    commit its normal template initialization before publishing this projection.
    """
    from skill_initial_state_values import _validate_grant, schema_binding, select_source_plan
    state = schema_binding()
    _validate_grant(state, grant)
    if (type(materialized_skill_ids) is not tuple or not 1 <= len(materialized_skill_ids) <= 256 or
            any(type(value) is not int for value in materialized_skill_ids) or
            len(set(materialized_skill_ids)) != len(materialized_skill_ids)):
        raise ValueError('The explicit bounded materialized skill identity subset is required')
    catalog, records = _record_catalog(), []
    rows = {r['skill_id']: r for r in select_source_plan(state, grant.hero_id)['source_row_plan']}
    for skill_id in materialized_skill_ids:
        row, record = rows.get(skill_id), catalog.get(skill_id)
        if row is None or record is None or record.template_class != row['configured_template_class']:
            raise ValueError('A configured template requires additional installed class qualification')
        records.append(record)
    return tuple(records)


def _records(records):
    if type(records) is not tuple or not 1 <= len(records) <= 256:
        raise ValueError('A bounded nonempty source template record tuple is required')
    catalog, seen = _record_catalog(), set()
    for record in records:
        if (type(record) is not SourceTemplateRecord or type(record.skill_id) is not int or
                record.skill_id in seen or catalog.get(record.skill_id) != record or
                record.use_ds_rep_data is not False or record.client_predict is not False):
            raise ValueError('The exact source template record and collect mode are required')
        seen.add(record.skill_id)
    return records


def _write_template_array(writer, schema, records):
    writer.write_packed_int(schema['template_array']['ordinary_handle'])
    writer.write_bytes(len(records).to_bytes(2, 'little'))
    stride = schema['template_array']['child_handle_count']
    for index, record in enumerate(records):
        writer.write_packed_int(index*stride + 1)
        writer.write_bytes(record.skill_id.to_bytes(4, 'little', signed=True))
        writer.write_packed_int(index*stride + 3)
        writer.write_bool(record.use_ds_rep_data)
        writer.write_packed_int(index*stride + 4)
        writer.write_bool(record.client_predict)
    writer.write_packed_int(0)


def build_template_content(schema, *, records):
    """Encode an initial template-array snapshot through its real local branch.

    Existing template records must not be overwritten with this initial-only
    producer. The omitted node/maps retain their normal constructor defaults;
    the configured template performs actual authored collection after RepNotify.
    """
    _qualify_schema(schema)
    records = _records(records)
    writer = BitWriter(maximum_bits=32768)
    writer.write_bool(False)
    _write_template_array(writer, schema, records)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)


@dataclass(frozen=True)
class InitialTemplatePlan:
    grant: object
    records: tuple
    ability_index_ram: int
    ability_index_ram2: int
    source_schema_sha256: str


def schema_sha(schema):
    return hashlib.sha256((json.dumps(schema, sort_keys=True) + '\n').encode()).hexdigest()


def project_initial_plan(schema, *, grant, materialized_skill_ids, ability_index_ram,
                         ability_index_ram2, existing_template_skill_ids):
    """Prepare a source projection; the caller owns actual authority commit.

    The service must pass its complete materialized template identity set and
    actual index state, retain the plan for this grant, commit normal authority
    initialization, and publish once after GS component creation is acknowledged.
    This function neither materializes a graph nor asserts that it is ready.
    """
    _qualify_schema(schema)
    if type(existing_template_skill_ids) is not tuple or existing_template_skill_ids:
        raise ValueError('This producer requires an initial empty template replication array')
    records = template_records_for_grant(grant, materialized_skill_ids=materialized_skill_ids)
    if any(type(v) is not int or not 0 <= v < 1 << 63 for v in (ability_index_ram, ability_index_ram2)):
        raise ValueError('Actual nonnegative signed-int64 authority index state is required')
    return InitialTemplatePlan(grant, records, ability_index_ram, ability_index_ram2, schema_sha(schema))


def _plan(schema, plan):
    _qualify_schema(schema)
    if type(plan) is not InitialTemplatePlan or plan.source_schema_sha256 != schema_sha(schema):
        raise ValueError('An exact admission-bound template plan is required')
    expected = project_initial_plan(schema, grant=plan.grant,
                                    materialized_skill_ids=tuple(r.skill_id for r in plan.records),
                                    ability_index_ram=plan.ability_index_ram,
                                    ability_index_ram2=plan.ability_index_ram2,
                                    existing_template_skill_ids=())
    if plan != expected:
        raise ValueError('The frozen source template projection changed')
    return plan


def build_initial_content(schema, *, plan):
    """One ordinary GS body: template array, signed indices, outer terminator."""
    plan = _plan(schema, plan)
    writer = BitWriter(maximum_bits=32768)
    writer.write_bool(False)
    _write_template_array(writer, schema, plan.records)
    for name, value in (('AbilityIndexRam', plan.ability_index_ram),
                        ('AbilityIndexRam2', plan.ability_index_ram2)):
        writer.write_packed_int(schema['index_fields'][name]['ordinary_handle'])
        writer.write_bytes(value.to_bytes(8, 'little', signed=True))
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)


def project_update(schema, *, plan, actor_guid, component_guid, class_guid, allocated_guids):
    """Bind the initial business state to an already allocated GS component."""
    block = build_initial_content(schema, plan=plan)
    if (type(allocated_guids) is not tuple or not 3 <= len(allocated_guids) <= 65536 or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX for g in allocated_guids) or
            len(set(allocated_guids)) != len(allocated_guids) or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX or g & 1
                for g in (actor_guid, component_guid)) or actor_guid == component_guid or
            type(class_guid) is not int or not 3 <= class_guid <= UINT32_MAX or not class_guid & 1 or
            not {actor_guid, component_guid, class_guid} <= set(allocated_guids)):
        raise ValueError('The current allocated GS Actor/component/class namespace is required')
    return SkillTemplateUpdate(actor_guid, component_guid, class_guid, COMPONENT, schema_sha(schema),
                               block.payload, block.payload_bit_count, plan, allocated_guids)


def write_followup(writer, update, *, actor_guids, object_bindings, creation_acknowledged):
    """Write the existing dynamic GS subobject header and exact business body.

    Ordinary non-internal-ACK, checksum/debug disabled, no byte swapping. Real
    class/creation ACKs and the normal authority materialization commit belong
    to the connection/service stage manager; transport ACK is not gameplay ready.
    """
    if creation_acknowledged is not True:
        raise ValueError('The exact GS ability component creation must be acknowledged by a real ACK')
    if type(writer) is not BitWriter or type(update) is not SkillTemplateUpdate:
        raise ValueError('A native bit writer and qualified template update are required')
    schema = source_schema()
    header = _instructions('work/evidence/model-init-chain-20261018/native-current-skill-dynamic-subobject-receive-header-v1.json')
    if (header['0x128646e7']['operands'] != 'qword ptr [rsp + 0x70], r14' or
            header['0x128646ec']['operands'] != '0x128648d7'):
        raise ValueError('The native existing-component followup branch changed')
    expected = project_update(schema, plan=update.plan, actor_guid=update.actor_guid,
                              component_guid=update.guid, class_guid=update.class_guid,
                              allocated_guids=update.allocated_guids)
    if update != expected:
        raise ValueError('The source-qualified GS template payload or binding changed')
    if (type(actor_guids) is not tuple or not 1 <= len(actor_guids) <= 128 or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX or g & 1 for g in actor_guids) or
            len(set(actor_guids)) != len(actor_guids) or update.actor_guid not in actor_guids or
            type(object_bindings) is not tuple or not 1 <= len(object_bindings) <= 128 or
            any(type(b) is not tuple or len(b) != 4 for b in object_bindings) or
            (update.guid, update.actor_guid, update.class_guid, COMPONENT) not in object_bindings or
            len({b[0] for b in object_bindings}) != len(object_bindings)):
        raise ValueError('The actual current GS Actor and exact component creation binding are required')
    BitReader(update.payload, bit_count=update.payload_bit_count)
    staged = BitWriter(maximum_bits=writer.maximum_bits)
    staged.write_bool(True)
    staged.write_bool(False)
    staged.write_packed_int(update.guid)
    staged.write_bool(False)
    staged.write_packed_int(update.class_guid)
    staged.write_packed_int(update.payload_bit_count)
    staged.write_payload(update.payload, update.payload_bit_count)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count


def source_pins():
    """Full transitive baseline sources required by a frozen executable trial."""
    source_schema()
    profiles = source_template_profiles()
    result = dict(PINS)
    catalog = _sealed(COVERAGE_CATALOG, PINS[COVERAGE_CATALOG])
    for package in catalog['packages']:
        result[package['metadata_path']] = package['metadata_sha256']
        result[package['bytecode_path']] = package['bytecode_sha256']
    for profile in profiles.values():
        for source in profile['package_sources']:
            result[source['relative_path']] = source['sha256']
    defaults = _sealed(BASE + 'configured-template-defaults-v3.json',
                       PINS[BASE + 'configured-template-defaults-v3.json'])
    for package in defaults['packages']:
        result.update({s['relative_path']: s['sha256'] for s in package['source_files']})
    from skill_initial_state_values import schema_binding
    result.update(schema_binding()['sources'])
    for relative in ('work/skill_template_replication.py',
                     'outputs/df-local-server/dfserver/legacy_ds_bit_archive.py',
                     'outputs/df-local-server/dfserver/legacy_ds_skill_template.py',
                     'outputs/df-local-server/dfserver/legacy_ds_actor_content.py'):
        result[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    return result
