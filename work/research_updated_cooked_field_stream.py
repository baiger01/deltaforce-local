"""Current cooked field streams and immutable ENetRole registration evidence.

Research only: no process access, native execution, profile activation or old
property handles. Serialized flags/types are not runtime offsets or handles.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from research_updated_metadata_roots import ROOT, NewImage, ForensicObservation, disasm, sha

PACKAGE_REPORT = 'work/research_updated_cooked_declarations_79fb7b10_v5.json'
PACKAGE_SHA = 'b29f6cda96c690351596f5e96879d96267610adbfd86b36cd253661af7ec3037'
CAPTURE = 'work/native-client-tests/1792803423602487700/updated-class-metadata.json'
CAPTURE_SHA = 'ae58fa8354c4a777e32ae4dac05481dfe0bd1662f263269f6a77b2c3e93fc64f'
CLIENT_SHA = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
LOAD_MASK = 0xfff7ffefbffffdff
PRESERVE_MASK = 0x8001040000200
RELEASE_GUID = '3f74fccf8044b043df14919373201d17'
FIELD_GUID = '3cc15e37fb48e406f08400b57e712a26'


class Cursor:
    def __init__(self, raw, names, imports, exports):
        if type(raw) is not bytes or len(raw) > 4096 or not 1 <= len(names) <= 10000:
            raise ValueError('Bounded class suffix and name table required')
        self.raw, self.names, self.imports, self.exports, self.at = raw, names, imports, exports, 0

    def number(self, fmt):
        size = struct.calcsize('<'+fmt)
        if self.at+size > len(self.raw):
            raise ValueError('Truncated native class suffix')
        value, = struct.unpack_from('<'+fmt, self.raw, self.at)
        self.at += size
        return value

    def name(self):
        index, number = self.number('i'), self.number('i')
        if not 0 <= index < len(self.names) or not 0 <= number < 1000000:
            raise ValueError('Invalid serialized field FName')
        return self.names[index] if not number else self.names[index]+'_'+str(number-1)

    def reference(self):
        index = self.number('i')
        if not -len(self.imports) <= index <= len(self.exports):
            raise ValueError('Field suffix object reference outside package')
        return index

    def count(self, bound):
        count = self.number('i')
        if not 0 <= count <= bound:
            raise ValueError('Serialized class count exceeds local bound')
        return count


def parse_class_stream(pkg):
    versions = {r['guid_bytes_hex']:r['value'] for r in pkg['custom_versions']}
    if len(versions) != len(pkg['custom_versions']):
        raise ValueError('Duplicate serialized custom-version GUID')
    if versions.get(RELEASE_GUID) != 36 or versions.get(FIELD_GUID) != 4:
        raise ValueError('Only the observed release36 / FField4 serialized branch is qualified')
    klass = pkg['class_export']
    raw = bytes.fromhex(klass['remaining_export_bytes_hex'])
    c = Cursor(raw, pkg['serialized_names'], pkg['imports'], pkg['exports'])
    if c.number('i') != 0:
        raise ValueError('Only the observed absent UObject serialized GUID is qualified')
    parent = c.reference()
    if parent != klass['super_index']:
        raise ValueError('Serialized SuperStruct differs from package SuperIndex')
    children = [c.reference() for _ in range(c.count(256))]
    if len(set(children)) != len(children) or any(i <= 0 for i in children):
        raise ValueError('Exact distinct exported child Functions required')
    function_indices = {r['index'] for r in pkg['function_exports']}
    if set(children) != function_indices:
        raise ValueError('Child Function array differs from complete Function export table')
    count, fields = c.count(256), []
    for _ in range(count):
        start, kind, name = c.at, c.name(), c.name()
        object_flags = c.number('I')
        array_dim, element_size, flags = c.number('i'), c.number('i'), c.number('Q')
        rep_index, notify, condition = c.number('H'), c.name(), c.number('B')
        if not 1 <= array_dim <= 1024 or not 1 <= element_size <= 1048576:
            raise ValueError('Unbounded serialized property dimensions')
        row = dict(name=name, serialized_kind=kind, serialized_object_flags=hex(object_flags),
            array_dim=array_dim, serialized_element_size=element_size,
            serialized_property_flags64=hex(flags), serialized_rep_index=rep_index,
            rep_notify_name=notify, serialized_blueprint_replication_condition=condition,
            source_uexp_offset=klass['property_terminator_end']+start,
            property_net_flag=bool(flags&0x20), runtime_storage_offset_recovered=False,
            serialized_rep_index_is_current_wire_handle=False)
        if kind in ('ObjectProperty', 'StructProperty'):
            row['type_object_package_index'] = c.reference()
        elif kind == 'BoolProperty':
            row['serialized_bool_bytes'] = [c.number('B') for _ in range(6)]
        elif kind != 'IntProperty':
            return dict(complete=False, unsupported_kind=kind, unsupported_property=name,
                unsupported_uexp_offset=row['source_uexp_offset'], declared_field_count=count,
                decoded_prefix_fields=fields, runtime_fields_exported=False)
        row['serialized_record_bytes'] = c.at-start
        fields.append(row)
    if len({r['name'] for r in fields}) != len(fields):
        raise ValueError('Duplicate own serialized property name')
    bytecode_size, stored_bytecode_size = c.number('i'), c.number('i')
    if bytecode_size or stored_bytecode_size:
        raise ValueError('Only the observed empty generated-class bytecode branch is qualified')
    functions = [dict(name=c.name(), package_index=c.reference()) for _ in range(c.count(256))]
    if ({r['package_index'] for r in functions} != function_indices or
            len(functions) != len(function_indices)):
        raise ValueError('Class Function map does not cover its exact Function exports')
    for row in functions:
        if row['package_index'] <= 0 or pkg['exports'][row['package_index']-1]['name'] != row['name']:
            raise ValueError('Function map name/index identity mismatch')
    class_flags, within, config_name = c.number('I'), c.reference(), c.name()
    branch_start, branches = c.at, []
    # ClassGeneratedBy is conditional on archive FilterEditorOnly. Accept only
    # one complete structural branch, including the exact named CDO reference.
    for generated_by_present in (False, True):
        c.at = branch_start
        try:
            generated_by = c.reference() if generated_by_present else None
            if c.count(128) != 0:
                raise ValueError('Only the observed empty own-interface branch is qualified')
            ignored_integer, ignored_name, cooked, cdo_index = c.number('i'), c.name(), c.number('i'), c.reference()
            if (c.at != len(raw) or cooked != 1 or cdo_index != pkg['cdo_export']['index']):
                raise ValueError('Native class tail extent/cooked/CDO identity mismatch')
            branches.append(dict(class_generated_by_present=generated_by_present,
                class_generated_by_package_index=generated_by, own_interfaces=[],
                deprecated_integer=ignored_integer, deprecated_name=ignored_name,
                serialized_cooked=True, serialized_cdo_index=cdo_index))
        except (ValueError, struct.error):
            pass
    if len(branches) != 1:
        raise ValueError('Class native tail is ambiguous or incomplete')
    return dict(complete=True, declared_field_count=count, fields=fields, child_function_indices=children,
        class_function_map=functions, serialized_class_flags=hex(class_flags),
        within_package_index=within, config_name=config_name, **branches[0],
        own_net_property_count=sum(r['property_net_flag'] for r in fields),
        native_parent_declarations_in_this_package=False,
        runtime_fields_exported=False, class_net_cache_indices_recovered=False,
        note='ElementSize is serialized input; native linking can recompute it. OffsetInternal is explicitly reset by the current loader.')


def native_proof(image, observation):
    functions = []
    entries = [('class_serialize', 0x10dff770), ('struct_serialize', 0x10e004a0),
        ('serialized_field_list', 0x10e031e0), ('field_serialize_base', 0x10e363d0),
        ('property_serialize_base', 0x10e61980), ('object_property_serialize', 0x10e92ca0),
        ('struct_property_serialize', 0x10e92e50), ('bool_property_serialize', 0x10e924f0),
        ('uobject_serialize_wrapper', 0x10e62c30), ('uobject_serialize', 0x10e62ca0),
        ('uobject_serialized_guid', 0x10e2b340), ('class_function_map', 0x10cf66b0),
        ('class_implemented_interface_array', 0x10cf6470),
        ('function_serialize', 0x10e00050), ('function_class_getter', 0x10cff0b0),
        ('function_instance_constructor', 0x10cf3a70),
        ('net_role_enum_factory', 0x132e97e0), ('enum_registration_consumer', 0x10ea59b0),
        ('engine_package_factory', 0x132e2700)]
    instructions = {}
    for name, rva in entries:
        ranges = image.fragments(rva)
        if not ranges or sum(b-a for a,b,_ in ranges) > 16384:
            raise ValueError('Bounded complete native function range required')
        fragments = []
        for first, end, unwind in ranges:
            raw = observation.read(first, end-first)
            decoded = list(disasm(observation, first, end-first))
            if sum(i.size for i in decoded) != len(raw):
                raise ValueError('Current native serializer decoder coverage incomplete')
            rows = [dict(rva=hex(i.address), bytes_hex=i.bytes.hex(), instruction=i.mnemonic+' '+i.op_str)
                    for i in decoded]
            instructions.update({i.address:i.mnemonic+' '+i.op_str for i in decoded})
            fragments.append(dict(first_rva=hex(first), end_rva=hex(end),
                unwind_rva=hex(unwind), bytes=len(raw), sha256=sha(raw), instructions=rows))
        functions.append(dict(name=name, entry_rva=hex(rva), fragments=fragments,
            complete_unwind_coverage=True, function_called=False))
    witnesses = {
        0x10e032ae:'call qword ptr [rax + 0x50]',
        0x10e032dd:'call qword ptr [r8 + 8]',
        0x10e6199a:'call 0x10e363d0', 0x10e61a2d:'movabs rbp, 0xfff7ffefbffffdff',
        0x10e61a84:'movabs rax, 0x8001040000200',
        0x10e61af4:'mov dword ptr [rdi + 0x54], eax',
        0x10e92cb5:'call 0x10e61980', 0x10e92cc7:'call qword ptr [rax + 0x40]',
        0x10e92e65:'call 0x10e61980', 0x10e92ed0:'call qword ptr [rax + 0x40]',
        0x10dff7cb:'call 0x10e004a0', 0x10dffa5d:'call 0x10cf6470',
        0x10dffc1f:'call qword ptr [rax + 0x40]',
        0x132e97f0:'lea rdx, [rip + 0xa4ee441]',
        0x132e97fe:'call 0x10ea59b0', 0x10ea5aec:'mov rdi, qword ptr [r14 + 0x20]',
        0x10ea5af0:'movsxd rsi, dword ptr [r14 + 0x28]',
        0x10ea5af4:'shl rsi, 4', 0x10ea5b10:'mov rdx, qword ptr [rdi]',
        0x10ea5b65:'mov rax, qword ptr [rdi + 8]', 0x10ea5b96:'add rdi, 0x10',
    }
    for at, expected in witnesses.items():
        if instructions.get(at) != expected:
            raise ValueError('Current native stream witness changed: '+hex(at))
    data = []

    def datum(name, rva, size):
        raw = image.read(rva, size)
        data.append(dict(name=name, rva=hex(rva), bytes=size, sha256=sha(raw), bytes_hex=raw.hex()))
        return raw

    if (datum('Release custom-version GUID', 0x1d5a75e0, 16).hex() != RELEASE_GUID or
            datum('FField custom-version GUID', 0x1d5a75a0, 16).hex() != FIELD_GUID):
        raise ValueError('Current custom-version GUID binding changed')
    for name, vtable, slot, target in (('UClass Serialize', 0x1ab3a1d8, 0xa8, 0x10dff770),
            ('UFunction Serialize', 0x15aba770, 0xa8, 0x10e00050),
            ('ObjectProperty Serialize', 0x15a86a90, 8, 0x10e92ca0),
            ('StructProperty Serialize', 0x15a86e50, 8, 0x10e92e50),
            ('BoolProperty Serialize', 0x15a867b0, 8, 0x10e924f0)):
        if struct.unpack('<Q', datum(name, vtable+slot, 8))[0] != image.image_base+target:
            raise ValueError('Current immutable serializer vtable binding changed')
    descriptor = datum('ENetRole registration parameters', 0x1d7d7c38, 56)
    outer, _, name, cpp, array, count = struct.unpack_from('<5Qi', descriptor)
    if (outer != image.image_base+0x132e2700 or name != cpp or
            name != image.image_base+0x15925860 or array != image.image_base+0x1b4f7e60 or count != 5):
        raise ValueError('Current named enum descriptor changed')
    if datum('ENetRole UTF8 identity', 0x15925860, 9) != b'ENetRole\0':
        raise ValueError('Current role enum name changed')
    package_parameters = datum('Engine package construction parameters', 0x1b4f4c58, 32)
    if struct.unpack_from('<Q', package_parameters)[0] != image.image_base+0x1b4f4c78:
        raise ValueError('Current enum outer package construction record changed')
    if datum('Engine package UTF8 identity', 0x1b4f4c78, 15) != b'/Script/Engine\0':
        raise ValueError('Current enum outer package identity changed')
    table = datum('ENetRole enumerator parameters', 0x1b4f7e60, count*16)
    enumerators = []
    for i in range(count):
        pointer, value = struct.unpack_from('<Qq', table, i*16)
        rva = pointer-image.image_base
        raw = image.read(rva, 64).split(b'\0', 1)[0]
        text = raw.decode('ascii')
        datum('ENetRole enumerator '+str(i), rva, len(raw)+1)
        enumerators.append(dict(name=text, value=value, name_rva=hex(rva), entry_rva=hex(0x1b4f7e60+i*16)))
    if len({r['name'] for r in enumerators}) != count or len({r['value'] for r in enumerators}) != count:
        raise ValueError('Ambiguous role enum entries')
    return dict(functions=functions, immutable_data=data,
        exact_instruction_witnesses=[dict(rva=hex(at), instruction=expected) for at,expected in witnesses.items()],
        property_net_bit_preserved_by_loading=bool(LOAD_MASK&0x20) and not bool(PRESERVE_MASK&0x20),
        enum=dict(name='ENetRole', package='/Script/Engine', descriptor_rva='0x1d7d7c38',
            factory_rva='0x132e97e0', enumerators=enumerators,
            runtime_enum_object_pointer_observed=False, actor_role_enum_pointer_observed=False))


def derive():
    raw = (ROOT/PACKAGE_REPORT).read_bytes()
    capture_raw = (ROOT/CAPTURE).read_bytes()
    if sha(raw) != PACKAGE_SHA or sha(capture_raw) != CAPTURE_SHA:
        raise ValueError('Pinned current package/current metadata evidence changed')
    packages, capture = json.loads(raw), json.loads(capture_raw)
    if packages['client_sha256'] != CLIENT_SHA or capture['client_sha256'] != CLIENT_SHA:
        raise ValueError('Mixed client identities')
    image, observation = NewImage(), ForensicObservation('new')
    proof = native_proof(image, observation)
    serializer_anchors = []
    for kind, owner, name, target in (
            ('ObjectProperty', 'Controller', 'Pawn', 0x10e92ca0),
            ('StructProperty', 'BP_DFMCharacter_C', 'UberGraphFrame', 0x10e92e50),
            ('BoolProperty', 'GameStateBase', 'bReplicatedHasBegunPlay', 0x10e924f0),
            ('IntProperty', 'Actor', 'NetTag', 0x10e61980)):
        cls = next(c for c in capture['selected_classes'] if c['name'] == owner)
        field = next(f for f in cls['own_properties'] if f['name'] == name)
        cell = field['field_vtable_rva']+8
        if struct.unpack('<Q', image.read(cell, 8))[0] != image.image_base+target:
            raise ValueError('Current observed field Serialize slot binding changed')
        serializer_anchors.append(dict(serialized_family=kind, current_observed_class=cls['path'],
            current_observed_property=name, field_vtable_rva=hex(field['field_vtable_rva']),
            immutable_serialize_target_rva=hex(target), function_called=False))
    actor = next(c for c in capture['selected_classes'] if c['path'] == '/Script/Engine.Actor')
    candidates = []
    for name, rva in (('Role', 0x1b48bdf0), ('RemoteRole', 0x1b48bf98)):
        field = next(f for f in actor['own_properties'] if f['name'] == name)
        record = image.read(rva, 48)
        pointer, notify, flags, gen, object_flags, dim, offset, enum_factory = struct.unpack('<3Q4iQ', record)
        observed_name = image.read(pointer-image.image_base, 64).split(b'\0', 1)[0].decode('ascii')
        if (observed_name != name or dim != field['array_dim'] or offset != field['storage_offset'] or
                enum_factory != image.image_base+0x132e97e0):
            raise ValueError('Current role property registration candidate differs from observed field identity')
        candidates.append(dict(property=name, parameter_record_rva=hex(rva),
            record_sha256=sha(record), record_bytes_hex=record.hex(),
            name_pointer_rva=hex(pointer-image.image_base), serialized_array_dim=dim,
            offset_matches_current_observed_property=offset, flags64=hex(flags),
            enum_factory_reference_rva=hex(enum_factory-image.image_base),
            native_parameter_consumer_qualified=False, runtime_enum_pointer_observed=False))
    parsed = [dict(package=p['package_path'], result=parse_class_stream(p)) for p in packages['packages']]
    helpers = [Path(__file__), ROOT/'work/research_updated_metadata_roots.py',
        ROOT/'work/research_updated_cooked_declarations_test.py']
    return dict(kind='current_cooked_field_stream_and_net_role_source_qualification',
        client_sha256=CLIENT_SHA, sources={PACKAGE_REPORT:PACKAGE_SHA, CAPTURE:CAPTURE_SHA,
            **{p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers}},
        native_proof=proof, native_code_source=observation.source_evidence(), packages=parsed,
        current_property_serializer_anchors=serializer_anchors,
        actor_role_registration_candidates=candidates,
        no_current_wire_handles_published=True, runtime_or_game_files_changed=False,
        process_opened=False, native_engine_function_called=False, native_acceptance_verified=False,
        remaining_requirements=[
            'Missing native parent reflected declarations: DFMPlayerController; GameState_SOL/GameState_PVPVE/DFMGameState/GPGameState/BaseGameState/GameState; SOLPlayerState/DFMPlayerState.',
            'The PC Blueprint Function export bodies still need complete UFunction field/parameter/FunctionFlags decoding before its own NetFunction contribution can be certified.',
            'Native parent and nested UScriptStruct declaration registration records: Actor.ReplicatedMovement/AttachmentReplication and native GameState MatchInfo.{MapID,RoomId}; their exact current type objects, struct flags, nested property order and serializer bindings are still required.',
            'The immutable Role/RemoteRole parameter candidates name the current ENetRole factory, but the native FPropertyParams constructor/owner linkage remains unqualified and their runtime Enum pointers were not observed.',
            'Inherited native C++ interface registration and nearest native parent constructor/vtable bindings for each selected Blueprint; cooked empty own interfaces do not establish inherited adjustments.',
            'Actual cached UClass+0x140 CDO pointer/index/serial and runtime main/secondary vtables are process-state observations; a serialized CDO export does not supply them.',
            'No current RepLayout/ClassNetCache index or checksum is recovered by this report.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or output.parent != ROOT/'work' or not output.name.startswith('research_'):
        parser.error('Fresh work/research_ report required')
    report = derive()
    raw = (json.dumps(report, ensure_ascii=True, indent=2)+'\n').encode('ascii')
    with output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(output), sha256=sha(raw),
        complete_packages=sum(r['result']['complete'] for r in report['packages']),
        enum=report['native_proof']['enum']['enumerators'])))
