"""Finite current RPC parameter receiver and compressed Rotator qualification."""
import argparse
import json
from pathlib import Path
import struct

from research_updated_metadata_roots import ROOT, ForensicObservation, sha
from research_updated_native_registration import Archive, CLIENT_SHA
from research_updated_replication_core import compare_full, locate
from research_updated_serializer_bindings import explicit_tail_leaf

INPUTS = {
    'work/research_updated_minimum_rpc_declarations_79fb7b10_v1.json':
        '246c6bdbf856f638c84d3f8916ac41773c38c8f7e53b8e1fcc25e657c52a9909',
    'work/research_updated_command_shapes_79fb7b10_v1.json':
        '68471964b153ab566619c123fe03b53f5ac1e7221f4f74697ad3b2aaf9476989',
}
PAIRS = (
    ('rpc_parameter_receiver', 0x12db93c0, 0x12db9710),
    ('rpc_recursive_command_receiver', 0x12dc23f0, 0x12dc2740),
    ('rpc_array_command_receiver', 0x12dc20b0, 0x12dc2400),
    ('function_layout_initialize', 0x12db2cb0, 0x12db3000),
    ('recursive_command_builder', 0x12d9b1e0, 0x12d9b530),
    ('rotator_net_bridge', 0x10ab4e20, 0x10ab4820),
    ('rotator_compressed_shorts', 0x10ab83a0, 0x10ab7da0),
)


def witness(rows, address, expected, meaning):
    actual = rows.get(address)
    if actual is None or actual['instruction'] != expected:
        raise ValueError('Current RPC receive witness changed: ' + meaning)
    return dict(meaning=meaning, **actual)


def derive():
    documents = {}
    for path, expected in INPUTS.items():
        raw = (ROOT/path).read_bytes()
        if sha(raw) != expected:
            raise ValueError('Current RPC source input changed: ' + path)
        documents[path] = json.loads(raw)
    declarations = next(v for k, v in documents.items() if 'declarations_' in k)
    if not declarations['current_parameter_declaration_trees_complete']:
        raise ValueError('Current complete RPC declaration trees required')
    a, old = Archive(), ForensicObservation('old')
    functions, searches = [], []
    for name, previous, current in PAIRS:
        candidates = locate(old, a.code, previous)
        if current not in candidates or (name != 'function_layout_initialize' and candidates != [current]):
            raise ValueError('Current full-function search candidate changed: '+name)
        searches.append(dict(function=name, candidates=[hex(x) for x in candidates],
            search_is_only_a_locator=True, selected_binding='Pinned current function-layout factory/declaration proof' if name == 'function_layout_initialize'
                else 'Unique search candidate followed by whole-function comparison'))
        functions.append(compare_full(old, a.code, a.image, name, previous, current))
    functions.append(explicit_tail_leaf(old, a.code, a.image, 'rotator_cpp_ops_net_serialize',
        0x10e3cb00, 0x10e3c4a0, 10, 'jmp 0x10ab4820'))
    rows = {int(i['rva'], 16): i for f in functions for i in f['decoded_new_instructions']}
    checks = (
        (0x12db9804, 'test byte ptr [rax + 0xb4], 1', 'Channel connection internal-ACK flag selects ordinary/compatibility path'),
        (0x12db9811, 'cmp byte ptr [rsi + 0xb0], 0', 'Channel-local second alternate receive-path guard'),
        (0x12db99c2, 'mov rax, qword ptr [rax + 0x20]', 'Outer parameter FFieldClass'),
        (0x12db99c9, 'shr rcx, 0x11', 'Bool FieldClass cast flag17'),
        (0x12db99d0, 'jne 0x12db9a37', 'Bool outer parameter bypasses presence read'),
        (0x12db99e4, 'cmp rdi, qword ptr [r13 + 0xa0]', 'Presence read checks archive bit limit'),
        (0x12db9a1f, 'inc qword ptr [r13 + 0xa8]', 'Exactly one presence bit consumed for a non-bool outer parameter'),
        (0x12db9a31, 'je 0x12db9bfd', 'Absent outer parameter skips the complete command range'),
        (0x12db9a50, 'movzx ecx, word ptr [r12 + rdi + 0x26]', 'Outer parameter exclusive command end'),
        (0x12db9a62, 'movzx r9d, word ptr [r12 + rax + 0x24]', 'Outer parameter command start'),
        (0x12db9a92, 'call 0x12dc2740', 'Present outer parameter delegates to command receiver'),
        (0x12db9c03, 'add r12, 0x40', 'Parameter parent stride64'),
        (0x12dc27bf, 'cmp byte ptr [r14 + 0x1c], 0', 'Opcode0 is the dynamic-array branch'),
        (0x12dc27fd, 'call 0x12dc2400', 'Array receiver is separately compared, though not used by the twelve RPCs'),
        (0x12dc2817, 'test byte ptr [r15 + 0x28], 2', 'Serialized-buffer cache is a saving-archive branch'),
        (0x12dc2886, 'mov rcx, qword ptr [r14]', 'Leaf serializer uses the command original property descriptor'),
        (0x12dc28a4, 'call qword ptr [rax + 0x90]', 'Leaf property NetSerializeItem dispatch'),
        (0x12d9b6b7, 'je 0x12d9b729', 'Struct without native NetSerialize recursively expands'),
        (0x12d9b89c, 'call 0x12d9b530', 'Ordinary nested struct fields are flattened by the builder'),
        (0x10ab4829, 'call 0x10ab7da0', 'Rotator native NetSerialize delegates compressed shorts'),
        (0x10ab7ddd, 'and r14b, 1', 'Compressed Rotator tests archive loading bit'),
        (0x10ab7e5f, 'call qword ptr [rax + 0x68]', 'Pitch presence bit'),
        (0x10ab7ed6, 'call qword ptr [rax + 0x68]', 'Yaw presence bit'),
        (0x10ab7f3c, 'call qword ptr [rax + 0x68]', 'Roll presence bit'),
    )
    witnesses = [witness(rows, *row) for row in checks]
    constants = []
    rotator = next(f for f in functions if f['name'] == 'rotator_compressed_shorts')
    expected_constants = ('610b3643', '0000003f', '0000b43b')
    for ref in rotator['references']:
        if ref['kind'] != 'rip_reference':
            continue
        previous, current = int(ref['old_target'], 16), int(ref['new_target'], 16)
        now = a.read(current, 4)
        if now.hex() != expected_constants[len(constants)]:
            raise ValueError('Current Rotator arithmetic constant changed')
        constants.append(dict(old_rva=hex(previous), current_rva=hex(current), bytes_hex=now.hex(),
            float32=struct.unpack('<f', now)[0], sha256=sha(now), historical_literal_value_available=False))
    if len(constants) != 3:
        raise ValueError('Complete Rotator literal closure changed')
    structures = declarations['structures']
    for node in structures:
        if node['name'] != 'Rotator':
            ops = node['cpp_struct_ops_source_binding']
            if not ops or ops['struct_flag_0x400_after_prepare'] is not False:
                raise ValueError('Ordinary RPC nested struct NetSerialize absence unqualified')
    pins = [Path(__file__), ROOT/'work/research_updated_native_registration.py',
        ROOT/'work/research_updated_replication_core.py', ROOT/'work/research_updated_serializer_bindings.py']
    return dict(kind='current_rpc_parameter_receive_source_qualification', client_sha256=CLIENT_SHA,
        source_inputs=INPUTS, source_pins={p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in pins},
        functions=functions, search_candidates=searches, exact_instruction_witnesses=witnesses, rotator_constants=constants,
        ordinary_receive_model=dict(
            guard='Channel connection at channel+0x28: connection byte+0xb4 bit0 clear OR channel byte+0xb0 nonzero; the selected ordinary connection path must establish this guard.',
            parent_order='Current function-layout parent declaration order, stride64; exclusive command range at parent+0x24/+0x26.',
            non_bool_outer_parameter='One presence bit; zero skips all commands; one serializes the full command range.',
            bool_outer_parameter='No presence bit; serializes its value using the bound bool property serializer.',
            ordinary_struct='No extra inner presence bits; current builder flattens recursively, using declaration and static-array order.',
            native_struct='One outer presence bit followed by the current bound native NetSerialize body.',
            scalar_leaf='The command original descriptor selects slot0x90; concrete current declaration/vtable/method bindings are in the pinned declaration report.',
            loading_archive='Must have archive+0x28 bit0 set and bit1 clear; this skips saving-only serialized-cache branch.'),
        derived_wire_shapes=dict(ServerBouncePing=dict(bits=225, recipe='outer presence1 + Double64 + five Float32'),
            ClientReturnPing=dict(bits=161, recipe='outer presence1 + Double64 + Double64 + Float32'),
            ClientSetRotation=dict(bits='5+16*n where n is number of nonzero quantized axes',
                recipe='outer Rotator presence1; three axis presence bits with u16 for each present axis; outer bool value1'),
            ClientSetViewTarget=dict(transition_present_bits=69,
                recipe='Object outer presence + PackageMap GUID; transition outer presence1 + Float32 + enum Byte3 + Float32 + bitfield Bool1',
                constructor_default_omission_qualified=False),
            FloatParameter=dict(bits=33, recipe='outer presence1 + Float32'),
            NativeBoolParameter=dict(bits=1, recipe='bool value only')),
        current_complete_receiver_equivalence=True, current_rpc_parameter_traversal_qualified=True,
        current_rotator_net_serialize_code_equivalence=True, current_rotator_arithmetic_constants_qualified=True,
        historical_rotator_literal_values_compared=False, current_property_bindings_from_pinned_declarations=True,
        selected_package_map_reference_dispatch_qualified=False, selected_connection_archive_context_qualified=False,
        limitations=['This proves the ordinary reader and exact declaration-based body shape; it does not approve an alternate internal-ACK compatibility path.',
            'Object PackageMap dispatch and selected loading/archive context require their separate finite source contract.',
            'No constructor-default claim for an omitted ViewTargetTransitionParams; explicit present values avoid that dependency.',
            'Source-derived values are not observed initialized runtime cache values or native acceptance.'],
        immutable_reads=list(a.data.values()), code_sources=[old.source_evidence(), a.code.source_evidence()],
        process_opened=False, native_engine_function_called=False, runtime_files_changed=False,
        profile_guards_relaxed=False, native_acceptance_verified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    target = args.output.resolve()
    if target.exists() or target.parent != ROOT/'work' or not target.name.startswith('research_'):
        parser.error('Fresh work/research_ report required')
    result = derive()
    raw = (json.dumps(result, ensure_ascii=True, indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target), sha256=sha(raw), functions=len(result['functions']),
        witnesses=len(result['exact_instruction_witnesses']))))
