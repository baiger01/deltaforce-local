"""Current native MovementReplicationActor creation recipe; no movement payload."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from research_updated_metadata_roots import ROOT, instruction_row
from research_updated_native_registration import Archive, CLIENT_SHA, text
from research_updated_source_map_schema import private_class_arguments
from research_updated_source_template_bindings import constructor, constructor_assignments, find_class


INPUTS = {
    'work/research_updated_native_registration_79fb7b10_v4.json':
        'e50210e8b851275204ab95ae67caedf3e03ef76353776387834578136bbda663',
    'work/evidence/updated-first-player-ready-prerequisite-79fb7b10.json':
        '0a69cc874dbe40647de6b5a304bae20fdac138aa941527e21387e99919e22ec9',
}


def derive():
    docs = {}
    for path, digest in INPUTS.items():
        raw = (ROOT/path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Current movement creation source changed')
        docs[path] = json.loads(raw)
    a = Archive()
    selected = find_class(a, 'MovementReplicationActor', prefix='A')
    row = a.class_record(a.factory(int(selected['factory_rva'], 16)))
    getter = int(row['private_class_getter_rva'], 16)
    arguments = private_class_arguments(a.instructions(getter))
    parent = a.class_identity(arguments['super_class_getter_rva'])
    if (row['package'], row['name'], parent['package'], parent['name']) != (
            '/Script/GPGameplay', 'MovementReplicationActor', '/Script/Engine', 'Actor'):
        raise ValueError('Current native movement class/parent identity changed')
    native = docs[next(path for path in INPUTS if 'native_registration_' in path)]
    ancestors = {c['name']: c for c in native['classes'] + native['supporting_native_ancestors']}
    interfaces = list(row['own_interfaces'])
    for name in ('Actor', 'Object'):
        ancestor = ancestors[name]
        if ancestor['own_interfaces']:
            interfaces += ancestor['own_interfaces']
    for interface in interfaces:
        interface['source_class_identity'] = a.class_identity(int(interface['class_getter_rva'], 16))
        if interface['source_class_identity']['name'] == 'NetRepActorInterface':
            raise ValueError('A movement Actor with a NetRepActorInterface requires another open-tail recipe')
    instructions, from_initializer = constructor(a, arguments['class_constructor_wrapper_rva'])
    assignments = constructor_assignments(instructions, from_initializer=from_initializer)
    primary = [r for r in assignments if r['object_offset'] == 0]
    if len(primary) != 1:
        raise ValueError('Unique native movement primary vtable required')
    table = primary[0]['source_rva']
    hook, = struct.unpack('<Q', a.read(table + 0x3d8, 8))
    hook -= a.base
    tail = a.instructions(hook)
    if len(tail) != 1 or (tail[0].mnemonic, tail[0].op_str) != ('ret', '0'):
        raise ValueError('Movement open hook is not a complete empty return')
    # The CDO's name and direct Package Outer come from current engine code,
    # independently of a cached runtime CDO or historical template observation.
    creator = a.instructions(0x10cf9c00)
    allocator = a.instructions(0x10ebc130)
    name_builder = a.instructions(0x10cfde80)
    expected = {
        0x10cf9e23: ('mov', 'rdx, qword ptr [rbx + 0x10]'),
        0x10cf9e27: ('mov', 'r9d, 0x31'),
        0x10cf9e47: ('call', '0x10ebc130'),
        0x10ebc16b: ('shr', 'eax, 4'),
        0x10ebc179: ('je', '0x10ebc194'),
        0x10ebc17f: ('call', '0x10cfde80'),
        0x10cfdec2: ('mov', 'rax, qword ptr [rbx + 0x1c]'),
        0x10cfded5: ('call', '0x10b5b890'),
    }
    by_address = {i.address: i for i in creator + allocator + name_builder}
    if any((by_address[at].mnemonic, by_address[at].op_str) != pair for at, pair in expected.items()):
        raise ValueError('Current native CDO naming/Outer algorithm changed')
    if text(a.read, 0x15745f18, wide=True) != 'Default__':
        raise ValueError('Current native CDO prefix differs')
    package, name = row['package'], row['name']
    helpers = ('work/research_updated_movement_actor_profile.py',
        'work/research_updated_native_registration.py', 'work/research_updated_metadata_roots.py',
        'work/research_updated_source_map_schema.py', 'work/research_updated_source_template_bindings.py')
    return dict(kind='current_native_movement_actor_creation_source', client_sha256=CLIENT_SHA,
        source_pins={**INPUTS, **{p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in helpers}},
        class_path=package+'.'+name, archetype_path=package+'.Default__'+name, package_path=package,
        archetype_qualification='source_native_class_default_object',
        native_class=row, native_class_registration=selected, constructor_arguments=arguments,
        constructor_primary_assignment=primary[0], inherited_interfaces=interfaces,
        actor_open_hook=dict(slot='0x3d8', target_rva=hex(hook), empty_return=True),
        net_rep_actor_interface=None, actor_open_tail_bits=0,
        cdo_source=dict(name_prefix_rva='0x15745f18', direct_outer='native_class_UObject_outer',
            class_flags='0x31', instructions=[instruction_row(by_address[at]) for at in expected]),
        replicated_movement_payload_implemented=False, runtime_cdo_observed=False,
        runtime_native_cache_observed=False, actor_transmission_enabled=False,
        native_acceptance_verified=False, process_opened=False, native_function_called=False,
        native_code_functions=[report for _, report in a.functions.values()],
        immutable_reads=list(a.data.values()), code_source=a.code.source_evidence())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    target = args.output.resolve()
    if target.parent != ROOT/'work/evidence' or target.exists():
        parser.error('A fresh work/evidence output is required')
    result = derive()
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=str(target), sha256=hashlib.sha256(raw).hexdigest(),
        class_path=result['class_path'], tail_bits=result['actor_open_tail_bits'])))
