"""Current immutable map component declarations, without profile activation."""
import argparse
import bisect
import json
import mmap
from pathlib import Path
import struct

from capstone.x86 import X86_OP_IMM, X86_OP_REG
from research_updated_metadata_roots import CLIENT, ROOT, sha
from research_updated_native_registration import Archive, CLIENT_SHA, text
from research_updated_nested_registration import struct_references
from research_updated_minimum_leaf_bindings import enum_registration

INPUT = 'work/research_updated_native_registration_79fb7b10_v4.json'
INPUT_SHA256 = 'e50210e8b851275204ab95ae67caedf3e03ef76353776387834578136bbda663'


def named_initializer(archive, name):
    targets = set()
    with CLIENT.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        for prefix in ('A', 'U'):
            literal = (prefix+name+'\0').encode('utf-16le')
            at = raw.find(literal)
            while at >= 0:
                for start, size, offset in archive.image.sections:
                    if offset <= at < offset+size:
                        targets.add(start+at-offset)
                at = raw.find(literal, at+1)
                if len(targets) > 16:
                    raise ValueError('Ambiguous native class registration literal')
    hits = {}
    for first, _, _ in archive.code.blocks:
        archive.code.read(first, 1)
        raw = archive.code.loaded[first]
        at = raw.find(b'\x4c\x8d\x05')
        while 0 <= at and at+7 <= len(raw):
            target = first+at+7+struct.unpack_from('<i', raw, at+3)[0]
            if target in targets:
                index = bisect.bisect_right(archive.image.starts, first+at)-1
                if index >= 0:
                    entry = archive.image.entries[index]
                    if entry[0] <= first+at < entry[1]:
                        ins = archive.instructions(entry[0])
                        if (len(ins) == 12 and ins[-3].mnemonic == 'call' and
                                ins[-3].operands[0].type == X86_OP_IMM and
                                ins[-3].operands[0].imm == 0x10ec0a90):
                            args = {i.reg_name(i.operands[0].reg): archive.rip(i) for i in ins
                                if i.mnemonic == 'lea' and i.operands[0].type == X86_OP_REG}
                            literal = text(archive.read, args['r8'], wide=True)
                            if literal not in ('A'+name, 'U'+name):
                                raise ValueError('Exact native class registration name disagrees')
                            row = archive.class_record(archive.factory(args['rcx']), include_functions=False)
                            if (row['name'] != name or row['package'] != text(archive.read, args['r9'], wide=True)
                                    or row['native_no_register_getter_rva'] != hex(args['rdx'])):
                                raise ValueError('Class registration getter/Params identities disagree')
                            row['registration_initializer_rva'] = hex(entry[0])
                            row['registration_cpp_name'] = literal
                            hits[row['factory_rva']] = row
            at = raw.find(b'\x4c\x8d\x05', at+1)
    if len(hits) != 1:
        raise ValueError('Unique complete current class initializer required: '+name)
    return next(iter(hits.values()))


def derive():
    raw = (ROOT/INPUT).read_bytes()
    if sha(raw) != INPUT_SHA256:
        raise ValueError('Current parent declaration source changed')
    native = json.loads(raw)
    expected = {c['name']: c for c in native['classes']}
    archive = Archive()
    specs = (('DFMGameState', 'MapInfoSystemComponent'),
             ('DFMPlayerState', 'MapInfoComp'), ('GameState_PVPVE', 'BlueprintPlunder'))
    classes, edges = {}, []
    for parent, field_name in specs:
        field, = [f for f in expected[parent]['fields']['fields'] if f['name'] == field_name]
        callback, = field['callbacks']
        identity = archive.class_identity(int(callback['function_rva'], 16))
        row = named_initializer(archive, identity['name'])
        if row['package'] != identity['package']:
            raise ValueError('Parent object property and current class package disagree')
        classes[row['factory_rva']] = row
        edges.append(dict(parent=parent, property=field_name, property_record_rva=field['parameter_record_rva'],
            no_register_getter_rva=callback['function_rva'], class_factory_rva=row['factory_rva']))
    pending = [dependency for c in classes.values() for dependency in c['dependency_factories']
               if dependency['kind'] == 'class']
    while pending:
        factory = pending.pop(0)
        if factory['factory_rva'] in classes:
            continue
        if len(classes) >= 32:
            raise ValueError('Current map component ancestry exceeds local bound')
        row = archive.class_record(factory, include_functions=False)
        classes[row['factory_rva']] = row
        pending.extend(d for d in row['dependency_factories'] if d['kind'] == 'class')
    references = []
    for row in classes.values():
        for field in row['fields']['fields']:
            if field['net_flag']:
                references.extend(struct_references(field, row['name']+'/'+field['name']))
    structures, unresolved, enums = {}, [], {}
    pending = list(references)
    while pending:
        edge = pending.pop(0)
        factory = edge['struct_factory_rva']
        if factory in structures or any(r['struct_factory_rva'] == factory for r in unresolved):
            continue
        if len(structures)+len(unresolved) >= 64:
            raise ValueError('Current nested map state exceeds local bound')
        try:
            row = archive.structure(int(factory, 16))
        except ValueError as error:
            unresolved.append(dict(**edge, reason=str(error)))
            continue
        structures[factory] = row
        for field in row['fields']['fields']:
            pending.extend(struct_references(field, row['name']+'/'+field['name']))
            if field['kind'] == 'FEnumProperty':
                callback, = [c for c in field['callbacks'] if c['parameter_offset'] == '0x28']
                key = callback['function_rva']
                if key not in enums:
                    enums[key] = enum_registration(archive, int(key, 16))
    helpers = ('research_updated_map_components.py', 'research_updated_native_registration.py',
        'research_updated_nested_registration.py', 'research_updated_minimum_leaf_bindings.py')
    return dict(kind='current_source_map_component_declarations', client_sha256=CLIENT_SHA,
        source_inputs={INPUT: INPUT_SHA256}, source_pins={
            'work/'+name: sha((ROOT/'work'/name).read_bytes()) for name in helpers},
        parent_component_edges=edges, classes=list(classes.values()), structures=list(structures.values()),
        enums=list(enums.values()), unresolved_struct_factories=unresolved,
        source_functions=[row for _, row in archive.functions.values()], immutable_reads=list(archive.data.values()),
        code_source=archive.code.source_evidence(), native_rep_layout_observed=False,
        runtime_wire_handles_qualified=False, process_opened=False, native_engine_function_called=False,
        gameplay_activated=False, native_acceptance_verified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    target = args.output.resolve()
    if target.exists() or target.parent != ROOT/'work/evidence':
        parser.error('Fresh work/evidence output required')
    report = derive()
    raw = (json.dumps(report, sort_keys=True, indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target), sha256=sha(raw), classes=len(report['classes']),
        structures=len(report['structures']), enums=len(report['enums']),
        unresolved=report['unresolved_struct_factories'])))
