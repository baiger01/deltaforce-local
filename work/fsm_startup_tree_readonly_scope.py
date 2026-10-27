"""Read typed inline startup nodes and their actual referenced FSM instances."""
from hashlib import sha256
import json
from pathlib import Path
import struct

from portable_main_fsm_startup import ROOT, GRAPH, REFERENCES, PINS, startup_schema


def source_pins():
    startup_schema()
    return dict(PINS, **{'work/fsm_startup_tree_readonly_scope.py': sha256(Path(__file__).read_bytes()).hexdigest()})


def read_node(read, instance, field, authored):
    if (field['field_vtable_rva'] != 0x15a86f40 or field['array_dimension'] != 1 or
            type(field['storage_offset']) is not int or not 0 <= field['storage_offset'] < 1024 * 1024 or
            not 0x138 <= field['element_bytes'] <= 0x358):
        raise ValueError('The current inline native state declaration is not qualified')
    node = instance + field['storage_offset']
    owner, = struct.unpack('<Q', read(node + 0xd8, 8))
    guid = read(node + 0x54, 16).hex()
    if owner != instance or guid != authored['Guid']:
        raise ValueError('The current inline node owner or authored GUID differs')
    active = read(node + 0x132, 1)
    if active not in (b'\0', b'\1'):
        raise ValueError('The current state active flag is not canonical')
    return node, dict(name=authored['NodeName'], guid=guid,
                      path_guid=read(node + 0x74, 16).hex(), active=active == b'\1',
                      storage_offset=field['storage_offset'])


def read_tree(*, read, instance, record, observation):
    source_pins()
    main = json.loads((ROOT / GRAPH).read_bytes())
    packages = {p['name']: p for p in json.loads((ROOT / REFERENCES).read_bytes())['packages']}
    rows, references = [], []

    def inline(current_instance, current_record, nodes):
        result = []
        declarations = {f['name']: f for d in current_record['declarations'] for f in d['fields']}
        for authored in nodes:
            if authored['meta'] not in (['SMState'], ['SMStateMachine']):
                continue
            values = {p['name']: p.get('value') for p in authored['properties']}
            if values['OwnerGuid'] == '0' * 32:
                continue
            field = declarations[authored['name']]
            pointer, row = read_node(read, current_instance, field, values)
            result.append(row)
            if current_instance != instance or not values.get('ReferencedStateMachineClass'):
                continue
            # SMStateMachine source 105d930/106c4c0 uses this reference pointer.
            reference, = struct.unpack('<Q', read(pointer + 0x330, 8))
            if not reference:
                references.append(dict(name=row['name'], status='null_reference', active=row['active']))
                continue
            identity = observation.identify(reference, 'SMInstance')
            reference_record = observation.metadata_reader(reference, 'SMInstance')
            class_path = values['ReferencedStateMachineClass']
            if reference_record['class_path'] != class_path:
                raise ValueError('The referenced FSM class differs from the authored class')
            root_field, = [f for d in reference_record['declarations'] for f in d['fields']
                          if f['name'] == 'RootStateMachine']
            if root_field['storage_offset'] != 0x220 or root_field['element_bytes'] != 0x358:
                raise ValueError('The referenced native root declaration changed')
            root_at = reference + root_field['storage_offset']
            parents = struct.unpack('<Q', read(root_at + 0x88, 8))[0], struct.unpack('<Q', read(root_at + 0x340, 8))[0]
            if any(p not in (0, pointer) for p in parents) or not any(parents):
                raise ValueError('The referenced root does not belong to this inline reference node')
            package = packages[class_path.rsplit('.', 1)[-1].removesuffix('_C')]
            references.append(dict(name=row['name'], status='observed', identity=identity,
                class_path=class_path, active=row['active'], root_guid=read(root_at + 0x54, 16).hex(),
                root_path_guid=read(root_at + 0x74, 16).hex(), parent_is_current_reference_node=True,
                nodes=inline(reference, reference_record, package['nodes'])))
        return result

    rows = inline(instance, record, main['nodes'])
    return dict(status='observed', inline_nodes=rows, references=references,
                native_methods_invoked=False, process_memory_written=False,
                gameplay_execution_inferred=False)
