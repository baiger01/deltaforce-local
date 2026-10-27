"""Admission-owned MainInit transition and native PathGuid derivation.

The authority evaluates the authored readiness edge. The client retains its
server-only transition policy and consumes ordinary replicated state changes.
"""
from contextlib import closing
from dataclasses import dataclass
from hashlib import md5, sha256
import json
from pathlib import Path
import sqlite3
import struct

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitWriter
from portable_character_initialization import CharacterInitializationReceipt

ROOT = Path(__file__).resolve().parent.parent
GRAPH = 'work/evidence/skill-flow-research-20261020-v1/authored-main-fsm-graph.json'
PATH_SOURCE = 'work/evidence/main-fsm-path-guid-source-20261021.json'
CAPTURE = 'work/native-client-tests/1792561390596287600/fsm-transition-node-policy-v2.json'
BYTECODE = 'work/evidence/skill-flow-research-20261020-v1/main-fsm-uassetapi-bytecode-v5.json'
RECEIVER = 'work/evidence/main-fsm-active-state-receiver-20261021.json'
REFERENCES = 'work/evidence/main-fsm-startup-reference-graphs-20261021.json'
REFERENCE_NATIVE = 'work/evidence/main-fsm-reference-parent-start-20261021.json'
PINS = {
    GRAPH: '2e2b74ec1c122deebabff271984caba88316220f43cd21fbb03953c6e7691e85',
    PATH_SOURCE: '0a45a079ae2fbef0e70b0c3469a0bdfbcc2b3b106d49ed17513108e2af49c731',
    CAPTURE: '180cd94c015cb31cc2db3ebad9de051084de1e2bfc7b0ca8869d53edf0d6d29a',
    BYTECODE: 'db061c7db7adaa493b637006c065343e791bf9d7996c2c43abb76ffe71f1b2d4',
    RECEIVER: '41b1c50331bbc0c4b7eb06fd8a4d52b95598149355b2581b824fbdb8b90b5fbf',
    REFERENCES: '39e21a52ebebfd41c78d1f287f4681c5f5f4927b61075c3d1ef440436c040806',
    REFERENCE_NATIVE: '0c23711f81a99a6304ffc5a4fe1ace56dc18aca81d9e4707e346b869fea6e08e',
}


def _sealed(relative):
    raw = (ROOT / relative).read_bytes()
    if sha256(raw).hexdigest() != PINS[relative]:
        raise ValueError('The native main FSM startup source changed: ' + relative)
    return json.loads(raw)


def path_guid(ancestors):
    """Native 1056730/10554e0/1065740: uppercase Guid path, MD5, FGuid words."""
    if (type(ancestors) is not tuple or not 1 <= len(ancestors) <= 64 or
            any(type(g) is not bytes or len(g) != 16 for g in ancestors)):
        raise ValueError('A bounded root-to-node tuple of native GUIDs is required')
    text = '/'.join(''.join(f'{word:08X}' for word in struct.unpack('<IIII', guid))
                    for guid in ancestors)
    digest = md5(text.encode('ascii')).digest()
    return struct.pack('<IIII', *struct.unpack('>IIII', digest))


def startup_schema():
    graph = _sealed(GRAPH)
    for source in graph['source_files']:
        if sha256((ROOT / source['relative_path']).read_bytes()).hexdigest() != source['sha256']:
            raise ValueError('The authored main FSM package changed')
    source = _sealed(PATH_SOURCE)
    if {f['requested_rva'] for f in source['functions']} != {
            '0x1056730', '0x10554e0', '0x1065740', '0x10b12c50',
            '0x10b37df0', '0x10b1fa60', '0x10b0a2b0'}:
        raise ValueError('The native PathGuid source functions changed')
    nodes = [(n, {p['name']: p.get('value') for p in n['properties']}) for n in graph['nodes']]
    _, initial = next((n, p) for n, p in nodes if p.get('NodeName') == 'MainInit')
    _, target = next((n, p) for n, p in nodes if p.get('NodeName') == 'DFMChararcterFSM_Sub')
    edge, transition = next((n, p) for n, p in nodes
        if p.get('FromGuid') == initial['Guid'] and p.get('ToGuid') == target['Guid'])
    if (initial['bIsRootNode'] is not True or initial['OwnerGuid'] != target['OwnerGuid'] or
            transition['bCanEvaluate'] is not True or
            transition['ConditionalEvaluationType'] != 'ESMConditionalEvaluationType::SM_Graph' or
            not edge['name'].startswith('SMGraphK2Node_TransitionResultNode_144_')):
        raise ValueError('The authored MainInit readiness edge changed')
    bytecode = _sealed(BYTECODE)
    wrapper, = [f for f in bytecode['functions']
                if f['name'].startswith('SMGraphK2Node_TransitionResultNode_144_MainInit to ')]
    call = wrapper['bytecode'][0]['expression']
    entry, = [p['Value'] for p in call['Parameters']]
    ubergraph, = [f for f in bytecode['functions'] if f['name'] == 'ExecuteUbergraph_DFMCharacterFSM_Main']
    assignment, = [b['expression'] for b in ubergraph['bytecode'] if b['memory_offset'] == entry]
    if (not assignment['$type'].startswith('UAssetAPI.Kismet.Bytecode.Expressions.EX_LetBool,') or
            assignment['VariableExpression']['StructMemberExpression']['New']['Path'] != ['bCanEnterTransition'] or
            assignment['AssignmentExpression']['Variable']['New']['Path'] != ['bFSMIsInited']):
        raise ValueError('The authored startup condition is no longer character readiness')
    capture = _sealed(CAPTURE)
    if (capture['status'] != 'observed' or capture['process_memory_written'] is not False or
            capture['native_methods_invoked'] is not False or
            capture['identities_and_fields_rechecked'] is not True):
        raise ValueError('Rechecked native state layout is required')
    row, = [o for o in capture['objects'] if o['class_path'].endswith('.DFMCharacterFSM_Main_C')]
    commands = row['existing_driver_class']['layout']['commands']
    fields = {}
    for name, handle, offset, children in (
            ('R_ActiveStates', 2, 1408, ('A', 'B', 'C', 'D')),
            ('RootStatePathGuidArray', 3, 1424, ('A', 'B', 'C', 'D')),
            ('PackedActiveStateNumInfos', 4, 1440, ('StatesSimpleId', 'StatesAddNum'))):
        command, = [c for c in commands if c.get('descriptor_name') == name]
        index = command['command_index']
        actual_children = commands[index + 1:index + 1 + len(children)]
        if (command['relative_handle'] != handle or command['data_offset'] != offset or
                command['dispatch_opcode'] != 0 or
                tuple(c['descriptor_name'] for c in actual_children) != children or
                tuple(c['relative_handle'] for c in actual_children) != tuple(range(1, len(children) + 1)) or
                any(c['dispatch_opcode'] != (5 if len(children) == 4 else 6) for c in actual_children)):
            raise ValueError('The native state array declaration changed: ' + name)
        fields[name] = handle
    _sealed(RECEIVER)
    _sealed(REFERENCE_NATIVE)
    states = [p for n, p in nodes if n['meta'] in (['SMState'], ['SMStateMachine'])]
    by_guid = {p['Guid']: p for p in states}
    if len(by_guid) != len(states) or not 1 <= len(states) <= 255:
        raise ValueError('The native byte-sized state path dictionary is not representable')
    root = target['OwnerGuid']

    def reachable(node):
        owner, seen = node['OwnerGuid'], {node['Guid']}
        while owner != root:
            if owner == '0' * 32:
                return False
            if owner in seen or len(seen) >= 64 or owner not in by_guid:
                raise ValueError('The authored state ancestry is incomplete or cyclic')
            seen.add(owner)
            owner = by_guid[owner]['OwnerGuid']
        return True

    # Cooked compiler placeholders with zero OwnerGuid are not in this root graph.
    states = [p for p in states if reachable(p)]

    def node_path(node):
        chain, seen = [bytes.fromhex(node['Guid'])], {node['Guid']}
        owner = node['OwnerGuid']
        while owner != root:
            if owner in seen or len(seen) >= 64 or owner not in by_guid:
                raise ValueError('The authored state ancestry is incomplete or cyclic')
            seen.add(owner)
            chain.append(bytes.fromhex(owner))
            owner = by_guid[owner]['OwnerGuid']
        return path_guid((bytes.fromhex(root), *reversed(chain))).hex()

    reference_graphs = {p['name']: p for p in _sealed(REFERENCES)['packages']}
    reference_entries, dictionary = {}, [node_path(p) for p in states]
    for node in states:
        class_path = node.get('ReferencedStateMachineClass')
        if not class_path:
            continue
        package = reference_graphs[class_path.rsplit('.', 1)[-1].removesuffix('_C')]
        for source in package['source_files']:
            if sha256((ROOT / source['relative_path']).read_bytes()).hexdigest() != source['sha256']:
                raise ValueError('A referenced FSM package changed')
        children = [{p['name']: p.get('value') for p in n['properties']}
                    for n in package['nodes'] if n['meta'] in (['SMState'], ['SMStateMachine'])]
        reference_by_guid = {p['Guid']: p for p in children}
        roots = {p['OwnerGuid'] for p in children} - set(reference_by_guid) - {'0' * 32}
        if len(roots) != 1 or any(p.get('ReferencedStateMachineClass') for p in children):
            raise ValueError('The referenced FSM topology differs from the qualified graph')
        reference_root, = roots

        def reference_reachable(value):
            seen = {value['Guid']}
            while value['OwnerGuid'] != reference_root:
                if value['OwnerGuid'] == '0' * 32:
                    return False
                if value['OwnerGuid'] in seen or len(seen) >= 64:
                    raise ValueError('A referenced state ancestry is cyclic')
                value = reference_by_guid[value['OwnerGuid']]
                seen.add(value['Guid'])
            return True

        children = [p for p in children if reference_reachable(p)]

        def chain_to_main(value):
            chain = [bytes.fromhex(value['Guid'])]
            while value['OwnerGuid'] != root:
                value = by_guid[value['OwnerGuid']]
                chain.append(bytes.fromhex(value['Guid']))
            return (bytes.fromhex(root), *reversed(chain))

        prefix = (*chain_to_main(node), bytes.fromhex(reference_root))

        def reference_path(value):
            chain, seen = [bytes.fromhex(value['Guid'])], {value['Guid']}
            while value['OwnerGuid'] != reference_root:
                if value['OwnerGuid'] in seen or len(seen) >= 64:
                    raise ValueError('A referenced state ancestry is cyclic')
                value = reference_by_guid[value['OwnerGuid']]
                seen.add(value['Guid'])
                chain.append(bytes.fromhex(value['Guid']))
            return path_guid((*prefix, *reversed(chain))).hex()

        dictionary.append(path_guid(prefix).hex())
        dictionary.extend(reference_path(p) for p in children)
        entries = []

        def reference_enter(owner):
            for child in children:
                if child['OwnerGuid'] == owner and child['bIsRootNode'] is True:
                    entries.append((child['NodeName'], reference_path(child)))
                    reference_enter(child['Guid'])

        reference_enter(reference_root)
        reference_entries[node['Guid']] = entries

    if not 1 <= len(dictionary) <= 255 or len(set(dictionary)) != len(dictionary):
        raise ValueError('The contextual state path dictionary is ambiguous or exceeds native IDs')
    active = []

    def enter(node):
        entry = (node['NodeName'], node_path(node))
        if entry in active:
            raise ValueError('The authored startup entry closure is cyclic')
        active.append(entry)
        for child in states:
            if child['OwnerGuid'] == node['Guid'] and child['bIsRootNode'] is True:
                enter(child)
        active.extend(reference_entries.get(node['Guid'], ()))

    enter(target)
    initial_active = tuple(active)
    init, = [p for p in states if p['NodeName'] == 'Init' and (p['NodeName'], node_path(p)) in active]
    if init['bStayActiveOnStateChange'] is not False:
        raise ValueError('The authored Init transition exit policy changed')
    parallel = [(n, p) for n, p in nodes if p.get('FromGuid') == init['Guid']]
    if len(parallel) != 4:
        raise ValueError('The authored server startup fork changed')
    active.remove((init['NodeName'], node_path(init)))
    by_offset = {b['memory_offset']: b['expression'] for b in ubergraph['bytecode']}
    for edge_node, edge_fields in parallel:
        if (edge_fields['bCanEvaluate'] is not True or edge_fields['bRunParallel'] is not True or
                edge_fields['Priority'] != 0 or
                edge_fields['ConditionalEvaluationType'] != 'ESMConditionalEvaluationType::SM_Graph'):
            raise ValueError('A parallel startup transition policy changed')
        edge_number = edge_node['name'].split('_')[2]
        wrapper, = [f for f in bytecode['functions'] if f['name'].startswith(
            'SMGraphK2Node_TransitionResultNode_' + edge_number + '_Init to ')]
        expression = by_offset[wrapper['bytecode'][0]['expression']['Parameters'][0]['Value']]
        call = expression['AssignmentExpression']
        math_function = bytecode['imports'][-call['StackNode'] - 1]['name']
        operands = tuple((p['ObjectExpression']['Variable']['New']['Path'],
                          p['ContextExpression']['Variable']['New']['Path']) for p in call['Parameters'])
        if math_function != 'BooleanAND' or operands != (
                (['FSMOwner'], ['bFSMIsInited']), (['Blackboard'], ['isServer'])):
            raise ValueError('A startup transition no longer uses committed server readiness')
        enter(by_guid[edge_fields['ToGuid']])
    return dict(active_name=target['NodeName'], active_path_guid=node_path(target),
                active_names=[n for n, _ in initial_active], active_paths=[g for _, g in initial_active],
                operational_names=[n for n, _ in active], operational_paths=[g for _, g in active],
                path_dictionary=dictionary,
                transition_name=edge['name'], fields=fields, sources=PINS,
                implementation_sha256=sha256(Path(__file__).read_bytes()).hexdigest())


def source_pins():
    startup_schema()
    return dict(PINS, **{'work/portable_main_fsm_startup.py': sha256(Path(__file__).read_bytes()).hexdigest()})


@dataclass(frozen=True)
class MainFSMStartup:
    character: CharacterInitializationReceipt
    source_sha256: str
    active_name: str
    active_path_guid: bytes
    active_names: tuple[str, ...]
    active_paths: tuple[bytes, ...]
    path_dictionary: tuple[bytes, ...]
    phase: str


def _expected(receipt, phase='entered'):
    if type(receipt) is not CharacterInitializationReceipt:
        raise ValueError('A committed initialized character is required')
    receipt.validate_committed()
    if receipt.fsm_ready is not True or receipt.state.server_identity is not True:
        raise ValueError('The authored startup readiness condition has not been met')
    if phase not in ('entered', 'operational'):
        raise ValueError('An authored startup phase is required')
    schema = startup_schema()
    digest = sha256(json.dumps(schema, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return MainFSMStartup(receipt, digest, schema['active_name'], bytes.fromhex(schema['active_path_guid']),
        tuple(schema['active_names' if phase == 'entered' else 'operational_names']),
        tuple(bytes.fromhex(g) for g in schema['active_paths' if phase == 'entered' else 'operational_paths']),
        tuple(bytes.fromhex(g) for g in schema['path_dictionary']), phase)


def commit_startup(receipt, *, phase='entered'):
    state = _expected(receipt, phase)
    with closing(sqlite3.connect(receipt.store_path, timeout=30)) as db, db:
        db.execute('begin immediate')
        db.execute('create table if not exists main_fsm_startups_v3 ('
                   'admission_sha256 text not null, phase text not null, character_sha256 text not null, '
                   'source_sha256 text not null, active_path_guid blob not null, '
                   'primary key(admission_sha256,phase))')
        expected = (receipt.state_sha256, state.source_sha256, state.active_path_guid)
        row = db.execute('select character_sha256,source_sha256,active_path_guid '
                         'from main_fsm_startups_v3 where admission_sha256=? and phase=?',
                         (receipt.admission_sha256, phase)).fetchone()
        if row is None:
            db.execute('insert into main_fsm_startups_v3 values(?,?,?,?,?)',
                       (receipt.admission_sha256, phase, *expected))
        elif row != expected:
            raise ValueError('This admission has conflicting main FSM startup state')
    return state


def commit_operational_startup(receipt):
    try:
        _validate(_expected(receipt))
    except sqlite3.OperationalError as error:
        raise ValueError('The authored main entry phase has not been committed') from error
    return commit_startup(receipt, phase='operational')


def _validate(state):
    if type(state) is not MainFSMStartup or state != _expected(state.character, state.phase):
        raise ValueError('A committed source-qualified main FSM startup is required')
    with closing(sqlite3.connect(Path(state.character.store_path).as_uri() + '?mode=ro',
                                 uri=True, timeout=30)) as db:
        row = db.execute('select character_sha256,source_sha256,active_path_guid '
                         'from main_fsm_startups_v3 where admission_sha256=? and phase=?',
                         (state.character.admission_sha256, state.phase)).fetchone()
    if row != (state.character.state_sha256, state.source_sha256, state.active_path_guid):
        raise ValueError('The startup state is not persisted for this admission')
    return startup_schema()['fields']


def _write_paths(writer, handle, paths, *, start=0, count=None):
    writer.write_packed_int(handle)
    writer.write_bits(len(paths) if count is None else count, 16)
    for index, path in enumerate(paths, start):
        for child, word in enumerate(struct.unpack('<IIII', path), 1):
            writer.write_packed_int(index * 4 + child)
            writer.write_bits(word, 32)
    writer.write_packed_int(0)


def build_dictionary_contents(state):
    fields = _validate(state)
    result = []
    for start in range(0, len(state.path_dictionary), 32):
        end = min(start + 32, len(state.path_dictionary))
        writer = BitWriter()
        writer.write_bool(False)
        # Grow the ordinary array by complete GUIDs; never expose zero placeholders.
        _write_paths(writer, fields['RootStatePathGuidArray'], state.path_dictionary[start:end],
                     start=start, count=end)
        writer.write_packed_int(0)
        result.append(ActorContentBlock(True, writer.to_bytes(), writer.bit_count))
    return tuple(result)


def build_content(state):
    fields = _validate(state)
    writer = BitWriter()
    writer.write_bool(False)
    _write_paths(writer, fields['R_ActiveStates'], state.active_paths)
    writer.write_packed_int(fields['PackedActiveStateNumInfos'])
    writer.write_bits(len(state.active_paths), 16)
    for index, path in enumerate(state.active_paths):
        writer.write_packed_int(index * 2 + 1)
        writer.write_bits(state.path_dictionary.index(path), 8)
        writer.write_packed_int(index * 2 + 2)
        writer.write_bits(1, 8)
    writer.write_packed_int(0)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)
