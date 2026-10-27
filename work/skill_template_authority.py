"""Local authority execution of the qualified authored template collection phase.

This executes collection, not gameplay effects. Parameters and callbacks are real
cooked inputs. The local task objects retain typed data, registration dependencies
and callback edges. No native lifecycle byte is set and no game process is used.
"""
from collections import deque
from contextlib import closing
from dataclasses import asdict, dataclass, replace
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import struct

from skill_template_replication import ROOT, project_initial_plan, source_schema

BASE = 'work/evidence/skill-template-materialization-20261020-v1/'
PINS = {
    'authored-task-construction-inputs.json': '7fc7d6c491ae33a0875e57255943c7b0c791d73a8d9d29eb2dca69f7b6a1c18b',
    'qualification.json': 'ac88b290c55deb22f52c357baae510ab3a9007ea4fdb9cc0049e4217a902084c',
    'native-derived-task-collect-vtables-v1.json': '6f61745827dfa98c08632569988233da521edca14f7d4e7e9b01d3ff3c6edf9d',
    'native-derived-task-collection-methods-v1.json': '5c40f61071ba2084591b10fca3623cf2c91c2a6e54f207adc177b55751b03e01',
    'native-task-collect-notify-and-ready-v1.json': '8a74e8858207cd803ee8ba571ed2fb1218a161421b92ed160306decd3366edc4',
    'native-task-collect-state-entry-v1.json': '20aa388e8cdc6945b2ae2573a4a01bf8d2696b009a0d99ab2845fbe7e75c44d1',
    'native-gs-index-consumer-v1.json': '41c2c974775039a20ceca0574c9eaf76db71d619bcff860f42b3a9cba09abb3e',
    'native-gs-index-default-step-v1.json': '553b1c1e6c6c508d63a6385ac5b68e453a92d3ab8dc61f99e16d70ab13b9b1c9',
    'native-task-montage-uht-fields-v1.json': '552757cb15721ed6c0d74abc236dd5d3e536fa0935364f1569baad7e22481cdd',
    'native-task-attach-uht-fields-v1.json': '4840c60d2fb468e970af88aa2857f80c12dda2f316777aaab0b5d48979424c34',
    'native-task-buff-uht-fields-v1.json': 'a865a263e2554b6a93273f4b29a905c024022bbc6854c8774c120f24d22d29ee',
    'native-extra-task-collect-vtables-v1.json': '20c1b391a823e9a8cf6085937451b4272953481cb79364b68e325ff8824e8d3c',
}
EXTERNAL_PINS = {
    'work/evidence/skill-template-coverage-20261020-v2/configured-program-catalog-v3.json':
        '304a6ab4e30c80ebec4bbc61f7a0b8c9ee4d489fd046b433b12671069cee7dcd',
    'work/evidence/skill-template-coverage-20261020-v2/new-factory-class-contracts.json':
        '1562b12d473a23d2f6c107d98c8a81435603a669ae0120e08f29def561d89913',
    'work/evidence/skill-template-coverage-20261020-v2/native-node-name-prefix.json':
        'df5c1d047b8bc4fb0278d733a82e2af37670163d2ffdccd5601819e40226b414',
    'work/evidence/skill-template-coverage-20261020-v2/additional-new-factory-class-contracts.json':
        '590741b5cf33c2106f1d1fe504ec5e437166f94c5cc54f2fb8ad11b4a07d7b16',
    'work/evidence/skill-template-coverage-20261020-v2/additional-task-kind-leaf.json':
        '6005c721253c4d8007f3f96cb80e1adb63097cc4762b065a20cd188df3debe31',
    'work/evidence/skill-template-coverage-20261020-v2/native-inherited-empty-listener-contract-v2.json':
        'e03835fb43ba15c890bdbfa74a2e2f51bde542625a6a1150adc783d224dde16e',
    'work/evidence/model-init-chain-20261018/native-current-skill-data-register-and-gs-local-init-v1.json':
        '4cb7360c38c538790bf1af1b3902fd759d48a1f2cc9383a65eaa38930087d954',
    'work/evidence/skill-flow-research-20261020-v1/native-template-blueprint-collect-completion.json':
        '9836f8d38c3e58d4b1cd8832d9da49173ed334af3bf2a359941f97a2532b206f',
    'work/evidence/skill-template-materialization-20261020-v1/native-task-creation-and-listener-registration.json':
        '431dcb0135a812d88aadd179141163f658dc555431b86bd7d3143768d8b67c87',
    'work/evidence/skill-template-replication-20261020-v1/index-seed-immutable-literals-v2.json':
        'b05e9a4341db023be325c8120f3c630aee45a56fcf52c3ef6e1ca486d6c2d496',
}


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def _digest(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _load(relative, expected):
    path = (ROOT / relative).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError('Repository source required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Pinned template authority source changed: ' + relative)
    return json.loads(raw)


def _kind(node):
    return node.get('operation') or node.get('$type', '').split(',')[0].split('.')[-1]


def _field(node):
    return tuple(node['Variable']['New']['Path'])


def _walk(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


@dataclass(frozen=True)
class TaskDefinition:
    factory_name: str
    native_class: str
    collection_kind: int
    required_struct: str | None
    notify_events: tuple
    source_argument_counts: tuple


@dataclass(frozen=True)
class StructRegistration:
    name: str
    native_bytes: int
    static_getter_rva: str
    registration_call_rva: str
    source_sha256: str


@dataclass(frozen=True)
class TaskRegistry:
    definitions: tuple
    structs: frozenset

    def without_struct(self, name):
        return replace(self, structs=frozenset(s for s in self.structs if s.name != name))

    def without_factory(self, name):
        return replace(self, definitions=tuple(d for d in self.definitions if d.factory_name != name))

    def definition(self, name):
        matches = [d for d in self.definitions if d.factory_name == name]
        if len(matches) != 1:
            raise ValueError('Missing or ambiguous local task factory registration: ' + name)
        return matches[0]

    def struct(self, name):
        matches = [s for s in self.structs if s.name == name]
        if len(matches) != 1:
            raise ValueError('Missing local task struct registration: ' + name)
        return matches[0]


@lru_cache(maxsize=1)
def _sources():
    evidence = {name: _load(BASE + name, sha) for name, sha in PINS.items()}
    for path, sha in EXTERNAL_PINS.items():
        _load(path, sha)
    source = _load('work/evidence/skill-template-coverage-20261020-v2/configured-program-catalog-v3.json',
                   EXTERNAL_PINS['work/evidence/skill-template-coverage-20261020-v2/configured-program-catalog-v3.json'])
    if source['all_functions_roundtrip_and_icode_matched'] is not True:
        raise ValueError('Roundtrip-qualified authored programs are required')
    packages = {}
    for package in source['packages']:
        metadata = _load(package['metadata_path'], package['metadata_sha256'])
        grammar = metadata.get('fname_number_grammar')
        if grammar:
            raw = (ROOT / grammar['parser_source']).read_bytes()
            if hashlib.sha256(raw).hexdigest() != grammar['source_sha256']:
                raise ValueError('The primary FName grammar source changed')
        bytecode = _load(package['bytecode_path'], package['bytecode_sha256'])
        for row in package['source_files']:
            raw = (ROOT / row['relative_path']).read_bytes()
            if hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise ValueError('Configured cooked package changed')
        packages[package['class_path']] = (package, metadata, bytecode)
    return evidence, packages


def _all_instructions(document):
    return {i['rva']: i for f in document['functions'] for i in f['instructions']}


@lru_cache(maxsize=1)
def source_task_registry():
    evidence, packages = _sources()
    native = evidence['native-derived-task-collect-vtables-v1.json']
    leaves = _all_instructions(evidence['native-derived-task-collection-methods-v1.json'])
    extra_leaf = 'work/evidence/skill-template-coverage-20261020-v2/additional-task-kind-leaf.json'
    leaves.update(_all_instructions(_load(extra_leaf, EXTERNAL_PINS[extra_leaf])))
    leaf_values = {'0xd5f3a0': 0, '0xd5c5d0': 1}
    for rva in ('0x13b48c0', '0x13b4940', '0x13b4900', '0x218a040', '0x80ea340'):
        instruction = leaves[rva]
        if instruction['mnemonic'] != 'mov' or not instruction['operands'].startswith('al, '):
            raise ValueError('Task kind leaf changed')
        leaf_values[rva] = int(instruction['operands'].split(', ')[1], 0)
    registrations = []
    registration_source = evidence['native-task-collect-notify-and-ready-v1.json']
    for function in registration_source['functions']:
        if function['span_start'] not in ('0x806d810', '0x80994c0', '0x806d9f0'):
            continue
        instructions = function['instructions']
        name = next(r['immutable_literal_candidate'] for i in instructions
                    for r in i.get('rip_references', []) if i['operands'].startswith('r8, [rip'))
        amount = next(int(i['operands'].split(', ')[1], 0) for i in instructions
                      if i['mnemonic'] == 'mov' and i['operands'].startswith('r9d, '))
        call = next(i['rva'] for i in instructions if i.get('direct_target_rva') == '0x10ead830')
        registrations.append(StructRegistration(name, amount, function['span_start'], call,
                                                PINS['native-task-collect-notify-and-ready-v1.json']))
    structs = frozenset(registrations)
    if len(structs) != 3:
        raise ValueError('The actual native struct registrations changed')
    ready_by_method = {'0xd5c5d0': None, '0x7c669a0': 'AbilityBlackBorad_AttachMesh',
                       '0x7d201f0': 'AbilityMontageSystemData',
                       '0x7d20250': 'AbilityBlackBorad_SpawnActor'}
    # Interface offsets are checked against immutable UHT fields, not inferred
    # from the Blueprint delegate names or a truthy task-kind value.
    notify_by_class = {}
    for label, name, offsets in (
        ('attach', 'QA_AbilityAttachMeshAnim', (0x328,)),
        ('buff', 'QA_AbilityBuff', (0x238, 0x248, 0x258)),
        ('montage', 'QA_AbilityPlayMontage', (0x288, 0x238, 0x248, 0x258, 0x268, 0x278)),
    ):
        cls, = evidence['native-task-' + label + '-uht-fields-v1.json']['declarations']
        fields = {int(p['native_member_offset'], 16): p['name'] for p in cls['selected_fields']
                  if p.get('native_member_offset') not in (None, '0x0', '0x1')}
        notify_by_class[name] = tuple(fields[o] for o in offsets)
    definitions = []
    factory_counts = {}
    for package, _, _ in packages.values():
        for call in package['task_constructor_calls']:
            name = call['constructor'].rsplit('.', 1)[-1]
            factory_counts.setdefault(name, set()).add(len(call['source_parameters']))
    classes = {row['name']: row for row in native['rows']}
    classes.update({row['name']: row for row in evidence['native-extra-task-collect-vtables-v1.json']['rows']})
    extra_path = 'work/evidence/skill-template-coverage-20261020-v2/new-factory-class-contracts.json'
    extra = _load(extra_path, EXTERNAL_PINS[extra_path])
    additional_path = 'work/evidence/skill-template-coverage-20261020-v2/additional-new-factory-class-contracts.json'
    additional = _load(additional_path, EXTERNAL_PINS[additional_path])
    extra['native_classes'].extend(additional['native_classes'])
    extra['factories'].extend(additional['factories'])
    classes.update({row['name']: row for row in extra['native_classes']})
    extra_factories = {row['factory_name']: row['matches'] for row in extra['factories']}
    for name, counts in sorted(factory_counts.items()):
        native_name = ('QA_AbilityBehaviorCall' if name in ('QA_AbilityListnerState', 'QA_AbilityBehaviorListner')
                       else 'QA_AbilityPlayMontage' if name == 'QA_AbilityPlayMontageWithAnimSet'
                       else name)
        if name == 'QA_EndAbility':
            native_name = 'QA_AbilityEnd'
        if name in extra_factories:
            matches = extra_factories[name]
            if len(matches) != 1:
                raise ValueError('A source-qualified unique native factory/class binding is required: ' + name)
            native_name = matches[0]['name']
        row = classes[native_name]
        kind_value = leaf_values[row['slots']['0x2f0']]
        required = ready_by_method[row['slots']['0x2a8']]
        definitions.append(TaskDefinition(name, native_name, kind_value, required,
                                           notify_by_class.get(native_name, ()), tuple(sorted(counts))))
    return TaskRegistry(tuple(definitions), structs)


@dataclass(frozen=True)
class FrozenTask:
    local_key: str
    task_index: int
    factory_name: str
    authored_name: str
    collection_kind: int
    source_function: str
    source_memory_offset: int
    source_uexp: int
    parameters_json: str
    applied_overrides_json: str
    callback_bindings: tuple
    emitted_events: tuple
    dependencies: tuple
    registered_data_json: str


@dataclass(frozen=True)
class FrozenTemplate:
    skill_id: int
    template_class: str
    tasks: tuple
    executed_entries: tuple
    collection_passes: int
    pending_tasks: tuple
    graph_edges: tuple
    common_configuration_json: str
    program_sha256: str


@dataclass(frozen=True)
class AuthorityTemplateState:
    plan: object
    templates: tuple
    deferred_source_rows: tuple
    admission_sha256: str
    binding_sha256: str
    graph_sha256: str
    session_sha256: str
    native_gameplay_verified: bool = False


@dataclass(frozen=True)
class TemplateSupport:
    hero_id: int
    configured_classes: tuple
    unsupported_classes: tuple

    @property
    def supported(self):
        """Executor capability only; this is not native gameplay readiness."""
        return bool(self.configured_classes) and not self.unsupported_classes


class UnsupportedTemplateSource(ValueError):
    def __init__(self, class_paths):
        self.class_paths = tuple(class_paths)
        super().__init__('Configured template authored source is unavailable: ' + ', '.join(self.class_paths))


@dataclass(frozen=True)
class LocalRequestIndex:
    raw_index: int
    encoded_index: int


def encode_request_index(raw_index):
    """The kind-one 0x7ee0e20 / GetSkillIDUniNum byte transform."""
    if type(raw_index) is not int or not 0 <= raw_index < 1 << 63:
        raise ValueError('A nonnegative signed-int64 local request index is required')
    b = raw_index.to_bytes(8, 'little')
    encoded = bytes(((b[0]+b[1])&255, (b[1]+b[2])&255, (b[2]+b[0])&255,
                     (2*b[3])&255, (b[4]+b[5])&255, (b[5]+b[7])&255,
                     (2*b[6])&255, (b[7]+b[4])&255))
    return int.from_bytes(encoded, 'little')


class _Task:
    def __init__(self, key, definition, name, args, source, overrides):
        self.key, self.definition, self.name = key, definition, name
        self.args, self.source, self.overrides = args, source, overrides
        self.callbacks, self.events, self.dependencies = {}, [], set()
        self.activations = 0


def _stable(value):
    if isinstance(value, _Task):
        return {'task': value.key}
    if isinstance(value, dict):
        return {key: _stable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_stable(item) for item in value]
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise ValueError('Unresolved local task argument')


class _Collector:
    def __init__(self, row, registry):
        self.row, self.registry = row, registry
        class_path = row['configured_template_class']
        try:
            self.package, self.metadata, self.bytecode = _sources()[1][class_path]
        except KeyError as exc:
            raise ValueError('Configured template authored program is unavailable') from exc
        exports = self.metadata['exports']
        self.refs = {r['index']: r for r in self.metadata['imports'] + exports}
        self.functions = {f['name']: f for f in self.bytecode['functions']}
        self.values, self.tasks, self.pending = {}, {}, deque()
        self.entries, self.edges, self.steps = [], set(), 0
        self.current_task, self.location = None, None
        self.common, self.cdo = {}, {}
        raw = (ROOT / next(r['relative_path'] for r in self.package['source_files']
                           if r['relative_path'].endswith('.uexp'))).read_bytes()
        names = self.metadata['names']
        for prop in self.package['actual_cdo_properties']:
            value = raw[prop['value_start']:prop['end']]
            if len(value) != prop['size']:
                raise ValueError('CDO source range is incomplete')
            name = prop['name']
            if prop['kind'] == 'IntProperty':
                decoded = struct.unpack('<i', value)[0]
            elif prop['kind'] == 'MapProperty' and prop['meta'] == ['NameProperty', 'EnumProperty']:
                removed, count = struct.unpack_from('<ii', value)
                if removed or len(value) != 8 + count * 16:
                    raise ValueError('Unsupported authored template enum-map source')
                decoded = {self._fname(value, 8 + n*16, names): self._fname(value, 16 + n*16, names)
                           for n in range(count)}
            elif prop['kind'] == 'ArrayProperty' and prop['meta'] == ['NameProperty']:
                count, = struct.unpack_from('<i', value)
                if len(value) != 4 + count*8:
                    raise ValueError('Unsupported authored template name-array source')
                decoded = [self._fname(value, 4 + n*8, names) for n in range(count)]
            else:
                decoded = dict(kind=prop['kind'], struct=prop['meta'][0] if prop['meta'] else None,
                               serialized_value_hex=value.hex(), source_uexp=prop['value_start'],
                               source_sha256=hashlib.sha256(value).hexdigest())
            self.cdo[(name,)] = decoded
            if name in ('LogicFlags', 'LogicExcuteType', 'OverrideParams'):
                self.common[name] = decoded

    @staticmethod
    def _fname(raw, offset, names):
        index, number = struct.unpack_from('<ii', raw, offset)
        if not 0 <= index < len(names) or number < 0:
            raise ValueError('Invalid source FName')
        return names[index] + ('_' + str(number-1) if number else '')

    def ref(self, index, depth=0):
        if not index:
            return None
        if depth > 64:
            raise ValueError('Source reference bound exceeded')
        row = self.refs[index]
        outer = self.ref(row['outer_index'], depth + 1)
        return (outer + '.' if outer else '') + row['name']

    def create(self, factory_name, args):
        definition = self.registry.definition(factory_name)
        if len(args) not in definition.source_argument_counts or args[0] != {'self': True}:
            raise ValueError('Typed task factory arguments do not match the authored constructor')
        registration = self.registry.struct(definition.required_struct) if definition.required_struct else None
        name = args[1]
        if type(name) is not str:
            raise ValueError('An actual authored task name is required')
        function, offset, uexp = self.location
        # 0x7ec8507 uses allTasks.count; 0x7ec856c accepts an explicit key
        # only for an input name beginning with ':'. Authored display/state
        # names may repeat without denoting the same task object.
        key = name if name.startswith(':') else ':' + str(len(self.tasks))
        overrides = {k: v[name] for k, v in self.common.items() if type(v) is dict and name in v}
        if key not in self.tasks:
            self.tasks[key] = _Task(key, definition, name, _stable(args), self.location, overrides)
            self.tasks[key].registered_data = dict(schema=asdict(registration),
                                                   constructor_arguments=_stable(args)) if registration else None
            self.pending.append(key)
        task = self.tasks[key]
        if task.definition != definition:
            raise ValueError('Conflicting authored task class for an explicit task key')
        # A real QA factory copies its typed arguments after central lookup,
        # including when an explicitly named task object was reused.
        task.args = _stable(args)
        if task.registered_data is not None:
            task.registered_data['constructor_arguments'] = task.args
        if self.current_task is not None:
            self.edges.add((self.current_task.key, key))
        return task

    def evaluate(self, node, context=None):
        op = _kind(node)
        if op == 'EX_Self':
            return {'self': True}
        if op in ('EX_True', 'EX_False'):
            return op == 'EX_True'
        if op in ('EX_Nothing', 'EX_NoObject', 'EX_NoInterface'):
            return None
        if op.endswith('Const') and 'Value' in node:
            if op == 'EX_ObjectConst':
                return {'object': self.ref(node['Value'])}
            return node['Value']
        if op == 'EX_LocalVariable':
            return self.values.get(_field(node), 0)
        if op == 'EX_InstanceVariable':
            field = _field(node)
            if isinstance(context, _Task):
                return context, field[0]
            if field not in self.cdo:
                raise ValueError('Missing authored CDO parameter: ' + '.'.join(field))
            return self.cdo[field]
        if op in ('EX_LetObj', 'EX_LetBool', 'EX_Let'):
            value = self.evaluate(node['Expression'] if op == 'EX_Let' else node['AssignmentExpression'], context)
            variable = node['Variable'] if op == 'EX_Let' else node['VariableExpression']
            if _kind(variable) == 'EX_LocalVariable':
                self.values[_field(variable)] = value
            elif _kind(variable) == 'EX_StructMemberContext':
                source = variable['StructExpression']
                if _kind(source) != 'EX_LocalVariable':
                    raise ValueError('Unsupported collection struct assignment target')
                pointer = variable['StructMemberExpression']['New']
                member = '.'.join(pointer['Path'])
                key = _field(source)
                existing = self.values.get(key)
                if existing is None:
                    existing = dict(struct=self.ref(pointer['ResolvedOwner']), members={})
                if type(existing) is not dict:
                    raise ValueError('A typed authored struct local is required')
                existing.setdefault('members', {})[member] = value
                self.values[key] = existing
            else:
                raise ValueError('Unsupported collection assignment target')
            return value
        if op == 'EX_StructMemberContext':
            source = self.evaluate(node['StructExpression'], context)
            member = '.'.join(node['StructMemberExpression']['New']['Path'])
            if type(source) is not dict or member not in source.get('members', {}):
                raise ValueError('An authored struct member requires its actual initialized value')
            return source['members'][member]
        if op == 'EX_LetValueOnPersistentFrame':
            value = self.evaluate(node['AssignmentExpression'], context)
            self.values[tuple(node['DestinationProperty']['New']['Path'])] = value
            return value
        if op == 'EX_BindDelegate':
            name = node['FunctionName']
            if name not in self.functions or self.evaluate(node['ObjectTerm']) != {'self': True}:
                raise ValueError('Missing authored callback function')
            self.values[_field(node['Delegate'])] = name
            return None
        if op == 'EX_AddMulticastDelegate':
            task, event = self.evaluate(node['Delegate'])
            callback = self.evaluate(node['DelegateToAdd'])
            if not isinstance(task, _Task) or callback not in self.functions:
                raise ValueError('Invalid authored callback dependency')
            callbacks = task.callbacks.setdefault(event, [])
            if callback not in callbacks:
                callbacks.append(callback)
            return None
        if op == 'EX_Context':
            owner = self.evaluate(node['ObjectExpression'], context)
            if owner is None:
                raise ValueError('Unresolved authored collection context')
            return self.evaluate(node['ContextExpression'], owner)
        if op == 'EX_StructConst':
            return dict(struct=self.ref(node['Struct']), values=[self.evaluate(x, context)
                        for x in node['Value']])
        if op == 'EX_MapConst':
            return {'map': [self.evaluate(x, context) for x in node['Elements']]}
        if op in ('EX_SetMap', 'EX_SetArray'):
            variable = node['MapProperty'] if op == 'EX_SetMap' else node['AssigningProperty']
            if _kind(variable) != 'EX_LocalVariable':
                raise ValueError('Unsupported authored collection container target')
            items = [self.evaluate(x, context) for x in node['Elements']]
            if op == 'EX_SetMap' and len(items) % 2:
                raise ValueError('An authored map requires key/value pairs')
            value = {'map' if op == 'EX_SetMap' else 'array': items}
            self.values[_field(variable)] = value
            return value
        if op in ('EX_CallMath', 'EX_FinalFunction', 'EX_LocalFinalFunction'):
            name = self.refs[node['StackNode']]['name']
            args = [self.evaluate(x, context) for x in node.get('Parameters', [])]
            if name.startswith('QA_'):
                return self.create(name, args)
            if name in self.functions:
                return self.execute(name, args[0] if args else 0)
            if name == 'IsValid':
                return isinstance(args[0], _Task) or args[0] == {'self': True}
            if name in ('EqualEqual_IntInt', 'EqualEqual_ByteByte'):
                return args[0] == args[1]
            if name in ('MakeLiteralText', 'Conv_TextToString', 'Conv_StringToName'):
                return args[0]
            raise ValueError('Unsupported authored collection native call: ' + name)
        if op in ('EX_VirtualFunction', 'EX_LocalVirtualFunction'):
            name = node['VirtualFunctionName']
            if isinstance(context, _Task) and name == 'Activate':
                context.activations += 1
                return None
            if name in self.functions:
                return self.execute(name)
            raise ValueError('Unsupported authored collection virtual call: ' + name)
        if op == 'EX_TextConst':
            return {'text': _stable(node)}
        if op == 'EX_VectorConst':
            return {'vector': _stable(node['Value'])}
        raise ValueError('Unsupported authored collection expression: ' + op)

    def execute(self, name, entry=0):
        if name not in self.functions:
            raise ValueError('Missing authored collection entry: ' + name)
        self.entries.append(name)
        function = self.functions[name]
        instructions = function['bytecode']
        offsets = {i['memory_offset']: n for n, i in enumerate(instructions)}
        source = function['source_bytecode_matching_offsets'][0]
        if not function['parsed'] or function['script_memory_bytes'] != function['calculated_memory_bytes']:
            raise ValueError('Authored function parse qualification changed')
        old_location, stack, pc = self.location, [], 0
        try:
            while pc < len(instructions):
                self.steps += 1
                if self.steps > 100000:
                    raise ValueError('Authored collection instruction bound exceeded')
                instruction = instructions[pc]
                self.location = name, instruction['memory_offset'], source + instruction['serialized_relative_offset']
                node, next_pc = instruction['expression'], pc + 1
                op = _kind(node)
                if op == 'EX_ComputedJump':
                    target = entry
                elif op == 'EX_Jump':
                    target = node['CodeOffset']
                elif op == 'EX_JumpIfNot':
                    target = node['CodeOffset'] if not self.evaluate(node['BooleanExpression']) else None
                elif op == 'EX_PushExecutionFlow':
                    stack.append(node['PushingAddress'])
                    target = None
                elif op in ('EX_PopExecutionFlow', 'EX_PopExecutionFlowIfNot'):
                    pop = op == 'EX_PopExecutionFlow' or not self.evaluate(node['BooleanExpression'])
                    if pop and not stack:
                        return None
                    target = stack.pop() if pop else None
                elif op in ('EX_Return', 'EX_EndOfScript'):
                    return None
                else:
                    self.evaluate(node)
                    target = None
                if target is not None:
                    if type(target) is not int or target not in offsets:
                        raise ValueError('Authored collection jump is not an instruction boundary')
                    next_pc = offsets[target]
                pc = next_pc
        finally:
            self.location = old_location

    def emit(self, task, event):
        task.events.append(event)
        for callback in tuple(task.callbacks.get(event, ())):
            self.execute(callback)

    def run(self):
        if 'LogicFlow_Listener' in self.functions:
            self.execute('LogicFlow_Listener')
        else:
            path = 'work/evidence/skill-template-coverage-20261020-v2/native-inherited-empty-listener-contract-v2.json'
            inherited = _load(path, EXTERNAL_PINS[path])
            base = _sources()[1].get(inherited['base_class'])
            base_functions = {f['name'] for f in base[2]['functions']} if base else set()
            if (inherited['event_name'] != 'LogicFlow_Listener' or
                    inherited['function_flags'] & 0x400 or not inherited['function_flags'] & 0x8000000 or
                    inherited['parameter_count'] != 0 or inherited['native_parameter_bytes'] != 0 or
                    self.package['parent_class'] != inherited['base_class'] or
                    not base or 'LogicFlow_Listener' in base_functions):
                raise ValueError('Missing authored collection entry without a qualified empty inherited event')
            self.entries.append('LogicFlow_Listener')
        passes = 0
        while self.pending:
            passes += 1
            if passes > 256 or len(self.tasks) > 4096:
                raise ValueError('Authored collection queue bound exceeded')
            batch = tuple(self.pending)
            self.pending.clear()
            for key in batch:
                task = self.tasks[key]
                self.current_task = task
                if task.definition.collection_kind == 1:
                    state_name = 'LogicState_' + task.name
                    if state_name in self.functions:
                        self.execute(state_name)
                    self.emit(task, 'OnThen')
                    self.emit(task, 'OnTrigger')
                else:
                    for event in ('OnThen', 'OnTrigger', 'OnUnTrigger') + task.definition.notify_events:
                        self.emit(task, event)
                self.current_task = None
        frozen = []
        for task_index, task in enumerate(self.tasks.values()):
            if not task.activations:
                raise ValueError('Task collection requires its authored Activate call')
            definition = task.definition
            dependencies = (definition.required_struct,) if definition.required_struct else ()
            for name in dependencies:
                if asdict(self.registry.struct(name)) != task.registered_data['schema']:
                    raise ValueError('Task struct registration did not survive collection')
            frozen.append(FrozenTask(task.key, task_index, definition.factory_name, task.name,
                                     definition.collection_kind, *task.source,
                                     _json(task.args), _json(task.overrides),
                                     tuple((event, callback) for event, callbacks in task.callbacks.items()
                                           for callback in callbacks), tuple(task.events), dependencies,
                                     _json(task.registered_data)))
        return FrozenTemplate(self.row['skill_id'], self.row['configured_template_class'], tuple(frozen),
                              tuple(dict.fromkeys(self.entries)), passes, tuple(self.pending),
                              tuple(sorted(self.edges)), _json(self.common), self.package['bytecode_sha256'])


def template_support_for_hero(hero_id):
    """Preflight the optional repair without allocating IDs or writing state.

    Callers can keep an unsupported hero on their existing departure path and
    report the explicit capability result instead of publishing empty readiness.
    """
    from skill_initial_state_values import schema_binding, select_source_plan
    rows = select_source_plan(schema_binding(), hero_id)['source_row_plan']
    required = [r for r in rows if r['configured_instance_class'] not in (None, 'None') and
                r['configured_template_class'] not in (None, 'None')]
    packages = _sources()[1]
    registry = source_task_registry()
    unsupported = []
    for row in required:
        path = row['configured_template_class']
        if path not in packages:
            unsupported.append((path, 'Exact configured cooked package was not recovered from verified installed PAK indices'))
            continue
        try:
            _Collector(row, registry).run()
        except (ValueError, KeyError) as exc:
            unsupported.append((path, 'Authored collector dependency: ' + str(exc)))
    return TemplateSupport(hero_id, tuple(r['configured_template_class'] for r in required), tuple(unsupported))


def collect_template_for_source_row(row):
    """Execute one real configured source row, including non-instance templates."""
    from skill_initial_state_values import schema_binding
    rows = [r for plan in schema_binding()['hero_plans'].values() for r in plan['source_row_plan']]
    if type(row) is not dict or row not in rows or row['configured_template_class'] in (None, 'None'):
        raise ValueError('An exact configured template source row is required')
    if row['configured_template_class'] not in _sources()[1]:
        raise UnsupportedTemplateSource((row['configured_template_class'],))
    return _Collector(row, source_task_registry()).run()


def _binding(ticket, grant):
    from dfserver.legacy_ds_match_admission import LocalMatchTicket
    from skill_initial_state_values import _validate_grant, schema_binding
    if (type(ticket) is not LocalMatchTicket or type(ticket.cookie) is not str or
            not 0 < len(ticket.cookie) <= 256 or type(ticket.loadout_snapshot) is not bytes or
            not 0 < len(ticket.loadout_snapshot) <= 1024*1024):
        raise ValueError('Actual frozen admission is required')
    if ticket.room_seed is not None and (type(ticket.room_seed) is not int or
                                        not 0 <= ticket.room_seed < 1 << 63):
        raise ValueError('An unsigned bounded authority room seed is required')
    _validate_grant(schema_binding(), grant)
    snapshot = json.loads(ticket.loadout_snapshot)
    if (str(ticket.room_id) != grant.room_id or ticket.player_id != grant.participant_uid or
            ticket.selected_hero_id != grant.hero_id or
            snapshot.get('selected_hero_id') != ticket.selected_hero_id or
            snapshot.get('selected_fashion_id') != ticket.selected_fashion_id):
        raise ValueError('The frozen admission and skill grant must match')
    identity = ({'room_seed': ticket.room_seed} if ticket.room_seed is not None else
                {'cookie_sha256': hashlib.sha256(ticket.cookie.encode()).hexdigest()})
    session = _digest(dict(room_id=str(ticket.room_id), identity=identity))
    return dict(room_id=ticket.room_id, room_seed=ticket.room_seed, session_sha256=session,
                player_id=ticket.player_id, map_id=ticket.map_id,
                match_mode_id=ticket.match_mode_id, grant=asdict(grant),
                loadout_sha256=hashlib.sha256(ticket.loadout_snapshot).hexdigest(),
                sources=dict(evidence=PINS, dependencies=EXTERNAL_PINS),
                local_policy='authored-collector-v4;session-room-seed-v2;secrets-randbelow-native-seed-ranges-v1')


def _restore_template(value):
    value = dict(value)
    value['tasks'] = tuple(FrozenTask(**dict(t, callback_bindings=tuple(tuple(x) for x in t['callback_bindings']),
                                            emitted_events=tuple(t['emitted_events']),
                                            dependencies=tuple(t['dependencies']))) for t in value['tasks'])
    for key in ('executed_entries', 'pending_tasks'):
        value[key] = tuple(value[key])
    value['graph_edges'] = tuple(tuple(x) for x in value['graph_edges'])
    return FrozenTemplate(**value)


class SkillTemplateAuthorityStore:
    def __init__(self, path):
        self.path = Path(path)

    def reserve_request_index(self, state):
        """Reserve service-owned request identities, separate from entity IDs.

        Native ctor 0x7eb4965 sets the step to three. 0x7ee0dba advances
        the local cache; 0x7ee0e95 rejects stale raw request IDs on authority.
        The initial replicated seeds stay immutable while this cache advances.
        """
        if type(state) is not AuthorityTemplateState or not self.path.is_file():
            raise ValueError('A committed admission-bound template authority state is required')
        _sources()
        with closing(sqlite3.connect(self.path, timeout=30)) as db, db:
            db.execute('pragma foreign_keys=on')
            db.execute('begin immediate')
            row = db.execute('select a.binding_digest,a.graph_digest,r.ram,r.ram2,a.binding_json from admissions_v2 a '
                             'join rooms_v2 r on a.session_digest=r.session_digest '
                             'where a.admission_digest=? and a.session_digest=? and r.room_id=?',
                             (state.admission_sha256, state.session_sha256, state.plan.grant.room_id)).fetchone()
            if (row is None or row[:4] != (state.binding_sha256, state.graph_sha256,
                                       state.plan.ability_index_ram, state.plan.ability_index_ram2)
                    or state.graph_sha256 != _digest([asdict(g) for g in state.templates])):
                raise ValueError('The persisted admission or graph binding changed')
            binding = json.loads(row[4])
            if (_digest(binding) != state.binding_sha256 or
                    binding['session_sha256'] != state.session_sha256 or
                    binding['grant'] != json.loads(_json(asdict(state.plan.grant)))):
                raise ValueError('The request grant differs from its persisted admission binding')
            db.execute('create table if not exists request_indices_v2(session_digest text primary key '
                       'references rooms_v2(session_digest), raw_index integer not null)')
            previous = db.execute('select raw_index from request_indices_v2 where session_digest=?',
                                  (state.session_sha256,)).fetchone()
            raw_index = (previous[0] if previous else row[2]) + 3
            encoded = encode_request_index(raw_index)
            db.execute('insert into request_indices_v2 values(?,?) on conflict(session_digest) '
                       'do update set raw_index=excluded.raw_index', (state.session_sha256, raw_index))
        return LocalRequestIndex(raw_index, encoded)

    def materialize(self, *, ticket, grant, task_registry=None):
        from skill_initial_state_values import schema_binding, select_source_plan
        binding = _binding(ticket, grant)
        session = binding['session_sha256']
        admission = hashlib.sha256(ticket.cookie.encode()).hexdigest()
        binding_sha = _digest(binding)
        registry = source_task_registry() if task_registry is None else task_registry
        qualified = source_task_registry()
        if (type(registry) is not TaskRegistry or not set(registry.definitions) <= set(qualified.definitions)
                or not registry.structs <= qualified.structs):
            raise ValueError('Source-qualified local task registrations are required')
        rows = select_source_plan(schema_binding(), grant.hero_id)['source_row_plan']
        configured = [r for r in rows if r['configured_instance_class'] not in (None, 'None') and
                      r['configured_template_class'] not in (None, 'None')]
        if not configured:
            raise ValueError('No authored configured instances exist in this grant')
        missing = tuple(r['configured_template_class'] for r in configured
                        if r['configured_template_class'] not in _sources()[1])
        if missing:
            raise UnsupportedTemplateSource(missing)
        deferred = tuple((r['skill_id'], 'no configured instance class') for r in rows if r not in configured)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=30)) as db, db:
            db.execute('pragma foreign_keys=on')
            # Legacy records have no qualified session seed. Keep them intact;
            # only versioned session-bound records can authorize publication.
            db.execute('create table if not exists rooms_v2(session_digest text primary key, room_id text not null, '
                       'map_id integer not null, mode_id integer not null, source_digest text not null, '
                       'ram integer not null, ram2 integer not null)')
            db.execute('create table if not exists admissions_v2(admission_digest text primary key, binding_digest text not null, '
                       'session_digest text not null references rooms_v2(session_digest), graph_digest text not null, graph_json text not null, '
                       'binding_json text not null)')
            db.execute('begin immediate')
            previous = db.execute('select binding_digest,graph_digest,graph_json,binding_json from admissions_v2 where admission_digest=?',
                                  (admission,)).fetchone()
            room = db.execute('select map_id,mode_id,source_digest,ram,ram2 from rooms_v2 where session_digest=? and room_id=?',
                              (session, str(ticket.room_id))).fetchone()
            source_digest = _digest(dict(evidence=PINS, dependencies=EXTERNAL_PINS))
            if room and room[:3] != (ticket.map_id, ticket.match_mode_id, source_digest):
                raise ValueError('Room source or admission configuration changed')
            if previous:
                if previous[0] != binding_sha:
                    raise ValueError('The admission has a conflicting frozen template binding')
                if previous[3] != _json(binding):
                    raise ValueError('The persisted admission binding changed')
                document = json.loads(previous[2])
                if _digest(document) != previous[1] or type(document) is not list:
                    raise ValueError('The persisted task graph digest changed')
                templates = tuple(_restore_template(g) for g in document)
                # Re-execution validates callback closure and typed data against
                # current qualified sources; a digest is not readiness proof.
                expected = tuple(_Collector(row, registry).run() for row in configured)
                if templates != expected:
                    raise ValueError('The persisted task graph is not the current authored execution')
            else:
                templates = tuple(_Collector(row, registry).run() for row in configured)
                document = [asdict(t) for t in templates]
                if room is None:
                    # The native producer clamps the seeds to these ranges.
                    # A local service chooses fresh seeds once per authority session.
                    ram, ram2 = secrets.randbelow(1001), secrets.randbelow(100001)
                    db.execute('insert into rooms_v2 values(?,?,?,?,?,?,?)',
                               (session, str(ticket.room_id), ticket.map_id, ticket.match_mode_id, source_digest, ram, ram2))
                    room = (ticket.map_id, ticket.match_mode_id, source_digest, ram, ram2)
                db.execute('insert into admissions_v2 values(?,?,?,?,?,?)',
                           (admission, binding_sha, session, _digest(document), _json(document), _json(binding)))
            plan = project_initial_plan(source_schema(), grant=grant,
                                        materialized_skill_ids=tuple(t.skill_id for t in templates),
                                        ability_index_ram=room[3], ability_index_ram2=room[4],
                                        existing_template_skill_ids=())
            graph_sha = _digest([asdict(t) for t in templates])
        # Leaving the connection context committed the graph and seeds first.
        return AuthorityTemplateState(plan, templates, deferred, admission, binding_sha, graph_sha, session)


def source_pins():
    """All fixed evidence and actual cooked programs used by this executor."""
    pins = {BASE + name: sha for name, sha in PINS.items()} | EXTERNAL_PINS
    _, packages = _sources()
    for package, _, _ in packages.values():
        pins[package['metadata_path']] = package['metadata_sha256']
        pins[package['bytecode_path']] = package['bytecode_sha256']
        for row in package['source_files']:
            pins[row['relative_path']] = row['sha256']
        metadata = _load(package['metadata_path'], package['metadata_sha256'])
        grammar = metadata.get('fname_number_grammar')
        if grammar:
            pins[grammar['parser_source']] = grammar['source_sha256']
    for name in ('skill_template_authority.py', 'skill_template_replication.py',
                 'skill_initial_state_values.py', 'portable_skill_entity_admission.py'):
        path = 'work/' + name
        pins[path] = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
    return pins
