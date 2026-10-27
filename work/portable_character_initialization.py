"""Committed local dedicated-server projection of native InitCharacter semantics.

This models typed admission relationships and empty event dispatch storage.
It invokes no native methods and establishes no complete gameplay readiness.
Transport ownership, current lease validation and delivery ACKs belong to the
admission adapter. A receipt is checked against its persisted canonical state.
"""
from contextlib import closing
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import sqlite3

from dfserver.legacy_ds_actor_manifest import ActorManifest, preflight_actor_manifest
from dfserver.legacy_ds_static_actor_manifest import StaticActorManifest
from dfserver.legacy_ds_control_connection import preflight_actor_content_plans
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_dynamic_object_creation import (
    DynamicObjectCreation, CLASS_PATH, SOURCE_SHA256, qualified_class_exports)
from dfserver.legacy_ds_ability_component_creation import (
    AbilityComponentCreation, CLASS_PATH as ABILITY_CLASS_PATH)
from dfserver.legacy_ds_match_admission import LocalMatchTicket
from portable_source_guard import cached_qualification


ROOT = Path(__file__).resolve().parent.parent
BASE = 'work/evidence/model-init-chain-20261018/'
SPEC = 'work/evidence/skill-flow-research-20261020-v1/native-character-authority-minimal-port-spec-subagent-v1.json'
CLIENT = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
COOKED = 'work/evidence/map-system-audit-20261018/native-owning-weapon-cooked-character-emptyhand-defaults.json'
KICKOFF = BASE + 'native-current-fsm-empty-kickoff-contract-v1.json'
FIXED_PINS = {
    SPEC: '09e8278dd43e4f4acfe3acc082dceb6524458ba1cf3adc4059d89cb0573c5b3b',
    COOKED: 'e935d6eab000430da6933ce6578e2fea6a40e9897849c14597c734bf742dc543',
    BASE + 'native-current-skill-main-fsm-cooked-contract-v1.json':
        'f9deebf95291c8c90b26b6d8f86e20c2dd02df6fc669383b23fec13da785a9ca',
    KICKOFF: 'e8ff3d1cee81134e7a498cf32ddbc121342f693e5b57cae43b3a99a2d9127617',
}
POLICY = 'local-dedicated-init-character-v1;typed-admission-context;native-empty-dispatch-map'
TABLE = '''create table if not exists character_initializations_v1 (
 admission_sha256 text primary key, binding_sha256 text not null,
 state_sha256 text not null, binding_json text not null, state_json text not null)'''


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _digest(value):
    return _sha(_json(value).encode())


def _read(relative, expected):
    if (type(relative) is not str or '\\' in relative or ':' in relative or
            PurePosixPath(relative).is_absolute() or
            any(p in ('', '.', '..') for p in relative.split('/'))):
        raise ValueError('A project-relative character initialization source is required')
    path = (ROOT / relative).resolve(strict=True)
    if not path.is_relative_to(ROOT.resolve()) or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError('Character initialization source escaped its bound')
    raw = path.read_bytes()
    if _sha(raw) != expected:
        raise ValueError('Changed character initialization source: ' + relative)
    return raw


@cached_qualification(ROOT)
def _source_schema():
    documents = {p: json.loads(_read(p, h)) for p, h in FIXED_PINS.items()}
    spec = documents[SPEC]
    if (spec['client_sha256'] != CLIENT or spec['process_access'] is not False or
            spec['InitCharacter_semantics']['event_map']['event_ids'] != {'first': 0, 'last': 163} or
            spec['InitCharacter_semantics']['ready_commit']['write_rva'] != '0x48a2920'):
        raise ValueError('The native InitCharacter port specification changed')
    pins = dict(FIXED_PINS, **spec['source_pins'])
    for path, expected in spec['source_pins'].items():
        _read(path, expected)
    package = documents[COOKED]['packages'][0]
    for source in package['source_files']:
        _read(source['relative_path'], source['sha256'])
        pins[source['relative_path']] = source['sha256']
    cdo, = [r for r in package['selected_defaults'] if r['export']['index'] == 47]
    board, = [r for r in package['exports'] if r['name'] == 'Blackboard']
    fsm, = [r for r in package['exports'] if r['name'] == 'GPFSMStateMachine']
    for field, export in (('Blackboard', board), ('FSMComponent', fsm)):
        prop, = [p for p in cdo['properties'] if p['name'] == field]
        if (prop['object_index'] != export['index'] or export['outer_index'] != 47 or
                export['template_path'] != '/Script/SOL.Default__SOLCharacter.' + export['name']):
            raise ValueError('The native Pawn default relationship changed: ' + field)
    authored = documents[BASE + 'native-current-skill-main-fsm-cooked-contract-v1.json']
    entry, = [e for e in authored['entries'] if e['export']['name'] == fsm['name']]
    klass, = [p for p in entry['properties'] if p['name'] == 'StateMachineClass']
    kickoff = documents[KICKOFF]
    if (klass['object_path'] != CLASS_PATH or
            kickoff['pawn_class_path'].rsplit('.', 1)[-1] != cdo['export']['class_path'] or
            kickoff['component']['class_path'] != fsm['class_path'] or
            kickoff['component']['name'] != fsm['name']):
        raise ValueError('The authored main FSM/default component class changed')
    for path in ('work/portable_character_initialization.py',
            'outputs/df-local-server/dfserver/legacy_ds_actor_manifest.py',
            'outputs/df-local-server/dfserver/legacy_ds_static_actor_manifest.py',
            'outputs/df-local-server/dfserver/legacy_ds_control_connection.py',
            'outputs/df-local-server/dfserver/legacy_ds_default_subobject.py',
            'outputs/df-local-server/dfserver/legacy_ds_dynamic_object_creation.py',
            'outputs/df-local-server/dfserver/legacy_ds_ability_component_creation.py',
            'outputs/df-local-server/dfserver/legacy_ds_match_admission.py'):
        pins[path] = _sha((ROOT / path).read_bytes())
    return dict(sources=pins, classes=dict(pawn_class=kickoff['pawn_class_path'],
        board_class=board['class_path'], board_name=board['name'],
        component_class=fsm['class_path'], component_name=fsm['name']))


def _sources():
    schema = _source_schema()
    return schema['sources'], schema['classes']


def source_pins():
    return _sources()[0]


@dataclass(frozen=True)
class CharacterObjectReference:
    outer_guid: int | None
    name: str | None
    class_path: str
    guid: int | None


@dataclass(frozen=True)
class CharacterEventEntry:
    event_id: int
    listeners: tuple = ()
    unbound_handle: int = -1


@dataclass(frozen=True)
class CharacterInitializationState:
    gp_actor: CharacterObjectReference
    gp_character: CharacterObjectReference
    gp_identity: CharacterObjectReference
    blackboard: CharacterObjectReference
    board_owner: CharacterObjectReference
    board_character: CharacterObjectReference
    board_fsm_component: CharacterObjectReference
    event_entries: tuple[CharacterEventEntry, ...]
    network_mode: int
    server_identity: bool
    network_initialized: bool
    standalone: bool
    autonomous: bool
    simulated: bool
    locally_controlled: bool
    gameplay_initialization_verified: bool = False


@dataclass(frozen=True)
class CharacterInitializationReceipt:
    store_path: str
    admission_sha256: str
    binding_sha256: str
    state_sha256: str
    pawn_guid: int
    component_guid: int
    instance_guid: int
    class_guid: int
    pawn_channel: int
    fsm_ready: bool
    state: CharacterInitializationState

    def validate_committed(self):
        return CharacterInitializationStore(self.store_path).validate_committed(self)

    def validate_binding(self, *, ticket, manifests, plans):
        return CharacterInitializationStore(self.store_path).validate_binding(
            self, ticket=ticket, manifests=manifests, plans=plans)


def _uint(value, maximum, label, minimum=1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('An actual bounded ' + label + ' is required')
    return value


def _ticket(ticket):
    if (type(ticket) is not LocalMatchTicket or type(ticket.cookie) is not str or
            re.fullmatch('[0-9a-f]{32}', ticket.cookie) is None or
            type(ticket.loadout_snapshot) is not bytes or
            not 0 < len(ticket.loadout_snapshot) <= 1024 * 1024):
        raise ValueError('An actual frozen local match ticket is required')
    for field in ('player_id', 'room_id', 'selected_hero_id', 'selected_fashion_id'):
        _uint(getattr(ticket, field), (1 << 64) - 1, field)
    for field in ('map_id', 'match_mode_id'):
        _uint(getattr(ticket, field), (1 << 32) - 1, field)
    _uint(ticket.room_seed, (1 << 63) - 1, 'authority room seed', 0)
    if (any(type(v) not in (int, float) or not math.isfinite(v)
            for v in (ticket.issued_at, ticket.expires_at)) or ticket.expires_at <= ticket.issued_at):
        raise ValueError('A bounded frozen admission lifetime is required')
    snapshot = json.loads(ticket.loadout_snapshot)
    if (type(snapshot) is not dict or snapshot.get('selected_hero_id') != ticket.selected_hero_id or
            snapshot.get('selected_fashion_id') != ticket.selected_fashion_id):
        raise ValueError('The frozen appearance differs from this ticket')
    return dict(admission_sha256=_sha(ticket.cookie.encode()), room_id=ticket.room_id,
        room_seed=ticket.room_seed, map_id=ticket.map_id, match_mode_id=ticket.match_mode_id,
        native_player_id=ticket.player_id, hero_id=ticket.selected_hero_id,
        fashion_id=ticket.selected_fashion_id, issued_at=ticket.issued_at,
        expires_at=ticket.expires_at, loadout_sha256=_sha(ticket.loadout_snapshot))


def _namespace(manifests, plans, classes):
    if (type(manifests) is not tuple or not 1 <= len(manifests) <= 128 or
            any(type(m) not in (ActorManifest, StaticActorManifest) for m in manifests) or
            type(plans) is not tuple or not plans):
        raise ValueError('Exact current Actor manifests and content plans are required')
    pawns = [m for m in manifests if type(m) is ActorManifest and m.class_path == classes['pawn_class']]
    if len(pawns) != 1:
        raise ValueError('One actual source-qualified current Pawn is required')
    pawn = pawns[0]
    fields, actors, assets, sources = [], [], {}, {}
    actor_guids = {m.actor_guid for m in manifests}
    for manifest in manifests:
        _read(manifest.source_relative_path, manifest.source_sha256)
        sources[manifest.source_relative_path] = manifest.source_sha256
        fields.append(dict(preflight_actor_manifest(manifest,
            channel_sequence=0, max_packet_bytes=1492).actor_fields))
        actors.append((manifest.actor_guid, manifest.channel_index, manifest.class_path,
                       manifest.source_relative_path, manifest.source_sha256))
        for path in manifest.path_bindings:
            if path.guid in assets and assets[path.guid] != path.full_path:
                raise ValueError('A current class/asset GUID has conflicting bindings')
            if path.guid in actor_guids and not (type(manifest) is StaticActorManifest
                                                and path.guid == manifest.actor_guid):
                raise ValueError('A dynamic Actor aliases the static class namespace')
            assets[path.guid] = path.full_path
    # Reuse the normal transport preflight for typed groups, creation order,
    # aliases and full class exports. Its payload bytes are not fingerprinted.
    preflight_actor_content_plans(tuple(fields), plans, initial_channel_sequence=0,
                                  max_packet_bytes=1492)
    components, dynamic, creations = {}, {}, []
    owners = {m.actor_guid: m.channel_index for m in manifests}
    for plan in plans:
        if plan['actor_guid'] not in owners or plan['channel_index'] != owners[plan['actor_guid']]:
            raise ValueError('A content plan changed the actual Actor owner')
        groups = [plan.get('default_subobjects', ())]
        if 'default_subobject' in plan:
            groups.append((plan['default_subobject'],))
        groups.extend(plan.get('continuations', ()))
        for group in groups:
            for update in group:
                if type(update) is DefaultSubobjectUpdate:
                    binding = (update.actor_guid, update.name)
                    if (update.guid in components and components[update.guid] != binding or
                            any(g != update.guid and b == binding for g, b in components.items())):
                        raise ValueError('A current default component changed GUID/name binding')
                    components[update.guid] = binding
                elif type(update) is DynamicObjectCreation:
                    dynamic[update.guid] = (update.actor_guid, update.class_guid, update.class_path)
                    creations.append(update)
                elif type(update) is AbilityComponentCreation:
                    dynamic[update.guid] = (update.actor_guid, update.class_guid, ABILITY_CLASS_PATH)
    instance_rows = [u for u in creations if u.actor_guid == pawn.actor_guid and u.class_path == CLASS_PATH]
    if len(instance_rows) != 1:
        raise ValueError('One actually planned source main FSM creation is required')
    instance = instance_rows[0]
    if (instance.source_sha256 != SOURCE_SHA256 or instance.payload != b'\0\0' or
            instance.payload_bit_count != 9 or
            (instance.class_guid, instance.class_path) not in qualified_class_exports(pawn.exports)):
        raise ValueError('The current main FSM class creation source changed')
    fsm = [g for g, b in components.items() if b == (pawn.actor_guid, classes['component_name'])]
    if len(fsm) != 1:
        raise ValueError('The actual current Pawn FSM default component is required')
    kickoff = [u for p in plans for group in p.get('continuations', ()) for u in group
        if type(u) is DefaultSubobjectUpdate and u.guid == fsm[0] and
        u.source_sha256 == FIXED_PINS[KICKOFF] and u.payload == b'\0\0' and u.payload_bit_count == 9]
    if not kickoff:
        raise ValueError('The source-qualified default FSM kickoff must precede its creation')
    board = [g for g, b in components.items() if b == (pawn.actor_guid, classes['board_name'])]
    return dict(actors=sorted(actors), assets=sorted(assets.items()),
        components=sorted((g, *b) for g, b in components.items()),
        dynamic_objects=sorted((g, *b) for g, b in dynamic.items()),
        pawn_guid=pawn.actor_guid, pawn_channel=pawn.channel_index,
        component_guid=fsm[0], instance_guid=instance.guid, class_guid=instance.class_guid,
        board_guid=board[0] if board else None), sources


def _binding(*, ticket, manifests, plans):
    identity = _ticket(ticket)
    sources, classes = _sources()
    namespace, actor_sources = _namespace(manifests, plans, classes)
    return dict(ticket=identity, namespace=namespace, classes=classes,
        sources=dict(sources, **actor_sources), policy=POLICY)


def _state(binding):
    namespace, classes = binding['namespace'], binding['classes']
    pawn = CharacterObjectReference(None, None, classes['pawn_class'], namespace['pawn_guid'])
    board = CharacterObjectReference(namespace['pawn_guid'], classes['board_name'],
        classes['board_class'], namespace['board_guid'])
    component = CharacterObjectReference(namespace['pawn_guid'], classes['component_name'],
        classes['component_class'], namespace['component_guid'])
    # This adapter owns a dedicated server context (native mode 1). Native
    # 0x409d5bc derives isServer; the character event loop installs no callbacks.
    network_mode = 1
    server = network_mode == 1
    return CharacterInitializationState(pawn, pawn, board, board, pawn, pawn, component,
        tuple(CharacterEventEntry(i) for i in range(164)), network_mode, server,
        True, False, False, False, False)


def _receipt(path, binding, state):
    n = binding['namespace']
    return CharacterInitializationReceipt(str(path.resolve()), binding['ticket']['admission_sha256'],
        _digest(binding), _digest(asdict(state)), n['pawn_guid'], n['component_guid'],
        n['instance_guid'], n['class_guid'], n['pawn_channel'], state.server_identity, state)


class CharacterInitializationStore:
    def __init__(self, path):
        self.path = Path(path).resolve()

    def materialize(self, *, ticket, manifests, plans):
        binding = _binding(ticket=ticket, manifests=manifests, plans=plans)
        state = _state(binding)
        receipt = _receipt(self.path, binding, state)
        expected = (receipt.binding_sha256, receipt.state_sha256, _json(binding), _json(asdict(state)))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=30)) as db, db:
            db.execute('begin immediate')
            db.execute(TABLE)
            row = db.execute('select binding_sha256,state_sha256,binding_json,state_json '
                'from character_initializations_v1 where admission_sha256=?',
                (receipt.admission_sha256,)).fetchone()
            if row is None:
                db.execute('insert into character_initializations_v1 values(?,?,?,?,?)',
                           (receipt.admission_sha256, *expected))
            elif row != expected:
                raise ValueError('The admission has a conflicting or changed character initialization')
        return receipt

    def validate_committed(self, receipt):
        if (type(receipt) is not CharacterInitializationReceipt or
                type(receipt.fsm_ready) is not bool or
                type(receipt.state) is not CharacterInitializationState or
                receipt.store_path != str(self.path) or not self.path.is_file()):
            raise ValueError('An actual committed character initialization receipt is required')
        with closing(sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True, timeout=30)) as db:
            row = db.execute('select binding_sha256,state_sha256,binding_json,state_json '
                'from character_initializations_v1 where admission_sha256=?',
                (receipt.admission_sha256,)).fetchone()
        if row is None:
            raise ValueError('The character initialization admission is not committed')
        binding = json.loads(row[2])
        sources, classes = _sources()
        if (binding['policy'] != POLICY or binding['classes'] != classes or
                any(binding['sources'].get(p) != h for p, h in sources.items())):
            raise ValueError('The committed character initialization source changed')
        for path, expected in binding['sources'].items():
            _read(path, expected)
        state = _state(binding)
        actual = _receipt(self.path, binding, state)
        if (row != (actual.binding_sha256, actual.state_sha256, _json(binding), _json(asdict(state))) or
                receipt != actual or _json(asdict(receipt)) != _json(asdict(actual))):
            raise ValueError('The persisted character initialization or receipt changed')
        return receipt

    def validate_binding(self, receipt, *, ticket, manifests, plans):
        self.validate_committed(receipt)
        binding = _binding(ticket=ticket, manifests=manifests, plans=plans)
        if _receipt(self.path, binding, _state(binding)) != receipt:
            raise ValueError('The character receipt belongs to another current admission or namespace')
        return receipt


def validate_committed(receipt):
    if type(receipt) is not CharacterInitializationReceipt:
        raise ValueError('An actual committed character initialization receipt is required')
    return receipt.validate_committed()
