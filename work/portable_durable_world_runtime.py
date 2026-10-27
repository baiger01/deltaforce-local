"""Admitted static box reference routing and ACK-driven durable world outbox.

Server allocations and positive export receipts qualify a reference namespace.
They grant no native resolution, position, permission or terminal authority.
"""
from dataclasses import dataclass, replace
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import threading

from dfserver.legacy_ds_actor_fields import NormalClassFieldProfile, read_class_fields
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_control_connection import (LegacyDSControlConnection, ControlConnection,
    _AdmittedActorReceiptLease, _OpaqueActorTransportReceipt, _ActualActorReceipt, _content_items)
from dfserver.legacy_ds_match_admission import LocalMatchTicket
from dfserver.legacy_ds_pc_receipt import bounded_actor_fields
from dfserver.legacy_ds_wire_codec import WireBunch, ChannelName
from portable_durable_world_dispatch import DurableWorldDispatcher, OpenDispatchResult, MoveDispatchResult
from portable_world_session import DurableWorldSession, SessionCredential, _json
import portable_durable_world_dispatch as dispatch_source
import portable_world_inventory_delta as inventory_delta
import portable_world_item_move_request as moves
import portable_world_interact_request as interactions
import portable_loot_box_codec as boxes
import portable_loot_box_request as opens
import portable_map_level_actors as level_actors
from dfserver.replication.static_actor_registry import AdmittedStaticActorRegistry, StaticActorRegistryProfile
from dfserver.legacy_ds_static_actor_manifest import StaticActorManifest
from portable_source_guard import SourceGuard


ROOT = Path(__file__).resolve().parent.parent
ROOM_SCHEMA = '''CREATE TABLE IF NOT EXISTS durable_room_namespace_v1 (
 wire_room_id TEXT NOT NULL, room_seed TEXT NOT NULL, durable_room_id TEXT NOT NULL UNIQUE,
 source_key TEXT NOT NULL UNIQUE, PRIMARY KEY(wire_room_id,room_seed))'''
MAX_RECEIPTS = 4096


@dataclass(frozen=True)
class RoomNamespace:
    wire_room_id: int
    room_seed: int
    durable_room_id: int
    key: str


@dataclass(frozen=True)
class RuntimeInstallation:
    installed: bool
    runtime: object
    reasons: tuple


@dataclass(frozen=True)
class PendingDelivery:
    kind: str
    path: str
    snapshot: object
    result: object
    phase: str = 'box_queue'


def source_pins():
    pins = dispatch_source.source_pins()
    pins.update(inventory_delta.source_pins())
    for relative in ('work/portable_durable_world_runtime.py',
            'work/portable_map_level_actors.py',
            'outputs/df-local-server/dfserver/_paths.py',
            'outputs/df-local-server/dfserver/replication/__init__.py',
            'outputs/df-local-server/dfserver/replication/static_actor_registry.py',
            'outputs/df-local-server/dfserver/legacy_ds_static_actor_manifest.py',
            'outputs/df-local-server/dfserver/legacy_ds_control_connection.py',
            'outputs/df-local-server/dfserver/legacy_ds_owned_pawn_receipt.py',
            'outputs/df-local-server/dfserver/legacy_ds_movement.py'):
        pins[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    return pins


def make_static_box_profile(ticket, manifests, plans):
    """Freeze source rows before the owner loop installs their actual receipts."""
    if (type(ticket) is not LocalMatchTicket or type(ticket.room_seed) is not int
            or not 0 <= ticket.room_seed < 1 << 63
            or type(manifests) is not tuple or not 1 <= len(manifests) <= 64):
        raise ValueError('The complete bounded actual admission manifest tuple is required')
    bindings = {binding.object_path: binding for binding in boxes.qualified_bindings()}
    rows = {row['actor_path']: row for row in level_actors.derive_schema(ROOT)['actors']}
    selected = []
    for manifest in manifests:
        if type(manifest) is not StaticActorManifest or manifest.actor_path not in bindings:
            continue
        row, binding = rows.get(manifest.actor_path), bindings[manifest.actor_path]
        if (row is None or manifest.class_path != row['class_path'] or manifest.class_path != binding.class_path
                or manifest.level_path != row['level_path']
                or manifest.source_relative_path != level_actors.SOURCE_REPORT
                or manifest.source_sha256 != level_actors.SOURCE_PINS[level_actors.SOURCE_REPORT]):
            raise ValueError('The admitted SafeBox path, class or source row changed')
        selected.append(manifest)
    pins = static_box_source_pins()
    guard = SourceGuard(ROOT, pins)
    try:
        return StaticActorRegistryProfile(ticket, tuple(selected), tuple(sorted(pins.items())), guard,
                                          RegisteredBoxReceiptRuntime)
    except BaseException:
        guard.close()
        raise


def static_box_source_pins():
    pins = source_pins()
    pins.update(level_actors.level_actor_source_pins(ROOT))
    for relative in ('work/portable_durable_world_runtime.py', 'work/portable_source_guard.py',
            'work/portable_map_level_actors.py',
            'outputs/df-local-server/dfserver/_paths.py',
            'outputs/df-local-server/dfserver/replication/__init__.py',
            'outputs/df-local-server/dfserver/replication/static_actor_registry.py',
            'outputs/df-local-server/dfserver/legacy_ds_static_actor_manifest.py',
            'outputs/df-local-server/dfserver/legacy_ds_control_connection.py',
            'outputs/df-local-server/dfserver/game_server_probe.py'):
        pins[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    return pins


def build_static_box_registry(connection, peer, manifests):
    """Select actual admitted SafeBoxes from the pinned source Actor rows."""
    state = connection.control_peers.get(peer)
    if type(state) is not ControlConnection:
        raise ValueError('The actual admitted Control owner is required')
    profile = make_static_box_profile(state.ticket, manifests, ())
    try:
        return AdmittedStaticActorRegistry(connection, peer, profile.manifests,
            source_pins=dict(profile.source_pins), sources_current=profile.sources_current)
    except BaseException:
        profile.sources_current.close()
        raise


def _room_id(wire_room_id, room_seed):
    raw = _json(['durable-world-room-v1', str(wire_room_id), str(room_seed)]).encode('ascii')
    return int.from_bytes(hashlib.sha256(raw).digest()[:8], 'big') or 1


def prepare_room_namespace(store, ticket):
    """Persist a collision-checked local namespace without changing the wire ID."""
    if (type(store) is not DurableWorldSession or type(ticket) is not LocalMatchTicket
            or type(ticket.room_id) is not int or not 0 < ticket.room_id < 1 << 64
            or type(ticket.room_seed) is not int or not 0 <= ticket.room_seed < 1 << 63):
        raise ValueError('The actual ticket room ID and actual room_seed are required')
    durable_id = _room_id(ticket.room_id, ticket.room_seed)
    namespace = RoomNamespace(ticket.room_id, ticket.room_seed, durable_id,
                              'room:' + str(ticket.room_id) + ':seed:' + str(ticket.room_seed))
    try:
        with store._transaction() as connection:
            connection.execute(ROOM_SCHEMA)
            previous = connection.execute('SELECT * FROM durable_room_namespace_v1 WHERE wire_room_id=? AND room_seed=?',
                (str(ticket.room_id), str(ticket.room_seed))).fetchone()
            values = (str(ticket.room_id), str(ticket.room_seed), str(durable_id), namespace.key)
            if previous is None:
                connection.execute('INSERT INTO durable_room_namespace_v1 VALUES (?,?,?,?)', values)
            elif tuple(previous) != values:
                raise ValueError('The durable room namespace mapping changed')
    except sqlite3.IntegrityError as error:
        raise ValueError('A durable room namespace hash collision must not alias another room_seed') from error
    return namespace


def wire_terminal_result(store, credential, namespace):
    """Translate only a real account-applied saved terminal to its wire room ID."""
    if (type(store) is not DurableWorldSession or type(credential) is not SessionCredential
            or type(namespace) is not RoomNamespace or credential.room_id != namespace.durable_room_id):
        raise ValueError('The exact saved durable room namespace is required')
    with store._connection() as connection:
        store._auth(connection, credential)
        row = connection.execute('SELECT * FROM durable_room_namespace_v1 WHERE durable_room_id=?',
            (str(credential.room_id),)).fetchone()
        if row is None or tuple(row) != (str(namespace.wire_room_id), str(namespace.room_seed),
                                         str(namespace.durable_room_id), namespace.key):
            raise ValueError('The durable-to-wire room namespace changed')
    terminal = store.match_over_result(credential)
    if terminal.room_id != namespace.durable_room_id or terminal.player_id != credential.player_id:
        raise ValueError('The saved materialized terminal belongs to another durable room/player')
    return replace(terminal, room_id=namespace.wire_room_id)


class ControlOwner:
    """Exact current ticket/transport/generation/receipt lease; no boolean oracle."""
    def __init__(self, connection, peer, credential, namespace):
        if (type(connection) is not LegacyDSControlConnection or type(credential) is not SessionCredential
                or type(namespace) is not RoomNamespace or credential.room_id != namespace.durable_room_id):
            raise ValueError('The actual Control owner and distinct durable room namespace are required')
        self.connection, self.peer, self.credential, self.namespace = connection, peer, credential, namespace
        state = connection.control_peers.get(peer)
        if type(state) is not ControlConnection:
            raise ValueError('No actual current Control owner exists')
        self.ticket, self.transport, self.lease = state.ticket, connection.peers.get(peer), state.admitted_actor_receipt_lease
        self.generation = connection._local_stage_owner(peer, state, self.transport)
        self.current()

    def current(self):
        connection, peer = self.connection, self.peer
        state, transport = connection.control_peers.get(peer), connection.peers.get(peer)
        if (type(state) is not ControlConnection or type(self.ticket) is not LocalMatchTicket
                or type(state.admitted_actor_receipt_lease) is not _AdmittedActorReceiptLease
                or state.ticket is not self.ticket or transport is not self.transport
                or state.admitted_actor_receipt_lease is not self.lease
                or state.client_closed is not False or state.client_join_observed is not True
                or self.ticket.player_id != self.credential.player_id
                or (self.ticket.room_id, self.ticket.room_seed) != (self.namespace.wire_room_id, self.namespace.room_seed)
                or connection._local_stage_owner(peer, state, transport) is not self.generation):
            raise ValueError('The durable world Control owner lease, room seed or generation changed')
        connection._admitted_actor_receipt_binding(state, state, peer, transport, self.generation)
        return state

    def admission_current(self, credential):
        self.current()
        return credential is self.credential

    def accepted_position(self, credential):
        if credential is not self.credential:
            raise ValueError('The accepted position belongs to another durable world credential')
        self.current()
        value = self.connection.accepted_movement_position(self.peer)
        if (type(value) is not tuple or len(value) != 3
                or any(type(part) not in (int, float) or not math.isfinite(part) for part in value)):
            raise ValueError('The actual committed movement position is unavailable')
        return value


def install_runtime(connection, peer, store=None, *, manifests=None, membership_observation=None,
                    tag_observation=None, package_map_provider=None, permission_provider=None, **unused):
    """Install actual reference routing; per-box mutation authority stays separate.

No durable tables, credential or mutation dispatcher are created here. A prior
client PackageMap allocation is not a prerequisite for a server static GUID.
"""
    if type(connection) is not LegacyDSControlConnection or store is not None and type(store) is not DurableWorldSession:
        raise ValueError('The actual Control transport and optional durable SQLite store are required')
    if manifests is not None:
        registry = build_static_box_registry(connection, peer, manifests)
        runtime = RegisteredBoxReceiptRuntime(registry)
        return RuntimeInstallation(True, runtime, runtime.mutation_refusals)
    state = connection.control_peers.get(peer)
    reasons = []
    if type(state) is not ControlConnection:
        reasons.append('current_control_owner_missing')
    else:
        transport = connection.peers.get(peer)
        try:
            generation = connection._local_stage_owner(peer, state, transport)
            connection._admitted_actor_receipt_binding(state, state, peer, transport, generation)
            connection.accepted_movement_position(peer)
        except ValueError:
            reasons.append('current_receipt_owner_or_accepted_movement_missing')
        if type(state.ticket.room_seed) is not int:
            reasons.append('actual_room_seed_missing')
    membership = membership_observation if type(membership_observation) is dict else {}
    if membership.get('kind') != 'owned_current_world_actor_membership_v1' or membership.get('identity_fields_roots_and_process_rechecked') is not True:
        reasons.append('current_world_membership_observation_missing')
    tag = tag_observation if type(tag_observation) is dict else {}
    if (tag.get('kind') != 'owned_current_native_gameplaytag_replication_mode_observation'
            or tag.get('current_identity_mode_and_owned_roots_rechecked') is not True
            or tag.get('nonfast_replication_confirmed') is not True or tag.get('raw_mode_hex') != '00'):
        reasons.append('current_nonfast_tag_observation_missing')
    reasons.extend((('package_map_provider_missing' if package_map_provider is None else
                     'package_map_provider_not_source_qualified'),
                    ('interaction_permission_provider_missing' if permission_provider is None else
                     'interaction_permission_provider_not_source_qualified'),
                    'source_qualified_box_world_position_missing', 'actual_admission_static_manifests_missing'))
    return RuntimeInstallation(False, None, tuple(reasons))


@dataclass(frozen=True)
class CommittedBoxReferenceUse:
    request: opens.OpenBoxRequest
    committed_receipt: _OpaqueActorTransportReceipt
    body: WireBunch


class RegisteredBoxReceiptRuntime:
    """Consume current PC226 receipts without turning delivery into gameplay proof."""
    mutation_ready = False
    mutation_refusals = ('source_qualified_box_world_position_missing',
                         'interaction_permission_provider_missing')

    def __init__(self, registry):
        if type(registry) is not AdmittedStaticActorRegistry:
            raise ValueError('The exact admitted source-qualified static registry is required')
        self.registry = registry
        self.sources_current = registry.sources_current
        qualified = {binding.object_path: binding for binding in boxes.qualified_bindings()}
        self.bindings_by_guid = {entry.actor_guid: qualified[entry.actor_path] for entry in registry.entries}
        self.reference_uses, self.last_refusal = {}, None
        registry.current()
        self._seen = {}

    def rebind_authenticated_peer(self, old_peer, new_peer):
        self.registry.rebind_authenticated_peer(old_peer, new_peer)

    def pump(self):
        state = self.registry.owner_current()
        retained = {id(entry): entry for entry in state.admitted_actor_opaque_journal}
        self._seen = {identity: entry for identity, entry in self._seen.items() if identity in retained}
        outcomes = []
        for entry in state.admitted_actor_opaque_journal:
            if id(entry) in self._seen:
                continue
            if len(self._seen) >= MAX_RECEIPTS:
                raise ValueError('The bounded static box receipt journal is exhausted')
            if (type(entry) is not _OpaqueActorTransportReceipt
                    or entry.payload_sha256 != hashlib.sha256(entry.bunch.payload).hexdigest()
                    or entry.channel_index != entry.bunch.channel_index):
                raise ValueError('The current committed static box receipt identity changed')
            try:
                for body in entry.ready:
                    for kind, field in route_committed_body(body, pc_channel=state.pc_startup_channel,
                            pawn_channel=state.pc_restart_pawn_channel,
                            inventory_manager_guid=None, interactor_guid=None):
                        if kind != 'open':
                            continue
                        self.registry.current()
                        request = opens.decode_reference_field(field, bindings_by_guid=self.bindings_by_guid,
                            recipient_scope=('room:' + str(self.registry.ticket.room_id) + ':seed:' +
                                str(self.registry.ticket.room_seed), self.registry.ticket.player_id))
                        self.registry.lookup(request.box_guid)
                        self.reference_uses[request.box_guid] = CommittedBoxReferenceUse(request, entry, body)
                        self.last_refusal = ','.join(self.mutation_refusals)
                        outcomes.append('box_reference_used_mutation_refused')
            except ValueError:
                # Source/owner loss disables routing; malformed client fields
                # remain ordinary policy refusals within the current lease.
                self.registry.current()
                self.last_refusal = 'box_reference_outside_current_admission_or_invalid_field'
                outcomes.append('world_policy_rejected')
            self._seen[id(entry)] = entry
        return tuple(outcomes)


def _component(state, name):
    values = {binding[0] for item in _content_items(state) for binding in item.component_bindings
              if binding[1:] == (state.pc_restart_pawn_guid, name)}
    if len(values) > 1:
        raise ValueError('The queued owning component name has multiple GUIDs')
    return next(iter(values)) if values else None


def route_committed_body(body, *, pc_channel, pawn_channel, inventory_manager_guid, interactor_guid):
    """Preflight one completed receipted body; no SQL, mutation or admission."""
    if (type(body) is not WireBunch or body.reliable is not True or body.partial
            or body.open or body.close or body.package_exports or body.must_be_mapped
            or body.flag4 or body.connection_flag or body.close_reason != 0
            or body.channel_name != ChannelName(hardcoded_index=102)):
        return ()
    if body.channel_index == pc_channel:
        return tuple(('open', field) for field in bounded_actor_fields(body, exclusive_index_maximum=245)
                     if field.rep_index == 226)
    if body.channel_index != pawn_channel:
        return ()
    reader = BitReader(body.payload, bit_count=body.payload_bits)
    actions, blocks = [], 0
    while reader.remaining:
        blocks += 1
        if blocks > 256:
            raise ValueError('The ordinary owning component content block limit was exceeded')
        has_layout, is_actor = reader.read_bool(), reader.read_bool()
        guid = None if is_actor else reader.read_packed_int()
        length = reader.read_packed_int()
        payload = reader.read_payload(length)
        if has_layout or is_actor:
            continue
        maximum = 53 if guid == inventory_manager_guid else 168 if interactor_guid is not None and guid == interactor_guid else None
        if maximum is None:
            continue
        fields = read_class_fields(BitReader(payload, bit_count=length), profile=NormalClassFieldProfile(maximum, False))
        for field in fields:
            if guid == inventory_manager_guid and field.rep_index == moves.RPC_INDEX:
                actions.append(('move', field))
            elif guid == interactor_guid and field.rep_index in (71, 72):
                actions.append(('interact', field))
    return tuple(actions)


class CommittedReceiptRuntime:
    """Integration core for an already-qualified dispatcher, not an installer.

    Call pump()/advance() under the same owner event-loop lock. Private SQL
    authority remains DurableWorldDispatcher alone. Tests may supply explicitly
    synthetic live/permission callbacks; install_runtime never certifies them.
    """
    def __init__(self, owner, dispatcher):
        if type(owner) is not ControlOwner or type(dispatcher) is not DurableWorldDispatcher:
            raise ValueError('One actual owner and already qualified durable dispatcher are required')
        if (dispatcher._credential is not owner.credential
                or dispatcher._recipient != (owner.namespace.key, owner.credential.player_id)
                or dispatcher._admission_current != owner.admission_current
                or dispatcher._accepted_position != owner.accepted_position):
            raise ValueError('The dispatcher must use the actual Control owner and accepted movement methods')
        self.owner, self.dispatcher = owner, dispatcher
        self._lock, self.pending, self.last_refusal = threading.RLock(), None, None
        state = owner.current()
        self.inventory_manager_guid = _component(state, 'InventoryManager')
        self.interactor_guid = _component(state, 'InteractorComponent')
        if self.inventory_manager_guid != state.inventory_refresh_profile.component_guid:
            raise ValueError('The exact queued owning InventoryManager is required')
        with dispatcher._store._connection() as connection:
            row = dispatcher._store._auth(connection, owner.credential, active=True)
            namespace = connection.execute('SELECT * FROM durable_room_namespace_v1 WHERE durable_room_id=?',
                (str(owner.credential.room_id),)).fetchone()
            if (namespace is None or tuple(namespace) != (str(owner.namespace.wire_room_id), str(owner.namespace.room_seed),
                    str(owner.namespace.durable_room_id), owner.namespace.key)
                    or row['initial_json'] != _json(json.loads(owner.ticket.loadout_snapshot))):
                raise ValueError('The durable room seed or frozen admission snapshot differs from Control')
        self._pins = source_pins()
        # Old committed bodies cannot become new commands on a later binding.
        self._seen = {id(entry): entry for entry in state.admitted_actor_opaque_journal}

    def _current(self):
        state = self.owner.current()
        if source_pins() != self._pins or not self.dispatcher.sources_current():
            raise ValueError('The frozen durable runtime source contracts changed')
        if (_component(state, 'InventoryManager') != self.inventory_manager_guid
                or _component(state, 'InteractorComponent') != self.interactor_guid):
            raise ValueError('The actual owning InventoryManager/Interactor component mapping changed')
        return state

    def pump(self):
        """Consume only receipt objects present in the current committed state."""
        with self._lock:
            state = self._current()
            if self.pending is not None:
                return ()
            outcomes = []
            for entry in state.admitted_actor_opaque_journal:
                if id(entry) in self._seen:
                    continue
                if len(self._seen) >= MAX_RECEIPTS:
                    raise ValueError('The bounded committed runtime receipt journal is exhausted')
                if (type(entry) is not _OpaqueActorTransportReceipt
                        or entry.payload_sha256 != hashlib.sha256(entry.bunch.payload).hexdigest()
                        or entry.channel_index != entry.bunch.channel_index):
                    raise ValueError('The current committed opaque receipt identity changed')
                try:
                    actions = tuple(action for body in entry.ready for action in route_committed_body(body,
                        pc_channel=state.pc_startup_channel, pawn_channel=state.pc_restart_pawn_channel,
                        inventory_manager_guid=self.inventory_manager_guid, interactor_guid=self.interactor_guid))
                    if len(actions) > 1:
                        raise ValueError('multiple_world_mutations_in_one_completed_receipt_unsupported')
                    if actions:
                        kind, field = actions[0]
                        if kind == 'move':
                            revision = self.dispatcher._store.current_snapshot(self.owner.credential).revision
                            result = self.dispatcher.move_field(field, expected_revision=revision)
                            self.pending = PendingDelivery('move', result.receipt.source_path, result.box_snapshot, result)
                        else:
                            result = (self.dispatcher.open_field(field) if kind == 'open' else self.dispatcher.interact_field(field))
                            self.pending = PendingDelivery('open', result.snapshot.owner_key, result.snapshot, result)
                        outcomes.append(self.pending.kind + '_queued')
                    else:
                        outcomes.append('opaque_unhandled')
                except ValueError as error:
                    self.last_refusal = str(error)[:512]
                    outcomes.append('world_policy_rejected')
                self._seen[id(entry)] = entry
                if self.pending is not None:
                    break
            return tuple(outcomes)

    def recover_pending_command(self, command_gid):
        """Recover immutable SQL output; never recreate lost Control ACK proof.

        Control must retain its exact current cursor/batch owner. A replacement
        connection lacking the source deletion baseline will still refuse RPC22.
        """
        with self._lock:
            state = self._current()
            if type(command_gid) is not int or not 0 < command_gid < 1 << 64:
                raise ValueError('An actual durable command GID is required')
            if self.pending is not None:
                if self.pending.kind == 'move' and self.pending.result.receipt.cmd_gid == command_gid:
                    return self.pending
                raise ValueError('Another immutable durable delivery is pending')
            with self.dispatcher._store._connection() as connection:
                self.dispatcher._store._auth(connection, self.owner.credential, active=True)
                row = connection.execute('SELECT * FROM durable_world_native_command_v1 WHERE admission_id=? AND cmd_gid=?',
                    (self.owner.credential.admission_id, str(command_gid))).fetchone()
                if row is None or hashlib.sha256(row['result_json'].encode()).hexdigest() != row['result_sha256']:
                    raise ValueError('The immutable durable native command result is missing or changed')
                native = json.loads(row['native_json'])
                for key in ('target_gids', 'target_loot_guids', 'origin_position', 'origin_forward', 'spaces_to_sync_guids'):
                    native[key] = tuple(native[key])
                request = moves.ItemMoveRequest(**native)
                if request.command_gid != command_gid or request.source_loot_guid not in self.dispatcher._bindings:
                    raise ValueError('The saved command differs from this actual static box namespace')
                result = self.dispatcher._result(request, self.dispatcher._bindings[request.source_loot_guid],
                                                 json.loads(row['result_json']))
            known = state.world_result_journal.get(command_gid)
            if known is not None:
                receipt = known[1]
                if (known[0] != result.receipt or type(receipt) is not _ActualActorReceipt
                        or receipt.ticket is not self.owner.ticket or receipt.transport is not self.owner.transport
                        or receipt.generation is not self.owner.generation):
                    raise ValueError('The completed native result belongs to another actual owner receipt')
                return None
            self.pending = PendingDelivery('move', result.receipt.source_path, result.box_snapshot, result)
            return self.pending

    def advance(self):
        """Queue box -> wait ACK -> inventory -> wait ACK -> RPC22 -> wait ACK.

        Queue errors preserve the immutable pending dispatcher result. They do
        not undo durable ownership, invent ACKs, or mark completion. Socket
        sends and all packet ACK/sequence commits remain owned by Control.
        """
        with self._lock:
            self._current()
            if self.pending is None:
                return 'idle'
            pending = self.pending
            connection, peer = self.owner.connection, self.owner.peer
            if pending.phase == 'box_queue':
                connection.queue_world_box_snapshot(peer, object_path=pending.path, snapshot=pending.snapshot)
                self.pending = replace(pending, phase='box_wait')
                return 'box_queued'
            if pending.phase == 'box_wait':
                try:
                    cursor = connection.world_box_cursor(peer, pending.path)
                except ValueError:
                    return 'awaiting_box_ack'
                if cursor is None or cursor.known_items != pending.snapshot.items:
                    raise ValueError('The acknowledged box differs from the immutable durable result')
                if pending.kind == 'open':
                    self.pending = None
                    return 'open_delivered'
                self.pending = replace(pending, phase='inventory_queue')
                return 'box_acknowledged'
            if pending.phase == 'inventory_queue':
                baseline = connection.inventory_refresh_revision_state(peer)
                if baseline['original_items'] != pending.result.inventory_snapshot.items:
                    projection = inventory_delta.project_addition(pending.result.receipt,
                        recipient_scope=self.dispatcher._recipient, pawn_guid=baseline['pawn_guid'],
                        inventory_component_guid=baseline['component_guid'], committed_array_key=baseline['array_key'],
                        committed_items=baseline['original_items'], authoritative_items=pending.result.inventory_snapshot.items)
                    connection.queue_inventory_update(peer, expected_array_key=projection.expected_array_key,
                        update=projection.update, authoritative_items=projection.authoritative_items)
                self.pending = replace(pending, phase='inventory_wait')
                return 'inventory_queued'
            if pending.phase == 'inventory_wait':
                try:
                    baseline = connection.inventory_refresh_revision_state(peer)
                except ValueError:
                    return 'awaiting_inventory_ack'
                if baseline['original_items'] != pending.result.inventory_snapshot.items:
                    raise ValueError('The actual acknowledged inventory differs from the durable destination')
                self.pending = replace(pending, phase='result_queue')
                return 'inventory_acknowledged'
            if pending.phase == 'result_queue':
                connection.queue_world_move_success(peer, pending.result.receipt)
                self.pending = replace(pending, phase='result_wait')
                return 'result_queued'
            if pending.phase == 'result_wait':
                known = self.owner.current().world_result_journal.get(pending.result.receipt.cmd_gid)
                if known is None:
                    return 'awaiting_result_ack'
                receipt = known[1]
                if (known[0] != pending.result.receipt or type(receipt) is not _ActualActorReceipt
                        or receipt.ticket is not self.owner.ticket or receipt.transport is not self.owner.transport
                        or receipt.generation is not self.owner.generation):
                    raise ValueError('The native result has no exact current owner receipt')
                self.pending = None
                return 'move_delivered'
            raise ValueError('The durable outbox phase is invalid')


make_runtime = install_runtime
