"""Transactional native box dispatch over DurableWorldSession's actual SQLite.

The caller holds its current transport/permission authority exclusive throughout
each call. Box authority requires a callback or an explicitly selected qualified
local normal box policy. Positions come only from the accepted movement provider. These local
policies support the three qualified existing SafeBoxes and complete ordinary
whole-stack stock; feature-bearing box instances need a qualified producer.

Only this dispatcher may mutate an attached admission after construction. It
does not create a FiniteLootAuthority, send packets, advance ACK cursors, invent
loot, or infer extraction conditions. Terminal retries retain the durable pending
result when the real same-connection account materializer rolls back.
"""
from dataclasses import asdict, dataclass, replace
import hashlib
import json
import math
from pathlib import Path
import threading

from dfserver.legacy_ds_inventory_items import InventoryFastArrayElement, InventoryItemLocation
from dfserver.legacy_ds_inventory_state import InventorySpace, InventorySpaceGrid
from dfserver.legacy_ds_world_delivery import WorldBoxProjection
from dfserver.native_match_materializer import materialize
from normal_map_archive_values import NativeName
from portable_finite_loot import LootSnapshot, TransferReceipt
import portable_loot_box_codec as boxes
import portable_loot_box_request as opens
import portable_map_inventory as inventory
import portable_normal_box_policy as normal_boxes
import portable_world_box_seed as seeds
import portable_world_interact_request as interactions
import portable_world_item_move_request as moves
import portable_world_loot_dispatch as qualified_dispatch
from portable_world_session import DurableWorldSession, PickupReceipt, SessionCredential, _json, _uint


SCHEMA = '''
CREATE TABLE IF NOT EXISTS durable_world_admission_v1 (
 admission_id TEXT PRIMARY KEY, profile_json TEXT NOT NULL, source_pins_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS durable_world_box_v1 (
 room_id TEXT NOT NULL, path TEXT NOT NULL, revision INTEGER NOT NULL,
 PRIMARY KEY(room_id,path));
CREATE TABLE IF NOT EXISTS durable_world_element_v1 (
 room_id TEXT NOT NULL, owner_key TEXT NOT NULL, gid TEXT NOT NULL, element_id INTEGER NOT NULL,
 PRIMARY KEY(room_id,owner_key,gid), UNIQUE(room_id,owner_key,element_id));
CREATE TABLE IF NOT EXISTS durable_world_native_command_v1 (
 admission_id TEXT NOT NULL, cmd_gid TEXT NOT NULL, native_json TEXT NOT NULL,
 result_json TEXT NOT NULL, result_sha256 TEXT NOT NULL,
 PRIMARY KEY(admission_id,cmd_gid));
'''
OPEN_TAG = NativeName('Interactor.CheckCollision.ContainerBox.Open', 0)


@dataclass(frozen=True)
class LiveWorldContext:
    ready_box_guids: frozenset
    references_resolved: bool
    exports_acknowledged: bool
    nonfast_replication_confirmed: bool


@dataclass(frozen=True)
class OpenDispatchResult:
    request: object
    snapshot: LootSnapshot
    projection: boxes.LootBoxProjection


@dataclass(frozen=True)
class MoveDispatchResult:
    request: moves.ItemMoveRequest
    receipt: TransferReceipt
    box_snapshot: LootSnapshot
    inventory_snapshot: LootSnapshot


def source_pins():
    pins = qualified_dispatch.source_pins()
    pins.update(seeds.source_pins())
    pins.update(inventory.source_pins())
    pins.update(normal_boxes.source_pins())
    root = Path(__file__).resolve().parent.parent
    for relative in ('work/portable_durable_world_dispatch.py', 'work/portable_world_session.py',
            'outputs/df-local-server/dfserver/native_match_materializer.py',
            'outputs/df-local-server/dfserver/legacy_ds_world_delivery.py'):
        pins[relative] = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    return pins


class DurableWorldDispatcher:
    """One immutable admitted recipient, SQL ownership and persistent native retries.

    Callbacks: admission_current(credential) -> True; live_world_current(credential)
    -> LiveWorldContext; accepted_position(credential) -> finite 3-tuple;
    interaction_allowed(credential=..., binding=..., operator_tag=...) -> True;
    terminal_allowed(credential=..., command_id=..., reason_name=...,
    expected_revision=..., terminal_evidence_sha256=..., retained_gids=...) -> True.
    interaction_allowed may instead be an explicit normal_box_policy instance.
    A missing actual box source rejects; missing terminal authority rejects only
    terminal(). Never wire constant True production callbacks. Box policy state
    changes must share the durable SQL transaction domain.
    """
    def __init__(self, store, credential, *, recipient_scope, bindings_by_guid,
            player_actor_guid, maximum_distance_cm, admission_current,
            live_world_current, accepted_position, interaction_allowed=None, terminal_allowed=None,
            normal_box_policy=None):
        if type(store) is not DurableWorldSession or type(credential) is not SessionCredential:
            raise ValueError('The actual durable store and admitted credential are required')
        if (type(recipient_scope) is not tuple or len(recipient_scope) != 2 or
                type(recipient_scope[0]) is not str or not 1 <= len(recipient_scope[0]) <= 256 or
                type(recipient_scope[1]) is not int or recipient_scope[1] != credential.player_id):
            raise ValueError('The exact current match/native-player recipient is required')
        if (type(player_actor_guid) is not int or not 2 <= player_actor_guid < 1 << 32 or
                type(maximum_distance_cm) not in (int, float) or not math.isfinite(maximum_distance_cm) or
                not 0 < maximum_distance_cm <= 10000):
            raise ValueError('The actual Pawn reference and bounded local distance policy are required')
        callbacks = (admission_current, live_world_current, accepted_position)
        if any(not callable(callback) for callback in callbacks):
            raise ValueError('Every actual admission, live-world and position authority callback is required')
        if normal_box_policy is None:
            if not callable(interaction_allowed):
                raise ValueError('An actual interaction authority or explicitly selected qualified normal box policy is required')
        elif (type(normal_box_policy) is not normal_boxes.QualifiedNormalBoxPolicy or
                interaction_allowed is not None):
            raise ValueError('Select exactly one actual box authority, callback or qualified normal box policy')
        if terminal_allowed is not None and not callable(terminal_allowed):
            raise ValueError('An actual terminal authority callback or no terminal source is required')
        if type(bindings_by_guid) is not dict or not 1 <= len(bindings_by_guid) <= 3:
            raise ValueError('The bounded qualified existing box mapping is required')
        self._bindings = dict(bindings_by_guid)
        for guid, binding in self._bindings.items():
            if type(guid) is not int or not 3 <= guid < 1 << 32 or not guid & 1:
                raise ValueError('An actual mapped static box GUID is required')
            boxes.qualify_binding(binding)
            seeds._capacity(binding)
        if len({b.object_path for b in self._bindings.values()}) != len(self._bindings):
            raise ValueError('The actual existing box map aliases an Actor')
        self._store, self._credential = store, credential
        self._recipient = recipient_scope
        self._player_actor_guid, self._maximum_distance = player_actor_guid, maximum_distance_cm
        self._admission_current, self._live_world_current, self._accepted_position = callbacks[:3]
        self._interaction_allowed, self._terminal_allowed = interaction_allowed, terminal_allowed
        self._normal_box_policy = normal_box_policy
        self._pins = source_pins()
        self._lock = threading.RLock()
        profile = _json(dict(recipient=recipient_scope, player_actor_guid=player_actor_guid,
            maximum_distance_cm=maximum_distance_cm,
            normal_box_policy=None if normal_box_policy is None else normal_box_policy.contract_sha256,
            bindings={str(guid): asdict(binding) for guid, binding in self._bindings.items()}))
        with store._connection() as connection:
            connection.executescript(SCHEMA + normal_boxes.SCHEMA)
        with store._transaction() as connection:
            session = store._auth(connection, credential)
            previous = connection.execute('SELECT * FROM durable_world_admission_v1 WHERE admission_id=?',
                (credential.admission_id,)).fetchone()
            if previous is None:
                if session['revision'] != 1 or session['phase'] != 'active':
                    raise ValueError('An existing mutated admission cannot be attached without its native durable journal')
                connection.execute('INSERT INTO durable_world_admission_v1 VALUES (?,?,?)',
                    (credential.admission_id, profile, _json(self._pins)))
                for prop in inventory._props(json.loads(session['initial_json'])):
                    self._allocate(connection, 'player:' + credential.admission_id, prop['gid'])
            elif previous['profile_json'] != profile or previous['source_pins_json'] != _json(self._pins):
                raise ValueError('The persisted current dispatcher profile or source contracts differ')
            for binding in self._bindings.values():
                path = binding.object_path
                if connection.execute('SELECT 1 FROM world_box_v1 WHERE room_id=? AND path=?',
                        (str(credential.room_id), path)).fetchone() is None:
                    raise ValueError('Only already seeded actual source boxes may be dispatched')
                if normal_box_policy is not None:
                    normal_box_policy.initialize(connection, credential, binding, allow_create=previous is None)
                connection.execute('INSERT OR IGNORE INTO durable_world_box_v1 VALUES (?,?,1)',
                    (str(credential.room_id), path))
                props = store._contents(connection, credential, path)
                for prop in sorted(props, key=lambda value: value['gid']):
                    self._allocate(connection, path, prop['gid'])
                self._box_snapshot(connection, binding)
            self._inventory_snapshot(connection, session)

    def sources_current(self):
        return source_pins() == self._pins

    def _current(self):
        if self._admission_current(self._credential) is not True:
            raise ValueError('The actual current transport admission rejects this credential')
        if not self.sources_current():
            raise ValueError('The frozen current dispatch source contracts changed')

    def _context(self):
        self._current()
        context = self._live_world_current(self._credential)
        if (type(context) is not LiveWorldContext or type(context.ready_box_guids) is not frozenset or
                not context.ready_box_guids <= self._bindings.keys() or
                context.references_resolved is not True or context.exports_acknowledged is not True):
            raise ValueError('Actual current live-world membership, type resolution and export ACKs are required')
        return context

    def _gate(self, connection, guid, context, operator_tag=OPEN_TAG, *, operation='open'):
        if guid not in self._bindings or guid not in context.ready_box_guids:
            raise ValueError('The exact live-world box Actor has no successful current receipt binding')
        binding = self._bindings[guid]
        if self._normal_box_policy is not None:
            self._normal_box_policy.authorize(connection, self._credential, binding, operation=operation)
        elif self._interaction_allowed(credential=self._credential, binding=binding, operator_tag=operator_tag) is not True:
            raise ValueError('The actual current box lock/permission state rejects this operation')
        self._store._near(connection, self._credential, binding.object_path,
            self._accepted_position(self._credential), self._maximum_distance)
        return binding

    def _allocate(self, connection, owner, gid):
        room = str(self._credential.room_id)
        row = connection.execute('SELECT element_id FROM durable_world_element_v1 WHERE room_id=? AND owner_key=? AND gid=?',
            (room, owner, str(gid))).fetchone()
        if row is not None:
            return row['element_id']
        element_id = connection.execute('SELECT COALESCE(MAX(element_id),-1)+1 FROM durable_world_element_v1 '
            'WHERE room_id=? AND owner_key=?', (room, owner)).fetchone()[0]
        if not 0 <= element_id < 1 << 31:
            raise ValueError('The stable local FastArray element namespace is exhausted')
        connection.execute('INSERT INTO durable_world_element_v1 VALUES (?,?,?,?)',
            (room, owner, str(gid), element_id))
        return element_id

    def _ids(self, connection, owner):
        return {int(row['gid']): row['element_id'] for row in connection.execute(
            'SELECT gid,element_id FROM durable_world_element_v1 WHERE room_id=? AND owner_key=?',
            (str(self._credential.room_id), owner))}

    def _box_payload(self, connection, binding):
        revision = connection.execute('SELECT revision FROM durable_world_box_v1 WHERE room_id=? AND path=?',
            (str(self._credential.room_id), binding.object_path)).fetchone()['revision']
        props = self._store._contents(connection, self._credential, binding.object_path)
        ids = self._ids(connection, binding.object_path)
        return dict(revision=revision, props=props, element_ids=tuple((p['gid'], ids[p['gid']]) for p in props))

    def _typed_box(self, binding, payload):
        length, height = seeds._capacity(binding)
        ids = dict(payload['element_ids'])
        items, occupied = [], set()
        for prop in payload['props']:
            if (not prop.keys() <= {'gid','template_id','quantity','grid_page_id','x','y','length','width','rotated','source_note'} or
                    prop['grid_page_id'] != 302 or type(prop.get('rotated', 0)) not in (int, bool) or
                    prop.get('rotated', 0) not in (0, 1)):
                raise ValueError('Feature-bearing or differently located box stock needs a qualified complete producer')
            seed = seeds.build_seed(binding, drops=((prop['template_id'], prop['quantity']),), allocated_gids=(prop['gid'],))
            original = seed.items[0].item
            base = inventory.base_item(original)
            if (prop['width'], prop['length']) != (base.location.length, base.location.height):
                raise ValueError('The actual complete box instance dimensions changed')
            location = InventoryItemLocation(prop['x'], prop['y'], prop['width'], prop['length'], bool(prop.get('rotated', 0)), 1)
            w, h = (location.height, location.length) if location.rotated else (location.length, location.height)
            if (any(type(v) is not int for v in (location.x, location.y)) or location.x < 0 or location.y < 0 or
                    location.x + w > length or location.y + h > height):
                raise ValueError('The actual box stock exceeds its source capacity')
            cells = {(x, y) for x in range(location.x, location.x+w) for y in range(location.y, location.y+h)}
            if occupied & cells:
                raise ValueError('The actual box stock positions overlap')
            occupied.update(cells)
            def relocate(item):
                if type(item) is type(base):
                    return replace(item, location=location)
                return replace(item, item=relocate(item.item))
            items.append(InventoryFastArrayElement(ids[prop['gid']], relocate(original)))
        items = tuple(sorted(items, key=lambda element: element.element_id))
        boxes.validate_items(items)
        spaces = (InventorySpace(302, 1, (InventorySpaceGrid(1, 0, 0, length, height, 0, 0),)),)
        return LootSnapshot(binding.object_path, payload['revision'], spaces, items)

    def _box_snapshot(self, connection, binding):
        return self._typed_box(binding, self._box_payload(connection, binding))

    def _inventory_payload(self, connection, session, *, initial=False):
        document = json.loads(session['initial_json' if initial else 'current_json'])
        ids = self._ids(connection, 'player:' + self._credential.admission_id)
        if not {prop['gid'] for prop in inventory._props(document)} <= ids.keys():
            raise ValueError('An outside writer changed this admission without its stable native journal')
        return dict(revision=1 if initial else session['revision'], document=document,
            element_ids=tuple((prop['gid'], ids[prop['gid']]) for prop in inventory._props(document)))

    def _typed_inventory(self, payload):
        projection = inventory.build(payload['document'], value_fields=(0,0,0,0,0,0,0),
            owner_player_id=self._credential.player_id, space_revision=1)
        ids = dict(payload['element_ids'])
        items = tuple(sorted((replace(element, element_id=ids[inventory.base_item(element.item).item_gid])
            for element in projection.items), key=lambda element: element.element_id))
        boxes.validate_items(items)
        return LootSnapshot('player:' + str(self._credential.player_id), payload['revision'], projection.repdata.spaces, items)

    def _inventory_snapshot(self, connection, session, *, initial=False):
        return self._typed_inventory(self._inventory_payload(connection, session, initial=initial))

    def initial_inventory_snapshot(self):
        with self._lock, self._store._transaction() as connection:
            self._current()
            session = self._store._auth(connection, self._credential)
            return self._inventory_snapshot(connection, session, initial=True)

    def inventory_snapshot(self):
        with self._lock, self._store._transaction() as connection:
            self._current()
            session = self._store._auth(connection, self._credential)
            return self._inventory_snapshot(connection, session)

    def box_snapshot(self, object_path):
        """Refresh an already opened observer from one consistent SQL snapshot."""
        with self._lock, self._store._transaction() as connection:
            context = self._context()
            self._store._auth(connection, self._credential, active=True)
            candidates = [(guid, binding) for guid, binding in self._bindings.items() if binding.object_path == object_path]
            if len(candidates) != 1 or connection.execute(
                    'SELECT 1 FROM world_open_v1 WHERE admission_id=? AND path=?',
                    (self._credential.admission_id, object_path)).fetchone() is None:
                raise ValueError('Only a current already opened actual box observer may refresh')
            guid, binding = candidates[0]
            self._gate(connection, guid, context, operation='browse')
            return self._box_snapshot(connection, binding)

    def _open(self, connection, request, guid, context, cursor, tag=OPEN_TAG):
        self._store._auth(connection, self._credential, active=True)
        binding = self._gate(connection, guid, context, tag)
        opened = None if self._normal_box_policy is None else self._normal_box_policy.mark_open(
            connection, self._credential, binding)
        connection.execute('INSERT OR IGNORE INTO world_open_v1 VALUES (?,?)',
            (self._credential.admission_id, binding.object_path))
        snapshot = self._box_snapshot(connection, binding)
        projection = boxes.project(binding, snapshot.spaces, snapshot.items, recipient_scope=self._recipient,
            cursor=cursor, opened=opened)
        return OpenDispatchResult(request, snapshot, projection)

    def open_field(self, field, *, cursor=None):
        with self._lock, self._store._transaction() as connection:
            context = self._context()
            request = opens.decode_field(field, bindings_by_guid=self._bindings,
                references_resolved=context.references_resolved, exports_acknowledged=context.exports_acknowledged,
                recipient_scope=self._recipient)
            return self._open(connection, request, request.box_guid, context, cursor)

    def interact_field(self, field, *, cursor=None):
        with self._lock, self._store._transaction() as connection:
            context = self._context()
            request = interactions.decode_field(field, bindings_by_guid=self._bindings,
                references_resolved=context.references_resolved, exports_acknowledged=context.exports_acknowledged,
                nonfast_replication_confirmed=context.nonfast_replication_confirmed)
            if request.operator_tag != OPEN_TAG:
                raise ValueError('Only the actual server-permitted box-open operator is implemented')
            return self._open(connection, request, request.target_guid, context, cursor, request.operator_tag)

    def move_field(self, field, *, expected_revision):
        return self.move_request(moves.decode_field(field), expected_revision=expected_revision)

    def move_bunch(self, bunch, *, pawn_channel, inventory_manager_guid, expected_revision):
        return self.move_request(moves.decode_bunch(bunch, pawn_channel=pawn_channel,
            inventory_manager_guid=inventory_manager_guid), expected_revision=expected_revision)

    def _result(self, request, binding, payload):
        box_snapshot = self._typed_box(binding, payload['box'])
        inventory_snapshot = self._typed_inventory(payload['inventory'])
        destination, = (element for element in inventory_snapshot.items
                        if inventory.base_item(element.item).item_gid == request.source_gid)
        receipt = TransferReceipt(destination_element=destination, **payload['receipt'])
        return MoveDispatchResult(request, receipt, box_snapshot, inventory_snapshot)

    def move_request(self, request, *, expected_revision):
        if type(request) is not moves.ItemMoveRequest:
            raise ValueError('An exact decoded native ItemMove request is required')
        _uint(request.command_gid, 'CmdGid')
        _uint(request.source_gid, 'source GID')
        if (request.source_position != 302 or request.target_gids or request.target_loot_guids or
                request.source_weapon_gid or request.target_weapon_gid or request.source_space_guid or
                request.target_space_guid or request.spaces_to_sync_guids or request.allow_relocate or
                request.allow_container_replace_backup or request.drop_container_items or request.force_replace_shell or
                request.command_owner_guid not in (0, self._player_actor_guid) or
                type(request.target_position) is not int or 100 <= request.target_position <= 160):
            raise ValueError('Only one mapped box whole-instance move to explicit free inventory cells is implemented')
        native = _json(asdict(request))
        with self._lock, self._store._transaction() as connection:
            context = self._context()
            session = self._store._auth(connection, self._credential, active=True)
            binding = self._gate(connection, request.source_loot_guid, context, operation='source_transfer')
            previous = connection.execute('SELECT * FROM durable_world_native_command_v1 WHERE admission_id=? AND cmd_gid=?',
                (self._credential.admission_id, str(request.command_gid))).fetchone()
            if previous is not None:
                if previous['native_json'] != native:
                    raise ValueError('A CmdGid was reused for a different native request')
                if hashlib.sha256(previous['result_json'].encode()).hexdigest() != previous['result_sha256']:
                    raise ValueError('The immutable durable native result identity changed')
                return self._result(request, binding, json.loads(previous['result_json']))
            if connection.execute('SELECT COUNT(*) FROM durable_world_native_command_v1 WHERE admission_id=?',
                    (self._credential.admission_id,)).fetchone()[0] >= 4096:
                raise ValueError('The finite native request journal bound is exhausted')
            if connection.execute('SELECT 1 FROM world_command_v1 WHERE admission_id=? AND cmd_gid=?',
                    (self._credential.admission_id, str(request.command_gid))).fetchone() is not None:
                raise ValueError('An outside dispatcher already owns this durable CmdGid')
            if type(expected_revision) is not int or expected_revision != session['revision']:
                raise ValueError('The actual inventory revision is stale')
            if connection.execute('SELECT 1 FROM world_open_v1 WHERE admission_id=? AND path=?',
                    (self._credential.admission_id, binding.object_path)).fetchone() is None:
                raise ValueError('The actual source box must be opened by this admitted player')
            source = self._box_snapshot(connection, binding)
            before = self._inventory_snapshot(connection, session)
            candidates = [element for element in source.items if inventory.base_item(element.item).item_gid == request.source_gid]
            if len(candidates) != 1 or request.move_count != boxes.item_quantity(candidates[0].item):
                raise ValueError('The actual finite whole-instance quantity differs or is no longer in this box')
            if max(source.revision, before.revision) >= (1 << 31) - 1:
                raise ValueError('The authoritative content revision namespace is exhausted')
            grid = next((grid for space in before.spaces if space.space_type == request.target_position
                         for grid in space.grids if grid.grid_id == request.target_index), None)
            if grid is None or request.target_position == 116001:
                raise ValueError('The chosen carried destination needs a qualified ordinary source grid')
            if (type(request.target_x) is not int or type(request.target_y) is not int or
                    type(request.rotated) is not bool or not 0 <= request.target_x <= 255 or not 0 <= request.target_y <= 255):
                raise ValueError('Explicit native grid coordinates and rotation are required')
            destination = dict(grid_page_id=request.target_position, x=request.target_index,
                y=request.target_y * grid.length + request.target_x, rotated=int(request.rotated), space_width=grid.length)
            row = connection.execute('SELECT prop_json FROM world_item_v1 WHERE room_id=? AND gid=? AND owner=?',
                (str(self._credential.room_id), str(request.source_gid), binding.object_path)).fetchone()
            if row is None:
                raise ValueError('The actual finite instance belongs to another owner')
            prop = json.loads(row['prop_json'])
            prop.update(destination)
            source_base = inventory.base_item(candidates[0].item)
            # Body rows persist displayed dimensions; native locations retain
            # the original dimensions plus rotation (InitFromPb equivalence).
            prop['width'], prop['length'] = ((source_base.location.height, source_base.location.length)
                if request.rotated else (source_base.location.length, source_base.location.height))
            document = json.loads(session['current_json'])
            document['props'].append(prop)
            owner = 'player:' + self._credential.admission_id
            self._allocate(connection, owner, request.source_gid)
            connection.execute('UPDATE world_item_v1 SET owner=?,prop_json=? WHERE room_id=? AND gid=? AND owner=?',
                (owner, _json(prop), str(self._credential.room_id), str(request.source_gid), binding.object_path))
            connection.execute('UPDATE world_session_v1 SET current_json=?,revision=revision+1 WHERE admission_id=?',
                (_json(document), self._credential.admission_id))
            connection.execute('UPDATE durable_world_box_v1 SET revision=revision+1 WHERE room_id=? AND path=?',
                (str(self._credential.room_id), binding.object_path))
            updated = self._store._auth(connection, self._credential, active=True)
            payload = dict(box=self._box_payload(connection, binding), inventory=self._inventory_payload(connection, updated),
                receipt=dict(match_id=self._recipient[0], player_id=self._credential.player_id,
                    cmd_gid=request.command_gid, item_gid=request.source_gid,
                    template_id=prop['template_id'], quantity=prop['quantity'], source_path=binding.object_path,
                    source_deleted_element_id=candidates[0].element_id, source_revision=source.revision+1,
                    destination_revision=before.revision+1, source_is_empty=len(source.items)==1))
            result = self._result(request, binding, payload)
            if result.inventory_snapshot.items != before.items + (result.receipt.destination_element,):
                raise ValueError('A whole-instance transfer cannot change existing native inventory items')
            desired = InventoryItemLocation(request.target_x, request.target_y,
                source_base.location.length, source_base.location.height,
                request.rotated and source_base.location.length != source_base.location.height, request.target_index)
            if inventory.base_item(result.receipt.destination_element.item).location != desired:
                raise ValueError('The native request destination differs from its durable business location')
            pickup = PickupReceipt(self._credential.room_id, self._credential.player_id, request.command_gid,
                request.source_gid, prop['quantity'], updated['revision'], binding.object_path)
            intent = _json(dict(box_path=binding.object_path, item_gid=request.source_gid, destination=destination))
            connection.execute('INSERT INTO world_command_v1 VALUES (?,?,?,?)',
                (self._credential.admission_id, str(request.command_gid), intent, _json(asdict(pickup))))
            raw = _json(payload)
            connection.execute('INSERT INTO durable_world_native_command_v1 VALUES (?,?,?,?,?)',
                (self._credential.admission_id, str(request.command_gid), native, raw, hashlib.sha256(raw.encode()).hexdigest()))
            return result

    def project_box(self, object_path, snapshot, cursor):
        """WorldDeliveryProfile callback; Control alone records actual stage ACKs."""
        with self._lock, self._store._transaction() as connection:
            context = self._context()
            candidates = [(guid, binding) for guid, binding in self._bindings.items() if binding.object_path == object_path]
            if len(candidates) != 1:
                raise ValueError('The actual current source box is outside this dispatcher')
            guid, binding = candidates[0]
            self._store._auth(connection, self._credential)
            if guid not in context.ready_box_guids or type(snapshot) is not LootSnapshot or snapshot != self._box_snapshot(connection, binding):
                raise ValueError('Only the current committed actual box snapshot may be delivered')
            opened = None
            if self._normal_box_policy is not None:
                self._normal_box_policy.authorize(connection, self._credential, binding, operation='browse')
                opened = self._normal_box_policy.opened(connection, self._credential, binding)
            projection = boxes.project(binding, snapshot.spaces, snapshot.items, recipient_scope=self._recipient,
                cursor=cursor, opened=opened)
            return WorldBoxProjection(object_path, snapshot.revision, projection.stages, projection.cursor_after_ack)

    def terminal(self, *, command_id, reason_name, expected_revision, terminal_evidence_sha256, retained_gids):
        """Return a native-notification result only after actual account commit."""
        with self._lock:
            if self._terminal_allowed is None:
                raise ValueError('The actual server terminal authority is unavailable')
            self._current()
            args = dict(command_id=command_id, reason_name=reason_name, expected_revision=expected_revision,
                terminal_evidence_sha256=terminal_evidence_sha256, retained_gids=retained_gids)
            if self._terminal_allowed(credential=self._credential, **args) is not True:
                raise ValueError('The actual server terminal condition rejects this evidence and retained inventory')
            receipt = self._store.commit_terminal(self._credential, **args)
            self._store.materialize_terminal(self._credential, receipt.result_sha256, materialize)
            return self._store.match_over_result(self._credential)
