"""Durable local finite-item sessions; no sockets, process access or native RPC guesses.

Admission credentials and accepted coordinates come from the trusted transport
adapter. Terminal evidence is an identity for its validated server condition,
not a client-supplied claim. Account writes happen only through the explicit
same-connection materializer; native notifications must wait for that commit.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field, replace
import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import sqlite3

import portable_loot_box_codec as boxes
import portable_map_inventory as inventory
from portable_match_end_values import CommittedTerminalResult

ROOT = Path(__file__).resolve().parent.parent
FLOW_SOURCE = 'work/evidence/map-system-audit-20261018/native-local-settlement-flow-v2-qualified.json'
FLOW_SHA256 = 'd4d66055c77244a4f58c2cd9b1d87461e1631b87ebc4d880a809e2a20784fd91'
RPC_SOURCE = 'work/native-client-tests/1792376752204334900/world-interaction-rpc-metadata.json'
RPC_SHA256 = 'e664315f6fe4fb60f91eb0e0dfceee6fe01017f1acc39c40d7424ebc3e6a8a2b'
TERMINAL_REASONS = ('Escaped', 'Dead', 'TimeOver', 'Quit', 'GiveUp')
DESTINATION_FIELDS = frozenset(('grid_page_id', 'x', 'y', 'rotated', 'space_width'))

SCHEMA = '''
CREATE TABLE IF NOT EXISTS world_session_v1 (
 admission_id TEXT PRIMARY KEY, room_id TEXT NOT NULL, player_id TEXT NOT NULL,
 token_sha256 TEXT NOT NULL, initial_json TEXT NOT NULL, current_json TEXT NOT NULL,
 revision INTEGER NOT NULL, phase TEXT NOT NULL, source_pins_json TEXT NOT NULL,
 UNIQUE(room_id, player_id));
CREATE TABLE IF NOT EXISTS world_box_v1 (
 room_id TEXT NOT NULL, path TEXT NOT NULL, position_json TEXT NOT NULL,
 PRIMARY KEY(room_id, path));
CREATE TABLE IF NOT EXISTS world_item_v1 (
 room_id TEXT NOT NULL, gid TEXT NOT NULL, owner TEXT NOT NULL, prop_json TEXT NOT NULL,
 PRIMARY KEY(room_id, gid));
CREATE TABLE IF NOT EXISTS world_instance_gid_v1 (
 room_id TEXT NOT NULL, gid TEXT NOT NULL, root_gid TEXT NOT NULL,
 PRIMARY KEY(room_id, gid));
CREATE TABLE IF NOT EXISTS world_open_v1 (
 admission_id TEXT NOT NULL, path TEXT NOT NULL, PRIMARY KEY(admission_id, path));
CREATE TABLE IF NOT EXISTS world_command_v1 (
 admission_id TEXT NOT NULL, cmd_gid TEXT NOT NULL, intent_json TEXT NOT NULL,
 receipt_json TEXT NOT NULL, PRIMARY KEY(admission_id, cmd_gid));
CREATE TABLE IF NOT EXISTS world_terminal_v1 (
 admission_id TEXT PRIMARY KEY, command_id TEXT NOT NULL, intent_json TEXT NOT NULL,
 result_sha256 TEXT NOT NULL UNIQUE, receipt_json TEXT NOT NULL, inventory_applied INTEGER NOT NULL);
'''


@dataclass(frozen=True)
class SessionCredential:
    admission_id: str
    room_id: int
    player_id: int
    token: bytes = field(repr=False)


@dataclass(frozen=True)
class SessionSnapshot:
    revision: int
    snapshot: dict


@dataclass(frozen=True)
class PickupReceipt:
    room_id: int
    player_id: int
    cmd_gid: int
    item_gid: int
    quantity: int
    revision: int
    source_box_path: str


@dataclass(frozen=True)
class TerminalReceipt:
    room_id: int
    player_id: int
    admission_id: str
    reason_name: str
    terminal_evidence_sha256: str
    inventory_revision: int
    result_sha256: str
    carry_in_snapshot: dict
    carry_out_snapshot: dict
    inventory_applied: bool


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _uint(value, label):
    if type(value) is not int or not 0 < value < 1 << 64:
        raise ValueError('An actual positive uint64 ' + label + ' is required')
    return value


def _text(value, label):
    if type(value) is not str or not 1 <= len(value) <= 256:
        raise ValueError('An explicit bounded ' + label + ' is required')
    return value


def _position(value):
    if type(value) is not tuple or len(value) != 3 or any(
            type(v) not in (int, float) or not math.isfinite(v) for v in value):
        raise ValueError('An actual finite accepted server position is required')
    return value


def source_qualification():
    """Retain actual evidence and distinguish declarations from missing RPC layouts."""
    pins = inventory.source_pins()
    documents = {}
    for relative, digest in ((FLOW_SOURCE, FLOW_SHA256), (RPC_SOURCE, RPC_SHA256)):
        raw = (ROOT / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Changed world session source ' + relative)
        documents[relative] = json.loads(raw)
        pins[relative] = digest
    flow = documents[FLOW_SOURCE]
    if flow['process_access'] is not False or flow['client_launched'] is not False:
        raise ValueError('The settlement source must remain offline installed evidence')
    enums = flow['qualified_flow']['actual_enums']
    if (enums['ESettlementNtf']['values']['SNTF_SOL'] != 3 or
            enums['EGspPlayerResultType']['values']['kGspPlayerResultEscaped'] != 0 or
            enums['EGspPlayerGameStatusType']['values']['kGspPlayerGameStatusTypeEndGame'] != 1):
        raise ValueError('The source settlement enum changed')
    rpc = documents[RPC_SOURCE]
    if rpc['status'] != 'observed' or rpc['client_sha256'] != boxes.CLIENT_SHA256:
        raise ValueError('The current interaction metadata identity changed')
    rpc_limits = tuple(dict(owner=owner['scope'], function=row['function_name'],
        network_index=row['network_index'], layout_status=row['layout_status'],
        codec_recovered=row['rpc_parameter_codec_recovered'])
        for owner in rpc['owners'] for row in owner['rpc_functions'])
    pins['work/portable_world_session.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return dict(source_pins=pins, settlement_enums=enums,
        actual_rpc_qualification=rpc_limits, native_wire_implemented=False,
        account_materialization_required_before_notification=True,
        coordinate_and_terminal_validation_owned_by_server_adapter=True,
        local_policy='whole-instance finite stock, explicit retained GIDs, no generated rewards')


class DurableWorldSession:
    """New namespaced tables; instantiate on a temporary DB for offline qualification."""
    def __init__(self, database_path):
        self.database_path = str(database_path)
        self.qualification = source_qualification()
        catalogs = boxes._sources()
        self.catalog = catalogs['outputs/df-local-server/protocol/game_item_catalog.json']['rows']
        self.receivers = catalogs['outputs/df-local-server/protocol/weapon_component_catalog.json']['rows']
        with self._connection() as connection:
            connection.executescript(SCHEMA)

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.database_path, timeout=15, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self):
        with self._connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                yield connection
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def _auth(self, connection, credential, *, active=False):
        if type(credential) is not SessionCredential or type(credential.token) is not bytes or len(credential.token) != 32:
            raise ValueError('An actual admitted session credential is required')
        _uint(credential.room_id, 'room ID')
        _uint(credential.player_id, 'player ID')
        row = connection.execute('SELECT * FROM world_session_v1 WHERE admission_id=?',
            (_text(credential.admission_id, 'admission ID'),)).fetchone()
        if (row is None or row['room_id'] != str(credential.room_id) or
                row['player_id'] != str(credential.player_id) or not hmac.compare_digest(
                    row['token_sha256'], hashlib.sha256(credential.token).hexdigest())):
            raise ValueError('The admission room/player credential is foreign or expired')
        if row['source_pins_json'] != _json(self.qualification['source_pins']):
            raise ValueError('The frozen admission source contracts differ from the current qualified implementation')
        if active and row['phase'] != 'active':
            raise ValueError('This admitted session already has an immutable terminal result')
        return row

    def admit(self, *, room_id, player_id, admission_id, token, snapshot):
        credential = SessionCredential(_text(admission_id, 'admission ID'),
            _uint(room_id, 'room ID'), _uint(player_id, 'player ID'), token)
        if type(token) is not bytes or len(token) != 32:
            raise ValueError('An explicit 32-byte server admission token is required')
        snapshot = deepcopy(inventory._document(snapshot))
        inventory.build_items(snapshot, owner_player_id=player_id)
        raw = _json(snapshot)
        try:
            with self._transaction() as connection:
                previous = connection.execute('SELECT * FROM world_session_v1 WHERE admission_id=?',
                    (admission_id,)).fetchone()
                if previous is not None:
                    self._auth(connection, credential)
                    if previous['initial_json'] != raw:
                        raise ValueError('An admission cannot replace its frozen carried snapshot')
                    return credential
                connection.execute('INSERT INTO world_session_v1 VALUES (?,?,?,?,?,?,1,?,?)',
                    (admission_id, str(room_id), str(player_id), hashlib.sha256(token).hexdigest(),
                     raw, raw, 'active', _json(self.qualification['source_pins'])))
                for prop in inventory._props(snapshot):
                    self._reserve_instance(connection, room_id, prop)
                    connection.execute('INSERT INTO world_item_v1 VALUES (?,?,?,?)',
                        (str(room_id), str(prop['gid']), 'player:' + admission_id, _json(prop)))
        except sqlite3.IntegrityError as error:
            raise ValueError('A room/player admission or actual item GID is already reserved') from error
        return credential

    def _reserve_instance(self, connection, room_id, prop):
        gids = (prop['gid'],)
        if str(prop['template_id']) in self.receivers:
            description = inventory.gun_from_snapshot_prop(prop)
            gids = tuple(row.gid for row in description.rows) + tuple(row.gid for row in description.ammo)
        for gid in gids:
            connection.execute('INSERT INTO world_instance_gid_v1 VALUES (?,?,?)',
                (str(room_id), str(gid), str(prop['gid'])))

    def current_snapshot(self, credential):
        with self._connection() as connection:
            row = self._auth(connection, credential)
            return SessionSnapshot(row['revision'], json.loads(row['current_json']))

    def seed_box(self, credential, binding, props, *, world_position):
        boxes.qualify_binding(binding)
        _position(world_position)
        if type(props) is not tuple or len(props) > boxes.MAX_ITEMS:
            raise ValueError('A bounded finite complete-instance tuple is required')
        for prop in props:
            if type(prop) is not dict:
                raise ValueError('A complete source-qualified item record is required')
            _uint(prop.get('gid'), 'item GID')
            row = self.catalog.get(str(prop.get('template_id')))
            if (row is None or type(prop.get('quantity')) is not int or
                    not 1 <= prop['quantity'] <= row['max_stack_count'] or
                    (prop.get('width'), prop.get('length')) != (row['width'], row['length'])):
                raise ValueError('The finite item template, stack or geometry differs from its installed source')
        try:
            with self._transaction() as connection:
                self._auth(connection, credential, active=True)
                connection.execute('INSERT INTO world_box_v1 VALUES (?,?,?)',
                    (str(credential.room_id), binding.object_path, _json(world_position)))
                for prop in props:
                    self._reserve_instance(connection, credential.room_id, prop)
                    connection.execute('INSERT INTO world_item_v1 VALUES (?,?,?,?)',
                        (str(credential.room_id), str(prop['gid']), binding.object_path, _json(prop)))
        except sqlite3.IntegrityError as error:
            raise ValueError('Finite box stock cannot refill or alias an actual item GID') from error

    def _near(self, connection, credential, box_path, position, maximum):
        _position(position)
        if type(maximum) not in (int, float) or not math.isfinite(maximum) or not 0 < maximum <= 10000:
            raise ValueError('An explicit bounded local interaction distance is required')
        row = connection.execute('SELECT position_json FROM world_box_v1 WHERE room_id=? AND path=?',
            (str(credential.room_id), box_path)).fetchone()
        if row is None or math.dist(position, json.loads(row['position_json'])) > maximum:
            raise ValueError('The registered source box is absent or outside accepted server interaction range')

    def _contents(self, connection, credential, box_path):
        return tuple(json.loads(row['prop_json']) for row in connection.execute(
            'SELECT prop_json FROM world_item_v1 WHERE room_id=? AND owner=? ORDER BY gid',
            (str(credential.room_id), box_path)))

    def box_contents(self, credential, box_path):
        with self._connection() as connection:
            self._auth(connection, credential)
            if connection.execute('SELECT 1 FROM world_open_v1 WHERE admission_id=? AND path=?',
                    (credential.admission_id, box_path)).fetchone() is None:
                raise ValueError('The actual source box must be opened before reading its contents')
            return self._contents(connection, credential, box_path)

    def open_box(self, credential, box_path, *, accepted_server_position, maximum_distance_cm):
        with self._transaction() as connection:
            self._auth(connection, credential, active=True)
            self._near(connection, credential, box_path, accepted_server_position, maximum_distance_cm)
            connection.execute('INSERT OR IGNORE INTO world_open_v1 VALUES (?,?)',
                (credential.admission_id, box_path))
            return self._contents(connection, credential, box_path)

    def pickup(self, credential, *, cmd_gid, box_path, item_gid, destination,
            accepted_server_position, maximum_distance_cm, expected_revision):
        _uint(cmd_gid, 'CmdGid')
        _uint(item_gid, 'item GID')
        if (type(destination) is not dict or not {'grid_page_id', 'x', 'y', 'rotated'} <= destination.keys()
                or not destination.keys() <= DESTINATION_FIELDS):
            raise ValueError('Only an explicit native inventory destination may change')
        if (any(type(destination[key]) is not int for key in destination if key != 'rotated') or
                type(destination['rotated']) not in (int, bool) or destination['rotated'] not in (0, 1)):
            raise ValueError('The native destination requires exact integer coordinates and a binary rotation')
        if type(destination['grid_page_id']) is not int or 100 <= destination['grid_page_id'] <= 160:
            raise ValueError('Equipment and weapon lifecycle changes need their own qualified receiver')
        intent = _json(dict(box_path=box_path, item_gid=item_gid, destination=destination))
        with self._transaction() as connection:
            session = self._auth(connection, credential, active=True)
            previous = connection.execute('SELECT * FROM world_command_v1 WHERE admission_id=? AND cmd_gid=?',
                (credential.admission_id, str(cmd_gid))).fetchone()
            if previous is not None:
                if previous['intent_json'] != intent:
                    raise ValueError('A CmdGid was reused for a different finite pickup')
                return PickupReceipt(**json.loads(previous['receipt_json']))
            if type(expected_revision) is not int or expected_revision != session['revision']:
                raise ValueError('The actual inventory revision is stale')
            self._near(connection, credential, box_path, accepted_server_position, maximum_distance_cm)
            if connection.execute('SELECT 1 FROM world_open_v1 WHERE admission_id=? AND path=?',
                    (credential.admission_id, box_path)).fetchone() is None:
                raise ValueError('The source box must be opened by this admitted player')
            item = connection.execute('SELECT * FROM world_item_v1 WHERE room_id=? AND gid=? AND owner=?',
                (str(credential.room_id), str(item_gid), box_path)).fetchone()
            if item is None:
                raise ValueError('The finite item is absent or belongs to a different owner')
            prop = json.loads(item['prop_json'])
            prop.update(destination)
            snapshot = json.loads(session['current_json'])
            snapshot['props'].append(prop)
            inventory.build_items(snapshot, owner_player_id=credential.player_id,
                space_revision=session['revision'] + 1)
            receipt = PickupReceipt(credential.room_id, credential.player_id, cmd_gid, item_gid,
                prop['quantity'], session['revision'] + 1, box_path)
            connection.execute('UPDATE world_item_v1 SET owner=?,prop_json=? WHERE room_id=? AND gid=?',
                ('player:' + credential.admission_id, _json(prop), str(credential.room_id), str(item_gid)))
            connection.execute('UPDATE world_session_v1 SET current_json=?,revision=? WHERE admission_id=?',
                (_json(snapshot), receipt.revision, credential.admission_id))
            connection.execute('INSERT INTO world_command_v1 VALUES (?,?,?,?)',
                (credential.admission_id, str(cmd_gid), intent, _json(receipt.__dict__)))
            return receipt

    def _terminal(self, connection, credential):
        row = connection.execute('SELECT * FROM world_terminal_v1 WHERE admission_id=?',
            (credential.admission_id,)).fetchone()
        if row is None:
            return None
        receipt = json.loads(row['receipt_json'])
        if hashlib.sha256(_json(receipt).encode()).hexdigest() != row['result_sha256']:
            raise ValueError('The persisted terminal result identity is inconsistent')
        return TerminalReceipt(**receipt, result_sha256=row['result_sha256'],
            inventory_applied=bool(row['inventory_applied']))

    def read_terminal(self, credential):
        with self._connection() as connection:
            self._auth(connection, credential)
            return self._terminal(connection, credential)

    def commit_terminal(self, credential, *, command_id, reason_name, expected_revision,
            terminal_evidence_sha256, retained_gids):
        _text(command_id, 'terminal command identity')
        if (type(reason_name) is not str or reason_name not in TERMINAL_REASONS or
                type(terminal_evidence_sha256) is not str or
                re.fullmatch('[0-9a-f]{64}', terminal_evidence_sha256) is None or
                type(retained_gids) is not tuple or len(retained_gids) != len(set(retained_gids))):
            raise ValueError('An actual terminal reason, server evidence and explicit retained GIDs are required')
        for gid in retained_gids:
            _uint(gid, 'retained item GID')
        intent = _json(dict(reason_name=reason_name, evidence=terminal_evidence_sha256,
            retained_gids=sorted(retained_gids), expected_revision=expected_revision))
        with self._transaction() as connection:
            session = self._auth(connection, credential)
            existing = connection.execute('SELECT * FROM world_terminal_v1 WHERE admission_id=?',
                (credential.admission_id,)).fetchone()
            if existing is not None:
                if existing['command_id'] != command_id or existing['intent_json'] != intent:
                    raise ValueError('The committed terminal result cannot be replaced or recommitted')
                return self._terminal(connection, credential)
            if type(expected_revision) is not int or expected_revision != session['revision']:
                raise ValueError('The terminal inventory revision is stale')
            snapshot = json.loads(session['current_json'])
            owned = {prop['gid'] for prop in inventory._props(snapshot)}
            retained = set(retained_gids)
            if not retained <= owned or reason_name == 'Escaped' and retained != owned:
                raise ValueError('Extraction must retain every actual owned GID; other outcomes require an explicit subset')
            carry_out = deepcopy(snapshot)
            carry_out['props'] = [prop for prop in snapshot['props'] if prop['gid'] in retained]
            melee = carry_out.get('selected_melee')
            if melee is not None and melee['gid'] not in retained:
                carry_out['selected_melee'] = None
            inventory.build_items(carry_out, owner_player_id=credential.player_id)
            values = dict(room_id=credential.room_id, player_id=credential.player_id,
                admission_id=credential.admission_id, reason_name=reason_name,
                terminal_evidence_sha256=terminal_evidence_sha256, inventory_revision=session['revision'],
                carry_in_snapshot=json.loads(session['initial_json']), carry_out_snapshot=carry_out)
            raw = _json(values)
            digest = hashlib.sha256(raw.encode()).hexdigest()
            connection.execute('INSERT INTO world_terminal_v1 VALUES (?,?,?,?,?,0)',
                (credential.admission_id, command_id, intent, digest, raw))
            connection.execute('UPDATE world_session_v1 SET phase=? WHERE admission_id=?',
                ('terminal_pending_materialization', credential.admission_id))
            return self._terminal(connection, credential)

    def materialize_terminal(self, credential, result_sha256, inventory_writer):
        """Run a trusted account writer exactly once in the same SQLite transaction.

        The callback receives (connection, terminal_receipt). It must use that
        connection for actual before/after account checks and writes and must not
        commit, roll back, perform external side effects or emit notifications.
        """
        if not callable(inventory_writer):
            raise ValueError('An explicit transactional actual-account inventory writer is required')
        with self._transaction() as connection:
            self._auth(connection, credential)
            receipt = self._terminal(connection, credential)
            if receipt is None or receipt.result_sha256 != result_sha256:
                raise ValueError('The actual saved terminal identity is required')
            if receipt.inventory_applied:
                return receipt
            conserved_snapshots = _json((receipt.carry_in_snapshot, receipt.carry_out_snapshot))
            def account_authorizer(action, first, second, database, trigger):
                if action in (sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_SAVEPOINT,
                        sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH):
                    return sqlite3.SQLITE_DENY
                if action != sqlite3.SQLITE_READ and first is not None and first.startswith('world_'):
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            connection.set_authorizer(account_authorizer)
            try:
                inventory_writer(connection, receipt)
            finally:
                connection.set_authorizer(None)
            if _json((receipt.carry_in_snapshot, receipt.carry_out_snapshot)) != conserved_snapshots:
                raise ValueError('The account materializer changed a conserved terminal snapshot')
            if not connection.in_transaction:
                raise ValueError('The inventory writer ended its required owning transaction')
            connection.execute('UPDATE world_terminal_v1 SET inventory_applied=1 WHERE admission_id=?',
                (credential.admission_id,))
            connection.execute('UPDATE world_session_v1 SET phase=? WHERE admission_id=?',
                ('terminal_materialized', credential.admission_id))
            return replace(receipt, inventory_applied=True)

    def match_over_result(self, credential):
        receipt = self.read_terminal(credential)
        if receipt is None or not receipt.inventory_applied:
            raise ValueError('Actual account inventory must be materialized before a native match-over notification')
        return CommittedTerminalResult(receipt.room_id, receipt.player_id,
            receipt.result_sha256, receipt.reason_name)
