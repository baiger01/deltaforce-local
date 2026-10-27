"""Apply a saved terminal receipt to the real account in its owning transaction.

Use as DurableWorldSession.materialize_terminal's callback. No connection,
transaction, notification, reward, permission or instance ID is created here.
The caller owns rollback on any exception, including a failed final readback.
"""
from copy import deepcopy
import hashlib
import json
import re
import sqlite3

from dfserver.app.core import Backend, CHEST_RIG_POSITION, BACKPACK_POSITION, SAFE_BOX_POSITION, POCKET_POSITION, KEYCHAIN_POSITION
from dfserver.match.native_match_loadout import ITEMS, SLOTS, ITEM_RAW, SLOT_RAW
from dfserver.inventory.native_keycards import catalog as keycard_catalog, keycard_fields
from dfserver.weapons.weapon_components import ROWS as RECEIVERS
from dfserver.weapons.weapon_ammo import magazine_capacity
from dfserver.weapons.melee_weapons import melee_prop, MELEE_POSITION
from dfserver.cosmetics import gun_skins
from dfserver.cosmetics import weapon_pendants
from dfserver.inventory import native_prop_bindings


SCHEMA = '''CREATE TABLE IF NOT EXISTS native_match_materializations_v1 (
 admission_id TEXT PRIMARY KEY, result_sha256 TEXT NOT NULL UNIQUE,
 native_id TEXT NOT NULL, account_player_id TEXT NOT NULL REFERENCES players(id),
 room_id TEXT NOT NULL, receipt_json TEXT NOT NULL, report_json TEXT NOT NULL)'''
ROOT_FIELDS = frozenset(('gid', 'template_id', 'quantity', 'grid_page_id', 'x', 'y', 'length', 'width'))
BINDING_FIELDS = frozenset(('bind_type', 'bind_player'))
PROP_FIELDS = ROOT_FIELDS | BINDING_FIELDS | {'rotated', 'space_width', 'components', 'weapon', 'health', 'health_max', 'expire_timestamp', 'source_note'}
WEAPON_FIELDS = frozenset(('load_bullets', 'skin_id', 'skin_gid', 'pendant_id', 'pendant_gid', 'magazine_capacity'))
BODY_POSITIONS = {CHEST_RIG_POSITION, BACKPACK_POSITION, SAFE_BOX_POSITION, POCKET_POSITION, KEYCHAIN_POSITION}
EQUIPMENT_POSITIONS = {int(key) for key, row in SLOTS.items()
                       if 100 < int(key) < 139 and int(row['grid_length']) > 0 and int(row['grid_width']) > 0}
CHILD_TABLES = ('native_lobby_weapon_parts', 'native_lobby_weapon_bullets',
                'native_lobby_assembled_weapons', 'native_lobby_weapon_skins', 'native_lobby_weapon_pendants')
INSTANCE_TABLES = ('native_lobby_props', 'native_lobby_weapon_parts', 'native_lobby_weapon_bullets',
                   'native_lobby_melee_props', 'native_lobby_melee_items', 'native_lobby_gun_skins',
                   'native_lobby_safe_box_permissions', 'native_lobby_pendant_instances',
                   'native_lobby_keychain_permissions')


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _integer(value, label, low=1, high=(1 << 63) - 1):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('Invalid persisted ' + label)
    return value


def _item(item_id, quantity):
    row = ITEMS.get(str(_integer(item_id, 'item ID')))
    if row is None or _integer(quantity, 'quantity', high=(1 << 31) - 1) > row['max_stack_count']:
        raise ValueError('Item or quantity has no installed account definition')
    return row


def _binding(value):
    if BINDING_FIELDS & value.keys():
        if not BINDING_FIELDS <= value.keys():
            raise ValueError('Incomplete persisted binding fields')
        _integer(value['bind_type'], 'binding type', low=0, high=2)
        _integer(value['bind_player'], 'binding player', low=0)


def _normalize(prop):
    if type(prop) is not dict or not ROOT_FIELDS <= prop.keys() or prop.keys() - PROP_FIELDS:
        raise ValueError('Unsupported or missing persisted item field')
    value = deepcopy(prop)
    value.pop('source_note', None)  # Provenance remains in the immutable receipt.
    _binding(value)
    for key in ROOT_FIELDS:
        _integer(value[key], key, low=0 if key in ('x', 'y') else 1,
                 high=(1 << 31) - 1 if key in ('quantity', 'grid_page_id', 'x', 'y', 'length', 'width') else (1 << 63) - 1)
    row = _item(value['template_id'], value['quantity'])
    rotated = value.get('rotated', 0)
    if type(rotated) not in (bool, int) or rotated not in (0, 1):
        raise ValueError('Invalid persisted rotation')
    value['rotated'] = int(rotated)
    if value['grid_page_id'] not in EQUIPMENT_POSITIONS | BODY_POSITIONS:
        raise ValueError('Terminal destination is not an admitted carried position')
    if value['grid_page_id'] in EQUIPMENT_POSITIONS and (value['x'] or value['y'] or rotated or value['quantity'] != 1):
        raise ValueError('Invalid carried equipment destination')
    if 'space_width' in value:
        _integer(value['space_width'], 'space width', high=100)
        value.pop('space_width')  # Derived from the actual equipped container.
    if 'expire_timestamp' in value:
        _integer(value['expire_timestamp'], 'permission expiry', low=0)
    is_card = str(value['template_id']) in keycard_catalog()['keycards']
    if 'health' in value or 'health_max' in value:
        if not is_card or set(('health', 'health_max')) - value.keys():
            raise ValueError('Condition has no qualified account persistence schema')
        if keycard_fields(value['template_id'], value['health']) != {k: value[k] for k in ('health', 'health_max')}:
            raise ValueError('Keycard condition differs from its installed maximum')
    elif is_card:
        raise ValueError('Actual keycard condition is required')
    components = value.get('components', [])
    weapon = value.get('weapon', {})
    receiver = str(value['template_id']) in RECEIVERS
    if not receiver and (components or weapon):
        raise ValueError('Item feature has no qualified persisted receiver')
    if receiver:
        if 'components' not in value or 'weapon' not in value or type(weapon) is not dict or weapon.keys() - WEAPON_FIELDS:
            raise ValueError('Actual persisted receiver components and weapon state are required')
        _parts(value)  # Validate the complete graph and every nested instance.
        for key in ('skin_id', 'skin_gid', 'pendant_id', 'pendant_gid'):
            _integer(weapon.get(key, 0), key, low=0)
        for prefix in ('skin', 'pendant'):
            if not weapon.get(prefix + '_id') and weapon.get(prefix + '_gid'):
                raise ValueError('An empty cosmetic cannot have an instance GID')
            weapon.setdefault(prefix + '_id', 0)
            weapon.setdefault(prefix + '_gid', 0)
        receiver_id = gun_skins.receiver(value['template_id'])
        if weapon['skin_id']:
            skin = gun_skins.SKINS.get(weapon['skin_id'])
            if skin is None or skin['weapon_id'] != receiver_id:
                raise ValueError('The installed skin belongs to another receiver')
        if weapon['pendant_id'] and (weapon['pendant_id'] not in weapon_pendants.PENDANTS or
                                    receiver_id not in weapon_pendants.PENDANT_RECEIVERS):
            raise ValueError('The installed receiver has no qualified pendant attachment')
        capacity = magazine_capacity(components, value['template_id'])
        if 'magazine_capacity' in weapon and weapon['magazine_capacity'] != capacity:
            raise ValueError('Magazine capacity hint differs from the installed components')
        weapon.pop('magazine_capacity', None)  # Derived, not a database column.
        if capacity is not None and sum(row['num'] for row in weapon['load_bullets']) > capacity:
            raise ValueError('Loaded ammunition exceeds the installed magazine capacity')
        value['components'] = _sorted_components(components)
    else:
        value.pop('components', None)
        value.pop('weapon', None)
    return value


def _sorted_components(components):
    return [dict(slot=row['slot'], prop_data={**row['prop_data'],
             'components': _sorted_components(row['prop_data']['components'])})
            for row in sorted(components, key=lambda row: (row['slot'], row['prop_data']['gid']))]


def _parts(prop):
    roots, bullets, seen = [], [], {prop['gid']}
    def visit(parent, children, depth=0):
        if type(children) is not list or len(children) > 64 or depth > 32:
            raise ValueError('Unbounded persisted component tree')
        slots = set()
        for child in children:
            if type(child) is not dict or set(child) != {'slot', 'prop_data'}:
                raise ValueError('Unsupported component slot record')
            slot = _integer(child['slot'], 'component slot', high=(1 << 32) - 1)
            node = child['prop_data']
            if (slot in slots or type(node) is not dict or
                    set(node) != {'id', 'gid', 'num', 'components', 'weapon'} or
                    node['num'] != 1 or node['weapon'] != {'load_bullets': []}):
                raise ValueError('Unsupported persisted component state')
            slots.add(slot)
            _item(node['id'], node['num'])
            gid = _integer(node['gid'], 'component GID')
            if gid in seen or len(seen) >= 64:
                raise ValueError('Duplicate or excessive component GID')
            seen.add(gid)
            roots.append((gid, prop['gid'], parent, slot, node['id']))
            visit(gid, node['components'], depth + 1)
    visit(prop['gid'], prop['components'])
    ammo = prop['weapon'].get('load_bullets')
    if type(ammo) is not list or len(ammo) > 32:
        raise ValueError('Actual bounded loaded ammunition is required')
    for row in ammo:
        if (type(row) is not dict or not {'id', 'gid', 'num'} <= row.keys() or
                row.keys() - {'id', 'gid', 'num'} - BINDING_FIELDS):
            raise ValueError('Unsupported persisted loaded ammunition state')
        _binding(row)
        _item(row['id'], row['num'])
        gid = _integer(row['gid'], 'ammunition GID')
        if gid in seen:
            raise ValueError('Duplicate nested ammunition GID')
        seen.add(gid)
        bullets.append((gid, prop['gid'], row['id'], row['num']))
    return roots, bullets


def _snapshot(snapshot):
    if (type(snapshot) is not dict or snapshot.get('kind') != 'local_account_carried_loadout_v1' or
            snapshot.get('source_item_catalog_sha256') != hashlib.sha256(ITEM_RAW).hexdigest() or
            snapshot.get('source_slot_catalog_sha256') != hashlib.sha256(SLOT_RAW).hexdigest() or
            type(snapshot.get('props')) is not list or len(snapshot['props']) > 2048):
        raise ValueError('Actual catalog-qualified carried snapshot is required')
    props = [_normalize(prop) for prop in snapshot['props']]
    by_gid = {prop['gid']: prop for prop in props}
    if len(by_gid) != len(props):
        raise ValueError('Repeated physical root GID')
    instances = {}
    for prop in props:
        entries = [(prop['gid'], prop['template_id'])]
        if str(prop['template_id']) in RECEIVERS:
            parts, ammo = _parts(prop)
            entries.extend((row[0], row[4]) for row in parts)
            entries.extend((row[0], row[2]) for row in ammo)
        for gid, item_id in entries:
            if gid in instances:
                raise ValueError('Physical GID reused between roots or nested instances')
            instances[gid] = item_id
    return by_gid, instances


def _read_prop(connection, player, gid, expected=None):
    row = connection.execute('SELECT p.gid,p.template_id,p.quantity,p.grid_page_id,p.x,p.y,p.length,p.width,'
        'COALESCE(r.rotated,0) AS rotated FROM native_lobby_props p '
        'LEFT JOIN native_lobby_prop_rotations r ON r.gid=p.gid WHERE p.player_id=? AND p.gid=?', (player, gid)).fetchone()
    if row is None:
        raise ValueError('The carry-in instance is missing or changed owner')
    # Detect hidden orphan/cyclic rows that the recursive account projection omits.
    projected = Backend._container_prop(connection, player, row)
    if expected is not None and 'space_width' in expected and projected.get('space_width') != expected['space_width']:
        raise ValueError('Snapshot width hint differs from the actual equipped container')
    normalized = _normalize(projected)
    if str(normalized['template_id']) in RECEIVERS:
        parts, ammo = _parts(normalized)
        actual = tuple(tuple(row) for row in connection.execute('SELECT gid,weapon_gid,parent_gid,slot,template_id '
            'FROM native_lobby_weapon_parts WHERE weapon_gid=? ORDER BY gid', (gid,)))
        if actual != tuple(sorted(parts)):
            raise ValueError('The carry-in nested component graph changed or contains orphans')
    return normalized


def _remove_weapon_features(connection, gid):
    # The world session can own a connection without SQLite cascades enabled.
    connection.execute('DELETE FROM native_lobby_loaded_bullet_bindings WHERE gid IN '
        '(SELECT gid FROM native_lobby_weapon_bullets WHERE weapon_gid=?)', (gid,))
    for table in CHILD_TABLES:
        connection.execute('DELETE FROM ' + table + ' WHERE weapon_gid=?', (gid,))


def _remove(connection, player, gid):
    _remove_weapon_features(connection, gid)
    for table in ('native_lobby_prop_rotations', 'native_lobby_keycard_health',
                  'native_lobby_container_move_receipts', 'native_lobby_prop_bindings'):
        connection.execute('DELETE FROM ' + table + ' WHERE gid=?', (gid,))
    connection.execute('DELETE FROM native_lobby_props WHERE gid=? AND player_id=?', (gid, player))


def _write_features(connection, prop):
    gid = prop['gid']
    _write_binding(connection, prop)
    if prop['rotated']:
        connection.execute('INSERT INTO native_lobby_prop_rotations VALUES (?,1) '
                           'ON CONFLICT(gid) DO UPDATE SET rotated=1', (gid,))
    else:
        connection.execute('DELETE FROM native_lobby_prop_rotations WHERE gid=?', (gid,))
    if 'health' in prop:
        connection.execute('INSERT INTO native_lobby_keycard_health VALUES (?,?,?) '
            'ON CONFLICT(gid) DO UPDATE SET health=excluded.health,health_max=excluded.health_max',
            (gid, prop['health'], prop['health_max']))
    if str(prop['template_id']) not in RECEIVERS:
        return
    parts, ammo = _parts(prop)
    _remove_weapon_features(connection, gid)
    connection.executemany('INSERT INTO native_lobby_weapon_parts VALUES (?,?,?,?,?)', parts)
    connection.executemany('INSERT INTO native_lobby_weapon_bullets VALUES (?,?,?,?)', ammo)
    for bullet in prop['weapon']['load_bullets']:
        _write_binding(connection, bullet, loaded=True)
    connection.execute('INSERT INTO native_lobby_assembled_weapons VALUES (?)', (gid,))
    for prefix, table in (('skin', 'native_lobby_weapon_skins'), ('pendant', 'native_lobby_weapon_pendants')):
        connection.execute('INSERT INTO ' + table + ' VALUES (?,?,?)',
            (gid, prop['weapon'][prefix + '_id'], prop['weapon'][prefix + '_gid']))


def _write_binding(connection, value, *, loaded=False):
    if 'bind_type' in value:
        native_prop_bindings.set_binding(connection, value['gid'], value['bind_type'],
                                         value['bind_player'], loaded=loaded)
    else:
        table = 'native_lobby_loaded_bullet_bindings' if loaded else 'native_lobby_prop_bindings'
        connection.execute('DELETE FROM ' + table + ' WHERE gid=?', (value['gid'],))


def _validate_geometry(connection, player):
    occupied = {}
    for row in connection.execute('SELECT * FROM native_lobby_props WHERE player_id=? AND grid_page_id<>2', (player,)):
        position = row['grid_page_id']
        if position in EQUIPMENT_POSITIONS:
            key, cells = (position, 0), {(0, 0)}
        elif position in BODY_POSITIONS:
            layout = Backend._native_body_layout(connection, player, position)
            space = row['x']
            if layout is None or (space not in layout if isinstance(layout, dict) else not 1 <= space <= len(layout)):
                raise ValueError('Terminal contents have no actual equipped container space')
            width, height = layout[space] if isinstance(layout, dict) else layout[space - 1]
            x, y = row['y'] % width, row['y'] // width
            if x + row['width'] > width or y + row['length'] > height:
                raise ValueError('Terminal item exceeds its actual container layout')
            if position == POCKET_POSITION and (row['width'], row['length']) != (1, 1):
                raise ValueError('The installed pocket requires one-cell items')
            if position == KEYCHAIN_POSITION:
                from dfserver.inventory.native_keycards import can_store
                if not can_store(row['template_id'], space):
                    raise ValueError('Terminal keycard has a foreign map destination')
            if position == SAFE_BOX_POSITION:
                from dfserver.inventory.safe_boxes import can_store
                if not can_store(row['template_id']):
                    raise ValueError('Terminal item violates installed safe-box rules')
            key = (position, space)
            cells = {(cx, cy) for cx in range(x, x + row['width']) for cy in range(y, y + row['length'])}
        else:
            continue
        if occupied.setdefault(key, set()) & cells:
            raise ValueError('Terminal destination overlaps a preserved account item')
        occupied[key].update(cells)


def materialize(connection, receipt):
    """Same-connection callback; raises instead of acknowledging unsupported state.

    The receipt must already exist in world_terminal_v1 on this connection. A
    successful return includes actual account readback and a durable local ledger.
    Reusing an identical committed receipt returns its ledger without new writes.
    """
    if not isinstance(connection, sqlite3.Connection) or not connection.in_transaction:
        raise ValueError('Materialization requires the owning active SQLite transaction')
    values = {name: getattr(receipt, name) for name in ('room_id', 'player_id', 'admission_id', 'reason_name',
        'terminal_evidence_sha256', 'inventory_revision', 'carry_in_snapshot', 'carry_out_snapshot')}
    raw = _json(values)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    if not re.fullmatch('[0-9a-f]{64}', str(receipt.result_sha256)) or digest != receipt.result_sha256:
        raise ValueError('Receipt does not match its immutable committed identity')
    saved = connection.execute('SELECT t.result_sha256,t.receipt_json,s.room_id,s.player_id '
        'FROM world_terminal_v1 t JOIN world_session_v1 s USING(admission_id) WHERE admission_id=?',
        (receipt.admission_id,)).fetchone()
    if saved is None or tuple(saved) != (digest, raw, str(receipt.room_id), str(receipt.player_id)):
        raise ValueError('The exact committed room/player terminal receipt is required')
    native = _integer(receipt.player_id, 'native identity')
    identity = connection.execute('SELECT player_id FROM native_identities WHERE native_id=?', (native,)).fetchone()
    if identity is None:
        raise ValueError('The admitted native identity has no real account mapping')
    player = identity[0]
    has_ledger = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='native_match_materializations_v1'").fetchone()
    if has_ledger:
        old = connection.execute('SELECT result_sha256,native_id,account_player_id,room_id,receipt_json,report_json '
            'FROM native_match_materializations_v1 WHERE admission_id=? OR result_sha256=?', (receipt.admission_id, digest)).fetchall()
        if old:
            if len(old) != 1 or tuple(old[0])[:5] != (digest, str(native), player, str(receipt.room_id), raw):
                raise ValueError('The terminal identity was already materialized for another account or room')
            return json.loads(old[0][5])
    before, before_ids = _snapshot(receipt.carry_in_snapshot)
    after, after_ids = _snapshot(receipt.carry_out_snapshot)
    metadata_in = {key: value for key, value in receipt.carry_in_snapshot.items() if key != 'props'}
    metadata_out = {key: value for key, value in receipt.carry_out_snapshot.items() if key != 'props'}
    if metadata_in != metadata_out:
        raise ValueError('Changing selected melee, permissions or snapshot metadata requires a qualified policy')
    melee = metadata_in.get('selected_melee')
    current_melee = connection.execute('SELECT template_id,gid FROM native_lobby_melee_props WHERE player_id=?', (player,)).fetchone()
    actual_melee = melee_prop(dict(current_melee), MELEE_POSITION) if current_melee else None
    if actual_melee != melee:
        raise ValueError('The carry-in selected melee changed concurrently')
    before_raw = {prop['gid']: prop for prop in receipt.carry_in_snapshot['props']}
    after_raw = {prop['gid']: prop for prop in receipt.carry_out_snapshot['props']}
    for gid, prop in before.items():
        if _read_prop(connection, player, gid, before_raw[gid]) != prop:
            raise ValueError('The carry-in account state changed concurrently')
    for gid, prop in after.items():
        dimensions = ('length', 'width', 'rotated')
        if gid in before and all(prop[key] == before[gid][key] for key in dimensions):
            continue  # Preserve an unchanged, DB-verified legacy representation.
        item = ITEMS[str(prop['template_id'])]
        expected = (item['width'], item['length']) if prop['rotated'] else (item['length'], item['width'])
        if (prop['length'], prop['width']) != expected:
            raise ValueError('New or changed dimensions differ from the installed item and rotation')
    for gid in before_ids.keys() & after_ids.keys():
        if before_ids[gid] != after_ids[gid]:
            raise ValueError('An actual carried GID cannot change its item identity')
    for gid in before_ids.keys() | after_ids.keys():
        for table in INSTANCE_TABLES:
            rows = connection.execute('SELECT * FROM ' + table + ' WHERE gid=?', (gid,)).fetchall()
            for row in rows:
                if table == 'native_lobby_props':
                    allowed = row['player_id'] == player and row['gid'] in before
                elif table in ('native_lobby_weapon_parts', 'native_lobby_weapon_bullets'):
                    allowed = row['weapon_gid'] in before and gid in before_ids
                else:
                    allowed = (gid in before and table in ('native_lobby_safe_box_permissions', 'native_lobby_keychain_permissions')
                               and row['player_id'] == player and row['template_id'] == before[gid]['template_id'])
                if not allowed:
                    raise ValueError('Physical GID collision with an existing account instance')
    deleted = sorted(before.keys() - after.keys())
    inserted = sorted(after.keys() - before.keys())
    updated = sorted(gid for gid in before.keys() & after.keys() if before[gid] != after[gid])
    for gid in deleted:
        _remove(connection, player, gid)
    # Vacate only changed destinations, so swaps retain root identity and FKs.
    for gid in updated:
        if any(before[gid][key] != after[gid][key] for key in ('grid_page_id', 'x', 'y')):
            connection.execute('UPDATE native_lobby_props SET grid_page_id=-1,x=?,y=0 WHERE gid=? AND player_id=?',
                               (gid, gid, player))
    for gid in inserted + updated:
        prop = after[gid]
        columns = ('template_id', 'quantity', 'grid_page_id', 'x', 'y', 'length', 'width')
        if gid in before:
            connection.execute('UPDATE native_lobby_props SET ' + ','.join(key + '=?' for key in columns) +
                ' WHERE gid=? AND player_id=?', tuple(prop[key] for key in columns) + (gid, player))
            connection.execute('DELETE FROM native_lobby_container_move_receipts WHERE gid=?', (gid,))
        else:
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                (gid, player) + tuple(prop[key] for key in columns))
        _write_features(connection, prop)
    _validate_geometry(connection, player)
    for gid, prop in after.items():
        if _read_prop(connection, player, gid, after_raw[gid]) != prop:
            raise ValueError('Actual account readback differs from terminal carry-out state')
    for gid in deleted:
        if connection.execute('SELECT 1 FROM native_lobby_props WHERE gid=?', (gid,)).fetchone():
            raise ValueError('Lost carry-in instance remained in the account')
    report = dict(account_player_id=player, native_player_id=native, result_sha256=digest,
                  deleted_root_gids=deleted, inserted_root_gids=inserted, updated_root_gids=updated)
    connection.execute(SCHEMA)
    connection.execute('INSERT INTO native_match_materializations_v1 VALUES (?,?,?,?,?,?,?)',
        (receipt.admission_id, digest, str(native), player, str(receipt.room_id), raw, _json(report)))
    return report
