"""Persist native component trees using owned instances, never template substitutes."""

from .core import fail, integer
from .weapon_components import ROWS
from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path


SCHEMA = '''
CREATE TABLE IF NOT EXISTS native_lobby_assembled_weapons (
 weapon_gid INTEGER PRIMARY KEY REFERENCES native_lobby_props(gid) ON DELETE CASCADE);
'''


@lru_cache(maxsize=1)
def _model_sockets():
    catalog = json.loads((Path(__file__).resolve().parent.parent /
                          'protocol/weapon_model_socket_catalog.json').read_text(encoding='utf-8'))
    return {(int(row['receiver_id']), int(row['parent_template_id']),
             int(row['slot']), int(row['model_id'])) for row in catalog['rows']}


def _tree(prop, root_gid, current, next_gid, linked_part):
    from .local_commerce import installed_items
    items = installed_items()
    nodes = {}
    receiver = int(prop['id'])

    def visit(parent_gid, parent_id, components, depth):
        if depth > 5 or len(nodes) > 128:
            fail('INVALID_ARGUMENT', 'Component tree exceeds the native bound')
        slots = set()
        for component in components:
            slot = integer(int(component.get('slot') or 0), 'slot', 0, 65535)
            child = component.get('prop_data') or {}
            item_id = integer(int(child.get('id') or 0), 'part_id', 1, 2**63 - 1)
            metadata = items.get(str(item_id))
            if metadata is None or not str(item_id).startswith('13'):
                fail('INVALID_ARGUMENT', 'The requested component is not a native adapter')
            gid = int(child.get('gid') or 0)
            model = metadata['is_model_only']
            if model and gid:
                saved = current.get(gid) or linked_part(gid)
                if not saved or (saved['parent_gid'], saved['slot'], saved['template_id']) != (
                        parent_gid, slot, item_id):
                    fail('INVALID_ARGUMENT', 'Model identity does not match its saved component socket')
            if model and not gid:
                existing = next((part for part in current.values()
                    if (part['parent_gid'], part['slot'], part['template_id']) ==
                       (parent_gid, slot, item_id)), None)
                if existing:
                    gid = existing['gid']
                else:
                    if (receiver, parent_id, slot, item_id) not in _model_sockets():
                        fail('INVALID_ARGUMENT', 'Model socket has no verified client binding')
                    # A local tree identity is not an owned, tradable component.
                    gid = next_gid()
            gid = integer(gid, 'part_gid', 1, 2**63 - 1)
            if model and gid in current and current[gid]['template_id'] != item_id:
                fail('INVALID_ARGUMENT', 'Model identity does not match its saved component')
            if model and gid not in current and (receiver, parent_id, slot, item_id) not in _model_sockets():
                fail('INVALID_ARGUMENT', 'Model socket has no verified client binding')
            if gid == root_gid or gid in nodes or slot in slots or int(child.get('num') or 1) != 1:
                fail('INVALID_ARGUMENT', 'Component instances and sockets must be unique')
            slots.add(slot)
            nodes[gid] = {'gid': gid, 'parent_gid': parent_gid, 'slot': slot,
                          'template_id': item_id, 'model_only': model}
            visit(gid, item_id, child.get('components') or [], depth + 1)

    visit(root_gid, receiver, prop.get('components') or [], 1)
    return nodes


def _warehouse_cell(connection, player_id, length, width, preferred=None):
    occupied = set()
    for row in connection.execute('SELECT x,y,length,width FROM native_lobby_props '
                                  'WHERE player_id=? AND grid_page_id=2', (player_id,)):
        occupied.update((x, y) for x in range(row['x'], row['x'] + row['length'])
                        for y in range(row['y'], row['y'] + row['width']))
    if preferred is not None:
        x, y = preferred
        if (x < 0 or y < 0 or x + length > 9 or y + width > 40 or
                {(cx, cy) for cx in range(x, x + length)
                 for cy in range(y, y + width)} & occupied):
            fail('WAREHOUSE_FULL', 'The removed component does not fit its requested warehouse cell')
        return preferred
    cell = next(((x, y) for y in range(41 - width) for x in range(10 - length)
                 if not {(cx, cy) for cx in range(x, x + length)
                         for cy in range(y, y + width)} & occupied), None)
    if cell is None:
        fail('WAREHOUSE_FULL', 'No warehouse space for the removed component')
    return cell


def update_in_transaction(backend, connection, player_id, fields):
    from .local_commerce import installed_items
    if int(fields.get('data_type') or 0) not in (0, 99):
        fail('INVALID_ARGUMENT', 'This component transaction supports the local SOL inventory only')
    if fields.get('swapped_peer_gun'):
        fail('INVALID_ARGUMENT', 'Peer-weapon swapping requires a separate verified transaction')
    prop = fields.get('prop') or {}
    gid = integer(int(prop.get('gid') or 0), 'weapon_gid', 1, 2**63 - 1)
    row = connection.execute('SELECT * FROM native_lobby_props WHERE player_id=? AND gid=?',
                             (player_id, gid)).fetchone()
    if row is None:
        fail('PROP_NOT_FOUND', 'The weapon is not owned by this account')
    if row['template_id'] != int(prop.get('id') or 0) or str(row['template_id']) not in ROWS:
        fail('INVALID_ARGUMENT', 'Weapon receiver does not match the owned instance')
    before = backend._container_prop(connection, player_id, row)
    from .weapon_ammo import magazine_capacity
    loaded = sum(bullet['num'] for bullet in before.get('weapon', {}).get('load_bullets', []))
    if loaded:
        capacity = magazine_capacity(prop.get('components') or [], row['template_id'])
        if capacity is None or loaded > capacity:
            fail('INVALID_EQUIPMENT', 'Unload ammunition before applying an unverified or smaller magazine')
    current = {r['gid']: dict(r) for r in connection.execute(
        'SELECT * FROM native_lobby_weapon_parts WHERE weapon_gid=?', (gid,))}
    next_model_gid = backend._next_native_prop_gid(connection)
    def allocate_model_gid():
        nonlocal next_model_gid
        value = next_model_gid
        next_model_gid += 1
        return value
    def linked_part(part_gid):
        return connection.execute('SELECT part.* FROM native_lobby_weapon_parts part '
            'JOIN native_lobby_props owner ON owner.gid=part.weapon_gid '
            'WHERE owner.player_id=? AND part.gid=?', (player_id, part_gid)).fetchone()
    desired = _tree(prop, gid, current, allocate_model_gid, linked_part)
    incoming = {}
    available = dict(current)
    for part_gid, part in desired.items():
        if part['model_only']:
            continue
        if part_gid not in available:
            physical = connection.execute('SELECT p.*,COALESCE(r.rotated,0) AS rotated '
                'FROM native_lobby_props p LEFT JOIN native_lobby_prop_rotations r ON r.gid=p.gid '
                'WHERE p.player_id=? AND p.gid=?', (player_id, part_gid)).fetchone()
            if physical is not None:
                incoming[part_gid] = backend._container_prop(connection, player_id, physical)
                available[part_gid] = dict(physical)
                children = {r['gid']: dict(r) for r in connection.execute(
                    'SELECT * FROM native_lobby_weapon_parts WHERE weapon_gid=?', (part_gid,))}
                available.update(children)
                current.update(children)
        owned = available.get(part_gid)
        if owned is None or owned['template_id'] != part['template_id']:
            fail('PROP_NOT_FOUND', 'A requested component instance is not owned')
        item = installed_items().get(str(part['template_id']))
        if item is None or int(str(part['template_id'])[:2]) != 13 or owned.get('quantity', 1) != 1:
            fail('INVALID_ARGUMENT', 'The requested component is not a single native adapter')
    removed = set(current) - set(desired)
    removed_roots = [r for r in current.values() if r['gid'] in removed and r['parent_gid'] not in removed]
    from .local_commerce import inventory_location
    hints = fields.get('unequip_pos') or []
    if not isinstance(hints, list) or len(hints) > 128:
        fail('INVALID_ARGUMENT', 'Expected a bounded component return-position list')
    return_cells = {}
    unchanged = (set(current) == set(desired) and all(
        all(part[key] == current[part_gid][key] for key in ('template_id', 'parent_gid', 'slot'))
        for part_gid, part in desired.items()))
    for hint in hints:
        loc = hint.get('loc') or {}
        if (int(loc.get('pos') or 0) != 2 or int(loc.get('space_id') or 0) not in (0, 1)
                or any(key not in loc for key in ('start_x', 'start_y', 'x', 'y'))):
            fail('INVALID_ARGUMENT', 'Component return position is not a warehouse cell')
        signature = tuple(int(loc[key]) for key in ('start_x', 'start_y', 'x', 'y'))
        x, y, span_x, span_y = signature
        if x < 0 or y < 0 or span_x < 1 or span_y < 1 or x + span_x > 9 or y + span_y > 40:
            fail('INVALID_ARGUMENT', 'Component return position exceeds the warehouse grid')
        if unchanged:
            continue
        source = next((part_gid for part_gid, value in incoming.items()
            if value['grid_page_id'] == 2 and tuple(inventory_location(value)[key]
                for key in ('start_x', 'start_y', 'x', 'y')) == signature), None)
        replacement = desired.get(source)
        old = next((part for part in removed_roots if replacement and
            (part['parent_gid'], part['slot']) == (replacement['parent_gid'], replacement['slot'])), None)
        if old is None or old['gid'] in return_cells:
            fail('INVALID_ARGUMENT', 'Component return position does not match the dragged replacement')
        if (int(hint.get('prop_gid') or old['gid']) != old['gid'] or
                int(hint.get('prop_id') or old['template_id']) != old['template_id']):
            fail('INVALID_ARGUMENT', 'Component return position identifies a different removed part')
        return_cells[old['gid']] = loc
    # Validate all incoming instances before modifying ownership or placements.
    moves = [{'before': value, 'after': None} for value in incoming.values()]
    for part_gid in incoming:
        connection.execute('DELETE FROM native_lobby_props WHERE gid=?', (part_gid,))
    connection.execute('DELETE FROM native_lobby_weapon_parts WHERE weapon_gid=?', (gid,))
    def has_removed_physical_ancestor(part):
        parent = current.get(part['parent_gid'])
        while parent and parent['gid'] in removed:
            if not installed_items()[str(parent['template_id'])]['is_model_only']:
                return True
            parent = current.get(parent['parent_gid'])
        return False

    physical_roots = [part for part in current.values() if part['gid'] in removed
        and not installed_items()[str(part['template_id'])]['is_model_only']
        and not has_removed_physical_ancestor(part)]
    for removed_root in physical_roots:
        metadata = installed_items()[str(removed_root['template_id'])]
        length, width = metadata['length'], metadata['width']
        root_id = removed_root['gid']
        loc = return_cells.get(root_id)
        rotated = bool(loc and loc.get('rotate'))
        if rotated:
            length, width = width, length
        x, y = _warehouse_cell(connection, player_id, length, width,
            (int(loc['start_x']), int(loc['start_y'])) if loc else None)
        connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
            (root_id, player_id, removed_root['template_id'], 1, 2, x, y, length, width))
        if rotated:
            connection.execute('INSERT INTO native_lobby_prop_rotations VALUES (?,?)', (root_id, 1))

        def retain_children(parent_gid):
            for child in current.values():
                if child['gid'] in removed and child['parent_gid'] == parent_gid:
                    connection.execute('INSERT INTO native_lobby_weapon_parts VALUES (?,?,?,?,?)',
                        (child['gid'], root_id, child['parent_gid'], child['slot'], child['template_id']))
                    retain_children(child['gid'])

        retain_children(root_id)
        after = backend._container_prop(connection, player_id, connection.execute(
            'SELECT p.*,COALESCE(r.rotated,0) AS rotated FROM native_lobby_props p '
            'LEFT JOIN native_lobby_prop_rotations r ON r.gid=p.gid WHERE p.gid=?',
            (root_id,)).fetchone())
        moves.append({'before': None, 'after': after})
    for part in desired.values():
        connection.execute('INSERT INTO native_lobby_weapon_parts VALUES (?,?,?,?,?)',
            (part['gid'], gid, part['parent_gid'], part['slot'], part['template_id']))
    connection.execute('INSERT OR IGNORE INTO native_lobby_assembled_weapons VALUES (?)', (gid,))
    moves.append({'before': before, 'after': backend._container_prop(connection, player_id, row)})
    return moves


def update(backend, token, fields):
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        backend._ensure_weapon_parts(connection, player_id)
        moves = update_in_transaction(backend, connection, player_id, fields)
        connection.commit()
        return moves


def response_fields(request, backend, token):
    from .core import DomainError
    from .client_errors import inventory_error
    from .handshake_diagnostic import _native_inventory_changes
    fields = request.fields
    response = {key: fields[key] for key in ('pass_through', 'bag_id', 'data_type', 'source') if key in fields}
    try:
        moves = update(backend, token, fields)
    except DomainError as error:
        return {**response, 'result': inventory_error(error), 'errmsg': error.message}
    prop = _native_inventory_changes([moves[-1]])['prop_changes'][0]['prop']
    return {**response, 'result': 0, 'changes': _native_inventory_changes(moves), 'local_prop': prop}


def purchase_and_assemble(backend, token, entries):
    from .local_commerce import CURRENCY_ID, stock_catalog, _price
    from .socket_guid import socket_path
    catalog = stock_catalog()
    orders = []
    for entry in entries:
        if int(entry.get('channel') or 0) != 2:
            fail('INVALID_ARGUMENT', 'Automatic assembly requires the verified local auction channel')
        offer = entry.get('auction_prop') or entry.get('single_auction_prop') or {}
        info = offer.get('assemble_info') or {}
        item_id = int(offer.get('prop_id') or 0)
        count = int(offer.get('total_num') or offer.get('buy_num') or 0)
        metadata = catalog.get(item_id)
        if (not metadata or count != 1 or int(info.get('num') or 0) != 1
                or int(info.get('id') or 0) != item_id
                or not str(item_id).startswith('13')
                or int(offer.get('currency') or 0) != CURRENCY_ID):
            fail('INVALID_ARGUMENT', 'Automatic assembly requires one verified component per socket')
        price = _price(metadata)
        if int(offer.get('price') or 0) != price:
            fail('INVALID_ARGUMENT', 'Automatic assembly quote does not match local stock')
        target_gid = int(info.get('target_gid') or 0)
        if target_gid <= 0 or info.get('target_buy_gid'):
            fail('INVALID_ARGUMENT', 'Automatic assembly requires an existing owned weapon')
        try:
            path = socket_path(int(info.get('pos_guid') or 0))
        except (ValueError, TypeError):
            fail('INVALID_ARGUMENT', 'Automatic assembly socket GUID is invalid or unsupported')
        orders.append((target_gid, path, item_id, price, metadata))
    if not 1 <= len(orders) <= 32 or len({(r[0], r[1]) for r in orders}) != len(orders):
        fail('INVALID_ARGUMENT', 'Automatic assembly sockets must be unique and bounded')
    with backend.connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        player_id = backend._authorize(connection, token)
        backend._ensure_weapon_parts(connection, player_id)
        total_price = sum(order[3] for order in orders)
        balance = connection.execute('SELECT amount FROM native_lobby_currencies '
            'WHERE player_id=? AND currency_id=?', (player_id, CURRENCY_ID)).fetchone()
        if balance is None or balance[0] < total_price:
            fail('INSUFFICIENT_FUNDS', 'Not enough local currency for the component batch')
        original, final, returned = {}, {}, []
        for target_gid, path, item_id, price, metadata in sorted(orders, key=lambda r: len(r[1])):
            root = connection.execute('SELECT * FROM native_lobby_props WHERE player_id=? AND gid=?',
                                      (player_id, target_gid)).fetchone()
            if root is None or str(root['template_id']) not in ROWS:
                fail('PROP_NOT_FOUND', 'The assembly target is not an owned weapon receiver')
            before = backend._container_prop(connection, player_id, root)
            original.setdefault(target_gid, before)
            components = deepcopy(before.get('components') or [])
            parent = components
            for parent_slot in path[:-1]:
                ancestor = next((part for part in parent if int(part['slot']) == parent_slot), None)
                if ancestor is None:
                    fail('INVALID_ARGUMENT', 'The requested parent socket is not installed')
                parent = ancestor['prop_data'].setdefault('components', [])
            new_gid = backend._next_native_prop_gid(connection)
            # This private staging row is deleted before commit and never sent to the client.
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                (new_gid, player_id, item_id, 1, 0, new_gid, 0, metadata['length'], metadata['width']))
            parent[:] = [part for part in parent if int(part['slot']) != path[-1]]
            parent.append({'slot': path[-1], 'prop_data': {'id': item_id, 'gid': new_gid, 'num': 1}})
            moves = update_in_transaction(backend, connection, player_id,
                {'prop': {'id': root['template_id'], 'gid': target_gid, 'components': components}})
            returned.extend(move for move in moves[:-1] if move['before'] is None)
            final[target_gid] = moves[-1]['after']
        current = balance[0] - total_price
        connection.execute('UPDATE native_lobby_currencies SET amount=? '
            'WHERE player_id=? AND currency_id=?', (current, player_id, CURRENCY_ID))
        connection.commit()
    return {'moves': returned + [{'before': original[gid], 'after': final[gid]} for gid in final],
            'currency_change': {'currency_id': CURRENCY_ID, 'delta': -total_price, 'current_num': current}}


def purchase_response(request, backend, token):
    from .core import DomainError
    from .client_errors import inventory_error
    from .handshake_diagnostic import _native_inventory_changes
    entries = request.fields.get('buy_list') or []
    try:
        purchase = purchase_and_assemble(backend, token, entries)
    except DomainError as error:
        return {'result': inventory_error(error), 'auction_fail_list': entries}
    changes = _native_inventory_changes(purchase['moves'])
    changes.update(reason=18, currency_changes=[purchase['currency_change']])
    return {'result': 0, 'auction_changes': changes, 'is_underbuy': False, 'force_buy_channel': 2}
