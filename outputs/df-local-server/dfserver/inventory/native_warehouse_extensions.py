"""Installed warehouse boxes, earned slots and ordinary empty-box operations.

ExtensionBoxDesc rows and reflection bindings are in native_extension_box_catalog.
Original cs_deposit_pb declares equip=1/uninstall=2. DepositLogic maps an
extension slot to floor(slot/1000), and a new page to page*1000+1. Normal
pages begin after MainContainer2 and precede DepositoryEnd20. The original
remote contents redistribution/replacement evaluator is unavailable here.
"""
from dfserver._paths import SERVER_ROOT

import json
from pathlib import Path
import sqlite3

from dfserver.gateway.client_errors import error_code
from dfserver.app.core import DomainError, fail


CATALOG = json.loads((SERVER_ROOT /
                     'protocol/native_extension_box_catalog.json').read_text(encoding='utf-8'))
BOXES = {row['ItemID']: row for row in CATALOG['rows']}
SLOTS = CATALOG['slot_contract']
MAIN_PAGE, FIRST_PAGE, PAGE_END = (SLOTS[key] for key in
                                  ('main_page', 'first_page', 'page_end_exclusive'))
EQUIP, UNINSTALL = (CATALOG['operations'][key] for key in ('equip', 'uninstall'))
SUPPORTED_REQUESTS = frozenset({'CSDepositOperateExtensionBoxReq'})
SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_warehouse_extensions (
 player_id TEXT NOT NULL REFERENCES players(id),
 slot_id INTEGER NOT NULL, page_id INTEGER NOT NULL,
 box_gid INTEGER NOT NULL UNIQUE REFERENCES native_lobby_props(gid) ON DELETE CASCADE,
 PRIMARY KEY(player_id,slot_id), UNIQUE(player_id,page_id),
 CHECK(page_id>=3 AND page_id<20), CHECK(slot_id=page_id*1000+1));
"""


def _catalog():
    if (CATALOG['mapping_status'] != 'verified_by_native_reflection_and_serialization'
            or len(BOXES) != len(CATALOG['rows'])):
        fail('DepositPropDescNotFound', 'Verified extension-box bindings are unavailable')


def _box(item_id):
    _catalog()
    box = BOXES.get(item_id)
    if box is None:
        fail('DepositPropDescNotFound', 'This item is not an original extension box')
    if str(item_id) in CATALOG['special_boxes']:
        fail('DepositNotSupportFeature', 'This box requires its original specialised permission path')
    return box


def _owned(connection, player_id, gid):
    return connection.execute('SELECT p.*,COALESCE(r.rotated,0) AS rotated FROM native_lobby_props p '
        'LEFT JOIN native_lobby_prop_rotations r ON r.gid=p.gid '
        'WHERE p.player_id=? AND p.gid=?', (player_id, gid)).fetchone()


def _installed(connection, player_id):
    result = []
    for row in connection.execute('SELECT * FROM native_lobby_warehouse_extensions '
                                  'WHERE player_id=? ORDER BY page_id', (player_id,)):
        prop = _owned(connection, player_id, row['box_gid'])
        if (prop is None or prop['grid_page_id'] != row['slot_id'] or prop['quantity'] != 1
                or not FIRST_PAGE <= row['page_id'] < PAGE_END
                or row['slot_id'] != row['page_id'] * SLOTS['slot_multiplier'] + SLOTS['first_slot_offset']):
            fail('DepositInvalidReq', 'Saved extension mapping differs from its owned physical box')
        _box(prop['template_id'])
        result.append({**dict(row), 'prop': dict(prop)})
    return result


def capacity(connection, player_id):
    """Read committed facility level; a pending upgrade does not grant slots."""
    _catalog()
    row = connection.execute('SELECT level FROM native_lobby_devices WHERE player_id=? AND device_id=?',
                             (player_id, CATALOG['warehouse_device_id'])).fetchone()
    level = row['level'] if row else 0
    if level and str(level) not in CATALOG['capacity_by_completed_level']:
        fail('DepositInvalidReq', 'Saved warehouse level has no original slot configuration')
    return {'cur_extension_num': len(_installed(connection, player_id)),
            'max_extension_num': CATALOG['capacity_by_completed_level'].get(str(level), 0),
            'upperlimit_extension_num': CATALOG['maximum_installed']}


def _order(connection, player_id, installed):
    slot_ids = {row['slot_id'] for row in installed}
    saved = connection.execute('SELECT order_json FROM native_lobby_extension_orders WHERE player_id=?',
                               (player_id,)).fetchone()
    order = json.loads(saved['order_json']) if saved else []
    if not isinstance(order, list) or any(type(value) is not int for value in order) or len(order) != len(set(order)):
        fail('DepositInvalidReq', 'Saved extension order is invalid')
    # Native GetAllDepositIds resolves these slot IDs through _extMapping.
    return [value for value in order if value in slot_ids] + sorted(slot_ids - set(order))


def validate_order(connection, player_id, order):
    slots = {row['slot_id'] for row in _installed(connection, player_id)}
    if (not isinstance(order, list) or any(type(value) is not int for value in order)
            or len(order) != len(set(order)) or set(order) != slots):
        fail('DepositInvalidReq', 'Extension order must contain each installed equipment slot exactly once')


def require_uninstalled_box(connection, player_id, gid):
    """Shared guard for generic move, sale and material consumption paths."""
    if connection.execute('SELECT 1 FROM native_lobby_warehouse_extensions '
                          'WHERE player_id=? AND box_gid=?', (player_id, gid)).fetchone():
        fail('DepositExtensionOperInvalid', 'Installed boxes require the dedicated empty-box uninstall operation')


def warehouse_grid(connection, player_id, page):
    """One boundary for main-grid upgrades and verified owned extension grids."""
    if page == MAIN_PAGE:
        from dfserver.inventory.native_warehouse_growth import main_size
        return main_size(connection, player_id)
    saved = next((row for row in _installed(connection, player_id) if row['page_id'] == page), None)
    if saved is None:
        fail('DepositInvalidReq', 'This account has no installed box for that warehouse page')
    box = _box(saved['prop']['template_id'])
    return box['GainPosLength'], box['GainPosWidth']


def _prefixes(raw):
    return tuple(int(value) for value in raw.replace('(', '').replace(')', '').split(',') if value.strip())


def can_store(box_id, item_id):
    """SlotConfig AddBatch/CheckItemFit/CheckItemQualityFit, with exclusions first."""
    from dfserver.commerce.premium_shop import ITEMS
    box, item = _box(box_id), ITEMS.get(str(item_id))
    if item is None:
        return False
    def matches(prefix):
        factor = 10 ** (11 - len(str(prefix)))
        return prefix * factor <= item_id < (prefix + 1) * factor
    if any(matches(prefix) for prefix in _prefixes(box['ExcludeTypeList'])):
        return False
    allowed = _prefixes(box['StorableItemTypeList'])
    return ((-1 in allowed or any(matches(prefix) for prefix in allowed))
            and item['quality'] not in _prefixes(box['ExcludeQualityList']))


def validate_content(connection, player_id, page, item_id):
    warehouse_grid(connection, player_id, page)
    if page == MAIN_PAGE:
        return
    saved = next(row for row in _installed(connection, player_id) if row['page_id'] == page)
    if not can_store(saved['prop']['template_id'], item_id):
        fail('INVALID_ARGUMENT', 'The installed box category or quality rules reject this item')


def _location(row):
    from dfserver.commerce.local_commerce import inventory_location
    if FIRST_PAGE <= row['grid_page_id'] < PAGE_END:
        return {'pos': row['grid_page_id'], 'space_id': 0, 'start_x': row['x'], 'start_y': row['y'],
                'x': row['length'], 'y': row['width'], 'rotate': bool(row.get('rotated', False))}
    return inventory_location(row)


def _wire_prop(connection, player_id, row):
    from dfserver.app.core import Backend
    from dfserver.commerce.local_commerce import item_condition_fields
    owned = Backend._container_prop(connection, player_id, row)
    return {'id': owned['template_id'], 'gid': owned['gid'], 'num': owned['quantity'],
            'position': owned['grid_page_id'], 'length': owned['length'], 'width': owned['width'],
            'loc': _location(owned),
            **item_condition_fields(owned['template_id'], components=owned.get('components'),
                                    weapon=owned.get('weapon'), health=owned.get('health')),
            **{name: owned[name] for name in ('bind_type', 'bind_player') if name in owned}}


def installed_state(connection, player_id):
    """Return extension fetch fields plus main-fetch capacity/order fields."""
    installed = _installed(connection, player_id)
    slots, pages = [], []
    slot_grid = SLOTS['default_slot_grid']
    for row in installed:
        prop, box = row['prop'], _box(row['prop']['template_id'])
        slots.append({'position': row['slot_id'], 'src_prop_id': prop['template_id'],
                      'capacity': slot_grid['capacity'],
                      'grid_space': [{'id': 0, 'length': slot_grid['grid_length'],
                                      'width': slot_grid['grid_width']}],
                      'load_props': [_wire_prop(connection, player_id, prop)]})
        contents = [dict(value) for value in connection.execute(
            'SELECT p.*,COALESCE(r.rotated,0) AS rotated FROM native_lobby_props p '
            'LEFT JOIN native_lobby_prop_rotations r ON r.gid=p.gid '
            'WHERE p.player_id=? AND p.grid_page_id=? ORDER BY p.gid', (player_id, row['page_id']))]
        pages.append({'grid_page_id': row['page_id'], 'grid_length': box['GainPosLength'],
                      'grid_width': box['GainPosWidth'],
                      'props': [_wire_prop(connection, player_id, value) for value in contents]})
    return {**capacity(connection, player_id), 'extension_pos_order': _order(connection, player_id, installed),
            'extension_slots': slots, 'in_extension_pages': pages}


def _free_main_position(connection, player_id, length, width, main_grid):
    dimensions = main_grid or warehouse_grid(connection, player_id, MAIN_PAGE)
    if (not isinstance(dimensions, (tuple, list)) or len(dimensions) != 2
            or any(type(value) is not int or value <= 0 for value in dimensions)):
        fail('DepositInvalidReq', 'Verified current warehouse dimensions are required')
    occupied = set()
    for row in connection.execute('SELECT x,y,length,width FROM native_lobby_props '
                                   'WHERE player_id=? AND grid_page_id=?', (player_id, MAIN_PAGE)):
        occupied.update((x, y) for x in range(row['x'], row['x'] + row['length'])
                        for y in range(row['y'], row['y'] + row['width']))
    orientations = [(length, width, False)]
    if length != width:
        orientations.append((width, length, True))
    for length, width, rotated in orientations:
        for y in range(dimensions[1] - width + 1):
            for x in range(dimensions[0] - length + 1):
                if not occupied.intersection((cx, cy) for cx in range(x, x + length)
                                             for cy in range(y, y + width)):
                    return x, y, length, width, rotated
    fail('DepositSpaceNotEnough', 'The warehouse has no space for the uninstalled physical box')


def operate(backend, connection, player_id, fields, changes, *, main_grid=None):
    """Run inside an authorized caller transaction; preserve the physical gid."""
    if not connection.in_transaction:
        fail('DepositInvalidReq', 'An authorized inventory transaction is required')
    values = {name: int(fields.get(name) or 0) for name in
              ('operation', 'prop_id', 'prop_gid', 'src_pos', 'dest_pos')}
    operation, gid = values['operation'], values['prop_gid']
    if operation not in (EQUIP, UNINSTALL) or not 0 < gid < 2**63:
        fail('DepositExtensionOperInvalid', 'Unknown extension operation or saved instance ID')
    box = _box(values['prop_id'])
    owned = _owned(connection, player_id, gid)
    if (owned is None or owned['template_id'] != values['prop_id'] or owned['quantity'] != 1
            or owned['grid_page_id'] != values['src_pos']):
        fail('DepositPropNotFound', 'The request does not identify this account\'s owned box and position')
    before = backend._container_prop(connection, player_id, owned)
    installed = _installed(connection, player_id)
    order = _order(connection, player_id, installed)
    from dfserver.commerce.premium_shop import ITEMS
    metadata = ITEMS[str(owned['template_id'])]
    rotated = False
    if operation == EQUIP:
        if values['src_pos'] != MAIN_PAGE:
            fail('DepositNotSupportFeature', 'Move the physical box to the main warehouse before installing it')
        cap = capacity(connection, player_id)
        if cap['cur_extension_num'] >= cap['max_extension_num']:
            fail('DepositExtensionExceed', 'Completed warehouse upgrades have not unlocked another box slot')
        used = {row['page_id'] for row in installed}
        page = next((value for value in range(FIRST_PAGE, PAGE_END) if value not in used), None)
        slot = page * SLOTS['slot_multiplier'] + SLOTS['first_slot_offset'] if page is not None else None
        if values['dest_pos'] != slot:
            fail('DepositInvalidReq', 'Destination differs from the original next free warehouse extension slot')
        if connection.execute('SELECT 1 FROM native_lobby_props WHERE player_id=? AND grid_page_id IN (?,?)',
                              (player_id, page, slot)).fetchone():
            fail('DepositSpaceHasOccupied', 'The extension slot or its content page is already occupied')
        x, y, length, width = 0, 0, metadata['length'], metadata['width']
        connection.execute('UPDATE native_lobby_props SET grid_page_id=?,x=?,y=?,length=?,width=? '
                           'WHERE player_id=? AND gid=?', (slot, x, y, length, width, player_id, gid))
        connection.execute('INSERT INTO native_lobby_warehouse_extensions VALUES (?,?,?,?)',
                           (player_id, slot, page, gid))
        order.append(slot)
        destination = slot
    else:
        saved = next((row for row in installed if row['box_gid'] == gid), None)
        if saved is None or values['dest_pos'] != MAIN_PAGE:
            fail('DepositNotSupportFeature', 'Only an installed ordinary box can return to the main warehouse')
        page = saved['page_id']
        if connection.execute('SELECT 1 FROM native_lobby_props WHERE player_id=? AND grid_page_id=?',
                              (player_id, page)).fetchone():
            fail('DepositExtensionOperInvalid', 'Empty the box before uninstalling it')
        x, y, length, width, rotated = _free_main_position(
            connection, player_id, metadata['length'], metadata['width'], main_grid)
        destination = MAIN_PAGE
        connection.execute('UPDATE native_lobby_props SET grid_page_id=?,x=?,y=?,length=?,width=? '
                           'WHERE player_id=? AND gid=?', (destination, x, y, length, width, player_id, gid))
        connection.execute('DELETE FROM native_lobby_warehouse_extensions WHERE player_id=? AND box_gid=?',
                           (player_id, gid))
        order.remove(saved['slot_id'])
    connection.execute('INSERT INTO native_lobby_prop_rotations VALUES (?,?) '
                       'ON CONFLICT(gid) DO UPDATE SET rotated=excluded.rotated', (gid, int(rotated)))
    connection.execute('INSERT INTO native_lobby_extension_orders VALUES (?,?) '
        'ON CONFLICT(player_id) DO UPDATE SET order_json=excluded.order_json', (player_id, json.dumps(order)))
    after = backend._container_prop(connection, player_id, _owned(connection, player_id, gid))
    change = {'change_type': 5, 'src': _location(before), 'dest': _location(after), 'delta': 0,
              'prop': _wire_prop(connection, player_id, after)}
    changes['inventory_moves'] = [{'before': before, 'after': after}]
    position = {'pos_id': page, 'src_prop_id': 0, 'tag': 0,
                'change_type': CATALOG['position_operations']['add' if operation == EQUIP else 'delete'],
                'space': ([{'id': 0, 'length': box['GainPosLength'], 'width': box['GainPosWidth']}]
                          if operation == EQUIP else [])}
    return {'result': 0, 'changes': {**capacity(connection, player_id),
                                    'prop_changes': [change], 'pos_changes': [position]},
            'extension_pos_order': order, 'operation': operation}


def response_fields(request, backend, token, *, changes=None, diagnostic=None, main_grid=None):
    if request.name not in SUPPORTED_REQUESTS:
        return None
    try:
        with backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = backend._authorize(connection, token)
            committed = {}
            result = operate(backend, connection, player_id, request.fields, committed, main_grid=main_grid)
            connection.commit()
        if changes is not None:
            changes.update(committed)
        return result
    except DomainError as error:
        if diagnostic is not None:
            diagnostic['local_extension_error'] = {'code': error.code, 'message': error.message}
        return {'result': error_code(error.code if error.code.startswith('Deposit') else 'DepositInternalError')}
    except (sqlite3.Error, ValueError, TypeError, KeyError) as error:
        if diagnostic is not None:
            diagnostic['local_extension_error'] = {'code': type(error).__name__, 'message': str(error)}
        return {'result': error_code('DepositInternalError')}
