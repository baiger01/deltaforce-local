"""Source-bound local production with durable materials, timing and claims."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import time

from .client_errors import error_code, inventory_error
from .core import DomainError, fail
from .premium_shop import ITEMS
from .weapon_components import PRESETS, ROWS


PROTOCOL = Path(__file__).resolve().parent.parent / 'protocol'
CATALOG = json.loads((PROTOCOL / 'native_safehouse_catalog.json').read_text(encoding='utf-8'))
FORMULAS = {row['Id']: row for row in CATALOG['formulas']}
DEVICE_IDS = frozenset(row['DeviceId'] for row in CATALOG['upgrades'])
SUPPORTED_REQUESTS = frozenset({'CSSafehouseProduceReq', 'CSSafehouseReceiveAwardReq',
                              'CSSafehouseGetInfoReq', 'CSSafehouseGetPlayerDeviceReq'})
SCHEMA = """
CREATE TABLE IF NOT EXISTS native_lobby_safehouse_production (
 player_id TEXT NOT NULL, device_id INTEGER NOT NULL, formula_id INTEGER NOT NULL,
 start_time INTEGER NOT NULL, end_time INTEGER NOT NULL, products_json TEXT NOT NULL,
 materials_json TEXT NOT NULL, PRIMARY KEY(player_id,device_id),
 FOREIGN KEY(player_id,device_id) REFERENCES native_lobby_devices(player_id,device_id) ON DELETE CASCADE);
"""


def _items(value):
    items = {}
    for part in value.split(';'):
        if not part:
            continue
        item, count = part.split(':')
        item, count = int(item), int(count)
        if item <= 0 or count <= 0 or str(item) not in ITEMS:
            fail('SafehouseInvalidFormula', 'Recipe references an unavailable native item')
        items[item] = items.get(item, 0) + count
    return [{'prop_id': item, 'num': count, 'bind_type': 0} for item, count in items.items()]


def _physical_product(item_id):
    # ItemBase.GetSize resolves presets to their receivers before reading size.
    receiver_id = PRESETS.get(item_id, item_id)
    metadata = ITEMS[str(receiver_id)]
    if receiver_id != item_id:
        source = ROWS.get(str(receiver_id))
        if (source is None or source['preset_id'] != item_id or
                source['prop']['id'] != receiver_id or
                (source['prop']['length'], source['prop']['width']) !=
                (metadata['length'], metadata['width'])):
            fail('SafehouseInvalidFormula', 'Source preset has no verified physical component tree')
    if (not 1 <= metadata['length'] <= 9 or not 1 <= metadata['width'] <= 40 or
            not 1 <= metadata['max_stack_count'] <= 1000):
        fail('SafehouseInvalidFormula', 'Source product has no supported warehouse layout')
    return receiver_id, metadata


def _formula_timestamp(value):
    return int(datetime.strptime(value, '%Y-%m-%d %H:%M:%S').replace(
        tzinfo=timezone(timedelta(hours=8))).timestamp())


def _info(row):
    return {'formula_id': row['formula_id'], 'device_id': row['device_id'],
            'start_time': row['start_time'], 'end_time': row['end_time'],
            'pause_remain_time': 0, 'products': json.loads(row['products_json'])}


def device_infos(connection, player_id):
    devices = []
    for row in connection.execute('SELECT device_id,level FROM native_lobby_devices '
                                  'WHERE player_id=? ORDER BY device_id', (player_id,)):
        device = dict(row)
        line = connection.execute('SELECT * FROM native_lobby_safehouse_production '
            'WHERE player_id=? AND device_id=?', (player_id, row['device_id'])).fetchone()
        if line is not None:
            device['produce_line'] = _info(line)
        devices.append(device)
    return devices


def _snapshot(backend, connection, player_id):
    backend._ensure_weapon_parts(connection, player_id)
    rows = connection.execute('SELECT p.*,COALESCE(r.rotated,0) AS rotated '
        'FROM native_lobby_props p LEFT JOIN native_lobby_prop_rotations r ON r.gid=p.gid '
        'WHERE p.player_id=? ORDER BY p.gid', (player_id,)).fetchall()
    return {row['gid']: backend._container_prop(connection, player_id, row) for row in rows}


def _device(connection, player_id, device_id):
    if device_id not in DEVICE_IDS:
        fail('SafehouseDeviceNotFound', 'Device is absent from the installed table')
    row = connection.execute('SELECT level FROM native_lobby_devices WHERE player_id=? AND device_id=?',
                             (player_id, device_id)).fetchone()
    if row is None:
        fail('SafehouseDeviceInfoNotFound', 'This local account does not own the device')
    return row


def _produce(connection, player_id, fields, now):
    device_id, formula_id = int(fields.get('device_id') or 0), int(fields.get('formula_id') or 0)
    device = _device(connection, player_id, device_id)
    formula = FORMULAS.get(formula_id)
    if formula is None:
        fail('SafehouseFormulaNotFound', 'Formula is absent from the installed table')
    if formula['DeviceId'] != device_id:
        fail('SafehouseFormulaNotInDevice', 'Formula belongs to a different native device')
    if device['level'] < formula['Level']:
        fail('SafehouseDeviceConditionIneligible', 'Owned device level is below the source recipe requirement')
    if connection.execute('SELECT 1 FROM native_lobby_safehouse_production WHERE player_id=? AND device_id=?',
                          (player_id, device_id)).fetchone():
        fail('SafehouseProducingFormula', 'An existing production must be claimed first')
    for key, is_start in (('StartTime', True), ('EndTime', False)):
        if formula[key]:
            stamp = _formula_timestamp(formula[key])
            if (is_start and now < stamp) or (not is_start and now > stamp):
                fail('SafehouseFormulaNotInTime', 'The original recipe availability window is closed')
    if formula['UnlockSystemList']:
        fail('SafehouseBlueprintLocked', 'Recipe requires a separately verified blueprint/leader unlock')
    if (formula['WeightProductList'] or formula['MaxLoopTimes'] or formula['Type'] or
            formula['bDisassemble'] or formula['IsBind'] or formula['Time'] < 0):
        fail('SafehouseInvalidFormula', 'This recipe needs an additional source-bound production path')
    materials, products = _items(formula['MaterialList']), _items(formula['ProductList'])
    if not products:
        fail('SafehouseInvalidFormula', 'Source recipe has no deterministic product')
    for product in products:
        _physical_product(product['prop_id'])
    # InventoryServer.GetItemNumById defaults to the Player inventory group.
    for material in materials:
        owned = connection.execute('SELECT COALESCE(SUM(quantity),0) FROM native_lobby_props '
            'WHERE player_id=? AND template_id=?', (player_id, material['prop_id'])).fetchone()[0]
        if owned < material['num']:
            fail('SafehouseDelMaterialFail', 'Owned local material quantity is insufficient')
    for material in materials:
        remaining = material['num']
        rows = connection.execute('SELECT gid,quantity FROM native_lobby_props '
            'WHERE player_id=? AND template_id=? ORDER BY gid', (player_id, material['prop_id'])).fetchall()
        for row in rows:
            take = min(remaining, row['quantity'])
            if take == row['quantity']:
                connection.execute('DELETE FROM native_lobby_props WHERE player_id=? AND gid=?',
                                   (player_id, row['gid']))
            else:
                connection.execute('UPDATE native_lobby_props SET quantity=quantity-? WHERE player_id=? AND gid=?',
                                   (take, player_id, row['gid']))
            remaining -= take
            if not remaining:
                break
    end = now + formula['Time']
    connection.execute('INSERT INTO native_lobby_safehouse_production VALUES (?,?,?,?,?,?,?)',
        (player_id, device_id, formula_id, now, end, json.dumps(products), json.dumps(materials)))
    return {'result': 0, 'device_id': device_id, 'produce_info': {
        'formula_id': formula_id, 'device_id': device_id, 'start_time': now, 'end_time': end,
        'pause_remain_time': 0, 'products': products}}


def _grant_products(backend, connection, player_id, products):
    granted = []
    for product in products:
        item_id, metadata = _physical_product(product['prop_id'])
        product = {**product, 'prop_id': item_id}
        length, width, maximum = metadata['length'], metadata['width'], metadata['max_stack_count']
        remaining = product['num']
        for row in connection.execute('SELECT gid,quantity FROM native_lobby_props '
                'WHERE player_id=? AND template_id=? AND grid_page_id=2 ORDER BY gid',
                (player_id, product['prop_id'])).fetchall():
            added = min(remaining, maximum - row['quantity'])
            if added > 0:
                connection.execute('UPDATE native_lobby_props SET quantity=quantity+? WHERE gid=? AND player_id=?',
                                   (added, row['gid'], player_id))
                granted.append({**product, 'num': added, 'gid': row['gid']})
                remaining -= added
            if not remaining:
                break
        while remaining:
            occupied = set()
            for row in connection.execute('SELECT x,y,length,width FROM native_lobby_props '
                                          'WHERE player_id=? AND grid_page_id=2', (player_id,)):
                occupied.update((x, y) for x in range(row['x'], row['x'] + row['length'])
                                for y in range(row['y'], row['y'] + row['width']))
            location = next(((x, y) for y in range(41 - width) for x in range(10 - length)
                if not occupied.intersection((cx, cy) for cx in range(x, x + length)
                                             for cy in range(y, y + width))), None)
            if location is None:
                fail('WAREHOUSE_FULL', 'No room for the actual safehouse product')
            gid = backend._next_native_prop_gid(connection)
            if gid >= 2**63 - 1:
                fail('SafehouseSaveDBFail', 'Local physical prop ID range is exhausted')
            count = min(remaining, maximum)
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                (gid, player_id, product['prop_id'], count, 2, *location, length, width))
            granted.append({**product, 'num': count, 'gid': gid})
            remaining -= count
    return granted


def _claim(backend, connection, player_id, fields, now):
    device_id = int(fields.get('device_id') or 0)
    _device(connection, player_id, device_id)
    row = connection.execute('SELECT * FROM native_lobby_safehouse_production WHERE player_id=? AND device_id=?',
                             (player_id, device_id)).fetchone()
    if row is None or now < row['end_time']:
        fail('SafehouseProduceNotFinish', 'No completed local production is ready')
    items = _grant_products(backend, connection, player_id, json.loads(row['products_json']))
    connection.execute('DELETE FROM native_lobby_safehouse_production WHERE player_id=? AND device_id=?',
                       (player_id, device_id))
    return {'result': 0, 'device_id': device_id, 'items': items, 'produce_list': [],
            'loop_produce_list': [], 'favorite_formula_ids': []}


def response_fields(request, backend, token, *, changes=None):
    if request.name not in SUPPORTED_REQUESTS:
        return None
    writing = request.name in ('CSSafehouseProduceReq', 'CSSafehouseReceiveAwardReq')
    try:
        with backend.connection() as connection:
            if writing:
                connection.execute('BEGIN IMMEDIATE')
            player_id = backend._authorize(connection, token)
            if not writing:
                devices = device_infos(connection, player_id)
                if request.name == 'CSSafehouseGetInfoReq':
                    return {'result': 0, 'devices': devices,
                            'upgraded_device_list': [row['device_id'] for row in devices],
                            'is_safehouse_unlocked': bool(devices)}
                return {'result': 0, 'device_infos': devices}
            if CATALOG['mapping_status'] != 'verified_by_native_reflection_and_serialization':
                fail('SafehouseLoadCfgFailed', 'Native formula bindings are unavailable')
            before = _snapshot(backend, connection, player_id)
            now = int(time.time())
            result = (_produce(connection, player_id, request.fields, now)
                      if request.name == 'CSSafehouseProduceReq' else
                      _claim(backend, connection, player_id, request.fields, now))
            after = _snapshot(backend, connection, player_id)
            moves = [{'before': before.get(gid), 'after': after.get(gid)}
                     for gid in sorted(before.keys() | after.keys()) if before.get(gid) != after.get(gid)]
            connection.commit()
        if changes is not None:
            changes['inventory_moves'] = moves
        return result
    except DomainError as error:
        return {'result': error_code(error.code) if error.code.startswith('Safehouse') else
                inventory_error(error) if error.code == 'WAREHOUSE_FULL' else error_code('SafehouseSaveDBFail')}
    except (sqlite3.Error, ValueError, TypeError, KeyError):
        return {'result': error_code('SafehouseSaveDBFail' if writing else 'SafehouseLoadDBFail')}
