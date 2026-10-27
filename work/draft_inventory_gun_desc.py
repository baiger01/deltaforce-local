"""Isolated source-qualified GPWeaponDescInfo payload subset; no transport.

The payload is archive byte serialization even when its enclosing inventory item
starts at a non-byte-aligned bit. This draft does not splice the outer selector,
send a packet, generate a preset, or create/equip a weapon Actor.
"""
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = 'work/evidence/map-system-audit-20261018/native-economy-gun-desc-wire-contract-draft.json'
CONTRACT_SHA = 'deb24d55ddec19dbb981e7b6d71403557884036ddd8948ff2be12199db57eec2'
BUSINESS_FIELDS = 'work/evidence/map-system-audit-20261018/native-economy-gun-desc-business-optional-fields-lua.json'
BUSINESS_FIELDS_SHA = '62449422c14631be3ab5e26a1e4c00dc5595c39738879428378d5ee4c3d997fd'
CATALOG = 'outputs/df-local-server/protocol/game_item_catalog.json'
CATALOG_SHA = '5b30d2179d77e62294e71d7510c21e03aa664f97c9c1c07399e911f8c91376e8'
MAX_ROWS = 64
MAX_AMMO = 32
MAX_CONTAIN_PLAYERS = 64
MAX_PAYLOAD = 16384
ROW = struct.Struct('<QHQQHIIHBffBQIii')


@dataclass(frozen=True)
class GunDescRow:
    index: int
    item_id: int
    gid: int
    parent_index: int
    parent_socket_id: int
    durability: float = 0.0
    bind_type: int = 1
    bind_player_id: int = 0
    raw_bound: bool = False


@dataclass(frozen=True)
class GunAmmo:
    item_id: int
    gid: int
    num: int
    bind_player_id: int = 0
    contain_player_ids: tuple[int, ...] = ()


@dataclass(frozen=True)
class GunSkin:
    skin_id: int
    skin_gid: int


@dataclass(frozen=True)
class GunDescription:
    rows: tuple[GunDescRow, ...]
    ammo: tuple[GunAmmo, ...]
    skin: GunSkin
    poor_item_id: int = 0


def source_pins():
    raw = (ROOT/CONTRACT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != CONTRACT_SHA:
        raise ValueError('Changed GunDesc draft wire contract')
    contract = json.loads(raw)
    if contract['kind'] != 'offline_inventory_gun_desc_payload_subset_v1':
        raise ValueError('Unsupported GunDesc contract')
    pins = dict(contract['source_pins'])
    pins[CONTRACT] = CONTRACT_SHA
    pins[BUSINESS_FIELDS] = BUSINESS_FIELDS_SHA
    pins[CATALOG] = CATALOG_SHA
    for relative, digest in pins.items():
        if hashlib.sha256((ROOT/relative).read_bytes()).hexdigest() != digest:
            raise ValueError('Changed GunDesc source '+relative)
    pins['work/draft_inventory_gun_desc.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return pins


def _integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('Invalid '+label)
    return value


def _u64(value, label, nonzero=False):
    return _integer(value, int(nonzero), (1 << 64)-1, label)


def _validate(desc):
    if type(desc) is not GunDescription or type(desc.rows) is not tuple or not 1 <= len(desc.rows) <= MAX_ROWS:
        raise ValueError('Bounded GunDesc rows required')
    if type(desc.ammo) is not tuple or len(desc.ammo) > MAX_AMMO or type(desc.skin) is not GunSkin:
        raise ValueError('Bounded GunDesc ammo and skin required')
    gids, sockets = set(), set()
    for ordinal, row in enumerate(desc.rows, 1):
        if type(row) is not GunDescRow or row.index != ordinal:
            raise ValueError('GunDesc indices must be contiguous and one based')
        _integer(row.index, 1, MAX_ROWS, 'row index')
        _integer(row.parent_index, 0, MAX_ROWS, 'parent index')
        _integer(row.parent_socket_id, 0, (1 << 32)-1, 'parent socket')
        _u64(row.item_id, 'part item ID', True)
        _u64(row.gid, 'original part GID', True)
        if row.gid in gids:
            raise ValueError('Repeated original GunDesc GID')
        gids.add(row.gid)
        if ordinal == 1:
            if row.parent_index != 0 or row.parent_socket_id != 0:
                raise ValueError('Root has no parent or parent socket')
        else:
            _integer(row.parent_index, 1, ordinal-1, 'parent index')
            _integer(row.parent_socket_id, 1, (1 << 32)-1, 'original parent socket')
            socket = (row.parent_index, row.parent_socket_id)
            if socket in sockets:
                raise ValueError('Repeated parent socket')
            sockets.add(socket)
        if type(row.durability) not in (int, float) or not math.isfinite(row.durability) or row.durability < 0:
            raise ValueError('Invalid source part durability')
        try:
            if not math.isfinite(struct.unpack('<f', struct.pack('<f', row.durability))[0]):
                raise ValueError('Part durability does not fit native float32')
        except (OverflowError, struct.error) as error:
            raise ValueError('Part durability does not fit native float32') from error
        _integer(row.bind_type, 0, 255, 'part bind type')
        _u64(row.bind_player_id, 'part bind player')
        if type(row.raw_bound) is not bool:
            raise ValueError('Raw bound must be bool')
    for ammo in desc.ammo:
        if type(ammo) is not GunAmmo:
            raise ValueError('Invalid ammo value')
        _u64(ammo.item_id, 'ammo item ID', True)
        _u64(ammo.gid, 'original loaded ammo GID', True)
        if ammo.gid in gids:
            raise ValueError('Repeated original loaded ammo GID')
        gids.add(ammo.gid)
        _integer(ammo.num, 1, (1 << 31)-1, 'actual loaded ammo quantity')
        _u64(ammo.bind_player_id, 'ammo bind player')
        if type(ammo.contain_player_ids) is not tuple or len(ammo.contain_player_ids) > MAX_CONTAIN_PLAYERS:
            raise ValueError('Bounded contain-player array required')
        for player in ammo.contain_player_ids:
            _u64(player, 'ammo contain-player ID', True)
    _u64(desc.skin.skin_id, 'original skin ID')
    _u64(desc.skin.skin_gid, 'original skin GID')
    _u64(desc.poor_item_id, 'original poor item ID')


def encode(desc):
    source_pins()
    _validate(desc)
    result = bytearray(struct.pack('<B', len(desc.rows)))
    for row in desc.rows:
        result.extend(ROW.pack(0, row.index, row.item_id, row.gid, row.parent_index,
            row.parent_socket_id, 0, 0, 0, row.durability, 0.0, row.bind_type,
            row.bind_player_id, int(row.raw_bound), 0, 0))
    result.extend(struct.pack('<iiii', 0, 0, 1, len(desc.ammo)))
    for ammo in desc.ammo:
        result.extend(struct.pack('<QQiQi', ammo.item_id, ammo.gid, ammo.num,
            ammo.bind_player_id, len(ammo.contain_player_ids)))
        for player in ammo.contain_player_ids:
            result.extend(struct.pack('<Q', player))
        result.extend(struct.pack('<I', 0))
    result.extend(struct.pack('<iiiQQQ', 0, 0, 0, desc.poor_item_id, 0, 0))
    result.extend(struct.pack('<6QI2Qi', desc.skin.skin_id, desc.skin.skin_gid,
        0, 0, 0, 0, 0, 0, 0, 0))
    if len(result) > MAX_PAYLOAD:
        raise ValueError('GunDesc payload exceeds draft bound')
    return bytes(result)


class _Reader:
    def __init__(self, data):
        if type(data) is not bytes or not 1 <= len(data) <= MAX_PAYLOAD:
            raise ValueError('Bounded GunDesc byte payload required')
        self.data, self.at = data, 0

    def values(self, pattern):
        value = struct.Struct('<'+pattern)
        if self.at+value.size > len(self.data):
            raise ValueError('Truncated GunDesc payload')
        result = value.unpack_from(self.data, self.at)
        self.at += value.size
        return result

    def count(self, maximum, label):
        return _integer(self.values('i')[0], 0, maximum, label)


def decode(data):
    source_pins()
    reader = _Reader(data)
    count = _integer(reader.values('B')[0], 1, MAX_ROWS, 'GunDesc row count')
    rows = []
    for _ in range(count):
        (des_id, index, item_id, gid, parent, socket, socket_id, child, node_type,
         health, health_max, bind_type, bind_player, raw_bound, tunes, values) = reader.values('QHQQHIIHBffBQIii')
        if any((des_id, socket_id, child, node_type, health_max, tunes, values)):
            raise ValueError('Unsupported nondefault GunDesc row feature')
        if raw_bound not in (0, 1):
            raise ValueError('Invalid native raw-bound bool32')
        rows.append(GunDescRow(index, item_id, gid, parent, socket, health, bind_type, bind_player, bool(raw_bound)))
    ids_count, values_count, owner_is_zero = reader.values('iii')
    if (ids_count, values_count, owner_is_zero) != (0, 0, 1):
        raise ValueError('Unsupported nondefault dynamic attributes or owner')
    ammo = []
    for _ in range(reader.count(MAX_AMMO, 'ammo array count')):
        item_id, gid, num, bind_player = reader.values('QQiQ')
        players = tuple(reader.values('Q')[0] for _ in range(reader.count(MAX_CONTAIN_PLAYERS, 'contain-player count')))
        if reader.values('I')[0] != 0:
            raise ValueError('Unsupported sub-clip ammo')
        ammo.append(GunAmmo(item_id, gid, num, bind_player, players))
    heat, seconds, decrease, poor, modify, attr_modify = reader.values('iiiQQQ')
    if any((heat, seconds, decrease, modify, attr_modify)):
        raise ValueError('Unsupported nondefault overheat or timestamps')
    skin_id, skin_gid, mystical, wear, seed, pendant, locked, kills, source, custom_name_count = reader.values('6QI2Qi')
    if any((mystical, wear, seed, pendant, locked, kills, source, custom_name_count)):
        raise ValueError('Unsupported nondefault mystical skin, pendant or custom name')
    if reader.at != len(data):
        raise ValueError('Trailing GunDesc bytes')
    result = GunDescription(tuple(rows), tuple(ammo), GunSkin(skin_id, skin_gid), poor)
    _validate(result)
    return result


def from_snapshot_prop(prop):
    """Project actual original snapshot nodes and ammo through the recovered bridge.

    Empty tune arrays retain native config defaults on 50817b0. Missing health is
    original Lua's zero/default context, and its explicit max argument is zero.
    Magazine capacity comes from the client's actual modular configuration; the
    snapshot's capacity hint is not a serialized ammo item or fabricated ammo.
    """
    source_pins()
    catalog = json.loads((ROOT/CATALOG).read_bytes())['rows']
    if type(prop) is not dict or type(prop.get('weapon')) is not dict:
        raise ValueError('Actual snapshot weapon prop required')
    rows, seen = [], set()

    def actual(item_id, quantity=1):
        _u64(item_id, 'actual catalog item ID', True)
        _integer(quantity, 1, (1 << 31)-1, 'original item quantity')
        row = catalog.get(str(item_id))
        if row is None or int(row['id']) != item_id or quantity > row['max_stack_count']:
            raise ValueError('Unqualified original item or quantity '+str(item_id))

    def visit(node, parent, socket, root=False):
        if type(node) is not dict:
            raise ValueError('Original component prop required')
        node_weapon = node.get('weapon', {})
        if type(node_weapon) is not dict:
            raise ValueError('Original node weapon data must be a record')
        if node_weapon.get('attr_set'):
            raise ValueError('Original node.weapon.attr_set tuning is outside this draft')
        if node_weapon.get('skinInfo') or node.get('mystical_skin_data'):
            raise ValueError('Original business skin details are outside this draft')
        if any(node.get(key) for key in ('tune_info', 'tunes', 'fine_tunes', 'finetune')):
            raise ValueError('Nondefault account tuning is outside this draft')
        item_id = node.get('template_id', node.get('id'))
        if 'id' in node and 'template_id' in node and node['id'] != node['template_id']:
            raise ValueError('Conflicting original item identity')
        quantity = node.get('quantity', node.get('num', 1))
        actual(item_id, quantity)
        if quantity != 1:
            raise ValueError('Weapon part quantity must be one')
        gid = _u64(node.get('gid'), 'original component GID', True)
        if gid in seen:
            raise ValueError('Repeated original component GID')
        seen.add(gid)
        index = len(rows)+1
        if index > MAX_ROWS:
            raise ValueError('GunDesc node bound exceeded')
        health = node.get('health', 0)
        if type(health) not in (int, float):
            raise ValueError('Invalid original part durability')
        if root and health:
            raise ValueError('Root account durability needs separate feature qualification')
        if root and (node.get('bind_type', 1), node.get('bind_player', 0), node.get('bRawBinded', False)) != (1, 0, False):
            raise ValueError('Root default context binding requires separate qualification')
        if node.get('health_max', 0):
            raise ValueError('Nondefault part max durability is outside original Lua bridge')
        rows.append(GunDescRow(index, item_id, gid, parent, socket, float(health),
            node.get('bind_type', 1), node.get('bind_player', 0), node.get('bRawBinded', False)))
        children = node.get('components', [])
        if not root and node_weapon.get('load_bullets'):
            raise ValueError('Nested loaded ammo is outside the original root-ammo bridge')
        if type(children) is not list or len(children) > MAX_ROWS:
            raise ValueError('Bounded actual components required')
        for component in children:
            if type(component) is not dict:
                raise ValueError('Actual component slot record required')
            slot = _integer(component.get('slot'), 1, (1 << 32)-1, 'original component slot')
            visit(component.get('prop_data'), index, slot)

    visit(prop, 0, 0, True)
    weapon = prop['weapon']
    if any(weapon.get(key) for key in ('skin_info', 'mystical_skin_info', 'pendant_info')):
        raise ValueError('Nondefault business skin details are outside this draft')
    ammo_rows = weapon.get('load_bullets', [])
    if type(ammo_rows) is not list or len(ammo_rows) > MAX_AMMO:
        raise ValueError('Bounded original loaded ammo required')
    ammo = []
    for bullet in ammo_rows:
        if type(bullet) is not dict:
            raise ValueError('Original loaded ammo prop required')
        item_id, num = bullet.get('id'), bullet.get('num')
        actual(item_id, num)
        bind_player = bullet.get('bind_player', 0)
        ammo.append(GunAmmo(item_id, bullet.get('gid'), num, bind_player,
            (bind_player,) if bind_player else ()))
    skin = GunSkin(weapon.get('skin_id', 0), weapon.get('skin_gid', 0))
    if skin.skin_id:
        actual(skin.skin_id)
    poor = weapon.get('sub_preset_id', 0)
    if poor:
        actual(poor)
    result = GunDescription(tuple(rows), tuple(ammo), skin, poor)
    _validate(result)
    return result
