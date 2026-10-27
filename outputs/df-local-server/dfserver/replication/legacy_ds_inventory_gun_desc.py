"""Native GPWeaponDescInfo subset from original carried receiver/part/ammo GIDs.

Archive bytes are emitted at the enclosing bit cursor without alignment padding.
This inventory description does not create or equip a weapon Actor.
"""
from dfserver._paths import SERVER_ROOT
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import struct

from dfserver.inventory.native_prop_bindings import snapshot_binding

ROOT = SERVER_ROOT
CONTRACT = 'protocol/portable-map-spawn/inventory-gun-desc-contract.json'
CONTRACT_SHA = '284a8e528484a67c771bb82884f97c86b714567744cdd5cb1f3286958a372835'
CATALOG = 'protocol/game_item_catalog.json'
RECEIVERS = 'protocol/weapon_component_catalog.json'
RECEIVERS_SHA = '9521d8ad19eb7dad4149195961f454f4ae64ed1008efa24fdf81af9b6624acd1'
CATALOG_SHA = '5b30d2179d77e62294e71d7510c21e03aa664f97c9c1c07399e911f8c91376e8'
MAX_ROWS = 64
MAX_AMMO = 32
MAX_CONTAIN_PLAYERS = 64
MAX_PAYLOAD = 16384
MAX_CACHE_REVISION = (1 << 31)-1
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
    modify_revision: int = 1
    attr_modify_revision: int = 1


def inventory_gun_desc_source_pins(server_root=None):
    root = Path(server_root) if server_root is not None else ROOT
    raw = (root/CONTRACT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != CONTRACT_SHA:
        raise ValueError('Changed native GunDesc wire contract')
    contract = json.loads(raw)
    if (contract['kind'] != 'native_inventory_gun_desc_payload_subset_v1' or
            contract['client_sha256'] != '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0' or
            contract['entry']['presence_selector_minimal_bit'] != 635):
        raise ValueError('Unsupported native GunDesc contract')
    pins = {CONTRACT: CONTRACT_SHA, CATALOG: CATALOG_SHA, RECEIVERS: RECEIVERS_SHA}
    for relative, digest in pins.items():
        if hashlib.sha256((root/relative).read_bytes()).hexdigest() != digest:
            raise ValueError('Changed native GunDesc source '+relative)
    for relative in ('dfserver/legacy_ds_inventory_gun_desc.py', 'dfserver/native_prop_bindings.py',
            'dfserver/inventory/native_prop_bindings.py', 'dfserver/inventory/__init__.py',
            'dfserver/_compat.py'):
        pins[relative] = hashlib.sha256((root/relative).read_bytes()).hexdigest()
    return pins


source_pins = inventory_gun_desc_source_pins

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
    _integer(desc.modify_revision, 0, MAX_CACHE_REVISION, 'description cache revision')
    _integer(desc.attr_modify_revision, 0, MAX_CACHE_REVISION, 'attribute cache revision')


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
    result.extend(struct.pack('<iiiQQQ', 0, 0, 0, desc.poor_item_id,
        desc.modify_revision, desc.attr_modify_revision))
    result.extend(struct.pack('<6QI2Qi', desc.skin.skin_id, desc.skin.skin_gid,
        0, 0, 0, 0, 0, 0, 0, 0))
    if len(result) > MAX_PAYLOAD:
        raise ValueError('GunDesc payload exceeds local bound')
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
    if any((heat, seconds, decrease)):
        raise ValueError('Unsupported nondefault overheat')
    skin_id, skin_gid, mystical, wear, seed, pendant, locked, kills, source, custom_name_count = reader.values('6QI2Qi')
    if any((mystical, wear, seed, pendant, locked, kills, source, custom_name_count)):
        raise ValueError('Unsupported nondefault mystical skin, pendant or custom name')
    if reader.at != len(data):
        raise ValueError('Trailing GunDesc bytes')
    result = GunDescription(tuple(rows), tuple(ammo), GunSkin(skin_id, skin_gid),
        poor, modify, attr_modify)
    _validate(result)
    return result


def _reject_unknown(record,allowed,label):
    for key,value in record.items():
        if key not in allowed and value not in (None,False,0,'',[],{}):
            raise ValueError('Unsupported nondefault '+label+'.'+str(key))


@lru_cache(maxsize=2)
def _decoded_catalog_rows(raw):
    # The caller still verifies current source hashes before every projection.
    return json.loads(raw)['rows']


def from_snapshot_prop(prop, *, desc_revision=1, attr_revision=1):
    """Project actual original snapshot nodes and ammo through the recovered bridge.

    Empty tune arrays retain native config defaults on 50817b0. Missing health is
    original Lua's zero/default context, and its explicit max argument is zero.
    Magazine capacity comes from the client's actual modular configuration; the
    snapshot's capacity hint is not a serialized ammo item or fabricated ammo.
    Revisions are explicit local initial-match counters. Native GetDescCount and
    GetAttrDescCount expose their low int32 values to ItemBase's zero cache gate.
    """
    source_pins()
    _integer(desc_revision, 1, MAX_CACHE_REVISION, 'initial description cache revision')
    _integer(attr_revision, 1, MAX_CACHE_REVISION, 'initial attribute cache revision')
    catalog = _decoded_catalog_rows((ROOT/CATALOG).read_bytes())
    if type(prop) is not dict or type(prop.get('weapon')) is not dict:
        raise ValueError('Actual snapshot weapon prop required')
    receivers = _decoded_catalog_rows((ROOT/RECEIVERS).read_bytes())
    if str(prop.get('template_id',prop.get('id'))) not in receivers:
        raise ValueError('Original receiver is absent from the source-qualified receiver catalog')
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
        _reject_unknown(node,{'template_id','id','gid','quantity','num','components','weapon',
            'health','health_max','bind_type','bind_player','bRawBinded','grid_page_id',
            'position','x','y','length','width','rotated','space_width'},'original weapon node')
        node_weapon = node.get('weapon', {})
        if type(node_weapon) is not dict:
            raise ValueError('Original node weapon data must be a record')
        _reject_unknown(node_weapon,{'load_bullets','skin_id','skin_gid','sub_preset_id',
            'magazine_capacity'},'original node.weapon')
        if not root and any(node_weapon.get(key) for key in ('skin_id','skin_gid','sub_preset_id','magazine_capacity')):
            raise ValueError('Nested skin/preset/capacity has no qualified inventory bridge')
        if root and 'magazine_capacity' in node_weapon:
            _integer(node_weapon['magazine_capacity'],0,(1<<31)-1,'magazine capacity hint')
        if node_weapon.get('attr_set'):
            raise ValueError('Original node.weapon.attr_set tuning is outside the qualified GunDesc subset')
        if node_weapon.get('skinInfo') or node.get('mystical_skin_data'):
            raise ValueError('Original business skin details are outside the qualified GunDesc subset')
        if any(node.get(key) for key in ('tune_info', 'tunes', 'fine_tunes', 'finetune')):
            raise ValueError('Nondefault account tuning is outside the qualified GunDesc subset')
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
        if root:
            snapshot_binding(node)
        if node.get('health_max', 0):
            raise ValueError('Nondefault part max durability is outside original Lua bridge')
        # PropInfo_To_Desc 0.14 PCs28-41 builds the root with a new default
        # ItemInfoContext; binding belongs to the outer inventory item.
        rows.append(GunDescRow(index, item_id, gid, parent, socket, float(health),
            1 if root else node.get('bind_type', 1),
            0 if root else node.get('bind_player', 0),
            False if root else node.get('bRawBinded', False)))
        children = node.get('components', [])
        if not root and node_weapon.get('load_bullets'):
            raise ValueError('Nested loaded ammo is outside the original root-ammo bridge')
        if type(children) is not list or len(children) > MAX_ROWS:
            raise ValueError('Bounded actual components required')
        for component in children:
            if type(component) is not dict:
                raise ValueError('Actual component slot record required')
            _reject_unknown(component,{'slot','prop_data'},'original component slot')
            slot = _integer(component.get('slot'), 1, (1 << 32)-1, 'original component slot')
            visit(component.get('prop_data'), index, slot)

    visit(prop, 0, 0, True)
    weapon = prop['weapon']
    if any(weapon.get(key) for key in ('skin_info', 'mystical_skin_info', 'pendant_info')):
        raise ValueError('Nondefault business skin details are outside the qualified GunDesc subset')
    ammo_rows = weapon.get('load_bullets', [])
    if type(ammo_rows) is not list or len(ammo_rows) > MAX_AMMO:
        raise ValueError('Bounded original loaded ammo required')
    ammo = []
    for bullet in ammo_rows:
        if type(bullet) is not dict:
            raise ValueError('Original loaded ammo prop required')
        _reject_unknown(bullet,{'id','gid','num','bind_type','bind_player'},'original loaded ammo')
        snapshot_binding(bullet)
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
    result = GunDescription(tuple(rows), tuple(ammo), skin, poor, desc_revision, attr_revision)
    _validate(result)
    return result
