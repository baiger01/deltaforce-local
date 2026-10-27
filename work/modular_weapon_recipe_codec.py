"""Initial Actor.ModularReplicateInfo from the real physical GunDesc tree.

This qualified subset has no account tuning, pendant/custom name, extra-model
nodes, or nonzero relative transforms. It never emits internal ready flags.
The caller must apply it to a fresh acknowledged Modular Actor before Active.
"""
from dataclasses import dataclass
import hashlib
import json
import math
import struct

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitWriter, MAX_BITS
from dfserver.legacy_ds_control_fields import encode_string
from dfserver.legacy_ds_inventory_gun_desc import GunDescription, encode as encode_description
from export_modular_weapon_recipe_schema import ROOT, OUTPUT, CLIENT_SHA

SCHEMA_SHA256 = 'f2e1cd4b012613154d2bf3648db942be3d2c00159480b3d223dc4819d1259547'
EXTRA_SOURCES = {
    'work/evidence/map-system-audit-20261018/native-owning-weapon-actor-property-serializers-v1.json':
        'dd600b28177bccef60437b6c4fa1db516271adfbfe383ea7f720dd6a9e648158',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-model-skin-netserialize-v1.json':
        'd195c179b8d12bc6bd0ab9c35b3fad6450f7e356a57bfa858ba79b0798109109',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-model-lifecycle-contract-v4.json':
        '9d675d256cc1577557ae932dbd32ec6d857a05873461913f55009afc9acbc0b2',
}


def _verify(pins):
    for relative, expected in pins.items():
        path = (ROOT/relative).resolve()
        if not path.is_relative_to(ROOT) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Changed Modular recipe source: '+relative)


def schema_binding():
    raw = OUTPUT.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError('Changed source-qualified full recipe schema')
    schema = json.loads(raw)
    if (schema['kind'] != 'source_qualified_modular_actor_recipe_subset_v1' or
            schema['client_sha256'] != CLIENT_SHA or schema['native_node_bytes'] != 296 or
            schema['outer_handles'] != dict(nodes=36, poor_item_id=37, skin=38)):
        raise ValueError('Unsupported Modular recipe schema')
    _verify(schema['sources'])
    _verify(EXTRA_SOURCES)
    return schema


def source_pins():
    pins = dict(schema_binding()['sources'])
    pins.update(EXTRA_SOURCES)
    pins[OUTPUT.relative_to(ROOT).as_posix()] = SCHEMA_SHA256
    for relative in ('work/modular_weapon_recipe_codec.py', 'work/export_modular_weapon_recipe_schema.py',
            'work/parse_economy_installed_tables.py', 'work/extract_operator_avatar_catalog.py',
            'work/recover_economy_pak_access.py',
            'outputs/df-local-server/dfserver/legacy_ds_bit_archive.py',
            'outputs/df-local-server/dfserver/legacy_ds_control_fields.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def _integer(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('Invalid recipe '+name)
    return value


@dataclass(frozen=True)
class SocketInfo:
    socket_id: int
    socket_name: str
    node_index: int
    number: int = 0


@dataclass(frozen=True)
class RecipeSkin:
    skin_gid: int = 0
    skin_id: int = 0
    appearance_id: int = 0


@dataclass(frozen=True)
class RecipeNode:
    item_id: int
    function_id: int
    anim_function_id: int
    audio_function_id: int
    fx_function_id: int
    parts_type_id: int
    parts_type_priority: int
    gid: int
    part_type: int
    socket_id: int
    socket_name: str
    parent_index: int
    children: tuple[SocketInfo, ...]
    function_ids: tuple[int, ...]
    socket_number: int = 0
    num: int = 1
    socket_depth: int = 0
    socket_guid: int = (1 << 63)-1
    flag: int = 0
    bind_type: int = 1
    bind_player_id: int = 0
    raw_bound: bool = False
    node_type: int = 1
    dependence_weapon_id: int = 0
    durability: int = 0
    durability_max: int = 0
    tune_ids: tuple[int, ...] = ()
    tune_values: tuple[float, ...] = ()
    find_relative_socket_item_id: int = 0
    tactical_effective: bool = False
    exclude_3p: bool = False
    exclude_1p: bool = False
    exclude_ui: bool = False
    default_merge_mesh: bool = True


@dataclass(frozen=True)
class ModularRecipe:
    nodes: tuple[RecipeNode, ...]
    poor_item_id: int
    skin: RecipeSkin


def project(description):
    """Mirror 50817b0 ->50668f0/5062d80 for the current qualified GunDesc subset.

    Durability is copied as the exact DWORD encoded by GunDesc, with no numeric
    float-to-int conversion. Nonzero business health semantics remain unverified.
    SOL function selection follows 5145990, including its zero fallback.
    """
    if type(description) is not GunDescription:
        raise ValueError('An actual qualified GunDescription is required')
    encode_description(description)
    schema = schema_binding()
    rows, children = description.rows, [[] for _ in description.rows]
    for row in rows[1:]:
        key = str(row.parent_socket_id)
        if key not in schema['socket_names']:
            raise ValueError('Unknown original parent socket')
        children[row.parent_index-1].append(SocketInfo(row.parent_socket_id,
            schema['socket_names'][key], row.index-1, schema['socket_numbers'][key]))
    nodes = []
    for row in rows:
        config = schema['parts_rows'].get(str(row.item_id))
        if config is None:
            raise ValueError('Unknown actual installed part configuration')
        family = min(99, row.item_id//1000000000)
        part_type = 1 if family == 18 else min(99, row.item_id % 1000000000//10000000)
        function = config['FunctionId_SOL'] or config['FunctionId']
        key = str(row.parent_socket_id)
        # 50651b0 grows TuneValues to PartsDataTable.TuneIds count with zeroes.
        tune_values = (0.0,)*len(config['TuneIds'])
        nodes.append(RecipeNode(row.item_id, function, config['AnimFunctionId'],
            config['AudioFunctionId'], config['FxFuntionId'], config['PartsTypeId'],
            config['PartsTypePriority'], row.gid, part_type, row.parent_socket_id,
            'None' if row.index == 1 else schema['socket_names'][key], row.parent_index-1,
            tuple(children[row.index-1]), (function,),
            socket_number=0 if row.index == 1 else schema['socket_numbers'][key],
            bind_type=row.bind_type, bind_player_id=row.bind_player_id, raw_bound=row.raw_bound,
            durability=struct.unpack('<i', struct.pack('<f', row.durability))[0],
            tune_values=tune_values))
    appearance = 0
    if str(description.skin.skin_id).startswith('2880'):
        appearance = schema['armed_skin_appearances'].get(str(description.skin.skin_id))
        if appearance is None:
            raise ValueError('Unknown actual armed skin appearance row')
    return ModularRecipe(tuple(nodes), description.poor_item_id,
        RecipeSkin(description.skin.skin_gid, description.skin.skin_id, appearance))


def root_only(item_id, gid, *, poor_item_id=0, skin=RecipeSkin()):
    """One physical root node for a non-modular weapon (EmptyHand or melee).

    The ready gate 590ce90 only initializes a weapon (view mode, a8d) when
    58af810 reports a nonzero ModularReplicateInfo.WeaponPartNodes count, so
    a recipe-less Actor never becomes first-person. Field values follow the
    client's own row lookup 511eb90: an actual PartsDataTable row when one
    exists, otherwise the static default FPartsDataRow 1ddfa410 (constructor
    38fb110), whose function, anim/audio/fx, type and priority are all zero.
    EmptyHand and the current melee rows are absent from base and patch tables.
    """
    _integer(item_id, 1, (1 << 63)-1, 'root item ID')
    _integer(gid, 1, (1 << 64)-1, 'root GID')
    config = schema_binding()['parts_rows'].get(str(item_id))
    if config is None:
        config = dict(FunctionId=0, FunctionId_SOL=0, AnimFunctionId=0, AudioFunctionId=0,
                      FxFuntionId=0, PartsTypeId=0, PartsTypePriority=0, TuneIds=[])
    family = min(99, item_id//1000000000)
    part_type = 1 if family == 18 else min(99, item_id % 1000000000//10000000)
    function = config['FunctionId_SOL'] or config['FunctionId']
    node = RecipeNode(item_id, function, config['AnimFunctionId'], config['AudioFunctionId'],
        config['FxFuntionId'], config['PartsTypeId'], config['PartsTypePriority'], gid, part_type,
        0, 'None', -1, (), (function,), tune_values=(0.0,)*len(config['TuneIds']))
    return ModularRecipe((node,), poor_item_id, skin)


def _name(writer, text, number):
    if type(text) is not str or not 1 <= len(text) <= 256 or '\0' in text:
        raise ValueError('A bounded exact native socket name is required')
    _integer(number, 0, (1 << 32)-1, 'FName number')
    if text == 'None' and number == 0:
        writer.write_bool(True)
        writer.write_packed_int(0)
    else:
        writer.write_bool(False)
        writer.write_bytes(encode_string(text))
        writer.write_bits(number, 32)


def _skin(writer, skin):
    if type(skin) is not RecipeSkin:
        raise ValueError('Exact qualified native skin values are required')
    for value in (skin.skin_gid, skin.skin_id, skin.appearance_id):
        _integer(value, 0, (1 << 64)-1, 'skin uint64')
    default = not (skin.skin_gid or skin.skin_id or skin.appearance_id)
    writer.write_bits(int(default), 32)
    if default:
        return
    for value in (skin.skin_gid, skin.skin_id, skin.appearance_id, 0, 0, 0, 0, 0, 0, 0):
        writer.write_bits(value, 64)
    writer.write_bits(0, 32)  # Empty FString CustomName.
    writer.write_bits(0, 128)  # Native default PendantInfo GID and ID.
    writer.write_bits(0, 128)  # Four distinct BOOL32 fields.
    writer.write_bits(0, 32)  # Empty pendant appearance array.


def _validate(recipe, schema):
    if type(recipe) is not ModularRecipe or type(recipe.nodes) is not tuple or not 1 <= len(recipe.nodes) <= 64:
        raise ValueError('A bounded nonempty physical Modular recipe is required')
    _integer(recipe.poor_item_id, 0, (1 << 64)-1, 'poor item ID')
    gids, socket_pairs = set(), set()
    part_type_maximum = schema['node_enums']['PartType']['generated_maximum']
    expected_children = [[] for _ in recipe.nodes]
    for index, node in enumerate(recipe.nodes):
        if type(node) is not RecipeNode:
            raise ValueError('Exact source-qualified physical recipe nodes are required')
        if type(node.node_type) is not int or node.node_type != 1:
            raise ValueError('Only the qualified physical native node types are supported')
        _integer(node.part_type, 0, part_type_maximum-1, 'physical part type')
        _integer(node.gid, 1, (1 << 64)-1, 'original GID')
        if node.gid in gids:
            raise ValueError('Repeated original recipe GID')
        gids.add(node.gid)
        _integer(node.parent_index, -1 if index == 0 else 0, -1 if index == 0 else index-1, 'parent index')
        _integer(node.socket_id, 0 if index == 0 else 1, (1 << 32)-1, 'socket ID')
        if index == 0 and (node.socket_id, node.socket_name, node.socket_number) != (0, 'None', 0):
            raise ValueError('The receiver root cannot have a parent socket')
        if index:
            pair = (node.parent_index, node.socket_id)
            if pair in socket_pairs:
                raise ValueError('Repeated physical parent socket')
            socket_pairs.add(pair)
            expected_children[node.parent_index].append(SocketInfo(node.socket_id,
                node.socket_name, index, node.socket_number))
        for field in ('raw_bound', 'tactical_effective', 'exclude_3p', 'exclude_1p', 'exclude_ui', 'default_merge_mesh'):
            if type(getattr(node, field)) is not bool:
                raise ValueError('Exact recipe bool required: '+field)
        if type(node.children) is not tuple or len(node.children) > 64:
            raise ValueError('Bounded child socket array required')
        for values in (node.function_ids, node.tune_ids, node.tune_values):
            if type(values) is not tuple or len(values) > 64:
                raise ValueError('Bounded recipe numeric arrays required')
    if any(node.children != tuple(expected_children[i]) for i, node in enumerate(recipe.nodes)):
        raise ValueError('Child socket links must equal the complete actual physical tree')


def encode(recipe, *, maximum_bits=MAX_BITS):
    """Encode one complete initial recipe atomically within the caller's body budget.

    Omitted fields are native initial defaults (zero relative transforms only).
    Num, SocketGUID, BindType and bDefaultMergeMesh are explicitly assigned so
    nonzero constructor defaults do not depend on receiver zero construction.
    This does not implement later recipe replacement or partial array chunks.
    """
    writer = BitWriter(maximum_bits=maximum_bits)
    writer.write_bool(False)
    write_recipe_fields(writer, recipe)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)


def write_recipe_fields(writer, recipe):
    """Write handles 36/37/38 into a caller's ordinary Actor block (ascending handles)."""
    schema = schema_binding()
    _validate(recipe, schema)
    writer.write_packed_int(36)
    writer.write_bits(len(recipe.nodes), 16)
    for index, node in enumerate(recipe.nodes):
        def handle(local):
            writer.write_packed_int(index*35+local)
        def scalar(local, value, bits, signed=False, always=False):
            _integer(value, -(1 << (bits-1)) if signed else 0,
                     (1 << (bits-1))-1 if signed else (1 << bits)-1, 'node scalar')
            if value or always:
                handle(local)
                writer.write_bits(value & ((1 << bits)-1), bits)
        for local, value in enumerate((node.item_id, node.function_id, node.anim_function_id,
                node.audio_function_id, node.fx_function_id, node.parts_type_id), 1):
            scalar(local, value, 64)
        scalar(7, node.parts_type_priority, 8)
        scalar(8, node.gid, 64, always=True)
        scalar(9, node.part_type, 7, always=True)
        scalar(10, node.socket_id, 32)
        handle(11)
        _name(writer, node.socket_name, node.socket_number)
        scalar(12, node.parent_index, 32, signed=True, always=True)
        handle(13)
        writer.write_bits(len(node.children), 16)
        for ordinal, socket in enumerate(node.children):
            writer.write_packed_int(ordinal*3+1)
            writer.write_bits(_integer(socket.socket_id, 1, (1 << 32)-1, 'child socket ID'), 32)
            writer.write_packed_int(ordinal*3+2)
            _name(writer, socket.socket_name, socket.number)
            writer.write_packed_int(ordinal*3+3)
            writer.write_bits(_integer(socket.node_index, 0, len(recipe.nodes)-1, 'child index'), 32)
        writer.write_packed_int(0)
        scalar(14, node.num, 8, always=True)
        scalar(15, node.socket_depth, 16)
        scalar(16, node.socket_guid, 64, always=True)
        scalar(17, node.flag, 64)
        scalar(18, node.bind_type, 8, always=True)
        scalar(19, node.bind_player_id, 64)
        if node.raw_bound:
            handle(20)
            writer.write_bool(True)
        scalar(21, node.node_type, 3, always=True)
        scalar(22, node.dependence_weapon_id, 64)
        def numeric_array(local, values, floating=False):
            handle(local)
            writer.write_bits(len(values), 16)
            for ordinal, value in enumerate(values, 1):
                writer.write_packed_int(ordinal)
                if floating:
                    if type(value) not in (float, int) or not math.isfinite(value):
                        raise ValueError('Finite recipe float32 required')
                    try:
                        raw = struct.pack('<f', value)
                    except (struct.error, OverflowError) as error:
                        raise ValueError('Recipe float32 exceeds native width') from error
                    if not math.isfinite(struct.unpack('<f', raw)[0]):
                        raise ValueError('Recipe float32 exceeds native width')
                    writer.write_bytes(raw)
                else:
                    writer.write_bits(_integer(value, 0, (1 << 64)-1, 'array uint64'), 64)
            writer.write_packed_int(0)
        numeric_array(23, node.function_ids)
        scalar(24, node.durability, 32, signed=True)
        scalar(25, node.durability_max, 32, signed=True)
        if node.tune_ids:
            numeric_array(28, node.tune_ids)
        if node.tune_values:
            numeric_array(29, node.tune_values, True)
        scalar(30, node.find_relative_socket_item_id, 64)
        for local, value in ((31, node.tactical_effective), (32, node.exclude_3p),
                (33, node.exclude_1p), (34, node.exclude_ui), (35, node.default_merge_mesh)):
            if value or local == 35:
                handle(local)
                writer.write_bool(value)
    writer.write_packed_int(0)
    writer.write_packed_int(37)
    writer.write_bits(recipe.poor_item_id, 64)
    writer.write_packed_int(38)
    _skin(writer, recipe.skin)
