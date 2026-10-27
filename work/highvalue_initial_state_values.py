"""Real source HighValueBoxInfo markers for a replay-verified local selection.

This creates ordinary component data only. It does not create containers,
Mandel actors, interaction/query state, tasks, or exit activation.
"""
import base64
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'outputs/df-local-server'))
from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitWriter, UINT32_MAX
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_local_map_rules import simulate_local_map_rules
from dfserver.legacy_ds_scalar_serializers import NativeScalarBinding, write_bool_value
from normal_map_archive_values import (NativeName, NativeStringTableText, qualify_contract,
    qualify_vector_contract, write_name, write_string_table_text, write_plain_vector)

CLIENT = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
SCHEMA_PATH = 'work/evidence/model-init-chain-20261018/native-highvalue-initial-state-wire-contract-v2.json'
SCHEMA_SHA256 = '9ac21754597a418a6ce3527bc8db4dbb0cc40e33de7a17c1626480c3ed23dfa0'


def _canonical(value):
    try:
        raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)).encode()
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError('A finite plain JSON local world-state snapshot is required') from exc
    if len(raw) > 32*1024*1024:
        raise ValueError('The local map world-state snapshot exceeds its fixed bound')
    return raw


def qualify_schema(schema):
    if (type(schema) is not dict or schema.get('client_sha256') != CLIENT
            or hashlib.sha256((json.dumps(schema, indent=2, sort_keys=True)+'\n').encode()).hexdigest()
            != SCHEMA_SHA256):
        raise ValueError('The exact source HighValueBoxInfo wire contract is required')
    return schema


def schema_binding(root=ROOT):
    root = Path(root).resolve()
    raw = (root/SCHEMA_PATH).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError('The source HighValueBoxInfo contract changed')
    schema = qualify_schema(json.loads(raw))
    for relative, digest in schema['sources'].items():
        path = (root/relative).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('The high-value source changed: '+relative)
    return schema


def _replay(schema, world_state):
    if type(world_state) is not dict:
        raise ValueError('The actual frozen local-rule world state is required')
    original = _canonical(world_state)
    encoded = world_state.get('config_snapshot_base64')
    if type(encoded) is not str:
        raise ValueError('The exact local rule config snapshot is required')
    try:
        config = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError('The local rule config snapshot is invalid') from exc
    sources = (ROOT/schema['local_rule_sources_path']).read_bytes()
    items = (ROOT/schema['item_catalog']['relative_path']).read_bytes()
    expected = simulate_local_map_rules(sources, items, config, seed=world_state.get('seed'))
    if _canonical(expected) != original:
        raise ValueError('The frozen rule state differs from its exact source/config/seed replay')
    return expected, original


@dataclass(frozen=True)
class FrozenHighValueMarkers:
    room_id: str
    participant_uid: int
    source_indices: tuple
    world_state_json: bytes
    world_state_sha256: str
    schema_sha256: str


def freeze_high_value_markers(schema, *, room_id, participant_uid, local_world_state,
                              existing_native_count):
    qualify_schema(schema)
    if (type(room_id) is not str or not 0 < len(room_id) <= 256 or
            type(participant_uid) is not int or not 0 < participant_uid < 1 << 64 or
            type(existing_native_count) is not int or existing_native_count != 0):
        raise ValueError('Actual initial room/participant and explicitly empty native marker array required')
    world, raw = _replay(schema, local_world_state)
    selected = []
    for obj in world['world_objects']:
        if obj['kind'] != 'high_value_point':
            continue
        index = obj['source_index']
        if type(index) is not int or not 0 <= index < len(schema['source_values']) or index in selected:
            raise ValueError('One unique real source index per selected local high-value object required')
        source = schema['source_values'][index]
        if any(obj.get(k) != value for k, value in source['local_rule_candidate'].items()):
            raise ValueError('The active local high-value point does not match its actual source metadata')
        if obj['active'] is not True or obj['runtime_actor_resolved'] is not False:
            raise ValueError('Initial source markers must retain their explicit local activation status')
        selected.append(index)
    return FrozenHighValueMarkers(room_id, participant_uid, tuple(selected), raw,
                                   hashlib.sha256(raw).hexdigest(), SCHEMA_SHA256)


def _selection(schema, selection):
    qualify_schema(schema)
    if (type(selection) is not FrozenHighValueMarkers or selection.schema_sha256 != SCHEMA_SHA256
            or type(selection.world_state_json) is not bytes
            or type(selection.source_indices) is not tuple
            or any(type(i) is not int or not 0 <= i < 32 for i in selection.source_indices)
            or len(set(selection.source_indices)) != len(selection.source_indices)
            or hashlib.sha256(selection.world_state_json).hexdigest() != selection.world_state_sha256):
        raise ValueError('The actual frozen source marker selection is required')
    expected = freeze_high_value_markers(schema, room_id=selection.room_id,
        participant_uid=selection.participant_uid, local_world_state=json.loads(selection.world_state_json),
        existing_native_count=0)
    if expected != selection:
        raise ValueError('The frozen selected source rows changed')


def _name(source):
    return NativeName(source['base_name'], source['original_number'])


def _text(source):
    return NativeStringTableText(source['flags'], _name(source['table_id']), source['key'])


def build_initial_high_value_blocks(schema, *, selection):
    _selection(schema, selection)
    name_binding, vector_binding = qualify_contract(), qualify_vector_contract()
    bool_command, = [c for c in schema['commands'] if c['descriptor_name'] == 'bHighValueBox']
    bool_binding = NativeScalarBinding(CLIENT, bool_command['property_serializer_hook']['target_rva'])
    blocks = []
    for index, source_index in enumerate(selection.source_indices):
        source = schema['source_values'][source_index]
        writer = BitWriter(maximum_bits=8192)
        writer.write_bool(False)
        writer.write_packed_int(schema['ordinary_handle'])
        writer.write_bytes((index+1).to_bytes(2, 'little'))
        for relative in range(1, 10):
            writer.write_packed_int(index*schema['child_handle_count']+relative)
            if relative == 1:
                write_bool_value(writer, source['bHighValueBox'], binding=bool_binding)
            elif 2 <= relative <= 4:
                name = ('HighValueBoxType', 'IconType', 'ColorType')[relative-2]
                writer.write_bits(source['enum_values'][name], schema['enums'][name]['wire_bits'])
            elif relative in (5, 6):
                write_string_table_text(writer, _text(source['HighValueBoxName' if relative == 5 else 'Desc']),
                                        binding=name_binding)
            elif relative == 7:
                items = source['HighValueItemList']
                writer.write_bytes(len(items).to_bytes(2, 'little'))
                for item_index, item in enumerate(items):
                    writer.write_packed_int(item_index+1)
                    write_name(writer, _name(item), binding=name_binding)
                writer.write_packed_int(0)
            elif relative == 8:
                write_name(writer, _name(source['IconName']), binding=name_binding)
            else:
                write_plain_vector(writer, tuple(source['DSLoc']), binding=vector_binding, no_byteswap=True)
        writer.write_packed_int(0)
        writer.write_packed_int(0)
        blocks.append(ActorContentBlock(True, writer.to_bytes(), writer.bit_count))
    if not blocks:
        writer = BitWriter(maximum_bits=41)
        writer.write_bool(False)
        writer.write_packed_int(schema['ordinary_handle'])
        writer.write_bytes(bytes(2))
        writer.write_packed_int(0)
        writer.write_packed_int(0)
        blocks.append(ActorContentBlock(True, writer.to_bytes(), writer.bit_count))
    return tuple(blocks)


def high_value_initial_updates(schema, *, selection, room_id, participant_uid, game_state_guid,
        component_guid, game_state_open_acknowledged, component_metadata_acknowledged,
        ack_ordered_continuations):
    """Return ACK-ordered continuations, each containing one new complete point.

    Grow1..N preserves earlier fully initialized rows. Sending these bodies as
    parallel updates or changing order is outside this API's transport contract.
    """
    blocks = build_initial_high_value_blocks(schema, selection=selection)
    if (room_id != selection.room_id or type(participant_uid) is not int
            or participant_uid != selection.participant_uid or game_state_open_acknowledged is not True
            or component_metadata_acknowledged is not True
            or ack_ordered_continuations is not True
            or any(type(g) is not int or not 2 <= g <= UINT32_MAX or g & 1
                   for g in (game_state_guid, component_guid)) or game_state_guid == component_guid):
        raise ValueError('Matching admitted room/UID, distinct GUIDs and preceding actual ACKs required')
    return tuple(DefaultSubobjectUpdate(game_state_guid, component_guid, schema['component']['name'],
        SCHEMA_SHA256, block.payload, block.payload_bit_count, has_rep_layout=True) for block in blocks)
