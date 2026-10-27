"""Bind the qualified native gameplay mode to the observed map-board mode."""
import hashlib
import json

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitWriter
from dfserver.legacy_ds_enum_property import (
    NativeEnumPropertyBinding, enum_property_bit_count, write_enum_property_value)
from dfserver.legacy_ds_scalar_serializers import SHIPPING_SHA256

SCHEMA_SHA256 = '61dead2051debfcc9dfd991bc622f1b06aaf5711e23a82e74b9478d4677b4b56'


def mode_content(schema, record, board, map_id):
    from portable_map_bootstrap import property_handle
    canonical = (json.dumps(schema, indent=2, sort_keys=True)+'\n').encode()
    if (hashlib.sha256(canonical).hexdigest() != SCHEMA_SHA256 or
            schema.get('kind') != 'client_derived_gameplay_mode_schema' or
            schema.get('client_sha256') != SHIPPING_SHA256 or
            schema.get('process_pointers_reused') is not False):
        raise ValueError('A qualified client gameplay mode schema is required')
    field, enum = schema['field'], schema['enum']
    handle = property_handle(record, 'DFMGamePlayerMode', opcode=6, serializer=0x10e29fa0)
    commands = [c for c in record['layout']['commands'] if c.get('descriptor_name') == field['name']]
    if (record['class_name'] != 'BP_GameState_PVPVE_C' or
            len(commands) != 1 or commands[0].get('data_offset') != field['offset'] or
            commands[0].get('parent_index') != field['parent_index'] or
            field.get('name') != 'DFMGamePlayerMode' or field.get('handle') != handle or
            field.get('offset') != 0x6e1 or field.get('parent_index') != 33 or
            field.get('serializer_rva') != 0x10e29fa0 or enum.get('name') != 'EDFMGamePlayMode'):
        raise ValueError('The qualified gameplay mode declaration changed')
    entries = enum['entries']
    if (type(entries) is not list or not 1 <= len(entries) <= 256 or
            any(type(e) is not dict or type(e.get('value')) is not int or
                type(e.get('name')) is not str or not e['name'].startswith(enum['name']+'::')
                for e in entries) or
            len({e['name'] for e in entries}) != len(entries) or
            len({e['value'] for e in entries}) != len(entries)):
        raise ValueError('Unique explicit client gameplay mode labels are required')
    selected = [e['value'] for e in entries if e['name'] == 'EDFMGamePlayMode::GamePlayMode_SOL']
    if len(selected) != 1 or enum['generated_maximum'] != max(e['value'] for e in entries)+1:
        raise ValueError('The native SOL label and generated maximum are required')
    binding = NativeEnumPropertyBinding(SHIPPING_SHA256, field['serializer_rva'],
        enum['generated_maximum'], enum['archive_version'])
    if enum['archive_version'] != 13 or enum_property_bit_count(binding) != enum['wire_bits']:
        raise ValueError('The gameplay mode archive profile changed')
    rows = board['operations']
    if type(rows) is not list or not 1 <= len(rows) <= 4096:
        raise ValueError('The observed map-board catalog is required')
    matches = [r for r in rows if type(r) is dict and r.get('map_id') == map_id]
    if (not matches or any(type(r.get('game_mode')) is not int or r['game_mode'] != selected[0] or
            type(r.get('match_mode_id')) is not int or not 0 < r['match_mode_id'] < 1 << 32
            for r in matches)):
        raise ValueError('Only explicitly observed SOL map modes qualify this profile')
    modes = frozenset(r['match_mode_id'] for r in matches)
    writer = BitWriter(maximum_bits=1+40+8+40)
    writer.write_bool(False)
    writer.write_packed_int(handle)
    write_enum_property_value(writer, selected[0], binding=binding)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count), modes
