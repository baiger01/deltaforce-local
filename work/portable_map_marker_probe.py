"""Two source-qualified map default probes, with no marker values or processes."""
import hashlib
import json

from dfserver.legacy_ds_bit_archive import UINT32_MAX
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_rep_layout_refs import build_empty_rep_layout_content
from dfserver.legacy_ds_scalar_serializers import SHIPPING_SHA256

SCHEMA_SHA256 = '9885d6d4195ab033f3644e9060168399deebb9116544580a6765b379f5f3fa74'


def qualify_schema(schema):
    raw = (json.dumps(schema, indent=2, sort_keys=True)+'\n').encode()
    if (hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256 or
            schema.get('client_sha256') != SHIPPING_SHA256 or
            schema.get('kind') != 'client_source_derived_empty_map_marker_component_probe_schema'):
        raise ValueError('The pinned map marker component probe schema is required')
    return tuple((r['parent'], r['name']) for r in schema['components'])


def map_marker_probe_source_pins(root, schema):
    qualify_schema(schema)
    for relative, expected in schema['sources'].items():
        if hashlib.sha256((root/relative).read_bytes()).hexdigest() != expected:
            raise ValueError('The sealed map marker probe source changed: '+relative)
    return dict(schema['sources'])


def empty_map_marker_updates(schema, *, game_state_guid, player_state_guid, allocated_guids):
    """Use one complete namespace to allocate two distinct even GUID holes.

    Each result belongs to its own parent Actor channel and requires that
    parent's actual prior receipts. The caller owns scheduling and packet limits.
    """
    names = qualify_schema(schema)
    parents = {'game_state': game_state_guid, 'player_state': player_state_guid}
    if (any(type(g) is not int or not 2 <= g <= UINT32_MAX or g & 1 for g in parents.values()) or
            game_state_guid == player_state_guid or type(allocated_guids) is not tuple or
            not 2 <= len(allocated_guids) <= 4096 or len(set(allocated_guids)) != len(allocated_guids) or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX for g in allocated_guids) or
            any(g not in allocated_guids for g in parents.values())):
        raise ValueError('Both actual parents and their complete bounded GUID namespace are required')
    used, candidate, result = set(allocated_guids), 2, []
    body = build_empty_rep_layout_content()
    for parent, name in names:
        while candidate in used:
            candidate += 2
        if candidate > UINT32_MAX:
            raise ValueError('No free even GUID remains')
        result.append(DefaultSubobjectUpdate(parents[parent], candidate, name, SCHEMA_SHA256,
            body.payload, body.payload_bit_count, has_rep_layout=True))
        used.add(candidate)
        candidate += 2
    return tuple(result)
