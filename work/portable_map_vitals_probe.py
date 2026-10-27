"""Source-qualified empty default vitals components for a future normal trial.

The producer supplies no health, movement, stamina or skill values. A successful
metadata observation after normal delivery is a separate required operation.
"""
import hashlib
import json

from dfserver.legacy_ds_bit_archive import UINT32_MAX
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_rep_layout_refs import build_empty_rep_layout_content
from dfserver.legacy_ds_scalar_serializers import SHIPPING_SHA256

SCHEMA_SHA256 = 'acec9f0b1f31346933d48e410ab8c866efd9cbab0c0da144933eafae94b904aa'


def qualify_schema(schema):
    raw = (json.dumps(schema, indent=2, sort_keys=True)+'\n').encode()
    if (hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256 or
            schema.get('client_sha256') != SHIPPING_SHA256 or
            schema.get('kind') != 'client_source_derived_empty_vitals_component_probe_schema'):
        raise ValueError('The pinned native vitals metadata probe schema is required')
    return tuple(row['name'] for row in schema['components'])


def empty_vitals_updates(schema, *, actor_guid, allocated_guids):
    """Return five updates using fresh even GUIDs from the complete namespace.

    allocated_guids must include every Actor, path binding and existing default
    component GUID. These updates form their own group, following earlier Actor
    and six-component acknowledgements; the original probe is unchanged.
    """
    names = qualify_schema(schema)
    if (type(actor_guid) is not int or not 2 <= actor_guid <= UINT32_MAX or actor_guid & 1 or
            type(allocated_guids) is not tuple or not allocated_guids or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX for g in allocated_guids) or
            len(set(allocated_guids)) != len(allocated_guids) or actor_guid not in allocated_guids):
        raise ValueError('The current Pawn and complete GUID namespace are required')
    used, candidate, result = set(allocated_guids), 2, []
    body = build_empty_rep_layout_content()
    for name in names:
        while candidate in used:
            candidate += 2
        if candidate > UINT32_MAX:
            raise ValueError('No free even GUID remains in the current namespace')
        result.append(DefaultSubobjectUpdate(actor_guid, candidate, name, SCHEMA_SHA256,
            body.payload, body.payload_bit_count, has_rep_layout=True))
        used.add(candidate)
        candidate += 2
    return tuple(result)
