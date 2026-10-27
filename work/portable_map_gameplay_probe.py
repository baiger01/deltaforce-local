"""Source-declared empty default components for ordinary metadata creation.

This producer has no process access. The caller supplies the current Pawn and
the entire allocated GUID namespace, then sends after parent Actor receipts.
"""
import hashlib
import json

from dfserver.legacy_ds_bit_archive import UINT32_MAX
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_rep_layout_refs import build_empty_rep_layout_content
from dfserver.legacy_ds_scalar_serializers import SHIPPING_SHA256

SCHEMA_SHA256 = '13c1125ea55c3efdfe67a4dd6ff55271fe77e31e62bec88ff74558f783217b05'


def qualify_schema(schema):
    raw = (json.dumps(schema, indent=2, sort_keys=True)+'\n').encode()
    if (hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256 or
            schema.get('client_sha256') != SHIPPING_SHA256 or
            schema.get('kind') != 'client_source_derived_empty_gameplay_component_probe_schema'):
        raise ValueError('The pinned native gameplay metadata probe schema is required')
    return tuple(row['name'] for row in schema['components'])


def empty_updates(schema, *, actor_guid, allocated_guids, existing_updates=()):
    """Return the existing tuple followed by six deterministic empty updates.

    allocated_guids includes every Actor and path binding in the connection;
    existing_updates separately reserves Fashion or other default components.
    No server-side native property handles are chosen by this function.
    """
    names = qualify_schema(schema)
    if (type(actor_guid) is not int or not 2 <= actor_guid <= UINT32_MAX or actor_guid & 1 or
            type(allocated_guids) is not tuple or not allocated_guids or
            any(type(g) is not int or not 2 <= g <= UINT32_MAX for g in allocated_guids) or
            len(set(allocated_guids)) != len(allocated_guids) or actor_guid not in allocated_guids or
            type(existing_updates) is not tuple or len(existing_updates)+len(names) > 8 or
            any(type(u) is not DefaultSubobjectUpdate for u in existing_updates)):
        raise ValueError('The current Pawn and complete bounded GUID namespace are required')
    used = set(allocated_guids)
    seen_names = set(names)
    for update in existing_updates:
        update.__post_init__()
        if update.actor_guid != actor_guid or update.guid in used or update.name in seen_names:
            raise ValueError('Existing default components conflict with the gameplay probe')
        used.add(update.guid)
        seen_names.add(update.name)
    body = build_empty_rep_layout_content()
    result = list(existing_updates)
    candidate = 2
    for name in names:
        while candidate in used:
            candidate += 2
        if candidate > UINT32_MAX:
            raise ValueError('No free even GUID remains in the current namespace')
        result.append(DefaultSubobjectUpdate(actor_guid, candidate, name, SCHEMA_SHA256,
            body.payload, body.payload_bit_count))
        used.add(candidate)
        candidate += 2
    return tuple(result)
