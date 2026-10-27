"""Build a one-shot runtime refresh profile from the exact final admission plans."""
from functools import lru_cache
import hashlib
import json

import portable_inventory_ready_refresh as ready
import portable_map_inventory_content as content
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_default_subobject import write_default_subobjects_followup
from dfserver.legacy_ds_actor_fields import NormalClassFieldProfile, read_class_fields
from dfserver.legacy_ds_inventory_gun import read_inventory_custom_delta
from dfserver.legacy_ds_inventory_refresh import InventoryRefreshProfile
from portable_source_guard import SourceGuard


def source_pins():
    pins = ready.source_pins()
    for name in ('work/portable_inventory_refresh_runtime.py', 'work/portable_source_guard.py',
            'outputs/df-local-server/dfserver/legacy_ds_inventory_refresh.py'):
        pins[name] = hashlib.sha256((ready.ROOT / name).read_bytes()).hexdigest()
    return pins


def _sources():
    return tuple(sorted(source_pins().items()))


def make_profile(ticket, manifests, plans):
    """Called after every admission producer, before normal final-plan preflight."""
    from dfserver.legacy_ds_match_admission import LocalMatchTicket
    if type(ticket) is not LocalMatchTicket or type(ticket.loadout_snapshot) is not bytes:
        raise ValueError('The exact immutable admitted carried snapshot is required')
    pins = _sources()
    snapshot = json.loads(ticket.loadout_snapshot)
    if (snapshot['selected_hero_id'] != ticket.selected_hero_id or
            snapshot['selected_fashion_id'] != ticket.selected_fashion_id):
        raise ValueError('Inventory refresh cannot change the admitted appearance')
    binding = ready.schema_binding()
    pcs = [manifest for manifest in manifests if manifest.class_path == binding['class_path']]
    if len(pcs) != 1:
        raise ValueError('One exact source-qualified owning PC manifest is required')
    pc = pcs[0]
    candidates = [(plan, update) for plan in plans for update in plan.get('default_subobjects', ())
        if update.name == 'InventoryManager']
    if len(candidates) != 1:
        raise ValueError('One actual admitted owning InventoryManager component is required')
    plan, component = candidates[0]
    if component.actor_guid != plan['actor_guid']:
        raise ValueError('InventoryManager must belong to its queued Pawn')
    projection = content.build(ticket.loadout_snapshot, pawn_guid=component.actor_guid,
        component_guid=component.guid, value_fields=content.ZERO_VALUES, owner_player_id=ticket.player_id)
    groups = plan.get('continuations', ())
    positions = []
    for group in projection.groups:
        matches = [index+1 for index, actual in enumerate(groups) if actual == group]
        if len(matches) != 1:
            raise ValueError('Every exact original inventory content group must appear once in the final plan')
        positions.append(matches[0])
    if positions != list(range(positions[0], positions[0]+len(positions))):
        raise ValueError('The original inventory append stream must remain ordered and contiguous')
    actors = tuple(manifest.actor_guid for manifest in manifests)
    initial_payloads = []
    for ordinal, group in zip(positions, projection.groups):
        writer = BitWriter(maximum_bits=8192)
        write_default_subobjects_followup(writer, group, (), actors)
        initial_payloads.append((ordinal, writer.to_bytes(), writer.bit_count))
    items = content.adapter.build_items(ticket.loadout_snapshot, owner_player_id=ticket.player_id)
    final_key = projection.qualification['chunks'][-1]['array_key']
    # Zero is the local initial scope epoch; the runtime separately binds the
    # actual PendingChallenge, ticket and transport by object identity.
    scope = ready.InventoryReadyScope(hashlib.sha256(ticket.cookie.encode()).hexdigest(),
        ticket.player_id, 0, pc.channel_index, pc.actor_guid, component.actor_guid, component.guid)

    def accept(field, sequence):
        return ready.decode_field(field, scope=scope, channel_index=scope.pc_channel,
            actor_guid=scope.pc_actor_guid, generation=0, reliable_sequence=sequence,
            reliable_receipt_admitted=True, current_pawn_bound=True)

    @lru_cache(maxsize=1)
    def project(receipt):
        # The runtime invokes this only after its exact own-full-send/ACK gate.
        cursor = ready.initial_cursor(scope, items, acknowledged_array_key=final_key,
            initial_delivery_acknowledged=True)
        return ready.project_refresh(receipt, cursor=cursor, current_items=items,
            current_array_key=final_key, current_delivery_acknowledged=True).update

    current = SourceGuard(ready.ROOT, dict(pins))

    def apply_update(update, baseline, expected_key, authoritative_items):
        if (update.source_sha256 != content.SCHEMA_SHA256 or update.has_rep_layout is not False or
                type(expected_key) is not int or not 1 <= expected_key < (1 << 31)-1):
            raise ValueError('One exact source inventory delta and current committed array key are required')
        ready._items_digest(baseline, ticket.player_id)
        ready._items_digest(authoritative_items, ticket.player_id)
        fields = read_class_fields(BitReader(update.payload, bit_count=update.payload_bit_count),
            profile=NormalClassFieldProfile(53, False))
        if len(fields) != 1 or fields[0].rep_index != 7:
            raise ValueError('One source-qualified InventoryManager item-array update is required')
        reader = BitReader(fields[0].payload, bit_count=fields[0].payload_bit_count)
        delta = read_inventory_custom_delta(reader, profile=content.PROFILE)
        if reader.remaining or (delta.base_replication_key, delta.array_replication_key) != (expected_key, expected_key+1):
            raise ValueError('The next inventory array key must follow the exact committed baseline')
        elements = {element.element_id: element for element in baseline}
        if not set(delta.deleted_ids) <= elements.keys():
            raise ValueError('An inventory delta cannot remove unknown element identities')
        for deleted in delta.deleted_ids:
            elements.pop(deleted)
        elements.update((element.element_id, element) for element in delta.changed)
        if elements != {element.element_id: element for element in authoritative_items}:
            raise ValueError('The decoded inventory delta differs from the full authoritative destination')
        return delta.array_replication_key, authoritative_items

    return InventoryRefreshProfile(pc.channel_index, pc.actor_guid, plan['channel_index'],
        component.actor_guid, component.guid, final_key, tuple(initial_payloads), items,
        accept, project, current, apply_update)
