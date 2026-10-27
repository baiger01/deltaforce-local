"""Draft source-qualified GunDesc inventory groups; no admission or transport."""
from dataclasses import dataclass
import hashlib
from pathlib import Path

import portable_map_inventory as adapter
import portable_map_inventory_content as base
import draft_inventory_gun_desc as desc_codec
import draft_inventory_gun_items as item_codec
from dfserver.legacy_ds_actor_fields import ClassFieldEnvelope, NormalClassFieldProfile, build_class_field_content
from dfserver.legacy_ds_bit_archive import BitWriter
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_inventory_items import InventoryFastArrayDelta, InventoryFastArrayElement

ROOT = Path(__file__).resolve().parent.parent
FROZEN = {
    'work/portable_map_inventory.py': 'ed84a2745da704262297b508df16f9147bbac88b9c68921d6a28a88f6ce3abce',
    'work/portable_map_inventory_content.py': '7566dad1a7dd17246eddb3b9593307918f75de5ae82061e66c1edc3e753c9a48',
}


@dataclass(frozen=True)
class DraftGunInventoryContent:
    groups: tuple[tuple[DefaultSubobjectUpdate, ...], ...]
    gun_descriptions: tuple[desc_codec.GunDescription, ...]
    qualification: dict


def source_pins():
    for relative, digest in FROZEN.items():
        if hashlib.sha256((ROOT/relative).read_bytes()).hexdigest() != digest:
            raise ValueError('Frozen inventory delivery changed '+relative)
    pins = base.source_pins()
    pins.update(item_codec.source_pins())
    pins['work/draft_inventory_gun_content.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return pins


def _split(elements):
    current = []
    for element in elements:
        if type(element.item) is item_codec.GunInventoryItem:
            if current:
                yield tuple(current)
                current = []
            yield (element,)
        else:
            current.append(element)
            if len(current) == 4:
                yield tuple(current)
                current = []
    if current:
        yield tuple(current)


def build(snapshot, *, pawn_guid, component_guid, value_fields, owner_player_id, schema=None):
    """Keep source RepData, then isolate each actual gun in its own ACK stage."""
    pins = source_pins()
    original = base.build(snapshot, pawn_guid=pawn_guid, component_guid=component_guid,
        value_fields=value_fields, owner_player_id=owner_player_id, schema=schema)
    document = adapter._document(snapshot)
    projected = adapter.build(document, value_fields=value_fields, owner_player_id=owner_player_id)
    descriptions = {p['gid']: desc_codec.from_snapshot_prop(p) for p in document['props'] if p.get('weapon')}
    elements = tuple(InventoryFastArrayElement(e.element_id,
        item_codec.GunInventoryItem(e.item, descriptions[e.item.item_gid])
        if e.item.item_gid in descriptions else e.item) for e in projected.items)
    groups = [original.groups[0]]
    chunks = []
    for number, values in enumerate(_split(elements), 1):
        delta = InventoryFastArrayDelta(number, number-1 if number > 1 else -1, (), values)
        writer = BitWriter(maximum_bits=8192)
        item_codec.write_inventory_custom_delta(writer, delta, profile=base.PROFILE)
        block = build_class_field_content((ClassFieldEnvelope(7, writer.to_bytes(), writer.bit_count),),
            profile=NormalClassFieldProfile(53, False))
        if block.payload_bit_count > 8192:
            raise ValueError('Draft inventory class content exceeds source component body bound')
        groups.append((DefaultSubobjectUpdate(pawn_guid, component_guid, 'InventoryManager',
            base.SCHEMA_SHA256, block.payload, block.payload_bit_count, False),))
        chunks.append(dict(array_key=number, base_key=delta.base_replication_key,
            item_count=len(values), content_bits=block.payload_bit_count,
            gun_description_count=sum(type(e.item) is item_codec.GunInventoryItem for e in values)))
    report = dict(original.qualification)
    report['original_optional_feature_gaps'] = report.pop('optional_feature_gaps')
    report.update(kind='draft_frozen_account_inventory_with_two_gun_descriptions',
        draft_only_not_admitted_to_current_plan=True, gun_description_count=len(descriptions),
        item_chunk_count=len(chunks), chunks=chunks,
        custom_delta_value_bits=None, source_pins=pins,
        packet_budget_checked=False, client_receipt_verified=False,
        native_weapon_description_reconstruction_verified=False,
        weapon_actor_spawn_or_equip_verified=False,
        source_policy='Original prop trees, ammo and skin only; each gun has an independent ACK stage',
        required_gate='ACK prior group before next; no other RepItemArray writer; full transport packet preflight required')
    return DraftGunInventoryContent(tuple(groups), tuple(descriptions.values()), report)


def build_content_groups(snapshot, **kwargs):
    return build(snapshot, **kwargs).groups
