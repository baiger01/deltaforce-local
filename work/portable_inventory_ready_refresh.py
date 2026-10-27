"""Pure handling of the native seamless-finished signal and an inventory retry.

Call decode_field only after the current connection's PCReceiptLedger admitted
the complete ordered reliable body. The zero-parameter RPC reports native entry
completion, not inventory UI success. The one-item retry remains a candidate
repair. The caller commits cursor_after_ack only after that exact update's ACK,
and keeps all normal inventory writers exclusive until then.
"""
from dataclasses import asdict, dataclass, replace
import hashlib
import json
from pathlib import Path

import portable_map_inventory_content as content
from dfserver.legacy_ds_actor_fields import ClassFieldEnvelope, NormalClassFieldProfile, build_class_field_content
from dfserver.legacy_ds_bit_archive import BitWriter
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_inventory_items import InventoryFastArrayDelta, InventoryFastArrayElement
from dfserver.legacy_ds_inventory_gun import write_inventory_custom_delta
from dfserver.legacy_ds_inventory_state import SCHEMA_SHA256

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = 'work/evidence/map-system-audit-20261018/native-economy-game-ready-boundary-v6-qualified.json'
CONTRACT_SHA = '93cc02c031c070004858ad1a094f3f5b4089d0aa9218710243f7085082196ca7'


@dataclass(frozen=True)
class InventoryReadyScope:
    match_key: str
    player_id: int
    generation: int
    pc_channel: int
    pc_actor_guid: int
    pawn_guid: int
    inventory_component_guid: int


@dataclass(frozen=True)
class SeamlessFinishedReceipt:
    scope: InventoryReadyScope
    reliable_sequence: int
    function_index: int = 225


@dataclass(frozen=True)
class InventoryReadyCursor:
    scope: InventoryReadyScope
    array_key: int
    items_sha256: str
    refresh_committed: bool = False


@dataclass(frozen=True)
class InventoryReadyRefresh:
    update: DefaultSubobjectUpdate
    cursor_after_ack: InventoryReadyCursor
    refreshed_element_id: int
    original_item_gid: int
    qualification: dict


def _uint(value, maximum, minimum=0):
    return type(value) is int and minimum <= value <= maximum


def _scope(scope):
    if (type(scope) is not InventoryReadyScope or type(scope.match_key) is not str or
            not 1 <= len(scope.match_key) <= 256 or
            not _uint(scope.player_id, (1 << 64) - 1, 1) or
            not _uint(scope.generation, (1 << 32) - 1) or
            not _uint(scope.pc_channel, 1023, 2)):
        raise ValueError('The exact current admitted inventory/PC namespace is required')
    guids = (scope.pc_actor_guid, scope.pawn_guid, scope.inventory_component_guid)
    if any(not _uint(value, (1 << 32) - 1, 2) or value & 1 for value in guids) or len(set(guids)) != 3:
        raise ValueError('Distinct current dynamic Actor/component GUID bindings are required')


def source_pins():
    raw = (ROOT / CONTRACT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != CONTRACT_SHA:
        raise ValueError('The source-qualified native readiness boundary changed')
    contract = json.loads(raw)
    receiver = contract['receiver']
    if (receiver['function_name'], receiver['function_index'], receiver['field_checksum'],
            receiver['exclusive_index_maximum'], receiver['parameter_bits']) != (
            'ServerNotifySeamlessFinish', 225, 3802576422, 245, 0):
        raise ValueError('The native seamless-finished receiver changed')
    pins = {CONTRACT: CONTRACT_SHA}
    for relative, expected in contract['source_pins'].items():
        if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != expected:
            raise ValueError('Changed native readiness source: ' + relative)
        pins[relative] = expected
    pins.update(content.source_pins())
    for relative in ('work/portable_inventory_ready_refresh.py',
            'outputs/df-local-server/dfserver/legacy_ds_wire_codec.py'):
        pins[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    return pins


def schema_binding():
    source_pins()
    contract = json.loads((ROOT / CONTRACT).read_bytes())
    return dict(contract['receiver'], native_refresh_acceptance_verified=False,
        complete_received_rpc_225_saved=contract['same_trial']['complete_received_rpc_225_saved'],
        semantic_signal='normal native seamless loading completion; not inventory UI completion')


def decode_field(field, *, scope, channel_index, actor_guid, generation,
        reliable_sequence, reliable_receipt_admitted, current_pawn_bound):
    """Decode an envelope sliced from an admitted complete reliable PC body."""
    source_pins()
    _scope(scope)
    if (type(field) is not ClassFieldEnvelope or field.rep_index != 225 or
            field.payload_bit_count != 0 or field.payload != b'' or
            not _uint(channel_index, 1023) or channel_index != scope.pc_channel or
            not _uint(actor_guid, (1 << 32) - 1) or actor_guid != scope.pc_actor_guid or
            not _uint(generation, (1 << 32) - 1) or generation != scope.generation or
            not _uint(reliable_sequence, 1023) or reliable_receipt_admitted is not True or
            current_pawn_bound is not True):
        raise ValueError('Only the current admitted ordered complete empty native ready RPC is supported')
    return SeamlessFinishedReceipt(scope, reliable_sequence)


def _items_digest(items, owner_player_id):
    if (type(items) is not tuple or not 1 <= len(items) <= 256 or
            any(type(element) is not InventoryFastArrayElement for element in items) or
            len({element.element_id for element in items}) != len(items) or
            len({element.item.item_gid for element in items}) != len(items)):
        raise ValueError('A bounded exact current original inventory element tuple is required')
    for element in items:
        if (not _uint(element.element_id, (1 << 31) - 1) or
                not _uint(element.item.item_gid, (1 << 64) - 1, 1) or
                content.adapter.base_item(element.item).owner_player_id != owner_player_id):
            raise ValueError('Invalid actual FastArray ID, inventory GID or current owning player')
    records = [dict(type=type(element.item).__name__, value=asdict(element)) for element in items]
    return hashlib.sha256(json.dumps(records, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def initial_cursor(scope, items, *, acknowledged_array_key, initial_delivery_acknowledged):
    source_pins()
    _scope(scope)
    if not _uint(acknowledged_array_key, (1 << 31) - 2, 1) or initial_delivery_acknowledged is not True:
        raise ValueError('The actual ACK-committed initial array revision is required')
    return InventoryReadyCursor(scope, acknowledged_array_key, _items_digest(items, scope.player_id))


def project_refresh(receipt, *, cursor, current_items, current_array_key, current_delivery_acknowledged):
    """Return one unchanged native item update; never commit the supplied cursor."""
    pins = source_pins()
    if type(receipt) is not SeamlessFinishedReceipt or type(cursor) is not InventoryReadyCursor:
        raise ValueError('An admitted native ready receipt and committed inventory cursor are required')
    _scope(receipt.scope)
    _scope(cursor.scope)
    if (receipt.scope != cursor.scope or receipt.function_index != 225 or
            not _uint(receipt.reliable_sequence, 1023) or
            type(cursor.refresh_committed) is not bool or
            not _uint(cursor.array_key, (1 << 31) - 2, 1) or
            type(current_array_key) is not int or current_array_key != cursor.array_key or
            current_delivery_acknowledged is not True or
            _items_digest(current_items, cursor.scope.player_id) != cursor.items_sha256):
        raise ValueError('Stale/foreign/unacknowledged inventory state cannot be replayed')
    if cursor.refresh_committed:
        return None
    next_key = cursor.array_key + 1
    candidates = []
    for element in current_items:
        writer = BitWriter(maximum_bits=8192)
        delta = InventoryFastArrayDelta(next_key, cursor.array_key, (), (element,))
        write_inventory_custom_delta(writer, delta, profile=content.PROFILE)
        candidates.append((writer.bit_count, element.element_id, element, writer.to_bytes()))
    bits, _, element, payload = min(candidates, key=lambda row: row[:2])
    block = build_class_field_content((ClassFieldEnvelope(7, payload, bits),),
        profile=NormalClassFieldProfile(53, False))
    scope = cursor.scope
    update = DefaultSubobjectUpdate(scope.pawn_guid, scope.inventory_component_guid,
        'InventoryManager', SCHEMA_SHA256, block.payload, block.payload_bit_count, False)
    next_cursor = replace(cursor, array_key=next_key, refresh_committed=True)
    return InventoryReadyRefresh(update, next_cursor, element.element_id, element.item.item_gid,
        dict(source_pins=pins, changed_element_count=1, all_current_element_count=len(current_items),
            array_key=next_key, base_key=cursor.array_key, content_bits=block.payload_bit_count,
            ready_reliable_sequence=receipt.reliable_sequence, values_unchanged=True,
            native_refresh_acceptance_verified=False, packet_budget_checked=False,
            commit_rule='Commit cursor_after_ack only on exact refresh update ACK; retries reuse this projection'))


def preflight_packet(projection, *, pawn_channel, channel_sequence, packet_template,
        actor_guids, max_packet_bytes):
    """Budget one exact component followup with caller-supplied transport state."""
    from dfserver.legacy_ds_default_subobject import write_default_subobjects_followup
    from dfserver.legacy_ds_wire_codec import WireBunch, WirePacket, ChannelName, encode_observed_application
    source_pins()
    if (type(projection) is not InventoryReadyRefresh or type(packet_template) is not WirePacket or
            packet_template.bunches or not _uint(pawn_channel, 65535, 2) or
            not _uint(channel_sequence, 1023) or not _uint(max_packet_bytes, 8192, 1)):
        raise ValueError('An explicit refresh projection and current empty packet template are required')
    writer = BitWriter(maximum_bits=max_packet_bytes * 8)
    write_default_subobjects_followup(writer, (projection.update,), (), actor_guids)
    bunch = WireBunch(pawn_channel, writer.to_bytes(), writer.bit_count, reliable=True,
        channel_sequence=channel_sequence, channel_name=ChannelName(hardcoded_index=102),
        package_exports=True)
    packet = replace(packet_template, bunches=(bunch,), consumed_bits=0)
    return encode_observed_application(packet, max_packet_bytes=max_packet_bytes, received_by_server=False)
