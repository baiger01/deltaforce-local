"""Qualify a pure readiness retry using the exact completed admission snapshot."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from dfserver.legacy_ds_actor_fields import ClassFieldEnvelope
from dfserver.legacy_ds_wire_codec import WirePacket
import portable_inventory_ready_refresh as ready
import portable_map_inventory_content as content


def derive():
    relative = 'work/native-client-tests/1792343957590810500/admitted-loadout-snapshot.json'
    raw = (ROOT / relative).read_bytes()
    snapshot = json.loads(raw)
    items = content.adapter.build_items(snapshot, owner_player_id=17)
    initial = content.build(snapshot, pawn_guid=2, component_guid=100,
        value_fields=content.ZERO_VALUES, owner_player_id=17)
    scope = ready.InventoryReadyScope('offline-diagnostic-scope', 17, 1, 2, 4, 2, 100)
    cursor = ready.initial_cursor(scope, items, acknowledged_array_key=len(initial.groups)-1,
        initial_delivery_acknowledged=True)
    receipt = ready.decode_field(ClassFieldEnvelope(225, b'', 0), scope=scope,
        channel_index=2, actor_guid=4, generation=1, reliable_sequence=75,
        reliable_receipt_admitted=True, current_pawn_bound=True)
    projected = ready.project_refresh(receipt, cursor=cursor, current_items=items,
        current_array_key=cursor.array_key, current_delivery_acknowledged=True)
    packet = ready.preflight_packet(projected, pawn_channel=4, channel_sequence=1023,
        packet_template=WirePacket(16383, 17, (0xffffffff,), False, 0, None, (), 0),
        actor_guids=(2, 4, 6, 8), max_packet_bytes=1024)
    repeat = ready.project_refresh(receipt, cursor=cursor, current_items=items,
        current_array_key=cursor.array_key, current_delivery_acknowledged=True)
    if projected != repeat or len(items) != 52 or initial.qualification['quantity_sum'] != 544:
        raise ValueError('The exact unchanged inventory or deterministic retry changed')
    pins = ready.source_pins()
    pins[relative] = hashlib.sha256(raw).hexdigest()
    for name in ('work/qualify_economy_ready_refresh_projection_v1.py',
            'work/test_portable_inventory_ready_refresh.py'):
        pins[name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    return dict(kind='pure_native_ready_inventory_refresh_projection_v1', source_pins=pins,
        scope_ids_and_receipt_sequence_are_offline_diagnostic=True,
        actual_admitted_snapshot_reused=True, process_access=False, client_launched=False,
        production_modified=False, packets_sent=False, account_written=False,
        original_items=52, original_quantity_sum=544,
        ordinary_spaces=initial.qualification['ordinary_space_count'],
        ordinary_grids=initial.qualification['ordinary_grid_count'],
        actual_initial_chunks=initial.qualification['item_chunk_count'],
        repeated_projection_is_identical=True, changed_item_count=1,
        changed_original_gid=projected.original_item_gid,
        changed_original_fastarray_element_id=projected.refreshed_element_id,
        base_key=cursor.array_key, next_key=projected.cursor_after_ack.array_key,
        component_content_bits=projected.update.payload_bit_count,
        complete_application_packet_bytes=len(packet), packet_budget_bytes=1024,
        complete_application_packet_sha256=hashlib.sha256(packet).hexdigest(),
        native_ready_receipt_saved_in_capture=False,
        native_refresh_or_ui_acceptance_verified=False,
        commit_rule='Root commits returned cursor only after exact update ACK; duplicate ready cannot increment it again')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / 'work/evidence'):
        parser.error('Use a fresh audit-only evidence path')
    report = derive()
    raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    with args.output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=str(args.output), sha256=hashlib.sha256(raw).hexdigest(),
        packet_bytes=report['complete_application_packet_bytes'],
        content_bits=report['component_content_bits'],
        initial_chunks=report['actual_initial_chunks'])))
