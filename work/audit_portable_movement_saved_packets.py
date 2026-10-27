"""Bounded offline movement audit; never print/persist private packet payloads."""
import argparse
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path

from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_guid_exports import read_guid_exports
from dfserver.legacy_ds_wire_codec import decode_observed_application
from dfserver.legacy_ds_actor_fields import read_class_fields, NormalClassFieldProfile
from portable_movement_wire import decode_new_server_move_parameters, MovementDecodeError


ROOT = Path(__file__).resolve().parent.parent
TRIAL = ROOT/'work/native-client-tests/1792460999986794500'


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def audit():
    report_raw = (TRIAL/'game-server-packets/report.json').read_bytes()
    journal_raw = (TRIAL/'game-server-packets/admitted-receipt-private.json').read_bytes()
    metadata_raw = (TRIAL/'owned-vitals-metadata.json').read_bytes()
    report, journal, metadata = map(json.loads, (report_raw, journal_raw, metadata_raw))
    movement = [o for o in metadata['objects'] if o['identity']['name'] == 'CharMoveComp']
    if len(movement) != 1 or movement[0]['object_metadata']['default_subobject_flag_present'] is not True:
        raise ValueError('The exact saved current movement identity is required')
    movement = movement[0]
    native_fields = [f for n in movement['existing_driver_class']['cache_nodes'] for f in n['fields']]
    selected = [f for f in native_fields if f['descriptor_name'] == 'NewServerMove']
    maximum = max(f['rep_index'] for f in native_fields)+1
    if len(selected) != 1 or selected[0]['rep_index'] != 6 or maximum != 9:
        raise ValueError('The saved current movement ClassNetCache changed')
    pawn = next(o for o in metadata['objects'] if o['scope'] == 'current_pawn')
    if movement['object_metadata']['outer']['identity'] != pawn['identity']:
        raise ValueError('The movement component Outer is not the saved selected Pawn')
    packets, seen, counts = [], set(), Counter()
    records = list(report['records'])+list(report['pc_restart_packet_capture']['records'])
    for record in records:
        relative = Path(record['private_packet_file'])
        candidates = (TRIAL/'game-server-packets'/relative, TRIAL/relative)
        path = next((p for p in candidates if p.exists()), None)
        if path is None or not path.resolve().is_relative_to(TRIAL.resolve()):
            raise ValueError('The saved private packet path is unavailable or foreign')
        raw = path.read_bytes()
        if _sha(raw) != record['sha256']:
            raise ValueError('The saved private datagram changed')
        packets.append((record, raw))
    for record in journal['records']:
        raw = base64.b64decode(record['payload_base64'], validate=True)
        if _sha(raw) != record['sha256'] or len(raw) != record['bytes']:
            raise ValueError('The bounded private journal changed')
        packets.append((record, raw))
    parsed = []
    for record, raw in packets:
        identity = record['direction'], record['sha256']
        if identity in seen:
            continue
        seen.add(identity)
        received = record['direction'] == 'received'
        try:
            packet = decode_observed_application(raw[8:] if received else raw,
                max_packet_bytes=1024, received_by_server=received)
        except ValueError:
            counts['datagrams_outside_existing_application_profile'] += 1
            continue
        parsed.append((record, packet))
    # Only a Name/Outer definition from an actual saved export can bind a GUID.
    # No candidate-GUID decoding or assumed bootstrap numbers is used.
    definitions, opens = {}, set()

    def remember(node):
        if node.outer is not None:
            remember(node.outer)
        definition = (node.path, node.outer.guid if node.outer is not None else 0)
        old = definitions.get(node.guid)
        if old is not None and old != definition:
            raise ValueError('Conflicting saved NetGUID definitions')
        definitions[node.guid] = definition

    for record, packet in parsed:
        for bunch in packet.bunches:
            reader = BitReader(bunch.payload, bit_count=bunch.payload_bits)
            try:
                if bunch.package_exports:
                    for node in read_guid_exports(reader):
                        remember(node)
                if record['direction'] == 'sent' and bunch.open:
                    actor = reader.read_packed_int()
                    archetype = reader.read_packed_int() if not actor & 1 else None
                    if archetype in definitions and definitions[archetype][0] == 'BP_DFMCharacter_C':
                        opens.add((bunch.channel_index, actor))
            except ValueError:
                counts['unrestored_export_or_open_profile'] += 1
    bindings = tuple((channel, actor, guid) for channel, actor in sorted(opens)
        for guid, (name, outer) in definitions.items() if name == 'CharMoveComp' and outer == actor)
    counts['qualified_pawn_opens'] = len(opens)
    counts['qualified_movement_name_outer_bindings'] = len(bindings)
    counts['saved_char_move_export_definitions'] = sum(name == 'CharMoveComp' for name, _ in definitions.values())
    decoded, rejected = [], Counter()
    for record, packet in parsed:
        if record['direction'] != 'received':
            continue
        for bunch in packet.bunches:
            if (bunch.open or bunch.close or bunch.partial or bunch.package_exports or
                    bunch.must_be_mapped or bunch.reliable):
                continue
            allowed = [(a, g) for c, a, g in bindings if c == bunch.channel_index]
            if not allowed:
                continue
            reader = BitReader(bunch.payload, bit_count=bunch.payload_bits)
            try:
                while reader.remaining:
                    layout, actor = reader.read_bool(), reader.read_bool()
                    if actor:
                        raise ValueError('Actor content requires a separate current Actor field profile')
                    guid = reader.read_packed_int()
                    length = reader.read_packed_int()  # C->S has no S->C stable-name bit.
                    body = reader.read_payload(length)
                    if (guid not in {g for _, g in allowed}) or layout:
                        continue
                    fields = read_class_fields(BitReader(body, bit_count=length),
                        profile=NormalClassFieldProfile(9, False))
                    for field in fields:
                        if field.rep_index != 6:
                            continue
                        try:
                            request = decode_new_server_move_parameters(field.payload, field.payload_bit_count)
                            decoded.append(dict(datagram_sha256=record['sha256'],
                                field_sha256=_sha(field.payload), field_bits=field.payload_bit_count,
                                exact_request_consumed=True))
                        except MovementDecodeError as error:
                            rejected[error.reason] += 1
            except ValueError:
                counts['qualified_channel_unrestored_content_profile'] += 1
    return dict(kind='offline_saved_movement_bounded_audit_v1', process_access=False,
        client_launched=False, packets_sent=False, payloads_printed_or_written=False,
        positions_advanced=False, saved_datagrams=len(seen), parsed_datagrams=len(parsed),
        saved_current_movement_field=dict(name='NewServerMove', index=6, exclusive_maximum=9),
        counts=dict(counts), qualified_binding_count=len(bindings), decoded_requests=decoded,
        decode_rejections=dict(rejected),
        limitation='No Name/Outer export binding means no candidate field is recognized or decoded.',
        sources={
            'trial/game-server-packets/report.json': _sha(report_raw),
            'trial/game-server-packets/admitted-receipt-private.json': _sha(journal_raw),
            'trial/owned-vitals-metadata.json': _sha(metadata_raw),
            'work/audit_portable_movement_saved_packets.py': _sha(Path(__file__).read_bytes()),
        })


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT/'work/evidence'):
        parser.error('Use a fresh evidence output inside work/evidence')
    result = audit()
    raw = (json.dumps(result, indent=2, sort_keys=True)+'\n').encode()
    args.output.write_bytes(raw)
    print(json.dumps(dict(path=str(args.output), sha256=_sha(raw),
        decoded_requests=len(result['decoded_requests']), counts=result['counts'])))
