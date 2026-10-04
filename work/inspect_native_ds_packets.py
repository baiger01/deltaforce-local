"""Summarize private loopback DS captures without copying packet contents."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'outputs/df-local-server'))
from dfserver.unreal_handshake_payload import LegacyHandshakePayload, decode_payload


def summarize(capture_dir):
    manifest = json.loads((capture_dir / 'report.json').read_text(encoding='utf-8'))
    packets = []
    for record in manifest['records']:
        if record['transport'] != 'udp':
            continue
        name = record['private_packet_file']
        if Path(name).name != name or Path(name).suffix != '.bin':
            raise ValueError('Packet path must remain in the capture directory')
        raw = (capture_dir / name).read_bytes()
        if len(raw) != record['bytes'] or hashlib.sha256(raw).hexdigest() != record['sha256']:
            raise ValueError('Capture manifest does not match its packet')
        packets.append(raw)
    result = {
        'kind': 'native_loopback_ds_packet_shape',
        'observed_at_utc': datetime.now(timezone.utc).isoformat(),
        'captured_udp_packets': len(packets),
        'tcp_accepts': manifest['tcp_connections_accepted'],
        'packet_lengths': sorted({len(p) for p in packets}),
        'raw_packets_in_report': False,
        'transport_format_verified': False,
        'gameplay_server_implemented': False,
    }
    if packets and all(len(p) == 33 for p in packets):
        counters = [int.from_bytes(p[4:8], 'little') for p in packets]
        initial = LegacyHandshakePayload(False, False, 0.0, bytes(20))
        matches = []
        for packet in packets:
            try:
                matches.append(decode_payload(packet[8:]) == initial)
            except ValueError:
                matches.append(False)
        result['observed_shape'] = {
            'first_four_bytes_vary': len({p[:4] for p in packets}) > 1,
            'offset_four_u32_deltas_modulo_2_32': sorted({
                (b - a) & 0xffffffff for a, b in zip(counters, counters[1:])}),
            'offset_eight_values': sorted({p[8] for p in packets}),
            'offset_nine_through_thirty_one_all_zero': all(not any(p[9:32]) for p in packets),
            'last_byte_values': sorted({p[32] for p in packets}),
            'crc32_remaining_bytes_matches_all': all(
                int.from_bytes(p[:4], 'little') == zlib.crc32(p[4:]) for p in packets),
        }
        result['legacy_body_comparison'] = {
            'candidate_offset_after_unidentified_outer_bytes': 8,
            'body_bytes': 25, 'native_initial_body_matches': sum(matches),
            'all_captured_bodies_match_zero_initial_payload': all(matches),
            'outer_header_verified': False,
            'challenge_or_ack_observed': False,
        }
        result['limitations'] = [
            'Body comparison does not identify the eight outer bytes or prove the active handler class',
            'No challenge response, control channel or map replication was implemented by the probe',
        ]
    # Compare the captured local challenge and echo, without publishing cookies.
    messages = []
    for record, raw in zip((r for r in manifest['records'] if r['transport'] == 'udp'), packets):
        body = raw[8:] if record['direction'] == 'received' and len(raw) == 33 else raw
        try:
            message = decode_payload(body)
        except ValueError:
            continue
        messages.append((record['number'], record['direction'], message))
    challenges = [(n, m) for n, d, m in messages if d == 'sent' and m.timestamp > 0]
    echoes = [(n, m) for n, d, m in messages if d == 'received' and m.timestamp > 0]
    acks = [(n, m) for n, d, m in messages if d == 'sent' and m.timestamp < 0]
    verified = [(n, m) for n, m in echoes if any(m == c for _, c in challenges)]
    result['local_exchange'] = {'challenge_packets': len(challenges),
        'verified_echo_packets': len(verified), 'negative_time_ack_packets': len(acks),
        'raw_cookies_in_report': False, 'native_control_channel_established': False}
    # Native code 0x12bb9edb..0x12bb9ef3 seeds two 14-bit sequences from cookie
    # byte offsets zero and two. Cross-check a public UE packet-header candidate
    # against those local seeds rather than assuming a current UE5 layout.
    if acks:
        cookie = acks[-1][1].cookie
        seeds = [int.from_bytes(cookie[i:i+2], 'little') & 0x3fff for i in (0, 2)]
        applications = [(r, p[8:]) for r, p in zip(
            (r for r in manifest['records'] if r['transport'] == 'udp'), packets)
            if r['direction'] == 'received' and r['number'] > acks[-1][0] and len(p) != 33]
        candidates = []
        for prefix_bits in range(8):
            headers = []
            for rec, body in applications:
                bits = int.from_bytes(body, 'little')
                outer_bits = bits.bit_length() - 1
                if outer_bits <= prefix_bits + 32:
                    break
                packed = (bits >> prefix_bits) & 0xffffffff
                seq, ack, words = (packed >> 18) & 0x3fff, (packed >> 4) & 0x3fff, (packed & 15) + 1
                if words > 8 or outer_bits < prefix_bits + 32 + 32 * words:
                    break
                headers.append((rec['number'], seq, ack, words,
                                outer_bits - prefix_bits - 32 - 32 * words))
            if len(headers) != len(applications) or len(headers) < 3:
                continue
            for client_seed_index in (0, 1):
                client_seed, server_seed = seeds[client_seed_index], seeds[1-client_seed_index]
                initial_matches = headers[0][1] == client_seed
                ack_matches = all(h[2] == (server_seed - 1) & 0x3fff for h in headers)
                deltas = [(b[1]-a[1]) & 0x3fff for a, b in zip(headers, headers[1:])]
                if initial_matches and ack_matches and all(d == 1 for d in deltas):
                    candidates.append({'handler_prefix_bits': prefix_bits,
                        'packed_header_bits': 32, 'sequence_bits': 14,
                        'history_count_low_bits': 4, 'client_sequence_cookie_byte_offset': client_seed_index*2,
                        'server_sequence_cookie_byte_offset': (1-client_seed_index)*2,
                        'captured_application_packets': len(headers), 'sequence_deltas': deltas,
                        'history_word_counts': [h[3] for h in headers],
                        'bits_after_header_and_history': [h[4] for h in headers],
                        'short_tail_bit_values': [
                            (int.from_bytes(body, 'little') >> (prefix_bits+32+32*h[3])) & ((1 << h[4])-1)
                            for (_, body), h in zip(applications, headers) if h[4] <= 16],
                        'initial_sequence_and_peer_ack_match_own_cookie': True})
        result['post_handshake_header_candidates'] = candidates
        result['post_handshake_candidate_count'] = len(candidates)
        result['packet_header_candidate_native_receive_acceptance_verified'] = False
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('capture_directory', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    rendered = json.dumps(summarize(args.capture_directory), indent=2) + '\n'
    if args.output:
        args.output.write_text(rendered, encoding='utf-8')
    print(rendered, end='')
