"""Summarize captured DS traffic and entry stages without exposing session data."""
import argparse
from collections import Counter
from datetime import datetime, timedelta
import hashlib
import json
from itertools import zip_longest
from pathlib import Path
import re
import socket
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server/tools'))
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from analyze_capture import captured_packets, wifi_ipv4, MAX_CAPTURE
from dfserver.unreal_handshake_payload import decode_payload, encode_payload
from ds_capture_timing import packet_unix_times


def udp_frame(link, frame):
    if link == 1:
        if len(frame) < 14:
            return None
        ether, at = int.from_bytes(frame[12:14], 'big'), 14
        while ether in (0x8100, 0x88a8):
            if len(frame) < at + 4:
                return None
            ether, at = int.from_bytes(frame[at + 2:at + 4], 'big'), at + 4
        ip = frame[at:] if ether == 0x0800 else wifi_ipv4(frame)
    elif link == 105:
        ip = wifi_ipv4(frame)
    elif link in (101, 228):
        ip = frame
    else:
        return None
    if not ip or len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 17:
        return None
    ihl, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], 'big')
    if ihl < 20 or total < ihl + 8 or len(ip) < total or int.from_bytes(ip[6:8], 'big') & 0x3fff:
        return None
    udp = ip[ihl:total]
    source, dest, length, _ = struct.unpack_from('>4H', udp)
    if length < 8 or length > len(udp):
        return None
    return ((socket.inet_ntoa(ip[12:16]), source),
            (socket.inet_ntoa(ip[16:20]), dest), udp[8:length])


def handshake_candidate(payload):
    offsets = (0,) if len(payload) == 25 else (8,) if len(payload) == 33 else ()
    for offset in offsets:
        try:
            message = decode_payload(payload[offset:])
        except ValueError:
            continue
        initial = message.timestamp == 0 and not any(message.cookie)
        role = ('initial_body' if initial else 'ack_body' if message.timestamp == -1
                else 'positive_time_body_candidate' if message.timestamp > 0 else 'other_body_candidate')
        return {'offset': offset, 'role': role, 'restart': message.restart,
                'third_flag': message.third_flag, 'cookie_zero': not any(message.cookie),
                'candidate_only': True}
    return None


def compare_initial_exchange(records):
    """Compare the first server wire body with the client's fixed-body echo.

    Equal lengths or an echoed-cookie layout alone cannot identify an incoming
    transform. Only shape/equality results are exported, never cookie values.
    """
    initial_seen, server_body, echo = False, None, None
    for direction, body in records:
        if direction == 'client_to_server' and len(body) == 33:
            try:
                message = decode_payload(body[8:])
            except ValueError:
                continue
            if message.timestamp == 0 and not any(message.cookie):
                initial_seen = True
            elif initial_seen and server_body is not None and message.timestamp > 0:
                echo = message
                break
        elif direction == 'server_to_client' and initial_seen and server_body is None:
            server_body = body
    result = {'initial_request_body_candidate_observed': initial_seen,
              'initial_server_packet_then_positive_client_body_observed': echo is not None,
              'server_response_envelope_verified': False,
              'encryption_algorithm_identified': False, 'session_values_exported': False}
    if echo is None:
        return result
    plain_echo = encode_payload(echo)
    result.update(server_first_payload_bytes=len(server_body), client_echo_third_flag=echo.third_flag,
                  server_wire_handshake_bit=bool(server_body[0] & 1))
    if len(server_body) == len(plain_echo):
        result['wire_vs_plain_echo_differing_bytes'] = sum(a != b for a, b in zip(server_body, plain_echo))
        result['wire_vs_plain_echo_differing_bits'] = sum((a ^ b).bit_count() for a, b in zip(server_body, plain_echo))
        value, cookie, mask = int.from_bytes(server_body, 'little'), int.from_bytes(echo.cookie, 'little'), (1 << 160) - 1
        result['client_echo_cookie_found_as_contiguous_wire_bits'] = any(
            (value >> offset) & mask == cookie for offset in range(len(server_body) * 8 - 160 + 1))
    return result


def summarize(folder):
    manifest = json.loads((folder / 'report.json').read_text(encoding='utf-8'))
    if not manifest.get('capture_export_succeeded') or not manifest.get('record_complete'):
        raise ValueError('Capture has not finished exporting')
    path = folder / 'official-ds.pcapng'
    if not 0 < path.stat().st_size <= MAX_CAPTURE:
        raise ValueError('Capture size exceeds the analysis bound')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['pcapng_sha256']:
        raise ValueError('Capture hash does not match its manifest')
    endpoints = {tuple(peer) for peer in manifest['matched_endpoints']}
    stage_times = {name: entry['client_wall_time'] for entry in manifest['stages']
                   for name in entry.get('stage_names', [])}
    # This tool runs on the same host as the client. A prearmed capture can contain
    # an earlier match, so ignore records before the fresh entry's start marker.
    start_text = stage_times.get('start_connect_requested')
    window_start = datetime.strptime(start_text, '%Y.%m.%d-%H.%M.%S:%f').timestamp() - 1 if start_text else None
    driver_text = stage_times.get('net_driver_initialized')
    driver_time = datetime.strptime(driver_text, '%Y.%m.%d-%H.%M.%S:%f').timestamp() if driver_text else None
    flows, unmatched, total, excluded_earlier = {}, 0, 0, 0
    records = zip_longest(captured_packets(raw), packet_unix_times(raw))
    for ordinal, (packet, packet_time) in enumerate(records):
        if packet is None or packet_time is None:
            raise ValueError('Packet records and timestamp records disagree')
        link, frame, truncated = packet
        total += 1
        if window_start is not None and packet_time < window_start:
            excluded_earlier += 1
            continue
        parsed = udp_frame(link, frame)
        if not parsed:
            unmatched += 1
            continue
        source, dest, body = parsed
        if dest in endpoints:
            direction, key = 'client_to_server', (source, dest)
        elif source in endpoints:
            direction, key = 'server_to_client', (dest, source)
        else:
            unmatched += 1
            continue
        flow = flows.setdefault(key, {'directions': Counter(), 'lengths': Counter(),
                                     'first_records': [], 'candidate_records': [], 'truncated': 0,
                                     'initial_exchange_private': []})
        flow['directions'][direction] += 1
        flow['lengths'][len(body)] += 1
        flow['truncated'] += truncated
        record = {'capture_record_index': ordinal, 'direction': direction, 'payload_bytes': len(body),
                  'milliseconds_from_net_driver_initialized':
                      round((packet_time - driver_time) * 1000, 3) if driver_time is not None else None}
        if len(flow['initial_exchange_private']) < 32:
            flow['initial_exchange_private'].append((direction, body))
        candidate = handshake_candidate(body)
        if candidate:
            record['body_candidate'] = candidate
            if len(flow['candidate_records']) < 20:
                flow['candidate_records'].append(record)
        if len(flow['first_records']) < 12:
            flow['first_records'].append(record)
    stages = stage_times
    result = {'kind': 'official_ds_capture_analysis',
              'source_relative_to_project_root': str(path.relative_to(ROOT)).replace('\\', '/'),
              'source_sha256': manifest['pcapng_sha256'], 'source_bytes': len(raw),
              'capture_record_count': total, 'unparsed_or_unmatched_records': unmatched,
              'records_excluded_before_fresh_entry': excluded_earlier,
              'fresh_entry_time_filter_applied': window_start is not None,
              'stage_times': stages, 'birth_status': manifest.get('birth_status', 'not_verified_by_capture'),
              'native_post_connect_observed': 'post_connect' in stages,
              'native_all_players_ready_observed': 'all_players_ready' in stages,
              'full_four_step_handshake_observed': False, 'raw_packets_in_report': False,
              'session_values_in_report': False, 'flows': [],
              'limitations': [
                  'Capture records can include NIC/offload duplicates and aggregated buffers',
                  'A body-layout candidate does not identify encryption, the outer header, or packet role',
                  'Body layout candidates do not prove a complete four-step handshake',
                  'No incoming ACK body matched the recovered unencrypted fixed-body codec',
                  'Traffic after connection does not recover actor schemas or server-side AI code']}
    for index, flow in enumerate(flows.values(), 1):
        result['flows'].append({'flow_id': index, 'direction_record_counts': dict(flow['directions']),
                                'payload_bytes_min': min(flow['lengths']), 'payload_bytes_max': max(flow['lengths']),
                                'most_common_lengths': flow['lengths'].most_common(8),
                                'truncated_records': flow['truncated'], 'first_records': flow['first_records'],
                                'initial_exchange_comparison': compare_initial_exchange(flow['initial_exchange_private']),
                                'fixed_body_candidates': flow['candidate_records']})
    result['initial_request_body_candidate_observed'] = any(
        record.get('body_candidate', {}).get('role') == 'initial_body'
        for flow in flows.values() for record in flow['candidate_records'])
    return result


def entry_parameter_shapes(log_path, capture_report):
    # Restrict the log evidence to the same connection window. Values, including
    # SecretKey, remain private in the client's log and are never copied here.
    times = [entry['client_wall_time'] for entry in capture_report['stages']
             if 'connection_url_built' in entry.get('stage_names', [])]
    if not times:
        return []
    targets = [datetime.strptime(value, '%Y.%m.%d-%H.%M.%S:%f') for value in times]
    raw = log_path.read_bytes()
    text = raw.removeprefix(b'\xef\xbb\xbf').translate(bytes(v ^ 0x5c for v in range(256))).decode('utf-8', 'replace')
    output = []
    for line in text.splitlines():
        if ('UGameFlowGraph::OnLuaGameFlowEvent()' not in line or
                'flowEvtPreparationStartMatchSuccess' not in line):
            continue
        stamp = re.match(r'^\[([^\]]+)\]', line)
        if not stamp:
            continue
        wall_time = datetime.strptime(stamp[1], '%Y.%m.%d-%H.%M.%S:%f')
        if not any(abs(wall_time - target) <= timedelta(seconds=2) for target in targets):
            continue
        lengths = {name: len(value) for name, value in re.findall(r'\?([A-Za-z0-9_]+)=([^?\s]*)', line)}
        output.append({'client_wall_time': stamp[1], 'url_parameter_lengths': lengths,
                       'secret_key_nonempty': lengths.get('SecretKey', 0) > 0,
                       'encryption_algorithm_identified': False})
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture_folder', type=Path)
    parser.add_argument('--game-root', type=Path)
    args = parser.parse_args()
    folder = args.capture_folder.resolve()
    if not folder.is_relative_to(ROOT / 'work/official-ds-captures'):
        parser.error('Use a local official capture folder')
    report = summarize(folder)
    if args.game_root:
        manifest = json.loads((folder / 'report.json').read_text(encoding='utf-8'))
        report['entry_parameter_shapes'] = entry_parameter_shapes(
            args.game_root / 'DeltaForce/Saved/Logs/DeltaForce.log', manifest)
    output = folder / 'analysis.json'
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'analysis_path': str(output), 'capture_records': report['capture_record_count'],
                      'matched_flows': len(report['flows']),
                      'native_post_connect_observed': report['native_post_connect_observed'],
                      'native_all_players_ready_observed': report['native_all_players_ready_observed'],
                      'full_four_step_handshake_observed': False,
                      'entry_parameter_shapes': report.get('entry_parameter_shapes', [])}, indent=2))
