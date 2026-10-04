"""Compare only numeric GCP header fields from the paired login handshake."""
from collections import defaultdict
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parent.parent
PROJECT = ROOT / 'outputs/df-local-server'
sys.path[:0] = [str(PROJECT / 'tools'), str(PROJECT)]
from analyze_capture import captured_packets, tcp_payload, reassemble
from dfserver.gcp_framing import decode_prefix

capture = PROJECT / 'data/captures/20260927-005342-81888.pcapng'
raw = capture.read_bytes()
assert hashlib.sha256(raw).hexdigest() == '70d8af6469185f4d3e97e3659a44506bfd15fd0a95f250f04e5ee4e083944439'
flows = defaultdict(list)
for link, packet, _ in captured_packets(raw):
    parsed = tcp_payload(link, packet)
    if parsed and 65010 in (parsed[0][1], parsed[0][3]):
        key, sequence, data = parsed
        flows[key].append((sequence, data))
rows = []
for key, segments in flows.items():
    for _, region in reassemble(segments)[0]:
        offset = 0
        while offset < len(region):
            try:
                parsed = decode_prefix(region[offset:])
            except ValueError:
                break
            if parsed is None:
                break
            frame, size = parsed
            offset += size
            if frame.command not in (0x1001, 0x1002):
                continue
            rows.append({'direction': 'client_to_server' if key[3] == 65010 else 'server_to_client',
                         'version': frame.version, 'command': frame.command,
                         'header_word4': frame.header_word4, 'header_word9': frame.header_word9,
                         'payload_encryption_flag': frame.payload_encryption_flag,
                         'extra_header_bytes': len(frame.extra_header), 'body_bytes': len(frame.body)})
assert len(rows) == 2 and {item['command'] for item in rows} == {0x1001, 0x1002}
result = {'capture_sha256': hashlib.sha256(raw).hexdigest(), 'handshake_headers': rows,
          'payloads_or_keys_exported': False, 'client_dh_modulus_recovered': False}
destination = PROJECT / 'protocol/handshake_header_words.json'
destination.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result, indent=2))
