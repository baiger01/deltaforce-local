"""Reassemble captured TCP bytes and export only initial GCP frame metadata."""
from collections import defaultdict
from pathlib import Path
import hashlib
import json
import sys

root = Path(__file__).resolve().parent.parent
server = root / 'outputs/df-local-server'
sys.path.insert(0, str(server))
from tools.analyze_capture import captured_packets, tcp_payload, reassemble
from dfserver.gcp_framing import decode_prefix

capture = server / 'data/captures/20260927-005342-81888.pcapng'
raw = capture.read_bytes()
assert hashlib.sha256(raw).hexdigest() == '70d8af6469185f4d3e97e3659a44506bfd15fd0a95f250f04e5ee4e083944439'
flows = defaultdict(list)
for link, packet, truncated in captured_packets(raw):
    parsed = tcp_payload(link, packet)
    if parsed:
        key, sequence, body = parsed
        if (key[1], key[3]) in ((55442, 65010), (65010, 55442)):
            flows['server_to_client' if key[1] == 65010 else 'client_to_server'].append((sequence, body))
rows = {}
for direction, segments in flows.items():
    regions, duplicates, conflicts = reassemble(segments)
    frames = []
    for start, body in regions:
        offset = 0
        while offset < len(body) and len(frames) < 40:
            try:
                parsed = decode_prefix(body[offset:])
            except ValueError:
                break
            if parsed is None:
                break
            frame, size = parsed
            frames.append({'command': f'0x{frame.command:04x}',
                           'version': frame.version,
                           'header_word4': frame.header_word4,
                           'payload_encryption_flag': frame.payload_encryption_flag,
                           'header_word9': frame.header_word9,
                           'wire_bytes': size,
                           'body_bytes': len(frame.body),
                           'data_flags': list(frame.extra_header[:4]) if frame.command == 0x4013 else None})
            offset += size
    rows[direction] = {'contiguous_regions': len(regions), 'duplicates': duplicates,
                       'conflicts': conflicts, 'first_frames': frames}
report = {'capture_sha256': hashlib.sha256(raw).hexdigest(), 'raw_payload_exported': False,
          'directions': rows}
path = server / 'protocol/official_initial_frames_metadata.json'
path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps(report, indent=2))
