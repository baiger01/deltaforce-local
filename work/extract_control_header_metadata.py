"""Compare captured login control-frame headers without exporting payloads."""
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parent.parent
PROJECT = ROOT / 'outputs/df-local-server'
sys.path.insert(0, str(PROJECT))
from dfserver.gcp_framing import decode_prefix
from tools.analyze_capture import captured_packets, tcp_payload, reassemble

CAPTURE = PROJECT / 'data/captures/20260927-005342-81888.pcapng'
EXPECTED_SHA256 = '70d8af6469185f4d3e97e3659a44506bfd15fd0a95f250f04e5ee4e083944439'
raw = CAPTURE.read_bytes()
assert hashlib.sha256(raw).hexdigest() == EXPECTED_SHA256
assert len(raw) <= 128 * 1024 * 1024
flows = defaultdict(list)
for link, packet, truncated in captured_packets(raw):
    if truncated:
        continue
    found = tcp_payload(link, packet)
    if found:
        key, sequence, payload = found
        if key[1] == 65010 or key[3] == 65010:
            flows[key].append((sequence, payload))

metadata = []
for key, segments in flows.items():
    if not ((key[1] == 65010 and key[3] == 55442) or
            (key[1] == 55442 and key[3] == 65010)):
        continue
    for _, region in reassemble(segments)[0]:
        if not region.startswith(b'\x33\x66'):
            continue
        offset = 0
        while offset < len(region):
            try:
                decoded = decode_prefix(memoryview(region)[offset:])
            except ValueError:
                break
            if decoded is None:
                break
            frame, size = decoded
            if frame.command in (0x1001, 0x1002, 0x2001, 0x2002, 0x6002):
                metadata.append({'direction': 'server_to_client' if key[1] == 65010 else 'client_to_server',
                                 'command': f'0x{frame.command:04x}',
                                 'version': frame.version,
                                 'header_word4': frame.header_word4,
                                 'header_word9': frame.header_word9,
                                 'encryption_flag': frame.payload_encryption_flag,
                                 'extra_header_bytes': len(frame.extra_header),
                                 'body_bytes': len(frame.body),
                                 'wire_bytes': frame.wire_size})
            offset += size

assert {row['command'] for row in metadata} == {'0x1001', '0x1002', '0x2001', '0x2002', '0x6002'}
report = {'checked_at_utc': datetime.now(timezone.utc).isoformat(),
          'capture_sha256': EXPECTED_SHA256,
          'control_frames': metadata,
          'raw_payloads_credentials_keys_or_ip_addresses_exported': False}
path = PROJECT / 'protocol/login_control_header_metadata.json'
path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(report, ensure_ascii=False, indent=2))
