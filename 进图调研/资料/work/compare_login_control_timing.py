"""Report timing and framing for one previously captured official GCP connection.

No addresses, payloads, keys, credentials, or TCP sequence values are exported.
"""
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "outputs/df-local-server"
sys.path.insert(0, str(SERVER))
from dfserver.gcp_framing import decode_prefix
from tools.analyze_capture import tcp_payload

CAPTURE = SERVER / "data/captures/20260927-005342-81888.pcapng"
EXPECTED_SHA256 = "70d8af6469185f4d3e97e3659a44506bfd15fd0a95f250f04e5ee4e083944439"
data = CAPTURE.read_bytes()
assert hashlib.sha256(data).hexdigest() == EXPECTED_SHA256
assert data[:4] == b"\x0a\x0d\x0d\x0a"

interfaces = []
seen = set()
rows = []
at = 0
endian = None
while at < len(data):
    if data[at:at + 4] == b"\x0a\x0d\x0d\x0a":
        endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}[data[at + 8:at + 12]]
        interfaces = []
    kind, size = struct.unpack_from(endian + "II", data, at)
    assert 12 <= size <= len(data) - at and size % 4 == 0
    assert struct.unpack_from(endian + "I", data, at + size - 4)[0] == size
    body = data[at + 8:at + size - 4]
    if kind == 1:
        assert len(body) >= 8
        link_type = struct.unpack_from(endian + "H", body)[0]
        # PCAPNG defaults to decimal microsecond resolution. Respect if_tsresol.
        resolution = 1_000_000
        opt = 8
        while opt + 4 <= len(body):
            code, length = struct.unpack_from(endian + "HH", body, opt)
            opt += 4
            if code == 0:
                break
            value = body[opt:opt + length]
            if code == 9 and length == 1:
                resolution = (2 if value[0] & 0x80 else 10) ** (value[0] & 0x7f)
            opt += (length + 3) & ~3
        interfaces.append((link_type, resolution))
    elif kind == 6:
        iface, high, low, caplen, original = struct.unpack_from(endian + "5I", body)
        assert iface < len(interfaces) and caplen <= len(body) - 20
        if caplen == original:
            link_type, resolution = interfaces[iface]
            parsed = tcp_payload(link_type, body[20:20 + caplen])
            if parsed:
                flow, sequence, payload = parsed
                if (flow[1], flow[3]) in ((55442, 65010), (65010, 55442)):
                    identity = (flow, sequence, payload)
                    if identity not in seen:
                        seen.add(identity)
                        offset = 0
                        while offset < len(payload):
                            if payload[offset:offset + 2] != b"\x33\x66":
                                break
                            try:
                                decoded = decode_prefix(memoryview(payload)[offset:])
                            except ValueError:
                                break
                            if decoded is None:
                                break
                            frame, used = decoded
                            rows.append({"direction": "server_to_client" if flow[1] == 65010 else "client_to_server",
                                         "command": f"0x{frame.command:04x}",
                                         "timestamp_ticks": (high << 32) | low,
                                         "resolution": resolution,
                                         "wire_bytes": frame.wire_size,
                                         "body_bytes": len(frame.body),
                                         "extra_header_bytes": len(frame.extra_header),
                                         "header_word9": frame.header_word9})
                            if frame.command == 0x4013 and len(frame.extra_header) >= 4:
                                rows[-1]["data_header_flags"] = list(frame.extra_header[:4])
                            offset += used
    at += size

assert rows
first = min(row["timestamp_ticks"] / row["resolution"] for row in rows)
for row in rows:
    row["relative_ms"] = round((row.pop("timestamp_ticks") / row.pop("resolution") - first) * 1000, 3)
report = {"checked_at_utc": datetime.now(timezone.utc).isoformat(),
          "capture_sha256": EXPECTED_SHA256,
          "frames": [row for row in rows if row["relative_ms"] < 10_000][:40],
          "only_complete_frames_within_one_tcp_payload": True,
          "payload_values_exported": False}
destination = SERVER / "protocol/login_control_timing_metadata.json"
destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"total_complete_single_segment_frames": len(rows),
                  "first_40_ten_second_frames": report["frames"]}, indent=2))
