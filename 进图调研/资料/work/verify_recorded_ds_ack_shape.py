"""Check the bounded ACK parser against our private native loopback capture."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from dfserver.legacy_ds_packet_ack_probe import LegacyDSPacketAckProbe, decode_packet
from dfserver.unreal_handshake_payload import decode_payload

folder = ROOT / 'work/native-client-tests/1790831328076933800/game-server-packets'
manifest = json.loads((folder / 'report.json').read_text(encoding='utf-8'))
peer = ('127.0.0.1', 54321)
probe = LegacyDSPacketAckProbe()
events = Counter()
for record in manifest['records']:
    name = record['private_packet_file']
    assert Path(name).name == name
    raw = (folder / name).read_bytes()
    assert len(raw) == record['bytes'] and hashlib.sha256(raw).hexdigest() == record['sha256']
    if record['direction'] == 'sent' and len(raw) == 25:
        message = decode_payload(raw)
        if message.timestamp < 0:
            probe.register_verified_echo(peer, message.cookie)
    elif record['direction'] == 'received' and len(raw) != 33:
        event, reply = probe.handle(raw, peer)
        events[event] += 1
        if reply:
            parsed = decode_packet(reply)
            assert parsed.remainder_bits == 9 and parsed.remainder == 0
assert events == {'control_payload_unimplemented': 2, 'empty_packet_ack_prepared': 6}
report = {'source_trial_relative_to_project_root': folder.parent.relative_to(ROOT).as_posix(),
          'native_captured_application_packets_replayed': 8, 'event_counts': dict(events),
          'all_recorded_packets_hash_verified': True, 'raw_payloads_or_cookies_exported': False,
          'candidate_parser_matches_recorded_native_packets': True,
          'native_receive_acceptance_verified': False, 'control_channel_implemented': False}
(folder.parent / 'recorded-ack-parser-check.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
print(json.dumps(report, indent=2))
