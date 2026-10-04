"""Summarize native DS stages without copying log payloads or session material."""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parent.parent
client = json.loads((ROOT / 'outputs/native-account-provider/client-observation.json').read_text(encoding='utf-8'))
path = Path(client['test_game_root']) / 'DeltaForce/Saved/Logs/DeltaForce.log'
raw = path.read_bytes()
body = raw[3:] if raw.startswith(b'\xef\xbb\xbf') else raw
decoded = body.translate(bytes(i ^ 0x5c for i in range(256)))
assert b'LogPakFile:' in decoded[:4096]
markers = ('Handshake', 'Stateless', 'Challenge', 'PendingNetGame', 'SendInitialJoin',
           'NotifyControlMessage', 'ConnectionTimeout', 'Connection closed', 'realDSconnect',
           'NetDriver', 'Welcomed by server', 'Join succeeded', 'PreLoadMap', 'PostLoadMap',
           'Connection established', 'HandshakeComplete', 'LogNet:', 'LogPacketHandler:',
           'OnConnected', 'PhysicsScene', 'LevelStreaming', 'ServerConnection',
           'ReceivedRawPacket', 'OnPacketRecv', 'PacketHandler', 'ConnectionLost',
           'NetConnection', 'NetworkFailure', 'TravelFailure', 'LoadMap',
           'local_identity', 'Connection timeout', 'GPCsPlayerJoinMatchNtf',
           '连接超时', '登录数据异常', '登录组件异常')
records = []
counts = Counter()
for number, line in enumerate(decoded.decode('utf-8', errors='replace').splitlines(), 1):
    found = [m for m in markers if m.casefold() in line.casefold()]
    if not found:
        continue
    counts.update(found)
    timestamp = re.match(r'\[([^\]]+)\]', line)
    category = re.search(r'\b(Log[A-Za-z0-9_]+):', line)
    scalars = dict(re.findall(r'\b(errorCode|error_code|MapId|map_id|progress|result|ret|State|state|Bits|bits|Sequence|sequence)\s*[:=]\s*(-?\d+)\b', line))
    records.append({'line': number, 'timestamp': timestamp[1] if timestamp else None,
                    'category': category[1] if category else None, 'markers': found,
                    'numeric_fields': scalars,
                    'status_words': [w for w in ('failed', 'success', 'complete', 'timeout',
                        'error', 'sent', 'received', 'initial', 'challenge', 'ack',
                        'pending', 'ready', 'loaded', 'cancel', 'close', 'waiting',
                        'control', 'hello', 'welcome', 'login', 'join', 'spawn')
                        if re.search(r'\b' + w + r'\b', line, re.IGNORECASE)]})
    if category and category[1] in ('LogNet', 'LogHandshake', 'LogPacketHandler'):
        prefix = line.split(category[1] + ':', 1)[1]
        prefix = re.split(r'(?i)\b(?:URL|Browse|Login|token|openid|pfkey|secretkey|cookie|account|password)\b', prefix, maxsplit=1)[0]
        prefix = re.sub(r'https?://\S+|\d{12,}|[A-Za-z0-9_+/=-]{28,}', '<redacted>', prefix)
        prefix = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?', '<endpoint>', prefix)
        records[-1]['message_prefix'] = prefix.strip()[:240]
event_path = max((ROOT / 'work/native-client-tests').glob('*/events.jsonl'), key=lambda p: p.stat().st_mtime)
report = {'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'trial': event_path.parent.name,
          'client_test_started_at_utc': client['observed_at_utc'],
          'marker_counts': dict(counts), 'records': records[-120:], 'raw_payloads_included': False}
report['connection_records'] = [r for r in records if r['category'] in
    ('LogNet', 'LogHandshake', 'LogPacketHandler') or any(m in r['markers'] for m in
    ('HandshakeComplete', 'Welcomed by server', 'Join succeeded', 'SendInitialJoin', 'realDSconnect'))][-80:]
(event_path.parent / 'native-ds-stage-observation.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(json.dumps(report, ensure_ascii=False, indent=2))
