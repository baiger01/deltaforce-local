"""Inspect fixed diagnostic labels and endpoint classes, never credential values."""
from pathlib import Path
from datetime import datetime, timezone
import json
import re

ROOT = Path(__file__).resolve().parent.parent
path = Path('D:/三角洲/WeGameApps/rail_apps/DeltaForce(2001918)/DeltaForce/Saved/Logs/DeltaForce.log')
raw = path.read_bytes()
assert len(raw) <= 32 * 1024 * 1024
lines = bytes(v ^ 0x5c for v in raw.removeprefix(b'\xef\xbb\xbf')).decode('utf-8', errors='replace').splitlines()
markers = ('GetGameBuildChannel', 'ParseGameChannel', 'GetLauncherChannel', 'GetWeGameSDKEnabled',
           'RailInitialize Success', 'RailInitialize Failed', 'MakeConnectInfo',
           'WeGame Global final zoneid:', 'WeGame Get ServerInfo Failed,set addr by channel',
           'Force Set AddrServer', 'WeGame TryAutoLogin With ZoneID:')
records = []
for n, line in enumerate(lines, 1):
    matched = [m for m in markers if m in line]
    if not matched:
        continue
    row = {'line': n, 'diagnostic_labels': matched}
    if any(m in line for m in ('GetGameBuildChannel', 'GetLauncherChannel')):
        channel = re.search(r'ChannelStr:([A-Za-z_]{1,32})(?=\s|$)', line)
        if channel and channel[1].lower() in ('official', 'wegame', 'steam', 'epic', 'google', 'unknown'):
            row['channel_name'] = channel[1]
        for key in ('ChannelNum', 'EGameChannel'):
            number = re.search(key + r':(-?\d{1,8})(?=\s|$)', line)
            if number:
                row[key] = int(number[1])
    if 'MakeConnectInfo' in line:
        row['field_labels'] = sorted(set(re.findall(r'\b([A-Za-z_][A-Za-z_0-9]{0,40})\s*[:=]', line)))
        endpoints = re.findall(r'\b(?:tcp|udp|gcp|tgp)://([^\s,"\}\]]+)', line)
        row['endpoint_count'] = len(endpoints)
        row['endpoint_is_loopback'] = [bool(re.match(r'(?:127\.0\.0\.1|localhost):', endpoint)) for endpoint in endpoints]
        row['contains_loopback_candidate'] = '127.0.0.1:65010' in line
    records.append(row)
result = {'observed_at_utc': datetime.now(timezone.utc).isoformat(), 'file': path.name,
          'records': records, 'raw_endpoint_or_credential_values_exported': False}
(ROOT / 'work/evidence/runtime_channel_metadata.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result, indent=2))
