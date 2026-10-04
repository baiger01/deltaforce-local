"""Validate and publish static handoff metadata, excluding original code and keys."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import struct
import pefile

ROOT = Path(__file__).resolve().parent.parent
raw = (ROOT / 'work/official-standalone-launcher/service_core.dll').read_bytes()
digest = hashlib.sha256(raw).hexdigest()
assert digest == 'a7c22fac8c044cc96df4b9e565d8189f9cbeda31712e9d5dcb299252fd48bcee'
pe = pefile.PE(data=raw)
base = pe.OPTIONAL_HEADER.ImageBase
def data(va, n):
    return pe.get_data(va - base, n)
def narrow(va):
    return data(va, 256).split(b'\0', 1)[0].decode('ascii')
def wide(va):
    b = data(va, 256)
    end = next(n for n in range(0, len(b)-1, 2) if b[n:n+2] == b'\0\0')
    return b[:end].decode('utf-16le')

anchors = [(0x10106df5, 0x105759c4), (0x1011fbfd, 0x1057426c), (0x10098494, 0x10564220)]
for instruction, pointer in anchors:
    assert data(instruction, 5) == b'\x68' + struct.pack('<I', pointer)
assert narrow(0x105759c4) == 'servers_info'
assert narrow(0x1057426c) == 'GameInfo.LaunchParam'
assert wide(0x10564220) == 'VERSION_SERVICE_GET_ZONE_URL'
assert wide(0x1056c75c) == 'developer.ini'
assert wide(0x1056c790) == 'Cfg'
assert wide(0x10575bac) == 'CommandLine'
locator = struct.unpack('<I', data(0x10567ea4 - 4, 4))[0]
type_pointer = struct.unpack('<5I', data(locator, 20))[3]
rtti = narrow(type_pointer + 8)
assert 'Srv_VersionMgr_GetGameZoneJsonInfo' in rtti
imports = {i.address: (entry.dll.decode('ascii'), i.name.decode('ascii') if i.name else None)
           for entry in pe.DIRECTORY_ENTRY_IMPORT for i in entry.imports}
assert imports[0x10559360][1] == 'GetPrivateProfileStringW'
assert imports[struct.unpack('<I', data(0x102d18f2 + 2, 4))[0]][1] == '??AValue@Json@@QAEAAV01@PBD@Z'
assert imports[struct.unpack('<I', data(0x102d19dc + 2, 4))[0]][1].startswith('??0Value@Json@@QAE@ABV?$basic_string')

report = {
    'validated_at_utc': datetime.now(timezone.utc).isoformat(),
    'source_sha256': digest,
    'evidence_kind': 'Immutable disk instructions, import table and RTTI; not a runtime route test',
    'server_configuration_handoff': {
        'launch_function_va': '0x10106866',
        'source_event_type': 'Srv_VersionMgr_GetGameZoneJsonInfo',
        'json_property': 'servers_info',
        'property_write_va': '0x10106df5',
        'source_field_offset': '0x48',
        'property_value_type': 'string',
        'public_zone_request_url_configuration_name': 'VERSION_SERVICE_GET_ZONE_URL',
        'public_zone_request_body_field_names': ['from_src', 'game_id'],
        'zone_api_url_resolved': False,
        'game_consumption_of_this_property_verified': False,
        'dh_parameters_recovered_from_this_property': False,
    },
    'dynamic_launch_parameter_update': {
        'response_handler_va': '0x1011f6a7',
        'configuration_key': 'GameInfo.LaunchParam',
        'configuration_key_reference_va': '0x1011fbfd',
        'static_update_path_present': True,
        'runtime_update_observed': False,
    },
    'extra_command_line_configuration': {
        'file_name': 'developer.ini',
        'section': 'Cfg', 'key': 'CommandLine',
        'windows_reader': 'GetPrivateProfileStringW',
        'runtime_read_verified': False,
        'local_destination_override_verified': False,
        'configuration_written': False,
    },
    'local_connection_entry_verified': False,
    'original_client_offline_lobby_available': False,
    'original_code_keys_or_credentials_exported': False,
    'binaries_configuration_registry_hosts_or_routes_modified': False,
}
(ROOT / 'work/evidence/official_launcher_handoff_static_validation.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
for name in ('status.json', 'address_activation_evidence.json'):
    path = ROOT / 'outputs/df-local-server/protocol' / name
    document = json.loads(path.read_text(encoding='utf-8'))
    document['official_standalone_route_investigation']['launcher_handoff_static_validation'] = report
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'static_anchors_validated': len(anchors), 'json_handoff_type_and_imports_validated': True,
                  'local_connection_entry_verified': False, 'original_client_offline_lobby_available': False}, indent=2))
