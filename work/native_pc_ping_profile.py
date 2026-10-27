"""Qualify the recorded native Ping schema before enabling a local receiver."""
import hashlib
import json
from pathlib import Path

from dfserver.legacy_ds_actor_manifest import CLIENT_SHA256
from dfserver.legacy_ds_pc_ping_receiver import PCPingProfile

SOURCE = 'work/evidence/map-entry-next-20261005/pc-ping-native-wire-spec-and-normal-reply-1791208572984445800.json'
SOURCE_SHA256 = '9c844f3b0dc70724c76151d1106aecaed7354f6d43db52e2b6c60e4e95b3dd0d'
CLASS_PATH = '/Game/BluePrints/Characters/BP_DFMPlayerController.BP_DFMPlayerController_C'
MODULES = ('work/native_pc_ping_profile.py',
    'outputs/df-local-server/dfserver/legacy_ds_pc_ping_receiver.py',
    'outputs/df-local-server/dfserver/legacy_ds_pc_rpc_fields.py',
    'outputs/df-local-server/dfserver/legacy_ds_actor_fields.py',
    'outputs/df-local-server/dfserver/legacy_ds_actor_content.py',
    'outputs/df-local-server/dfserver/legacy_ds_bit_archive.py',
    'outputs/df-local-server/dfserver/legacy_ds_control_connection.py',
    'outputs/df-local-server/dfserver/game_server_probe.py')


def qualified_pc_ping_sources(root):
    root = Path(root).resolve(strict=True)
    pins = {}
    for relative in (SOURCE, *MODULES):
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise ValueError('PC Ping source is missing or outside its bound')
        pins[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    if pins[SOURCE] != SOURCE_SHA256 or hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != pins[MODULES[0]]:
        raise ValueError('PC Ping source identity mismatch')
    spec = json.loads((root / SOURCE).read_bytes())
    if spec.get('client_sha256') != CLIENT_SHA256 or spec.get('kind') != 'pinned_ordinary_server_bounce_ping_client_return_ping_wire_spec':
        raise ValueError('PC Ping schema does not match this client')
    metadata = spec['metadata_source']
    fields = {v['descriptor_name']: v for v in metadata['compatible_actual_pc_class_fields']}
    if (metadata['exclusive_index_maximum'] != 245 or
            metadata['observed_connection_internal_ack_bit_set'] is not False or
            fields['ServerBouncePing']['rep_index'] != 151 or fields['ClientReturnPing']['rep_index'] != 138 or
            any(v['incompatible'] or v['descriptor_representation'] != 1 for v in fields.values())):
        raise ValueError('PC Ping field profile lacks the recorded ordinary cache qualification')
    functions = {v['name']: v for v in spec['function_records']}
    for name, direction in (('ServerBouncePing', 'server_mask_0x200000'), ('ClientReturnPing', 'client_mask_0x1000000')):
        record = functions[name]
        if record['net_mask_0x40'] is not True or record[direction] is not True or record['reliable_mask_0x80'] is not False:
            raise ValueError('PC Ping direction or reliability differs from the native source')
    if spec['present_request_bits'] != 225 or spec['present_reply_bits'] != 161:
        raise ValueError('PC Ping scalar schema changed')
    return pins


def install_pc_ping_profile(root, probe, manifests, sealed_sources):
    pins = qualified_pc_ping_sources(root)
    if any(sealed_sources.get(k) != v for k, v in pins.items()):
        raise ValueError('PC Ping sources changed after trial sealing')
    matches = [item for item in manifests if item.class_path == CLASS_PATH]
    if len(matches) != 1:
        raise ValueError('PC Ping requires exactly one qualified controller manifest')
    profile = PCPingProfile(CLASS_PATH, 245, 151, 138, SOURCE_SHA256)
    probe.set_pc_ping_profile(2201, matches[0], profile)
    return {'status': 'explicit_native_ping_receiver_configured', 'source_relative_path': SOURCE,
            'source_sha256': SOURCE_SHA256, 'request_rep_index': 151, 'reply_rep_index': 138,
            'clock_policy': 'local_monotonic_world_and_authenticated_transport_receive_timestamps',
            'minimum_reply_interval_seconds': profile.minimum_reply_interval,
            'per_connection_reply_limit': profile.maximum_replies,
            'unknown_rpc_ack_enabled': False, 'scene_ready_implemented': False,
            'native_reply_acceptance_verified': False, 'playable_map_verified': False}
