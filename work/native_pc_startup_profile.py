"""Seal the observed startup declarations and native scalar/acknowledgement code."""
import hashlib
import json
from pathlib import Path, PurePosixPath

from dfserver.legacy_ds_actor_manifest import CLIENT_SHA256
from dfserver.legacy_ds_pc_startup_rpc import PCStartupProfile, PCStartupField

SPEC_PATH = 'work/evidence/map-entry-next-20261006/pc-startup-rpc-profile.json'
SPEC_SHA256 = 'a8e0b57afc3f19636f07c8f28997120165c5656093c8ee605323adc979c39357'
CLASS_PATH = '/Game/BluePrints/Characters/BP_DFMPlayerController.BP_DFMPlayerController_C'
MODULES = ('work/native_pc_startup_profile.py',
           'work/native_post_actor_retry.py',
           'outputs/df-local-server/dfserver/legacy_ds_pc_startup_rpc.py')


def qualified_pc_startup_sources(root):
    root = Path(root).resolve(strict=True)
    def read(relative):
        if (type(relative) is not str or ':' in relative or '\\' in relative or
                PurePosixPath(relative).is_absolute() or
                any(p in ('', '.', '..') for p in relative.split('/'))):
            raise ValueError('Startup evidence requires a plain project-relative path')
        p = (root / relative).resolve(strict=True)
        if not p.is_relative_to(root) or not p.is_file() or p.stat().st_size > 1024 * 1024:
            raise ValueError('Startup source is missing or outside its bound')
        raw = p.read_bytes()
        return raw, hashlib.sha256(raw).hexdigest()
    raw, digest = read(SPEC_PATH)
    if digest != SPEC_SHA256:
        raise ValueError('PC startup declaration seal changed')
    spec = json.loads(raw)
    if (spec['kind'] != 'native_pc_startup_rpc_profile' or spec['client_sha256'] != CLIENT_SHA256 or
            spec['class_path'] != CLASS_PATH or spec['exclusive_index_maximum'] != 245 or
            spec['internal_ack'] is not False or spec['archive_byte_swap'] is not False or
            spec['qualification']['native_parameter_grammar_recovered'] is not True):
        raise ValueError('PC startup schema does not match the native source')
    functions = {f['name']: f for f in spec['functions']}
    if len(functions) != 5:
        raise ValueError('The startup source must contain exactly five declared functions')
    for name in ('ServerShortTimeout', 'Server_RcvACWorldTime', 'ServerFieldOfView', 'NotifySeamlessLoginReady', 'ClientAckSeamlessLoginReady'):
        f = functions[name];flags = f['function_flags']
        direction = 0x1000000 if name == 'ClientAckSeamlessLoginReady' else 0x200000
        if (not flags & 0x40 or not flags & 0x80 or not flags & direction or
                f['identity_and_fields_rechecked'] is not True):
            raise ValueError('Startup RPC direction or reliability differs from its source')
        commands = f['commands']
        if name in ('ServerShortTimeout', 'ClientAckSeamlessLoginReady'):
            if f['parameter_parent_count'] != 0 or len(commands) != 1 or commands[0]['dispatch_opcode'] != 1:
                raise ValueError('Empty startup RPC has an unqualified parameter layout')
        else:
            c = commands[0]
            if (f['parameter_parent_count'] != 1 or len(commands) != 2 or
                    c['data_offset'] != 0 or commands[-1]['dispatch_opcode'] != 1):
                raise ValueError('Startup RPC requires one exact scalar declaration')
            target = '0x10e8ebe0' if name == 'NotifySeamlessLoginReady' else '0x10e5ce20'
            if c['property_serializer_hook']['target_rva'] != target or c['property_serializer_hook']['identity_rechecked'] is not True:
                raise ValueError('Startup scalar serializer differs from the observed native target')
            if name != 'NotifySeamlessLoginReady' and c['property_scalar_leaf_hook']['target_rva'] != '0x286bf70':
                raise ValueError('Startup float scalar leaf is not qualified')
    pins = {SPEC_PATH: digest}
    for row in spec['source_files']:
        _, actual = read(row['relative_path'])
        if actual != row['sha256']:
            raise ValueError('Startup native code source changed')
        pins[row['relative_path']] = actual
    for relative in MODULES:
        _, pins[relative] = read(relative)
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != pins[MODULES[0]]:
        raise ValueError('PC startup helper was imported from another checkout')
    return pins


def install_pc_startup_profile(root, probe, manifests, sealed_sources):
    pins = qualified_pc_startup_sources(root)
    if any(sealed_sources.get(k) != v for k, v in pins.items()):
        raise ValueError('PC startup source identity changed after trial sealing')
    spec = json.loads((Path(root) / SPEC_PATH).read_bytes())
    functions = {f['name']: f for f in spec['functions']}
    requests = tuple(PCStartupField(name, functions[name]['rep_index'], kind) for name, kind in (
        ('ServerShortTimeout', 'empty'), ('Server_RcvACWorldTime', 'float32'),
        ('ServerFieldOfView', 'float32'), ('NotifySeamlessLoginReady', 'bool')))
    profile = PCStartupProfile(CLASS_PATH, spec['exclusive_index_maximum'], requests,
        functions['ClientAckSeamlessLoginReady']['rep_index'], SPEC_SHA256)
    matches = [m for m in manifests if m.class_path == CLASS_PATH]
    if len(matches) != 1:
        raise ValueError('Startup receiver requires exactly one evidenced PC manifest')
    probe.set_pc_startup_profile(2201, matches[0], profile)
    return {'status': 'explicit_startup_rpc_receiver_configured', 'source_relative_path': SPEC_PATH,
            'source_sha256': SPEC_SHA256, 'request_names': [f.name for f in requests],
            'ready_acknowledgement_index': profile.acknowledgement_index,
            'reliable_retries_idempotent': True, 'unknown_bunch_ack_enabled': False,
            'native_ack_callback_verified': False, 'scene_ready_implemented': False,
            'playable_map_verified': False}
