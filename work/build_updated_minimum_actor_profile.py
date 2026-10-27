"""Compile sealed current declarations without activating Actor transmission.

This is a distinct source-derived profile, not a relabeled native observation.
The launcher still needs qualified connection/header context and a current
Actor plan. No process, socket, installed-client write or old-profile rewrite.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from dfserver.transport.native.legacy_ds_current_pc_rpc_profile import (
    CURRENT_CLIENT_SHA256, CURRENT_PC_CLASS_PATH, CURRENT_RPC_SOURCE_PATH,
    CURRENT_RPC_SOURCE_SHA256, CURRENT_RPC_RECEIVE_SOURCE_PATH,
    CURRENT_RPC_RECEIVE_SOURCE_SHA256, qualify_current_pc_rpc_sources,
)

READINESS_PATH = 'work/research_updated_minimum_profile_readiness_79fb7b10_v1.json'
READINESS_SHA256 = '6e2f513a37d7e47f4f1240a64416297ae970dc830546670efcd95382c1270890'
COOKED_PATH = 'work/research_updated_cooked_declarations_79fb7b10_v5.json'
COOKED_SHA256 = 'b29f6cda96c690351596f5e96879d96267610adbfd86b36cd253661af7ec3037'
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
ROLES = {'Pawn': 'BP_DFMCharacter_C', 'PlayerController': 'BP_DFMPlayerController_C',
         'GameState': 'BP_GameState_PVPVE_C', 'PlayerState': 'BP_SOLPlayerState_C'}


def _document(raw, expected):
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_SOURCE_BYTES or
            hashlib.sha256(raw).hexdigest() != expected):
        raise ValueError('Current minimum source SHA256 mismatch')
    return json.loads(raw)


def _read(root, relative):
    name = PurePosixPath(relative)
    if (not isinstance(relative, str) or ':' in relative or '\\' in relative or
            name.is_absolute() or any(p in ('', '.', '..') for p in relative.split('/'))):
        raise ValueError('A bounded project-relative current source is required')
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or not 0 < path.stat().st_size <= MAX_SOURCE_BYTES:
        raise ValueError('Current minimum source exceeds project/size bound')
    return path.read_bytes()


def source_blobs(root=ROOT):
    root = Path(root).resolve(strict=True)
    raw = _read(root, READINESS_PATH)
    readiness = _document(raw, READINESS_SHA256)
    pins = {READINESS_PATH: READINESS_SHA256, COOKED_PATH: COOKED_SHA256, **readiness['source_proofs'],
        CURRENT_RPC_RECEIVE_SOURCE_PATH: CURRENT_RPC_RECEIVE_SOURCE_SHA256}
    blobs = {path: _read(root, path) for path in pins}
    for path in (CURRENT_RPC_SOURCE_PATH, CURRENT_RPC_RECEIVE_SOURCE_PATH):
        doc = _document(blobs[path], pins[path])
        for name, digest in {**doc['source_inputs'], **doc['source_pins']}.items():
            if name in pins and pins[name] != digest:
                raise ValueError('Conflicting current source provenance')
            pins[name] = digest
            if name not in blobs:
                blobs[name] = _read(root, name)
    if sum(map(len, blobs.values())) > MAX_TOTAL_BYTES:
        raise ValueError('Current minimum inputs exceed total byte bound')
    for path, digest in pins.items():
        _document(blobs[path], digest) if path.endswith('.json') else _verify(blobs[path], digest)
    return blobs


def _verify(raw, digest):
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_SOURCE_BYTES or
            hashlib.sha256(raw).hexdigest() != digest):
        raise ValueError('Current minimum source SHA256 mismatch')


def compile_sources(blobs):
    """Compile exact evidence bytes; output cannot authorize a network sender."""
    if type(blobs) is not dict or len(blobs) > 128 or sum(map(len, blobs.values())) > MAX_TOTAL_BYTES:
        raise ValueError('Bounded current source bytes are required')
    readiness = _document(blobs.get(READINESS_PATH), READINESS_SHA256)
    pins = {READINESS_PATH: READINESS_SHA256, COOKED_PATH: COOKED_SHA256, **readiness['source_proofs']}
    docs = {path: _document(blobs.get(path), digest) for path, digest in pins.items()}
    if any(doc.get('client_sha256') != CURRENT_CLIENT_SHA256 for doc in docs.values()):
        raise ValueError('Current and historical minimum source reports cannot be mixed')
    get = lambda token: next(doc for path, doc in docs.items() if token in path)
    if readiness['ready_to_compile_distinct_source_derived_minimum_profile'] is not True:
        raise ValueError('The current minimum source declarations are not ready')
    qualification = qualify_current_pc_rpc_sources(blobs.get(CURRENT_RPC_SOURCE_PATH), source_blobs=blobs)
    pins.update(dict(qualification.source_pins))
    cache = {c['path'].rsplit('.', 1)[-1]: c for c in get('source_map_schema_')['selected_classes']}
    constructors = {c['class_path']: c for c in get('generated_constructor_load_')['selected_classes']}
    packages = {p['class_export']['name']: p for p in get('cooked_declarations_')['packages']}
    shapes = {c['receiver_class']: c for c in get('command_shapes_')['selected_classes']}
    leaves = get('minimum_leaf_bindings_')['minimum_fields']
    widths = get('enum_widths_')
    if (len(leaves) != 17 or len(cache) != 4 or len(packages) != 4 or len(shapes) != 4 or
            widths['current_role_byte_width'] != [2] or
            widths['current_game_mode_enum_width_all_archive_versions'] != [4]):
        raise ValueError('The exact current four-class/seventeen-field subset is required')
    actors = {}
    for role, name in ROLES.items():
        selected, package, shape = cache[name], packages[name], shapes[name]
        klass, cdo = package['class_export'], package['cdo_export']
        path = '.'.join(klass['object_reference'])
        if (path != selected['path'] or klass['outer_index'] != 0 or cdo['outer_index'] != 0 or
                cdo['class_reference'] != klass['object_reference'] or
                cdo['name'] != 'Default__' + name):
            raise ValueError('Current cooked class/CDO ownership disagrees: ' + name)
        constructor = constructors[path]
        props = {}
        for leaf in (r for r in leaves if r['receiver_class'] == name):
            cmd = shape['commands'][leaf['command_index']]
            if (cmd['kind'] != 'leaf' or cmd['scope'] != [] or cmd['name'] != leaf['field'] or
                    cmd['relative_handle'] != leaf['relative_handle'] or cmd['field_family'] != leaf['family']):
                raise ValueError('Current complete command prefix disagrees: ' + leaf['field'])
            indices = [f['cache_index'] for f in selected['cache']['fields']
                       if f['kind'] == 'property' and f['name'] == leaf['field']]
            if len(indices) > 1 or leaf['field'] in props:
                raise ValueError('Ambiguous current minimum field')
            props[leaf['field']] = {**leaf, 'property_cache_index': indices[0] if indices else None,
                'enum_serialized_bit_width': 2 if leaf['field'] in ('Role', 'RemoteRole') else
                    4 if leaf['field'] == 'DFMGamePlayerMode' else None}
        actors[role] = dict(class_path=path, archetype_path='.'.join(cdo['object_reference']),
            package_path=package['package_path'], exclusive_cache_index_maximum=selected['cache']['exclusive_cache_index_maximum'],
            class_export_sha256=klass['export_sha256'], cdo_export_sha256=cdo['export_sha256'],
            actor_open_hook=constructor['expected_actor_open_hook'],
            net_rep_actor_interface=constructor['expected_net_rep_actor_interface'],
            properties=props, command_prefix=shape['commands'],
            command_prefix_is_source_derived=True, constructor_offsets_are_native_runtime_offsets=False)
    if actors['PlayerController']['class_path'] != CURRENT_PC_CLASS_PATH:
        raise ValueError('Current PC source identity disagrees')
    return dict(kind='current_source_minimum_actor_profile', client_sha256=CURRENT_CLIENT_SHA256,
        source_pins=dict(sorted(pins.items())), actors=actors,
        rpc_declarations=get('minimum_rpc_declarations_')['functions'],
        rpc_recipe_qualification=qualification.summary(),
        actor_transmission_enabled=False, runtime_native_cache_observed=False,
        native_acceptance_verified=False, profile_guards_relaxed=False,
        pending_integration=['Selected current connection/PackageMap/ActorChannel/header context',
            'Current source-derived Actor creation and logical-stage reliable delivery',
            'Current owning-world spawn transform and gameplay component qualification',
            'Native possession, randomized spawn, loot/Mandel interaction and persistence validation'])


def compile_profile(root=ROOT):
    return compile_sources(source_blobs(root))


def validate_profile(profile, *, root=ROOT):
    if type(profile) is not dict or profile != compile_profile(root):
        raise ValueError('Compiled current minimum profile differs from its sealed sources')


def rpc_profiles(root=ROOT):
    """Return existing qualified codecs, independent of network activation."""
    from dfserver.legacy_ds_pc_startup_rpc import PCStartupField, PCStartupProfile
    from dfserver.legacy_ds_pc_ping_receiver import PCPingProfile
    from dfserver.legacy_ds_pc_restart_rpc import PCRestartProfile
    from dfserver.legacy_ds_pc_view_target_rpc import PCViewTargetProfile, PCViewTargetTransition
    from dfserver.legacy_ds_pc_rotation_rpc import PCRotationProfile
    from dfserver.legacy_ds_scalar_serializers import NativeScalarBinding
    blobs = source_blobs(root)
    report = compile_sources(blobs)
    q = qualify_current_pc_rpc_sources(blobs[CURRENT_RPC_SOURCE_PATH], source_blobs=blobs)
    rows = {f['name']: f for f in report['rpc_declarations']}
    idx = lambda name: rows[name]['class_cache_index']
    flags = lambda name: int(rows[name]['declaration']['function_flags'], 16)
    common = dict(class_path=CURRENT_PC_CLASS_PATH, exclusive_index_maximum=244,
        source_sha256=CURRENT_RPC_SOURCE_SHA256, current_qualification=q)
    binding = NativeScalarBinding(CURRENT_CLIENT_SHA256, 0x10e8e6c0, None, 0x15a86a90)
    requests = tuple(PCStartupField(name, idx(name), kind) for name, kind in (
        ('ServerShortTimeout', 'empty'), ('Server_RcvACWorldTime', 'float32'),
        ('ServerFieldOfView', 'float32'), ('NotifySeamlessLoginReady', 'bool')))
    return dict(startup=PCStartupProfile(**common, requests=requests,
            acknowledgement_index=idx('ClientAckSeamlessLoginReady')),
        ping=PCPingProfile(**common, request_index=idx('ServerBouncePing'), reply_index=idx('ClientReturnPing')),
        restart=PCRestartProfile(**common, restart_index=idx('ClientRestart'),
            acknowledgement_index=idx('ServerAcknowledgePossession'), object_binding=binding,
            client_function_flags=flags('ClientRestart'), server_function_flags=flags('ServerAcknowledgePossession')),
        view=PCViewTargetProfile(**common, view_target_index=idx('ClientSetViewTarget'),
            verify_index=idx('ServerVerifyViewTarget'), object_binding=binding,
            # Explicit local instant-camera policy, not an assumed C++ default.
            current_transition=PCViewTargetTransition(0.0, 0, 1.0, False),
            client_function_flags=flags('ClientSetViewTarget'), server_function_flags=flags('ServerVerifyViewTarget')),
        rotation=PCRotationProfile(**common, rotation_index=idx('ClientSetRotation'),
            client_function_flags=flags('ClientSetRotation')))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    target = args.output.resolve()
    if target.parent != ROOT/'work/evidence' or target.exists():
        parser.error('A fresh work/evidence output is required')
    result = compile_profile()
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=str(target), sha256=hashlib.sha256(raw).hexdigest(),
        actors=len(result['actors']), actor_transmission_enabled=False)))
