"""Observe the native first-player prerequisites on one current primary PC.

No GUID is assumed for an official session. This callback-only reader follows
source-proved connection/PC relations and two typed Actor references. Flags are
current observations, not a claim that a historical callback executed. It does
not create objects, set flags, invoke methods, or authorize any network message.
"""
import hashlib
import json
from pathlib import Path

from native_connection_binding import (
    SHIPPING_SHA256, IMAGE_SIZE, MAX_ADDRESS, _View, _pointer,
    ConnectionBindingObservationError,
)
from native_gp_bind_gate import _GateBudget, GP_BIND_RVA, PC_OPEN_RVA


SOURCE_PATH = 'work/evidence/native-official-entry-new-source-20261006.json'
SOURCE_SHA256 = '45b2aac764d6d1a78b170465dc4dda584522cda90c3e24fbeb455d10686e4c7f'
CODE_PATH = 'work/evidence/native-official-entry-new-source-20261006.49520d0.code'
CODE_SHA256 = 'a0f6a1f7baad99194e60e6a83f1057b66293d2809cf9cb4cd6a3178e29636ec4'
ASM_PATH = 'work/evidence/native-official-entry-new-source-20261006.49520d0.asm.txt'
ASM_SHA256 = 'e3a813356fe49b315005aae9b67e0bde7145183d055a9e63ace81b3b24e89fd9'
REQUIRED_FLAGS_MASK = 0x6e  # 0x49527fd..0x4952801, not a server wire enum.
MOVEMENT_CLASS = 'MovementReplicationActor'
PLAYER_STATE_CLASS = 'BP_SOLPlayerState_C'
PLAYER_STATE_SOURCE = 'work/evidence/map-entry-next-20261006/official-after-spawn-first-player-state.json'
PLAYER_STATE_SOURCE_SHA256 = '76bc34db403b3b83ac56b648d24758ed3be8d96d1281ae57b28508f536cb69b1'
MOVEMENT_SOURCE = 'work/evidence/native-movement-replication-class-20261006.json'
MOVEMENT_SHA256 = '452ff6bc144824a7a945c9cc41e76cd5f457282637b2a6f7eeb0c1998cc0bd67'
READY_ACK_SOURCE = 'work/evidence/map-entry-next-20261005/native-seamless-ready-rpc-source.4dbf630.asm.txt'
READY_ACK_SOURCE_SHA256 = 'ee256d7a887cddee5ee11d0aa5ba6dd59922672f2f9e6d13c1615d0aba7bcb4d'
READY_ACK_OFFSET = 0xa60  # ClientAckSeamlessLoginReady writes 1 at RVA 0x4dbf6d2.


def qualified_first_player_source_pins(root):
    from native_gp_bind_gate import qualified_gp_bind_gate_source_pins
    root = Path(root).resolve(strict=True)
    pins = qualified_gp_bind_gate_source_pins(root)
    from native_game_state_start_observation import qualified_start_observation_sources
    pins.update(qualified_start_observation_sources(root))
    for relative, expected in ((SOURCE_PATH, SOURCE_SHA256),
                               (CODE_PATH, CODE_SHA256), (ASM_PATH, ASM_SHA256),
                               (PLAYER_STATE_SOURCE, PLAYER_STATE_SOURCE_SHA256),
                               (READY_ACK_SOURCE, READY_ACK_SOURCE_SHA256),
                               (MOVEMENT_SOURCE, MOVEMENT_SHA256)):
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file() or path.stat().st_size > 65536:
            raise ValueError('First-player source is missing or outside its byte bound')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('First-player source SHA256 mismatch')
        pins[relative] = expected
    player_source = json.loads((root / PLAYER_STATE_SOURCE).read_bytes())
    player_ref = player_source.get('state', {}).get('pc_player_state_reference', {})
    if (player_source.get('client_sha256') != SHIPPING_SHA256 or
            player_ref.get('status') != 'typed_existing_reference' or
            player_ref.get('class_ancestry', [None])[0] != PLAYER_STATE_CLASS or
            player_ref.get('class_asset_path') !=
                '/Game/BluePrints/GameModes/TestGame/BP_SOLPlayerState.BP_SOLPlayerState_C'):
        raise ValueError('PlayerState class must match the qualified spawned official reference')
    ledger = json.loads((root / MOVEMENT_SOURCE).read_bytes())
    if (ledger.get('client_sha256') != SHIPPING_SHA256
            or ledger.get('class_name') != MOVEMENT_CLASS
            or ledger.get('package') != '/Script/GPGameplay'):
        raise ValueError('Movement class source differs from the fixed native declaration')
    for row in ledger['sources']:
        for path_key, hash_key in (('code_relative_path', 'code_sha256'),
                                   ('asm.txt_relative_path', 'asm.txt_sha256')):
            relative, expected = row[path_key], row[hash_key]
            path = (root / relative).resolve(strict=True)
            if (not path.is_relative_to(root) or path.stat().st_size > 65536
                    or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
                raise ValueError('Movement class source bytes changed')
            pins[relative] = expected
    relative = 'work/native_gp_first_player_state.py'
    pins[relative] = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != pins[relative]:
        raise ValueError('First-player reader was imported from another checkout')
    return pins


def _actor_reference(view, pc, offset, expected_class):
    address = view.ptr(pc + offset)
    if not address:
        return {'status': 'null_reference', 'source_offset': offset,
                'required_base_class': expected_class}
    identity = view.object(address, expected_class)
    return {'status': 'typed_existing_reference', 'source_offset': offset,
            'required_base_class': expected_class, 'address': address,
            'class_address': identity[3], 'class_ancestry': list(identity[4]),
            'object_index': identity[1], 'serial': identity[2]}


def observe_first_player_state(session, module_base, *, driver_address,
                               connection_address, pc_address, object_identity):
    budget = None
    try:
        base = _pointer(module_base)
        if base + IMAGE_SIZE - 1 > MAX_ADDRESS:
            raise ValueError('Invalid pinned image span')
        if (getattr(session, 'module_sha256', None) != SHIPPING_SHA256 or
                getattr(session, 'module_size', None) != IMAGE_SIZE):
            raise ValueError('Pinned image identity is required')
        driver, connection, pc = map(_pointer, (driver_address, connection_address, pc_address))
        if len({driver, connection, pc}) != 3 or not callable(object_identity):
            raise ValueError('Distinct typed roots and an identity callback are required')
        budget = _GateBudget(session, object_identity)
        view = _View(budget, base)
        view.object(driver, 'NetDriver')
        cidentity = view.object(connection, 'NetConnection')
        view.object(pc, 'PlayerController')
        if 'GPNetConnection' not in cidentity[4]:
            raise ValueError('GPNetConnection ancestry is required')
        if (view.ptr(driver + 0x98) != connection or view.ptr(connection + 0x58) != driver
                or view.ptr(pc + 0x568) != connection or view.keep(pc + 0x524, 1) != b'\0'):
            raise ValueError('Current primary local PC relation is required')
        chook = view.method(connection, 0x2c0, GP_BIND_RVA)
        phook = view.method(pc, 0x3d8, PC_OPEN_RVA)
        if not chook['matches_saved_base_body'] or not phook['matches_saved_base_body']:
            raise ValueError('Saved GP connection and PC method targets are required')
        current_pc, owner = view.ptr(connection + 0x30), view.ptr(connection + 0xa8)
        if current_pc not in (0, pc) or owner not in (0, pc):
            raise ValueError('Primary connection refers to a different PC or Owner')
        gate = view.keep(connection + 0x21d1, 1)[0]
        flags = view.keep(connection + 0x20b8, 1)[0]
        ready_ack = view.keep(pc + READY_ACK_OFFSET, 1)[0]
        if ready_ack not in (0, 1):
            raise ValueError('Ready acknowledgement flag is not a native Boolean')
        # These offsets are checked by the existing-object branches at
        # 0x495257f..0x495259c and 0x495272a..0x495273b. No payloads are read.
        pawn = _actor_reference(view, pc, 0x3a0, 'Pawn')
        player_state = _actor_reference(view, pc, 0x378, 'PlayerState')
        view.finish()
        row = {'status': 'observed', 'selection': 'current_primary_local_pc_instance',
               'native_guid_assumed': False, 'state_gate_raw': gate, 'flags_raw': flags,
               'required_flags_mask': REQUIRED_FLAGS_MASK,
               'required_flags_present': flags & REQUIRED_FLAGS_MASK == REQUIRED_FLAGS_MASK,
               'completion_broadcast_condition_now':
                   flags & REQUIRED_FLAGS_MASK == REQUIRED_FLAGS_MASK and gate != 0,
               'ordinary_base_bind_condition_now': gate == 0 or bool(flags & 4),
               'connection_pc_equals_selected_pc': current_pc == pc,
               'connection_owner_equals_selected_pc': owner == pc,
               'pc_ready_ack_flag_raw': ready_ack,
               'pc_ready_ack_flag_set': bool(ready_ack),
               'pc_ready_ack_source_relative_path': READY_ACK_SOURCE,
               'pc_ready_ack_source_sha256': READY_ACK_SOURCE_SHA256,
               'pc_pawn_reference': pawn, 'pc_player_state_reference': player_state,
               'identity_and_fields_rechecked': True}
    except (ValueError, OSError) as error:
        row = {'status': 'refused', 'reason': str(error)}
    row.update(kind='native_first_player_prerequisite_observation',
               source_relative_path=SOURCE_PATH, source_sha256=SOURCE_SHA256,
               read_calls=budget.calls if budget else 0,
               read_bytes=budget.bytes_read if budget else 0,
               native_dispatch_executed=False, historical_state_verified=False,
               process_memory_written=False, native_methods_invoked=False,
               snapshot_atomic=False, playable_map_verified=False)
    return row
