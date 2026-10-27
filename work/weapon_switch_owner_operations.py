"""Native operation ordering for the authenticated local owner-switch policy.

Instant is a SwitchType; it still submits Start and then ActivatePending.
Cancel targets the current weapon and clears its pending switch. The native
anti-cheat check code is retained without claiming official validation parity.
"""
from dataclasses import replace
from functools import lru_cache
import hashlib
import json
import re

from portable_weapon_switch_owner import OwnerSwitchState, OwnerSwitchProposal, _timeline, _budget
from weapon_switch_owner_rpc_codec import VerifyFrameRequest, encode_verify_parameters, integer, float32
from weapon_switch_timeline_codec import SwitchFrame, ROOT, schema_binding as timeline_schema

BASE = 'work/evidence/map-system-audit-20261018/'
PINS = {
    'native-owned-weapon-owner-runtime-frame-operations-v1.json':
        '1336ba6e30bb7a7d80e16b686557f1ccb4c3c6b32f305c36240f2aec81eac3fc',
    'native-owned-weapon-current-switch-and-timeline-source-v1.json':
        '2cbf0b5202a5bc2de32b7bb75b54e5a9dd4019337bd9870816be93ccf57c2cf9',
    'native-owned-weapon-local-current-writer-and-timeline-selector-v1.json':
        '012477e0e1ded2e6a1c512a8b5ea43f6b5a3699a5383d30e02ca9826ffaff81c',
    'native-owned-weapon-cancel-switch-real-body-v1.json':
        '3042bea3cbf29dbbddf627afa4c4f04f4a38ffabb5b93ab6fd806307700af9f5',
    'native-owned-weapon-runtime-context-current-frame-v1.json':
        '09395d8386b871d9a124314b6ddb54ac253875fe1224e3519a5eb80fb0c55070',
}


@lru_cache(maxsize=1)
def _contract_raw():
    instructions = {}
    for name, expected in PINS.items():
        raw = (ROOT / BASE / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Changed owning operation native source: ' + name)
        document = json.loads(raw)
        for function in document['functions']:
            instructions.update({row['rva']: row['bytes'] for row in function['instructions']})
    expected = {
        '0x55e5301': '41b001', '0x55e530f': 'e8cc290000',
        '0x55e53a3': '488903',
        '0x565fd88': '4533c0', '0x565fd9b': 'e8407ff8ff',
        '0x565fdb4': '807c247002', '0x565fdfa': 'ff90e8040000',
        '0x565e122': '41b002', '0x565e135': 'e8a69bf8ff',
        '0x55f5102': '498b9d18020000', '0x55f512e': '41b002',
        '0x55f513d': 'e89e2bffff', '0x55f5259': '4989bd28020000',
        '0x55ed5ef': '80f902', '0x55ed618': '418b4f2c',
        '0x55ed61c': '3908', '0x55ee4e2': '4c89af28020000',
        '0x58ef31c': '418b510c', '0x58ef320': '458b4108',
        '0x58ef374': '89542428', '0x58ef381': '448944242c',
    }
    if any(instructions.get(at) != value for at, value in expected.items()):
        raise ValueError('The native operation, activation order or remote frame import changed')
    return json.dumps(dict(kind='source_qualified_owner_operation_order_v1',
        sources={BASE + name: digest for name, digest in PINS.items()},
        instant_start_emits_activate_pending=True,
        activate_submission_precedes_current_pointer_write=True,
        cancel_target='current_active_identity', cancel_clears_pending=True,
        remote_import_swaps_local_and_remote_frame_numbers=True,
        semantics_are_local_server_acceptance_policy=True,
        native_anticheat_validation_verified=False), sort_keys=True).encode()


def schema_binding():
    return json.loads(_contract_raw())


def source_pins():
    from portable_weapon_switch_owner import source_pins as base_pins
    pins = base_pins()
    pins.update(schema_binding()['sources'])
    pins['work/weapon_switch_owner_operations.py'] = hashlib.sha256(
        (ROOT / 'work/weapon_switch_owner_operations.py').read_bytes()).hexdigest()
    return pins


def _zero_active_is_pending_source_state(state, known):
    frame = state.last_server_frame
    if (state.active_identity != 0 or state.pending_identity not in known or
            type(frame) is not SwitchFrame or frame.local_frame_no != state.server_frame_no or
            frame.last_identity != 0 or frame.pending_identity != state.pending_identity or frame.operation != 0):
        return False
    if state.last_client_frame_no == -1:
        return (frame.remote_frame_no, frame.dep_frame_no, frame.switch_type, frame.context) == (-1, -1, 2, 2)
    return frame.remote_frame_no == state.last_client_frame_no


def advance(state, request, *, admission_digest, transport_generation, identity_slots,
        server_frame_no, server_world_time, max_packet_bytes=1024):
    schema_binding()
    if (type(state) is not OwnerSwitchState or type(request) is not VerifyFrameRequest or
            type(admission_digest) is not str or re.fullmatch('[0-9a-f]{64}', admission_digest) is None or
            state.admission_digest != admission_digest or state.transport_generation != transport_generation):
        raise ValueError('The exact current owning admission and generation are required')
    integer(transport_generation, 0, (1 << 31)-1)
    integer(state.server_frame_no, 1, (1 << 31)-1)
    integer(state.last_client_frame_no, -1, (1 << 31)-1)
    integer(state.ring_rear, 0, 1)
    integer(state.manager_slot, 0, 255)
    if (type(identity_slots) is not tuple or not 1 <= len(identity_slots) <= 4 or
            any(type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not int or
                not 1 <= pair[0] < 1 << 32 or type(pair[1]) is not int or
                pair[1] != state.manager_slot for pair in identity_slots) or
            len({pair[0] for pair in identity_slots}) != len(identity_slots)):
        raise ValueError('The exact distinct admitted equipped identities and native slot are required')
    known = {pair[0] for pair in identity_slots}
    if ((state.active_identity not in known and not _zero_active_is_pending_source_state(state, known)) or
            state.pending_identity not in known | {0}):
        raise ValueError('The owning state no longer matches the qualified initial or equipped state')
    raw, bits = encode_verify_parameters(request)
    digest = hashlib.sha256(bits.to_bytes(4, 'little') + raw).digest()
    if digest == state.last_request_digest:
        if type(state.last_server_frame) is not SwitchFrame:
            raise ValueError('An owning semantic repeat has no committed native reply')
        content = _timeline(state.last_server_frame, state.ring_rear)
        return OwnerSwitchProposal(state, state.last_server_frame, content,
            _budget(content, max_packet_bytes), True)
    frame = request.frame
    enums = timeline_schema()['enums']
    if (request.frame_present and frame.last_identity != state.active_identity and
            frame.last_identity == state.pending_identity and
            _zero_active_is_pending_source_state(state, known)):
        # The seeded server ring is Start(0 -> initial). The client completes
        # that ActivatePending itself and never sends it, so its first own Start
        # names the initial weapon as last. Treat the seeded pending as active.
        state = replace(state, active_identity=state.pending_identity, pending_identity=0)
    if (not request.frame_present or frame.local_frame_no < 0 or
            frame.local_frame_no < state.last_client_frame_no or frame.world_time < 0 or
            not -1 <= frame.remote_frame_no <= state.server_frame_no or
            not -1 <= frame.dep_frame_no <= frame.local_frame_no or
            frame.last_identity != state.active_identity or frame.pending_identity not in known or
            any(value not in {row['value'] for row in enums[name]['entries']} for name, value in (
                ('SwitchType', frame.switch_type), ('Operation', frame.operation),
                ('SwitchWeaponContext', frame.context)))):
        raise ValueError('The native owning frame is stale or names another admitted state')
    if frame.operation == 0:
        active, pending = state.active_identity, frame.pending_identity
    elif frame.operation == 1 and state.pending_identity == frame.pending_identity:
        active, pending = frame.pending_identity, 0
    elif frame.operation == 2 and frame.pending_identity == state.active_identity:
        active, pending = state.active_identity, 0
    else:
        raise ValueError('Activation needs the pending target; cancellation needs the current target')
    integer(server_frame_no, state.server_frame_no + 1, (1 << 31)-1)
    float32(server_world_time)
    if server_world_time < state.server_world_time or server_world_time < 0:
        raise ValueError('The explicit local owning clock must be monotonic')
    server_frame = replace(frame, local_frame_no=server_frame_no,
        remote_frame_no=frame.local_frame_no, world_time=server_world_time)
    rear = 1 - state.ring_rear
    content = _timeline(server_frame, rear)
    maximum = _budget(content, max_packet_bytes)
    next_state = replace(state, server_frame_no=server_frame_no, active_identity=active,
        pending_identity=pending, last_client_frame_no=frame.local_frame_no,
        last_request_digest=digest, last_server_frame=server_frame, ring_rear=rear,
        server_world_time=server_world_time)
    return OwnerSwitchProposal(next_state, server_frame, content, maximum)
