"""Pure authenticated local owner-switch proposals; transport commits separately.

The caller validates the real ticket/socket owner and reliable receive sequence.
These rules deliberately describe this local server's equipped-weapon policy;
the decoded native anti-cheat code is preserved but official validation parity
is not claimed. Cancellation remains unsupported until its consumer is closed.
"""
from dataclasses import dataclass, replace
import hashlib
import re

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitWriter, UINT32_MAX
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate, write_default_subobject_followup
from dfserver.legacy_ds_wire_codec import WireBunch, WirePacket, ChannelName, encode_observed_application
from weapon_switch_timeline_codec import SwitchFrame, schema_binding as timeline_schema
from weapon_switch_owner_rpc_codec import (VerifyFrameRequest, encode_verify_parameters,
    integer, float32, source_pins as codec_pins, SCHEMA_SHA256)


@dataclass(frozen=True)
class OwnerSwitchState:
    admission_digest: str
    transport_generation: int
    server_frame_no: int
    active_identity: int
    pending_identity: int
    last_client_frame_no: int
    last_request_digest: bytes
    last_server_frame: SwitchFrame | None = None
    ring_rear: int = 1
    server_world_time: float = 0.0
    manager_slot: int = 0


@dataclass(frozen=True)
class OwnerSwitchProposal:
    state: OwnerSwitchState
    server_frame: SwitchFrame
    content: ActorContentBlock
    maximum_packet_bytes: int
    duplicate: bool = False
    local_initialization_policy: str = 'authenticated_equipped_owner_switch'
    native_anticheat_validation_verified: bool = False
    gameplay_success_observed: bool = False


def source_pins():
    from export_weapon_switch_owner_rpc_schema import ROOT
    pins = codec_pins()
    pins['work/portable_weapon_switch_owner.py'] = hashlib.sha256(
        (ROOT / 'work/portable_weapon_switch_owner.py').read_bytes()).hexdigest()
    for name in ('legacy_ds_default_subobject.py', 'legacy_ds_even_component_guid_exports.py'):
        path = ROOT / 'outputs/df-local-server/dfserver' / name
        pins[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return pins


def _timeline(frame, rear):
    schema = timeline_schema()
    frames = [SwitchFrame(), SwitchFrame()]
    frames[rear] = frame
    writer = BitWriter(maximum_bits=2048)
    writer.write_bool(False)
    writer.write_packed_int(9)
    writer.write_bits(2, 16)
    for ordinal, item in enumerate(frames):
        values = (item.local_frame_no, item.remote_frame_no, item.dep_frame_no, item.world_time,
            item.last_identity, item.pending_identity, item.switch_type, item.operation, item.context)
        for local, value in enumerate(values, 1):
            writer.write_packed_int(ordinal*9 + local)
            if local <= 3:
                writer.write_bits(value & 0xffffffff, 32)
            elif local == 4:
                writer.write_bytes(float32(value))
            elif local <= 6:
                writer.write_bits(value, 32)
            else:
                name = ('SwitchType', 'Operation', 'SwitchWeaponContext')[local-7]
                writer.write_bits(value, schema['enums'][name]['wire_bits'])
    writer.write_packed_int(0)
    for handle, value in ((10, 1-rear), (11, rear), (12, 1)):
        writer.write_packed_int(handle)
        writer.write_bits(value, 32)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)


def _budget(content, maximum):
    integer(maximum, 1, 1024)
    writer = BitWriter(maximum_bits=maximum*8)
    update = DefaultSubobjectUpdate(2, UINT32_MAX-1, 'WeaponManager', SCHEMA_SHA256,
        content.payload, content.payload_bit_count, True)
    write_default_subobject_followup(writer, update, (), (2,))
    bunch = WireBunch(UINT32_MAX, writer.to_bytes(), writer.bit_count, reliable=True,
        package_exports=True, channel_sequence=1023, channel_name=ChannelName(hardcoded_index=102))
    return len(encode_observed_application(WirePacket(16383, 16383, (0xffffffff,), False,
        255, None, (bunch,), 0), max_packet_bytes=maximum, received_by_server=False))


def advance(state, request, *, admission_digest, transport_generation, identity_slots,
            server_frame_no, server_world_time, max_packet_bytes=1024):
    """Return an immutable semantic proposal and complete one-frame ring reply.

    Root must authorize the current admitted owner, assemble reliable input,
    isolate this exact component/field, and journal identical reply bytes. The
    proposal does not send, ACK, mutate a ticket, or mark a native object ready.
    """
    if (type(state) is not OwnerSwitchState or type(request) is not VerifyFrameRequest or
            type(admission_digest) is not str or re.fullmatch('[0-9a-f]{64}', admission_digest) is None or
            state.admission_digest != admission_digest or
            state.transport_generation != transport_generation):
        raise ValueError('The exact current admission and transport generation are required')
    integer(transport_generation, 0, (1 << 31)-1)
    integer(state.server_frame_no, 1, (1 << 31)-1)
    integer(state.ring_rear, 0, 1)
    integer(state.manager_slot, 0, 255)
    if (type(identity_slots) is not tuple or not 1 <= len(identity_slots) <= 4 or
            any(type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not int or
                not 1 <= pair[0] <= UINT32_MAX or type(pair[1]) is not int or
                pair[1] != state.manager_slot for pair in identity_slots) or
            len({pair[0] for pair in identity_slots}) != len(identity_slots)):
        raise ValueError('Exact distinct equipped identities from this manager slot are required')
    known = {pair[0] for pair in identity_slots}
    if state.active_identity not in known or state.pending_identity not in known | {0}:
        raise ValueError('Owner state no longer matches the admitted equipped identities')
    raw, bits = encode_verify_parameters(request)
    digest = hashlib.sha256(bits.to_bytes(4, 'little') + raw).digest()
    if digest == state.last_request_digest:
        if type(state.last_server_frame) is not SwitchFrame:
            raise ValueError('A repeated frame has no committed semantic reply')
        content = _timeline(state.last_server_frame, state.ring_rear)
        return OwnerSwitchProposal(state, state.last_server_frame, content,
            _budget(content, max_packet_bytes), True)
    frame = request.frame
    if (not request.frame_present or frame.local_frame_no < 0 or
            frame.local_frame_no < state.last_client_frame_no or frame.world_time < 0 or
            not -1 <= frame.remote_frame_no <= state.server_frame_no or
            not -1 <= frame.dep_frame_no <= frame.local_frame_no or
            frame.last_identity != state.active_identity or frame.pending_identity not in known):
        raise ValueError('The owning frame is stale or names another admitted weapon')
    if frame.operation == 0:
        active, pending = state.active_identity, frame.pending_identity
    elif frame.operation == 1 and state.pending_identity == frame.pending_identity:
        # Native55e530f submits OP_ActivatePending before CurrentActiveWeapon is
        # replaced at55e53a3, so LastIdentity still names the previous weapon.
        active, pending = frame.pending_identity, 0
    else:
        raise ValueError('Activation requires the prior pending weapon; cancellation is not yet qualified')
    integer(server_frame_no, state.server_frame_no+1, (1 << 31)-1)
    float32(server_world_time)
    if server_world_time < state.server_world_time or server_world_time < 0:
        raise ValueError('The explicit local server clock must be monotonic')
    server_frame = replace(frame, local_frame_no=server_frame_no,
        remote_frame_no=frame.local_frame_no, world_time=server_world_time)
    rear = 1-state.ring_rear
    content = _timeline(server_frame, rear)
    packet_bytes = _budget(content, max_packet_bytes)
    next_state = replace(state, server_frame_no=server_frame_no, active_identity=active,
        pending_identity=pending, last_client_frame_no=frame.local_frame_no,
        last_request_digest=digest, last_server_frame=server_frame, ring_rear=rear,
        server_world_time=server_world_time)
    return OwnerSwitchProposal(next_state, server_frame, content, packet_bytes)
