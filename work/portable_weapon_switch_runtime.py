"""Immutable admitted owner-RPC dispatch proposals, without socket or ACK IO.

The transport caller authenticates the ticket/socket, performs its existing
reliable receive admission, and supplies the actual receipt sequence. It must
journal a proposal before transmission and commit its state with the response.
"""
from dataclasses import dataclass, replace
from functools import lru_cache
import hashlib
import json
import re

from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_wire_codec import WireBunch, ChannelName
from portable_weapon_switch_owner import OwnerSwitchState, _timeline, _budget
from weapon_switch_owner_operations import (
    advance, source_pins as owner_pins, _zero_active_is_pending_source_state)
from portable_weapon_equipment_position import source_pins as position_pins
from weapon_switch_owner_rpc_codec import (decode_verify_bunch, decode_verify_bunch_requests,
    InvalidOwnerParameters, encode_verify_parameters, integer, float32)
from weapon_switch_timeline_codec import SCHEMA_SHA256, ROOT, InitialSwitchTimeline, encode as encode_initial


def source_pins():
    pins = owner_pins()
    for path, digest in position_pins().items():
        if path in pins and pins[path] != digest:
            raise ValueError('Owner runtime and equipment position sources disagree')
        pins[path] = digest
    pins['work/portable_weapon_switch_runtime.py'] = hashlib.sha256(
        (ROOT / 'work/portable_weapon_switch_runtime.py').read_bytes()).hexdigest()
    return pins


@lru_cache(maxsize=1)
def source_generation_digest():
    """Qualify once before serving; caller guards profile/source generation after it."""
    return hashlib.sha256(json.dumps(source_pins(), sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()


@dataclass(frozen=True)
class OwnerSwitchRuntimeBinding:
    admission_digest: str
    transport_generation: int
    pawn_guid: int
    pawn_channel: int
    manager_guid: int
    identity_slots: tuple[tuple[int, int], ...]
    source_generation_digest: str
    initialization_receipted: bool
    positions_receipted: bool


@dataclass(frozen=True)
class ReceivedOwnerSwitchEnvelope:
    admission_digest: str
    transport_generation: int
    source_generation_digest: str
    bunch: WireBunch
    reliable_receipt_sequence: int


@dataclass(frozen=True)
class OwnerSwitchRuntimeState:
    semantic: OwnerSwitchState
    last_received_sequence: int | None
    last_envelope_digest: bytes = b''
    last_reply: DefaultSubobjectUpdate | None = None
    maximum_packet_bytes: int = 0
    binding_digest: bytes = b''
    last_received_envelope: ReceivedOwnerSwitchEnvelope | None = None
    last_disposition: str = ''
    last_error: str | None = None


@dataclass(frozen=True)
class OwnerSwitchRuntimeProposal:
    state: OwnerSwitchRuntimeState
    update: DefaultSubobjectUpdate
    maximum_packet_bytes: int
    duplicate: bool = False
    native_gameplay_verified: bool = False


@dataclass(frozen=True)
class OwnerSwitchReceiveProposal:
    state: OwnerSwitchRuntimeState
    update: DefaultSubobjectUpdate | None
    maximum_packet_bytes: int
    disposition: str
    unhandled_envelope: ReceivedOwnerSwitchEnvelope | None = None
    reason: str | None = None
    duplicate: bool = False
    gameplay_acknowledgement: bool = False


def _binding_digest(binding, state):
    if (type(binding) is not OwnerSwitchRuntimeBinding or type(state) is not OwnerSwitchRuntimeState or
            type(state.semantic) is not OwnerSwitchState or
            type(binding.admission_digest) is not str or
            re.fullmatch('[0-9a-f]{64}', binding.admission_digest) is None or
            state.semantic.admission_digest != binding.admission_digest or
            state.semantic.transport_generation != binding.transport_generation or
            binding.source_generation_digest != source_generation_digest() or
            binding.initialization_receipted is not True or binding.positions_receipted is not True):
        raise ValueError('The current admitted owner, source generation and initialization receipts are required')
    integer(binding.transport_generation, 0, (1 << 31)-1)
    integer(binding.pawn_guid, 2, (1 << 32)-1)
    integer(binding.manager_guid, 2, (1 << 32)-1)
    integer(binding.pawn_channel, 2, 65535)
    integer(state.semantic.server_frame_no, 1, (1 << 31)-1)
    integer(state.semantic.manager_slot, 0, 255)
    if binding.pawn_guid & 1 or binding.manager_guid & 1 or binding.pawn_guid == binding.manager_guid:
        raise ValueError('Distinct current native Pawn and default component GUIDs are required')
    slots = binding.identity_slots
    if (type(slots) is not tuple or not 1 <= len(slots) <= 4 or
            any(type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not int or
                not 1 <= pair[0] < 1 << 32 or type(pair[1]) is not int or
                pair[1] != state.semantic.manager_slot for pair in slots) or
            len({pair[0] for pair in slots}) != len(slots)):
        raise ValueError('The exact distinct admitted identities and manager slot are required')
    known = {pair[0] for pair in slots}
    if ((state.semantic.active_identity not in known and
            not _zero_active_is_pending_source_state(state.semantic, known)) or
            state.semantic.pending_identity not in known | {0}):
        raise ValueError('The current owning semantic state has another equipped identity')
    digest = hashlib.sha256(json.dumps((binding.admission_digest,
        binding.transport_generation, binding.pawn_guid, binding.pawn_channel,
        binding.manager_guid, binding.identity_slots, binding.source_generation_digest),
        separators=(',', ':')).encode()).digest()
    if state.binding_digest and state.binding_digest != digest:
        raise ValueError('The committed owning reply belongs to another Pawn/equipment binding')
    return digest


def _received(binding, state, envelope, max_packet_bytes, *, maximum_body_bits=8192):
    binding_digest = _binding_digest(binding, state)
    integer(max_packet_bytes, 1, 1024)
    if (type(envelope) is not ReceivedOwnerSwitchEnvelope or type(envelope.bunch) is not WireBunch or
            envelope.admission_digest != binding.admission_digest or
            envelope.transport_generation != binding.transport_generation or
            envelope.source_generation_digest != binding.source_generation_digest):
        raise ValueError('The exact current admitted reliable envelope is required')
    integer(envelope.transport_generation, 0, (1 << 31)-1)
    sequence = integer(envelope.reliable_receipt_sequence, 0, 1023)
    bunch = envelope.bunch
    if (bunch.reliable is not True or bunch.channel_index != binding.pawn_channel or
            type(bunch.channel_sequence) is not int or bunch.channel_sequence != sequence or
            type(bunch.channel_name) is not ChannelName or bunch.channel_name != ChannelName(hardcoded_index=102) or
            type(bunch.payload) is not bytes or type(bunch.payload_bits) is not int or
            not 0 <= bunch.payload_bits <= maximum_body_bits or len(bunch.payload) != (bunch.payload_bits + 7)//8 or
            int.from_bytes(bunch.payload, 'little') >> bunch.payload_bits):
        raise ValueError('A bounded exact received Pawn reliable body and receipt are required')
    if state.last_received_sequence is not None:
        integer(state.last_received_sequence, 0, 1023)
        if sequence not in (state.last_received_sequence, (state.last_received_sequence + 1) & 1023):
            raise ValueError('A reliable Pawn sequence gap requires the caller normal receive assembler')
    digest = hashlib.sha256(bunch.payload_bits.to_bytes(4, 'little') + bunch.payload).digest()
    previous = state.last_received_envelope
    # Packet offsets are decoder diagnostics, and change when the same reliable
    # bunch is retransmitted at another position within a packet.
    same_envelope = (type(previous) is ReceivedOwnerSwitchEnvelope and
        replace(previous, bunch=replace(previous.bunch, header_start_bit=None, payload_start_bit=None)) ==
        replace(envelope, bunch=replace(bunch, header_start_bit=None, payload_start_bit=None)))
    if sequence == state.last_received_sequence and (not same_envelope or state.last_envelope_digest != digest):
        raise ValueError('A reliable sequence repeat changed its exact preserved envelope')
    return binding_digest, sequence, digest


def seed_from_initial_timeline(binding, timeline, *, last_received_sequence=None):
    """Seed before admitting the client's initial ActivatePending(last=0).

    Pass the exact produced initial_timeline value. No transport ACK or current
    native pointer value is inferred: this records the source operation order.
    """
    if type(binding) is not OwnerSwitchRuntimeBinding or type(timeline) is not InitialSwitchTimeline:
        raise ValueError('The exact source-qualified initial owner ring is required')
    if (type(binding.identity_slots) is not tuple or not 1 <= len(binding.identity_slots) <= 4 or
            any(type(pair) is not tuple or len(pair) != 2 for pair in binding.identity_slots)):
        raise ValueError('The complete admitted native manager identity/slot pairs are required')
    slot = integer(binding.identity_slots[0][1], 0, 255)
    encode_initial(timeline)
    frame = timeline.data[timeline.rear]
    semantic = OwnerSwitchState(binding.admission_digest, binding.transport_generation,
        frame.local_frame_no, 0, frame.pending_identity, -1, b'', frame,
        timeline.rear, frame.world_time, slot)
    state = OwnerSwitchRuntimeState(semantic, last_received_sequence)
    digest = _binding_digest(binding, state)
    if last_received_sequence is not None:
        integer(last_received_sequence, 0, 1023)
    return replace(state, binding_digest=digest)


def dispatch(binding, state, envelope, *, server_frame_no, server_world_time, max_packet_bytes=1024):
    """Propose one exact S->C manager timeline update from an accepted C->S RPC.

    An uninitialized receive cursor accepts the caller's first admitted sequence;
    after that it accepts only its exact repeat or the next modulo-1024 sequence.
    Sequence gaps/mixed/partial blocks require the transport's normal assembler.
    No invalid-frame RPC is synthesized for unqualified or stale input.
    """
    binding_digest, sequence, digest = _received(binding, state, envelope, max_packet_bytes)
    request = decode_verify_bunch(envelope.bunch, pawn_channel=binding.pawn_channel,
        manager_guid=binding.manager_guid)
    proposal = advance(state.semantic, request, admission_digest=binding.admission_digest,
        transport_generation=binding.transport_generation, identity_slots=binding.identity_slots,
        server_frame_no=server_frame_no, server_world_time=server_world_time,
        max_packet_bytes=max_packet_bytes)
    update = DefaultSubobjectUpdate(binding.pawn_guid, binding.manager_guid,
        'WeaponManager', SCHEMA_SHA256, proposal.content.payload,
        proposal.content.payload_bit_count, True)
    if sequence == state.last_received_sequence:
        if (digest != state.last_envelope_digest or type(state.last_reply) is not DefaultSubobjectUpdate or
                state.last_reply != update or state.maximum_packet_bytes != proposal.maximum_packet_bytes or
                state.binding_digest != binding_digest):
            raise ValueError('A repeated reliable sequence must retain its exact committed reply')
        return OwnerSwitchRuntimeProposal(state, state.last_reply, state.maximum_packet_bytes, True)
    next_state = replace(state, semantic=proposal.state, last_received_sequence=sequence,
        last_envelope_digest=digest, last_reply=update,
        maximum_packet_bytes=proposal.maximum_packet_bytes, binding_digest=binding_digest,
        last_received_envelope=envelope, last_disposition='owner_accepted', last_error=None)
    return OwnerSwitchRuntimeProposal(next_state, update, proposal.maximum_packet_bytes,
        proposal.duplicate)


def receive(binding, state, envelope, *, server_frame_no, server_world_time, max_packet_bytes=1024):
    """Receipt every admitted Pawn reliable body; interpret only exact owner RPCs.

    Unknown, mixed, partial and policy-rejected inputs retain the full immutable
    envelope in both the result and next state, advance only the receive cursor,
    and produce no gameplay reply. The caller journals the result before commit.
    This function neither sends nor represents a transport/gameplay ACK.
    """
    binding_digest, sequence, digest = _received(binding, state, envelope, max_packet_bytes)
    if sequence == state.last_received_sequence and state.last_disposition != 'owner_accepted':
        return OwnerSwitchReceiveProposal(state, None, 0, state.last_disposition,
            envelope, state.last_error, True)

    def opaque(disposition, error):
        next_state = replace(state, last_received_sequence=sequence, last_envelope_digest=digest,
            last_reply=None, maximum_packet_bytes=0, binding_digest=binding_digest,
            last_received_envelope=envelope, last_disposition=disposition, last_error=str(error)[:256])
        return OwnerSwitchReceiveProposal(next_state, None, 0, disposition, envelope, str(error)[:256])

    try:
        request = decode_verify_bunch(envelope.bunch, pawn_channel=binding.pawn_channel,
            manager_guid=binding.manager_guid)
    except ValueError as error:
        return opaque('opaque_unhandled', error)
    raw, bits = encode_verify_parameters(request)
    request_digest = hashlib.sha256(bits.to_bytes(4, 'little') + raw).digest()
    if request_digest != state.semantic.last_request_digest:
        integer(server_frame_no, state.semantic.server_frame_no + 1, (1 << 31)-1)
        float32(server_world_time)
        if server_world_time < state.semantic.server_world_time or server_world_time < 0:
            raise ValueError('The caller must supply a monotonic local owning clock')
    _budget(_timeline(request.frame, 0), max_packet_bytes)
    try:
        proposal = dispatch(binding, state, envelope, server_frame_no=server_frame_no,
            server_world_time=server_world_time, max_packet_bytes=max_packet_bytes)
    except ValueError as error:
        return opaque('owner_policy_rejected', error)
    return OwnerSwitchReceiveProposal(proposal.state, proposal.update,
        proposal.maximum_packet_bytes, 'owner_accepted', duplicate=proposal.duplicate)


def receive_admitted(binding, state, bunch, receipt, *, server_frame_no, server_world_time,
        max_packet_bytes=1024):
    """Consume one body released by the real owning reliable assembler.

    The transport owns fragment sequences and duplicate suppression. A complete
    body can span several wire sequences, so its final sequence need not be the
    next semantic-body sequence. Admission/identity and client-frame validation
    still apply; no synthetic intermediate frames or gameplay ACKs are made.
    """
    from dfserver.legacy_ds_owned_pawn_receipt import OwnedPawnReceiptResult
    if (type(receipt) is not OwnedPawnReceiptResult or receipt.received is not True or
            receipt.duplicate or receipt.pending or bunch not in receipt.ready or
            bunch.reliable is not True or bunch.partial or
            type(bunch.channel_sequence) is not int):
        raise ValueError('An actual complete body from the owning reliable assembler is required')
    _binding_digest(binding, state)
    envelope = ReceivedOwnerSwitchEnvelope(binding.admission_digest, binding.transport_generation,
        binding.source_generation_digest, bunch, bunch.channel_sequence)
    # Reliable retry/ordering is already checked by the receipt above. Preserve
    # semantic frame history while allowing the assembler's final wire cursor.
    from dfserver.legacy_ds_pc_receipt import MAX_ASSEMBLY_BITS
    ordered = replace(state, last_received_sequence=None)
    binding_digest, sequence, digest = _received(binding, ordered, envelope,
        max_packet_bytes, maximum_body_bits=MAX_ASSEMBLY_BITS)

    def opaque(disposition, error):
        unchanged = replace(state, last_received_sequence=sequence, last_envelope_digest=digest,
            last_reply=None, maximum_packet_bytes=0, binding_digest=binding_digest,
            last_received_envelope=envelope, last_disposition=disposition, last_error=str(error)[:256])
        return OwnerSwitchReceiveProposal(unchanged, None, 0, disposition, envelope, str(error)[:256])

    try:
        requests = decode_verify_bunch_requests(bunch, pawn_channel=binding.pawn_channel,
            manager_guid=binding.manager_guid)
    except InvalidOwnerParameters as error:
        return opaque('owner_policy_rejected', error)
    except ValueError as error:
        return opaque('opaque_unhandled', error)
    if not requests:
        return opaque('opaque_unhandled', 'No qualified owning switch field is present')
    semantic = state.semantic
    all_duplicates = True
    try:
        for request in requests:
            proposal = advance(semantic, request, admission_digest=binding.admission_digest,
                transport_generation=binding.transport_generation, identity_slots=binding.identity_slots,
                server_frame_no=max(server_frame_no, semantic.server_frame_no + 1),
                server_world_time=server_world_time, max_packet_bytes=max_packet_bytes)
            semantic = proposal.state
            all_duplicates = all_duplicates and proposal.duplicate
    except ValueError as error:
        return opaque('owner_policy_rejected', error)
    update = DefaultSubobjectUpdate(binding.pawn_guid, binding.manager_guid,
        'WeaponManager', SCHEMA_SHA256, proposal.content.payload,
        proposal.content.payload_bit_count, True)
    committed = replace(state, semantic=semantic, last_received_sequence=sequence,
        last_envelope_digest=digest, last_reply=update, maximum_packet_bytes=proposal.maximum_packet_bytes,
        binding_digest=binding_digest, last_received_envelope=envelope,
        last_disposition='owner_accepted', last_error=None)
    return OwnerSwitchReceiveProposal(committed, update, proposal.maximum_packet_bytes,
        'owner_accepted', duplicate=all_duplicates)
