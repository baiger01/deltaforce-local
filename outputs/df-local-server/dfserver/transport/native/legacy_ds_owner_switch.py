"""Source-owned switch semantics and reliable results on the admitted Pawn."""
import time
from dataclasses import dataclass, field, replace

from dfserver.transport.native.legacy_ds_bit_archive import BitWriter
from dfserver.replication.legacy_ds_default_subobject import DefaultSubobjectUpdate, write_default_subobjects_followup
from dfserver.transport.native.legacy_ds_wire_codec import ChannelName, WireBunch, WirePacket, encode_observed_application


@dataclass(frozen=True)
class OwnerSwitchProfile:
    pawn_channel: int
    pawn_guid: int
    manager_guid: int
    initial_state: object = field(repr=False)
    consume: object = field(repr=False)
    sources_current: object = field(repr=False)

    def __post_init__(self):
        if (type(self.pawn_channel) is not int or not 2 <= self.pawn_channel <= 1023 or
                any(type(g) is not int or not 2 <= g <= 0xffffffff or g & 1
                    for g in (self.pawn_guid, self.manager_guid)) or self.pawn_guid == self.manager_guid or
                self.initial_state is None or not callable(self.consume) or not callable(self.sources_current)):
            raise ValueError('One explicit source-qualified owning weapon profile is required')


@dataclass(frozen=True)
class OwnerSwitchDecision:
    state: object = field(repr=False)
    update: DefaultSubobjectUpdate | None
    disposition: str
    duplicate: bool = False


def _binding(connection, state, peer):
    profile, lease = state.owner_switch_profile, state.owner_switch_lease
    transport = connection.peers.get(peer)
    original = connection.control_peers.get(peer)
    generation = connection._local_stage_owner(peer, original, transport) if original is not None else None
    if (type(profile) is not OwnerSwitchProfile or type(lease) is not tuple or len(lease) != 4 or
            lease[0] is not state.ticket or lease[1] is not transport or lease[2] is not generation or
            lease[3] is not profile or profile.sources_current() is not True or
            (state.pc_restart_pawn_channel, state.pc_restart_pawn_guid) !=
                (profile.pawn_channel, profile.pawn_guid)):
        raise ValueError('The owning switch admission, generation or source binding changed')
    connection._admitted_actor_receipt_binding(state, original, peer, transport, generation)
    return profile, transport, generation


def set_profile(connection, peer, profile):
    from dfserver.transport.native.legacy_ds_control_connection import _content_items
    state = connection.control_peers.get(peer)
    if (state is None or type(profile) is not OwnerSwitchProfile or state.owner_switch_profile is not None or
            not state.admitted_actor_reliable_receipts or
            (state.pc_restart_pawn_channel, state.pc_restart_pawn_guid) !=
                (profile.pawn_channel, profile.pawn_guid) or profile.sources_current() is not True or
            not any(binding[:2] == (profile.manager_guid, profile.pawn_guid)
                for item in _content_items(state) for binding in item.component_bindings)):
        raise ValueError('The exact queued owning Pawn and manager metadata are required')
    transport = connection.peers.get(peer)
    generation = connection._local_stage_owner(peer, state, transport)
    lease = state.admitted_actor_receipt_lease
    if (lease.ticket is not state.ticket or lease.transport is not transport or
            lease.generation is not generation or generation is None):
        raise ValueError('A verified owning Actor receipt lease is required')
    candidate = connection._clone(state)
    candidate.owner_switch_profile = profile
    candidate.owner_switch_lease = (state.ticket, transport, generation, profile)
    candidate.owner_switch_state = profile.initial_state
    connection.control_peers[peer] = candidate


def consume(connection, state, peer, bunch, receipt, now):
    if state.owner_switch_profile is None or bunch.reliable is not True:
        return
    profile, _, _ = _binding(connection, state, peer)
    elapsed = max(0.0, now - state.joined_at)
    before = getattr(state.owner_switch_state, 'semantic', None)
    decision = profile.consume(state.owner_switch_state, bunch, receipt, elapsed)
    if (type(decision) is not OwnerSwitchDecision or decision.state is None or
            decision.disposition not in ('owner_accepted', 'opaque_unhandled', 'owner_policy_rejected') or
            type(decision.duplicate) is not bool):
        raise ValueError('The owning switch dispatcher returned an invalid decision')
    # Diagnostic only: count each disposition and its bounded error text.
    error = getattr(decision.state, 'last_error', None)
    key = decision.disposition + ('' if not error else ': ' + str(error)[:120])
    counts = state.owner_switch_dispositions
    if key in counts or len(counts) < 32:
        counts[key] = counts.get(key, 0) + 1
    if decision.disposition == 'owner_policy_rejected' and len(state.owner_switch_rejected_frames) < 24:
        # Diagnostic only: the client frame against the server's switch state.
        try:
            from weapon_switch_owner_rpc_codec import decode_verify_bunch_requests
            frames = tuple(r.frame for r in decode_verify_bunch_requests(bunch,
                pawn_channel=profile.pawn_channel, manager_guid=profile.manager_guid))
        except Exception as exc:  # noqa: BLE001 - diagnostic capture only
            frames = (type(exc).__name__,)
        state.owner_switch_rejected_frames += (dict(elapsed=round(elapsed, 3),
            error=str(error)[:160] if error else None,
            client_frames=[repr(f) for f in frames],
            server_before=dict(active=getattr(before, 'active_identity', None),
                pending=getattr(before, 'pending_identity', None),
                server_frame_no=getattr(before, 'server_frame_no', None),
                last_client_frame_no=getattr(before, 'last_client_frame_no', None))),)
    update = decision.update
    if update is not None:
        if (decision.disposition != 'owner_accepted' or type(update) is not DefaultSubobjectUpdate or
                (update.actor_guid, update.guid, update.name, update.has_rep_layout) !=
                (profile.pawn_guid, profile.manager_guid, 'WeaponManager', True)):
            raise ValueError('An owning switch result targets another component')
        if update not in state.owner_switch_pending:
            if len(state.owner_switch_pending) >= 64:
                raise ValueError('The bounded owning switch result queue is full')
            state.owner_switch_pending += (update,)
        state.owner_switch_accepted += 1
    state.owner_switch_state = decision.state


def _trace(state, event, **values):
    """Diagnostic only: bounded switch-reply send/ACK timeline for the report."""
    if len(state.owner_switch_trace) < 400:
        state.owner_switch_trace += (dict(event=event, at=round(time.perf_counter(), 3), **values),)


def _bunch(connection, state):
    profile = state.owner_switch_profile
    update = state.owner_switch_update
    writer = BitWriter(maximum_bits=connection.max_packet_bytes * 8)
    write_default_subobjects_followup(writer, (update,), (),
        tuple(item.actor_guid for item in state.actor_opens.values()))
    return WireBunch(profile.pawn_channel, writer.to_bytes(), writer.bit_count, reliable=True,
        channel_sequence=(state.owner_switch_previous_sequence + 1) & 1023,
        channel_name=ChannelName(hardcoded_index=102), package_exports=True)


def _current_delivery(connection, state, peer):
    profile, transport, generation = _binding(connection, state, peer)
    item = state.owner_switch_delivery
    if (item is None or not state.owner_switch_pending or
            state.owner_switch_pending[0] != state.owner_switch_update or
            item.actor_guid != profile.pawn_guid or item.bunch != _bunch(connection, state)):
        raise ValueError('The exact pending owner switch result changed')
    return item, transport, generation


def poll(connection, peer, state, now):
    from dfserver.transport.native.legacy_ds_control_connection import ActorOpenDelivery
    if state.owner_switch_profile is None or not state.owner_switch_pending:
        return ()
    try:
        profile, transport, _ = _binding(connection, state, peer)
        if state.owner_switch_delivery is None or state.owner_switch_delivery.delivered:
            previous = connection._post_admission_previous_sequence(state, profile.pawn_channel, profile.pawn_guid)
            state.owner_switch_update = state.owner_switch_pending[0]
            state.owner_switch_previous_sequence = previous
            bunch = _bunch(connection, state)
            connection._post_admission_reserve(state, bunch, profile.pawn_guid)
            state.owner_switch_delivery = ActorOpenDelivery(bunch, profile.pawn_guid)
        item, _, _ = _current_delivery(connection, state, peer)
        if not connection._stage_can_prepare(peer, state, transport, item, now):
            return ()
        payload = encode_observed_application(WirePacket(transport.out_sequence,
            transport.in_sequence, (transport.history,), False, 0, None, (item.bunch,), 0),
            max_packet_bytes=connection.max_packet_bytes, received_by_server=False)
    except (ValueError, OSError, KeyError):
        return ()
    event = ('actor_content_owner_switch_send_prepared' if not item.transmissions else
        'actor_content_owner_switch_timer_retransmit_prepared')
    connection._stage_note_prepared(peer, state, transport, item, now)
    _trace(state, 'send', packet_seq=item.sent_packets[-1] if item.sent_packets else None,
        reply_seq=item.bunch.channel_sequence, transmissions=item.transmissions,
        pending=len(state.owner_switch_pending), payload_bits=item.bunch.payload_bits)
    connection.control_events[event] += 1
    return ((peer, event, payload),)


def before_socket(connection, peer, payload):
    from dfserver.transport.native.legacy_ds_wire_codec import decode_observed_application
    state = connection.control_peers.get(peer)
    if state is None:
        return False
    try:
        item, _, _ = _current_delivery(connection, state, peer)
        packet = decode_observed_application(payload, max_packet_bytes=connection.max_packet_bytes,
            received_by_server=False)
        return tuple(replace(b, header_start_bit=None, payload_start_bit=None)
            for b in packet.bunches) == (item.bunch,)
    except (ValueError, OSError, KeyError):
        return False


def acknowledge(connection, original, state, packet, peer, transport, generation):
    from dfserver.transport.native.legacy_ds_control_connection import _ActualActorReceipt, MASK
    if state.owner_switch_delivery is None or state.owner_switch_delivery.delivered or state.client_closed:
        return
    try:
        item, current_transport, current_generation = _current_delivery(connection, state, peer)
    except (ValueError, OSError, KeyError):
        return
    if transport is not current_transport or generation is not current_generation:
        return
    matched = next((sent for sent in original.actual_application_sends
        for distance in ((packet.acknowledged_sequence - sent.sequence) & MASK,)
        if sent.ticket is state.ticket and sent.transport is transport and sent.generation is generation and
            item.bunch in sent.bunches and sent.sequence in item.sent_packets and
            distance < len(packet.history) * 32 and
            (packet.history[distance // 32] >> (distance % 32)) & 1), None)
    if matched is None:
        # Diagnostic only: why this incoming ACK did not confirm the reply.
        # Every incoming packet reaches here; log only a few per reply.
        misses = sum(1 for t in state.owner_switch_trace
                     if t['event'] == 'ack_miss' and t['reply_seq'] == item.bunch.channel_sequence)
        if misses >= 6:
            return
        sends = [s for s in original.actual_application_sends
                 if s.ticket is state.ticket and item.bunch in s.bunches]
        _trace(state, 'ack_miss', acked=packet.acknowledged_sequence,
            history_words=len(packet.history), reply_seq=item.bunch.channel_sequence,
            sent_packets=list(item.sent_packets)[-6:],
            recorded_sends=[s.sequence for s in sends][-6:],
            transport_same=[s.transport is transport for s in sends][-3:],
            generation_same=[s.generation is generation for s in sends][-3:])
        return
    _trace(state, 'ack_hit', acked=packet.acknowledged_sequence, packet_seq=matched.sequence,
        reply_seq=item.bunch.channel_sequence)
    receipt = _ActualActorReceipt(item.actor_guid, item.bunch, matched.sequence, state.ticket, transport, generation)
    connection._post_admission_commit(state, item, receipt)
    item.delivered = True
    state.owner_switch_pending = state.owner_switch_pending[1:]
    state.owner_switch_result_acks += 1
