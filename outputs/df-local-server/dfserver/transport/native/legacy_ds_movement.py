"""Current admitted Pawn movement state, committed with its enclosing packet."""
from dataclasses import dataclass, field


MOVEMENT_REJECTION_CODES = frozenset(('movement_binding', 'movement_wire',
    'move_replay', 'movement_mode', 'client_clock_delta', 'client_clock_skew',
    'position_budget', 'velocity_budget', 'server_clock', 'movement_order',
    'movement_validation'))


@dataclass(frozen=True)
class MovementProfile:
    config: object
    initial_state: object = field(repr=False)
    consume: object = field(repr=False)
    sources_current: object = field(repr=False)

    def __post_init__(self):
        if (self.config is None or self.initial_state is None or
                not callable(self.consume) or not callable(self.sources_current)):
            raise ValueError('An explicit current admitted movement profile is required')


@dataclass(frozen=True)
class MovementDecision:
    state: object = field(repr=False)
    disposition: str
    reason_code: str = ''


def _reject_reason(state, reason):
    state.movement_last_reason = reason
    counts = state.movement_rejection_counts
    counts[reason] = min(counts.get(reason, 0)+1, 0x7fffffff)


def _binding(connection, state, peer):
    if state is None:
        raise ValueError('No current admitted movement owner exists')
    profile, lease = state.movement_profile, state.movement_lease
    original = connection.control_peers.get(peer)
    transport = connection.peers.get(peer)
    generation = connection._local_stage_owner(peer, original, transport) if original is not None else None
    if (type(profile) is not MovementProfile or type(lease) is not tuple or len(lease) != 4 or
            any(left is not right for left, right in zip(lease, (state.ticket, transport, generation, profile))) or
            profile.sources_current() is not True or
            (profile.config.pawn_channel, profile.config.pawn_guid) !=
                (state.pc_restart_pawn_channel, state.pc_restart_pawn_guid)):
        raise ValueError('The actual movement admission, component or generation changed')
    connection._admitted_actor_receipt_binding(state, original, peer, transport, generation)
    return profile


def set_profile(connection, peer, profile):
    from dfserver.transport.native.legacy_ds_control_connection import _content_items
    original = connection.control_peers.get(peer)
    if (original is None or type(profile) is not MovementProfile or original.movement_profile is not None or
            not original.admitted_actor_reliable_receipts or profile.sources_current() is not True):
        raise ValueError('One current movement profile and actual admitted receipt policy are required')
    config = profile.config
    pawn = original.actor_opens.get(config.pawn_channel)
    spawn = dict(pawn.open_fields).get('location') if pawn is not None and pawn.open_fields is not None else None
    if ((config.pawn_channel, config.pawn_guid) !=
            (original.pc_restart_pawn_channel, original.pc_restart_pawn_guid) or
            spawn is None or profile.initial_state.position != spawn.native_float_components() or
            sum((config.movement_guid, config.pawn_guid, config.component_name) in item.component_bindings
                for item in _content_items(original)) != 1):
        raise ValueError('The movement profile must use the exact queued component metadata')
    transport = connection.peers.get(peer)
    generation = connection._local_stage_owner(peer, original, transport)
    lease = original.admitted_actor_receipt_lease
    if (lease.ticket is not original.ticket or lease.transport is not transport or
            lease.generation is not generation or generation is None):
        raise ValueError('A current authenticated movement transport lease is required')
    state = connection._clone(original)
    state.movement_profile = profile
    state.movement_lease = (state.ticket, transport, generation, profile)
    state.movement_state = profile.initial_state
    connection.control_peers[peer] = state


def consume(connection, state, peer, bodies, now):
    if state.movement_profile is None or not any(not body.reliable for body in bodies):
        return
    try:
        profile = _binding(connection, state, peer)
    except ValueError:
        # Unknown transport remains receipted. An invalid movement lease cannot
        # advance position or prevent other admitted RPC handlers from running.
        state.movement_rejected += 1
        state.movement_last_disposition = 'movement_rejected'
        _reject_reason(state, 'movement_binding')
        return
    decision = profile.consume(state.movement_state, bodies, max(0.0, now-state.joined_at))
    if (type(decision) is not MovementDecision or decision.state is None or decision.disposition not in
            ('movement_accepted', 'movement_rejected', 'opaque_unhandled') or
            decision.reason_code not in MOVEMENT_REJECTION_CODES | {''} or
            (decision.reason_code and decision.disposition != 'movement_rejected')):
        raise ValueError('The movement handler returned an invalid packet proposal')
    state.movement_state = decision.state
    state.movement_last_disposition = decision.disposition
    state.movement_last_reason = decision.reason_code
    if decision.disposition == 'movement_accepted':
        state.movement_accepted += 1
    elif decision.disposition == 'movement_rejected':
        state.movement_rejected += 1
        _reject_reason(state, decision.reason_code or 'movement_validation')


def accepted_position(connection, peer):
    state = connection.control_peers.get(peer)
    _binding(connection, state, peer)
    return state.movement_state.position
