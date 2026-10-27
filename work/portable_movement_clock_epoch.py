"""Explicit LOCAL clock recovery; no recovered native reset period is claimed.

The raw client timestamp can roll over while MoveNumber advances. Clock origins
identify a local epoch only. Recovery never reseeds the accepted server position,
grants a correction/ACK, wraps MoveNumber or reconstructs unobserved history.
"""
from dataclasses import dataclass, replace
import hashlib
import math
from pathlib import Path

from portable_movement_wire import (
    MovementAcceptanceError, accept_position, seed_position,
    source_pins as wire_sources,
)

ROOT = Path(__file__).resolve().parent.parent
_CLOCK_ERRORS = frozenset((
    'Stale, reset or excessive client movement time delta',
    'The client movement clock exceeds explicit local skew policy',
))


@dataclass(frozen=True)
class LocalClockEpochPolicy:
    minimum_reset_drop: float
    minimum_rebase_interval: float
    maximum_receive_gap: float
    allow_receive_clock_rebase: bool

    def __post_init__(self):
        for value in (self.minimum_reset_drop, self.minimum_rebase_interval, self.maximum_receive_gap):
            try:
                valid = type(value) in (int, float) and math.isfinite(value) and value > 0
            except OverflowError:
                valid = False
            if not valid:
                raise ValueError('Explicit finite positive LOCAL clock recovery bounds are required')
        if type(self.allow_receive_clock_rebase) is not bool:
            raise ValueError('An explicit LOCAL receive-clock rebase boolean is required')


def source_pins():
    return dict(wire_sources(), **{'work/portable_movement_clock_epoch.py':
        hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})


def accept_local_epoch(state, request, *, binding, server_time, policy,
                       epoch_policy, allow_receive_gap=False):
    """Return the existing immutable state type; reject without any side effect.

    Normal requests use the original validator unchanged. Recovery is attempted
    only for its two clock errors, after exact wire/binding/order/mode checks.
    A backward clock needs the explicit minimum drop. A positive clock needs
    the opt-in local receive-clock policy. Equal timestamps never recover.
    Position remains bounded by server delta and one ordinary maximum interval;
    positive client deltas retain their smaller original displacement bound.
    """
    if type(epoch_policy) is not LocalClockEpochPolicy:
        raise MovementAcceptanceError('An explicit LOCAL clock epoch policy is required', request)
    try:
        epoch_policy.__post_init__()
    except ValueError as error:
        raise MovementAcceptanceError(str(error), request) from error
    try:
        return accept_position(state, request, binding=binding, server_time=server_time,
            policy=policy, allow_receive_gap=allow_receive_gap)
    except MovementAcceptanceError as original:
        if original.reason not in _CLOCK_ERRORS:
            raise
        # The preceding validator has already checked exact state/request/binding,
        # forward MoveNumber, positive server delta, canonical raw and allowed mode.
        client_delta = request.timestamp-state.client_timestamp
        server_delta = float(server_time)-state.server_time
        if (client_delta == 0 or server_delta > epoch_policy.maximum_receive_gap or
                server_time-state.clock_server_origin < epoch_policy.minimum_rebase_interval or
                (client_delta < 0 and -client_delta < epoch_policy.minimum_reset_drop) or
                (client_delta > 0 and not epoch_policy.allow_receive_clock_rebase)):
            raise
        interval = min(server_delta, policy.max_client_delta)
        if client_delta > 0:
            interval = min(interval, client_delta)
        if math.dist(request.client_location, state.position) > policy.max_speed*interval+policy.position_tolerance:
            raise MovementAcceptanceError('The client position exceeds accepted local server movement budget', request)
        # Seed only the clock adapter from the already accepted server position.
        # It preserves the move-number replay floor and the last server instant.
        clock_seed = seed_position(binding, state.position, server_time=state.server_time,
            move_number=state.last_move_number)
        accepted = accept_position(clock_seed, request, binding=binding,
            server_time=server_time, policy=policy)
        try:
            return replace(accepted, revision=state.revision+1)
        except ValueError as error:
            raise MovementAcceptanceError(str(error), request) from error


def accept_packet_moves(state, requests, *, binding, server_time, policy,
                        epoch_policy=None, allow_receive_gap=False):
    """Validate every coalesced claim against one original server-position budget.

    The packet has one receive instant. Intermediate claims advance only the
    replay floor and client clock adapter; they never grant more server time or
    move the position used for the next claim's displacement check. Only the
    newest exact raw request is returned, with one committed revision.
    """
    if type(requests) is not tuple or not 1 <= len(requests) <= 256:
        raise ValueError('A bounded nonempty native movement packet is required')
    first = requests[0]
    if epoch_policy is None:
        accepted = accept_position(state, first, binding=binding, server_time=server_time,
            policy=policy, allow_receive_gap=allow_receive_gap)
    else:
        accepted = accept_local_epoch(state, first, binding=binding, server_time=server_time,
            policy=policy, epoch_policy=epoch_policy, allow_receive_gap=allow_receive_gap)
    server_delta = float(server_time)-state.server_time
    client_budget = policy.max_client_delta
    if state.client_timestamp is not None and first.timestamp > state.client_timestamp:
        client_budget = min(client_budget, first.timestamp-state.client_timestamp)
    for request in requests[1:]:
        # This is a validation anchor at the existing authoritative position,
        # never a persisted spawn/reset or a client-position seed.
        anchor = seed_position(binding, state.position, server_time=state.server_time,
            move_number=accepted.last_move_number)
        checked = accept_position(anchor, request, binding=binding, server_time=server_time,
            policy=policy, allow_receive_gap=allow_receive_gap)
        delta = request.timestamp-accepted.client_timestamp
        origin, server_origin = accepted.clock_client_origin, accepted.clock_server_origin
        receive_gap = (allow_receive_gap and delta > policy.max_client_delta and
            server_delta > policy.max_client_delta and
            abs(delta-server_delta) <= policy.max_clock_skew)
        clock_error = None
        if delta <= 0 or delta > policy.max_client_delta and not receive_gap:
            clock_error = 'Stale, reset or excessive client movement time delta'
        elif abs((request.timestamp-origin)-(server_time-server_origin)) > policy.max_clock_skew:
            clock_error = 'The client movement clock exceeds explicit local skew policy'
        if clock_error is not None:
            if (epoch_policy is None or delta == 0 or
                    server_delta > epoch_policy.maximum_receive_gap or
                    server_time-server_origin < epoch_policy.minimum_rebase_interval or
                    (delta < 0 and -delta < epoch_policy.minimum_reset_drop) or
                    (delta > 0 and not epoch_policy.allow_receive_clock_rebase)):
                raise MovementAcceptanceError(clock_error, request)
            origin, server_origin = request.timestamp, float(server_time)
        client_budget = (policy.max_client_delta if delta < 0 else
            min(policy.max_client_delta, client_budget+delta))
        budget = policy.max_speed*min(server_delta, client_budget, policy.max_client_delta)
        if math.dist(request.client_location, state.position) > budget+policy.position_tolerance:
            raise MovementAcceptanceError('The client position exceeds accepted local server movement budget', request)
        accepted = replace(checked, revision=state.revision+1,
            clock_client_origin=origin, clock_server_origin=server_origin)
    return accepted
