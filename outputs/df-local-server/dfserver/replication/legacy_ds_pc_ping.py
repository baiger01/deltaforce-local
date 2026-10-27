"""Pure local server state for the source-qualified normal PC Pong branch.

Native source: 0x4e269b0, with timestamp getter 0x12b8aa60, clock
0x4ded320 and world-clock getter 0x4de2e80. The fixed source ledger is
SOURCE_RELATIVE_PATH/SOURCE_SHA256 below. These functions neither dispatch
RPCs nor acknowledge packets, bind actors, execute native code or read clocks.

The caller supplies server-owned seconds in two explicitly separate epochs.
The connection timestamp must belong to the same local connection and the
same monotonic epoch. World time is converted to float32 before throttling.

LOCAL_FINITE_PING_POLICY is a stricter local policy: all six input scalars
must be finite. The native imported predicate on the five ClientPingInfo
floats is unnamed; this module does not claim to reproduce that predicate.
The extra finite-TC1/derived-delta checks are likewise local policies. No
negative clock, interval or delta is clipped or replaced with zero.
"""
from dataclasses import dataclass, field, replace
from enum import Enum
import math
import struct

from dfserver.transport.native.legacy_ds_bit_archive import BitWriter
from dfserver.transport.native.legacy_ds_pc_rpc_fields import ClientReturnPingParams, OrdinaryRPCScalarProfile, ServerBouncePingParams, write_client_return_ping


SOURCE_RELATIVE_PATH = (
    'work/evidence/map-entry-next-20261005/'
    'pc-ping-native-wire-spec-and-normal-reply-1791208572984445800.json'
)
SOURCE_SHA256 = '9c844f3b0dc70724c76151d1106aecaed7354f6d43db52e2b6c60e4e95b3dd0d'


class PingValidationPolicy(Enum):
    LOCAL_FINITE_INPUT_SCALARS = 'local_finite_input_scalars_v1'


LOCAL_FINITE_PING_POLICY = PingValidationPolicy.LOCAL_FINITE_INPUT_SCALARS


def _number(value, label):
    if type(value) not in (int, float):
        raise ValueError(label + ' must be numeric, excluding booleans')
    try:
        return float(value)
    except (OverflowError, ValueError) as error:
        raise ValueError(label + ' exceeds the float64 representation') from error


def _finite(value, label):
    value = _number(value, label)
    if not math.isfinite(value):
        raise ValueError(label + ' must be finite')
    return value


def _f32(value, label):
    value = _finite(value, label)
    try:
        result = struct.unpack('<f', struct.pack('<f', value))[0]
    except (OverflowError, struct.error) as error:
        raise ValueError(label + ' exceeds the float32 representation') from error
    if not math.isfinite(result):
        raise ValueError(label + ' exceeds the finite float32 representation')
    return result


def _connection_id(value):
    # A caller-defined local id, not a native pointer, account or ticket token.
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError('A local uint64 connection id is required')


def _clock_id(value):
    if (type(value) is not str or not 1 <= len(value) <= 64 or
            not value.isascii() or any(ord(char) < 33 or ord(char) > 126 for char in value)):
        raise ValueError('A bounded local clock epoch id is required')


@dataclass(frozen=True)
class PingServerState:
    connection_id: int
    world_clock_id: str
    monotonic_clock_id: str
    last_world_time_f32: float
    throttle_interval_f32: float

    def __post_init__(self):
        _connection_id(self.connection_id)
        _clock_id(self.world_clock_id)
        _clock_id(self.monotonic_clock_id)
        if self.world_clock_id == self.monotonic_clock_id:
            raise ValueError('World and monotonic epochs must be explicitly separate')
        object.__setattr__(self, 'last_world_time_f32',
                           _f32(self.last_world_time_f32, 'Last accepted world time'))
        object.__setattr__(self, 'throttle_interval_f32',
                           _f32(self.throttle_interval_f32, 'Throttle interval'))


@dataclass(frozen=True)
class PingClockSample:
    connection_id: int
    world_clock_id: str
    monotonic_clock_id: str
    world_time_seconds: float
    monotonic_time_seconds: float
    connection_available: bool
    connection_timestamp_seconds: float | None
    timestamp_connection_id: int | None
    timestamp_monotonic_clock_id: str | None

    def __post_init__(self):
        _connection_id(self.connection_id)
        _clock_id(self.world_clock_id)
        _clock_id(self.monotonic_clock_id)
        if self.world_clock_id == self.monotonic_clock_id:
            raise ValueError('World and monotonic epochs must be explicitly separate')
        _f32(self.world_time_seconds, 'Current world time')
        _finite(self.monotonic_time_seconds, 'Current monotonic time')
        if type(self.connection_available) is not bool:
            raise ValueError('Connection availability must be an explicit boolean')
        if not self.connection_available:
            if (self.connection_timestamp_seconds is not None or
                    self.timestamp_connection_id is not None or
                    self.timestamp_monotonic_clock_id is not None):
                raise ValueError('Unavailable connection cannot supply a timestamp')
        else:
            _finite(self.connection_timestamp_seconds, 'Connection timestamp')
            _connection_id(self.timestamp_connection_id)
            _clock_id(self.timestamp_monotonic_clock_id)
            if self.timestamp_connection_id != self.connection_id:
                raise ValueError('Timestamp belongs to a different local connection')
            if self.timestamp_monotonic_clock_id != self.monotonic_clock_id:
                raise ValueError('Timestamp belongs to a different monotonic epoch')


@dataclass(frozen=True)
class PingDecision:
    reply: ClientReturnPingParams | None
    next_state: PingServerState
    reason: str
    validation_policy: PingValidationPolicy
    native_validation_equivalent: bool = field(default=False, init=False)
    native_binding_complete: bool = field(default=False, init=False)


def decide_ping(request, state, clocks, *, validation_policy):
    """Return the next local state and optional normal Pong, without effects.

    An omitted Struct is rejected, not populated with invented zero fields.
    Malformed input raises ValueError with the original frozen state intact.
    A policy/throttle/connection/delta rejection returns an explicit reason.
    Once throttling passes, last-world-time advances even if no reply follows,
    matching 0x4e26af0 before the null-connection and two-second gates.
    """
    if type(request) is not ServerBouncePingParams:
        raise ValueError('A present ServerBouncePingParams is required')
    if type(state) is not PingServerState or type(clocks) is not PingClockSample:
        raise ValueError('Explicit server state and clock provenance are required')
    if validation_policy is not LOCAL_FINITE_PING_POLICY:
        raise ValueError('The named local finite input policy is required')
    # Revalidation constructs independent values; it never writes the inputs.
    replace(state)
    replace(clocks)
    if (state.connection_id != clocks.connection_id or
            state.world_clock_id != clocks.world_clock_id or
            state.monotonic_clock_id != clocks.monotonic_clock_id):
        raise ValueError('Clock sample does not belong to this connection state')

    values = (request.tc1, request.exact_ping, request.delta_ts, request.old_ping,
              request.delta_tc, request.client_delta_time)
    values = tuple(_number(value, 'Ping scalar') for value in values)
    if not all(math.isfinite(value) for value in values):
        return PingDecision(None, state, 'local_finite_policy_rejected', validation_policy)
    # Fail before constructing a new state if the caller supplied values that
    # cannot be represented by the recovered wire profile.
    for value in values[1:]:
        _f32(value, 'ClientPingInfo scalar')

    world_time = _f32(clocks.world_time_seconds, 'Current world time')
    threshold = state.last_world_time_f32 + state.throttle_interval_f32 * 0.5
    if threshold > world_time:
        return PingDecision(None, state, 'throttled', validation_policy)
    next_state = replace(state, last_world_time_f32=world_time)
    if not clocks.connection_available:
        return PingDecision(None, next_state, 'connection_unavailable', validation_policy)

    timestamp = float(clocks.connection_timestamp_seconds)
    delta = 0.0 if timestamp == 0.0 else float(clocks.monotonic_time_seconds) - timestamp
    if not math.isfinite(delta):
        return PingDecision(None, next_state, 'local_nonfinite_delta_rejected', validation_policy)
    if delta > 2.0:
        return PingDecision(None, next_state, 'connection_timestamp_delta_exceeds_two_seconds',
                            validation_policy)
    reply = ClientReturnPingParams(values[0], delta, world_time)
    return PingDecision(reply, next_state, 'normal_pong_prepared', validation_policy)


def encode_pong(decision, *, profile):
    """Encode only a prepared reply with the existing ordinary 161-bit codec."""
    if type(decision) is not PingDecision or decision.reply is None:
        raise ValueError('A prepared normal Pong decision is required')
    if type(profile) is not OrdinaryRPCScalarProfile:
        raise ValueError('An explicit ordinary scalar RPC profile is required')
    writer = BitWriter(maximum_bits=161)
    bits = write_client_return_ping(writer, decision.reply, profile=profile)
    return writer.to_bytes(), bits
