"""This build's ordinary NewServerMove decoder and immutable local position policy.

Native4d11810 serializes GPMoveParams; its 248-byte C++ storage is not wire.
The supported branch has no base/bone, custom index, vault or extension data.
The caller isolates field6/max10 on the authenticated current Pawn's exact
movement component, and persists an accepted state atomically with its journal.
There is no socket I/O, game invocation, ACK, collision simulation, correction
reply, official anti-cheat parity, or F-interaction-coordinate authority here.
"""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import math
from pathlib import Path
import struct

from dfserver.legacy_ds_bit_archive import BitReader, UINT32_MAX


ROOT = Path(__file__).resolve().parent.parent
RPC_INDEX = 6
EXCLUSIVE_RPC_MAXIMUM = 10
MAX_RPC_BITS = 8192  # Explicit local archive bound, not a recovered game limit.
BASE = 'work/evidence/map-system-audit-20261018/'
PINS = {
    BASE+'ai-runtime-research-20261020-world-movement-archive-bridge-v1.json':
        'ff33af3698e0514997becb1fb20dcec8e4bac81190b70638777363ca6eb61ee3',
    BASE+'ai-runtime-research-20261020-world-movement-params-fields-v1.json':
        '55ac2fdc6b77f0092f960a594dc2cfbd6a8d678bc4d0d1d2b0398a8f44921bf1',
    BASE+'ai-runtime-research-20261020-world-movement-owner-functions-v1.json':
        'ecb70137ed2b71bb1aa128c3f368ea0ae1a3c1b2a8e7339b875c4b22a7ed6dc9',
    BASE+'ai-runtime-research-20261020-world-movement-ops-vtable-v1.json':
        '6af1aa380dd2304575eb47eea67a43afbaa245113c36a2fbbac1ea7393fe6e98',
    BASE+'ai-runtime-research-20261020-movement-wire-vectors-v1.json':
        '8c83a0f0057891aa93043a29a7a53c66bc81557b2b5dce8b754887952ae64e30',
    BASE+'ai-runtime-research-20261020-movement-wire-scalars-v1.json':
        '2e8b9ce24f51104b382a5feb59a95a4e9f2653d0aa7cb6e5a521cfdca3a756ac',
    BASE+'native-owned-weapon-rpc-struct-receive-and-netserialize-v1.json':
        '7e1ada98fd63d8b83d5a52f637663e785bd726a001c1dca2d7d9098b6764ef21',
    BASE+'native-owned-weapon-rpc-struct-ops-and-command-loop-v1.json':
        '02560a092cd714b820b93ab6fb60d00277ca5bb413065d2caf6bd53ffbeaefce',
    'outputs/df-local-server/dfserver/transport/native/legacy_ds_bit_archive.py':
        'ab64dd2d3e3853b9c78de25d39d9cc1f4d8df004d8ddde3241365197524ab17e',
}


@lru_cache(maxsize=1)
def _qualify_sources():
    for relative, expected in PINS.items():
        if hashlib.sha256((ROOT/relative).read_bytes()).hexdigest() != expected:
            raise ValueError('The qualified native movement source changed: '+relative)


def source_pins():
    _qualify_sources()
    return {**PINS, 'work/portable_movement_wire.py':
        hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


class MovementDecodeError(ValueError):
    def __init__(self, reason, payload, bits, position=0):
        super().__init__(reason)
        self.reason = reason
        self.raw_payload = payload
        self.raw_bit_count = bits
        self.bit_offset = position


class MovementAcceptanceError(ValueError):
    def __init__(self, reason, request):
        super().__init__(reason)
        self.reason = reason
        self.raw_payload = getattr(request, 'raw_payload', None)
        self.raw_bit_count = getattr(request, 'raw_bit_count', None)


def _uint(value, maximum=UINT32_MAX):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('An exact bounded movement integer is required')
    return value


def _finite(value):
    try:
        valid = type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError('An explicit finite movement number is required')
    return float(value)


def _position(value):
    if type(value) is not tuple or len(value) != 3:
        raise ValueError('Three explicit current server coordinates are required')
    return tuple(_finite(n) for n in value)


def _float32(value):
    return struct.unpack('<f', struct.pack('<f', value))[0]


def _scaled(steps, constant):
    scale = struct.unpack('<f', bytes.fromhex(constant))[0]
    return tuple(_float32(_float32(n)*scale) for n in steps)


@dataclass(frozen=True)
class DecodedMove:
    timestamp: float
    acceleration_steps: tuple
    move_flags: int
    view: int
    location_steps: tuple
    client_roll: int
    move_number: int
    client_movement_mode: int
    velocity_steps: tuple
    raw_payload: bytes
    raw_bit_count: int

    @property
    def acceleration(self):
        return _scaled(self.acceleration_steps, 'cdcccc3d')

    @property
    def client_location(self):
        return _scaled(self.location_steps, '0ad7233c')

    @property
    def client_velocity(self):
        return _scaled(self.velocity_steps, '0ad7233c')


def _vector(reader, maximum):
    width = reader.read_bounded_int(maximum)
    bias, limit = 1 << (width+1), 1 << (width+2)
    return tuple(reader.read_bounded_int(limit)-bias for _ in range(3))


def decode_new_server_move_parameters(payload, bits):
    """Read the isolated ordinary RPC parameters, including struct presence bit.

    Unsupported branches fail with the exact original request retained on the
    error. Successful decode only describes a client claim; accept_position is
    a separate explicit server-local policy decision.
    """
    reader = None
    try:
        _qualify_sources()
        if (type(payload) is not bytes or type(bits) is not int or
                not 1 <= bits <= MAX_RPC_BITS or len(payload) != (bits+7)//8 or
                int.from_bytes(payload, 'little') >> bits):
            raise ValueError('An exact bounded movement bit slice is required')
        reader = BitReader(payload, bit_count=bits)
        if not reader.read_bool():
            raise ValueError('Absent GPMoveParams constructor defaults are not qualified')
        timestamp = _finite(struct.unpack('<f', reader.read_bytes(4))[0])
        acceleration = _vector(reader, 24)
        move_flags, view = reader.read_bits(32), reader.read_bits(32)
        location = _vector(reader, 30)
        roll, number, mode = reader.read_bits(8), reader.read_bits(32), reader.read_bits(8)
        velocity = _vector(reader, 30)
        flags = reader.read_bits(8)
        if flags:
            raise ValueError('Unrestored movement extension flags: '+hex(flags))
        if reader.remaining:
            raise ValueError('Movement parameters must end at exact EOF')
        return DecodedMove(timestamp, acceleration, move_flags, view, location, roll,
            number, mode, velocity, payload, bits)
    except (ValueError, OSError) as error:
        raise MovementDecodeError(str(error), payload, bits,
            reader.position if reader is not None else 0) from error


@dataclass(frozen=True)
class MovementBinding:
    match_id: str
    pawn_guid: int
    movement_guid: int
    transport_generation: int

    def __post_init__(self):
        if type(self.match_id) is not str or not 1 <= len(self.match_id) <= 256:
            raise ValueError('An explicit current match namespace is required')
        if not _uint(self.pawn_guid) or not _uint(self.movement_guid):
            raise ValueError('The two actual nonzero owning NetGUIDs are required')
        if self.pawn_guid == self.movement_guid:
            raise ValueError('Pawn and its component must have distinct actual NetGUIDs')
        _uint(self.transport_generation)


@dataclass(frozen=True)
class MovementPolicy:
    max_speed: float
    max_client_delta: float
    max_clock_skew: float
    position_tolerance: float
    allowed_movement_modes: tuple

    def __post_init__(self):
        for value in (self.max_speed, self.max_client_delta, self.max_clock_skew):
            if _finite(value) <= 0:
                raise ValueError('Explicit positive local movement limits are required')
        if _finite(self.position_tolerance) < 0:
            raise ValueError('The local position tolerance cannot be negative')
        if (type(self.allowed_movement_modes) is not tuple or not self.allowed_movement_modes or
                any(type(mode) is not int for mode in self.allowed_movement_modes) or
                len(set(self.allowed_movement_modes)) != len(self.allowed_movement_modes)):
            raise ValueError('Explicit distinct allowed packed movement modes are required')
        for mode in self.allowed_movement_modes:
            _uint(mode, 255)


@dataclass(frozen=True)
class AcceptedPositionState:
    binding: MovementBinding
    position: tuple
    client_timestamp: float | None
    last_move_number: int
    server_time: float
    revision: int
    clock_client_origin: float | None
    clock_server_origin: float
    raw_payload: bytes = b''
    raw_bit_count: int = 0

    def __post_init__(self):
        if type(self.binding) is not MovementBinding:
            raise ValueError('An exact current movement binding is required')
        _position(self.position)
        _uint(self.revision)
        if type(self.last_move_number) is not int or not -1 <= self.last_move_number <= UINT32_MAX:
            raise ValueError('An exact last accepted move number is required')
        if not 0 <= _finite(self.clock_server_origin) <= _finite(self.server_time):
            raise ValueError('Invalid accepted local movement clock origin')
        if self.client_timestamp is None:
            if self.clock_client_origin is not None or self.revision:
                raise ValueError('Unknown client movement clock is restricted to a seed')
        elif (self.clock_client_origin is None or
              not 0 <= _finite(self.clock_client_origin) <= _finite(self.client_timestamp)):
            raise ValueError('Invalid accepted client movement clock origin')
        if self.revision == 0:
            if self.raw_payload != b'' or type(self.raw_payload) is not bytes or self.raw_bit_count != 0:
                raise ValueError('A server position seed has no accepted client request')
        else:
            decoded = decode_new_server_move_parameters(self.raw_payload, self.raw_bit_count)
            if (decoded.timestamp, decoded.move_number, decoded.client_location) != (
                    self.client_timestamp, self.last_move_number, self.position):
                raise ValueError('The accepted position state differs from its native request')


def seed_position(binding, position, *, server_time, client_timestamp=None, move_number=-1):
    """Seed only from a trusted server spawn/reset, never F-interaction context.

    Unknown initial client timestamp stays unknown until the first valid move;
    its first displacement is bounded only by elapsed server time. A new Pawn,
    connection generation or qualified timestamp reset requires explicit reseed.
    """
    if type(binding) is not MovementBinding:
        raise ValueError('An explicit current Pawn/component binding is required')
    position = _position(position)
    if _finite(server_time) < 0 or (client_timestamp is not None and _finite(client_timestamp) < 0):
        raise ValueError('Nonnegative explicit movement clocks are required')
    if type(move_number) is not int or not -1 <= move_number <= UINT32_MAX:
        raise ValueError('An explicit last accepted move number is required')
    return AcceptedPositionState(binding, position, client_timestamp, move_number,
        float(server_time), 0, client_timestamp, float(server_time))


def accept_position(state, request, *, binding, server_time, policy, allow_receive_gap=False):
    """Return the next immutable state; all rejection paths leave state unchanged.

    This local admission requires monotonic move number/time and both client and
    server elapsed-time budgets. Position/velocity are bounded client claims,
    not collision-resimulated native movement. The authenticated caller owns
    channel/GUID discovery and atomic commit; this API never sends success.
    """
    try:
        if (type(allow_receive_gap) is not bool or
                type(state) is not AcceptedPositionState or type(request) is not DecodedMove or
                type(binding) is not MovementBinding or state.binding != binding or
                type(policy) is not MovementPolicy):
            raise ValueError('The exact current match/Pawn/component/generation binding is required')
        # Prevent a hand-built or replaced dataclass from bypassing wire validation.
        if decode_new_server_move_parameters(request.raw_payload, request.raw_bit_count) != request:
            raise ValueError('Movement values differ from their exact decoded native request')
        _position(state.position)
        now = _finite(server_time)
        server_delta = now-_finite(state.server_time)
        if server_delta <= 0 or request.timestamp < 0:
            raise ValueError('The explicit local server clock must advance')
        if (request.move_number <= state.last_move_number or
                request.client_movement_mode not in policy.allowed_movement_modes):
            raise ValueError('Replayed move or unsupported local movement mode')
        if state.client_timestamp is None:
            client_delta = policy.max_client_delta
            client_origin, server_origin = request.timestamp, now
        else:
            client_delta = request.timestamp-state.client_timestamp
            client_origin, server_origin = state.clock_client_origin, state.clock_server_origin
            recovery = (allow_receive_gap and state.revision > 0 and
                client_delta > policy.max_client_delta and server_delta > policy.max_client_delta and
                abs(client_delta-server_delta) <= policy.max_clock_skew)
            if not 0 < client_delta or client_delta > policy.max_client_delta and not recovery:
                raise ValueError('Stale, reset or excessive client movement time delta')
            if abs((request.timestamp-client_origin)-(now-server_origin)) > policy.max_clock_skew:
                raise ValueError('The client movement clock exceeds explicit local skew policy')
        position = request.client_location
        distance = math.dist(position, state.position)
        # A gap can resume its clock while retaining the prior server position;
        # it never grants more displacement than one ordinary local time budget.
        budget = policy.max_speed*min(client_delta, server_delta, policy.max_client_delta)
        if distance > budget+policy.position_tolerance:
            raise ValueError('The client position exceeds accepted local server movement budget')
        if math.hypot(*request.client_velocity) > policy.max_speed:
            raise ValueError('The claimed velocity exceeds explicit local movement speed policy')
        return AcceptedPositionState(binding, position, request.timestamp, request.move_number,
            now, state.revision+1, client_origin, server_origin, request.raw_payload, request.raw_bit_count)
    except (ValueError, TypeError, OverflowError) as error:
        raise MovementAcceptanceError(str(error), request) from error
