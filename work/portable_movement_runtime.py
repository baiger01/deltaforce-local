"""Source-bound unreliable movement authority for one frozen local admission."""
import hashlib
from portable_source_guard import SourceGuard

from dfserver.legacy_ds_actor_fields import read_class_fields
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_movement import MovementProfile, MovementDecision
from portable_movement_binding import (from_admitted_plans, qualify_unreliable_header,
    source_pins as binding_sources, ROOT)
from portable_movement_wire import (MovementBinding, MovementPolicy, seed_position,
    MovementDecodeError, decode_new_server_move_parameters, source_pins as wire_sources)
from portable_movement_clock_epoch import (LocalClockEpochPolicy, accept_packet_moves,
    source_pins as epoch_sources)


def source_pins():
    pins = binding_sources()
    pins.update(wire_sources())
    pins.update(epoch_sources())
    for relative in ('work/portable_movement_runtime.py', 'work/portable_source_guard.py',
                     'outputs/df-local-server/dfserver/legacy_ds_movement.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def _moves(config, bodies):
    result = []
    for body in bodies:
        if body.reliable:
            continue
        qualify_unreliable_header(config, body)
        reader = BitReader(body.payload, bit_count=body.payload_bits)
        blocks = 0
        while reader.remaining:
            blocks += 1
            if blocks > 256:
                raise ValueError('The bounded movement content block count was exceeded')
            has_layout, is_actor = reader.read_bool(), reader.read_bool()
            guid = None if is_actor else reader.read_packed_int()
            length = reader.read_packed_int()
            payload = reader.read_payload(length)
            if has_layout or is_actor or guid != config.movement_guid:
                continue
            fields = read_class_fields(BitReader(payload, bit_count=length), profile=config.field_profile)
            for field in fields:
                if field.rep_index == config.rpc_index:
                    result.append(decode_new_server_move_parameters(field.payload, field.payload_bit_count))
                    if len(result) > 256:
                        raise ValueError('The bounded movement request count was exceeded')
    return tuple(result)


def make_profile(ticket, manifests, plans, *, spawn_location, policy):
    config = from_admitted_plans(manifests, plans)
    required = {'max_speed', 'max_client_delta', 'max_clock_skew',
        'position_tolerance', 'allowed_movement_modes'}
    if type(policy) is not dict or set(policy) not in (required, required | {'clock_epoch'}):
        raise ValueError('The explicit local movement acceptance policy is required')
    values = dict(policy)
    epoch_policy = None
    if 'clock_epoch' in values:
        clock = values.pop('clock_epoch')
        if type(clock) is not dict or set(clock) != {'minimum_reset_drop',
                'minimum_rebase_interval', 'maximum_receive_gap', 'allow_receive_clock_rebase'}:
            raise ValueError('The exact explicit LOCAL clock epoch policy is required')
        epoch_policy = LocalClockEpochPolicy(**clock)
    modes = values['allowed_movement_modes']
    if modes == 'all_native_packed_uint8':
        values['allowed_movement_modes'] = tuple(range(256))
    elif type(modes) in (list, tuple):
        values['allowed_movement_modes'] = tuple(modes)
    else:
        raise ValueError('Explicit local packed movement-mode acceptance is required')
    limits = MovementPolicy(**values)
    from dfserver.legacy_ds_quantized_vector import QuantizedVector10
    if type(spawn_location) is not QuantizedVector10:
        raise ValueError('Movement requires this admission\'s exact server-selected spawn')
    binding = MovementBinding(hashlib.sha256(ticket.cookie.encode()).hexdigest(),
        config.pawn_guid, config.movement_guid, 0)
    initial = seed_position(binding, spawn_location.native_float_components(), server_time=0.0)
    pins = tuple(sorted(source_pins().items()))

    def consume(state, bodies, elapsed):
        try:
            moves = _moves(config, bodies)
            if not moves:
                return MovementDecision(state, 'opaque_unhandled')
            accepted = accept_packet_moves(state, moves, binding=binding,
                server_time=elapsed, policy=limits, epoch_policy=epoch_policy,
                allow_receive_gap=True)
            return MovementDecision(accepted, 'movement_accepted')
        except ValueError as error:
            return MovementDecision(state, 'movement_rejected', _reason_code(error, state, limits))

    current = SourceGuard(ROOT, dict(pins))

    return MovementProfile(config, initial, consume, current)


def _reason_code(error, state, policy):
    if isinstance(error, MovementDecodeError):
        return 'movement_wire'
    reason = str(error)
    if reason == 'Replayed move or unsupported local movement mode':
        request = decode_new_server_move_parameters(error.raw_payload, error.raw_bit_count)
        if request.move_number <= state.last_move_number:
            return 'move_replay'
        return ('movement_mode' if request.client_movement_mode not in policy.allowed_movement_modes
            else 'movement_order')
    return {
        'Stale, reset or excessive client movement time delta': 'client_clock_delta',
        'The client movement clock exceeds explicit local skew policy': 'client_clock_skew',
        'The client position exceeds accepted local server movement budget': 'position_budget',
        'The claimed velocity exceeds explicit local movement speed policy': 'velocity_budget',
        'The explicit local server clock must advance': 'server_clock',
    }.get(reason, 'movement_validation')
