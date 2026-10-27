"""Bind the qualified native one-human allocator to an immutable admission."""
import hashlib
import math

from dfserver.legacy_ds_match_admission import LocalMatchTicket
from dfserver.legacy_ds_ms23_spawn import (
    CLIENT_SHA256, SpawnParticipant, allocate_ms23_one_participant, load_ms23_spawn_schema)
from dfserver.legacy_ds_quantized_vector import QuantizedVector10
from dfserver.legacy_ds_rotator import CompressedRotator16


def spawn_selector(schema_raw, observation, policy):
    schema = load_ms23_spawn_schema(schema_raw)
    expected = dict(kind='explicit_local_single_human_room_policy', map_level=0,
                    team_id=1, team_index=0, seed_policy='sha256_issued_ticket_context')
    if policy != expected or any(type(policy.get(k)) is not int for k in ('map_level', 'team_id', 'team_index')):
        raise ValueError('The explicit single-human local room policy is required')
    if (observation.get('client_sha256') != CLIENT_SHA256 or observation.get('map_id') != schema['map_id'] or
            observation.get('kind') != 'owned_client_player_start_coordinate_observation' or
            observation.get('identities_and_fields_rechecked') is not True):
        raise ValueError('A matching rechecked world-origin observation is required')
    origin = tuple(observation['pawn_owning_world_origin_xyz'])
    if len(origin) != 3 or any(type(value) is not int for value in origin):
        raise ValueError('The qualified native world-origin vector is required')

    def select(ticket):
        if (type(ticket) is not LocalMatchTicket or ticket.map_id != schema['map_id'] or
                not 0 < ticket.player_id < 1 << 64):
            raise ValueError('The current actual local participant is required')
        # Local server seed policy, not a recovered official server seed. An
        # immutable ticket yields the same allocation on retries and rebinding.
        context = (bytes.fromhex(ticket.cookie) + ticket.room_id.to_bytes(8, 'little') +
                   ticket.map_id.to_bytes(4, 'little') + ticket.match_mode_id.to_bytes(4, 'little'))
        seed = (ticket.room_seed if ticket.room_seed is not None else
                int.from_bytes(hashlib.sha256(b'DF-local-MS23-room-v1\0' + context).digest()[:8], 'little'))
        result = allocate_ms23_one_participant(schema_raw, seed=seed,
            participants=(SpawnParticipant(ticket.player_id, expected['team_id'], expected['team_index']),),
            map_level=expected['map_level'], world_origin=origin,
            normal_native_policy=True, specified_spot=False, specified_template=False)
        vector = QuantizedVector10(tuple(math.floor(value * 10) for value in result['protocol_coordinate_xyz']))
        rotation = CompressedRotator16.from_degrees(tuple(result['authored_rotation_degrees']))
        error = math.dist(vector.native_float_components(), result['protocol_coordinate_xyz'])
        if error > 0.2:
            raise ValueError('Selected spawn exceeds its qualified quantization error budget')
        return dict(result, quantized_steps=list(vector.steps), rotation_steps=list(rotation.steps),
                    quantization_error_world_units=error,
                    seed_origin=('prepared_local_room_seed' if ticket.room_seed is not None else expected['seed_policy']),
                    official_server_seed_recovered=False, official_server_map_level_recovered=False)

    return select
