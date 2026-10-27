"""Select an authored Dam PlayerStart after matching loaded client transforms."""
import hashlib
import json
import math

from dfserver.legacy_ds_actor_manifest import CLIENT_SHA256
from dfserver.legacy_ds_quantized_vector import QuantizedVector10
from dfserver.legacy_ds_rotator import CompressedRotator16


def qualify_spawn_point(observation, catalog, actor_path):
    if (observation.get('kind') != 'owned_client_player_start_coordinate_observation' or
            observation.get('client_sha256') != CLIENT_SHA256 or
            observation.get('map_id') != 2201 or observation.get('identities_and_fields_rechecked') is not True or
            catalog.get('source_client_sha256') != CLIENT_SHA256 or catalog.get('map_id') != 2201):
        raise ValueError('Matching rechecked client PlayerStart and Dam catalog sources are required')
    origin = observation['pawn_owning_world_origin_xyz']
    if len(origin) != 3 or any(type(v) is not int for v in origin):
        raise ValueError('The current Pawn owning World origin is required')
    authored = {}
    for group in catalog['spawn_groups']:
        for start in group['player_starts']:
            key = (group['package'], start['actor'])
            if key in authored:
                raise ValueError('Authored PlayerStart identity is ambiguous')
            authored[key] = start['transform']
    selected, selected_rotations, matched = [], [], 0
    seen = set()
    for row in observation['player_starts']:
        path = row['asset_path']
        package, name = path.split('.', 1)[0], path.rsplit('.', 1)[-1]
        if path in seen or (package, name) not in authored:
            raise ValueError('Loaded PlayerStart does not uniquely match the Dam catalog')
        seen.add(path)
        transform = authored[package, name]
        if transform.get('attach_parent') is not None:
            raise ValueError('Attached spawn points need an independently qualified parent transform')
        local = row['root_world_translation_xyz']
        asset = transform['relative_location']['serialized_float32']
        if (len(local) != 3 or len(asset) != 3 or
                any(type(v) not in (int, float) or not math.isfinite(v) for v in local + asset)):
            raise ValueError('Spawn coordinates must be three finite values')
        # This exact equality was observed independently at five loaded native
        # collision capsules, rather than inferred from matching map names.
        if any(abs(local[i] + origin[i] - asset[i]) > 0.001 for i in range(3)):
            raise ValueError('Loaded PlayerStart transform does not match the Pawn world rebasing')
        matched += 1
        if path == actor_path:
            selected.append(asset)
            rotation = transform.get('relative_rotation', {})
            if rotation.get('serialized_type') != 'Rotator':
                raise ValueError('The selected authored PlayerStart rotation is required')
            angles = rotation.get('serialized_float32')
            if type(angles) is not list:
                raise ValueError('An explicit authored rotation list is required')
            selected_rotations.append((angles, CompressedRotator16.from_degrees(tuple(angles))))
    if matched < 3 or len(selected) != 1:
        raise ValueError('Spawn selection needs three corroborating starts and one exact selected path')
    vector = QuantizedVector10(tuple(math.floor(value * 10) for value in selected[0]))
    decoded = vector.native_float_components()
    error = math.dist(decoded, selected[0])
    if error > 0.2:
        raise ValueError('Spawn quantization exceeds the diagnostic coordinate error budget')
    return vector, dict(kind='client_authored_diagnostic_spawn_selection',
        actor_path=actor_path, matched_loaded_player_starts=matched,
        protocol_coordinate_xyz=selected[0], quantized_steps=list(vector.steps),
        native_decoded_xyz=list(decoded), quantization_error_world_units=error,
        authored_rotation_degrees=selected_rotations[0][0],
        rotation_steps=list(selected_rotations[0][1].steps),
        native_decoded_rotation_degrees=list(selected_rotations[0][1].native_float_components()),
        movement_direction_verified=False,
        original_server_random_selection_rules_recovered=False,
        native_spawn_position_verified=False, playable_map_verified=False)
