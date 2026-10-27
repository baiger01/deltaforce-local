"""Pinned normal MS23 first-human allocation, before collision adjustment."""
import copy
from dataclasses import dataclass
import hashlib
import json
import math
import struct

SCHEMA_SHA256 = '1d849b047eeddc72ce7e3852734ca75bcbae4bb7249ec4a7e512bd9ac6c8a8a1'
CLIENT_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
MASK64 = (1 << 64) - 1


def _f32(value):
    return struct.unpack('<f', struct.pack('<f', value))[0]


def _rol64(value, shift):
    return ((value << shift) | (value >> (64-shift))) & MASK64


def _mix64(value):
    value = ((value ^ (value >> 30)) * 0xbf58476d1ce4e5b9) & MASK64
    value = ((value ^ (value >> 27)) * 0x94d049bb133111eb) & MASK64
    return value ^ (value >> 31)


class NativeSpawnRandom:
    """The pinned c404400/c41f820/c41f920 normal native routines."""

    def __init__(self, seed):
        if type(seed) is not int or not 0 <= seed <= MASK64:
            raise ValueError('An explicit uint64 room seed is required')
        self.seed, self.state, self.draws = seed, [], []
        for _ in range(4):
            seed = _mix64(seed)
            self.state.append(seed)
        if not any(self.state):
            self.state[0] = 1

    def next_uint64(self):
        s0, s1, s2, s3 = self.state
        result = (_rol64((s1*5) & MASK64, 7)*9) & MASK64
        mixed03, mixed02 = s1 ^ s3, s0 ^ s2
        self.state = [s0 ^ mixed03, s1 ^ mixed02,
                      mixed02 ^ ((s1 << 17) & MASK64), _rol64(mixed03, 45)]
        return result

    def range(self, first, exclusive, purpose):
        if (type(first) is not int or type(exclusive) is not int or
                not 0 <= first <= exclusive <= MASK64 or type(purpose) is not str):
            raise ValueError('An explicit nonnegative native range and purpose are required')
        before = list(self.state)
        raw = self.next_uint64() if first != exclusive else None
        result = first if raw is None else first + raw % (exclusive-first)
        self.draws.append(dict(purpose=purpose, first=first, exclusive=exclusive,
                               raw_uint64=raw, result=result, state_before=before,
                               state_after=list(self.state)))
        return result

    def shuffle(self, items, purpose):
        for index in range(len(items)-1):
            other = self.range(index, len(items), purpose + ':' + str(index))
            items[index], items[other] = items[other], items[index]


@dataclass(frozen=True)
class SpawnParticipant:
    uid: int
    team_id: int
    team_index: int

    def check(self):
        if (type(self.uid) is not int or not 0 <= self.uid <= MASK64 or
                8000 <= self.uid <= 8999):
            raise ValueError('One native human UID outside the AI interval is required')
        if any(type(value) is not int or not 0 <= value <= 0xffffffff
               for value in (self.team_id, self.team_index)):
            raise ValueError('Explicit uint32 ticket team ID and member index are required')


def load_ms23_spawn_schema(raw):
    if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError('The pinned static MS23 source schema is required')
    return json.loads(raw)


def _point_distance(point, origin):
    transform = point['transform']
    if transform['attach_parent'] is not None:
        raise ValueError('Attached PlayerStarts require a qualified parent transform')
    location = transform['relative_location']
    if location['serialized_type'] != 'EncVector':
        raise ValueError('The pinned EncVector source is required')
    xyz = location['serialized_float32']
    if len(xyz) != 3 or any(type(v) not in (int, float) or not math.isfinite(v) for v in xyz):
        raise ValueError('Three finite authored location components are required')
    local = [_f32(_f32(xyz[i]) - _f32(origin[i])) for i in range(3)]
    square = [_f32(value*value) for value in local]
    return _f32(_f32(square[0]+square[1])+square[2])


def allocate_ms23_one_participant(schema_raw, *, seed, participants, map_level, world_origin,
                                  normal_native_policy, specified_spot, specified_template):
    schema = load_ms23_spawn_schema(schema_raw)
    if type(participants) is not tuple or len(participants) != 1 or type(participants[0]) is not SpawnParticipant:
        raise ValueError('The qualified subset requires exactly one explicit participant')
    participant = participants[0]
    participant.check()
    if normal_native_policy is not True or specified_spot is not False or specified_template is not False:
        raise ValueError('Explicit normal native and unspecified spot/template policies are required')
    if type(map_level) is not int or not -(1 << 31) <= map_level < (1 << 31) or map_level == 1:
        raise ValueError('The source group set requires an explicit MapLevel other than 1')
    if (type(world_origin) is not tuple or len(world_origin) != 3 or
            any(type(v) is not int or not -(1 << 31) <= v < (1 << 31) for v in world_origin)):
        raise ValueError('An explicit int32 world-origin XYZ tuple is required')
    random = NativeSpawnRandom(seed)
    groups = schema['spawn_groups']
    orientations = []
    for group in sorted(groups, key=lambda g: g['team_start_group_id']):
        matching = [o for o in orientations if o['id'] == group['orientation']]
        if not matching:
            orientations.append(dict(id=group['orientation'], groups=[]))
            matching = [orientations[-1]]
        matching[0]['groups'].append(group['team_start_group_id'])
    for orientation in orientations:
        random.shuffle(orientation['groups'], 'InitTeamStarts.orientation.' + str(orientation['id']))
    random.shuffle(orientations, 'InitTeamStarts.orientations')
    rows = schema['equivalent_positive_template_rows']
    total = sum(row['weight'] for row in rows)
    template_draw = random.range(0, total, 'InitGeneralTemplate.weight')
    # Every positive source row is equivalent for the first human allocation.
    # Keep the full set because the native RowMap-to-serialized order is unclosed.
    containers = copy.deepcopy(schema['effective_first_human_containers'])
    containers.sort(key=lambda container: container['Priority'], reverse=True)
    for index, container in enumerate(containers):
        minimum, maximum = container['MinTeamNums'], container['MaxTeamNums']
        container['RemainingCapacity'] = (random.range(minimum, maximum+1, 'InitTemplate.capacity.' + str(index))
                                          if maximum >= minimum else maximum)
        random.shuffle(container['OrientationTeamStarts'], 'InitTemplate.orientations.' + str(index))
    orientation = containers[0]['OrientationTeamStarts'][0]
    candidates = orientation['TeamStartIdGroup']
    group_id = candidates[random.range(0, len(candidates), 'TempMS23.TeamStartId')]
    group = next(group for group in groups if group['team_start_group_id'] == group_id)
    ranked = [(_point_distance(point, world_origin), point) for point in group['player_starts']]
    if len({distance for distance, _ in ranked}) != len(ranked):
        raise ValueError('Equal native distances need independent native tie-order qualification')
    ranked.sort(key=lambda pair: pair[0])
    slot = participant.team_index % len(ranked)
    _, point = ranked[slot]
    package = group['package']
    return dict(kind='source_derived_normal_MS23_one_human_authored_PlayerStart',
        client_sha256=CLIENT_SHA256, source_schema_sha256=SCHEMA_SHA256, map_id=schema['map_id'],
        seed=seed, uid=participant.uid, team_id=participant.team_id, team_index=participant.team_index,
        map_level=map_level, world_origin=list(world_origin),
        source_equivalent_template_rows=[row['name'] for row in rows], exact_selected_template_row=None,
        weighted_template_draw=template_draw, template_weight_sum=total,
        team_start_group_id=group_id, logical_orientation_id=orientation['OrientationId'],
        player_start_slot=slot, player_start_actor=point['actor'], player_start_export=point['export'],
        actor_path=package + '.' + package.rsplit('/', 1)[1] + ':PersistentLevel.' + point['actor'],
        protocol_coordinate_xyz=point['transform']['relative_location']['serialized_float32'],
        authored_rotation_degrees=point['transform']['relative_rotation']['serialized_float32'],
        all_group_points_native_fixed_order=[point['actor'] for _, point in ranked],
        native_rng_draw_count=len(random.draws), native_rng_final_state=list(random.state), draws=random.draws,
        native_collision_adjustment_applied=False, native_spawn_position_verified=False,
        movement_direction_verified=False, playable_map_verified=False)
