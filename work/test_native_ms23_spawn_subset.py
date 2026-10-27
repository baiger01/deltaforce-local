"""Source-backed tests for the isolated one-participant MS23 subset."""
import copy
import functools
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'outputs/df-local-server'))
sys.path.insert(0, str(ROOT/'work'))
from dfserver.legacy_ds_ms23_spawn import (
    allocate_ms23_one_participant, load_ms23_spawn_schema, NativeSpawnRandom, SpawnParticipant)
from native_spawn_rng_instruction_oracle import seed_state, next_state, player_start_before

SCHEMA_RAW = (ROOT/'outputs/df-local-server/protocol/portable-map-spawn/ms23-spawn-schema.json').read_bytes()
ORIGIN = (357385, -769888, -16797)


def f32(value):
    return struct.unpack('<f', struct.pack('<f', value))[0]


class NativeRandomTests(unittest.TestCase):
    def test_seed_and_next_match_interpreted_native_instructions(self):
        for seed in [0, 1, 2, 0xe9b1526, (1 << 32)-1, 1 << 32, 1 << 63, (1 << 64)-1]:
            random = NativeSpawnRandom(seed)
            expected = seed_state(seed)
            self.assertEqual(random.state, expected)
            for _ in range(32):
                value, expected = next_state(expected)
                self.assertEqual(random.next_uint64(), value)
                self.assertEqual(random.state, expected)

    def test_frozen_native_instruction_vectors(self):
        path = ROOT/'work/evidence/map-system-audit-20261018/native-spawn-rng-instruction-oracle-vectors.json'
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), '11c65f04627ad45bc3883a695248029804b7bda1533a8f0fd9e5c791b1240817')
        for row in json.loads(raw)['vectors']:
            random = NativeSpawnRandom(row['seed'])
            self.assertEqual(random.state, row['initial_state'])
            self.assertEqual([random.next_uint64() for _ in range(8)], row['next_uint64'])
            self.assertEqual(random.state, row['final_state'])

    def test_native_range_width_one_consumes_and_zero_does_not(self):
        random = NativeSpawnRandom(1)
        expected = list(random.state)
        self.assertEqual(random.range(9, 9, 'zero'), 9)
        self.assertEqual(random.state, expected)
        _, expected = next_state(expected)
        self.assertEqual(random.range(9, 10, 'one'), 9)
        self.assertEqual(random.state, expected)

    def test_native_upper_exclusive_modulo(self):
        random = NativeSpawnRandom(0xe9b1526)
        expected = seed_state(random.seed)
        for first, end in [(0, 90), (2, 3), (10, 11), (0, 2), (1, 10), (0, 5)]:
            value, expected = next_state(expected)
            self.assertEqual(random.range(first, end, 'source'), first+value%(end-first))
        self.assertEqual(random.state, expected)


class MS23SubsetTests(unittest.TestCase):
    def allocate(self, **changes):
        args = dict(seed=1, participants=(SpawnParticipant(123456789, 1, 0),), map_level=0,
                    world_origin=ORIGIN, normal_native_policy=True,
                    specified_spot=False, specified_template=False)
        args.update(changes)
        return allocate_ms23_one_participant(SCHEMA_RAW, **args)

    def test_actual_source_rows_are_equivalent_and_groups_are_present(self):
        schema = load_ms23_spawn_schema(SCHEMA_RAW)
        self.assertEqual(len(schema['equivalent_positive_template_rows']), 9)
        self.assertEqual(len(schema['spawn_groups']), 20)
        self.assertEqual(sum(row['weight'] for row in schema['equivalent_positive_template_rows']), 90)
        self.assertEqual(sum(len(g['player_starts']) for g in schema['spawn_groups']), 100)

    def test_full_draw_sequence_matches_native_instruction_oracle(self):
        expected_ranges = [(i, 10) for _ in range(2) for i in range(9)] + [(0, 2), (0, 90),
                           (2, 3), (0, 2), (10, 11), (0, 2), (0, 2)]
        for seed in (0, 1, (1 << 64)-1):
            result = self.allocate(seed=seed)
            self.assertEqual(result['native_rng_draw_count'], 25)
            self.assertEqual([(d['first'], d['exclusive']) for d in result['draws']], expected_ranges)
            state = seed_state(seed)
            for draw in result['draws']:
                value, state = next_state(state)
                self.assertEqual(draw['raw_uint64'], value)
                self.assertEqual(draw['result'], draw['first']+value%(draw['exclusive']-draw['first']))
            self.assertEqual(result['native_rng_final_state'], state)

    def test_native_float32_point_order_from_actual_source_comparator(self):
        schema = load_ms23_spawn_schema(SCHEMA_RAW)
        observed = set()
        for seed in range(64):
            result = self.allocate(seed=seed)
            group = next(g for g in schema['spawn_groups'] if g['team_start_group_id'] == result['team_start_group_id'])
            def local(point):
                xyz = point['transform']['relative_location']['serialized_float32']
                return tuple(f32(f32(xyz[i])-f32(ORIGIN[i])) for i in range(3))
            def compare(left, right):
                return -1 if player_start_before(local(left), local(right)) else 1
            ordered = sorted(group['player_starts'], key=functools.cmp_to_key(compare))
            self.assertEqual(result['player_start_actor'], ordered[0]['actor'])
            self.assertEqual(result['all_group_points_native_fixed_order'], [p['actor'] for p in ordered])
            observed.add(result['team_start_group_id'])
        self.assertEqual(observed, {104, 105, 201, 205})

    def test_member_index_uses_native_modulo_after_fixed_order(self):
        result = self.allocate(participants=(SpawnParticipant(123456789, 1, 7),))
        self.assertEqual(result['player_start_slot'], 2)
        self.assertEqual(result['player_start_actor'], result['all_group_points_native_fixed_order'][2])

    def test_no_exact_template_label_or_collision_claim(self):
        result = self.allocate()
        self.assertIsNone(result['exact_selected_template_row'])
        self.assertEqual(len(result['source_equivalent_template_rows']), 9)
        self.assertFalse(result['native_collision_adjustment_applied'])
        self.assertFalse(result['native_spawn_position_verified'])

    def test_schema_mutation_is_refused(self):
        changed = copy.deepcopy(load_ms23_spawn_schema(SCHEMA_RAW))
        changed['equivalent_positive_template_rows'][0]['weight'] += 1
        with self.assertRaises(ValueError):
            load_ms23_spawn_schema(json.dumps(changed).encode())

    def test_multiple_or_missing_roster_is_refused(self):
        for participants in ((), (SpawnParticipant(1, 1, 0), SpawnParticipant(2, 1, 1))):
            with self.assertRaises(ValueError):
                self.allocate(participants=participants)

    def test_unqualified_inputs_are_refused(self):
        for changes in ({'seed': True}, {'seed': -1}, {'seed': 1 << 64}, {'map_level': 1},
                        {'world_origin': (0, 0, True)}, {'normal_native_policy': False},
                        {'specified_spot': True}, {'specified_template': True},
                        {'participants': (SpawnParticipant(8000, 1, 0),)}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.allocate(**changes)


if __name__ == '__main__':
    unittest.main()
