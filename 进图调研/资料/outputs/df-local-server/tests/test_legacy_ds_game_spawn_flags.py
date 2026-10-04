import unittest

from dfserver.legacy_ds_game_spawn_flags import (
    SOURCE_BUILD_SHA256, calculate_game_spawn_flags,
)


class NativeGameSpawnFlagsTests(unittest.TestCase):
    def calculate(self, **changes):
        # A literal synthetic server state, not a client CDO or engine enum.
        fields = dict(
            source_build_sha256='4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0',
            original_state_u8=0,
            actor_byte93_mask20=False,
            owner_connection_match=False,
            connection_present=True,
            actor_is_connection_actor=False,
            actor_in_connection_actor_array=False,
        )
        fields.update(changes)
        return calculate_game_spawn_flags(**fields)

    def test_literal_no_matches_produces_zero(self):
        result = self.calculate()
        self.assertEqual((result.effective_state_u8, result.flags_u8), (0, 0))
        self.assertFalse(result.state_downgraded)
        self.assertIsNone(result.downgrade_reason)

    def test_literal_state_one_sets_only_bit_zero(self):
        result = self.calculate(original_state_u8=1)
        self.assertEqual((result.effective_state_u8, result.flags_u8), (1, 1))
        self.assertFalse(result.state_downgraded)

    def test_connection_object_reference_sets_only_bit_one(self):
        result = self.calculate(original_state_u8=255, actor_is_connection_actor=True)
        self.assertEqual((result.effective_state_u8, result.flags_u8), (255, 2))

    def test_connection_array_reference_sets_both_bits_for_state_one(self):
        result = self.calculate(original_state_u8=1, actor_in_connection_actor_array=True)
        self.assertEqual((result.effective_state_u8, result.flags_u8), (1, 3))

    def test_both_connection_reference_facts_remain_single_bit(self):
        result = self.calculate(original_state_u8=3, actor_is_connection_actor=True,
                                actor_in_connection_actor_array=True)
        self.assertEqual((result.effective_state_u8, result.flags_u8), (3, 2))

    def test_state_two_nonmatching_owner_and_replication_mask_changes_to_one(self):
        result = self.calculate(original_state_u8=2, actor_byte93_mask20=True,
                                actor_in_connection_actor_array=True)
        self.assertEqual((result.effective_state_u8, result.flags_u8), (1, 3))
        self.assertTrue(result.state_downgraded)
        self.assertEqual(result.downgrade_reason,
                         'native_numeric_state_2_changed_to_1_for_nonmatching_owner')

    def test_state_two_matching_owner_does_not_change(self):
        result = self.calculate(original_state_u8=2, actor_byte93_mask20=True,
                                owner_connection_match=True, actor_is_connection_actor=True)
        self.assertEqual((result.effective_state_u8, result.flags_u8), (2, 2))
        self.assertFalse(result.state_downgraded)
        self.assertIsNone(result.downgrade_reason)

    def test_state_two_without_replication_mask_does_not_change(self):
        result = self.calculate(original_state_u8=2)
        self.assertEqual((result.effective_state_u8, result.flags_u8), (2, 0))
        self.assertFalse(result.state_downgraded)
        self.assertIsNone(result.downgrade_reason)

    def test_absent_connection_cannot_set_connection_bit(self):
        result = self.calculate(original_state_u8=1, connection_present=False)
        self.assertEqual((result.effective_state_u8, result.flags_u8), (1, 1))

    def test_absent_connection_does_not_suppress_source_state_adjustment(self):
        result = self.calculate(original_state_u8=2, actor_byte93_mask20=True,
                                connection_present=False)
        self.assertEqual((result.effective_state_u8, result.flags_u8), (1, 1))
        self.assertTrue(result.state_downgraded)

    def test_non_state_two_never_uses_the_adjustment(self):
        for state, expected_flags in ((0, 0), (1, 1), (3, 0), (255, 0)):
            with self.subTest(state=state):
                result = self.calculate(original_state_u8=state, actor_byte93_mask20=True)
                self.assertEqual((result.effective_state_u8, result.flags_u8),
                                 (state, expected_flags))
                self.assertFalse(result.state_downgraded)

    def test_absent_connection_rejects_every_positive_match_fact(self):
        for key in ('owner_connection_match', 'actor_is_connection_actor',
                    'actor_in_connection_actor_array'):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'absent connection'):
                self.calculate(connection_present=False, **{key: True})

    def test_all_boolean_inputs_reject_integer_or_coerced_values(self):
        for key in ('actor_byte93_mask20', 'owner_connection_match', 'connection_present',
                    'actor_is_connection_actor', 'actor_in_connection_actor_array'):
            for value in (0, 1, None, '', 'true', [], 1.0):
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, 'explicit bool'):
                    self.calculate(**{key: value})

    def test_state_requires_exact_integer_byte_not_bool(self):
        for value in (True, False, -1, 256, None, '2', 2.0):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'integer byte'):
                self.calculate(original_state_u8=value)

    def test_source_build_identity_is_exact_and_explicit(self):
        self.assertEqual(SOURCE_BUILD_SHA256,
                         '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0')
        for value in (None, True, 1, b'4254', '', '0' * 64, SOURCE_BUILD_SHA256.upper()):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'source-qualified'):
                self.calculate(source_build_sha256=value)

    def test_no_business_parameters_have_defaults(self):
        with self.assertRaises(TypeError):
            calculate_game_spawn_flags(source_build_sha256=SOURCE_BUILD_SHA256)


if __name__ == '__main__':
    unittest.main()
