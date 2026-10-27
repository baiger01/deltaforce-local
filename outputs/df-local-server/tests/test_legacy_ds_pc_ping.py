from dataclasses import FrozenInstanceError
import math
import struct
import unittest

from dfserver.legacy_ds_pc_ping import (
    LOCAL_FINITE_PING_POLICY, PingClockSample, PingServerState, decide_ping, encode_pong,
)
from dfserver.legacy_ds_pc_rpc_fields import OrdinaryRPCScalarProfile, ServerBouncePingParams


def state(**overrides):
    fields = dict(connection_id=17, world_clock_id='local-world-A',
                  monotonic_clock_id='local-monotonic-A',
                  last_world_time_f32=9.0, throttle_interval_f32=2.0)
    fields.update(overrides)
    return PingServerState(**fields)


def clocks(**overrides):
    fields = dict(connection_id=17, world_clock_id='local-world-A',
                  monotonic_clock_id='local-monotonic-A', world_time_seconds=10.25,
                  monotonic_time_seconds=1000.5, connection_available=True,
                  connection_timestamp_seconds=1000.25, timestamp_connection_id=17,
                  timestamp_monotonic_clock_id='local-monotonic-A')
    fields.update(overrides)
    return PingClockSample(**fields)


def request(**overrides):
    fields = dict(tc1=1234.5, exact_ping=.5, delta_ts=.25, old_ping=.125,
                  delta_tc=.0625, client_delta_time=.03125)
    fields.update(overrides)
    return ServerBouncePingParams(**fields)


def decide(req=None, current=None, sample=None):
    return decide_ping(request() if req is None else req,
                       state() if current is None else current,
                       clocks() if sample is None else sample,
                       validation_policy=LOCAL_FINITE_PING_POLICY)


class PCPingPolicyTests(unittest.TestCase):
    def test_normal_reply_formula_and_independent_161bit_literal(self):
        original = state()
        result = decide(current=original)
        self.assertEqual(result.reason, 'normal_pong_prepared')
        self.assertEqual(result.reply.server_returned_client_time_stamp, 1234.5)
        self.assertEqual(result.reply.delta_ts, .25)
        self.assertEqual(result.reply.in_server_time_stamp, 10.25)
        self.assertEqual(result.next_state.last_world_time_f32, 10.25)
        self.assertEqual(original.last_world_time_f32, 9.0)
        raw, bits = encode_pong(result, profile=OrdinaryRPCScalarProfile(False, False))
        literal = (int.from_bytes(struct.pack('<ddf', 1234.5, .25, 10.25), 'little') << 1) | 1
        self.assertEqual(bits, 161)
        self.assertEqual(raw, literal.to_bytes(21, 'little'))
        self.assertFalse(result.native_validation_equivalent)
        self.assertFalse(result.native_binding_complete)

    def test_world_and_monotonic_clocks_are_distinct_not_echoed_as_tc1(self):
        result = decide(sample=clocks(world_time_seconds=20.0,
                                     monotonic_time_seconds=987654.25,
                                     connection_timestamp_seconds=987654.0))
        self.assertEqual(result.reply.server_returned_client_time_stamp, 1234.5)
        self.assertEqual(result.reply.delta_ts, .25)
        self.assertEqual(result.reply.in_server_time_stamp, 20.0)

    def test_throttle_strict_greater_and_exact_half_interval(self):
        current = state()
        below = decide(current=current, sample=clocks(world_time_seconds=9.75))
        self.assertEqual(below.reason, 'throttled')
        self.assertIsNone(below.reply)
        self.assertIs(below.next_state, current)
        equal = decide(current=current, sample=clocks(world_time_seconds=10.0))
        self.assertIsNotNone(equal.reply)
        self.assertEqual(equal.next_state.last_world_time_f32, 10.0)

    def test_world_is_f32_before_throttle_and_reply(self):
        current = state(last_world_time_f32=16777216.0, throttle_interval_f32=2.0)
        result = decide(current=current, sample=clocks(world_time_seconds=16777217.0))
        self.assertEqual(result.reason, 'throttled')
        # Next representable float32 value, not a double-only boundary.
        accepted = decide(current=current, sample=clocks(world_time_seconds=16777218.0))
        self.assertEqual(accepted.reply.in_server_time_stamp, 16777218.0)

    def test_null_connection_advances_accepted_throttle_time(self):
        result = decide(sample=clocks(connection_available=False,
                                     connection_timestamp_seconds=None,
                                     timestamp_connection_id=None,
                                     timestamp_monotonic_clock_id=None))
        self.assertEqual(result.reason, 'connection_unavailable')
        self.assertIsNone(result.reply)
        self.assertEqual(result.next_state.last_world_time_f32, 10.25)

    def test_zero_timestamp_yields_zero_delta_without_now_subtraction(self):
        result = decide(sample=clocks(connection_timestamp_seconds=0.0,
                                     monotonic_time_seconds=1000000.0))
        self.assertEqual(result.reply.delta_ts, 0.0)

    def test_two_seconds_inclusive_and_over_limit_keeps_new_state(self):
        equal = decide(sample=clocks(monotonic_time_seconds=1002.25))
        self.assertEqual(equal.reply.delta_ts, 2.0)
        over = decide(sample=clocks(monotonic_time_seconds=1002.5))
        self.assertEqual(over.reason, 'connection_timestamp_delta_exceeds_two_seconds')
        self.assertIsNone(over.reply)
        self.assertEqual(over.next_state.last_world_time_f32, 10.25)

    def test_negative_delta_world_and_interval_are_not_clipped(self):
        result = decide(current=state(last_world_time_f32=-10.0, throttle_interval_f32=-2.0),
                        sample=clocks(world_time_seconds=-10.5,
                                      monotonic_time_seconds=999.75))
        self.assertEqual(result.reply.delta_ts, -.5)
        self.assertEqual(result.reply.in_server_time_stamp, -10.5)
        self.assertEqual(result.next_state.throttle_interval_f32, -2.0)

    def test_omitted_struct_and_unknown_policy_are_not_success(self):
        with self.assertRaises(ValueError):
            decide_ping(None, state(), clocks(), validation_policy=LOCAL_FINITE_PING_POLICY)
        for policy in (None, True, 'native', 'local_finite_input_scalars_v1'):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                decide_ping(request(), state(), clocks(), validation_policy=policy)

    def test_local_finite_policy_rejects_each_scalar_without_state_advance(self):
        current = state()
        for name in ('tc1', 'exact_ping', 'delta_ts', 'old_ping', 'delta_tc', 'client_delta_time'):
            for bad in (math.nan, math.inf, -math.inf):
                with self.subTest(name=name, bad=bad):
                    result = decide(req=request(**{name: bad}), current=current)
                    self.assertEqual(result.reason, 'local_finite_policy_rejected')
                    self.assertIsNone(result.reply)
                    self.assertIs(result.next_state, current)

    def test_clock_provenance_rejects_other_connection_or_epoch(self):
        for override in ({'connection_id': 18, 'timestamp_connection_id': 18},
                         {'world_clock_id': 'different-world'},
                         {'monotonic_clock_id': 'different-mono',
                          'timestamp_monotonic_clock_id': 'different-mono'}):
            with self.subTest(override=override), self.assertRaises(ValueError):
                decide(sample=clocks(**override))
        for override in ({'timestamp_connection_id': 18},
                         {'timestamp_monotonic_clock_id': 'other-epoch'},
                         {'world_clock_id': 'local-monotonic-A'}):
            with self.subTest(override=override), self.assertRaises(ValueError):
                clocks(**override)

    def test_nonfinite_clock_and_f32_overflow_are_rejected(self):
        for name in ('world_time_seconds', 'monotonic_time_seconds', 'connection_timestamp_seconds'):
            for bad in (math.nan, math.inf, -math.inf, True):
                with self.subTest(name=name, bad=bad), self.assertRaises(ValueError):
                    clocks(**{name: bad})
        for factory, override in ((clocks, {'world_time_seconds': 1e100}),
                                  (state, {'last_world_time_f32': 1e100}),
                                  (state, {'throttle_interval_f32': 1e100})):
            with self.subTest(override=override), self.assertRaises(ValueError):
                factory(**override)

    def test_bad_request_types_and_f32_overflow_leave_original_state(self):
        current = state()
        for override in ({'tc1': True}, {'exact_ping': True}, {'old_ping': 1e100},
                         {'tc1': 1 << 2000}):
            with self.subTest(override=override), self.assertRaises(ValueError):
                decide(req=request(**override), current=current)
            self.assertEqual(current.last_world_time_f32, 9.0)

    def test_finite_inputs_with_overflowed_delta_are_local_rejection_after_update(self):
        result = decide(sample=clocks(monotonic_time_seconds=1e308,
                                     connection_timestamp_seconds=-1e308))
        self.assertEqual(result.reason, 'local_nonfinite_delta_rejected')
        self.assertIsNone(result.reply)
        self.assertEqual(result.next_state.last_world_time_f32, 10.25)

    def test_state_and_sample_are_immutable_and_require_strict_identifiers(self):
        current = state()
        with self.assertRaises(FrozenInstanceError):
            current.last_world_time_f32 = 999.0
        for override in ({'connection_id': True}, {'world_clock_id': ''},
                         {'monotonic_clock_id': 'not a clock'}):
            with self.subTest(override=override), self.assertRaises(ValueError):
                state(**override)
        with self.assertRaises(ValueError):
            clocks(connection_available=1)
        with self.assertRaises(ValueError):
            clocks(connection_available=False)

    def test_accepted_state_throttles_next_request_without_mutating_old_state(self):
        original = state()
        first = decide(current=original)
        second = decide(current=first.next_state, sample=clocks(world_time_seconds=10.75))
        self.assertEqual(second.reason, 'throttled')
        self.assertEqual(second.next_state.last_world_time_f32, 10.25)
        self.assertEqual(original.last_world_time_f32, 9.0)

    def test_drop_cannot_be_encoded_as_pong_or_empty_success(self):
        result = decide(sample=clocks(world_time_seconds=9.0))
        with self.assertRaises(ValueError):
            encode_pong(result, profile=OrdinaryRPCScalarProfile(False, False))
        prepared = decide()
        with self.assertRaises(ValueError):
            encode_pong(prepared, profile=None)


if __name__ == '__main__':
    unittest.main()
