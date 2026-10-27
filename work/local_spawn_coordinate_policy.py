"""Local server floor-grid diagnosis policy, independent of native rounding.

Only caller-qualified current coordinates are accepted. Rational arithmetic
selects the tenth-unit grid; every possible per-instruction IEEE rounding mode
is covered by a finite bound. No process/native/packet APIs are created here.
"""
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import struct

import native_spawn_coordinate_candidate as source_bundle

PREFIX = "work/evidence/map-entry-next-20261007/"
SOURCE_PATH = PREFIX + "local-spawn-floor-policy-profile.json"
SOURCE_SHA256 = "e80bbcc1515d590bbaea3cd14eb4c3ca1beb58e7dccd0f4214fc3da773d71278"
MODULE_PATH = "work/local_spawn_coordinate_policy.py"
MIN_STEP, MAX_STEP = -(1 << 24), (1 << 24) - 1
MODES = ("nearest_even", "down", "up", "toward_zero")
MIN_NORMAL = Fraction(1, 1 << 126)
SCALE_BITS = 0x3dcccccd


class SpawnPolicyError(ValueError):
    pass


def qualified_source_pins(root):
    try:
        root = Path(root).resolve(strict=True)
        pins = source_bundle.qualified_spawn_coordinate_sources(root)
        def pin(relative, expected):
            raw = source_bundle.source_io._read_source(root, relative)
            if relative in pins or hashlib.sha256(raw).hexdigest() != expected:
                raise SpawnPolicyError("fixed_local_spawn_policy_source_changed")
            pins[relative] = expected
            return raw
        profile = json.loads(pin(SOURCE_PATH, SOURCE_SHA256))
        if (profile.get("kind") != "source_qualified_local_server_current_point_floor_spawn_policy"
                or profile.get("client_sha256") != source_bundle.source_io.SHIPPING_SHA256
                or profile.get("wire_steps_range_inclusive") != [MIN_STEP, MAX_STEP]
                or profile.get("native_decoder_scale_bits") != hex(SCALE_BITS)
                or len(profile.get("codec_source_files", [])) != 2):
            raise SpawnPolicyError("fixed_local_spawn_policy_profile_changed")
        scale = profile["scale_source"]
        if pin(scale["relative_path"], scale["sha256"]) != struct.pack("<I", SCALE_BITS):
            raise SpawnPolicyError("native_decoder_scale_changed")
        for row in profile["codec_source_files"]:
            pin(row["relative_path"], row["sha256"])
        raw = source_bundle.source_io._read_source(root, MODULE_PATH)
        if raw != Path(__file__).read_bytes():
            raise SpawnPolicyError("imported_local_spawn_policy_module_changed")
        pins[MODULE_PATH] = hashlib.sha256(raw).hexdigest()
        return pins
    except Exception:
        raise SpawnPolicyError("local_spawn_policy_source_qualification_refused") from None


qualified_local_spawn_policy_sources = qualified_source_pins


def _power_two(exponent):
    return Fraction(1 << exponent) if exponent >= 0 else Fraction(1, 1 << -exponent)


def _bits_fraction(bits):
    sign, exponent, mantissa = bits >> 31, (bits >> 23) & 255, bits & 0x7fffff
    if exponent == 255:
        raise SpawnPolicyError("nonfinite_binary32_intermediate")
    if exponent == 0:
        value = Fraction(mantissa) * _power_two(-149)
    else:
        value = Fraction((1 << 23) + mantissa) * _power_two(exponent - 150)
    return -value if sign else value


def _round_binary32(exact, mode):
    """Round exact Fraction without float64/double-rounding intermediates."""
    if mode not in MODES:
        raise SpawnPolicyError("unsupported_rounding_mode")
    if exact == 0:
        return 0  # Numeric zero only; native sign bit is not claimed.
    negative = exact < 0
    value = abs(exact)
    exponent = value.numerator.bit_length() - value.denominator.bit_length()
    if value < _power_two(exponent):
        exponent -= 1
    if exponent < -126:
        raise SpawnPolicyError("subnormal_intermediate_not_covered")
    if exponent > 127:
        raise SpawnPolicyError("overflow_intermediate_not_covered")
    quantum = _power_two(exponent - 23)
    significand = value // quantum
    low = ((exponent + 127) << 23) | (significand - (1 << 23))
    low_value = _bits_fraction(low)
    high = low if low_value == value else low + 1
    if high >= 0x7f800000:
        raise SpawnPolicyError("overflow_intermediate_not_covered")
    if mode == "nearest_even":
        high_value = _bits_fraction(high)
        lo_distance, hi_distance = value - low_value, high_value - value
        selected = low if lo_distance < hi_distance or (lo_distance == hi_distance and not (low & 1)) else high
    elif mode == "toward_zero":
        selected = low
    elif mode == "down":
        selected = high if negative else low
    else:
        selected = low if negative else high
    return selected | (0x80000000 if negative else 0)


def _rational(value):
    return {"numerator": value.numerator, "denominator": value.denominator}


def _float_value(bits):
    return struct.unpack("<f", struct.pack("<I", bits))[0]


def _axis_candidates(step, local_origin, subtract):
    # All allowed steps have exact int32->float32 conversion, regardless of RC.
    if _bits_fraction(_round_binary32(Fraction(step), "nearest_even")) != step:
        raise SpawnPolicyError("step_conversion_not_exact")
    scale = _bits_fraction(SCALE_BITS)
    values = set()
    for multiply_mode in MODES:
        decoded = _bits_fraction(_round_binary32(Fraction(step) * scale, multiply_mode))
        if not subtract:
            values.add(decoded)
            continue
        for origin_mode in MODES:
            converted = _bits_fraction(_round_binary32(Fraction(local_origin), origin_mode))
            for subtraction_mode in MODES:
                bits = _round_binary32(decoded - converted, subtraction_mode)
                values.add(_bits_fraction(bits))
    return values


def select_current_sample_spawn_steps(*, observed_client_xyz, observed_world_origin,
        observed_feature_gate, observed_default_origin, local_world_origin,
        local_feature_gate, local_default_origin, current_samples_source_qualified,
        same_map_content_and_subworld_verified, current_pawn_root_world_relationship_verified,
        maximum_position_error_world_units, source_pins):
    """Select bounded diagnostic steps; never construct or send an ActorOpen.

    The caller budget is a three-dimensional distance in the same native units
    as the sampled Root XYZ. One tenth native unit is this server's policy grid;
    a physical centimeter mapping is deliberately not inferred.
    """
    try:
        root = Path(__file__).resolve().parent.parent
        pins = qualified_source_pins(root)
        def seal():
            if type(source_pins) is not dict or any(source_pins.get(p) != h for p, h in pins.items()):
                raise SpawnPolicyError("caller_local_spawn_policy_source_seal_required")
        seal()
        for value, code in ((current_samples_source_qualified, "qualified_current_samples_required"),
                           (same_map_content_and_subworld_verified, "same_map_content_and_subworld_required"),
                           (current_pawn_root_world_relationship_verified, "current_pawn_root_world_relationship_required")):
            if value is not True:
                raise SpawnPolicyError(code)
        b = maximum_position_error_world_units
        if type(b) not in (int, float) or not math.isfinite(b) or not 0 < b <= 1:
            raise SpawnPolicyError("finite_positive_distance_budget_at_most_one_unit_required")
        budget = Fraction(b)
        point = tuple(Fraction.from_float(v) for v in source_bundle._float3(observed_client_xyz))
        sample_origin = source_bundle._int3(observed_world_origin)
        sample_default = source_bundle._int3(observed_default_origin)
        local_origin = source_bundle._int3(local_world_origin)
        local_default = source_bundle._int3(local_default_origin)
        sample_subtract = source_bundle._branch(observed_feature_gate, sample_origin, sample_default) == "origin_arithmetic"
        local_subtract = source_bundle._branch(local_feature_gate, local_origin, local_default) == "origin_arithmetic"
        ideal = tuple(v + o if sample_subtract else v for v, o in zip(point, sample_origin))
        steps = tuple((v * 10).numerator // (v * 10).denominator for v in ideal)
        if any(not MIN_STEP <= value <= MAX_STEP for value in steps):
            raise SpawnPolicyError("floor_steps_outside_compressed_vector10_range")
        target = tuple(v - o if local_subtract else v for v, o in zip(ideal, local_origin))
        axes, errors = [], []
        for step, origin, wanted in zip(steps, local_origin, target):
            values = _axis_candidates(step, origin, local_subtract)
            error = max(abs(v - wanted) for v in values)
            errors.append(error)
            axes.append({"minimum_numeric_float32": _float_value(_round_binary32(min(values), "nearest_even")),
                         "maximum_numeric_float32": _float_value(_round_binary32(max(values), "nearest_even")),
                         "maximum_absolute_error_exact": _rational(error),
                         "distinct_numeric_results": len(values)})
        squared = sum(e * e for e in errors)
        if squared > budget * budget:
            raise SpawnPolicyError("diagnostic_distance_error_budget_exceeded")
        if qualified_source_pins(root) != pins:
            raise SpawnPolicyError("local_spawn_policy_sources_changed_during_math")
        seal()
        result = {"status": "diagnostic_steps_selected", "steps": list(steps),
                  "sample_branch": "origin_arithmetic" if sample_subtract else "identity_bitcopy",
                  "local_receive_branch": "origin_arithmetic" if local_subtract else "identity_bitcopy",
                  "ideal_protocol_location_exact": [_rational(v) for v in ideal],
                  "ideal_local_translation_exact": [_rational(v) for v in target],
                  "possible_native_translation_axes": dict(zip(("x", "y", "z"), axes)),
                  "position_error_bound_squared_exact": _rational(squared),
                  "caller_distance_budget_squared_exact": _rational(budget * budget),
                  "position_error_bound_approx": math.sqrt(float(squared)),
                  "source_pins_rechecked": True}
    except Exception as error:
        reason = str(error) if type(error) is SpawnPolicyError else "controlled_local_spawn_policy_refused"
        result = {"status": "refused", "refusal_reason": reason}
    result.update(kind="source_qualified_local_server_floor_spawn_policy_result",
        source_profile_sha256=SOURCE_SHA256, policy_grid="floor_to_one_tenth_native_world_unit",
        diagnostic_only=True, coordinate_unit="native_world_units", centimeter_unit_mapping_proved=False,
        independent_rounding_combinations_per_axis=64, mxcsr_constant_between_instructions_assumed=False,
        numeric_bound_requires_normal_completion=True, native_exception_masks_observed=False,
        native_writer_rounding_reproduced=False, native_signed_zero_bytes_reproduced=False,
        current_point_is_historical_birth_point=False, final_spawned_pawn_root_position_verified=False,
        actor_open_reference_version_presence_and_lifecycle_are_caller_contract=True,
        new_process_accessed=False, native_methods_invoked=False, memory_written=False,
        packet_produced_or_sent=False, playable_map_verified=False,
        current_sample_world_and_map_relationships_are_caller_contract=True)
    return result
