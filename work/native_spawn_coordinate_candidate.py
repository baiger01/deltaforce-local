"""Pure exact current-point arithmetic; no process/native/packet operations.

The result is an unquantized diagnostic point for a new server policy. It never
recovers a historical ActorOpen input or claims a final spawned Character root.
The predicted local translation excludes the later Vector10 quantization;
this helper deliberately does not assert that a wire vector preserves it.
Caller assertions qualify the two samples and same-map/world relationships.
"""
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import struct

import native_spawn_default_state as source_io

PREFIX = "work/evidence/map-entry-next-20261007/"
SOURCE_PATH = PREFIX + "spawn-current-point-coordinate-candidate-profile.json"
SOURCE_SHA256 = "48cf237bbe9d1e144dcbc667f84ab3f592f11c6c8a566fb53c95a70473cb0bfb"
EXTRACTION_PATH = PREFIX + "spawn-vector-producer-source-extraction.json"
EXTRACTION_SHA256 = "51e54ec1cdea3cf48e93bfed748ba43e6026c967626adf97967ffb7e15f65701"
MODULE_PATH = "work/native_spawn_coordinate_candidate.py"
MIN_NORMAL = 2.0 ** -126


class SpawnCoordinateCandidateError(ValueError):
    pass


def qualified_source_pins(root):
    try:
        root = Path(root).resolve(strict=True)
        pins = source_io.qualified_source_pins(root)
        def pin(relative, expected):
            raw = source_io._read_source(root, relative)
            if relative in pins or hashlib.sha256(raw).hexdigest() != expected:
                raise SpawnCoordinateCandidateError("fixed_coordinate_source_changed")
            pins[relative] = expected
            return raw
        profile = json.loads(pin(SOURCE_PATH, SOURCE_SHA256))
        if (profile.get("kind") != "source_qualified_current_point_actor_open_coordinate_candidate_profile"
                or profile.get("client_sha256") != source_io.SHIPPING_SHA256
                or profile.get("producer_extraction_relative_path") != EXTRACTION_PATH
                or profile.get("producer_extraction_sha256") != EXTRACTION_SHA256):
            raise SpawnCoordinateCandidateError("fixed_coordinate_profile_changed")
        extraction = json.loads(pin(EXTRACTION_PATH, EXTRACTION_SHA256))
        if (extraction.get("kind") != "offline_same_build_spawn_vector_producer_sources"
                or extraction.get("client_sha256") != source_io.SHIPPING_SHA256
                or len(extraction.get("source_files", [])) != 6
                or len(extraction.get("immutable_records", [])) != 5):
            raise SpawnCoordinateCandidateError("fixed_coordinate_extraction_changed")
        for row in extraction["source_files"]:
            for extension, key in (("code", "code_sha256"), ("asm.txt", "asm_sha256")):
                pin(PREFIX + row["stem"] + "." + extension, row[key])
        for row in extraction["immutable_records"]:
            pin(row["relative_path"], row["sha256"])
        raw = source_io._read_source(root, MODULE_PATH)
        if raw != Path(__file__).read_bytes():
            raise SpawnCoordinateCandidateError("imported_coordinate_module_changed")
        pins[MODULE_PATH] = hashlib.sha256(raw).hexdigest()
        return pins
    except Exception:
        raise SpawnCoordinateCandidateError("coordinate_source_qualification_refused") from None


qualified_spawn_coordinate_sources = qualified_source_pins


def _int3(value):
    if (type(value) is not dict or set(value) != {"x", "y", "z"}
            or any(type(value[k]) is not int or not -(1 << 31) <= value[k] < 1 << 31
                   for k in ("x", "y", "z"))):
        raise SpawnCoordinateCandidateError("qualified_int32_triplet_required")
    return tuple(value[k] for k in ("x", "y", "z"))


def _float3(value):
    if type(value) is not dict or set(value) != {"x", "y", "z"}:
        raise SpawnCoordinateCandidateError("qualified_float32_triplet_required")
    result = []
    for key in ("x", "y", "z"):
        v = value[key]
        if type(v) not in (int, float) or not math.isfinite(v):
            raise SpawnCoordinateCandidateError("qualified_finite_float32_required")
        try:
            f = struct.unpack("<f", struct.pack("<f", v))[0]
        except (OverflowError, ValueError, struct.error):
            raise SpawnCoordinateCandidateError("qualified_finite_float32_required") from None
        if f != v:
            raise SpawnCoordinateCandidateError("input_not_exact_float32")
        result.append(f)
    return tuple(result)


def _branch(gate, origin, default):
    if type(gate) is not int or not -(1 << 31) <= gate < 1 << 31:
        raise SpawnCoordinateCandidateError("qualified_int32_gate_required")
    return "origin_arithmetic" if gate > 0 and origin != default else "identity_bitcopy"


def _arithmetic(point, origin, sign):
    result = []
    for value, integer in zip(point, origin):
        converted = struct.unpack("<f", struct.pack("<f", integer))[0]
        if converted != integer:
            raise SpawnCoordinateCandidateError("origin_conversion_not_exact_float32")
        if 0 < abs(value) < MIN_NORMAL:
            raise SpawnCoordinateCandidateError("subnormal_input_mxcsr_unobserved")
        exact = Fraction.from_float(value) + sign * integer
        if not exact:
            raise SpawnCoordinateCandidateError("zero_result_sign_mxcsr_unobserved")
        try:
            candidate = struct.unpack("<f", struct.pack("<f", float(exact)))[0]
        except (OverflowError, ValueError, struct.error):
            raise SpawnCoordinateCandidateError("arithmetic_not_exact_finite_float32") from None
        if not math.isfinite(candidate) or Fraction.from_float(candidate) != exact:
            raise SpawnCoordinateCandidateError("arithmetic_not_exact_finite_float32")
        if abs(candidate) < MIN_NORMAL:
            raise SpawnCoordinateCandidateError("subnormal_result_mxcsr_unobserved")
        result.append(candidate)
    return tuple(result)


def _safe_point(point):
    raw = struct.pack("<fff", *point)
    return {"float32_bits": list(struct.unpack("<III", raw)),
            "finite_xyz": dict(zip(("x", "y", "z"), point))}


def candidate_current_sample_actor_open_location(*, observed_client_xyz,
        observed_world_origin, observed_feature_gate, observed_default_origin,
        local_world_origin, local_feature_gate, local_default_origin,
        current_samples_source_qualified, same_map_coordinate_frame_verified, source_pins):
    """No missing values or float rounding are filled in by this pure helper."""
    try:
        root = Path(__file__).resolve().parent.parent
        pins = qualified_source_pins(root)
        def seal():
            if type(source_pins) is not dict or any(source_pins.get(p) != h for p, h in pins.items()):
                raise SpawnCoordinateCandidateError("caller_coordinate_source_seal_required")
        seal()
        if current_samples_source_qualified is not True:
            raise SpawnCoordinateCandidateError("qualified_current_samples_required")
        if same_map_coordinate_frame_verified is not True:
            raise SpawnCoordinateCandidateError("same_map_coordinate_frame_required")
        point = _float3(observed_client_xyz)
        sample_origin, sample_default = _int3(observed_world_origin), _int3(observed_default_origin)
        local_origin, local_default = _int3(local_world_origin), _int3(local_default_origin)
        sample_branch = _branch(observed_feature_gate, sample_origin, sample_default)
        local_branch = _branch(local_feature_gate, local_origin, local_default)
        location = (_arithmetic(point, sample_origin, +1)
                    if sample_branch == "origin_arithmetic" else point)
        if sample_branch == "origin_arithmetic":
            roundtrip = _arithmetic(location, sample_origin, -1)
            if struct.pack("<fff", *roundtrip) != struct.pack("<fff", *point):
                raise SpawnCoordinateCandidateError("sample_roundtrip_not_exact")
        translation = (_arithmetic(location, local_origin, -1)
                       if local_branch == "origin_arithmetic" else location)
        if qualified_source_pins(root) != pins:
            raise SpawnCoordinateCandidateError("coordinate_sources_changed_during_math")
        seal()
        result = {"status": "diagnostic_candidate_exact", "sample_branch": sample_branch,
                  "local_receive_branch": local_branch,
                  "actor_open_location_float32_candidate": _safe_point(location),
                  "local_pre_spawn_translation_float32_candidate": _safe_point(translation),
                  "source_pins_rechecked": True}
    except Exception as error:
        result = {"status": "unknown", "reason": str(error) if type(error) is SpawnCoordinateCandidateError
                  else "controlled_coordinate_candidate_refused"}
    result.update(kind="source_qualified_current_point_coordinate_candidate",
        source_profile_sha256=SOURCE_SHA256, diagnostic_only=True,
        current_point_is_historical_birth_point=False, final_character_root_position_proved=False,
        native_rounding_mode_observed=False, native_float_to_steps_full_handler_qualified=False,
        local_translation_is_unquantized_arithmetic_prediction=True,
        candidate_survives_quantized_vector_codec_verified=False,
        quantized_steps_produced=False, packet_produced_or_sent=False, process_accessed=False,
        native_methods_invoked=False, memory_written=False, playable_map_verified=False,
        current_samples_and_same_world_relationship_are_caller_contract=True,
        repeated_samples_are_atomic=False)
    return result
