"""Fixed module BSS reads through a caller-owned, qualified read-only session.

No process is opened, object pointer followed, native method called or memory
written. These repeated current global values are not ActorOpen-time inputs or
the Character's final transform. Candidate arithmetic is deliberately narrower
than SSE: only exact normal results independent of unobserved MXCSR are emitted.
"""
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import struct

SHIPPING_SHA256 = "4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0"
IMAGE_SIZE = 536408064
MAX_ADDRESS = 0x7fffffffffff
SOURCE_PATH = "work/evidence/map-entry-next-20261007/spawn-default-state-read-profile.json"
SOURCE_SHA256 = "78afc0ae0b565c5657ce5d76f60043b31ccf4a545afb17779c4e2b0efaec8c35"
BIRTH_SOURCE_PATH = "work/evidence/map-entry-next-20261007/birth-location-world-origin-source.json"
BIRTH_SOURCE_SHA256 = "f8aa5bfa942a71fb6af38bba5298cc78c5a7d7471267afec6cdf31ce3df747e8"
MODULE_PATH = "work/native_spawn_default_state.py"
FIELDS = (("feature_gate", 0x1e4dc898, 4, "signed_int32"),
          ("default_origin", 0x1e2f8028, 12, "signed_int32_xyz"),
          ("location_velocity_default", 0x1e2f8090, 12, "float32_xyz_bits"))
MAX_READ_CALLS, MAX_READ_BYTES = 6, 56
MAX_SOURCE_BYTES, MAX_TOTAL_SOURCE_BYTES = 128 * 1024, 1024 * 1024
MIN_NORMAL_FLOAT32 = 2.0 ** -126


class SpawnDefaultObservationError(ValueError):
    """Only fixed, non-sensitive refusal codes may escape this module."""


def _read_source(root, relative):
    if (type(relative) is not str or not relative or ":" in relative or "\\" in relative
            or "\0" in relative or PurePosixPath(relative).is_absolute()
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        raise SpawnDefaultObservationError("invalid_source_path")
    try:
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file():
            raise SpawnDefaultObservationError("source_outside_root_or_missing")
        before = path.stat()
        if not 0 < before.st_size <= MAX_SOURCE_BYTES:
            raise SpawnDefaultObservationError("source_byte_bound")
        with path.open("rb") as stream:
            raw = stream.read(MAX_SOURCE_BYTES + 1)
        after = path.stat()
        if (len(raw) != before.st_size or
                (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
            raise SpawnDefaultObservationError("source_changed_during_read")
        return raw
    except OSError:
        raise SpawnDefaultObservationError("source_missing_or_unreadable") from None


def qualified_source_pins(root):
    """Validate the fixed profile, native source artifacts and imported module."""
    try:
        root = Path(root).resolve(strict=True)
        if not root.is_dir():
            raise SpawnDefaultObservationError("source_root_not_directory")
        pins, total = {}, 0

        def pin(relative, expected):
            nonlocal total
            if relative in pins:
                raise SpawnDefaultObservationError("duplicate_source_path")
            raw = _read_source(root, relative)
            total += len(raw)
            if total > MAX_TOTAL_SOURCE_BYTES or hashlib.sha256(raw).hexdigest() != expected:
                raise SpawnDefaultObservationError("fixed_source_sha256_mismatch")
            pins[relative] = expected
            return raw

        profile = json.loads(pin(SOURCE_PATH, SOURCE_SHA256))
        expected_fields = [{"name": name, "rva": hex(rva), "bytes": size, "storage": storage}
                           for name, rva, size, storage in FIELDS]
        contract = profile.get("read_contract", {})
        if (profile.get("kind") != "source_qualified_module_spawn_default_state_read_profile"
                or profile.get("client_sha256") != SHIPPING_SHA256
                or type(profile.get("image_size")) is not int or profile["image_size"] != IMAGE_SIZE
                or profile.get("source_relative_path") != BIRTH_SOURCE_PATH
                or profile.get("source_sha256") != BIRTH_SOURCE_SHA256
                or profile.get("fixed_reads") != expected_fields
                or type(contract.get("maximum_read_calls")) is not int
                or contract["maximum_read_calls"] != MAX_READ_CALLS
                or type(contract.get("maximum_read_bytes")) is not int
                or contract["maximum_read_bytes"] != MAX_READ_BYTES
                or type(contract.get("reads_per_span")) is not int or contract["reads_per_span"] != 2
                or contract.get("require_identical_repeated_bytes") is not True
                or contract.get("image_and_complete_source_pins_before_after") is not True):
            raise SpawnDefaultObservationError("fixed_profile_schema_changed")
        source = json.loads(pin(BIRTH_SOURCE_PATH, BIRTH_SOURCE_SHA256))
        if (source.get("kind") != "same_build_native_actor_birth_location_receive_translation_source"
                or source.get("client_sha256") != SHIPPING_SHA256
                or source.get("native_receive_translation_formula_closed") is not True
                or source.get("function", {}).get("rva") != "0x1290b840"
                or source.get("function", {}).get("end_exclusive") != "0x1290b8c5"):
            raise SpawnDefaultObservationError("fixed_native_source_schema_changed")
        sources = source.get("source_files")
        if type(sources) is not list or len(sources) != 5:
            raise SpawnDefaultObservationError("fixed_source_list_changed")
        for row in sources:
            for path_key, hash_key in (("code_relative_path", "code_sha256"),
                                       ("asm_relative_path", "asm_sha256")):
                pin(row[path_key], row[hash_key])
        raw = _read_source(root, MODULE_PATH)
        if raw != Path(__file__).read_bytes():
            raise SpawnDefaultObservationError("imported_source_module_mismatch")
        total += len(raw)
        if total > MAX_TOTAL_SOURCE_BYTES:
            raise SpawnDefaultObservationError("source_byte_bound")
        pins[MODULE_PATH] = hashlib.sha256(raw).hexdigest()
        return pins
    except (OSError, TypeError, KeyError, AttributeError, UnicodeError, json.JSONDecodeError):
        raise SpawnDefaultObservationError("source_qualification_refused") from None


qualified_spawn_default_sources = qualified_source_pins


def _origin(value):
    if (type(value) is not dict or set(value) != {"x", "y", "z"}
            or any(type(value[key]) is not int or not -(1 << 31) <= value[key] < 1 << 31
                   for key in ("x", "y", "z"))):
        return None
    return tuple(value[key] for key in ("x", "y", "z"))


def _float_triplet(raw):
    values = struct.unpack("<fff", raw)
    return {"bits": list(struct.unpack("<III", raw)),
            "finite_values": [x if math.isfinite(x) else None for x in values],
            "all_finite": all(math.isfinite(x) for x in values)}


def _candidate(gate, default_origin, default_raw, origin):
    unknown = lambda reason: {"status": "unknown", "reason": reason}
    if origin is None:
        return unknown("world_origin_not_supplied_or_not_qualified")
    location = struct.unpack("<fff", default_raw)
    if not all(math.isfinite(x) for x in location):
        return unknown("location_default_nonfinite")
    if gate <= 0 or origin == default_origin:
        return {"status": "candidate_exact", "branch": "identity_bitcopy",
                **_float_triplet(default_raw), "arithmetic_executed": False}
    result = []
    for value, integer in zip(location, origin):
        converted = struct.unpack("<f", struct.pack("<f", float(integer)))[0]
        if converted != integer:
            return unknown("origin_int32_to_float32_not_exact")
        if 0 < abs(value) < MIN_NORMAL_FLOAT32:
            return unknown("subnormal_input_mxcsr_unobserved")
        # Fraction checks mathematical exactness even when float64 subtraction
        # would discard a small operand next to a large float32 input.
        exact = Fraction.from_float(value) - integer
        if exact == 0:
            return unknown("zero_result_sign_mxcsr_unobserved")
        try:
            candidate = struct.unpack("<f", struct.pack("<f", float(exact)))[0]
        except (OverflowError, ValueError):
            return unknown("subtraction_not_finite_float32")
        if not math.isfinite(candidate) or Fraction.from_float(candidate) != exact:
            return unknown("subtraction_not_exact_float32")
        if abs(candidate) < MIN_NORMAL_FLOAT32:
            return unknown("subnormal_result_mxcsr_unobserved")
        result.append(candidate)
    raw = struct.pack("<fff", *result)
    return {"status": "candidate_exact", "branch": "subtract_origin",
            **_float_triplet(raw), "arithmetic_executed": True,
            "all_integer_conversions_and_subtractions_exact": True}


def observe_spawn_default_state(session, module_base, *, source_pins, world_origin_xyz=None):
    """Read three fixed global spans twice, publishing values only after rechecks.

    The caller must qualify the exact process lifetime and an existing authorized
    session. Optional WorldOrigin is caller-supplied; this module does not read
    World or establish an atomic relation with the current BSS observations.
    """
    reads = requested_bytes = source_checks = image_checks = 0
    result = None
    origin_before = _origin(world_origin_xyz)
    try:
        root = Path(__file__).resolve().parent.parent
        source_checks += 1
        pins = qualified_source_pins(root)
        if (type(source_pins) is not dict
                or any(source_pins.get(path) != digest for path, digest in pins.items())):
            raise SpawnDefaultObservationError("caller_source_seal_missing_or_changed")
        if (type(module_base) is not int or module_base < 0x10000 or module_base % 4096
                or module_base + IMAGE_SIZE - 1 > MAX_ADDRESS):
            raise SpawnDefaultObservationError("invalid_pinned_image_span")
        if not callable(getattr(session, "read", None)):
            raise SpawnDefaultObservationError("controlled_read_callback_required")

        def image():
            nonlocal image_checks
            image_checks += 1
            if (getattr(session, "module_sha256", None) != SHIPPING_SHA256
                    or type(getattr(session, "module_size", None)) is not int
                    or session.module_size != IMAGE_SIZE):
                raise SpawnDefaultObservationError("pinned_image_qualification_required")

        def read_fields():
            nonlocal reads, requested_bytes
            fields = {}
            for name, rva, count, _ in FIELDS:
                if (reads >= MAX_READ_CALLS or requested_bytes + count > MAX_READ_BYTES
                        or not 0 <= rva < rva + count <= IMAGE_SIZE):
                    raise SpawnDefaultObservationError("fixed_read_budget_exhausted")
                reads += 1
                requested_bytes += count
                try:
                    raw = session.read(module_base + rva, count)
                except Exception:
                    raise SpawnDefaultObservationError("controlled_read_callback_refused") from None
                if type(raw) is not bytes or len(raw) != count:
                    raise SpawnDefaultObservationError("incomplete_fixed_read")
                fields[name] = raw
            return fields

        image()
        first = read_fields()
        second = read_fields()
        source_checks += 1
        if qualified_source_pins(root) != pins:
            raise SpawnDefaultObservationError("source_changed_during_observation")
        if (type(source_pins) is not dict
                or any(source_pins.get(path) != digest for path, digest in pins.items())):
            raise SpawnDefaultObservationError("caller_source_seal_missing_or_changed")
        image()
        if first != second:
            raise SpawnDefaultObservationError("spawn_default_bytes_changed")
        gate = struct.unpack("<i", first["feature_gate"])[0]
        default = struct.unpack("<iii", first["default_origin"])
        candidate = _candidate(gate, default, first["location_velocity_default"], origin_before)
        if _origin(world_origin_xyz) != origin_before:
            candidate = {"status": "unknown", "reason": "caller_world_origin_input_changed"}
        result = {"status": "observed", "feature_gate": gate,
                  "default_origin_xyz": dict(zip(("x", "y", "z"), default)),
                  "location_velocity_default": _float_triplet(first["location_velocity_default"]),
                  "candidate_rebased_default": candidate,
                  "image_source_and_bytes_rechecked": True}
    except SpawnDefaultObservationError as error:
        result = {"status": "refused", "refusal_reason": str(error)}
    except Exception:
        result = {"status": "refused", "refusal_reason": "controlled_observation_refused"}
    result.update(kind="source_qualified_module_spawn_default_state_observation",
        source_profile_sha256=SOURCE_SHA256, read_calls=reads, read_bytes=requested_bytes,
        source_qualification_calls=source_checks, image_qualification_calls=image_checks,
        native_methods_invoked=False, new_process_opened=False, memory_written=False,
        object_references_followed=False, raw_module_base_exported=False,
        caller_world_origin_verified_by_module=False, process_identity_recheck_required_by_caller=True,
        snapshot_atomic=False, after_read_inputs_only=True, historical_actor_open_inputs_verified=False,
        final_pawn_position_verified=False, playable_map_verified=False)
    return result
