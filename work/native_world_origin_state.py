"""Fixed callback-only WorldOrigin observation on a caller-selected UWorld.

The caller owns selection from its rechecked controller/Level/World relation and
the already authorized read-only session. This module opens no process, invokes
no native resolver/getter, follows no object reference, and writes no memory.
Only signed origin XYZ and fixed qualification/counts are safe output. They are
world rebasing offsets, not Pawn coordinates or a verified scene transform.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct

import native_connection_binding as _binding
from native_connection_binding import (
    SHIPPING_SHA256, IMAGE_SIZE, MAX_ADDRESS, _pointer, _identity,
    ConnectionBindingObservationError,
)

SOURCE_PATH = "work/evidence/map-entry-next-20261007/world-origin-read-profile.json"
SOURCE_SHA256 = "0d3e82a12dd820abf1ae505ef4b59043bbfffaa5b6d1e4abff85173e47b4f570"
MODULE_PATH = "work/native_world_origin_state.py"
DEPENDENCY_PATH = "work/native_connection_binding.py"
ORIGIN_OFFSET, ORIGIN_BYTES = 0x640, 12
MAX_READ_CALLS, MAX_READ_BYTES, MAX_IDENTITY_CALLS = 2, 24, 2


class WorldOriginObservationError(ConnectionBindingObservationError):
    pass


def _read_source(root, relative):
    if (type(relative) is not str or not relative or ":" in relative or "\\" in relative
            or "\0" in relative or PurePosixPath(relative).is_absolute()
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        raise WorldOriginObservationError("invalid_source_path")
    try:
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file():
            raise WorldOriginObservationError("source_outside_root_or_missing")
        before = path.stat()
        if not 0 < before.st_size <= 128 * 1024:
            raise WorldOriginObservationError("source_byte_bound")
        with path.open("rb") as stream:
            raw = stream.read(128 * 1024 + 1)
        after = path.stat()
        if (len(raw) != before.st_size or
                (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
            raise WorldOriginObservationError("source_changed_during_read")
        return raw
    except OSError:
        raise WorldOriginObservationError("source_missing_or_unreadable") from None


def qualified_source_pins(root):
    """Pin the fixed IntVector/native WorldOffset evidence and imported helpers."""
    try:
        root = Path(root).resolve(strict=True)
        raw = _read_source(root, SOURCE_PATH)
        if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
            raise WorldOriginObservationError("fixed_profile_sha256_mismatch")
        profile = json.loads(raw)
        field = profile.get("field", {})
        expected_members = [{"name": name, "offset": offset, "bytes": 4, "storage": "signed_int32"}
                            for name, offset in (("X", 0), ("Y", 4), ("Z", 8))]
        if (profile.get("kind") != "source_qualified_existing_typed_world_origin_read_profile"
                or profile.get("client_sha256") != SHIPPING_SHA256
                or type(profile.get("image_size")) is not int or profile["image_size"] != IMAGE_SIZE
                or profile.get("required_base_class") != "World"
                or field != {"name": "OriginLocation", "offset": "0x640", "bytes": 12,
                             "type": "IntVector", "alignment": 4, "members": expected_members}):
            raise WorldOriginObservationError("fixed_origin_type_or_offset_schema_changed")
        sources = profile.get("source_files")
        if type(sources) is not list or len(sources) != 20:
            raise WorldOriginObservationError("fixed_source_list_changed")
        pins, total = {SOURCE_PATH: SOURCE_SHA256}, len(raw)
        for row in sources:
            relative, expected = row.get("relative_path"), row.get("sha256")
            if relative in pins:
                raise WorldOriginObservationError("duplicate_source_path")
            raw = _read_source(root, relative)
            total += len(raw)
            if total > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected:
                raise WorldOriginObservationError("fixed_source_sha256_mismatch")
            pins[relative] = expected
        for relative, imported in ((MODULE_PATH, Path(__file__)),
                                   (DEPENDENCY_PATH, Path(_binding.__file__))):
            raw = _read_source(root, relative)
            if raw != imported.read_bytes():
                raise WorldOriginObservationError("imported_source_module_mismatch")
            pins[relative] = hashlib.sha256(raw).hexdigest()
        return pins
    except (OSError, TypeError, KeyError, AttributeError, UnicodeError, json.JSONDecodeError):
        raise WorldOriginObservationError("source_qualification_refused") from None


def observe_world_origin_state(session, module_base, *, world_address,
                               object_identity, source_pins):
    """Read exactly twice at typed World+640, with initialized identity rechecks.

    No value is retained after any refusal. The caller rechecks its selected
    controller/Level/World relationship and process identity around this call.
    Equal repeated bytes and weak identity are bounded checks, not atomicity or
    native serial continuity. Image identity is checked both before and after.
    """
    reads = identity_calls = 0
    result = None
    try:
        pins = qualified_source_pins(Path(__file__).resolve().parent.parent)
        if (type(source_pins) is not dict or
                any(source_pins.get(path) != digest for path, digest in pins.items())):
            raise WorldOriginObservationError("caller_source_seal_missing_or_changed")
        base, world = _pointer(module_base), _pointer(world_address)
        if base + IMAGE_SIZE - 1 > MAX_ADDRESS or world + ORIGIN_OFFSET + ORIGIN_BYTES - 1 > MAX_ADDRESS:
            raise WorldOriginObservationError("invalid_qualified_span")
        if not callable(getattr(session, "read", None)) or not callable(object_identity):
            raise WorldOriginObservationError("controlled_read_and_identity_callbacks_required")

        def image_identity():
            if (getattr(session, "module_sha256", None) != SHIPPING_SHA256
                    or type(getattr(session, "module_size", None)) is not int
                    or session.module_size != IMAGE_SIZE):
                raise WorldOriginObservationError("pinned_image_qualification_required")

        def identity():
            nonlocal identity_calls
            if identity_calls >= MAX_IDENTITY_CALLS:
                raise WorldOriginObservationError("identity_budget_exhausted")
            identity_calls += 1
            try:
                row = object_identity(world, "World")
            except (ValueError, OSError, TypeError):
                raise WorldOriginObservationError("controlled_identity_callback_refused") from None
            if type(row) is not dict:
                raise WorldOriginObservationError("typed_identity_record_required")
            if "client_sha256" in row and row["client_sha256"] != SHIPPING_SHA256:
                raise WorldOriginObservationError("identity_source_mismatch")
            if type(row.get("serial")) is not int or type(row.get("object_index")) is not int:
                raise WorldOriginObservationError("exact_identity_scalar_types_required")
            value = _identity(row, world, "World")
            if value[2] == 0:
                raise WorldOriginObservationError("world_weak_identity_uninitialized")
            if "weak_identity_initialized" in row and row["weak_identity_initialized"] is not True:
                raise WorldOriginObservationError("weak_identity_flag_mismatch")
            if "key" in row and row["key"] != struct.pack("<iI", value[1], value[2]).hex():
                raise WorldOriginObservationError("weak_identity_key_mismatch")
            return value

        def read_origin():
            nonlocal reads
            if reads >= MAX_READ_CALLS:
                raise WorldOriginObservationError("fixed_read_budget_exhausted")
            reads += 1
            try:
                raw = session.read(world + ORIGIN_OFFSET, ORIGIN_BYTES)
            except (ValueError, OSError, TypeError):
                raise WorldOriginObservationError("controlled_read_callback_refused") from None
            if type(raw) is not bytes or len(raw) != ORIGIN_BYTES:
                raise WorldOriginObservationError("incomplete_fixed_origin_read")
            return raw

        image_identity()
        before = identity()
        first = read_origin()
        second = read_origin()
        after = identity()
        image_identity()
        if before != after:
            raise WorldOriginObservationError("world_identity_changed")
        if first != second:
            raise WorldOriginObservationError("world_origin_bytes_changed")
        x, y, z = struct.unpack("<iii", first)
        result = {"status": "observed", "origin_xyz": {"x": x, "y": y, "z": z},
                  "selected_world_weak_identity_initialized": True,
                  "identity_and_origin_bytes_rechecked": True,
                  "selection": "caller_rechecked_controller_level_world_relationship"}
    except (ValueError, OSError, TypeError) as error:
        reason = str(error) if isinstance(error, ConnectionBindingObservationError) else "controlled_observation_refused"
        result = {"status": "refused", "refusal_reason": reason}
    result.update(kind="source_qualified_existing_typed_world_origin_observation",
        source_profile_sha256=SOURCE_SHA256, source_offset=ORIGIN_OFFSET, source_bytes=ORIGIN_BYTES,
        field_storage="signed_int32_xyz", read_calls=reads, read_bytes=reads * ORIGIN_BYTES,
        identity_callbacks=identity_calls, native_getter_invoked=False, memory_written=False,
        new_process_opened=False, object_references_followed=False, snapshot_is_atomic=False,
        native_serial_continuity_proved=False, pawn_position_verified=False,
        level_transform_verified=False, playable_map_verified=False)
    return result
