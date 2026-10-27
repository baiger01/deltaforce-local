"""Read current Role byte width and destination metadata, never send a value.

The caller selects the current typed Pawn's existing RepLayout export and owns
the authorized session/lifetime checks. Fixed Cmd/Parent records are matched to
that export, then independently repeated with enum data, source and image checks.
No process/native access is created here; no enum labels or two-bit default are
assumed. The observed destination is for the pinned normal Actor receive path.
"""
import hashlib
import json
from pathlib import Path
import struct

import native_connection_binding as binding
import native_spawn_default_state as source_io
from native_connection_binding import SHIPPING_SHA256, IMAGE_SIZE, MAX_ADDRESS, _pointer, _identity

PREFIX = "work/evidence/map-entry-next-20261007/"
SOURCE_PATH = PREFIX + "role-byte-metadata-read-profile.json"
SOURCE_SHA256 = "5b4166801b63e6c2da77574a4a4b263272c43d4994e9ebaa409c6f26dce720c0"
MODULE_PATH = "work/native_role_byte_metadata.py"
FIELDS = (("RemoteRole", 5, 5, 152, 6), ("Role", 14, 9, 304, 15))
MAX_READ_CALLS, MAX_READ_BYTES, MAX_ENUM_ENTRIES = 64, 8192, 64
BYTE_SERIALIZER_RVA, ACCESSOR_SLOT_RVA, ACCESSOR_RVA = 0x10e8ec50, 0x1d59de58, 0xd968d0


class RoleByteMetadataError(ValueError):
    pass


def qualified_source_pins(root):
    try:
        root = Path(root).resolve(strict=True)
        def read(relative):
            try:
                return source_io._read_source(root, relative)
            except Exception:
                raise RoleByteMetadataError("source_read_refused") from None
        raw = read(SOURCE_PATH)
        if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
            raise RoleByteMetadataError("fixed_profile_sha256_mismatch")
        profile = json.loads(raw)
        expected = [{"name": n, "command_index": c, "parent_index": p,
                     "data_offset": o, "handle": h} for n, c, p, o, h in FIELDS]
        if (profile.get("kind") != "source_qualified_role_byte_enum_and_parent_destination_read_profile"
                or profile.get("client_sha256") != SHIPPING_SHA256
                or type(profile.get("image_size")) is not int or profile["image_size"] != IMAGE_SIZE
                or profile.get("fields") != expected or len(profile.get("source_files", [])) != 6):
            raise RoleByteMetadataError("fixed_profile_schema_changed")
        pins, total = {SOURCE_PATH: SOURCE_SHA256}, len(raw)
        for row in profile["source_files"]:
            for extension, key in (("code", "code_sha256"), ("asm.txt", "asm_sha256")):
                relative = PREFIX + row["stem"] + "." + extension
                raw = read(relative)
                total += len(raw)
                if relative in pins or hashlib.sha256(raw).hexdigest() != row[key] or total > 1024 * 1024:
                    raise RoleByteMetadataError("fixed_source_sha256_mismatch")
                pins[relative] = row[key]
        for relative, imported in ((MODULE_PATH, Path(__file__)),
                                   ("work/native_connection_binding.py", Path(binding.__file__)),
                                   ("work/native_spawn_default_state.py", Path(source_io.__file__))):
            raw = read(relative)
            if raw != imported.read_bytes():
                raise RoleByteMetadataError("imported_source_module_mismatch")
            pins[relative] = hashlib.sha256(raw).hexdigest()
        return pins
    except RoleByteMetadataError:
        raise
    except Exception:
        raise RoleByteMetadataError("source_qualification_refused") from None


qualified_role_byte_metadata_sources = qualified_source_pins


def observe_role_byte_metadata(session, module_base, *, layout_export, object_identity,
                              source_pins, caller_current_pawn_layout_verified):
    """Observe a caller-selected current Pawn export without invoking serializers.

    Pass the layout dictionary from the newly exported current Pawn, containing
    commands/parents, record hashes and raw Parent24/28. The result never exposes
    layout/descriptor/enum/data addresses, object identities or enum entry names.
    """
    reads = byte_count = identity_calls = 0
    try:
        root = Path(__file__).resolve().parent.parent
        pins = qualified_source_pins(root)
        def seal():
            if type(source_pins) is not dict or any(source_pins.get(p) != h for p, h in pins.items()):
                raise RoleByteMetadataError("caller_source_seal_missing_or_changed")
        seal()
        if caller_current_pawn_layout_verified is not True:
            raise RoleByteMetadataError("current_pawn_layout_selection_required")
        base = _pointer(module_base)
        if base + IMAGE_SIZE - 1 > MAX_ADDRESS or not callable(getattr(session, "read", None)) or not callable(object_identity):
            raise RoleByteMetadataError("controlled_qualified_session_required")
        if type(layout_export) is not dict:
            raise RoleByteMetadataError("current_layout_export_required")
        layout = _pointer(layout_export.get("layout_address"))
        cmds, parents = layout_export.get("commands"), layout_export.get("parents")
        if (type(cmds) is not list or type(parents) is not list or len(cmds) != 198 or len(parents) != 108
                or layout_export.get("command_count") != 198 or layout_export.get("parent_count") != 108
                or any(type(x) is not dict or type(x.get("dispatch_opcode")) is not int
                       or x["dispatch_opcode"] == 0 for x in cmds[:15])):
            raise RoleByteMetadataError("fixed_pawn_layout_schema_required")
        for name, ci, pi, offset, handle in FIELDS:
            row = cmds[ci]
            if (row.get("descriptor_name") != name or row.get("command_index") != ci
                    or row.get("parent_index") != pi or row.get("data_offset") != offset
                    or row.get("relative_handle") != handle or row.get("dispatch_opcode") != 6
                    or parents[pi].get("parent_index") != pi):
                raise RoleByteMetadataError("fixed_role_command_schema_changed")

        def image():
            if (getattr(session, "module_sha256", None) != SHIPPING_SHA256
                    or type(getattr(session, "module_size", None)) is not int or session.module_size != IMAGE_SIZE):
                raise RoleByteMetadataError("pinned_image_qualification_required")

        def read(address, size):
            nonlocal reads, byte_count
            if (type(size) is not int or not 0 < size <= MAX_ENUM_ENTRIES * 16
                    or not 0x10000 <= address <= MAX_ADDRESS or address + size - 1 > MAX_ADDRESS
                    or reads >= MAX_READ_CALLS or byte_count + size > MAX_READ_BYTES):
                raise RoleByteMetadataError("fixed_read_budget_or_span_refused")
            reads += 1
            byte_count += size
            try:
                raw = session.read(address, size)
            except Exception:
                raise RoleByteMetadataError("controlled_read_callback_refused") from None
            if type(raw) is not bytes or len(raw) != size:
                raise RoleByteMetadataError("incomplete_fixed_read")
            return raw

        def identity(address):
            nonlocal identity_calls
            if identity_calls >= 4:
                raise RoleByteMetadataError("enum_identity_budget_exhausted")
            identity_calls += 1
            try:
                row = object_identity(address, "Enum")
                if type(row) is not dict or row.get("name") != "ENetRole":
                    raise RoleByteMetadataError("role_enum_type_not_qualified")
                return _identity(row, address, "Enum")
            except Exception:
                raise RoleByteMetadataError("role_enum_identity_refused") from None

        image()
        header = read(layout + 0x40, 32)
        pp, pn, pc, cp, cn, cc = struct.unpack("<QiiQii", header)
        pp, cp = _pointer(pp), _pointer(cp)
        if pn != 108 or cn != 198 or not pn <= pc <= 65535 or not cn <= cc <= 65535:
            raise RoleByteMetadataError("current_layout_array_counts_changed")
        flag = read(layout + 0x30, 1)
        accessor = read(base + ACCESSOR_SLOT_RVA, 8)
        if struct.unpack("<Q", accessor)[0] != base + ACCESSOR_RVA:
            raise RoleByteMetadataError("enum_array_accessor_unsupported")

        def fields():
            result = {}
            for name, ci, pi, offset, handle in FIELDS:
                command = read(cp + ci * 32, 32)
                parent = read(pp + pi * 64, 64)
                if (hashlib.sha256(command).hexdigest() != cmds[ci].get("record_sha256")
                        or hashlib.sha256(parent).hexdigest() != parents[pi].get("record_sha256")):
                    raise RoleByteMetadataError("current_command_or_parent_record_changed")
                descriptor = _pointer(struct.unpack_from("<Q", command)[0])
                if (struct.unpack_from("<i", command, 0xc)[0] != offset
                        or struct.unpack_from("<H", command, 0x14)[0] != handle
                        or struct.unpack_from("<H", command, 0x16)[0] != pi
                        or command[0x1c] != 6
                        or struct.unpack_from("<Q", parent)[0] != descriptor):
                    raise RoleByteMetadataError("raw_role_records_not_qualified")
                if descriptor != _pointer(cmds[ci].get("descriptor_address")):
                    raise RoleByteMetadataError("current_descriptor_changed")
                table_raw = read(descriptor, 8)
                table = _pointer(struct.unpack("<Q", table_raw)[0])
                if not base <= table < table + 0x98 <= base + IMAGE_SIZE:
                    raise RoleByteMetadataError("byte_vtable_outside_pinned_image")
                target = read(table + 0x90, 8)
                if struct.unpack("<Q", target)[0] != base + BYTE_SERIALIZER_RVA:
                    raise RoleByteMetadataError("byte_serializer_target_unsupported")
                enum_raw = read(descriptor + 0x90, 8)
                enum = struct.unpack("<Q", enum_raw)[0]
                if enum:
                    _pointer(enum)
                result[name] = (command, parent, table_raw, target, enum_raw)
            return result

        first = fields()
        enums = {}
        for record in first.values():
            address = struct.unpack("<Q", record[4])[0]
            if not address or address in enums:
                continue
            before = identity(address)
            eh = read(address + 0x40, 12)
            data, count = struct.unpack("<Qi", eh)
            data = _pointer(data)
            if not 1 <= count <= MAX_ENUM_ENTRIES:
                raise RoleByteMetadataError("enum_values_count_unsupported")
            values = read(data, count * 16)
            maximum = max(struct.unpack_from("<q", values, i * 16 + 8)[0] for i in range(count))
            if not 0 <= maximum <= 256:
                raise RoleByteMetadataError("enum_maximum_not_byte_qualified")
            enums[address] = (before, eh, values, data, count, maximum)
        second = fields()
        if first != second:
            raise RoleByteMetadataError("role_descriptor_metadata_changed")
        for address, (before, eh, values, data, count, maximum) in enums.items():
            if read(address + 0x40, 12) != eh or read(data, count * 16) != values or identity(address) != before:
                raise RoleByteMetadataError("role_enum_metadata_changed")
        if (read(layout + 0x40, 32) != header or read(layout + 0x30, 1) != flag
                or read(base + ACCESSOR_SLOT_RVA, 8) != accessor):
            raise RoleByteMetadataError("role_layout_or_accessor_changed")
        if qualified_source_pins(root) != pins:
            raise RoleByteMetadataError("source_changed_during_observation")
        seal()
        image()
        outputs = {}
        by_parent = {pi: (name, ci, offset) for name, ci, pi, offset, _ in FIELDS}
        remap_enabled = bool(flag[0] & 2)  # ReceiveProperties caller has OR2.
        for name, ci, pi, offset, handle in FIELDS:
            parent = first[name][1]
            alt = struct.unpack_from("<i", parent, 0x28)[0]
            destination = (name, ci, offset)
            if remap_enabled and alt != -1:
                if alt not in by_parent:
                    raise RoleByteMetadataError("alternate_parent_not_role_pair")
                other_name, other_ci, other_offset = by_parent[alt]
                if struct.unpack_from("<H", first[other_name][1], 0x24)[0] != other_ci:
                    raise RoleByteMetadataError("alternate_parent_start_command_unsupported")
                destination = (other_name, other_ci, other_offset)
            enum = struct.unpack("<Q", first[name][4])[0]
            maximum = enums[enum][5] if enum else None
            outputs[name] = {"wire_handle": handle, "destination_field": destination[0],
                "destination_offset": destination[2], "parent_remap_applied": destination[1] != ci,
                "enum_status": "typed_enum_values_observed" if enum else "null_enum_eight_bit_branch",
                "enum_value_count": enums[enum][4] if enum else 0, "enum_maximum": maximum,
                "wire_bit_count": (0 if maximum <= 1 else (maximum - 1).bit_length()) if enum else 8}
        result = {"status": "observed", "layout_flags_raw": flag[0], "normal_receiver_remap_enabled": remap_enabled,
                  "fields": outputs, "image_source_records_and_enum_metadata_rechecked": True}
    except Exception as error:
        result = {"status": "refused", "refusal_reason": str(error) if type(error) is RoleByteMetadataError
                  else "controlled_role_metadata_observation_refused"}
    result.update(kind="source_qualified_role_byte_metadata_observation", source_profile_sha256=SOURCE_SHA256,
        read_calls=reads, read_bytes=byte_count, identity_callbacks=identity_calls,
        new_process_opened=False, native_methods_invoked=False, memory_written=False,
        raw_addresses_or_enum_names_exported=False, role_enum_business_mapping_inferred=False,
        role_value_sent=False, snapshot_atomic=False, native_serial_continuity_proved=False,
        current_pawn_layout_selection_is_caller_contract=True,
        receiver_destination_is_normal_actor_path_contract=True,
        actual_receiver_dispatch_observed=False, playable_map_verified=False)
    return result
