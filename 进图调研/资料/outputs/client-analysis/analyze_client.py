"""Read-only PE dependencies and bounded protobuf metadata inspection.

Never loads a target DLL, launches a game, edits its files, or reads account data.
An embedded descriptor is metadata evidence, not proof of an active wire format.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import re
from datetime import datetime, timezone
from pathlib import Path

import pefile
from google.protobuf import descriptor_pb2, descriptor_pool

MAX_DESCRIPTOR = 1024 * 1024
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
SCHEMA_NAME = re.compile(rb"[A-Za-z_0-9./-]+\.proto(?:devel)?\Z")
# FileDescriptorProto: accepted top-level fields and their wire encodings.
WIRES = {1: {2}, 2: {2}, 3: {2}, 4: {2}, 5: {2}, 6: {2}, 7: {2},
         8: {2}, 9: {2}, 10: {0, 2}, 11: {0, 2}, 12: {2}, 14: {0}}
SINGULAR = {1, 2, 8, 9, 12, 14}
SELECTED = (
    "DeltaForceClient.exe",
    "DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe",
    "DeltaForce/Binaries/Win64/DeltaForceClient-Win64-ShippingBase.dll",
    "DeltaForce/Binaries/Win64/GCloud.dll",
    "DeltaForce/Binaries/Win64/GCloudCore.dll",
    "DeltaForce/Binaries/Win64/MSDKCore.dll",
    "DeltaForce/Binaries/Win64/MSDKUnityAdapter.dll",
    "DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll",
)
RELEVANT_EXPORT = re.compile(
    r"proto|serialize|parsefrom|gamechannel|launcher|railinitialize|railfactory|"
    r"railfinalize|sdkinit|seturl|connect@|makeconnect", re.I)
FIXED_LABELS = (
    "InitializeWeGameSDK Failed", "RailInitialize Failed", "RailInitialize Success",
    "GetWeGameSDKEnabled", "GetGameChannel", "ParseGameChannel", "GetLauncherChannel",
    "GetLauncherParamsByKey", "SetLauncherQueryInfo", "SendProtoBase", "InitProto",
    "google::protobuf::MessageLite", "google::protobuf::Message",
    "google.protobuf.MessageLite", "ServerAddrRelease", "launcherchannel",
    "gamesubchannel", "gamechannel", "game_id", "servers_info", "support_zone_server",
)


def read_varint(data, at, limit):
    value = 0
    for shift in range(0, 70, 7):
        if at >= limit:
            raise ValueError("truncated varint")
        byte = data[at]
        at += 1
        if shift == 63 and byte > 1:
            raise ValueError("varint exceeds uint64")
        value |= (byte & 127) << shift
        if byte < 128:
            return value, at
    raise ValueError("unterminated varint")


def descriptor_extent(data, start):
    """Stop before padding, a malformed field, or a second descriptor's name.

    A bounded valid prefix alone does not prove the native registered length.
    Repeated singular fields are a boundary here, not protobuf parse semantics.
    """
    at = end = start
    limit = min(len(data), start + MAX_DESCRIPTOR)
    seen = set()
    reason = "end_of_input"
    while at < limit:
        try:
            tag, cursor = read_varint(data, at, limit)
            field, wire = tag >> 3, tag & 7
            if field not in WIRES or wire not in WIRES[field]:
                reason = "non_descriptor_field"
                break
            if field in SINGULAR and field in seen:
                reason = "repeated_singular_field"
                break
            if wire == 2:
                length, cursor = read_varint(data, cursor, limit)
                if length > limit - cursor:
                    reason = "truncated_length_delimited_field"
                    break
                cursor += length
            else:
                _, cursor = read_varint(data, cursor, limit)
        except ValueError:
            reason = "invalid_varint"
            break
        seen.add(field)
        end = at = cursor
    else:
        if limit < len(data):
            reason = "size_limit"
    return end, reason


def valid_qualified(name, leading_dot=False):
    if leading_dot and name.startswith("."):
        name = name[1:]
    return bool(name) and all(IDENTIFIER.fullmatch(part) for part in name.split("."))


def validate_structure(fd):
    """Validate declarations before trusting a successfully parsed byte string."""
    if not SCHEMA_NAME.fullmatch(fd.name.encode("utf-8")):
        raise ValueError("invalid schema name")
    if fd.package and not valid_qualified(fd.package):
        raise ValueError("invalid package")
    if fd.syntax not in ("", "proto2", "proto3", "editions"):
        raise ValueError("invalid syntax")
    if not (fd.message_type or fd.enum_type or fd.service or fd.extension):
        raise ValueError("no declarations")
    for dependency in fd.dependency:
        if not SCHEMA_NAME.fullmatch(dependency.encode("utf-8")):
            raise ValueError("invalid dependency name")
    for index in (*fd.public_dependency, *fd.weak_dependency):
        if not 0 <= index < len(fd.dependency):
            raise ValueError("invalid dependency index")

    def validate_field(field, oneof_count=None):
        if not IDENTIFIER.fullmatch(field.name):
            raise ValueError("invalid field name")
        if not field.HasField("number") or not 1 <= field.number < (1 << 29):
            raise ValueError("invalid field number")
        if 19000 <= field.number <= 19999:
            raise ValueError("reserved field number")
        if not field.HasField("type") or field.type not in range(1, 19):
            raise ValueError("missing or invalid field type")
        if field.label not in (1, 2, 3):
            raise ValueError("invalid label")
        if field.type in (10, 11, 14) and not valid_qualified(field.type_name, True):
            raise ValueError("missing or invalid referenced type")
        if field.HasField("oneof_index"):
            if oneof_count is None or not 0 <= field.oneof_index < oneof_count:
                raise ValueError("invalid oneof index")

    def validate_enum(enum):
        if not IDENTIFIER.fullmatch(enum.name) or not enum.value:
            raise ValueError("invalid enum")
        names = set()
        for value in enum.value:
            if not IDENTIFIER.fullmatch(value.name) or not value.HasField("number"):
                raise ValueError("invalid enum value")
            if value.name in names:
                raise ValueError("duplicate enum value name")
            names.add(value.name)

    def validate_message(message):
        if not IDENTIFIER.fullmatch(message.name):
            raise ValueError("invalid message name")
        numbers, names = set(), set()
        for field in message.field:
            validate_field(field, len(message.oneof_decl))
            if field.number in numbers or field.name in names:
                raise ValueError("duplicate field")
            numbers.add(field.number)
            names.add(field.name)
        for oneof in message.oneof_decl:
            if not IDENTIFIER.fullmatch(oneof.name):
                raise ValueError("invalid oneof name")
        for field in message.extension:
            validate_field(field)
            if not valid_qualified(field.extendee, True):
                raise ValueError("invalid extension target")
        for nested in message.nested_type:
            validate_message(nested)
        for enum in message.enum_type:
            validate_enum(enum)

    for message in fd.message_type:
        validate_message(message)
    for enum in fd.enum_type:
        validate_enum(enum)
    for field in fd.extension:
        validate_field(field)
        if not valid_qualified(field.extendee, True):
            raise ValueError("invalid extension target")
    for service in fd.service:
        if not IDENTIFIER.fullmatch(service.name):
            raise ValueError("invalid service")
        for method in service.method:
            if not IDENTIFIER.fullmatch(method.name):
                raise ValueError("invalid method")
            if not all(valid_qualified(t, True) for t in (method.input_type, method.output_type)):
                raise ValueError("invalid method type")


def scan_descriptors(data):
    at = 0
    seen = set()
    while True:
        marker = data.find(b".proto", at)
        if marker < 0:
            return
        at = marker + 6
        name_end = at + 5 if data[at:at + 5] == b"devel" else at
        for start in range(max(0, marker - 512), marker):
            if data[start] != 10:
                continue
            try:
                length, name_start = read_varint(data, start + 1, name_end)
                if name_start + length != name_end or length > 512:
                    continue
                name = data[name_start:name_end]
                if not SCHEMA_NAME.fullmatch(name):
                    continue
                end, boundary = descriptor_extent(data, start)
                blob = data[start:end]
                fd = descriptor_pb2.FileDescriptorProto()
                fd.ParseFromString(blob)
                validate_structure(fd)
                if fd.name.encode("utf-8") != name:
                    continue
            except (ValueError, RecursionError, UnicodeError):
                continue
            except Exception as error:
                # Protobuf versions expose DecodeError through different modules.
                if type(error).__name__ == "DecodeError":
                    continue
                raise
            digest = hashlib.sha256(blob).hexdigest()
            if (start, digest) not in seen:
                seen.add((start, digest))
                yield start, end, boundary, fd, blob


def messages_of(fd):
    result = []

    def visit(message, prefix):
        name = ".".join(filter(None, (prefix, message.name)))
        fields = []
        for field in message.field:
            item = {"name": field.name, "number": field.number,
                    "type": descriptor_pb2.FieldDescriptorProto.Type.Name(field.type),
                    "label": descriptor_pb2.FieldDescriptorProto.Label.Name(field.label)}
            if field.type_name:
                item["type_name"] = field.type_name
            if field.HasField("oneof_index"):
                item["oneof_index"] = field.oneof_index
            if field.HasField("default_value"):
                item["has_explicit_default"] = True
                if field.type in (9, 12):
                    item["default_length"] = len(field.default_value)
                    item["default_sha256"] = hashlib.sha256(field.default_value.encode()).hexdigest()
                else:
                    item["default_value"] = field.default_value
            fields.append(item)
        result.append({"name": name, "field_count": len(message.field), "fields": fields})
        for nested in message.nested_type:
            visit(nested, name)

    for message in fd.message_type:
        visit(message, fd.package)
    return result


def inspect_module(path, display_path):
    with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        pe = pefile.PE(data=data, fast_load=True)
        try:
            pe.parse_data_directories(directories=[0, 1, 13])
            imports = []
            for kind, attribute in (("regular", "DIRECTORY_ENTRY_IMPORT"),
                                    ("delay", "DIRECTORY_ENTRY_DELAY_IMPORT")):
                for entry in getattr(pe, attribute, []):
                    imports.append({"module": entry.dll.decode("ascii", "replace"), "kind": kind})
            exports = [symbol.name.decode("ascii", "replace")
                       for symbol in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])
                       if symbol.name and RELEVANT_EXPORT.search(symbol.name.decode("ascii", "replace"))]
            labels = []
            for label in FIXED_LABELS:
                for encoding in ("ascii", "utf-16le"):
                    offset = data.find(label.encode(encoding))
                    if offset >= 0:
                        labels.append({"label": label, "encoding": encoding, "first_offset": offset})
            descriptors, blobs = [], {}
            for start, end, boundary, fd, blob in scan_descriptors(data):
                digest = hashlib.sha256(blob).hexdigest()
                blobs[digest] = blob
                descriptors.append({"name": fd.name, "package": fd.package, "offset": start,
                                    "length": end - start, "sha256": digest, "boundary": boundary,
                                    "dependencies": list(fd.dependency), "syntax": fd.syntax or "proto2",
                                    "messages": messages_of(fd), "active_game_protocol_verified": False})
            report = {"path": display_path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                      "machine": hex(pe.FILE_HEADER.Machine), "imports": imports,
                      "relevant_exports": exports, "fixed_labels": labels,
                      "descriptor_candidates": descriptors}
        finally:
            pe.close()
    return report, blobs


def link_candidates(modules, blobs):
    """Validate each module's descriptor set; do not mix incompatible libraries."""
    for module in modules:
        records = module.get("descriptor_candidates", [])
        pool = descriptor_pool.DescriptorPool()
        pending = list(records)
        errors = {}
        while pending:
            remaining = []
            for record in pending:
                try:
                    pool.AddSerializedFile(blobs[record["sha256"]])
                except Exception as error:
                    errors[record["sha256"]] = str(error)[:240]
                    remaining.append(record)
                else:
                    record["descriptor_pool_linked"] = True
            if len(remaining) == len(pending):
                break
            pending = remaining
        for record in pending:
            record["descriptor_pool_linked"] = False
            record["link_error"] = errors[record["sha256"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--game", type=Path, required=True)
    parser.add_argument("--launcher", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    paths = [(args.game / relative, relative) for relative in SELECTED]
    if args.launcher:
        paths.extend((args.launcher / name, "standalone-launcher/" + name)
                     for name in ("rail_sdk_common64.dll", "rail_sdk_common.dll", "rail_sdk_platform.dll"))
    records, blobs = [], {}
    for path, display in paths:
        if not path.is_file():
            records.append({"path": display, "missing": True})
            continue
        record, extracted = inspect_module(path, display)
        records.append(record)
        blobs.update(extracted)
        print(json.dumps({"module": display, "descriptors": len(record["descriptor_candidates"]),
                          "relevant_exports": len(record["relevant_exports"])}), flush=True)
    link_candidates(records, blobs)
    summaries = [{"path": r["path"], "sha256": r.get("sha256"),
                  "schema_count": len(r.get("descriptor_candidates", [])),
                  "schemas": [{"name": d["name"], "package": d["package"],
                               "linked": d["descriptor_pool_linked"]}
                              for d in r.get("descriptor_candidates", [])]}
                 for r in records]
    result = {"generated_at_utc": datetime.now(timezone.utc).isoformat(),
              "scope": "Selected PE imports, exports, fixed labels and uncompressed descriptor candidates",
              "limitations": ["No runtime initialization or registered descriptor length verification",
                              "No compressed, encrypted, obfuscated or descriptor-free schema recovery",
                              "Imports do not include all dynamically loaded dependencies",
                              "Metadata does not establish an independent identity or active game protocol"],
              "client_modified": False, "vendor_code_executed": False,
              "original_client_compatible": False, "summary": summaries, "modules": records}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(args.report), "module_count": len(records),
                      "descriptor_count": sum(len(r.get("descriptor_candidates", [])) for r in records)}))


if __name__ == "__main__":
    main()
