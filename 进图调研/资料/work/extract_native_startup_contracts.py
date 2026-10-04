"""Produce a focused metadata report from the read-only native inventory."""
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parent.parent
source = ROOT / "outputs/client-analysis/native-inventory.json"
inventory = json.loads(source.read_text(encoding="utf-8"))
modules = inventory["modules"]
focus = []
for module in modules:
    for descriptor in module.get("descriptor_candidates", []):
        filename = descriptor["name"].rsplit("/", 1)[-1]
        if filename not in {"puffer_service.proto", "version_service.proto", "dir_service.proto",
                            "rail_game_message.proto", "wegame_game_config.proto"}:
            continue
        messages = descriptor["messages"]
        if filename == "rail_game_message.proto":
            messages = [m for m in messages if re.search("serverinfo|zone|launch|gameinfo|config", m["name"], re.I)]
        focus.append({"module": module["path"], "module_sha256": module["sha256"],
                      "schema": descriptor["name"], "descriptor_sha256": descriptor["sha256"],
                      "descriptor_pool_linked": descriptor["descriptor_pool_linked"],
                      "messages": messages})
comparison = []
message_differences = []
game_sdk = next(m for m in modules if m["path"].endswith("/rail_api64.dll"))
platform_sdk = next(m for m in modules if m["path"].endswith("/rail_sdk_platform.dll"))
right = {d["name"]: d for d in platform_sdk["descriptor_candidates"]}
for descriptor in game_sdk["descriptor_candidates"]:
    other = right.get(descriptor["name"])
    if other:
        comparison.append({"schema": descriptor["name"],
                           "descriptor_bytes_identical": descriptor["sha256"] == other["sha256"]})
        if descriptor["sha256"] != other["sha256"]:
            left_messages = {m["name"]: m for m in descriptor["messages"]}
            right_messages = {m["name"]: m for m in other["messages"]}
            for name in sorted(set(left_messages) | set(right_messages)):
                left_message, right_message = left_messages.get(name), right_messages.get(name)
                if left_message != right_message:
                    left_fields = {f["number"]: f for f in (left_message or {}).get("fields", [])}
                    right_fields = {f["number"]: f for f in (right_message or {}).get("fields", [])}
                    message_differences.append({"schema": descriptor["name"], "message": name,
                                               "client_field_count": len(left_fields),
                                               "launcher_field_count": len(right_fields),
                                               "client_only_fields": [left_fields[n] for n in sorted(left_fields.keys() - right_fields.keys())],
                                               "launcher_only_fields": [right_fields[n] for n in sorted(right_fields.keys() - left_fields.keys())],
                                               "changed_fields": [{"number": n, "client": left_fields[n], "launcher": right_fields[n]}
                                                                  for n in sorted(left_fields.keys() & right_fields.keys())
                                                                  if left_fields[n] != right_fields[n]]})
result = {
    "inventory_generated_at_utc": inventory["generated_at_utc"],
    "unique_descriptor_byte_strings": len({d["sha256"] for m in modules
                                           for d in m.get("descriptor_candidates", [])}),
    "all_candidates_pool_linked": all(d["descriptor_pool_linked"] for m in modules
                                     for d in m.get("descriptor_candidates", [])),
    "focused_contracts": focus,
    "sdk_schema_comparison": comparison,
    "sdk_message_differences": message_differences,
    "limitations": ["Static metadata only; active call paths and framing unverified",
                    "SDK messages are not established as game lobby messages",
                    "Matching schemas do not imply matching startup ABI or local-account support"],
    "original_client_compatible": False,
}
out = ROOT / "outputs/client-analysis/startup-contracts.json"
out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"focused_schemas": len(focus), "unique_descriptors": result["unique_descriptor_byte_strings"],
                  "all_linked": result["all_candidates_pool_linked"],
                  "sdk_shared_schemas": len(comparison),
                  "sdk_identical_shared_schemas": sum(r["descriptor_bytes_identical"] for r in comparison)}))
