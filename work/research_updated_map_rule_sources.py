"""Compare current shadow Dam rule assets to the historical source-pinned policy.

Reads PAK entries in memory. Writes one research report only; never rewrites a
runtime profile, source catalog, game file, account, or decryption constant.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

from bundle_asset_locations_package import package
from extract_game_item_catalog import scalar
from extract_operator_avatar_catalog import fname, tags
from parse_economy_installed_tables import tag_value
from recover_dam_gameplay_catalog import Package
from recover_economy_pak_access import (
    pak_footer, validate_index, directory_index, entry_offset, decode_entry,
    installed_name_map, installed_table_package_identity)
from research_updated_content_resources import access
from scan_weapon_tables import parse_entry
import oodle_payload_reader

ROOT = Path(__file__).resolve().parent.parent
CLIENT_SHA = "79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203"
OLD_CLIENT_SHA = "4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0"
DEFAULT_SHADOW = Path("F:/deltaforce-local-shadow-build-79fb7b10")
PROFILE = "outputs/df-local-server/protocol/portable-map-spawn/profile-carried-inventory.json"
PAKS = ("pak-0-0-pakchunk2-WindowsClient.pak",
        "pak-0-1-pakchunk84-WindowsClient.pak",
        "1.101.37117.36.14_WindowsNoEditor_37131_P.pak")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_json(relative, expected=None):
    raw = (ROOT / relative).read_bytes()
    if expected is not None and sha(raw) != expected:
        raise ValueError("Pinned local source changed: " + relative)
    return json.loads(raw), dict(relative_path=relative, sha256=sha(raw), bytes=len(raw))


def fields_table(header, data, selected_rows=None, selected_fields=None, decoder=tag_value):
    names = installed_name_map(header)
    head, at = tags(data, 0, names, len(data))
    if not any(p["name"] == "RowStruct" for p in head):
        raise ValueError("A complete tagged DataTable is required")
    prefix, count = struct.unpack_from("<ii", data, at)
    if prefix or not 0 <= count <= 100000:
        raise ValueError("Unqualified DataTable prefix/count")
    at += 8
    rows, seen = {}, set()
    for _ in range(count):
        start = at
        name = fname(data, at, names)
        props, at = tags(data, at + 8, names, len(data))
        if name in seen:
            raise ValueError("Duplicate DataTable row")
        seen.add(name)
        if selected_rows is not None and name not in selected_rows:
            continue
        rows[name] = dict(serialized_uexp_offset=start,
            fields={p["name"]: decoder(data, p, names) for p in props
                if selected_fields is None or p["name"] in selected_fields},
            serialized_sha256=sha(data[start:at]))
    if data[at:] != bytes.fromhex("c1832a9e"):
        raise ValueError("Incomplete DataTable row coverage")
    return dict(table=installed_table_package_identity(header)["package_path"],
        row_count=count, complete_row_coverage=True, rows=rows,
        uasset_sha256=sha(header), uexp_sha256=sha(data))


class MemoryPackage(Package):
    """Reuse the historical typed actor reader with current verified bytes."""

    def __init__(self, header, payload):
        metadata = package(header)
        if metadata is None:
            raise ValueError("Unqualified current package header")
        self.header, self.payload = header, payload
        self.names = metadata["names"]
        self.imports = [r["object"] for r in metadata["imports"]]
        summary = 41 + struct.unpack_from("<i", header, 20)[0] * 20
        count, offset = struct.unpack_from("<ii", header, summary + 16)
        self.exports, previous = [], len(header)
        for index in range(count):
            at = offset + index * 104
            cls, _, _, outer = struct.unpack_from("<4i", header, at)
            size, absolute = struct.unpack_from("<qq", header, at + 28)
            if not 0 <= size <= 8 * 1024 * 1024 or absolute != previous:
                raise ValueError("Current package exports are not sequential")
            previous = absolute + size
            self.exports.append(dict(index=index + 1,
                name=fname(header, at + 16, self.names), class_index=cls,
                outer_index=outer, size=size, offset=absolute - len(header)))
        if previous - len(header) != len(payload) - 4 or payload[-4:] != bytes.fromhex("c1832a9e"):
            raise ValueError("Current package companion extent differs")
        self.property_cache = {}
        roots = [e for e in self.exports if e["outer_index"] == 0 and self.object(e["class_index"]) == "World"]
        root_bases = {self.names[struct.unpack_from("<i", header, offset + (e["index"] - 1) * 104 + 16)[0]] for e in roots}
        own = [n for n in self.names if n.startswith("/Game/") and n.rsplit("/", 1)[-1] in root_bases]
        if len(roots) != 1 or len(own) != 1:
            raise ValueError("Current package root World identity is ambiguous")
        self.package_path = own[0]
        for index in (1, max(1, count // 2), count):
            self.properties(index)


def actor_definitions(pkg):
    result = dict(spawn_groups=[], high_value_containers=[], random_loot_points=[])
    for export in pkg.exports:
        index = export["index"]
        props = pkg.properties(index)
        cls = pkg.object(export["class_index"])
        if cls == "TeamStart" and "Dam_Iris_Level1_GameplayConfig" in pkg.package_path:
            points = []
            for ref in pkg.value(props.get("FixedOrderPlayerStarts")):
                point = pkg.exports[ref - 1]
                if pkg.object(point["class_index"]) != "PlayerStart":
                    raise ValueError("Current spawn group references a non-PlayerStart")
                points.append(dict(actor=point["name"], export=ref,
                    tag=pkg.value(pkg.properties(ref).get("PlayerStartTag")),
                    transform=pkg.root_transform(ref)))
            result["spawn_groups"].append(dict(package=pkg.package_path,
                actor=export["name"], export=index, group_id=pkg.value(props.get("GroupId")),
                team_start_group_id=pkg.value(props.get("TeamStartGroupId")),
                orientation=pkg.value(props.get("TeamStartOrientation")),
                indoor=pkg.value(props.get("bIsIndoorStart")), player_starts=points))
        if "HighValueBoxInfo" in props:
            tag = props["HighValueBoxInfo"]
            inner, _ = tags(pkg.payload, tag["value_start"], pkg.names, tag["end"])
            fields = {p["name"]: pkg.value(p) for p in inner}
            if fields:
                result["high_value_containers"].append(dict(package=pkg.package_path,
                    actor=export["name"], export=index, **{"class": cls},
                    explicit_fields=fields, class_defaults_not_resolved=True,
                    transform=pkg.root_transform(index)))
        if cls == "BP_Loot_RandomObj_C":
            result["random_loot_points"].append(dict(package=pkg.package_path,
                actor=export["name"], export=index, **{"class": cls},
                transform=pkg.root_transform(index),
                explicit_fields={k: pkg.value(v) for k, v in props.items()
                    if k != "Loot_Debug_Cube" and any(term in k.lower() for term in
                        ("loot", "rate", "random", "weight", "itemspawn", "\u6389\u843d", "isblocktospawn"))}))
    return result


def changed_fields(old, current):
    return {key: dict(previous=old.get(key), current=current.get(key),
                     previous_present=key in old, current_present=key in current)
        for key in sorted(set(old) | set(current)) if old.get(key) != current.get(key) or (key in old) != (key in current)}


def table_comparison(previous, current):
    old_rows, new_rows = previous["rows"], current["rows"]
    changed = {}
    for name in sorted(set(old_rows) & set(new_rows)):
        changes = changed_fields(old_rows[name]["fields"], new_rows[name]["fields"])
        if changes:
            changed[name] = dict(previous_uexp_offset=old_rows[name]["serialized_uexp_offset"],
                current_uexp_offset=new_rows[name]["serialized_uexp_offset"], fields=changes)
    return dict(previous_row_count=previous["row_count"], current_row_count=current["row_count"],
        added_rows=sorted(set(new_rows) - set(old_rows)), removed_rows=sorted(set(old_rows) - set(new_rows)),
        changed_existing_rows=changed, changed_existing_row_count=len(changed),
        bytes_identical=dict(uasset=previous["source_uasset_sha256"] == current["uasset_sha256"],
            uexp=previous["source_uexp_sha256"] == current["uexp_sha256"]))


def derive(shadow):
    executable = shadow / "DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe"
    if sha(executable.read_bytes()) != CLIENT_SHA:
        raise ValueError("Exact current shadow executable required")
    profile, profile_pin = read_json(PROFILE)
    rules, rules_pin = read_json(profile["local_map_rules"]["sources"]["relative_path"], profile["local_map_rules"]["sources"]["sha256"])
    config, config_pin = read_json(profile["local_map_rules"]["config_relative_path"])
    schema, schema_pin = read_json(profile["random_spawn"]["schema"]["relative_path"], profile["random_spawn"]["schema"]["sha256"])
    catalog, catalog_pin = read_json(profile["spawn"]["catalog"]["relative_path"], profile["spawn"]["catalog"]["sha256"])
    items, items_pin = read_json(profile["local_map_rules"]["items"]["relative_path"], profile["local_map_rules"]["items"]["sha256"])
    observation, observation_pin = read_json(profile["spawn"]["source"]["relative_path"], profile["spawn"]["source"]["sha256"])
    pins = [profile_pin, rules_pin, config_pin, schema_pin, catalog_pin, items_pin, observation_pin]
    old_docs = {}
    source_pin_map = {p["relative_path"]: p["sha256"] for p in rules["source_files"]}
    for row in rules["source_tables"]:
        doc, pin = read_json(row["parsed_report"], source_pin_map[row["parsed_report"]])
        for kind in ("uasset", "uexp"):
            raw = (ROOT / doc["source_" + kind]).read_bytes()
            if sha(raw) != doc["source_" + kind + "_sha256"]:
                raise ValueError("Historical parsed table source changed")
        old_docs[row["table"]] = doc
        pins.append(pin)
    template_path = schema["template_table"]
    template_source = [p for p in schema["source_files"] if p["relative_path"].endswith("SOLStartSpotTemplateTable.uasset")][0]
    template_header = (ROOT / template_source["relative_path"]).read_bytes()
    template_export = (ROOT / template_source["relative_path"]).with_suffix(".uexp").read_bytes()
    for pin in schema["source_files"]:
        if pin["relative_path"].endswith(("SOLStartSpotTemplateTable.uasset", "SOLStartSpotTemplateTable.uexp")):
            if sha((ROOT / pin["relative_path"]).read_bytes()) != pin["sha256"]:
                raise ValueError("Historical spawn template source changed")
            pins.append(pin)
    parsed_template = fields_table(template_header, template_export)
    old_docs[template_path] = dict(parsed_template,
        source_uasset_sha256=sha(template_header), source_uexp_sha256=sha(template_export))
    table_assets = {"../../../DeltaForce/Content/" + name.removeprefix("/Game/"): name for name in old_docs}
    item_stem = "../../../DeltaForce/Content/R13N/Common/Base/DataTables/GameItem"
    map_bases = {"../../../DeltaForce/Content/" + p["package_path"].removeprefix("/Game/") for p in catalog["packages"]}
    map_pattern = re.compile("^(?:" + "|".join(re.escape(p) for p in sorted(map_bases)) + r")(?:_[0-9]+)?\.(?:umap|uexp)$")
    keys, key_provenance = access()
    oodle_payload_reader.PATH = shadow / "DeltaForce/Binaries/Win64/oo2core_8_win64.dll"
    decoded, archive_reports = {}, []
    for filename in PAKS:
        path = shadow / "DeltaForce/Content/Paks" / filename
        footer = pak_footer(path)
        clear, key = None, None
        for candidate in keys:
            public, clear, key = validate_index(path, footer, {footer["guid"]: candidate})
            if clear is not None:
                break
        if clear is None:
            raise ValueError("Current archive index validation failed: " + filename)
        public.pop("registered_guid_found", None)
        directory, files, encoded = directory_index(path, footer, clear, key)
        matches = []
        with path.open("rb") as stream:
            for name, location in files:
                stem = name.rsplit(".", 1)[0]
                if not (stem in set(table_assets) | {item_stem} and name.endswith((".uasset", ".uexp")) or map_pattern.fullmatch(name)):
                    continue
                offset = entry_offset(encoded, location)
                entry = parse_entry(stream, offset, footer["offset"], variant="observed_permutation")
                raw, valid = decode_entry(stream, offset, entry, footer["methods"], key)
                if valid is not True:
                    raise ValueError("Current archive payload SHA1 failed")
                witness = dict(asset=name, archive=filename, encoded_offset=location,
                    entry_offset=offset, decoded_sha256=sha(raw), decoded_bytes=len(raw), archive_payload_sha1_valid=True)
                decoded.setdefault(name, []).append((raw, witness))
                matches.append(witness)
        archive_reports.append(dict(archive=filename, size=path.stat().st_size,
            validation=public, directory=directory, selected_assets=matches))
    ambiguous = {name: [row[1] for row in values] for name, values in decoded.items() if len(values) != 1}
    if ambiguous:
        raise ValueError("Selected source asset has multiple mounted candidates; precedence needs qualification")
    tables, missing = {}, []
    for stem, source_table in table_assets.items():
        if stem + ".uasset" not in decoded or stem + ".uexp" not in decoded:
            missing.append(dict(table=source_table, reason="missing_current_package_companion"))
            continue
        h, hw = decoded[stem + ".uasset"][0]
        b, bw = decoded[stem + ".uexp"][0]
        parsed = fields_table(h, b)
        if parsed["table"] != source_table:
            raise ValueError("Current DataTable package identity differs")
        tables[source_table] = dict(source=dict(uasset=hw, uexp=bw),
            comparison=table_comparison(old_docs[source_table], parsed), current=parsed)
    item_ids = {i["item_id"] for p in rules["blueprint_drop_pools"].values() for i in p["items"]}
    item_ids.update(i for p in rules["high_value_points"] for i in p["source_high_value_items"])
    item_ids.update(i["item_id"] for p in config["pools"].values() for i in p.get("items", []))
    h, hw = decoded[item_stem + ".uasset"][0]
    b, bw = decoded[item_stem + ".uexp"][0]
    item_source = dict(uasset=hw, uexp=bw)
    item_fields = {"ItemID": "id", "Name": "name_key", "GameItemType": "game_item_type",
        "Quality": "quality", "MaxStackCount": "max_stack_count", "Length": "length",
        "Width": "width", "Weight": "weight", "CanStoreInSafeBox": "can_store_in_safe_box"}
    current_items = fields_table(h, b, item_ids, set(item_fields), decoder=scalar)
    qualified_items, item_changes = {}, {}
    for ident, row in current_items["rows"].items():
        normalized = {target: row["fields"][source] for source, target in item_fields.items() if source in row["fields"]}
        if normalized.get("id") != ident:
            raise ValueError("Current GameItem identity differs from its source row")
        differences = {field: dict(previous=items["rows"].get(ident, {}).get(field), current=value)
            for field, value in normalized.items() if items["rows"].get(ident, {}).get(field) != value}
        if differences:
            item_changes[ident] = differences
        qualified_items[ident] = dict(normalized, serialized_uexp_offset=row["serialized_uexp_offset"],
            serialized_row_sha256=row["serialized_sha256"])
    matched_packages, unmatched_previous, current_extra = [], [], []
    old_by_hash = {(p["uasset_sha256"], p["uexp_sha256"]): p for p in catalog["packages"]}
    normalized_current = {key: [] for key in ("spawn_groups", "high_value_containers", "random_loot_points")}
    all_current_counts = Counter()
    for name in sorted(decoded):
        if not name.endswith(".umap"):
            continue
        companion = name[:-5] + ".uexp"
        if companion not in decoded:
            missing.append(dict(asset=name, reason="missing_current_map_companion"))
            continue
        h, hw = decoded[name][0]
        b, bw = decoded[companion][0]
        pkg = MemoryPackage(h, b)
        definitions = actor_definitions(pkg)
        all_current_counts.update({k: len(v) for k, v in definitions.items()})
        identity = (sha(h), sha(b))
        old = old_by_hash.get(identity)
        if old is None:
            current_extra.append(dict(uasset=hw, uexp=bw, package=pkg.package_path,
                definition_counts={k: len(v) for k, v in definitions.items()}))
            continue
        matched_packages.append(dict(previous_uasset_entry=old["uasset_entry"],
            previous_uexp_entry=old["uexp_entry"], uasset=hw, uexp=bw,
            all_source_bytes_identical=True, package=pkg.package_path))
        for key, rows in definitions.items():
            normalized_current[key].extend(dict(row, uasset_entry=old["uasset_entry"]) for row in rows)
    matched_ids = {r["previous_uasset_entry"] for r in matched_packages}
    unmatched_previous = [p for p in catalog["packages"] if p["uasset_entry"] not in matched_ids]
    actor_mismatches = {}
    for key, current_rows in normalized_current.items():
        old_rows = [r for r in catalog[key] if r["uasset_entry"] in matched_ids]
        signature = lambda r: (r["uasset_entry"], r["export"], r["actor"])
        previous_by_id, current_by_id = {signature(r): r for r in old_rows}, {signature(r): r for r in current_rows}
        changes = []
        for identity in sorted(set(previous_by_id) | set(current_by_id)):
            before, after = previous_by_id.get(identity), current_by_id.get(identity)
            if before != after:
                changes.append(dict(identity=list(identity), fields=changed_fields(before or {}, after or {})))
        actor_mismatches[key] = changes
    new_template = tables.get(template_path, {}).get("current", {})
    dam_template_rows = {k: v for k, v in new_template.get("rows", {}).items() if v["fields"].get("SOLMapName") == "Dam_Iris_Level1"}
    current_mandel = tables.get("/Game/DataTables/SOL/MandelBrickSeamlessMapInfoTable", {}).get("current", {}).get("rows", {}).get("2201", {})
    current_high = tables.get("/Game/DataTables/SOL/HighValueBoxSeamlessMapInfoTable", {}).get("current", {}).get("rows", {}).get("2201", {})
    current_counts = dict(spawn_template_rows=new_template.get("row_count"),
        dam_template_rows=len(dam_template_rows),
        dam_positive_template_rows=sum(r["fields"].get("Weight", 0) > 0 for r in dam_template_rows.values()),
        matched_previous_packages=len(matched_packages), selected_current_map_packages=len(matched_packages) + len(current_extra),
        spawn_groups=len(normalized_current["spawn_groups"]),
        player_starts=sum(len(g["player_starts"]) for g in normalized_current["spawn_groups"]),
        high_value_container_overrides=len(normalized_current["high_value_containers"]),
        random_loot_points=len(normalized_current["random_loot_points"]),
        explicitly_blocked_loot_actors=sum(p["explicit_fields"].get("isBlockToSpawn") is True for p in normalized_current["random_loot_points"]),
        mandel_generators=len(current_mandel.get("fields", {}).get("GeneratorStructMap", [])),
        high_value_points=len(current_high.get("fields", {}).get("HighValueBoxInfoArray", [])),
        high_value_event_ids=len(set(current_high.get("fields", {}).get("EventIDForSpawnArray", []))))
    sys.path.insert(0, str(ROOT / "outputs/df-local-server"))
    from dfserver.legacy_ds_local_map_rules import simulate_local_map_rules
    from dfserver.legacy_ds_ms23_spawn import allocate_ms23_one_participant, SpawnParticipant
    sources_raw = (ROOT / rules_pin["relative_path"]).read_bytes()
    items_raw = (ROOT / items_pin["relative_path"]).read_bytes()
    config_raw = (ROOT / config_pin["relative_path"]).read_bytes()
    schema_raw = (ROOT / schema_pin["relative_path"]).read_bytes()
    seeds = range(128)
    simulated = [simulate_local_map_rules(sources_raw, items_raw, config_raw, seed=s) for s in seeds]
    if simulated[7] != simulate_local_map_rules(sources_raw, items_raw, config_raw, seed=7):
        raise ValueError("Existing local policy replay was not deterministic")
    allocated = [allocate_ms23_one_participant(schema_raw, seed=s,
        participants=(SpawnParticipant(123456789, 1, 0),), map_level=0,
        world_origin=tuple(observation["pawn_owning_world_origin_xyz"]),
        normal_native_policy=True, specified_spot=False, specified_template=False) for s in seeds]
    if len({r["team_start_group_id"] for r in allocated}) < 2:
        raise ValueError("Existing authored allocation did not vary by seed")
    compact_tables = {name: {k: v for k, v in row.items() if k != "current"} for name, row in tables.items()}
    changed_tables = [name for name, row in compact_tables.items() if any((row["comparison"]["added_rows"],
        row["comparison"]["removed_rows"], row["comparison"]["changed_existing_rows"]))]
    current_rule_rows_same = all(name not in changed_tables for name in (
        "/Game/DataTables/SOL/MandelBrickSeamlessMapInfoTable",
        "/Game/DataTables/SOL/HighValueBoxSeamlessMapInfoTable"))
    return dict(kind="updated_Dam_map_rule_source_comparison_v1", client_sha256=CLIENT_SHA,
        previous_client_sha256=OLD_CLIENT_SHA, current_shadow=str(shadow),
        exact_shadow_executable_sha256_verified=True, local_source_pins=pins,
        historical_asset_access_candidates_qualified_by_current_index_hash=True,
        key_provenance=key_provenance, keys_disclosed=False, archives=archive_reports,
        archive_scope="Historical source archives chunk2/chunk84 plus current _P hotfix; other mounted archives and runtime hot replacements are not resolved",
        count_scope="Historical qualified Dam package selection and matching numbered package siblings, not an exhaustive census of all Dam assets",
        historical_counts=catalog["counts"], current_counts=current_counts,
        tables=compact_tables, changed_tables=changed_tables,
        local_drop_item_qualification=dict(source=item_source,
            current_GameItem_row_count=current_items["row_count"], referenced_item_count=len(item_ids),
            qualified_current_rows=qualified_items,
            referenced_ids_absent_from_current=sorted(item_ids - set(qualified_items)),
            changed_normalized_existing_rows=item_changes,
            scope="All historical BlueprintPlunderDropPool candidates, Dam high-value source item lists and explicit local custom pool IDs; no official drop distribution inferred"),
        package_comparison=dict(matched_previous_packages=matched_packages,
            previous_packages_without_identical_current_bytes=unmatched_previous,
            additional_current_selected_packages=current_extra,
            additional_current_selection_status="Absent from the historical selected catalog; not proof these packages were added in this update",
            current_candidate_package_definition_counts=dict(all_current_counts),
            actor_definition_mismatches_for_identical_packages=actor_mismatches),
        missing_current_assets=missing,
        current_Dam_rule_rows_unchanged=current_rule_rows_same,
        existing_local_config=config,
        local_policy_semantics=dict(appearance="one Bernoulli draw per family",
            candidate_selection="weighted without replacement", drop_slots="weighted with replacement",
            quantities="bounded configurable local aggregate units",
            official_server_rates_recovered=False, configurable_local_rates_supported=True,
            source_item_lists_are_official_drop_distributions=False),
        offline_plumbing_checks=dict(seed_count=128, replay_seed_7_identical=True,
            authored_spawn_groups_selected=sorted({r["team_start_group_id"] for r in allocated}),
            authored_spawn_actor_count=len({r["actor_path"] for r in allocated}),
            specified_spot=False, specified_template=False,
            simulated_mandel_seeds=sum(bool(r["selected_mandel_generator_ids"]) for r in simulated),
            simulated_high_value_event_sets=len({tuple(r["selected_high_value_event_ids"]) for r in simulated}),
            outputs_prove_current_native_spawning_or_pickup=False),
        migration=dict(packaged_data_comparison_available=True,
            byte_identical_previous_map_packages_reusable_as_source_evidence=len(unmatched_previous) == 0,
            production_sources_migrated=False,
            missing_inputs=[
                "Current-client qualification of normal MS23 allocator/native RNG, template branches and collision adjustment; existing instruction evidence is old-client only",
                "Current-client owning-world origin and PlayerStart/root-world relationship observation; spawn-points.json is old-client only",
                "Current-client map admission/control/replication and actor metadata contracts; packaged asset equality does not qualify wire compatibility",
                "Native activation/world placement, loot interaction/pickup and inventory persistence acceptance against the current shadow",
                "Mounted source precedence and live hot replacements outside the three selected source archives if exact effective runtime source identity is required"],
            official_server_activation_rates_or_pool_bindings_not_required_for_user_configurable_local_policy=True),
        game_files_modified=False, runtime_profiles_or_catalogs_modified=False,
        game_process_accessed=False, network_used=False, native_acceptance_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shadow", type=Path, default=DEFAULT_SHADOW)
    parser.add_argument("--output", type=Path, default=ROOT / "work/evidence/updated-map-rule-sources-79fb7b10.json")
    args = parser.parse_args()
    if not args.output.resolve().is_relative_to(ROOT / "work/evidence"):
        parser.error("Research report must remain under work/evidence")
    report = derive(args.shadow.resolve(strict=True))
    raw = (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("ascii")
    if args.output.exists():
        if args.output.read_bytes() != raw:
            parser.error("Existing research report differs; use a fresh evidence path")
    else:
        with args.output.open("xb") as stream:
            stream.write(raw)
    print(json.dumps(dict(output=str(args.output), sha256=sha(raw), bytes=len(raw),
        current_counts=report["current_counts"], changed_tables=report["changed_tables"],
        previous_map_package_mismatches=len(report["package_comparison"]["previous_packages_without_identical_current_bytes"]),
        additional_current_map_packages=len(report["package_comparison"]["additional_current_selected_packages"]))))


if __name__ == "__main__":
    main()
