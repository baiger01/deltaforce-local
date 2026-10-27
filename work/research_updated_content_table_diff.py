"""Compare exact current GameItem rows to the existing source-qualified catalog."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

from extract_operator_avatar_catalog import fname, tags
from extract_game_item_catalog import scalar
from recover_economy_pak_access import installed_name_map, installed_table_package_identity

ROOT = Path(__file__).resolve().parent.parent
WITNESS = ROOT / "work/evidence/research_updated_content_tables_79fb7b10_v1.json"
WITNESS_SHA = "8d291a8d6c55acad0cb7106957c0e8ea495fb9f9295d80451e8753744e61a8f5"
CATALOG = ROOT / "outputs/df-local-server/protocol/game_item_catalog.json"
FIELDS = {
    "ItemID": "id", "Name": "name_key", "GameItemType": "game_item_type", "Quality": "quality",
    "Material": "material", "MaxStackCount": "max_stack_count", "Length": "length", "Width": "width",
    "Weight": "weight", "CanStoreInSafeBox": "can_store_in_safe_box", "IsCurrency": "is_currency",
    "IsModelOnly": "is_model_only", "bValuableItem": "valuable_item",
    "bHighValueItemNeedInspection": "high_value_needs_inspection", "RecycleMoney": "recycle_currency_id",
    "RecyclePrice": "recycle_price", "InitialGuidePrice": "initial_guide_price", "MallItemIcon": "mall_item_icon",
}


def table(stem):
    header, data = stem.with_suffix(".uasset").read_bytes(), stem.with_suffix(".uexp").read_bytes()
    identity = installed_table_package_identity(header)
    names = installed_name_map(header)
    h, at = tags(data, 0, names, len(data))
    if not any(t["name"] == "RowStruct" for t in h) or struct.unpack_from("<i", data, at)[0] != 0:
        raise ValueError("Qualified DataTable header required")
    count = struct.unpack_from("<i", data, at + 4)[0]
    at += 8
    rows = {}
    for _ in range(count):
        offset = at
        name = fname(data, at, names)
        props, at = tags(data, at + 8, names, len(data))
        if name in rows:
            raise ValueError("Duplicate current table row")
        rows[name] = dict(serialized_uexp_offset=offset,
            fields={t["name"]: (fname(data, t["value_start"], names)
                if t["kind"] == "SoftObjectProperty" and t["size"] == 12
                else scalar(data, t, names)) for t in props},
            serialized_row_sha256=hashlib.sha256(data[offset:at]).hexdigest())
    if data[at:] != bytes.fromhex("c1832a9e"):
        raise ValueError("Unparsed current DataTable bytes")
    return dict(identity=identity, uasset_sha256=hashlib.sha256(header).hexdigest(),
        uexp_sha256=hashlib.sha256(data).hexdigest(), row_count=count, rows=rows)


def derive():
    witness_raw = WITNESS.read_bytes()
    if hashlib.sha256(witness_raw).hexdigest() != WITNESS_SHA:
        raise ValueError("Current extraction witness changed")
    witness = json.loads(witness_raw)
    assets = [r for a in witness["archives"] for r in a["matches"]]
    for a in assets:
        if hashlib.sha256((ROOT / a["output"]).read_bytes()).hexdigest() != a["decoded_sha256"]:
            raise ValueError("Current extraction payload differs from its witness")
    raw = CATALOG.read_bytes()
    catalog = json.loads(raw)
    item, = [a for a in assets if a["asset"].endswith("/GameItem.uasset")]
    parsed = table((ROOT / item["output"]).with_suffix(""))
    new_ids, old_ids = set(parsed["rows"]), set(catalog["rows"])
    new_rows = {}
    changed_rows = {}
    for ident, row in parsed["rows"].items():
        fields = row["fields"]
        normalized = {target: fields[source] for source, target in FIELDS.items() if source in fields}
        if normalized.get("id") != ident:
            raise ValueError("Current GameItem ItemID differs from row name")
        if ident not in old_ids:
            new_rows[ident] = dict(row, normalized=normalized)
        else:
            changes = {key: dict(catalog=catalog["rows"][ident].get(key), current=value)
                for key, value in normalized.items() if catalog["rows"][ident].get(key) != value}
            if changes:
                changed_rows[ident] = dict(serialized_uexp_offset=row["serialized_uexp_offset"], changes=changes)
    preset_raw = (ROOT / "outputs/df-local-server/protocol/weapon_preset_catalog.json").read_bytes()
    preset_catalog = json.loads(preset_raw)
    preset_asset, = [a for a in assets if a["asset"].endswith("/RecFunctionTable.uasset")]
    presets = table((ROOT / preset_asset["output"]).with_suffix(""))
    preset_fields = {"RecFunctionId": "receiver_id", "DefaultPreset": "default_preset_id",
        "MPDefaultPreset": "mp_default_preset_id", "BPClass": "bp_class",
        "IsBaseModel": "is_base_model", "IsBaseWeapon": "is_base_weapon"}
    preset_changes = {}
    for ident, row in presets["rows"].items():
        normalized = {target: row["fields"][source] for source, target in preset_fields.items()}
        old = preset_catalog["rows"].get(ident)
        if normalized != old:
            preset_changes[ident] = dict(current=normalized, catalog=old, serialized_uexp_offset=row["serialized_uexp_offset"])
    return dict(kind="updated_current_gameitem_catalog_comparison",
        extracted_source={k:v for k,v in parsed.items() if k != "rows"},
        extraction_witness_sha256=WITNESS_SHA, catalog_sha256=hashlib.sha256(raw).hexdigest(),
        catalog_source={k:v for k,v in catalog.items() if k != "rows"},
        current_ids_absent_from_catalog=new_rows,
        catalog_ids_absent_from_current=sorted(old_ids - new_ids),
        changed_existing_rows=changed_rows,
        new_id_counts_by_type=dict(Counter(r["fields"].get("GameItemType") for r in new_rows.values())),
        new_id_status="Absent from current local catalog; not proof newly released in this update",
        preset_comparison=dict(source={k:v for k,v in presets.items() if k != "rows"},
            catalog_sha256=hashlib.sha256(preset_raw).hexdigest(), catalog_row_count=preset_catalog["row_count"],
            changed_rows=preset_changes, catalog_ids_absent_from_current=sorted(set(preset_catalog["rows"]) - set(presets["rows"]))),
        runtime_catalog_modified=False, native_acceptance_verified=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / "work/evidence"):
        parser.error("Fresh research evidence path required")
    report = derive()
    raw = (json.dumps(report, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    with args.output.open("xb") as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(args.output), sha256=hashlib.sha256(raw).hexdigest(),
        current_rows=report["extracted_source"]["row_count"],
        catalog_rows=report["catalog_source"]["row_count"],
        added_to_catalog_candidates=len(report["current_ids_absent_from_catalog"]),
        absent_current=len(report["catalog_ids_absent_from_current"]),
        changed=len(report["changed_existing_rows"]),
        types=report["new_id_counts_by_type"])))
