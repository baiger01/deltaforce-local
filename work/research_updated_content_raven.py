"""Read the exact Raven exchange component and linked client configuration."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zlib

from bundle_asset_locations_package import package
from extract_operator_avatar_catalog import fname, tags
from extract_game_item_catalog import scalar
from recover_economy_pak_access import fstring, installed_name_map
from research_updated_content_table_diff import ROOT, table

BASE = ROOT / "work/evidence/research_updated_content_assets_79fb7b10"
CONTENT = BASE / "pak-0-0-pakchunk2-WindowsClient/DeltaForce/Content"
RAVEN = BASE / "pak-0-1-pakchunk80-WindowsClient/DeltaForce/Content/BluePrints/Interact/SingleItemContainer/BP_Interactor_SingleItemContainer_HalloweenRaven"
WITNESSES = {
    "research_updated_content_tables_79fb7b10_v1.json": "8d291a8d6c55acad0cb7106957c0e8ea495fb9f9295d80451e8753744e61a8f5",
    "research_updated_content_activity_sources_79fb7b10_v1.json": "4120f55fecdee5177a1db5fc1251728593d6a6a382c0a2b3a8f9bc0122bb9e9e",
    "research_updated_content_raven_linked_sources_79fb7b10_v1.json": "1d82724634c2a01bd9a2100f77f2848a70ca1e47d96639abd104e74b982e5ce4",
}


def string_table(path):
    source = path.read_bytes()
    at, chunks = 0, []
    while at < len(source):
        magic, block, stored, size, compressed, output = struct.unpack_from("<6Q", source, at)
        if magic != 0x9e2a83c1 or block != 131072 or compressed != stored or output != size or not 0 < size <= block:
            raise ValueError("String-table compression extent changed")
        decoder = zlib.decompressobj()
        raw = decoder.decompress(source[at + 48:at + 48 + stored], size + 1)
        if len(raw) != size or not decoder.eof or decoder.unused_data:
            raise ValueError("String-table decompression failed")
        chunks.append(raw)
        at += 48 + stored
    data = b"".join(chunks)
    name, at = fstring(data, 8)
    count = struct.unpack_from("<I", data, at)[0]
    at += 4
    rows = {}
    for _ in range(count):
        start = at
        key, at = fstring(data, at)
        text, at = fstring(data, at)
        at += 4
        if key in rows:
            raise ValueError("Duplicate localization key")
        rows[key] = dict(text=text, decoded_offset=start)
    if data[at:] != bytes(8):
        raise ValueError("Unexpected localization trailer")
    return dict(source_sha256=hashlib.sha256(source).hexdigest(), decoded_sha256=hashlib.sha256(data).hexdigest(),
        table=name, rows=rows)


def value(data, tag, names):
    result = scalar(data, tag, names)
    at = tag["value_start"]
    if result is not None:
        return result
    if tag["kind"] in ("Int64Property", "UInt32Property"):
        return struct.unpack_from("<q" if tag["kind"] == "Int64Property" else "<I", data, at)[0]
    if tag["kind"] == "ArrayProperty" and tag["meta"][0] in ("UInt64Property", "IntProperty", "UInt32Property", "NameProperty"):
        count = struct.unpack_from("<I", data, at)[0]
        kind = tag["meta"][0]
        stride = 8 if kind in ("UInt64Property", "NameProperty") else 4
        if 4 + count * stride != tag["size"]:
            raise ValueError("Array extent changed")
        return ([fname(data, at + 4 + i * 8, names) for i in range(count)] if kind == "NameProperty"
            else list(struct.unpack_from("<" + str(count) + ("Q" if kind == "UInt64Property" else "I" if kind == "UInt32Property" else "i"), data, at + 4)))
    if tag["kind"] == "StructProperty":
        nested, end = tags(data, at, names, tag["end"])
        if end != tag["end"]:
            return dict(unparsed_struct=tag["meta"], bytes=tag["size"])
        return {t["name"]: dict(value=value(data, t, names), value_offset=t["value_start"]) for t in nested}
    return dict(unparsed_type=tag["kind"], meta=tag["meta"], bytes=tag["size"])


def configuration_table(path):
    h, b = path.with_suffix(".uasset").read_bytes(), path.with_suffix(".uexp").read_bytes()
    names = installed_name_map(h)
    _, at = tags(b, 0, names, len(b))
    count = struct.unpack_from("<i", b, at + 4)[0]
    at += 8
    rows = []
    for _ in range(count):
        start = at
        name = fname(b, at, names)
        ps, at = tags(b, at + 8, names, len(b))
        rows.append(dict(row=name, serialized_row_offset=start,
            fields={t["name"]: dict(value=value(b, t, names), serialized_value_offset=t["value_start"]) for t in ps}))
    if b[at:] != bytes.fromhex("c1832a9e"):
        raise ValueError("Unexpected linked configuration trailer")
    return dict(uasset_sha256=hashlib.sha256(h).hexdigest(), uexp_sha256=hashlib.sha256(b).hexdigest(), rows=rows)


def derive():
    for name, digest in WITNESSES.items():
        witness = (ROOT / "work/evidence" / name).read_bytes()
        if hashlib.sha256(witness).hexdigest() != digest:
            raise ValueError("Pinned current resource extraction witness changed")
        for archive in json.loads(witness)["archives"]:
            for source in archive["matches"]:
                raw = (ROOT / source["output"]).read_bytes()
                if hashlib.sha256(raw).hexdigest() != source["decoded_sha256"]:
                    raise ValueError("Extracted bytes differ from current installed witness")
    h, b = RAVEN.with_suffix(".uasset").read_bytes(), RAVEN.with_suffix(".uexp").read_bytes()
    pkg = package(h)
    eo = struct.unpack_from("<i", h, 61 + struct.unpack_from("<i", h, 20)[0] * 20)[0]
    component = pkg["exports"][8]
    if component["class"] != "InteractorContainerReplaceComponent" or component["outer"] != 1:
        raise ValueError("Exact Raven replacement component identity changed")
    size, offset = struct.unpack_from("<qq", h, eo + 8 * 104 + 28)
    offset -= len(h)
    props, end = tags(b, offset, pkg["names"], offset + size)
    keep = {"MapInCluster2OutPool", "SpecialItemIds", "HighValueRewardItemIds", "HolidayIds", "bUseMainTable", "ProtectSeconds"}
    selected = {t["name"]: dict(value=value(b, t, pkg["names"]), serialized_value_offset=t["value_start"],
        kind=t["kind"], metadata=t["meta"]) for t in props if t["name"] in keep}
    path = CONTENT / "R13N/Common/Base/DataTables/ItemExchangeActivityTable"
    th, tb = path.with_suffix(".uasset").read_bytes(), path.with_suffix(".uexp").read_bytes()
    names = installed_name_map(th)
    _, at = tags(tb, 0, names, len(tb))
    count = struct.unpack_from("<i", tb, at + 4)[0]
    at += 8
    exchange = []
    for _ in range(count):
        start = at
        row = fname(tb, at, names)
        fields, at = tags(tb, at + 8, names, len(tb))
        parsed = {t["name"]: dict(value=value(tb, t, names), serialized_value_offset=t["value_start"]) for t in fields}
        if parsed["HolidayId"]["value"] in selected["HolidayIds"]["value"]:
            exchange.append(dict(row=row, serialized_row_offset=start, fields=parsed))
    loc = string_table(CONTENT / "StringTables/STForDataTable/Common/Base/LOC_GameItem.ustbin")
    items = table(CONTENT / "R13N/Common/Base/DataTables/GameItem")
    identifiers = set(selected["HighValueRewardItemIds"]["value"])
    identifiers.update(p["value"] for p in selected["SpecialItemIds"]["value"].values() if isinstance(p["value"], int))
    for row in exchange:
        identifiers.update(row["fields"]["LuckySkuIds"]["value"])
    terms = re.compile("HVK|乌鸦|捣蛋|南瓜|糖果|惊喜|阿萨拉恶灵|嘎嘎|花小蝶")
    localized = {key: r for key, r in loc["rows"].items() if terms.search(r["text"]) or any(key.startswith(str(i) + "_") for i in identifiers)}
    identifiers.update(int(k.split("_")[0]) for k in localized if k.endswith("_Name") and k.split("_")[0].isdigit())
    item_rows = {str(i): dict(items["rows"][str(i)], localized_name=loc["rows"].get(str(i) + "_Name"))
        for i in sorted(identifiers) if str(i) in items["rows"]}
    clusters = configuration_table(CONTENT / "R13N/Common/Base/DataTables/ItemsClusterTable")
    mappings = configuration_table(CONTENT / "R13N/Common/Base/DataTables/SkuDropMappingTable")
    cluster_ids = {i for r in exchange for i in r["fields"]["ClusterIdList"]["value"]}
    mapping_ids = {i for r in exchange for i in r["fields"]["DropMappingIdList"]["value"]}
    clusters["rows"] = [r for r in clusters["rows"] if r["fields"]["ClusterID"]["value"] in cluster_ids]
    mappings["rows"] = [r for r in mappings["rows"] if r["fields"]["DropMappingId"]["value"] in mapping_ids]
    tips = string_table(CONTENT / "StringTables/STForMaps/Common/Base/LOC_MAPS_OtherBP.ustbin")
    raven_tips = {k:r for k,r in tips["rows"].items() if "HalloweenRaven" in k}
    return dict(kind="updated_client_raven_and_equipment_source_research",
        extraction_witnesses=WITNESSES,
        actor=dict(package=pkg["own_paths"], uasset_sha256=hashlib.sha256(h).hexdigest(),
            uexp_sha256=hashlib.sha256(b).hexdigest(), component_export=9, component=component,
            component_uexp_offset=offset, component_size=size, fields=selected),
        exchange_table=dict(path="/Game/R13N/Common/Base/DataTables/ItemExchangeActivityTable",
            uasset_sha256=hashlib.sha256(th).hexdigest(), uexp_sha256=hashlib.sha256(tb).hexdigest(),
            linked_rows=exchange),
        linked_clusters=clusters, linked_drop_mappings=mappings,
        raven_localization_source={k:v for k,v in tips.items() if k != "rows"}, raven_tips=raven_tips,
        localization_source={k:v for k,v in loc.items() if k != "rows"}, localization_matches=localized,
        qualified_gameitem_rows=item_rows,
        ids_are_client_configuration_only=True, server_activity_ids_or_store_prices_qualified=False,
        original_server_random_selection_or_drop_rates_qualified=False, runtime_catalog_modified=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / "work/evidence"):
        parser.error("Fresh research evidence required")
    report = derive()
    raw = (json.dumps(report, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    with args.output.open("xb") as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(args.output), sha256=hashlib.sha256(raw).hexdigest(),
        holiday_ids=report["actor"]["fields"]["HolidayIds"]["value"],
        linked_rows=len(report["exchange_table"]["linked_rows"]),
        qualified_item_ids=list(report["qualified_gameitem_rows"]))))
