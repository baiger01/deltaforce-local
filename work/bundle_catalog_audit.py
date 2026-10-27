"""Audit recovered premium tables and reward references without changing catalogs."""

from collections import Counter, defaultdict
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

from extract_cosmetic_catalogs import export, PAK, PROTOCOL
from explore_game_item import UASSET, UEXP, name_map
from explore_tagged_export import read_row
from extract_game_item_catalog import scalar
from extract_operator_avatar_catalog import tags
from extract_premium_shop_catalog import items, string

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "outputs/df-local-server"))
from dfserver import premium_shop

RECOMMENDATION_FIELDS = {
    301: "tab_id", 259: "banner_type", 296: "SortIndex",
    261: "bundle_currency_type", 267: "bundle_price", 263: "disbundle_price",
    262: "bundle_item_list", 282: "jump_to", 274: "IamgeSourceSmall_CDN",
    272: "IamgeSourceBig_CDN", 276: "ImageSourceLogo_CDN_CN",
    277: "ImageSourceLogo_CDN_EN", 273: "preview_asset",
    271: "native_big_asset", 275: "native_logo_asset", 281: "items_sort_index_text",
    304: "additional_resource_references",
}
GIFT_FIELDS = {
    77: "goods_id", 78: "goods_type", 103: "Sortindex", 69: "currency_type",
    98: "price", 99: "price_pre_dis", 85: "is_cash", 89: "limit_type",
    88: "limit_amount", 73: "midas_product_id", 74: "google_item_id",
    86: "bundle_item_list", 95: "online_time_text", 94: "offline_time_text",
    80: "native_banner_asset", 87: "items_sort_index_text",
}

SOURCE_RESOURCE_NAMES = {
    "recommendations": {273: "IamgeSourceSmall", 271: "IamgeSourceBig",
        275: "ImageSourceLogo", 281: "ItemsSortIndex"},
    "gifts": {80: "IamgeSource", 87: "ItemsSortIndex"},
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fstring(raw):
    if len(raw) < 4:
        return None
    length = struct.unpack_from("<i", raw)[0]
    if length == 0 and len(raw) == 4:
        return {"kind": "FString", "text": "", "encoding": "empty"}
    if length > 0 and len(raw) == 4 + length and raw[-1:] == b"\0":
        try:
            return {"kind": "FString", "text": raw[4:-1].decode("utf-8"), "encoding": "utf-8"}
        except UnicodeDecodeError:
            return None
    if length < 0 and len(raw) == 4 - length * 2 and raw[-2:] == b"\0\0":
        try:
            return {"kind": "FString", "text": raw[4:-2].decode("utf-16le"), "encoding": "utf-16le"}
        except UnicodeDecodeError:
            return None
    return None


def raw_rows(entry):
    parsed, source = export(entry)
    data = (ROOT / "work/evidence/matched_assets" / f"{PAK}.entry-{entry}.bin").read_bytes()
    none_offset = 29 if struct.unpack_from("<i", data, 37)[0] == 0 else 55
    none = struct.unpack_from("<i", data, none_offset)[0]
    layout = {}
    result = []
    for row in parsed:
        tagged, end, recovered_layout = read_row(data, row["offset"] + 8, none, known_types=layout)
        layout = dict(recovered_layout)
        fields = {}
        for tag in tagged:
            raw = data[tag["value_start"]:tag["end"]]
            decoded = fstring(raw) if tag["kind"] == (299 if entry == 7142 else 106) else None
            fields[tag["field"]] = {
                "tag_offset": tag["offset"], "value_offset": tag["value_start"],
                "size": tag["size"], "kind_index": tag["kind"],
                "metadata_bytes": tag["metadata_bytes"], "raw_hex": raw.hex(),
                "raw_sha256": sha(raw), "scalar": row["fields"][tag["field"]],
                **(decoded or {}),
            }
            if decoded is None and tag["field"] in (258, 76):
                fields[tag["field"]]["localization_key"] = [
                    v.decode("ascii") for v in re.findall(rb"[0-9]+_(?:BannerName|GiftName)\0", raw)]
        result.append({"row": row["row"], "offset": row["offset"], "end_offset": end,
                       "row_sha256": sha(data[row["offset"]:end]), "fields": fields})
    return result, source


def flatten_item_ids(bundle):
    return [p["id"] for item in bundle for p in (item.get("item_list") or [item])]


def field_stats(rows):
    stats = {}
    for index in sorted({k for row in rows for k in row["fields"]}):
        fs = [row["fields"][index] for row in rows if index in row["fields"]]
        strings = [f for f in fs if f.get("kind") == "FString"]
        texts = [f["text"] for f in strings if f["text"]]
        stats[index] = {"rows_present": len(fs), "sizes": dict(Counter(f["size"] for f in fs)),
            "decoded_fstrings": len(strings), "nonempty_fstrings": len(texts),
            "fstring_encodings": dict(Counter(f["encoding"] for f in strings)),
            "asset_reference_count": sum(t.startswith("Texture2D'") for t in texts),
            "sample_nonempty_strings": texts[:3],
            "scalar_counts": dict(Counter(str(f["scalar"]) for f in fs if not isinstance(f["scalar"], str)))}
    return stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=PROTOCOL / "premium_shop_catalog.json")
    parser.add_argument("--output", type=Path, default=ROOT / "work/bundle_catalog_audit.json")
    args = parser.parse_args()
    catalog_bytes = args.catalog.read_bytes()
    item_catalog_bytes = (PROTOCOL / "game_item_catalog.json").read_bytes()
    catalog = json.loads(catalog_bytes)
    game_items = json.loads(item_catalog_bytes)["rows"]
    recs, rec_source = raw_rows(7142)
    gifts, gift_source = raw_rows(7156)
    exported_rec = {r["tab_id"]: r for r in catalog["recommendations"]}
    exported_gift = {r["goods_id"]: r for r in catalog["gifts"]}
    all_exposed = set(premium_shop.RECOMMENDATIONS) | set(premium_shop.PROMOTIONS)
    source_mismatches = []
    uses = defaultdict(set)
    known_fstring_failures = []
    for category, rows, exported, id_field, mapped in (
        ("recommendations", recs, exported_rec, 301, RECOMMENDATION_FIELDS),
        ("gifts", gifts, exported_gift, 77, GIFT_FIELDS),
    ):
        for row in rows:
            row_id = row["fields"][id_field]["scalar"]
            row["id"] = row_id
            out = exported.get(row_id)
            row["exposed"] = row_id in (all_exposed if category == "recommendations" else premium_shop.GIFTS)
            row["exported"] = out
            row["omitted_fields"] = sorted(set(row["fields"]) - set(mapped))
            row["reward_ids"] = flatten_item_ids(out["bundle_item_list"])
            for key in ("row", "offset"):
                if out.get(key) != row[key]:
                    source_mismatches.append({"category":category,"id":row_id,"target":key,
                                              "source":row[key],"exported":out.get(key)})
            for item_id in row["reward_ids"]:
                uses[item_id].add(f"{category}:{row_id}")
            for field, target in mapped.items():
                raw_value = row["fields"][field]["scalar"]
                if target == "bundle_item_list":
                    actual = items(raw_value, category == "recommendations")
                elif target == "additional_resource_references":
                    actual = [{"field_index": field, "value": string(raw_value)}] if raw_value else []
                elif row["fields"][field].get("kind") == "FString":
                    try:
                        actual = string(raw_value)
                    except (ValueError, UnicodeDecodeError) as exc:
                        known_fstring_failures.append({"category":category,"id":row_id,"field":field,"error":str(exc)})
                        actual = row["fields"][field]["text"]
                elif raw_value == 0 and target in ("jump_to", "preview_asset", "online_time_text", "offline_time_text",
                    "midas_product_id", "google_item_id", "IamgeSourceSmall_CDN", "IamgeSourceBig_CDN",
                    "ImageSourceLogo_CDN_CN", "ImageSourceLogo_CDN_EN", "native_big_asset",
                    "native_logo_asset", "native_banner_asset", "items_sort_index_text"):
                    actual = ""
                else:
                    actual = raw_value
                if out.get(target) != actual:
                    source_mismatches.append({"category":category,"id":row_id,"field":field,"target":target,
                                              "source":actual,"exported":out.get(target),"field_present":target in out})
            if category == "recommendations":
                f = row["fields"]
                row["filter_reasons"] = []
                if not out["bundle_item_list"]:
                    row["filter_reasons"].append("no_bundle_rewards")
                if not (out["preview_asset"] or out["IamgeSourceSmall_CDN"]):
                    row["filter_reasons"].append("no_native_small_asset_or_small_cdn")
                unsupported = sorted({p for p in row["reward_ids"] if str(p).startswith(("280","281"))
                    and p not in premium_shop.gun_skins.SKINS and p not in premium_shop.MELEE_SKINS})
                if unsupported:
                    row["filter_reasons"].append("unrecovered_skin_mapping")
                    row["unsupported_skin_ids"] = unsupported
                native_small = f[273].get("text", "")
                cdn_small = f[274].get("text", "")
                row["resource_profile"] = "native_and_cdn" if native_small and cdn_small else "native_only" if native_small else "cdn_only" if cdn_small else "empty"
                row["confirmed_melee_ids"] = sorted(set(row["reward_ids"]) & set(premium_shop.MELEE_SKINS))
                row["cdn_without_extension"] = [i for i in (272,274,276,277) if f[i].get("text") and not re.search(r"\.[A-Za-z0-9]{2,5}$", f[i]["text"])]
            else:
                row["filter_reasons"] = []
                if not (out["is_cash"] or out["currency_type"]):
                    row["filter_reasons"].append("no_cash_or_currency")
                unsupported = sorted({p["id"] for p in out["bundle_item_list"]
                    if game_items.get(str(p["id"]), {}).get("length") and not game_items[str(p["id"])]["is_currency"]})
                if unsupported:
                    row["filter_reasons"].append("warehouse_reward_requires_inventory_grant")
                    row["warehouse_reward_ids"] = unsupported

    for reward in catalog["lottery_rewards"]:
        for prop in reward["props"]:
            uses[prop["id"]].add(f"lottery_rewards:{reward['lottery_id']}:{reward['num_id']}")
    data = UEXP.read_bytes()
    uasset_data = UASSET.read_bytes()
    names = name_map(uasset_data)
    item_rows = {}
    mall_decode_mismatches = []
    for item_id, owners in sorted(uses.items()):
        catalog_row = game_items.get(str(item_id))
        result = {"id": item_id, "used_by": sorted(owners), "in_game_item": catalog_row is not None}
        if catalog_row is not None:
            parsed_tags, end = tags(data, catalog_row["serialized_uexp_offset"] + 8, names, len(data))
            references = {}
            for tag in parsed_tags:
                raw = data[tag["value_start"]:tag["end"]]
                decoded = fstring(raw) if tag["kind"] == "StrProperty" else None
                val = scalar(data, tag, names)
                if tag["name"] == "MallItemIcon" or (isinstance(val, str) and ("/Game/" in val or val.startswith("Resource/"))):
                    references[tag["name"]] = {"property_kind":tag["kind"],"meta":tag["meta"],"size":tag["size"],
                        "value_offset":tag["value_start"],"raw_hex":raw.hex(),"raw_sha256":sha(raw),
                        "value":val,**(decoded or {})}
            result.update({"row_offset":catalog_row["serialized_uexp_offset"], "row_end_offset":end,
                "row_sha256":sha(data[catalog_row["serialized_uexp_offset"]:end]),
                "name_key":catalog_row.get("name_key"), "game_item_type":catalog_row.get("game_item_type"),
                "quality":catalog_row.get("quality"), "is_currency":catalog_row.get("is_currency"),
                "length":catalog_row.get("length"), "width":catalog_row.get("width"),
                "catalog_mall_item_icon":catalog_row.get("mall_item_icon"), "native_references":references})
            icon = references.get("MallItemIcon", {})
            native_text = icon.get("text")
            if native_text and native_text != catalog_row.get("mall_item_icon"):
                mall_decode_mismatches.append({"id":item_id,"source":native_text,"exported":catalog_row.get("mall_item_icon")})
            result["mall_icon_state"] = "source_nonempty" if native_text else "source_empty" if native_text == "" else "not_fstring_or_absent"
        item_rows[str(item_id)] = result

    groups = {}
    def group(name, selected):
        groups[name] = [{"id":r["id"],"row":r["row"],"offset":r["offset"],"row_sha256":r["row_sha256"]} for r in selected]
    group("exposed_recommendation_native_only", [r for r in recs if r["exposed"] and r["resource_profile"] == "native_only"])
    group("exposed_recommendation_native_and_cdn", [r for r in recs if r["exposed"] and r["resource_profile"] == "native_and_cdn"])
    group("exposed_recommendation_cdn_without_extension", [r for r in recs if r["exposed"] and r["cdn_without_extension"]])
    group("unexposed_recommendation_empty_resources", [r for r in recs if not r["exposed"] and r["resource_profile"] == "empty"])
    group("unexposed_recommendation_unsupported_skin", [r for r in recs if not r["exposed"] and "unrecovered_skin_mapping" in r["filter_reasons"]])
    group("unexposed_recommendation_no_bundle", [r for r in recs if not r["exposed"] and "no_bundle_rewards" in r["filter_reasons"]])
    group("source_confirmed_melee_bundles", [r for r in recs if r["confirmed_melee_ids"]])
    group("exposed_gift_native_banner_present", [r for r in gifts if r["exposed"] and r["fields"][80].get("text")])
    group("exposed_gift_native_banner_empty", [r for r in gifts if r["exposed"] and not r["fields"][80].get("text")])
    group("unexposed_gift_no_cash_or_currency", [r for r in gifts if "no_cash_or_currency" in r["filter_reasons"]])
    group("unexposed_gift_inventory_rewards", [r for r in gifts if "warehouse_reward_requires_inventory_grant" in r["filter_reasons"]])
    missing = sorted(item_id for item_id, r in item_rows.items() if not r["in_game_item"])
    report = {"sources":{"recommendations":rec_source,"gifts":gift_source,
        "catalog_path":str(args.catalog),
        "premium_shop_catalog_sha256":sha(catalog_bytes),"game_item_catalog_sha256":sha(item_catalog_bytes),
        "game_item_uasset":str(UASSET),"game_item_uasset_sha256":sha(uasset_data),
        "game_item_uexp":str(UEXP),"game_item_uexp_sha256":sha(data)},
        "counts":{"recommendations":len(recs),"gifts":len(gifts),"exposed_recommendations":len(all_exposed),
            "purchasable_recommendations":len(premium_shop.RECOMMENDATIONS),"promotions":len(premium_shop.PROMOTIONS),
            "exposed_gifts":len(premium_shop.GIFTS),"unique_reward_ids":len(uses),
            "reward_ids_missing_game_item":len(missing),"catalog_source_mismatches":len(source_mismatches),
            "known_fstring_failures":len(known_fstring_failures),"mall_icon_decode_mismatches":len(mall_decode_mismatches),
            "groups":{name:len(rows) for name,rows in groups.items()},
            "mall_icon_states":dict(Counter(r.get("mall_icon_state","missing_game_item") for r in item_rows.values()))},
        "source_mismatches":source_mismatches,"known_fstring_failures":known_fstring_failures,
        "mall_icon_decode_mismatches":mall_decode_mismatches,"missing_game_item_ids":missing,
        "recommendation_fields":field_stats(recs),"gift_fields":field_stats(gifts),
        "mapped_recommendation_fields":RECOMMENDATION_FIELDS,"mapped_gift_fields":GIFT_FIELDS,
        "source_resource_property_names":SOURCE_RESOURCE_NAMES,
        "groups":groups,"recommendations":recs,"gifts":gifts,"reward_items":item_rows,
        "limitations":["Encrypted table name maps are unavailable; field names are only mapped where existing extractor/client proof exists.",
            "Resource references establish source strings, not mounted package presence or runtime load success.",
            "Empty MallItemIcon is a source fact and may use native category icon fallback.",
            "Native launch, HTTP requests and installed game writes were not performed."]}
    output = args.output
    output.write_text(json.dumps(report,ensure_ascii=True,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report["counts"],ensure_ascii=True,indent=2))
    print("output", output)
    if source_mismatches or known_fstring_failures or mall_decode_mismatches:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
