"""Summarize bounded current resource and backend contract research."""
import argparse
import hashlib
import json
from pathlib import Path

from google.protobuf.descriptor_pb2 import FileDescriptorSet
from research_updated_content_table_diff import ROOT


def read(path):
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def derive():
    protocol = ROOT / "outputs/df-local-server/protocol"
    evidence = ROOT / "work/evidence"
    recovery, recovery_sha = read(protocol / "generated_codec_fields.json")
    current_editor, editor_sha = read(evidence / "research_updated_content_lua_activity_editor_79fb7b10_v1.json")
    actual = current_editor["sources"][0]
    if actual["current_sha256"] != "279087d858cce5cf2fe3779e17e7dc1fc50fe0ed805e78014475310e2bda6cad":
        raise ValueError("Current activity editor bytes changed")
    descriptor_raw = (protocol / "candidate_business.pb").read_bytes()
    descriptor = FileDescriptorSet()
    descriptor.ParseFromString(descriptor_raw)
    available = {m.name for f in descriptor.file for m in f.message_type}
    messages = {r["name"]: r for r in recovery["messages"]}
    roots = {"ActivityInfo", "CSActivityGetRes", "CSActivityPropExchangeRes"}
    todo, visited, missing = list(roots), set(), set()
    while todo:
        name = todo.pop()
        if name in visited:
            continue
        visited.add(name)
        row = messages.get(name)
        if row is None:
            missing.add(name)
            continue
        todo.extend(f["nested_type"] for f in row["fields"] if f["nested_type"])
    requests = ["CSActivityExchangeReq", "CSActivityPropExchangeReq", "CSActivityGetCurrencyReq",
        "CSActivityGetBannersReq", "CSActivityFocusExchangeReq", "CSActivityChangeExchangePlanReq"]
    server = ROOT / "outputs/df-local-server/dfserver"
    occurrences = {name: [] for name in requests}
    for path in server.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for name in requests:
            if name in text:
                occurrences[name].append(str(path.relative_to(ROOT)))
    lua, lua_sha = read(evidence / "research_updated_content_lua_79fb7b10_v1.json")
    consumers = []
    focus = {"@ActivityServer_Base.lua": {"0.33", "0.33.0", "0.88", "0.100", "0.102", "0.102.0"},
        "@ActivityUniversalExchangeTemplatePanel.lua": {"0.16"}, "@ActivityExchangeMall.lua": {"0.4", "0.5"}}
    for source in lua["sources"]:
        for function in source["functions"]:
            if function["function_id"] in focus.get(source["source_name"], set()):
                consumers.append(dict(source=source["source_name"], sha256=source["current_sha256"],
                    archive=source["archive"], entry_offset=source["entry_offset"], function=function))
    diff, diff_sha = read(evidence / "research_updated_content_gameitem_diff_79fb7b10_v2.json")
    raven, raven_sha = read(evidence / "research_updated_content_raven_79fb7b10_v4.json")
    return dict(kind="updated_content_backend_gap_research", process_accessed=False,
        runtime_modified=False, game_files_modified=False,
        sources=dict(current_activity_editor=dict(evidence_sha256=editor_sha, actual_lua=actual["current_sha256"]),
            paired_codec_metadata_sha256=recovery_sha, candidate_descriptor_sha256=hashlib.sha256(descriptor_raw).hexdigest(),
            current_lua_consumers_sha256=lua_sha, current_catalog_comparison_sha256=diff_sha,
            current_raven_research_sha256=raven_sha),
        descriptor_gap=dict(missing_dependency_types=sorted(missing), omitted_roots=sorted(roots - available),
            existing_observed_empty_only_pattern="dfserver/gateway/candidate_schema.py EMPTY_ONLY_TYPES and compile_candidate_descriptors opaque entry path",
            current_source_functions=[f for f in actual["functions"] if f["function_id"] in {"0.16", "0.17"}]),
        absent_runtime_request_identifiers=occurrences,
        existing_bootstrap_only="dfserver/gateway/handshake_diagnostic.py:3165 returns CSActivityGetRes result=0 only",
        consumers=consumers,
        current_catalog_comparison=dict(gameitem_rows=diff["extracted_source"]["row_count"],
            added=len(diff["current_ids_absent_from_catalog"]), absent=len(diff["catalog_ids_absent_from_current"]),
            changed=len(diff["changed_existing_rows"]),
            preset_changed=len(diff["preset_comparison"]["changed_rows"]),
            preset_absent=len(diff["preset_comparison"]["catalog_ids_absent_from_current"])),
        qualified_localized_items={i:r for i,r in raven["qualified_gameitem_rows"].items()
            if i in {"28020240007", "13460040096", "15200000281", "13050000425", "13560000002", "13120000393"}},
        unresolved=["Exact active CSActivityGetRes server-provided event IDs and exchange rows",
            "Trickster currency identifier, exchange identifiers, costs, limits and reward counts",
            "Original server Raven roll weights and token award rules",
            "Native Raven interaction request and result replication acceptance"],
        next_scoped_patch=[
            "Source-pin and enforce an opaque empty-only ActivityObjectiveConditions_ExtConditionsEntry, matching the existing descriptor pattern; reject all populated occurrences",
            "Export source-qualified Raven holiday, cluster and drop-mapping configuration as a separate catalog with all source hashes and offsets",
            "Implement activity balances and transactional exchange handlers only after exact active event rows are recovered; do not substitute Raven HolidayId for ActivityInfo.actv_id",
            "Preserve currently equal GameItem and preset mappings; retain IsModelOnly for 13120000393"],
        official_context_url="https://steamcommunity.com/app/2507950/announcements/?l=schinese")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / "work/evidence"):
        parser.error("Fresh research evidence required")
    report = derive()
    raw = (json.dumps(report, ensure_ascii=True, indent=2) + "\n").encode("ascii")
    with args.output.open("xb") as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(args.output), sha256=hashlib.sha256(raw).hexdigest(),
        missing=report["descriptor_gap"]["missing_dependency_types"],
        request_occurrences=report["absent_runtime_request_identifiers"])))
