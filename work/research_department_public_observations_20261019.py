"""Record reviewed public client observations without filling unknown config rows."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "work/evidence/department-public-observations-20261019"
SCREENSHOTS = ROOT.parent / "output/playwright"


def describe(path: Path) -> dict:
    data = path.read_bytes()
    return {
        "path": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def fetch(url: str, name: str) -> dict:
    target = OUT / name
    if not target.exists():
        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(request, timeout=30) as response:
            target.write_bytes(response.read())
    return {"url": url, **describe(target)}


def capture(name: str) -> dict:
    source = SCREENSHOTS / name
    target = OUT / name
    shutil.copy2(source, target)
    return {"capture_method": "Public browser video element screenshot", **describe(target)}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    contract_path = ROOT / "work/evidence/reputation-department-contract-witnesses-20261019.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    role = contract["sources"]["RoleInfoServer.lua"]
    panel = contract["sources"].get("PrestigeUsagePanel.lua")
    report = {
        "scope": "Read-only public pages and native gameplay recorded by their publishers; no accounts or game processes used.",
        "full_curve_recovered": False,
        "observed_transition_scores": [
            {"level": 1, "next_level": 2, "score": None, "status": "unrecovered"},
            {"level": 2, "next_level": 3, "score": 30, "status": "reviewed_recorded_native_client_frame"},
            {"level": 3, "next_level": 4, "score": None, "status": "unrecovered"},
        ],
        "terminal_level_config_score": None,
        "terminal_score_reason": "MAX presentation does not expose the final RepLevelConfig.score. Do not fill it with a protobuf default.",
        "numeric_observations": [
            {
                "page": "https://www.taptap.cn/moment/633848456032554940",
                "title": "Why cannot I upgrade despite my combat department reputation reaching level 2?",
                "published_date": "2025-01-29",
                "publisher": "TapTap user, not game publisher",
                "evidence_type": "Primary observation of recorded mainland native client UI, not the author's textual claim",
                "video_id_in_public_page": 4720192,
                "video_duration_seconds": 21.899251,
                "frame_seconds": 18.0,
                "department_in_frame": "Tactical Warfare Unit / mainland tactical department",
                "readout": {"current_level": 2, "current_level_progress": 2, "score_denominator": 30, "preview_level": 3},
                "interpretation": "The popup shows current level 2, 2/30 progress, and level 3 purchase unlock preview.",
                "limits": "This is a historical recorded version; no claim that it is the current installed server configuration.",
                "still": capture("department-primary-taptap-feedback-18.png"),
            }
        ],
        "max_level_observations": [],
        "original_client_contract": {
            "source_report": describe(contract_path),
            "client_contract": contract["client_contract"],
            "RoleInfoServer.lua": {
                **{key: role[key] for key in ("pak", "entry", "pak_offset", "sha256", "size")},
                "functions": {key: value for key, value in role["functions"].items() if key in {"0.58", "0.58.0", "0.65", "0.66", "0.67", "0.68", "0.69", "0.70"}},
            },
            "PrestigeUsagePanel.lua": panel,
            "score_scope": "RoleInfoServer stores one repLevelConfigs array from CSAttributeGetConfigRes; lookup takes level, without a card ID. GetPrestigeCurValueAndScoreById supplies the selected card's level to that shared lookup.",
        },
        "rejected_numeric_substitutes": [
            "Unverified third-party guide prose claiming 20/30/30",
            "Department overview showing LV.4 without MAX, which establishes only a lower bound",
            "Behavior reputation Reputation/ReputationStar tables, unrelated to department repLevelConfigs",
            "Protobuf field default zero, which is not an authentic fourth config row",
        ],
        "official_public_website_research": {
            "wiki": "https://www.playdeltaforce.com/act/officialwiki/",
            "saved_report": "work/evidence/official-public-curve-20261019/report.json",
            "result": "Published no-login config.list and all eight place.list facility categories expose facility conditions but no department curve.",
            "official_garena_guide": "https://deltaforce.garena.com/en/news/system/RMDWVM",
            "official_garena_guide_date": "2026-02-20",
            "linked_department_video": "https://www.youtube.com/watch?v=9iSjVZjchoE&t=441s",
            "result_video": "Reviewed department segment; normal task and department pages show levels and progress bars without numeric denominator.",
            "official_taptap_guide": "https://www.taptap.cn/moment/558219402227486498",
            "official_taptap_guide_date": "2024-07-05",
            "result_official_taptap": "Overview image shows all five LV4; no MAX or numeric score denominator.",
        },
    }
    max_sources = [
        ("tactical", "2025-10-31", "nb19d75e51c33", "225975873/rectangle_large_type_2_4766e04180742b8256ef4c6044331602.png?fit=bounds&quality=85&width=1280"),
        ("combat", "2025-11-03", "n57db690467b5", "226702976/rectangle_large_type_2_6f5b2b5265f97dfd49fa83dcab97b5b9.png?width=1280"),
        ("medical", "2025-11-03", "neb8ec91bc1fb", "226737825/rectangle_large_type_2_f00d880c43d3f6b9ef624d01c84fc237.png?fit=bounds&quality=85&width=1280"),
        ("logistics", "2025-11-30", "n7331fcaf45f0", "226768265/rectangle_large_type_2_477c5311fb0a0b69af60578442c108c5.png?width=1280"),
        ("research", "2025-11-04", "nf8a9f133a6c5", "227034292/rectangle_large_type_2_acae35f56f4db50d6e5f74ea9974abbf.png?fit=bounds&quality=85&width=1280"),
    ]
    for department, published, slug, image in max_sources:
        report["max_level_observations"].append({
            "department": department,
            "page": f"https://note.com/nothope_nar_2low/n/{slug}",
            "page_published_date": published,
            "date_status": "Page publication date; page can be updated and image capture date is not established",
            "publisher": "Player walkthrough author Low on note.com, not game publisher",
            "region_language": "Japanese international client",
            "status": "visually_reviewed_recorded_native_client_ui",
            "claim_to_review": {"reputation_level": 4, "progress_label": "MAX"},
            "limits": "Does not prove the current mainland server config or the final config score value.",
            "image": fetch("https://assets.st-note.com/production/uploads/images/" + image, f"note-{department}-max-candidate.png"),
        })
    target = OUT / "report.json"
    target.write_text(json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(target), "numeric_observations": len(report["numeric_observations"]), "full_curve_recovered": False}))


if __name__ == "__main__":
    main()
