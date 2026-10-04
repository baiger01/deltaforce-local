"""Inspect local binary/log metadata without printing account or session data."""
from pathlib import Path
import json
import re
import sqlite3

GAME = Path("D:/三角洲/WeGameApps/rail_apps/DeltaForce(2001918)")
OUT = Path(__file__).resolve().parent / "evidence" / "local_metadata.json"
result = {}
log = GAME / "DeltaForce/Saved/Logs/DeltaForce.log"
prefix = log.read_bytes()
if prefix.startswith(b"\xef\xbb\xbf"):
    prefix = prefix[3:]
# The known header phrase 'Log file' produces one consistent XOR byte.
decoded = bytes(b ^ 0x5C for b in prefix)
log_text = decoded.decode("utf-8", errors="replace")
markers = [
    "Build Configuration:", "Engine Version:", "Compatible Engine Version:",
    "Game Name:", "LogInit: Build:", "LogInit: Branch Name:",
]
result["log_decode"] = {
    "method": "candidate single-byte XOR 0x5c, supported by readable header",
    "size": len(prefix),
    "known_header_readable": "Log file" in log_text[:1000],
    "metadata_lines": [line[:400] for line in log_text.splitlines()
                       if any(marker in line for marker in markers)][:20],
    "keyword_counts_only": {term: len(re.findall(re.escape(term), log_text, re.I))
                            for term in ["offline", "standalone", "dedicated", "login",
                                         "inventory", "quest", "WindowsClient"]},
}
snippets = []
for number, line in enumerate(log_text.splitlines(), 1):
    match = re.search(r"standalone|dedicated|offline", line, re.I)
    if not match:
        continue
    if re.search(r"token|ticket|password|openid|account|uin|https?://", line, re.I):
        continue
    snippet = line[max(0, match.start()-100):match.end()+140]
    snippet = re.sub(r"\b[0-9a-fA-F]{24,}\b", "<redacted>", snippet)
    snippet = re.sub(r"\b\d{7,}\b", "<redacted>", snippet)
    if snippet not in [item["snippet"] for item in snippets]:
        snippets.append({"line": number, "snippet": snippet})
result["log_decode"]["mode_snippets"] = snippets[:40]
cache = GAME / "tiny_cache/Game_2001918.db"
with cache.open("rb") as handle:
    header = handle.read(16)
result["cache_db"] = {"path": str(cache), "sqlite_header": header == b"SQLite format 3\0"}
if result["cache_db"]["sqlite_header"]:
    connection = sqlite3.connect(cache.as_uri() + "?mode=ro", uri=True)
    try:
        result["cache_db"]["tables"] = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    finally:
        connection.close()
OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(result, ensure_ascii=False, indent=2))
