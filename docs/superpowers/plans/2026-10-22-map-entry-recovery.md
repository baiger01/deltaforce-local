# Canonical Map Runtime Recovery

> **For agentic workers:** Execute this plan inline with executing-plans. The user explicitly requires the existing canonical main workspace.

**Goal:** Restore the archived map runtime into the sole canonical workspace without replacing current lobby features or account data.

**Architecture:** Audit the archived runtime import graph, port native transport and replication into the current domain layout, and merge shared launch/gateway code against the common Git ancestor. Keep the current lobby, season, difficulty catalog and account database. Record every imported file and source hash.

**Tech Stack:** Python, SQLite, native UE replication, existing unittest suite and native shadow-client runner.

## Tasks

- [x] Identify the missing runtime and the common ancestor `933aa3c`.
- [ ] Add a failing canonical-runtime availability check, covering the portable plan, map admission and launcher flag.
- [ ] Generate a reviewed migration preview. Copy missing runtime dependencies, adapt imports and resource roots, and three-way merge shared files. Resolve conflicts explicitly.
- [ ] Restore only referenced schema/configuration/evidence files; never copy account databases or executable DLLs. Preserve source hashes and update the difficulty catalog pin only after semantic review.
- [ ] Run portable-profile preflight and the native transport tests. Run season, difficulty, gateway and package-layout regression tests.
- [ ] Start the canonical shadow client with the real DS/bootstrap profile and a 1800-second limit. State validation scope before launch, obtain actual map-entry evidence, then verify SDK restoration and owned-process cleanup.
- [ ] Record the imported inventory, validation results and remaining gameplay gaps in the canonical documentation. Keep unfinished gameplay clearly separate from successful map entry.

## Verification Commands

From `outputs/df-local-server`, use `../../.venv/Scripts/python.exe -B -m unittest discover -s tests -p test_canonical_map_runtime.py -v`, then the existing `test_server_layout.py`, `test_native_map_board.py`, `test_native_season.py` and `test_handshake_diagnostic.py` suites. The availability check must fail before importing the archived runtime and pass afterward. Native acceptance requires an actual admitted map session, not merely a successful import or packet ACK.
