# Receive-path profiling and optimization

## Baseline

Native trial `1792734854626602400` captured 2600 datagrams. Its
`game-server-packets/receive-profile.txt` reports 54 content preflights taking
55.072 cumulative seconds. The nested skill-template writer accounts for
54.669 seconds; these times overlap and must not be added together.

The progress observer reconstructed the complete frozen initialization payload
on every poll. Incoming Actor binding checks also searched the actual receipt
tuple separately for every prerequisite (745172 helper calls in this capture).

## Changes

- Reuse the compiled content expectation within its existing admission registration.
  Detached Actor fields, content plans, initial channel sequence and packet budget
  identify it. In-place content changes invalidate it. Current source leases,
  ticket identity, connection generation, peer binding and every delivery still
  need to pass their existing checks.
- Build one exact receipt lookup per Actor binding check. Keys retain the complete
  Actor GUID and bunch; records from another ticket, transport or generation are
  excluded. Prepared sends and manually changed delivery flags remain insufficient.

Regression tests first reproduced 64 preflight builds for 64 unchanged polls and
14 receipt scans for 14 prerequisites. Both now perform one build/scan respectively.
Additional tests cover altered content, changed sequence, reduced packet budget,
expired source lease and foreign/modified receipts.

The related GameServer, Actor/control transport, receipt, ownership and canonical
runtime suites ran 396 checks: 389 passed and 7 skipped for unavailable historical
fixtures.

Five-run median synthetic comparisons on this machine:

- 200 progress polls, two delivered Actors: 0.0395713 s before, 0.0187821 s after.
- 2000 binding checks, 14 prerequisite bunches: 0.123629 s before, 0.1003675 s after.

These are implementation measurements, not native latency or gameplay acceptance.
The original method bodies were reconstructed in memory for the comparison;
production code and the live account were not replaced by the benchmark.

## Native validation

Trial `1792739013204163300` used both optimizations. It authorized one player,
observed the map Join and processed 38787 datagrams. The 23 saved profiler windows
cover 38630 of these datagrams. Only the initial window has content preflight in
its top 40 functions; later windows no longer repeatedly reconstruct the skill
templates. The remaining leading cost is connection-state cloning.

There were 21 receives above 200 ms, including four above one second (maximum
3.428 s). Workloads and startup coverage differ from the original aggregate
capture, so these runs do not establish a percentage reduction in native latency
or resolution of all disconnects. Profiling overhead is included.

The owned client was closed after sampling. The final report confirms SDK
restoration and no helper error. Engine.ini was rewritten by the client and no
longer matches either the original or trial bytes; automatic restoration refused
to overwrite it. Preserve the current opaque configuration and its exact private
backup in the trial directory. Do not report exact configuration restoration.

Weapon visibility, skills, interaction, AI and settlement remain separate
unfinished gameplay work; this optimization does not establish their correctness.
