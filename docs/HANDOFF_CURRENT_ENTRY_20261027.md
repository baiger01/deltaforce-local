# Current Entry Handoff

## Status

The canonical checkout is `main`; lobby and map work use this repository. The
retired map checkout is historical evidence, not another runtime to merge.
No new native trial should run during the current commit/migration freeze.

Current client SHA256:
`79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203`.
Historical client SHA256:
`4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`.
Their source qualifications remain separate; changing a SHA is not a port.

The last completed native trial is `work/native-client-tests/1793076660826961200`.
The client created PC GUID4, GameState GUID6, Pawn GUID2 and PlayerState GUID8.
All four opens and all four post-open contents received transport ACKs.
`SeamlessFlow_InfoInteract` succeeded, but `SeamlessFlow_TravelToDS` timed out
after 120 seconds and returned to the lobby. Ready notifications and Restart
transmissions remained zero. Native map entry and gameplay are NOT accepted.

The current first-player receiver requires pending mask `0x6e`, including a
separate `MovementReplicationActor` prerequisite at bit `0x40`, plus a nonzero
byte at interface offset `0x121`. The completed trial had neither the movement
preprocessing log nor the final `OnPostConnectDS` completion log. Current source
proof is `work/evidence/updated-first-player-ready-prerequisite-79fb7b10.json`.
The actual runtime pending byte was not sampled; further prerequisites can exist.

## Latest Changes

- `dfserver/replication/legacy_ds_current_actor_profile.py` provides the exact
  four-role current source qualification, including the enabled receiver v3
  contract. `legacy_ds_actor_manifest.py` supports this explicit current branch
  while retaining historical guards and static-Actor compatibility.
- `dfserver/replication/legacy_ds_current_movement_actor.py` adds a separate
  current native movement creation qualification. Its class, native constructor,
  empty Actor-open hook, absence of NetRepActorInterface, and CDO name/Outer
  construction were derived from current code. This implements creation only,
  not movement payloads or playable movement.
- `dfserver/replication/legacy_ds_game_state_start.py` supports the six exact
  current readiness/identity fields with current bool and uint64 recipes.
- `dfserver/transport/native/legacy_ds_current_pc_rpc_profile.py` and the PC
  startup, ping, restart, view-target and rotation modules support current cache
  maximum 244. Historical profiles retain maximum 245 and their original guards.
- `dfserver/match/game_server_probe.py` requires matching Actor/RPC build and
  source qualifications when registering startup, readiness and restart.
- `work/updated_map_bootstrap.py` now registers FIVE Actors, adding native
  `MovementReplicationActor` at local GUID10/channel6. The existing four-role
  declaration artifact was not relabeled or overwritten.
- The bootstrap preserves the collaborator's current-table avatar mapping and
  sends PlayerState Uin, HeroID, CurrSameTeamAvatarId and CurrDiffTeamAvatarId.
  Native PlayerState data in the completed trial contained HeroID `88000000026`;
  the preserved local account currently selects fashion `30000060006`. Fashion
  was not carried by the old two-field trial payload, so its historical admission
  value is not independently proven by that packet.
- `work/run_native_elevated_trial.py` forwards the current minimum-Actor flag to
  the UAC child. `work/verify_local_provider_client.py` requests restart for the
  qualified current plan using existing admission/delivery gates.
- The explicit current view-target profile has a local instant-camera policy;
  it does not depend on unqualified native constructor default omission.

Server paths above are relative to `outputs/df-local-server/`. Root-level
compatibility shims are not the implementation modules.

## Evidence And Tests

New native movement source artifact:
`work/evidence/updated-movement-actor-profile-79fb7b10.json`, SHA256
`d507835ac7ed4a50bc245ad0161a12a31368771d2395be62e9a0f6ffb7795ee3`.
Its producer is `work/research_updated_movement_actor_profile.py`.
The readiness proof producer is `work/research_updated_ready_gate.py`.
Neither producer opens a process or changes a runtime profile.

Latest verification: 715 legacy protocol tests passed, with one skip. Another
17 tests passed across current bootstrap, appearance, launcher qualification,
UAC forwarding/restart scheduling, live receiver guard and build routing.
The server registration tests previously passed: 13 historical and 4 current.
`git diff --check` passed for the touched runtime files.

Migration verification: an independent export of the Git index passed SHA256
and size checks for all 2107 dependency files (1135905705 bytes). It passed 28
entry/appearance/launcher/metadata/portability tests and loaded the current
transport qualification plus five-Actor plan from the exported tree. The full
1811-test server run had one 120-second catalog-notification stress timeout
(seven skips); that test then passed in isolation from the exported tree in
32.343 seconds. The earlier stale source pin and machine-dependent launcher
test were corrected and their six focused regressions passed. This records
actual validation limits rather than claiming a clean full-suite run.

Focused server tests are `tests/test_legacy_ds_current_actor_profile.py`,
`tests/test_legacy_ds_current_movement_actor.py`,
`tests/test_legacy_ds_current_game_state_start.py`,
`tests/test_legacy_ds_current_pc_rpc_profiles.py`, and
`tests/test_game_server_current_profiles.py`.
Launcher regressions include `work/test_updated_map_bootstrap.py` and
`work/test_updated_minimum_wrapper_forwarding.py`.

## Migration And Next Validation

Set `DF_LOCAL_SOURCE_GAME` to the installed game directory and
`DF_LOCAL_SHADOW_GAME` to an independent test shadow. Run commands from the
repository root. Recreate the virtual environment on the new machine; do not
assume a copied environment is relocatable. Runtime entry is
`python -B work/run_local_game.py --observation-seconds 1800`.
The startup Control evidence now records game-relative locations rather than a
specific computer's shadow directory. Necessary runtime and source-research
inputs are enumerated in `work/git-runtime-manifest.json` and committed with
their exact bytes. Historical location labels inside sealed observations are
provenance, not a runtime configuration. Account saves are intentionally separate
from the public source repository. Follow `MIGRATION.md` for the destination setup.

Include the transitive runtime evidence and extracted table files, not just the
Python changes. `updated_map_bootstrap.load_plan().sources` enumerates the plan
closure; `updated_minimum_launch.qualify_launch(...)['source_pins']` also covers
the transport, current server modules and runtime receiver dependencies. Missing
evidence must fail explicitly, without falling back to historical schemas.

The last trial has `record_complete=true`, `original_sdk_restored=true` and
`remaining_test_processes=[]`. The exact original Engine.ini was restored and
its trial lock is absent. No game/helper process remained when this handoff was
written.

After migration/freeze, first validate five native Actor creations, the movement
preprocessing and completion logs, NotifySeamlessLoginReady, readiness delivery,
ClientRestart and possession. The five-Actor and new-avatar combination has NOT
been launched yet. Do not describe passing offline tests as a successful entry.
Random spawn, loot/Mandel state, HUD/inventory, usable weapons/skills,
interactions, AI and full settlement remain incomplete in the current minimum
profile. Retain their existing source data and historical implementations for
qualified restoration; they are not enabled by this minimal creation patch.
