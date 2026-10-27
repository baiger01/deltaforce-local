# Weapon Role Initialization and Interrupted Validation

## Implemented Changes

The active map plan now records its actual `profile_relative_path`. Weapon
observers qualify that explicitly pinned file instead of refusing a plan that
also pins its base profile. Invalid explicit paths do not fall back to another
profile.

Trial `1792746695779188800/owned-weapon-mesh-followup.json` observed local
`Role=ROLE_None` on both the EmptyHand and modular weapon Actors. Their inherited
Actor declarations and existing driver replication layouts agree with the
source-qualified player receiver schema: RemoteRole is ordinary handle 6 with
two enum bits, and the native receiver maps it into local Role.

`work/weapon_actor_network_role.py` qualifies these exact sources and emits
RemoteRole `ROLE_SimulatedProxy`. EmptyHand, modular and melee initial-content
producers share it. This is the local server's explicit replication policy;
ownership is still initialized separately. Source pins include the helper and
both evidence files.

The targeted Role, weapon-initialization, observer-profile and canonical-runtime
suites passed 29 checks. An offline admission preflight also accepted the frozen
loadout from the successful diagnostic trial. These are implementation checks;
weapon appearance and switching have not passed native acceptance.

## Native Validation Failure

Trial `1792749824832078500` was intended to verify the new weapon Role on the
native client. It started at 18:03 on 2026-10-23 with a 1800-second observation
period. The client crashed at 18:06:34, before the scheduled 18:33 cleanup.
The final report records exit code 3 before cleanup and stop reason
`owned_client_processes_exited`. No handshake, Actor initialization or restart
datagrams were sent by its map server. The crash metadata still identifies
`/Game/Maps/Iris_Entry/Iris_Entry`, so this run cannot validate the weapon change.

The decoded client log first reports Oodle decompression failure at 18:06:31:

- PAK: `DeltaForce/Content/Paks/pak-0-1-pakchunk78-WindowsClient.pak`
- Entry offset: 158976000
- Compressed block: 1649 bytes; encrypted stored extent: 1664 bytes
- Expected output: 3132 bytes
- Asset: `DeltaForce/Content/Environment/Props/HAAVK/IceLand/Lighting/00_Materials/HD/MI_H_IceLand_Lighting_StreetLamp_03_HD.uasset`

The client retries, then aborts with `Retry was NOT sucessful.` on
TaskGraphThreadBP 52. Its `Saved/AsyncloadingError.log` names the same asset.

## Read-Only Resource Cross-Checks

The installed and shadow PAK are the same hard-linked file, size 378997619.
Their 4096-byte interval at 158975872 has SHA256
`588ecd985c9b09004e830175f18f9819f033cd495a80bda244b0099094d671f4`.
Neither installation was modified during this investigation.

The existing offline PAK reader verified the primary and secondary indices,
resolved the exact asset to offset 158976000, and reproduced decompression
failure using the installed pure Oodle codec. The decrypted compressed prefix
matches the prefix in the client error. Its stored payload SHA1 also differs
from the entry header.

Three adjacent encrypted entries decode successfully and match their stored
SHA1 values, providing controls for the key, parser and codec:

- Non-HD street-lamp material, offset 159000576
- HD street-lamp texture header, offset 159002624
- Military storage-box texture header, offset 158924026

A read-only directory scan of 292 distinct installed/shadow baseline and hotfix
PAKs found this asset only in the failing entry; all scanned indices qualified.
There is no verified alternate local resource to substitute. A complete copy
from the same client version is needed before repeating native validation.
Do not substitute a different material or suppress the resource failure.

## Cleanup and Remaining Work

The final report confirms SDK restoration. The restored SDK SHA256 is
`9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723`;
temporary SDK sidecars are absent and no client remains running.

Engine.ini was rewritten during the run, so its restoration manifest reports
`restore_refused_external_change`. Preserve the current opaque configuration
and the trial's original-byte backup; exact configuration restoration is not
claimed. Its lock owner PID 53048 was confirmed dead, and the lock was renamed
to `Engine.ini.codex-trial.lock.stale-53048-pak-crash-1792749824832078500`.

After a same-version resource replacement is verified in the independent
shadow, repeat weapon Role and first-person attachment observations. The exact
native hide reason, sustained gun visibility, knife switching and firing remain
unverified or unfinished. Skills, interactions, AI and complete settlement are
also not established by this change.
