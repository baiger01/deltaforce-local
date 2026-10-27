# Updated Client Integration, 2026-10-24

## Scope

The canonical code and service remain in this repository. The updated client is
not approved for the historical gameplay profile by changing its executable hash.
Weapon visibility/switching, interaction, skills, loot, AI and complete match
settlement are still unfinished. The modes below are explicit diagnostics.

## Actual Build

- Installed root: configured with `DF_LOCAL_SOURCE_GAME`; read only.
- Clean independent shadow: configured with `DF_LOCAL_SHADOW_GAME`.
- Executable SHA256: `79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203`.
- Executable bytes: `514154112`; image bytes: `536408064`.
- `UserGameVersion.ini`: game `1.101.37117.36.9`, resources `1.101.37117.36.52`.
- The old shadow shares hard-linked resources with the installation and also
  changed during the user's update. It is not an intact historical build.

The previously failing StreetLamp material entry decoded and passed its payload
checksum after the user's update. Its decoded asset SHA256 is
`cc60a1675aff39a794a43abb0e5efa75beb2010d06af17c7756cc83f002f08da`.
This resource recovery came from the game update, not the weapon Role patch.
See `WEAPON_ROLE_AND_RESOURCE_CRASH_20261023.md` for the original crash.

## Implemented Diagnostics

`snapshot_updated_client_code.py` verifies this exact PE and bounds code reads to
its file-backed executable sections. Cache
`work/native-code-cache/1792785456045583200/manifest.json` contains all
349562715 planned bytes, with zero unavailable bytes. Its distinct cache kind
cannot silently pass an old production CodeCache guard.

`updated_client_metadata.py` relocates only the exact, separately proved global
cells used by hash-pinned historical pure readers. It preserves their algorithms,
decoder refusal, identity checks and old defaults. Actual heap addresses and
metadata values are not translated. Path formatting is restricted to
unambiguous ASCII. Property and UFunction reads are confined to selected current
class descriptors and their verified inheritance chains.

Native result:
`work/native-client-tests/1792803423602487700/updated-class-metadata.json`.

- 45 selected/ancestor classes, current property declarations and method targets.
- 353 own net UFunction declarations; no functions were called.
- All selected native replication arrays were empty and setup bit `0x800` clear.
- Property RepIndex, ClassNetCache field index and RepLayout handle are separate
  values. No current wire handles were obtained or invented.
- All diagnostic clients were closed and SDK restoration reported successful.

Offline comparison found no geometry/order/low-flag changes in 1646 matched
properties across 36 classes. The actual weapon inheritance chain was observed.
32 actual old/current serializer target pairs and four direct delegates passed
complete function comparisons. These facts do not prove a working match.

The UAC wrapper and client runner support these explicit updated diagnostics:

- `--updated-client-code-observation`: lobby executable-code observation.
- `--updated-client-metadata-observation`: automatic lobby metadata observation.
- `--updated-client-transport-observation`: requires explicit game-server,
  handshake and packet-ACK probe flags. Control is accepted only with the
  separately source-qualified current profile described below. Actor bootstrap
  and historical memory readers remain rejected.
- Transport plus metadata observation is allowed only with that qualified Control
  profile. It collects metadata after an actual active Join, rather than treating
  lobby descriptors as initialized match replication data.

All require the independent shipping shadow and local business bootstrap. The
transport experiment preserves the existing explicitly unqualified outer UDP
envelope. Trial `1792984987382326700` captured Hello version `1077088301`.
`work/build_updated_control_profile.py --check` reproduces
`protocol/native_ds_control_profile_79fb7b10.json` from the updated native
Control/SubWorld comparisons and current MapConfig rows. It targets map 2201,
`Iris_Entry`, and `SubWorld=Dam_Iris_Level1`. It requires the separately proved
DisableDeviceSeamless override. This is a Control-only diagnostic, not the
historical full gameplay profile with a substituted executable hash.
Observation limit remains 1800 seconds; automatic metadata/code modes stop after
their bounded collection and restore the SDK.

## Updated Content

The current GameItem table has 16426 rows. Its mapped values and 271 receiver /
preset mappings match existing catalogs. Packaged content is not necessarily an
active server event.

The separate `protocol/native_raven_catalog.json` now records three real holiday
configurations, 45 input clusters, 180 drop mappings, actual actor fields and 18
activity contracts with archive, payload, row and serialized-offset provenance.
`work/research_updated_content_catalog.py --check` reproduces it exactly.
It does not enable a gameplay handler or invent token prices / active stock.

The source-pinned opaque activity descriptor entry was added using the existing
empty-only policy. Full activity response types now compile, and
`candidate_business.pb` plus its validation report were regenerated. Populated
unknown nested entries still fail closed. There is no active token store yet.

## Evidence And Remaining Work

Exact proof files are in `work/` and `work/evidence/`:

- `updated-metadata-roots-79fb7b10-{static,emulation,qualified}.json`.
- `updated-replication-core-79fb7b10.json`.
- `research_updated_transport_79fb7b10.json` and corresponding profile report.
- `research_updated_cache_initialization_79fb7b10.json`.
- `research_updated_serializer_bindings_79fb7b10.json`.
- `research_updated_stateless_handshake_79fb7b10.json`.

## Integration Status, 2026-10-27

Random-spawn and loot sources were not deleted. The updated-source audit
`work/evidence/updated-map-rule-sources-79fb7b10.json` verifies all ten selected
tables and 27 historical Dam packages against the current shadow. They retain
20 spawn groups / 100 PlayerStarts, 265 selected loot actors, eight Mandel
generators, and 32 high-value candidates. This is the qualified historical
selection, not a census of every updated map object. The old complete profile
still targets the historical executable. A transport-only trial does not load
those gameplay rules and must never be presented as their acceptance test.

Initial-admission inventory and ordinary Actor recipe content now use bounded
reliable fragmentation in the canonical transport. Small payloads retain their
existing bytes. Oversized default-subobject exports stay unfragmented and must
receive a positive ACK before body fragments are sent. Dependent stages wait for
every fragment's send/receipt proof. Sequence wrap and retransmission are tested.
The 64-bit routing reserve and fragment-count/assembly limits are conservative
local bounds, not inferred native connection settings. Dynamic creation,
post-admission inventory refresh and world deltas retain their existing bounds.
Native large-loadout acceptance is still unverified. A fresh regression run
passed 677 legacy tests with one skip, including eight fragmentation tests.

A later review reproduced two additional sender failures: a permitted burst
could evict outstanding full-send proof from the 128-entry journal, and two
successive admissions could exceed the combined wire-piece limit. The canonical
sender now reserves bounded in-flight capacity, retains unresolved send proof,
and checks the combined old/new queue before publication. Historical and current
PC RPC profiles are separate: current cache maximum 244 and current object
serializer/table bindings cannot be mixed with the historical maximum 245.
Startup, ping, possession, view-target and rotation have source-qualified current
recipes; the exact receiver certificate is required. This does not activate the
new map bootstrap. A fresh full legacy run passed 698 tests with one private
fixture skip.

Trial `1793011958770760000` exited in lobby before sending DS packets or
collecting match metadata. Its dump records an access violation at executable
RVA `0xf3f7b4` in Lua prototype traversal while loading GuideModule.lua. The
packaged module parses fully offline; the dump does not retain enough heap/input
data to identify the corrupting write. A stale cache is not established, and no
cache was deleted. SDK restoration was verified. The externally rewritten
Engine.ini and stale lock were preserved in that private trial directory before
the exact original Engine.ini was restored; the historical failed restoration
record remains unchanged.

Offline current registration/package extraction now supplies the minimum four
Actor declarations, 17 field handles/types, twelve startup RPC declarations,
nested structs, enum widths and ordinary generated-constructor inheritance.
These are explicitly source-derived values, not invented initialized-cache
observations. A cached CDO pointer is not required to derive deterministic wire
indices. Native acceptance and the full inventory/loot/skill migration remain
separate.

Automatic trial `1793063444267071700` completed in 32.12 seconds. Its metadata
record at `work/native-client-tests/1793063482116451500/updated-class-metadata.json`
has SHA256 `0d67c2042ee16854754da498b0a675bbf45df8d27f97c7e5b45480bad6c96b65`.
Both before and after the 49-class scan, guarded reads observed global hook
enable `1de36180=1` and alternate Actor channel `1e322935=1`. The conservative
zero-gate path is therefore not an activation route for this actual process.
Do not set either byte to zero. The actual GP alternate and hook paths must be
qualified. Pawn cached CDO and inherited NetRepActorInterface adjustment 0xa60
were also observed without calling native functions or reading CDO payloads.

User-view trial `1793068109385738800` deliberately enabled current DS Control
only, with no portable map bootstrap. It exited after 841.3 seconds, captured
64 DS packets and created no Actor bootstrap. It cannot validate random spawn,
loot or Mandel gameplay. SDK restoration was verified. The client again rewrote
Engine.ini to SHA256 `847f386922ec5b25f00ba535af4033b441b16e7184e44fc9e62d51f5ff27b0d4`;
those bytes and the stale helper-74680 lock were preserved in the private trial
directory before restoring the exact original SHA256 `64e41a95ab6557ad89025bacff7f7238b90ad5aa8b4e62e0a3420dac90349953`.
No game/helper remained; the original installation was not written. The original
restore-refusal manifest remains intact.

Next: qualify actual GP alternate/hook receive behavior, then activate a
separately guarded current minimum Actor profile and migrate the full gameplay
profile. Broad cache sampling is not a substitute for this finite receiver
contract. Raven interaction and active activity stock also require integration.

The actual enabled-route certificate is now sealed at
`work/evidence/updated-enabled-actor-receiver-79fb7b10-v3.json`. It proves that
native GP immediate/deferred paths preserve the bunch and add no Actor payload
header, conditional on 37 source-bound hook bytes being zero. The bounded reader
`work/updated_enabled_header_context.py` checks 13 exact data ranges and 88
instruction guards, with two full rechecks; it writes no process memory.
Automatic trial `1793071777888899100` read top flags 1/1 and all 37 hooks zero
both before and after its class scan. The capture SHA256 is
`587f50cc6fd807fcc37a1b871a4a4aef66b008439944a41011afac12fe5fee10`, and its
summary is `work/evidence/updated-enabled-actor-receiver-observation-79fb7b10.json`.
It closed after 36.44 seconds with SDK/Engine.ini restored and no active lock or
remaining processes. Future admissions must check their live gate; this past
snapshot does not authorize a different process, activate Actor transmission,
or prove map gameplay.
