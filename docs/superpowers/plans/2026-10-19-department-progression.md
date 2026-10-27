# Department Progression Repair Plan

Goal: restore source-backed department identity, prestige, mission submission,
and reward persistence without the current empty-configuration maximum-level state.

Architecture: use the original RoleQuality/Trader/quest tables and wire consumers.
Keep department state in SQLite and commit objective submission, inventory changes,
prestige changes, and reward claims atomically. Keep map-event ownership with the
map integration and never count client completion requests as proof of a match event.

Tech stack: Python, SQLite, original tagged PAK exports, native reflected field
registrations, Lua bytecode metadata, and the existing protobuf/GCP codec.

## Research

- [x] Trace QuestServer.IsAllDepartmentPrestigeMaxed to the empty rep_level_configs
  returned by the generic read handler. Trace MerchantStruct to RoleQualityCard.
- [x] Inspect complete original RoleQuality and TraderInfo registrations and rows.
  Reproduce with work/probe_native_department_bindings.py and a typed export reader.
- [ ] Recover actual reputation score thresholds, initial unlock conditions, reward
  types, submission objective types, and change-notification consumers before using them.
- [x] Inspect existing local save tables read-only for prior quality, quest, and reward
  records. Record the migration rules separately from ordinary account initialization.

## Implementation And Checks

- [x] Add a default-disabled operator configuration with all-quest completion and
  explicit per-quest IDs. Validate IDs against installed tables; persist Completed
  separately from Rewarded, preserve already claimed rewards, and apply atomically.
  Apply on the authenticated player's task query, with an alternate config path
  supported by the local server command. Keep the checked-in config disabled.
- [x] Test disabled configuration, all/individual selection, unknown ID rejection,
  repeated execution, rollback, and restart using the same native quest save.
- [x] Add failing regression coverage for the empty-config maximum-level condition
  through CSAttributeGetConfigReq and CSAttrGetAllQualityReq.
- [x] Add a source catalog and focused department service; route role config, quality,
  and department unlock queries through authenticated account state.
- [x] Add focused quest tests for owned-item submission, unsupported objective rejection,
  duplicate claim, missing inventory space, rollback, and database reopen.
- [x] Connect source-proven completion and reward paths to native_quests.py. Publish
  CSQuestDataChangeNtf, CSAttrQualityValueChangeNtf and inventory changes only after commit.
- [x] Replace the single fixed merchant/VIP record with five source MerchantIDs.
  Keep VIP independent of reputation and omit unrecovered VIP values.
- [x] Verify affected tests and real shadow-client requests with a 1800-second trial.
  Record actual UI confirmation separately from protocol and database verification.
- [x] Update README only for completed, verified results and DATA_PROVENANCE for sources.

No production progress migration or automatic prestige initialization has been performed
at the time this research plan was created.

2026-10-19: recovered all 4537 QuestObjectiveRow records with zero unresolved
references from the 2365 existing quests. Configuration completion, simple physical
submission, ordinary validated reward claims, explicit binding, and all
42 ordinary reward weapon preset trees are implemented and tested. Department balances
are durable source-context grants, but real reputation thresholds and department query/
upgrade responses remain unresolved. No native UI validation of these new mutations yet.

2026-10-19 later: department query routing and score/level notifications are integrated;
synthetic curves verify calculation and wire shape without becoming production data.
Accepted Type21/Type6 objectives refresh from owned reputation/facility levels.
Original material submission and facility upgrade requests now save partial costs,
charge currency, enforce prerequisites and finish original timers after reconnect.
UnlockSystemList was verified as outputs rather than construction gates.

The preserved account matched the complete deprecated maximum-level signature exactly.
After a full SQLite backup and protected-state comparison, an explicit audited migration
retired those levels; real progress/production and different signatures are excluded.
Official account initialization is unavailable: only original free immediate first builds
are automatically supplied by the documented local bootstrap policy.

2026-10-20: integrated a separate, explicitly mixed-provenance 20/30/30 curve.
LV2/LV3 widths have native popup evidence; LV1 uses an explicit primary provider
progress report with platform/build uncertainty. This is not an official server
configuration recovery. A missing or invalid curve still fails rather than faking MAX.
Recovered original SeasonLevel costs and integrated transactional action XP/level
updates and native notifications. Six real quest rewards now move action1->4 and
flip the real warehouse2 gate; action3 remains ineligible even with all materials.
Account/blast legacy presentation is separately frozen and audited, not raised by
SOL quest XP. Manual quest abandonment clears objective state without refunds.
Native UI trial remains a required final check.

2026-10-20 native trial: 50001 give-up/reaccept/physical submission/reward and
49001 give-up/reaccept succeeded in actual requests; SDK restored after1800s.
User cash mismatch exposed a wrong local Currency2 manual-spend interpretation.
Original QuestStruct excludes Currency2 from its Submit list. Replaced that path
with actual wallet conditions and post-transaction quest refresh, no spending.
User confirmed the cash goal completes normally without reducing wallet balance.
Two matching owned gun candidates remain separate;
fulfilling the single target closes the native panel while consuming only one.

The third native trial remains connected after the wallet-hook guard repair.
The remaining season query error was traced to the original valid default mode0
request; the mode validator and privacy-limited mode/serial diagnostic have focused
wire coverage. Full trial closure and SDK restoration are recorded separately.

2026-10-20 warehouse continuation: recovered all ten native upgrade rows and42
display fields. Completed levels govern cumulative expansion0/18/18/45/45/72/
72/108/108/144 and ordinary box slots0..9. Base315 is qualified primary-creator
arithmetic, not an original server response. New-account enrollment is explicit;
the preserved account was fully backed up and migrated without changing instance
identity, quantities, components, currency, quests or other protected tables.

Native testing exposed space1 rejection and a missing extension_pos_order in
ordinary equipment responses. Both were fixed against original Lua callbacks;
the transaction captures the order before commit and publishes it only afterwards.
User confirmed box transfers, page switching and reopening now work. A later
trial exposed partial-stack and full-magazine rejection plus an empty collection
read entry. Source-backed requests now split quantities and tolerate the original
empty receipt; actual loading is locally saturated to available magazine space,
without implicit unloading or replacement. User confirmed all three ammo checks
and correct quantities.125 focused contract/progression tests passed after these
repairs, with independent review finding no blocker. The final trial was configured
for1800s and ended normally when the owned client exited after722.3s. All1142
processed native requests had no recorded business failure, and no request was
marked unanswered. The record is complete, process exit is0 and the SDK is
restored. Warehouse main9x37 and installed box9x12 passed a read-only coordinate,
overlap and source-category check. User confirmation covers the box page and three
ammo operations; full ten-level progression is covered by source rows and tests,
without advancing the actual account to level10 for the test.
