# Estate window 21 — Plan 035 revision-3 requalification (2026-10-20)

The round-2 review of the Plan 035 branches (Sol: request-changes; DeepSeek:
pass) found that revision 2 could still verify a run that did something
else. That is answered by revision 3 of both capabilities and by a record
field, and this window requalified both. The estate is the one window 20
left: LabMS01 `domain-joined` from 19:59 UTC, rotation disabled.

Timeline (UTC): canary **10/10** 22:19 → guest parse-check of the three
changed scripts (0 errors each) and bundle placed in
`C:\gpo-studio\wcd-stage\incoming\` → r1 22:20–22:31 **verified** → r2
22:32–22:39 **verified** → WP-1 backup collected 22:40 → LabMS01 reverted with
`tools/estate_revert_member.ps1` (pre-check passed; clock −9665 s → 0; secure
channel True) → bring-up READY → canary attempt 1 died on a controller-side
pwsh crash (`malloc(): unaligned tcache chunk detected`; the REPL process, not
the estate) → re-run **10/10, exit 0, 22:43:35**. **Estate released 22:43
UTC.**

## What revision 3 changed, and why

- **Sol B1 / DS N3.** A require clause's fact key predicts every key under
  it. Revision 2's `scripts_ini.machine` / `scripts_ini.user` clauses
  therefore covered an extra populated `[Startup]` trigger and any change to
  the INI's aggregate facts. Sol's probe verified that attack at 25 clauses
  with nothing unclassified. Revision 3 names no side or file as a prefix.
  Every measured fact is asserted leaf by leaf, and both `scripts.ini` files
  are pinned by `file_digest` (length + SHA-256, absent before). The tests
  rebuild the banked w20-r1 run, which revision 3 accepts, then add the
  Startup entry or alter any INI measurement, which revision 3 disproves.
- **Sol B3 / DS N2.** Notes are capped at 512 characters, and w20-r2's
  argument and setup-manifest notes ended mid-JSON. v2 records now carry an
  optional, untruncated `provenance.invocation`: the canonical arguments
  with their SHA-256, the run-sheet SHA-256, and every setup script's whole
  output with its SHA-256. `record_schema` refuses a record whose hashes do
  not recompute from the record itself. This stays inside v2 because the
  WEL seam accepts exactly `schema_version == 2`.
- **Sol B2 / DS N5.** `dir_clean_owned` re-checks the fixed root and every
  ancestor for reparse points at cleanup time. The other two confined
  scripts walk the same chain. This is tested behaviourally under pwsh with
  a symlinked root, a symlinked ancestor and a symlinked leaf.

## r1 — `gpmc.author_scripts_logon_shutdown` revision 3, verified

`records/w21-r1-record.json`: 22 clauses satisfied, 42/42 deltas covered.
That is 6 more deltas than revision 2, because the `file_digest` facts are
now observed. Both INIs are absent→present with exactly 158 B `f8fa4009…`
and 138 B `ba526db6…`, identical to windows 19 and 20 and to the backup the
cleanup took (`captures/w21-r1-*-scripts.ini`, Hidden). The arguments'
SHA-256 is `70ba03aa…`. The record's `provenance.invocation` carries the
arguments and all three setup outputs whole.

## r2 — `gpmc.observe_imported_firewall_rules` revision 3, verified

`records/w21-r2-record.json`: 13 clauses, 15/15 deltas. The same exact
delta as window 20 (stub 142 B `07cba636…`, parsed leaf by leaf, and the
pinned relpath lists). `provenance.invocation` carries `gpo_stage_import`'s
whole output: `backup_id=cb31b508-…`, `bundle_sha256=3f146885…`,
`stage=…\w21-r2`, `registry_pol_sha256=25ad9748…`. That output was cut short
in window 20's notes. The dumps' digests are in the journal and in
`captures/MANIFEST.sha256`. Cleanup removed the owned GUID and the owned
stage.

## Follow-ups (filed here; not fixed in this change)

- **DS N1: legacy run-sheets still remove GPOs by display name.**
  `runsheets/gpmc.author_registry_security.json` (gpo_backup to a fixed
  caller path, gpo_remove by name) and
  `runsheets/gpmc.author_scripts_ps_order.json` (gpo_remove by name) still
  carry the hazard Plan 035 removed: an existing-name refusal at setup could
  clean up a pre-existing GPO of the same name. Port them to
  `gpo_remove_owned` / `gpo_backup_owned` and requalify. The same applies to
  every other qualified sheet that still calls `gpo_remove.ps1`.
- **DS N6:** `shot` steps are not digest-bound in the record, unlike
  `dump save_as`. The PNGs rest on `MANIFEST.sha256`.
- **Sol B4:** `plan035/estate-repair-tools` is an archived reference, not
  for merge (its top commit says so). The maintained revert path is
  `tools/estate_revert_member.ps1` on `estate/password-rotation-guard`.

True size: one estate, one run per capability at revision 3. Display and
edit persistence through GPME remain person-reviewed and unproven
respectively.
