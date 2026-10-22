# Estate window 19 — gpo-studio Plan 035 WP-1 and WP-2 (2026-10-20)

Two new capabilities for gpo-studio's Plan 035, both authored from a recon
pass taken in this window and both qualified here:
`gpmc.author_scripts_logon_shutdown` (WP-1, WI-071: the user-side Scripts
extension pair and the Shutdown/Logon `scripts.ini` shapes) and
`gpmc.observe_imported_firewall_rules` (WP-2, WI-077: whether GPME shows the
rules of a Studio-imported firewall GPO). Windows 17 and 18 are taken by open
PRs (#31, #32), so this window is numbered 19. One estate, one console
session lineage, mvmcc02-driven, lab domain `ad.labdomain.dev`.

Timeline (UTC): canary 16:5x 7/8 (no console session) → `estate_bringup
-RedeployHelper` READY 16:57 → recon 17:00–17:30 → canary **8/8** 17:34 →
r1 17:34–17:40 (indeterminate) → route re-measured → r2 17:48–17:58
(**verified**) → r3 17:59–18:08 (**verified**) → guest backups collected
18:09 → member reverted to `domain-joined` 18:11 → bring-up NOT READY (see
"The revert") → member repaired 18:28 → bring-up READY + canary **8/8**
18:30:54. Estate released 18:30 UTC.

## Pre-flight

The estate had no console session (canary 7/8: `console_session`
`no_session`, everything else green); nothing looked in use — no logged-on
operator session, no WEL or requalification process on mvmcc02 or mvmcc03.
`estate_bringup -RedeployHelper` walked all seven steps (DC −63 s, member
+1 s, first-try CAD logon, helper redeployed, context smoke answered).

## Recon (observe-only, disposable GPO, cancelled out)

Driven step by step through `GestureExecutor` without a transaction (an
operator scratch driver; nothing committed), on `zz-studio-evidence-recon035`
and later `-recon035b`, both removed (`remaining=0`). Captures are under
`captures/recon-*`.

- **Logon and Shutdown sheets are the Startup sheet's twins.** `Logon
  Properties` / `Shutdown Properties` (`#32770`), the same Scripts tab, the
  same Up/Down/Add.../Edit.../Remove/Show Files.../OK/Cancel/Apply panes, the
  same `Add a Script` child (`Script Name:` edit 151, `Script Parameters:`
  edit 152, Browse..., OK, Cancel). Results-pane routes: User Configuration
  > Windows Settings > `Scripts (Logon/Logoff)` > `Logon`/`Logoff`; Computer
  Configuration > Windows Settings > `Scripts (Startup/Shutdown)` >
  `Startup`/`Shutdown`. The frame is `gpedit.msc` titled `Local Group Policy
  Editor` opened onto the GPO, so there is no `Policies` level (soft step).
- **Crossing from one side to the other.** Backspace walks up only to the
  side node; Alt+Left does nothing; Tab+Home from the results pane does
  nothing. Run r1 then showed that clicking the tree's centre can land on the
  already-selected node and open a label edit that swallows Home. The route
  that works in both directions: click the GPO root row of the UIA-invisible
  scope tree (offset −201 px from the tree's centre), Escape, Home, in one
  `keys` invocation (`navigate_scope_root`).
- **Opening Security Settings writes SYSVOL.** On a fresh GPO the walk left
  `Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf` (142 bytes) plus the
  Scripts and `User/Documents & Settings` directories, with both versions
  still 0 and both extension lists empty. So `navigate_security_settings` is
  classified `potentially_mutating`, and WP-2 predicts the file.
- **Firewall node.** Its results pane is a WinForms overview whose `Inbound
  Rules` link sits below the fold. The tree walk works: Tab into the scope
  tree, Right, Down to `Windows Defender Firewall with Advanced Security -
  LDAP://CN={GUID},...`, Right, Down to `Inbound Rules`, whose results list
  has 18 columns (Name, Group, Profile, Enabled, Action, Override, ...).
- Seen in passing, for WP-3: User Windows Settings lists `Folder
  Redirection`. Nothing was opened.

## Run r1 — WP-1, indeterminate

`zz-studio-evidence-plan035-wp1-r1`. The Shutdown sheet was authored and
committed (`ok_child_dialog`, then parent OK), then the first
scope-root route clicked the tree's centre, opened a label edit on
`User Configuration\Windows Settings`, and `wait_element` for `User
Configuration` timed out at step 19. **Indeterminate**; cleanup ran in
full (backup, `removed=`, strict requery 0). It is banked unclaimed. Its
backup's machine `scripts.ini` is byte-identical to r2's.

## Run r2 — WP-1 `gpmc.author_scripts_logon_shutdown` revision 1, verified

Arguments: `shutdown_script=zz-studio-shutdown.cmd`, `shutdown_params=/c
shutdown-alpha`, `logon_script=zz-studio-logon.cmd`, `logon_params=/c
logon-beta`, `backup_dir=C:\gpo-studio\manual\plan035-wp1\r2`. **Exit 0,
record `verified`** (`records/w19-r2-record.json`, schema v2, capability
sha256 `07174ef6…` = the committed bytes), transaction `7bffe13c-…`. 24
clauses satisfied, 36/36 deltas covered, converged after 2 polls / 2
reproductions, all three prepare gates banked==observed. Measured:

- `gPCUserExtensionNames` =
  `[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B66650-4972-11D1-A7CA-0000F87571E3}]`
  — **the user-side tool GUID is `{40B66650-…}`**, not the machine side's
  `{40B6664F-…}`. The envelope did not assert it; it is the measurement.
- `gPCMachineExtensionNames` =
  `[{42B5FAAE-…}{40B6664F-4972-11D1-A7CA-0000F87571E3}]`, as R2 measured for
  Startup.
- Versions: machine 0→1, user 0→1, `versionNumber` 0→65537. One OK per
  sheet moved its own half by exactly one. The envelope asserted only `>`
  plus the packing relation.
- `Machine/Scripts/scripts.ini`: 158 bytes, UTF-16LE BOM, 4 CR / 4 LF,
  `[Shutdown]` only (no empty `[Startup]`). `User/Scripts/scripts.ini`: 138
  bytes, same encoding, `[Logon]` only. Split style
  (`0CmdLine=`/`0Parameters=`), leading blank line, as R2.
- No `psscripts.ini` on either side; both `config_shape` `none`.
- New directories: `Machine/Scripts/{Startup,Shutdown}`,
  `User/Scripts/{Logon,Logoff}`, `User/Documents & Settings`.

**Byte-exact capture.** Cleanup ran `Backup-GPO` into `backup_dir` before
removing the GPO. The backups were collected from the guest before the
revert. The INIs are **Hidden** files: `Compress-Archive` and
`Get-ChildItem` without `-Force` skip them, so the first collection came back
without them. The second used `ZipFile.CreateFromDirectory`. Sizes and CR/LF
counts equal the oracle's facts. The raw zip is held outside both repos
(sha256 `494be98c…`, gpo-studio inbox `plan035-w19/`), and gpo-studio banks
the transcripts with provenance.

## Run r3 — WP-2 `gpmc.observe_imported_firewall_rules` revision 1, verified

The bundle is gpo-studio's firewall lane candidate built at `badcaf9` by
`scripts/plan-033/build-firewall-candidate.py` (`studio-firewall-backup.zip`,
sha256 `3f146885…`, the same bytes the 1.1.0 batch's firewall lane
imported). It was placed in the guest beforehand by an operator push into
`C:\gpo-studio\manual\plan035-wp2\r1\`, and the setup script refused unless
the hash matched. `expected_machine_extensions` was the export's registration,
`[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{B05566AC-FE9C-4368-BE01-7A4CBB6CBA11}]`.
**Exit 0, record `verified`** (`records/w19-r3-record.json`, capability
sha256 `143c0634…`), transaction `6459cd9a-…`. 12 clauses, 12/12 deltas
covered, 2 polls / 2 reproductions.

- **Post equals pre** on both version halves, `versionNumber`, both
  extension lists, and (through the unclassified per-file rule)
  `Machine/registry.pol`. The pre-state machine list equalled the export's
  `B05566AC` registration.
- The walk wrote what recon predicted: `GptTmpl.inf` appeared (UTF-16LE,
  CRLF, `[Unicode]` + `[Version]` only), plus the Scripts and SecEdit
  directories. Nothing else moved.
- **Surface evidence, for review** (`captures/wp2-*`): the overview reads
  Domain and Private profiles on, inbound blocked, Private outbound not
  configured, and Public not configured, which is the profile policy the
  candidate authors. The Inbound Rules list shows **all 10 inbound rules the
  candidate authored** (names checked against `authoring.json`). They carry
  their profiles, the Block action, `Secure` for the authenticated-bypass
  rule, and `No` plus `StudioFwLane Group` for the disabled grouped rule.
  `StudioFwLane in tcp allow Properties` opened on the General tab with all
  nine tabs, the name field, Enabled ticked, and the Action radios at Allow.
  It was cancelled; Apply stayed greyed.
- What it does not show: UIA here exposes no enabled/disabled state, so
  "editable" is read off the screenshot by a person. No edit was made, and
  nothing proves an edit would persist.

## The revert, and what it broke

After collection, LabMS01 was restored to `domain-joined` (Running→Running,
`-Confirm:$false`). Bring-up then failed: **every PSDirect logon to the member
answered "The credential is invalid"**, as `LAB\claude`, as `LAB\Administrator`
and as the local accounts. The DC's security log showed TGTs and
`LABMS01$` service tickets issued successfully, so the member was rejecting
them. The cause is that the checkpoint was minted on **2026-09-20**, while AD's
`LABMS01$` `pwdLastSet` is **2026-10-16**. The live member rotated its
machine password after window 14's revert. A revert now restores a machine
key older than the one the KDC encrypts tickets with, and puts the guest clock
30 days back (`2026-09-20T19:16Z` measured).

Repair, on the lab member only: disconnect both NICs from the host, open a
PSDirect session on cached credentials, reconnect the NICs, `Set-Date` from
host UTC, then `Test-ComputerSecureChannel -Repair` as `LAB\Administrator`
(repair True, verify True, `nltest /sc_query` NERR_Success). Bring-up
(`-RedeployHelper`) then went READY, with first-try CAD logon. **Closing
canary 8/8, exit 0, 18:30:54Z.** Every guest-side artifact of the window
(backups, staged bundle) went with the revert, and both runs' cleanup had
already removed their GPOs (strict requery 0).

**Standing consequence (owner decision):** while the checkpoint predates the
member's newest machine-password rotation, every revert of LabMS01 (WEL's
`revert_environment` included) will leave the member unable to take a
Kerberos logon until this repair is repeated. Re-minting the checkpoint, or
pinning the member's machine password (`DisablePasswordChange`) in the
next baseline, are the durable fixes. Neither was done here.

## What this window changes

- Two ledger rows qualified (revision 1 each); claim-registry rows W19a
  (WP-1 measurement) and W19b (WP-2 surface evidence).
- The `dump` run-sheet step gains `save_as`, which saves the full UIA payload
  to the evidence directory beside the screenshots.
- The capability-seam fixture now collects both scripts sides, as the
  executor's `r2_core` does.

True size: one estate, one console session lineage, one run each. WP-1
measured GPME's behaviour for one `.cmd` per trigger on one build. WP-2 is
a person-reviewed view, not a certified claim.

## Review corrections (2026-10-20, Sol + DeepSeek)

The two-lineage review of this window found that the records support
narrower claims than the first version of these notes made. The corrections:

- **r3 did not enforce an exact observe-only blast radius.** Its envelope
  required `gpttmpl.present` (a prefix clause that covers ANY GptTmpl.inf
  content) and `sysvol_relpaths != pre` (true for ANY added path). The walk
  also added `Machine/Scripts/{Startup,Shutdown}`, which "GPME wrote only
  `GptTmpl.inf`" omitted. What r3 shows is what it observed: versions,
  both extension lists and `Machine/registry.pol` unchanged, plus the stub
  (`[Unicode]`/`[Version]`, 5 CR/LF), its SecEdit parents, and the two
  Scripts directories. It is not a certified exact exception.
- **Neither record binds its inputs or the collected bytes.** Schema v2
  binds the capability document only. r3's record does not carry the
  bundle hash or backup id the setup script emitted, and r2's does not
  carry the scripts.ini bytes. The bundle identity rests on the operator's
  push and the setup script's hash check; the INI bytes rest on the
  operator's collection. This window now banks the raw INIs
  (`captures/w19-r{1,2}-*-scripts.ini`), the collection listing with file
  attributes (`captures/w19-wp1-backup-collection.txt`), and
  `captures/MANIFEST.sha256` over every capture. That makes the bytes
  reviewable, not record-bound.
- **The Hidden attribute is operator-observed** (the collection listing),
  not something a record or the zip preserves.
- **Cleanup removed by display name**, and WP-2's staging path was
  caller-chosen. Neither caused harm here (both names were fresh and
  disposable), but a refused setup could have removed a pre-existing GPO of
  the same name.

Revision 2 of both capabilities (same branch) answers each point: exact
lists and digests in the envelopes, cleanup by the GPO GUID captured from
`New-GPO` only, staging and backup confined to fixed roots by leaf name
with an ownership marker, and the invocation arguments, run-sheet digest
and setup output written into every record's notes. The revision-1 records
stay banked as what they are; requalification at revision 2 is in the next
window's notes.
