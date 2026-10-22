# Estate window 20 — Plan 035 revision-2 requalification (2026-10-20)

The capture half of window 20. The estate half (machine-password rotation
disabled on the members, checkpoints re-minted, revert proven) is written up
in `NOTES.md` on the `estate/password-rotation-guard` branch. Both
capabilities ran at revision 2 against the re-minted LabMS01 baseline, after
the first revert proof left the canary 10/10.

## Recon: the GptTmpl.inf stub, measured before the envelope used it

On a disposable GPO built the revision-2 way, `zz-studio-evidence-recon20`,
`gpo_create` then `gpo_stage_import` imported the firewall bundle into the
fresh GUID. `GptTmpl.inf` was **absent** after the import. After GPME opened
Computer Configuration > Windows Settings > Security Settings it was
**142 bytes**, SHA-256 `07cba636ed9c1c30c4a4c228e555151f1fc43f7bfc941cbb221ed67297ea3dbc`:
UTF-16LE BOM, then `[Unicode]` / `Unicode=yes` / `[Version]` /
`signature="$CHICAGO$"` / `Revision=1`, CRLF. The bytes are banked at
`captures/recon-gpttmpl-stub.inf`. The recon cleaned up through the new owned
scripts (`removed_guid=…`, `removed_dir=recon20`, requery 0). Those values went
into the WP-2 run as `expected_gpttmpl_bytes` / `expected_gpttmpl_sha256`, which
the record's notes now bind.

## r1 — `gpmc.author_scripts_logon_shutdown` revision 2, verified

The window-19 argument set, plus `backup_name=w20-r1`. **Exit 0, record
`verified`** (`records/w20-r1-record.json`, capability revision 2). 25
clauses satisfied, 36/36 deltas covered, converged after 2 polls / 2
reproductions, all three prepare gates banked==observed.

- Both extension lists equal the exact measured strings. The user side is
  `[{42B5FAAE-…}{40B66650-4972-11D1-A7CA-0000F87571E3}]` again; window 19
  measured it unasserted, and this run asserted it.
- The relpath delta is exactly window 19's. There is no psscripts.ini, and each
  version half moved 0→1.
- The cleanup journal binds the bytes: `gpo_backup_owned` reported
  `Machine/Scripts/scripts.ini sha256=f8fa4009… bytes=158 attrs=Hidden,Archive`
  and `User/Scripts/scripts.ini sha256=ba526db6… bytes=138
  attrs=Hidden,Archive`, **byte-identical to window 19's collection**.
  `gpo_remove_owned` removed GUID `c7d948da-…`.
- The notes carry the invocation arguments with their SHA-256, the run-sheet
  digest, and the setup output (`guid=`).

## r2 — `gpmc.observe_imported_firewall_rules` revision 2, verified

Arguments: `bundle_name=studio-firewall-backup.zip`, `bundle_sha256=3f146885…`,
`stage_name=w20-r2`, `expected_machine_extensions=[{35378EAC-…}{B05566AC-…}]`,
the stub values above, `rule_display_name=StudioFwLane in tcp allow`.
**Exit 0, record `verified`** (`records/w20-r2-record.json`, revision 2).
13 clauses, 15/15 deltas covered, 2 polls / 2 reproductions.

- **The exact exception held.** The only changes were the stub
  (`filedigest.gpttmpl` absent→142 B / `07cba636…`, with `gpttmpl.*` facts
  `[Unicode]`/`[Version]`) and `scope.sysvol_relpaths` moving from the pinned
  pre list to the pinned post list. That post list is the stub, its SecEdit
  parents, and `Machine/Scripts/{Startup,Shutdown}`. Versions, both extension
  lists and `Machine/registry.pol` stayed equal.
- **The input is bound.** The setup manifest in the notes carries
  `backup_id=cb31b508-35ee-54e1-9dad-fb54db071b99`,
  `bundle_sha256=3f146885…` and the imported
  `registry_pol_sha256=25ad9748d1872472abcc7b8992016989c011e9b60fda3fc5dfc53e8b179de081`.
- **The review evidence is bound.** Each `dump save_as` journal entry carries
  the SHA-256 of the file it wrote exclusively (`wp2-inbound-rules.uia.json`
  `66c56f8b…`, `wp2-rule-properties.uia.json` `0163b802…`,
  `wp2-firewall-overview.uia.json` `ac302d3f…`). The inbound list's text cells
  are identical, cell for cell, to window 19's.
- Cleanup removed the owned GUID `c242687d-…` and the owned staging leaf
  (`removed_dir=w20-r2`); requery 0.

## Collection and close

The WP-1 backup (`C:\gpo-studio\wcd-backup\w20-r1`, with its `.wcd-owner`
marker) was collected before the closing revert. The raw zip sha256 is
`6a8b4fb2…` and is held outside the repo. The two INIs and the collection
listing are banked here under `captures/`, with `MANIFEST.sha256` over every
capture. The window then closed with LabMS01 reverted to the new
`domain-joined`, which also removed the staging and backup residue,
bring-up READY, and the canary 10/10 (see `NOTES.md`).

True size: one estate, one run per capability at revision 2. The display
half of WP-2 is still read by a person, and no edit was made, so
persistence through GPME stays unproven.
