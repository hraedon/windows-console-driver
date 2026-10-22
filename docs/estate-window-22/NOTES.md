# Estate window 22 — Plan 035 revision-4 requalification, record-schema v3 (2026-10-21)

The round-3 review (Sol: request-changes; DeepSeek: pass) found that window 21
had retrofitted `provenance.invocation` into record-schema v2. v2 provenance is
closed, so a v2 reader refuses those records. This window answers that, and
the review's other points, then requalified both capabilities so that the
evidence is v3 records. Window 21's records are banked as superseded
(`../estate-window-21/superseded/`).

Timeline (UTC, 2026-10-21): canary **10/10** 04:13 → the changed
`dir_clean_owned.ps1` parse-checked on the guest (0 errors) and the bundle
placed in `C:\gpo-studio\wcd-stage\incoming\` → r1 04:14–04:25 **verified** →
r2 04:25–04:32 **verified** → WP-1 backup collected → LabMS01 reverted with
`tools/estate_revert_member.ps1` (pre-check passed; clock −30841 s → 0;
secure channel True) → bring-up READY → canary **10/10, exit 0, 04:36**.
**Estate released 04:37 UTC.**

## What changed since window 21

- **Record-schema v3** (`docs/transaction-record-schema-v3.json`). v2 is
  restored byte-identical to its window-20 form and frozen. v3 is v2 plus a
  required `provenance.invocation`. The executor mints v3 whenever the
  capability text is supplied. The reader recomputes the arguments' digest
  from the record. Given the run-sheet bytes, it recomputes the run-sheet
  digest and requires the setup script names to be that sheet's setup steps
  in order; the CLI passes the bytes it executed. Setup output is whole, with
  no cap. It travels as LF-split `stdout_lines`, because windows-evidence-lab
  refuses record strings that contain a line break. The WEL reader path is
  branch `wcd-record-v3` (hraedon-labs/windows-evidence-lab), not yet merged.
- **`dir_clean_owned.ps1` has no root parameter.** The root is the literal
  `C:\gpo-studio\wcd-stage`, resolved through the PowerShell provider. The
  behavioural tests run the shipped script under a temporary `C:` PSDrive.
- **Revision 4.** Every `expected_*` argument, and WP-2's bundle digest, is
  pinned by enum to its single banked value (DS N4).
- **The legacy by-name cleanup hazard (DS N1/N3)** is tracked with a closing
  condition as
  [hraedon/windows-console-driver#35](https://github.com/hraedon/windows-console-driver/issues/35).

## r1 — `gpmc.author_scripts_logon_shutdown` revision 4, verified

`records/w22-r1-record.json`: schema v3, 22 clauses, 42/42 deltas. The same
bytes as windows 19–21: 158 B `f8fa4009…` and 138 B `ba526db6…`. The user
list ends `{40B66650-…}`. Arguments SHA-256 `41bb9881…`. The setup manifest
holds `mmc_kill`, `gpo_create` (`guid=e41bcb23-…`) and `gpme_launch`, whole.
The cleanup backup's INIs are banked under `captures/`.

## r2 — `gpmc.observe_imported_firewall_rules` revision 4, verified

`records/w22-r2-record.json`: schema v3, 13 clauses, 15/15 deltas, with the
same exact delta as windows 20–21. `gpo_stage_import`'s whole output is in the
record (`backup_id=cb31b508-…`, `bundle_sha256=3f146885…`,
`registry_pol_sha256=25ad9748…`). The UIA dumps are bound by digest in the
journal and in `captures/MANIFEST.sha256`.

Both records validate with `validate_record(record, capability_text=…,
run_sheet_bytes=…)` against the committed capability and run-sheet files.

True size: one estate, one run per capability at revision 4. The GPME
display remains person-reviewed, and edit persistence is unproven.
