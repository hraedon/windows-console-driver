# Second estate window — 2026-09-03: the engine comes online

Session goal (per the predecessor's plan): promote the first window's ad-hoc
scripts in `C:\temp\lab` into real wcd operations, then run the remaining
Sitting-A evidence requests through the engine. Everything below happened
against LabMS01 (Server 2025, checkpoint-backed, driver-development mode).

## What was built (windows-console-driver)

- `wcd` CLI (`src/wcd/cli.py`, entry point in pyproject): `exec-transaction`
  (the WEL seam: plan on stdin, record on stdout), `ensure-console`
  (wake/unlock + 4800/4801 audit + reboot gate), `console-state`.
- `tools/session_repl.ps1` + `src/wcd/transport.py`: persistent REPL
  transport (fresh host session per request; nested PSDirect with open-retry
  and teardown protection).
- `src/wcd/console_ops.py`: lock classification, host-side credential unlock
  (Ctrl+Alt+Del → per-char VK typing → Enter), lock-audit read,
  reboot-readiness gate.
- `src/wcd/runsheets.py`: the run-sheet interpreter — guest/host scripts,
  wait_foreground (window-enum based), dumps, hwnd-targeted clicks with
  focus-forcing, composite `keys` (click + chords + per-char text in one
  invocation), `shot`, commit crossings wired to the transaction machine.
- `src/wcd/exec_transaction.py`: the executor — ensure-console → recovery
  check → setup → pre-oracle → prepare/arm → gestures → converge + reproduce
  → envelope → cleanup → record `{state, verdict, envelope_result, events,
  provenance}`. Every terminal path emits a record and cleans up.
- Observers: `gpttmpl_inf.py` (R4), `fdeploy_ini.py` (R3), the migration-table
  collector (R1); `scripts_ini_raw` absence handling; AD-identity via root-DSE
  DN in three psl snippets; per-file SYSVOL facts exclude observer-covered
  files; scope enumeration scoped to the GPO's own directory.
- Capabilities + run-sheets: `setup.author_migration_table`,
  `gpmc.author_scripts_entry` (re-run), `gpmc.author_registry_security`,
  `gpmc.author_admin_template_machine` / `_user`,
  `gpmc.author_folder_redirection`. Profile extended with the dialog-action
  vocabulary.
- `local/estate.toml` (gitignored) configures host/VM/credentials-by-env.

## Run results (records under `runs/`, gitignored)

| Lane | State | Note |
|---|---|---|
| ensure-console + audit | — | unlocked; 4800=0 since armed; reboot ready |
| R1 migration table | **verified** | GPMC namespace/shape ≠ migration.py — silent no-op CONFIRMED |
| R2 scripts entry (re-run) | **verified** | first GUI transaction through the engine |
| R5 machine edit | **verified** | machine half +1, Registry CSE machine-side |
| R5 user edit | **verified** | user half +1 (raw 0→65536); `Registry.pol` + `comment.cmtx` |
| R4 propagation codes | **verified** | propagate=0, do-not-allow=1, replace=2; quoted-CSV; UTF-16LE |
| R3 folder redirection | indeterminate | dialog flow partially mapped; fdeploy.ini not yet authored; estate clean |

## R3 — what remains (bounded, for the next window)

The Documents Properties dialog opens and dumps cleanly. The Setting combo
("Not configured" → Basic) and the conditional Root Path edit need one more
qualification pass: the closed-combo DOWN variation committed *something* (a
`User/Documents & Settings` directory appeared) but fdeploy.ini was not
written and the envelope rightly disproved. Next step is screenshot-per-step
iteration on exactly that combo, then the Settings-tab flags. Everything else
in the flow (navigation, Action-menu open, OK, cleanup) already works.

### Correction (2026-09-03, after commit 0c28257)

A reviewer flagged the run table above as inconsistent with this section and
with the committed record `records/r3-record.json` (`"state": "disproven"`),
and recommended re-labelling the table row **disproven**. The recommendation
predates a same-day evaluator change (commit 0c28257) and is now moot: the
table row is the classification that survives current semantics.

- The record was labelled under the pre-tri-state evaluator, where a clause
  that could not be evaluated counted toward violation. Under the current
  evaluator every clause resolves to satisfied / violated / unresolved, and
  any unresolved clause caps the assertion at **indeterminate**. Replaying
  R3's envelope under current semantics yields exactly that: `require[1]` /
  `require[2]` reference the absent `post.fdeploy` subtree (unresolved).
- The grounded violations stand as characterized observations and are
  unaffected: the redirect directory (`User/Documents & Settings`) was
  created, `fdeploy.ini` was not written, and the user-half version never
  bumped.

So the record's `disproven` label is an artifact of the pre-tri-state
evaluator; the correct current classification of that envelope is
indeterminate. This note is the correction — the original prose, the run
table, and the committed record are left as written. The run-sheet defect the
run exposed (the Setting combo never actually changed) is unaffected: it is a
driver-development finding, independent of how the envelope outcome is
labelled.

## Decisions

- **Baseline re-mint: yes, recommended at the end of the next window, after
  R3/R9 land.** The estate's working state now includes autologon,
  `InactivityTimeoutSecs=0`, no screensaver lock, and the WCDHelper task.
  Re-minting (`join_lab_domain.sh -ReMint` per the WEL runbook) makes every
  future lane start from that deterministic state instead of re-fighting the
  console. Cost: one reset + two mints. Risk if deferred: every lane pays the
  ensure-console and drift tax forever.
- MCP layer: still deferred (the primitive is now stable enough to design
  against, but the runbook + CLI are the interface for one more window).
- R10 stays blocked on the `export.py` product change; R7 needs a DC console;
  R11 needs the operator go-ahead.

## Measured facts that changed the tools

- PSDirect session teardown NRE (see `docs/surface-onboarding.md`).
- Helper console self-shadow → hwnd-targeted orientation everywhere.
- Dialog focus resets across invocations → composite `keys` with in-invocation
  clicks; per-character typing for autocomplete combos.
- The scope_forbid enumerator originally walked the whole Policies directory
  (every GPO's tree) — containment was unsatisfiable by construction; now
  walks the GPO's own directory.
- `Get-ADObject -Identity` does not resolve bare/braced GUIDs on Server 2025;
  the DN (root-DSE derived) is required.
- gpedit `/gpobject:"domain\{guid}"` errors out; the LDAP-path form works.
- GPM COM constants and the migration-table namespace (see claim registry).
