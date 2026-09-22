# Capability qualification status

Capability behavior, record-format qualification, and historical evidence are
separate claims. A banked record remains immutable evidence for the capability
definition that produced it; changing the current capability does not silently
upgrade that record.

| Capability | Current revision | Current qualification | Banked evidence |
|---|---:|---|---|
| `setup.author_migration_table` | 2 | Qualified; the parent-directory blast-radius clause evaluated and satisfied, clean cleanup | `estate-window-6/records/r1-v2-record.json` (revision-1 evidence remains at `estate-window-4/records/r1-v1-record.json`) |
| `gpmc.author_scripts_ps_order` | 1 | Qualified; exact envelope, clean cleanup | `estate-window-3/records/r2-psorder-window3-record.json` |
| `gpmc.author_folder_redirection` | 2 | Qualified; exact marker and payload envelope, clean cleanup | `estate-window-3/records/r3-window3-record.json` |
| `gpmc.author_scripts_entry` | 2 | Qualified; exact entry envelope, clean cleanup | `estate-window-4/records/r2-v2-record.json` |
| `gpmc.author_admin_template_machine` | 2 | Qualified; side-specific path envelope, clean cleanup | `estate-window-4/records/r5m-v2-record.json` |
| `gpmc.author_admin_template_user` | 2 | Qualified; side-specific path envelope, clean cleanup | `estate-window-4/records/r5u-v2-record.json` |
| `gpmc.author_registry_security` | 2 | Qualified; fixed three-key experiment, six distinct screenshots, clean cleanup | `estate-window-4/records/r4-v2b-record.json` |
| `gpmc.author_wmi_filter` | 1 | Qualified; exact msWMI-* representation incl. the measured Parm2 wire format, SOM-container blast radius frozen at +1, clean cleanup | `estate-window-7/records/w7-record.json` |
| `certtmpl.duplicate_template` | 1 | Qualified; exact validity duration, blast radius frozen at one added object, clean cleanup with independent strict-absence confirmation. The same qualified bytes also verified through WEL's hosted lane (estate window 12) | `estate-window-10/records/w10-r2-record.json` (the pre-commit abort that preceded it is at `estate-window-10/records/w10-r1-record.json`); WEL-hosted: `estate-window-12/records/w12-r1-record.json` |
| `certsrv.restrict_certificate_manager` | 1 | Qualified; the restriction value certified through two independent read channels, blast radius frozen at one added configuration value, clean cleanup with absence confirmed through both channels | `estate-window-11/records/w11-r2-record.json` (the pre-commit abort that preceded it is at `estate-window-11/records/w11-r1-record.json`) |

The eight GPO-surface capabilities all have clean lab qualification evidence at
their current revision. The migration-table capability requalified at revision 2
in estate window 6 (2026-09-05), which was the last row reading "pending" until
the WMI-filter row below was authored and qualified in the same session
(2026-09-15, estate window 7). The WMI-filter capability is the first whose
gesture runs in the GPMC main console rather than the GPME editor. Its
revision-1 qualification is also the first obtained through seven recorded
iterations (five indeterminate, one disproven, then verified) — the full
disprove-and-refine arc the qualification process is designed around. The
certtmpl capability was the pending row until estate window 10 (2026-09-20)
qualified it in two runs, and it was the first surface outside the GPO family:
its mutation lives in the forest configuration partition, where a guest
checkpoint revert cannot reach it, so its recovery is logical (directory-side)
rather than a checkpoint revert.

The certsrv row qualified in estate window 11 (2026-09-21) in two runs, and
it reached that point differently from every row before it. Its five artifacts
were authored from a recon pass that measured the surface BEFORE anything was
written — the launch-time
error modal, the absence of any command-line target for the snap-in, the
Retarget wizard, the results-pane-versus-scope-tree menu split, the three-row
tab strip, and the Certificate Managers page's full control set — and then
cancelled out, proven afterwards by `OfficerRights` still absent and the CA's
security-descriptor digest unmoved. So its pre-commit half was measured rather
than assumed, which is the opposite of where certtmpl's sheet started, and it
showed: run 1 reached step 12 of 36 before failing, and run 2 was verified.

The two channels the observer reads answered the question the sketch could not
settle off-window. **The CA adopts the restriction immediately and caches
nothing**: `certutil -getreg CA\OfficerRights` moved from `0x80070002` to rc 0
with four decoded rows in the same observation that saw the registry value
appear, and after cleanup deleted the value it returned to failing in the same
observation that saw the value-name list lose it. No CertSvc restart is
involved in either direction, and the `residual` field is empty rather than
tolerated. Had the answer gone the other way, the `decoded_present` require
clause would have failed with the registry clause passing, and that pair of
results would itself have been the measurement — which is why both channels
are read rather than whichever one is convenient.

Transaction-record v1 records the capability ID and run-sheet name, but not a
capability revision or content digest. Until a future record schema adds an
immutable binding, qualification notes must state the revision explicitly and
must not infer it from the current file at review time.

“Qualified” in this ledger means the named revision completed the banked estate
experiment. Since WI-L5 the runtime enforces ONE declared dependency — the
prepared-surface `uia_digest` banked in the profile's
`[[surface_fingerprints]]` is compared at prepare and a mismatch refuses
before setup (the ledger rows above were qualified with that same prepared
context, byte-identical across windows 2–7). Every other selector dependency
(`ui_language`, `binary_version`, per-dialog fingerprints) remains declared
but not runtime-enforced, and no per-dialog fingerprint is banked yet. These
records must not be generalized to a changed estate.
