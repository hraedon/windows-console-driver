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
| `certtmpl.duplicate_template` | 1 | Pending first qualification; surface prep authored 2026-09-17 (first non-GPO surface -- certtmpl.msc on a Server 2025 member console; dialog facts unobserved, validity-period arg form the open question the run must answer, the Parm2 arc again) | -- |

The eight GPO-surface capabilities all have clean lab qualification evidence at
their current revision. The migration-table capability requalified at revision 2
in estate window 6 (2026-09-05), which was the last row reading "pending" until
the WMI-filter row below was authored and qualified in the same session
(2026-09-15, estate window 7). The WMI-filter capability is the first whose
gesture runs in the GPMC main console rather than the GPME editor. Its
revision-1 qualification is also the first obtained through seven recorded
iterations (five indeterminate, one disproven, then verified) — the full
disprove-and-refine arc the qualification process is designed around. The
certtmpl row above is the pending one today, and the first surface outside the
GPO family: its mutation lives in the forest configuration partition, where a
guest checkpoint revert cannot reach it, so its recovery is logical
(directory-side) rather than a checkpoint revert.

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
