# Capability qualification status

Capability behavior, record-format qualification, and historical evidence are
separate claims. A banked record remains immutable evidence for the capability
definition that produced it; changing the current capability does not silently
upgrade that record.

| Capability | Current revision | Current qualification | Banked evidence |
|---|---:|---|---|
| `setup.author_migration_table` | 2 | Pending requalification; adds an enforced parent-directory blast-radius clause | Revision-1 evidence: `estate-window-4/records/r1-v1-record.json` |
| `gpmc.author_scripts_ps_order` | 1 | Qualified; exact envelope, clean cleanup | `estate-window-3/records/r2-psorder-window3-record.json` |
| `gpmc.author_folder_redirection` | 2 | Qualified; exact marker and payload envelope, clean cleanup | `estate-window-3/records/r3-window3-record.json` |
| `gpmc.author_scripts_entry` | 2 | Qualified; exact entry envelope, clean cleanup | `estate-window-4/records/r2-v2-record.json` |
| `gpmc.author_admin_template_machine` | 2 | Qualified; side-specific path envelope, clean cleanup | `estate-window-4/records/r5m-v2-record.json` |
| `gpmc.author_admin_template_user` | 2 | Qualified; side-specific path envelope, clean cleanup | `estate-window-4/records/r5u-v2-record.json` |
| `gpmc.author_registry_security` | 2 | Qualified; fixed three-key experiment, six distinct screenshots, clean cleanup | `estate-window-4/records/r4-v2b-record.json` |

Six current GPMC UI capabilities have clean lab qualification evidence. The
revision-2 migration-table capability requires a new estate run; its revision-1
record remains historical evidence and is not silently upgraded. The window-2
R2/R4/R5 records likewise remain revision-1 historical evidence.

Transaction-record v1 records the capability ID and run-sheet name, but not a
capability revision or content digest. Until a future record schema adds an
immutable binding, qualification notes must state the revision explicitly and
must not infer it from the current file at review time.

“Qualified” in this ledger means the named revision completed the banked estate
experiment. It does not mean that the current runtime checked a binary/hash/UI
fingerprint compatibility baseline; selector dependencies remain declared but
not runtime-enforced. These records must not be generalized to a changed estate.
