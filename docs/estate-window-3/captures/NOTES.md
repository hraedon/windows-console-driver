# R3 raw captures — durable copies

The R3 transaction (folder redirection, 2026-09-04) produced the only
native `fdeploy.ini` / `fdeploy1.ini` this project has read. They lived
only in the gitignored `runs/` tree until 2026-09-06; these are
byte-identical durable copies (hash-verified at copy time), preserved so
the gpo-studio fixture's SHA-256 binding stays checkable.

| file | bytes | SHA-256 |
|---|---|---|
| `r3-fdeploy.ini` | 20 | `5ad8f52071d25165e7e68064ab194ec27a074a3846149ed0689af23e7f7f2d00` |
| `r3-fdeploy1.ini` | 458 | `71f1026180c4a92ed5bcca3366e5d22b80a64931f663fa079ef5d49cd2450800` |

- Record: `docs/estate-window-3/records/r3-window3-record.json`
  (transaction `150db7fe`, `verified`, strict cleanup `remaining=0`).
- Claim row: `docs/claim-registry.md` (R3, 2026-09-04).
- Curated transcript + provenance: gpo-studio
  `tests/fixtures/native-folder-redirection-gpmc/` — the transcript
  test reconstructs these exact bytes and pins both hashes.
- Native SYSVOL paths: `User/Documents & Settings/fdeploy.ini` (empty
  marker) and `User/Documents & Settings/fdeploy1.ini` (the semantic
  policy).
