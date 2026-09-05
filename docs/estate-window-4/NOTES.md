# Estate window 4 — first native transaction-record v1

Date: 2026-09-04 (America/Phoenix)

The setup-only R1 migration-table capability was executed after the v1 record
contract and capability execution-boundary validation landed. This is the
first real-estate transaction emitted natively as v1 rather than read through
the historical compatibility path.

## Result

- `records/r1-v1-record.json`: **verified**.
- Capability validation completed before transport construction.
- The record retained the five top-level WEL keys and carried
  `provenance.$schema = docs/transaction-record-schema-v1.json` with
  `schema_version = 1`.
- The envelope satisfied 5 clauses over 18 covered delta entries.
- Convergence completed after 2 polls and 2 reproductions.
- Cleanup removed `C:\gpo-studio\manual\r01-migtable-v1`; no GPO was created.
- The record was checked for lab-credential leakage before banking.

The compatibility tests now validate the eight unchanged window-2/window-3
artifacts as v0 and this record as v1, each against its corresponding Draft
2020-12 schema.

## Revision-2 capability qualification

After an independent artifact review separated historical state evidence from
current capability qualification, the four revised capabilities were rerun
through the native v1 boundary. All four reached `verified`, reproduced twice,
had no violated, unresolved, or unclassified clauses, and completed strict
cleanup with zero remaining evidence GPOs.

| Capability | Record | Envelope result |
|---|---|---|
| Scripts entry revision 2 | `records/r2-v2-record.json` | 23 clauses; 38 covered deltas |
| Administrative Template machine revision 2 | `records/r5m-v2-record.json` | 12 clauses; 13 covered deltas; machine-only `Registry.pol` |
| Administrative Template user revision 2 | `records/r5u-v2-record.json` | 12 clauses; 13 covered deltas; user-only `Registry.pol` |
| Registry Security revision 2 | `records/r4-v2b-record.json` | 18 clauses; 53 covered deltas; fixed three-key mapping; six distinct screenshots |

Each record was checked for lab-credential leakage before banking. The
Registry Security rerun also demonstrates that its formerly failing backup and
strict-removal cleanup path is now clean.

An earlier clean state run, `records/r4-v2-record.json`, reused two screenshot
names across the three entries, so later captures overwrote earlier ones. Its
observer evidence remains valid, but it is retained only as historical state
evidence. The `r4-v2b` rerun is the qualification artifact, and a static
run-sheet test now rejects duplicate screenshot names.
