# Estate window 3 — R3 and PowerShell-order qualification

Date: 2026-09-04 (America/Phoenix)

This window closed the remaining R3 Folder Redirection gap and re-qualified
the stronger R2 PowerShell-order variant against LabMS01. Both final
transactions reached `verified`; their envelopes were satisfied with no
unresolved or unclassified changes, and strict cleanup found zero remaining
evidence GPOs.

## Banked records

| Lane | Record | Result |
|---|---|---|
| R3 Basic Documents Folder Redirection | `records/r3-window3-record.json` | **verified** — 19 clauses, 44 covered delta entries, cleanup `remaining=0` |
| R2 scripts + explicit PowerShell-first order | `records/r2-psorder-window3-record.json` | **verified** — 24 clauses, 41 covered delta entries, cleanup `remaining=0` |

The records do not contain the lab password. Screenshots remain under the
gitignored `runs/` workspace because the JSON records carry the semantic UI
journal and independent post-state evidence needed for review.

## Measured facts and driver changes

- The helper console is a transient foreground self-shadow during requests.
  Commit guards now compare stable session/user/desktop identity, then validate
  the explicit target HWND with a fresh targeted dump/focus operation.
- Every mutating run-sheet action now receives a fresh commit-context check,
  not only the first commit crossing.
- Screenshots are targeted to the live sheet HWND. Malformed screenshot base64
  becomes a contained run-sheet error, so the transaction still records and
  cleans up.
- Server 2025 Folder Redirection presents its compatibility warning as a nested
  pane in the Documents Properties window. The measured flow must click `Yes`.
- Basic Documents redirection writes a tiny `fdeploy.ini` marker with no
  sections or entries. The semantic policy is `fdeploy1.ini`: three sections
  and four entries, including `version=100`, `Flags=1021`, and the authored
  `FullPath`.
- The PowerShell-order control initially exposes the value `Not configured`,
  not either final option. Selecting it with one composite click + type-ahead
  invocation yields the visible value `Run Windows PowerShell scripts first`
  and the independent `StartExecutePSFirst=true` fact.

## Completed follow-on

The missing `docs/capability-schema-v0.json` and versioned transaction-record
schemas now validate every capability, all immutable legacy records, and newly
generated v1 records in CI. New records keep the five-key WEL wire envelope and
carry their v1 stamp inside `provenance`; historical evidence remains
unchanged behind an explicit compatibility path.

The next estate action is to re-mint the baseline so the proven console/helper
state becomes the deterministic starting point for subsequent lanes. The next
local design task is to let record schema v1 survive another capability window
before defining the deferred MCP/agent surface against it.
