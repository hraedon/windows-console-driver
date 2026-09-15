# Estate window 6 — the migration-table capability requalifies at revision 2

Date: 2026-09-05 (America/Phoenix)

One transaction, for one reason: `setup.author_migration_table` was the only
row in `docs/capability-qualification.md` reading **Pending requalification**.
Its revision-2 definition adds an enforced parent-directory blast-radius clause
that no run had ever evaluated, so the capability was shipping a check whose
behaviour on a real estate was unknown, and the matrix said so honestly. That
row is now closed.

## Result

- `records/r1-v2-record.json`: **verified**, schema v1, transaction
  `a6a4bef9-462a-461a-8764-835becd6e8b1`.
- Envelope **satisfied** with nothing violated and nothing unresolved: the five
  revision-1 `require` clauses (present, parses, `mapping_count == 4`, GPMC
  namespace, first mapping type) **plus** `forbid[0]
  migtable.parent.unexpected_entry_count`, the revision-2 clause, evaluated for
  the first time.
- State machine ran the full path — `prepared → armed → commit_attempted →
  verified` — crossing `commit_migration_table_save`, and converged after
  **2 polls, 2 reproductions**, meeting the capability's own
  `convergence.reproduce = 2`.
- Cleanup ran and returned `removed_dir=C:\gpo-studio\manual\r01-migtable-v2`.
- Recovery guard satisfied: checkpoint `estate-current-20260905` asserted
  present at prepare, on all five estate VMs.

## What the new clause actually asserts

`forbid[0]` resolves to `Split-Path -Parent` of `migtable_path` and counts every
entry in that directory other than the migration table itself. So it says: the
COM save wrote **one file and no others**. Revision 1 could not have caught a
`GPMgmt.GPM` save that scattered temporary or sidecar files beside its output,
because nothing looked. Revision 2 looks, and on Server 2025 the answer is zero.

That is a small claim, and it is worth being precise about its size: it bounds
the blast radius of THIS capability's own gesture. It is not a statement about
GPMC's file behaviour in general, and it does not generalise to the interactive
authoring capabilities, whose gestures touch SYSVOL and AD.

## Independence

Unchanged from the revision-1 row in the claim registry, and restated because a
requalification is a new claim rather than a re-run of an old one: authoring is
COM (`GPMgmt.GPM`) on the guest, transport is PSDirect, and the XML parse and
every envelope predicate are controller-side. The three channels remain
separate.

## Estate state

LabDC01, LabMS01, LabCL01, LabCA01 running; LabCAroot off. No GPO was created
and no AD object was touched — this capability is setup-only by construction,
which is what makes it the cheapest possible requalification and why it was the
right one to run first.
