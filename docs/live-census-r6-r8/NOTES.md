# R6/R8 live census — execution notes, verbatim copy

Copied 2026-09-06 from mvmcc03:/home/itadmin/gpo-studio-evidence/inbox/r08-gpo-anatomy/NOTES.md
(SHA-256 476bc218f0f1587b8e52b82c6e8deb20cd0b2c0acd349b3e385b945c2eb63bde).
The `docs/manual-evidence-requests.md` referenced below is gpo-studio's.
The ten data artifacts themselves are committed in gpo-studio
tests/fixtures/live-domain-census/ (each SHA-256 in its provenance).

# R8 — execution notes (2026-09-02)

Executed read-only from the local machine (user `merrittp`, non-domain-admin)
per `docs/manual-evidence-requests.md` R8. Artifacts in this directory; GPO
display names were never read and appear nowhere in the artifacts
(`displayName=` stripped from every GPT.INI copy).

## Results

- **`gpos_with_wmi_filter`: 3** — three production GPOs carry `gPCWQLFilter`
  associations. WMI-filter association is one of `publication.py`'s six
  planned step kinds (`associate_wmi_filter`), so the plan anticipates it;
  the value of this count is that the association is *real* here and can be
  modelled from a live example when needed.
- Three diverse GPOs censused (`gpo{1,2,3}-attributes.csv`,
  `gpo{1,2,3}-sysvol.csv`, `gpo{1,2,3}-GPT.INI`):
  - **gpo1** — policy-heavy: `Registry.pol` (9.4 KB), `GptTmpl.inf`,
    `Preferences\ScheduledTasks\ScheduledTasks.xml`, `comment.cmtx`. A genuine
    multi-CSE SYSVOL tree authored by Windows.
  - **gpo2** — packed version `0x0002000A` → user counter 2, machine counter
    10. Direct live-domain confirmation that the two 16-bit counters both
    move in practice (the R5 `gpt.ini` question's production corroboration).
  - **gpo3** — `Version=0` with a populated folder: a GPC whose SYSVOL exists
    but whose version counters never moved (created, never edited).

## Estate-structure findings beyond the scripted census

1. **SYSVOL ↔ AD reconciliation (folder-name join, authoritative):**
   30 GPC-named folders (excluding `PolicyDefinitions`) ↔ 29 AD objects found
   by DN ↔ **26 objects of class `groupPolicyContainer`**. The filtered
   census (26) is complete.
2. **One orphaned SYSVOL folder** — a folder with no AD object at all.
   Classic deleted-GPO residue; harmless but it exists.
3. **Three DN-addressable objects in the Policies container that carry GPC-style
   `{GUID}` CNs but are NOT class `groupPolicyContainer`** — each still has a
   SYSVOL folder. Whatever created them did not produce a normal GPC. (The
   domain's former life as this project's validation forest is a plausible
   explanation; the objects predate the production regime.)
4. **Methodology finding for the queue documents:** GUID-as-string comparisons
   and lowercase-GUID UNC paths behaved inconsistently under PS 5.1 in this
   environment (Guid-object `-eq` string comparisons failed; lowercase-GUID
   `Test-Path` on the DFS path returned False where the uppercase path
   returns True). Folder-name/DN joins are the reliable join; any scripted
   census should avoid Guid-object string comparison entirely.

## Sanitisation

Attributes CSVs contain attribute names + populated/kind only, by
construction. SYSVOL CSVs contain relative structural paths + sizes; scanned
for identifier-shaped file names: none. GPT.INI copies carry `[General]` +
`Version=` only. The GPO count (26) and folder counts are weak estate
structure; fine here, not fixture material.
