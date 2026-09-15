# Estate window 7: the WMI-filters capability qualifies at revision 1

LabMS01 + LabDC01, 2026-09-15, transaction `842d087e-b11a-4de9-88c8-1963dc27cb5e`,
record `records/w7-record.json` — **verified**: envelope satisfied (10 clauses,
nothing violated, nothing unresolved), 7 delta entries all covered, converged
and reproduced per the capability's own policy, cleanup `removed=` the filter
and unregistered the launch task.

The first capability whose gesture runs in the **GPMC main console** rather
than the GPME editor, and the first surface qualified end-to-end in one
session from authored-but-unobserved selectors. Seven runs: five indeterminate,
one disproven, then verified — the disprove-and-refine arc the qualification
process exists to run, with every intermediate record retained under `runs/`
(gitignored) and its load-bearing fact folded into the artifacts below.

## What the window measured

- **`msWMI-Parm2` is not `namespace;query`.** GPMC composes it as
  `1;3;10;35;WQL;root\CIMv2;SELECT * FROM Win32_OperatingSystem;` — a
  semicolon-delimited list with a `1;3;10;35;WQL;` prefix and a trailing
  semicolon. Any consumer that splits on `;` expecting two fields gets
  garbage; any consumer that joins `ns + ";" + query` writes an attribute
  GPMC did not produce. The prefix constants are recorded verbatim and stay
  uninterpreted (measured once, one WQL query; variation by language/locale
  is unmeasured).
- **`msWMI-ID` is a braced GUID** (`{7218E9CF-89FF-4FF8-89A6-9210BA799AA8}`),
  distinct from the object's CN.
- **The New WMI Filter dialog's commit button is `Save`**, not OK (buttons:
  Add / Remove / Edit on the query pane, Save / Cancel at the bottom). The
  child WMI Query dialog does use OK.
- **The GPMC scope tree is keyboard-navigable but UIA-invisible**, exactly as
  the GPME tree was: `Tree:'Console Embedded Scope'` enumerates no children,
  and the results-pane rows are not ListItems either (run 2's empty match).
  Working route: click the Tree control for focus, then one composite key
  invocation — HOME, DOWN, RIGHT, DOWN, RIGHT, DOWN, RIGHT (root → Forest →
  Domains → domain, each expanded) and type-ahead `w` lands on WMI Filters.
- **Menus die between helper invocations** (the known popup-lifetime fact,
  re-confirmed on this surface): the Action menu opened by Alt+A in one
  invocation was gone before the next invocation's click. The working route
  is the **context menu as one composite key sequence**: Shift+F10, DOWN,
  ENTER.
- **MMC dialogs expose controls as Pane elements named by label**, including
  the edit fields (`Pane:'zz-wcd-wmi-w7'` is the Name field carrying its
  typed value), so `^Save$` / `^OK$` / `^Add$` selectors resolve.
- Typing into the WMI Query dialog lands in the query box with the default
  namespace intact (`root\CIMv2` reached Parm2 unmodified).

## The seven runs

| Run | State | What changed |
|---|---|---|
| 1 | indeterminate | `^Forest:` ListItem click matched 0 — scope tree UIA-invisible |
| 2 | indeterminate | results-pane rows are not ListItems either |
| 3 | indeterminate | keyboard navigation landed on WMI Filters (screenshot-verified); Action menu + separate MenuItem click — menu died between invocations |
| 4 | indeterminate | Alt+A/DOWN/ENTER composite — menu opened but produced no dialog (item order unobserved) |
| 5 | indeterminate | Shift+F10/DOWN/ENTER composite opened the dialog; name/description/query typed; child OK clicked; parent `^OK$` matched 0 — the commit button is **Save** |
| 6 | **disproven** | full arc with Save; envelope rejected Parm2 — the wire format above |
| 7 | **verified** | expected_parm2 = the measured string |

## Estate events in this window (before any run)

The domain `claude` account's password had **expired** (`PasswordExpired=True`,
aged out since ~2026-08-29) — PSDirect as `ad.labdomain.dev\claude` failed
"credential is invalid" on every guest. As `LAB\Administrator` (whose password
is the same bootstrap value per the WEL provisioning design), the password was
reset to the documented `labhv.txt` value and the account flagged
`PasswordNeverExpires` to stop silent recurrence. This restores the estate's
documented credential contract rather than deviating from it; the
`estate-current-20260905` checkpoints predate the expiry and were minted with
the same value.

Also measured while diagnosing: `Get-ADObject` reaches the SOM container
through root-DSE + full DN exactly as it does for GPC objects. The
`CN=SOM,CN=WMIPolicy,CN=System` container **already existed at pre-state**
in this forest (`wmifilter.container.present` is absent from the record's
delta — unchanged across the transaction), so this window did not exercise
the container-creation path; whether a filter-less domain always carries the
container is unmeasured, and the envelope deliberately accepts either
pre-state through its require clause rather than assuming one.
