# Estate window 10 — the certificate-template surface, first qualification (2026-09-20)

The window window 9 had to abandon. Its blockers were estate provisioning, and
the estate repo closed all three before this window opened: `certtmpl.msc` is
installed on the console guest (RSAT-ADCS), the forest holds 33 default
certificate templates, and `Lab Issuing CA 01` is published under Enrollment
Services. Verified read-only before anything was touched, not assumed.

Canary green 8/8 on the first pass (DC clock within 66 s of the guest, ticket
minted, helper task ready, console session unlocked).

## The defect that would have cost the window, found before the gesture

`certtmpl_collect.ps1` — the observer's guest half — asked Active Directory for
`msPKI-Validity-Period` and `msPKI-Validity-PeriodUnits`. Neither exists in a
Server 2025 schema:

```
error=One or more properties are invalid.  Parameter name: msPKI-Validity-Period
```

The observation then fails closed. Correct behaviour, ruinous timing: the
oracle runs AFTER the gesture, and this capability's mutation lands in the
forest configuration partition, which a guest checkpoint revert cannot reach.
The window would have produced a mutated directory and no observation of it.

What the directory actually holds, read off a built-in template:
`pKIExpirationPeriod` and `pKIOverlapPeriod`, octet strings carrying an 8-byte
little-endian signed FILETIME interval, stored negative because it is relative
time. **There is no units attribute at all** — the years/months/weeks/days
choice the console offers is a rendering of that single duration. `CN=Machine`
(displayName "Computer") carries `00 40 39 87 2E E1 FE FF` = 315360000000000
hundred-nanosecond units = exactly 365 days.

This is the third instance of one estate-wide shape: **an AD name that is
legacy, invented, or merely plausible is a filter-shaped hole** — the query
returns nothing and looks like an empty container rather than a wrong question.
The estate repo hit it as `certTemplate` versus `pKICertificateTemplate` two
days earlier.

## The second defect, measured mid-window: the console had five minutes to live

The console is launched by cloning the `WCDHelper` scheduled task's XML and
swapping its Actions subtree. The clone also inherits its **Settings**, whose
`ExecutionTimeLimit` is `PT5M` — a bound sized for a helper invocation that
answers in seconds. Task Scheduler applies it to the console the task launches,
so `mmc.exe` was terminated five minutes after launch, mid-flow, with nothing
in the surface's behaviour to explain it (`LastTaskResult` 267014 =
`SCHED_S_TASK_TERMINATED`).

It presents as a window that "vanished": the enumeration stops listing the
dialog, the sheet's live-target pops to nothing, and the next dump silently
describes the helper console instead. All three launchers (`certtmpl_launch`,
`gpmc_launch`, `gpme_launch`) shared it, so every GPO-surface qualification ran
under the same five-minute ceiling and passed only by being fast enough. The
launch clone now sets `PT1H` — bounded, far outside any transaction, and the
console still ends where it always did, in cleanup's `mmc_kill`.

## What the surface actually looks like

Measured by live UIA dump, replacing the documentation-convention guesses the
sheet was authored from:

| Question the sheet asked | What the estate answered |
|---|---|
| Console window title | `Certificate Templates Console` |
| Does duplicating a V1 template show a schema-version dialog? | **No.** `Properties of New Template` opens directly |
| Which page does it open on? | **Compatibility**, not General — the whole reason run 1 found no name field |
| How are the tabs addressed? | They are not: the strip is an unnamed `SysTabControl32` (automation id 12320) with **no tab items in the UIA tree** |
| Does Ctrl+Tab move the page? | **No** — measured with the dialog foreground and a click landed in it first |
| How are the edits named? | By their **content** (`Copy of Computer`, `1`, `years`), never by their label |

Two consequences shaped the sheet. The page is reached by a click anchored to
the named page pane and offset to the tab, and that click verifies itself
structurally: **the page pane is renamed to the selected tab**, so every later
selector resolves only if the page switch landed. And because the edits are
content-named, every field is label-anchored with a measured offset — the first
selectors in this repo that bind DPI, now declared as such in the profile.

The General page, measured: `Template display name:` and `Template name:` edits
(both pre-filled `Copy of Computer`), a `Validity period:` row of amount edit +
units combo, a `Renewal period:` row of the same shape, and two checkboxes.
Display name is set FIRST, because the console auto-fills the template name
from it until that field is edited by hand — setting the CN first would have
the console overwrite the very name this capability certifies.

## The runs

**Run 1 — indeterminate, aborted at step 8, before the commit point.** The
sheet reached the property dialog and then found no `Template name` field,
because the dialog was showing Compatibility. Nothing was written: the abort
happened three steps short of the OK that commits. Banked at
`records/w10-r1-record.json` — a run that stops before its commit point is
still evidence about the surface, and this one is what sent the session into
recon.

**Run 2 — VERIFIED.** `records/w10-r2-record.json`, transaction
`61800ec4-0da5-4440-b6b3-2d2da5ba506d`, capability revision 1, capability
digest `a9169bf3…`. All thirteen clauses held, no unresolved clause, and
**every one of the eleven delta entries was covered** — the run reports no
unclassified change. State path: prepared → armed → commit_attempted →
verified, converged after 2 polls and 2 reproductions.

### The prediction under test became a measurement

The envelope asserted `expiration_100ns == validity_units * 365 * 864000000000`
on the strength of a built-in template's 1-year period decoding to exactly 365
days. The console, asked for **3 Years**, wrote:

```
certtmpl.target.expiration_100ns  ""  ->  946080000000000
```

= 1095 days = 3 × 365, exactly as predicted. The clause stands as written,
now with a measurement behind it rather than an inference.

The rest of the observed transition, for the record: the container went
33 → 34 objects, its names digest moved, `other_names_sha256` did NOT (the
forbid clause held), and the new object carries schema version 4,
`cert_name_flag` 134217728, `key_flag` 16842752, overlap period 42 days
(the console's default 6 weeks, untouched by this capability).

**The blast radius is exactly one object**, and that is a structural claim
rather than a count: the other-names digest freezing while the total rises by
one means no unrelated template was renamed, removed, or added beside ours.

### Cleanup, and the independent check

Cleanup ran all three steps: `mmc_kill` (remaining=0),
`certtmpl_remove` (**removed=zz-wcd-certtmpl-01**), `task_unregister`
(unregistered=WCDLaunchCertTmpl).

Then the directory was asked directly, in a separate session that shares no
channel with the driver: **33 objects, target absent, no `zz-*` template of any
kind, and no orphaned `Copy of …` template.** The estate is as it was found.

## Claim size

One estate, one host build, one UI language, one source template (`Computer`,
whose CN is `Machine` — display name and CN differ, and the console's list
shows the display name). The capability's claim ends at the template object
existing in the directory with the certified shape: **nothing here published a
template to a CA or issued a certificate**, and the `Publish certificate in
Active Directory` checkbox was left as the console set it.

The descriptor is certified by digest, not content — which ACEs a duplicate
inherits from its source is a separate question this revision does not answer.
Schema version, name flag and key flag carry presence claims only, for the same
reason: they are values the console chooses, not values the arguments predict.

## Estate left as found

Console session unlocked and healthy, `mmc.exe` gone, the cloned launch task
unregistered, the Certificate Templates container back to its 33 built-ins. No
guest was rebooted and no checkpoint was restored: this capability's mutation
lives in the configuration partition, so its recovery was logical (the
directory-side removal above) exactly as the capability declares.
