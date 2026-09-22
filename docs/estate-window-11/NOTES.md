# Estate window 11 — the Certification Authority surface (2026-09-21)

The second AD CS surface, and the one the park was declared on top of.
[`surface-sketch-certsrv-officer-rights.md`](../surface-sketch-certsrv-officer-rights.md)
was written the same day on the assumption that the estate was about to go
away and a cold start would resume from it. The estate was still up, all eight
canary checks green with a live console session, so the sketch was used the
way it was meant to be used — as the expensive half already done — and the
window spent its time converting its assumptions into measurements.

The order was deliberately inverted from the onboarding checklist. The sketch
said "author the offline artifacts, perhaps a day, then open a window". With
the rig already booked, recon came first and the artifacts were authored from
measurements instead of from documentation conventions. That is the opposite
of where window 10's certtmpl sheet started, and it is why this sheet's
pre-commit half is measured and only its commit is a prediction.

## What the sketch got right, wrong, and could not have known

| Sketch said | Estate answered |
|---|---|
| The console guest reaches the CA remotely | **Right.** `-ping` alive; and better than assumed: `OpenRemoteBaseKey` from the console guest reads the CA's `CertSvc\Configuration` key including raw `REG_BINARY`, so the oracle needs **no second PSDirect channel** into the CA guest |
| The actuation guest is not the mutation target | **Right**, and it is the observer's problem more than the gesture's — hence `certsrv.ca.host` and `certsrv.ca.observed_from` as separate identity facts, and a fact tree that refuses a read of a CA the plan did not name |
| Recovery is "restore the prior opaque value", i.e. removal | **Right**, and cleanup re-queries absence through both channels, which turns the unanswerable restart question into a recorded residual |
| `certsrv.msc` "may open empty and need a Retarget step" | **Wrong in shape.** It does not open a frame at all. It raises a modal error about the LOCAL CA, because the snap-in resolves the local CertSvc configuration and the console guest is not a CA |
| **The object picker is the top unknown and the likeliest place a first run stalls** | **Avoidable entirely.** The Certificate Managers page does not add managers — its list is populated from the CA's security descriptor and labelled "(configured on the Security tab)". The only control on the page that opens the standard object picker is the *Permissions* Add, which is the SUBJECT restriction. Revision 1 restricts by template only and never opens it |

The last row is the window's best result. The single risk that made this
capability look like a two-window job turned out to sit on a path the
capability does not need to take — and that was only visible by looking at the
page.

## Measured facts

Everything below was read off the live estate on 2026-09-21. Nothing in this
section is inference.

### The snap-in has no command-line target

Four forms, all launched through a clone of the `WCDHelper` task, all giving
the identical modal with the frame behind it still titled
`certsrv - [Certification Authority (Local)]`:

```
certsrv.msc
certsrv.msc "<ca host>"
certsrv.msc /computer="<ca host>"
certsrv.msc /computer "<ca host>"
```

The modal reads *"Cannot manage Active Directory Certificate Services. The
system cannot find the file specified. 0x80070002 (WIN32: 2
ERROR_FILE_NOT_FOUND)"*. Note the coincidence and do not read anything into
it: the same status code is what `certutil -getreg CA\OfficerRights` returns
for the absent value, and the two have nothing to do with each other.

So the launcher takes no target parameter, and the run-sheet declares the
target through the Retarget gesture. An earlier draft of the launcher carried
a `-TargetCa` parameter; it was deleted once the four forms were measured,
because a parameter that encodes a disproven hypothesis is worse than no
parameter — the next reader would assume it worked.

### The frame title is the oracle for the console's own state

```
certsrv - [Certification Authority (Local)]
certsrv - [Certification Authority (<ca host>)]
certsrv - [Certification Authority (<ca host>)\<ca name>]
```

Retarget and node selection are both structurally verifiable from the title
alone. The sheet asserts `(Local)` before the retarget and the CA host after
it: a wizard that silently kept Local fails at the assertion rather than three
steps later inside a property sheet belonging to the wrong machine.

### The scope tree and the results pane are two different menus

This is the surprise of the window, and it cost about forty minutes.

Right-clicking the CA **in the scope tree**:

```
All Tasks  >      View  >      Export List...      Help
```

Right-clicking the same CA's row **in the results pane**:

```
All Tasks  >      Refresh      Properties      Help
```

No Refresh and no Properties on the scope-tree node, and the Action menu
agreed with the context menu, so it is not a context-menu quirk. The repo's
existing idiom said the results pane is *addressable* where the scope tree is
UIA-invisible; on this surface the difference is stronger than addressability.
Only one of the two can open the property sheet at all.

The root node's menu is different again — `Retarget Certification Authority…`,
`View >`, `Export List…`, `Help` — which is how the retarget is reached.

### Two idioms that contradict the general rules, and one that confirms them

- **Context menus SURVIVE the next helper invocation** when addressed by
  window class (`#32768`). The GPMC surface established that popups die when
  the next invocation's console takes foreground; a *class-targeted dump* does
  not change the foreground, so the menu is still there to be dumped and
  screenshotted. That is how all three menus above were read.
- **Their items are UIA-invisible**: a menu dumps as one unnamed `Pane` with a
  rect and nothing else. So a menu is read off a screenshot once, at authoring
  time, and driven blind thereafter.
- **Mnemonics do not work.** `P` for Properties was injected both as a VK
  chord and as `WM_CHAR` and neither selected it; the menu simply stayed open.
  The arrow walk did. Every menu selection on this surface is positional, and
  the position is recorded next to the screenshot it was read from.
- **Timing is part of the composite.** At `delay_ms` 250 the keystroke after
  `Shift+F10` arrived before the menu had rendered and went to the list
  underneath as type-ahead. 600 works. This looks exactly like a mnemonic
  failure, which is how the first two attempts were misread.

### The property sheet

`<ca name> Properties`, opening on **General**. Same UIA-invisible
`SysTabControl32` as the certtmpl sheet, same page-pane rename as the
structural proof of a page switch — and one thing certtmpl's single-row strip
never showed:

> The tab strip is **three rows**, and selecting a tab **moves its row to the
> bottom of the strip**.

So the measured offset from the `General` page pane to the
`Certificate Managers` tab (+109, −246) is valid from the sheet's opening
state only. A sheet that switched pages twice with two static offsets would
land its second click somewhere unpredictable. This one switches once.

### The Certificate Managers page

In the default state (`Do not restrict certificate managers`) every list below
is empty and disabled. Selecting `Restrict certificate managers` populates it:

- **Certificate Managers:** `BUILTIN\Administrators`, `LAB\Domain Admins`,
  `LAB\Enterprise Admins` — exactly the three `Allow Certificate Manager`
  grants that `certutil -getreg CA\Security` decodes, read through a different
  channel. Independent corroboration between the console's rendering and the
  CA's own registry, and the reason the security-descriptor forbid clause is a
  real check rather than a formality.
- **Certificate Templates:** `<All>` — the default, unrestricted.
- **Permissions:** `Everyone` / `Allow`.

So selecting the radio restricts nothing by itself. A restriction is built by
selecting a manager, removing `<All>`, and adding named templates. The
template `Add…` opens `Enable Certificate Templates` — the console reusing its
publication chooser, title and all, listing `<All>` plus the forest's
templates by display name.

### Estate readings

- CA: `LabCA01.ad.labdomain.dev\Lab Issuing CA 01`, the forest's only
  enrollment-services object. `ICertRequest2` alive, 94 ms. CertSvc running.
- `CA\Security`: `REG_BINARY`, 320 bytes, sha256 `e0e944b2…`. Read three times
  across the window through two APIs; identical every time, including after
  the recon cancelled out.
- `CA\OfficerRights` and `CA\EnrollmentAgentRights`: absent. `certutil -getreg`
  returns `0x80070002`; the value-name list (50 values) does not contain them.
- 11 templates published to the CA.
- The console guest is a Domain Admin in `LAB`, which is what makes the remote
  registry read (and the cleanup's write) possible.

## What the recon deliberately did not do

It never crossed the commit point. The flow was driven all the way to the
template chooser and then cancelled out, and the cancel was verified rather
than assumed: afterwards `OfficerRights` was still absent, the `Security`
digest was unmoved, no `mmc.exe` remained, and both probe tasks were
unregistered. That is what makes the sheet's pre-commit half evidence instead
of a story.

## Pre-flight before the first run

Two cheap checks, both of which would have been expensive to skip:

1. **The three new guest scripts were parse-checked under the guest's real
   Windows PowerShell 5.1**, because CI only does that on `windows-latest` and
   a syntax error found mid-transaction costs the window. Two passed
   immediately; `certsrv_launch.ps1` killed the transport outright, which is
   how the dead `-TargetCa` branch (and its backtick-escaped quoting) came to
   be deleted rather than merely doubted.
2. **The observer was run end to end against the live pre-state**, read-only,
   before any gesture. A fail-closed oracle that fails *after* an irreversible
   mutation is the worst possible timing, and this capability's mutation is
   one no checkpoint can reach. It emitted all seventeen facts, none
   unclassified, with `ca.observed_from` = the console guest and `ca.host` =
   the CA — different machines, which is the whole point of the pair — and a
   `security.sha256` matching the independent reading taken hours earlier.

## The runs

**Run 1 — indeterminate, aborted at step 12 of 36, before the commit point.**
Banked at `records/w11-r1-record.json`. Nothing was written: cleanup reported
`present_before=False`, and the abort happened many steps short of the OK that
commits.

It failed selecting the CA's results-pane row, and the reason is worth more
than the failure. Steps 0-11 — launch, dismiss the local-CA modal, retarget,
and assert the retargeted frame — all passed exactly as recon measured them.
The screenshot taken at step 11 shows why step 12 could not work:

> `certsrv - [Certification Authority (LabCA01.ad.labdomain.dev)] (Not Responding)`
> with an empty results pane.

**The frame title gains the CA host the instant Retarget commits, while the
console is still enumerating the remote CA.** So the title proves the
retarget's INTENT and says nothing about readiness, and a sheet that reads it
as readiness resolves its next selector against a pane that has not been
filled — intermittently, because whether it wins is a race with another
machine. Recon never saw this: every round trip there was a separate
invocation minutes apart, so the pane was always long since populated. It took
a run at machine speed to expose it.

The fix is a primitive, not a settle. `wait_foreground` answers "does the
window exist"; nothing in the driver answered "has its content arrived", which
is a question no surface had needed to ask before, because no surface had
drawn its content from another machine. `wait_element` polls for a named
element in the target window, and treats a dump that FAILS as a reason to keep
waiting rather than as a report of absence — the console is at its least
responsive precisely while doing the remote work whose result the sheet is
waiting for. A fixed settle would have been the wrong instrument: the right
delay is whatever the other machine takes today.

**Run 2 — VERIFIED.** `records/w11-r2-record.json`, capability revision 1,
capability digest `c1df0cc3…`. State path prepared -> armed ->
commit_attempted -> verified, converged after 2 polls and 2 reproductions. All
fifteen clauses held, nothing unresolved, and **all ten delta entries were
covered** — the run reports no unclassified change.

### What the commit actually wrote

```
certsrv.officerrights.present        False -> True
certsrv.officerrights.kind           ''    -> Binary
certsrv.officerrights.bytes          0     -> 188
certsrv.officerrights.sha256         ''    -> e4f0ec16...
certsrv.officerrights.certutil_rc    -2147024894 -> 0
certsrv.officerrights.decoded_rows   0     -> 4
certsrv.officerrights.decoded_sha256 ''    -> afc1777a...
certsrv.config.value_count           50    -> 51
certsrv.config.value_names_sha256    99e7865d... -> 01a21547...
```

One 188-byte `REG_BINARY` value, added as the 51st value on a key that held
50, with the security descriptor and the published-template list both unmoved
(the four forbid clauses held).

### The question the sketch could not settle, answered

Whether the CA needs a service restart before a restriction takes effect. It
does not, in either direction, and the answer came free from reading both
channels:

- the `certutil_rc` moved from `0x80070002` to 0 **in the same observation**
  that saw the registry value appear, with four decoded rows;
- after cleanup deleted the value, `absent_registry` and `absent_certutil`
  were both true **in the same observation**, and `residual` was empty.

Had it gone the other way, the `decoded_present` require clause would have
failed with the registry clause passing — and that pair of results would
itself have been the measurement. That is the whole reason the observer reads
two stacks instead of whichever one is convenient.

### The unknown that was flagged before the run

The manager-row type-ahead. It did not stall the run, and the envelope cannot
tell us whether it selected `LAB\Domain Admins` or left the default row
selected, because this revision digests the opaque value rather than parsing
it. So it remains exactly as honest as it was: unresolved, and named in the
capability's own `what_this_revision_deliberately_does_not_claim`. The lead
worth following is `decoded_rows = 4` — `certutil` decodes the value into
named rows, so a revision 2 that parses them could certify WHOSE restriction
it is, and could then prove the selection rather than assuming it.

### The sheet's principal unknown, as stated BEFORE the run

Selecting the manager row. The Certificate Managers list is an unnamed Pane
with UIA-invisible rows, so the step is a label-anchored click onto the first
row followed by type-ahead of the principal. Whether a Win32 listbox does
incremental search across a string containing a backslash
(`LAB\Domain Admins`) was **not** measured in recon. If it does not, the
selection silently lands on the default row — and because this revision
digests the opaque value rather than parsing it, the envelope would not catch
it. That is the one place where a green run would not mean what it appears to
mean, which is exactly why it is written down here before the run rather than
explained afterwards.

## Correction, 2026-09-22 (pre-merge review)

The wrong-CA guard is narrower than three claim sites stated. The observer's
`ca.host` fact is the argument the collector was INVOKED with, echoed back —
so the controller's comparison (reported CA vs the plan's) catches a garbled
or misrouted read, not a plan that itself names the wrong CA: such a plan
drives gesture and oracle alike with the same argument. The guard against a
wrong-CA plan is the run-sheet's targeted-frame selector, which interpolates
`{args.ca_host}` into the frame title and so fails on any other machine's
frame. The docstring, claim-registry row, and this note now carry the
accurate statement; the capability file's `structured_checks` wording is left
byte-identical because the banked records bind its digest — a revision-2
observer could derive the read host independently (for example from the
remote machine's own `ComputerName` registry value) and close the gap for
real.
