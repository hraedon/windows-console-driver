# Surface sketch: restricted certificate managers (certsrv.msc)

> **SUPERSEDED IN PART, 2026-09-21 — read
> [`estate-window-11/NOTES.md`](estate-window-11/NOTES.md) first.** The park
> this sketch was written for did not happen: the estate was still up, so the
> window opened the same day and converted most of what is below into
> measurement. Two of its conclusions were wrong in ways worth keeping
> visible rather than editing away — `certsrv.msc` does not open "empty and
> needing a Retarget", it raises a modal error about the LOCAL CA and has no
> command-line target at all; and the object picker ranked here as the top
> risk turned out to sit on a path the capability does not need to take,
> because the Certificate Managers page does not add managers. The sketch is
> kept as written, because a record of what an unmeasured surface looked like
> from the outside is worth more than a tidied one — and because the thing it
> got right is the thing it was for: the window started at step 3 of the
> onboarding checklist instead of step 0.

The pre-window half of `surface-onboarding.md`, done for a surface nobody has
driven yet, while the estate was still up. Written 2026-09-21 as the lab goes
into a park, so that a cold start begins at step 3 of the onboarding checklist
rather than step 0 — the sketch is the expensive part of resuming, and it is
the part that decays fastest when it lives only in somebody's memory.

**Everything below is labeled measured or assumed.** The measured facts were
read off the estate on 2026-09-21 through read-only probes; the assumed ones
are the conservative reading of the idioms this repository has already
qualified on other surfaces. A qualification window exists to convert the
second list into the first, and the usual expectation applies: the first run
disproves or goes indeterminate.

## Why this capability, specifically

AD CS has two administration acts with no command-line path. One is template
authoring, qualified in estate window 10 as `certtmpl.duplicate_template`. The
other is the **restriction** of a certificate manager — which templates, and
which subjects, a given officer may act on. That is the Certificate Managers
page of the CA's property sheet, and it is the subject of this sketch.

The boundary is sharper than "the GUI is how people do it", and it was
measured rather than assumed:

| Act | Command-line path | Measured |
|---|---|---|
| Certificate-manager ROLE assignment | `certutil -getreg CA\Security` reads it and decodes it into named role grants (`Allow CA Administrator`, `Allow Certificate Manager`); the value is a 320-byte `REG_BINARY` the matching `-setreg` can write | yes |
| Publishing a template to the CA | `Add-CATemplate` / `Get-CATemplate` / `Remove-CATemplate` | yes |
| Template authoring | nothing in `ADCSAdministration` (13 cmdlets, none touch template objects beyond publication) | yes |
| **Certificate-manager RESTRICTIONS** | **none found**: no cmdlet, and the registry value does not exist to be read | **yes** |

The last row is the interesting one. On an unrestricted CA the values are
absent entirely:

```
certutil -getreg CA\OfficerRights            FAILED 0x80070002 (ERROR_FILE_NOT_FOUND)
certutil -getreg CA\EnrollmentAgentRights    FAILED 0x80070002 (ERROR_FILE_NOT_FOUND)
```

So this is not a setting with a GUI front end. It is a value the console
CREATES, in a serialized form with no documented layout — which means the
usual fallback of "write the bytes yourself" requires reversing the format
first. That is what makes the console the sanctioned authoring tool, and what
makes the capability worth having.

## Three things that make it unlike every capability so far

**1. The actuation guest is not the mutation target.** Measured: the console
guest holds `certsrv.msc` (RSAT-ADCS-Mgmt installed) and reaches the CA
remotely — `certutil -config "LabCA01\<CA name>" -ping` answers
`ICertRequest2 interface is alive (94ms)`. So the gesture can run on the guest
that already carries the banked desktop fingerprint and the helper task, while
the mutation lands in LabCA01's registry.

Every capability to date has actuated and observed the same machine. Here the
record's machine binding names the console, the observer reads a different
guest, and a reviewer has to be able to tell which is which from the record
alone. That is a schema question to settle BEFORE the window, not during it.

**2. Recovery is a third kind.** The GPO capabilities revert a checkpoint;
`certtmpl.duplicate_template` deletes a directory object. This one can do
neither: the mutation is in the CA's own configuration, a checkpoint revert of
the console guest cannot reach it, and reverting the CA guest is expensive
even now that it carries a baseline.

Recovery is therefore **restore the prior opaque value** — and because the
pre-state is the value being *absent*, cleanup is really "remove the value the
gesture created", re-queried for strict absence by name. The general shape
(capture the prior value and its digest before the gesture; afterwards restore
it and prove the digest returned) is the one most likely to generalize: plenty
of GUI-only settings are opaque values in a config store.

**3. A behavioral oracle is cheaply available, for the first time on this
surface family.** A restriction is a claim about what an identity may do, so it
can be corroborated by *doing it*: leave a request pending, attempt approval as
the restricted officer, observe the refusal. The registry digest says the
configuration changed; the CA's own behavior says it means what it claims. The
claim registry already has a `behavior` category for rows of that kind. It
costs extra setup (a template that holds requests for manager approval, and a
submitted request), so it is a revision-2 candidate rather than a precondition.

## The five artifacts

1. **Profile `certsrv-server2025.toml`.** Actions: open the console, connect to
   the CA, open its property sheet, select the Certificate Managers page, add
   an officer, set the restrictions, and the OK that commits. Classify the OK
   as the commit point and everything before it `reversible_pre_commit`, as
   the template sheet does.
2. **Capability `certsrv.restrict_certificate_manager`, revision 1.** Arguments
   name the CA config string, the officer principal, and the restriction. The
   claim ends at the configuration existing with the certified digest —
   publication, issuance, and what the restriction *does* stay out of it, the
   same discipline that kept window 10's claim honest.
3. **Run-sheet.** Setup `mmc_kill` + a new `certsrv_launch` guest script,
   cloned from the helper task the same way the other launchers are —
   **including the `ExecutionTimeLimit` override**, or the console inherits
   five minutes to live and dies mid-arc.
4. **Observer `officerrights`.** The guest transports presence, byte length and
   sha256 of `OfficerRights` from the CA guest — never the bytes — and the
   controller recomputes, exactly as the security descriptor is handled on the
   template surface. Facts: `officerrights.present`, `.bytes`, `.sha256`, plus
   `ca.security_sha256` as a forbid scope, because the base role assignment is
   NOT what this capability edits and must be shown not to move.
5. **Qualification run.** Expect the arc.

Envelope sketch: require presence true, non-zero length, and a digest
different from the pre-state; forbid the CA security descriptor and the
published-template list from moving; derive the absent → present transition.
Remember window 10's lesson — every fact the observer emits and that changes
must be referenced by some clause, or the run is disproven for bookkeeping
reasons that say nothing about the gesture.

## What is NOT known, ranked by how much it could cost

1. **The object picker.** The Add button on the Certificate Managers page
   almost certainly opens the standard Windows object picker ("Select User,
   Computer, Service Account, or Group"). That is a control family this
   repository has never driven — it is not an MMC pane, it has its own
   `Check Names` round trip, and it can resolve asynchronously. Assumed, not
   measured, and the most likely place a first run stalls.
2. **Whether the console opens already connected to a CA.** `certsrv.msc`
   launched with no argument may open empty and need a Retarget step with its
   own dialog. Unmeasured. Worth resolving with one recon launch before
   authoring the sheet.
3. **Whether the CA needs a service restart for a restriction to take effect.**
   Unmeasured, and it decides whether the behavioral oracle can run in the same
   transaction or needs a restart between gesture and probe.
4. **Dialog facts generally**: page name, control names, whether the
   restrictions live in a sub-dialog. Assumed to follow the property-sheet
   shape that window 10 measured — which, if it holds, means the page-pane
   rename trick transfers directly and the tab strip is the same unnamed
   `SysTabControl32` with no UIA tab items.

## Estate facts measured 2026-09-21

Read-only, on the live estate, so a resumed session does not re-derive them:

- Console guest: `certsrv.msc` **and** `certtmpl.msc` both present,
  `RSAT-ADCS-Mgmt` installed; reaches the CA remotely (`-ping` alive, 94 ms;
  `-CAInfo name` answers).
- CA guest configuration key holds `Security` (REG_BINARY, 320 bytes) and no
  `OfficerRights` or `EnrollmentAgentRights` value.
- `ADCSAdministration` exports 13 cmdlets: AIA and CDP management, template
  publication, role-service backup/restore, attestation confirmation. Nothing
  that authors a template or restricts an officer.

## Cost, honestly

The offline artifacts are perhaps a day: profile, capability, run-sheet,
observer, tests. The window is the unknown, and the object picker is the reason
it could take two rather than one. Window 10 landed in two runs plus a recon
pass only because the idioms were already measured — and the object picker is
the first control family since the WMI-filter dialog that this repository has
no measurement for at all.

If the lab is woken for this, the park's own wake-up work comes first: re-issue
the CA's CRL before anything trusts it, run the canary, and confirm the estate
is the one these records were made against.
