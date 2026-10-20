# Estate window 20 — machine-password rotation off, checkpoints re-minted, revert proven (2026-10-20)

Window 19 reverted LabMS01 to a `domain-joined` checkpoint from 2026-09-20,
but the member had rotated its machine password on 2026-10-16. The KDC
encrypts service tickets with the current machine key only, so the reverted
member refused every logon ("The credential is invalid") for every account,
and its clock came back 30 days stale. Window 19 repaired the member by hand.
On 2026-10-20 the owner decided: disable machine-password rotation and
re-mint, "if there is not a better way". This window did that and proved it.
The Plan 035 revision-2 reruns that followed in the same window are written up
on the `plan035/wp1-wp2-captures` branch (`plan035-requalification.md`).

## Was there a better way?

The alternatives checked before acting:

- **Keep checkpoints valid without touching rotation.** There is no
  Hyper-V or AD mechanism for this. AD keeps the previous machine password
  for NTLM secure-channel setup, but tickets are always encrypted with the
  current key, and no Hyper-V checkpoint type restores AD's side.
- **`RefusePasswordChange=1` on the DC.** This blocks every member's change
  from one place. However, it is a DC change the DC's own checkpoint does not
  capture, and the members keep retrying and logging failures. The owner
  ruled the DC out of scope.
- **Repair after every revert** (`Test-ComputerSecureChannel -Repair`). This
  only works through a cached-credential session with the NICs disconnected,
  because PSDirect itself is refused, and it rewrites AD on every revert.
  It is kept as the documented fallback, not the fix.
- **Host time sync / w32time.** Host time sync is off on every lab VM, and
  the members point at an unreachable `time.windows.com`. A domain-hierarchy
  w32time source would not correct a 30-day jump promptly either. An explicit
  post-revert `Set-Date` is the deterministic answer.

No better way was found, so the owner's plan was carried out.

## Timeline (UTC)

- **19:53** Pre-flight canary (guard branch, 10 checks; transcripts of every canary and revert in this window are under `canary/`). `member_clock` and
  `machine_password` are new. Exit 3: `machine_password` red, LabMS01
  `pwdLastSet` 18:27 (the window-19 repair) NEWER than checkpoint 09-20.
  The first run also exposed a probe bug: a case-insensitive PowerShell
  variable coerced the parsed time back to a string. It was fixed and
  re-run, and `member_clock` went green.
- **19:56** `DisablePasswordChange=1` set on LabMS01, LabCL01 and LabCA01
  (all three were 0, MaximumPasswordAge 30). LabDC01 and LabCAroot were not
  touched.
- **19:57–19:59 LabMS01.** Guest-initiated restart, which cleared a pending
  servicing reboot and the console session. Verified session-free (LogonUI,
  no user), no pending reboot, rotation disabled, secure channel True, clock
  within 30 s, no `C:\gpo-studio`. The old checkpoint was renamed
  `domain-joined-20260920` (kept), and **new `domain-joined` minted 19:59:29**.
- **20:00 LabCA01.** No session, no residue, no pending reboot, secure
  channel True. The clock was set from host UTC (it read −63 s). Renamed old
  checkpoint to `domain-joined-20260920`, then **minted `domain-joined`
  20:00:41**. This needed ADSI, because CA01 has no AD PowerShell module.
- **20:01–20:03 LabCL01.** Removed a 40-file `C:\gpo-studio` residue left by
  the endpoint/RSOP lanes (those lanes recreate it with `-Force`). Renamed
  `domain-joined` → `domain-joined-20261008` and `user-logged-on` →
  `user-logged-on-20261008`. Then ran WEL's own
  `enable_lab_autologon.ps1 -ReMintBaseline` (dry run first), which disabled
  autologon, restarted, confirmed session-free twice, and **minted
  `domain-joined` 20:02:41**. It then reset `labauto1`, re-enabled
  autologon, restarted into the session, and **minted `user-logged-on`
  20:03:41** with the session live. That is the order WEL's design requires:
  `domain-joined` predates autologon.
- **20:01 Revert proof.** `tools/estate_revert_member.ps1` pre-check passed
  (pwdLastSet 18:27 < checkpoint 19:59, rotation disabled). Restored
  headless, clock −137 s → 0 at once, secure channel True. Then bring-up
  READY (first-try CAD logon) and **canary 10/10, exit 0**.
- **20:07–20:27** Plan 035 revision-2 runs (both `verified`; see the other
  branch).
- **20:27 Closing revert.** The same tool reverted LabMS01 again: pre-check
  passed, clock −1720 s → 0, secure channel True. Bring-up READY, **canary
  10/10 exit 0 at 20:30**. `C:\gpo-studio` is absent and rotation is still
  disabled. **Estate released 20:30 UTC.**

## State left behind

| VM | Checkpoints (UTC) | Rotation | AD pwdLastSet |
|---|---|---|---|
| LabMS01 | `domain-joined` 10-20 19:59 (new); `domain-joined-20260920` (kept) | disabled | 10-20 18:27 |
| LabCL01 | `domain-joined` 10-20 20:02 + `user-logged-on` 20:03 (new); `*-20261008` (kept) | disabled | 10-19 16:30 |
| LabCA01 | `domain-joined` 10-20 20:00 (new); `domain-joined-20260920` (kept) | disabled | 10-19 16:34 |
| LabDC01 | `domain-joined` 10-08 (untouched) | DC default | — |

The old checkpoints are kept, renamed, as instructed: delete them once the
owner is satisfied. **Open hazard, owner's call:** LabDC01's 10-08 checkpoint
predates every member's current machine password. Reverting the DC would roll
AD back behind all three members' keys and break all of them, which is the
same fault from the other side. WEL already treats DC rollback as a
convenience, not a reset path.

## What this window adds to WCD (`estate/password-rotation-guard`)

- **New canary checks.**
  - `member_clock`: guest against host UTC, MaxClockSkew 300 s.
  - `machine_password`: AD `pwdLastSet` must not be newer than the recovery
    checkpoint, and `DisablePasswordChange` must be 1.
  - Both fail closed. A PSDirect refusal now points at the machine key.
- **`tools/estate_revert_member.ps1`, the post-revert time-sync step.**
  It refuses a stale checkpoint unless `-Force` is given, restores with
  `-Confirm:$false`, sets the guest clock from host UTC as soon as PSDirect
  answers, and verifies the secure channel and clock read-only.
- **Bring-up fails fast.** Three consecutive credential refusals are now
  reported as the machine-key fault, instead of waiting out a 600 s boot
  timeout.

True size: one estate. The revert was proven twice on LabMS01 only; LabCL01
and LabCA01 were re-minted but not reverted. The canary watches the estate
file's member, not every lab VM.

## Addendum, 22:00 UTC — superseded checkpoints removed (owner-authorized)

The owner authorized clearing the old checkpoints, "including the 10-08 DC
checkpoint". Removed with `Remove-VMSnapshot -Confirm:$false`, never
`-IncludeAllChildSnapshots` (a removed parent merges into its children):
LabMS01 `domain-joined-20260920`, LabCA01 `domain-joined-20260920`, LabCL01
`user-logged-on-20261008` and `domain-joined-20261008`, and LabDC01
`domain-joined` (10-08). Merges completed within the pass and every VM reported
"Operating normally".

What is left is LabMS01 / LabCA01 `domain-joined` and LabCL01 `domain-joined`
→ `user-logged-on`, all from 2026-10-20 with rotation disabled, plus
LabCAroot `offline-root`, which was out of scope and left in place. **LabDC01
now has no checkpoint**, so the stale-DC-rollback hazard is gone with it.
Canary after the prune: 10/10, exit 0.
