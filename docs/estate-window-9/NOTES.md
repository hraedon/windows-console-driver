# Estate window 9 — recovery diagnosis + operator tooling (2026-09-17)

No capability lanes ran. This window qualified the two operator tools that
came out of the window-8 assessment (the Kerberos-sensitive canary check and
the bring-up/teardown glue) and closed the checkpoint question window 8 left
open ("unrestorable estate-current on LabMS01, root cause unknown").

## The "unrestorable checkpoint" is solved: a cmdlet seam, not VMMS

**`Restore-VMSnapshot` without `-Confirm:$false` throws a bare
NullReferenceException when run in a headless WinRM session.** The cmdlet's
confirmation path dies before VMMS is ever contacted — failing restores
produce zero VMMS events. With `-Confirm:$false`, the identical checkpoint
restores instantly, unprimed, on every VM tried:

- MS01 `domain-joined` restored while Running (twice — the second as
  remediation, below).
- DC01 `domain-joined` restored while Running.
- DC01 fresh-minted `zz-restore-probe-20260917`: checkpoint → restore →
  remove, all OK.

Window 8's failing scripts (`window8-vhdx-acl-fix`,
`window8-vmms-restart-restore`) and this window's first five repro attempts
all omitted the flag; WEL's `revert_environment` has always passed it, which
is why WEL restores kept working through the same period. **The recovery
posture was never broken.** Consequences:

- Any restore script must pass `-Confirm:$false` (or run where a prompt can
  render). The window-8 "unrestorable" line is corrected in that window's
  NOTES.
- The VHDX ACL repair was a red herring. The `20790 "Failed to set security
  info"` VMMS events fire on successful restores too (twice per VM before
  the 16:24/16:45/16:55 successes on 9/15) — they are non-fatal noise, not
  a diagnostic.
- The window-8 shape stands independently: a standard-checkpoint revert of
  a powered-off guest lands it Saved; restoring a Running guest to a
  standard checkpoint resumes it running.
- `estate-current-20260905` was deliberately left unrestored (superseded by
  the re-mint baselines; restorability is proven by mechanism).

## The degraded live MS01 state (observed, then reverted away)

Before the remediation restore, MS01's live state (the window-8 close state)
was unhealthy:

- The console logon-looped: 4624 type-2 successes alternating with 1326/4625
  failures with no input at the console; `qwinsta` session 1 stuck in
  `Conn`; the desktop appeared (Server Manager visible in a framebuffer
  capture) and then vanished without any 4647 logoff.
- **Two `claude` profiles existed**: `C:\Users\claude` and
  `C:\Users\claude.LAB` (the latter stuck `Loaded=True` with no session).
  This is the local-vs-domain `claude` collision whose estate-side fix
  (deleting the local account, 2026-09-05) **did not survive into this
  estate generation** — the re-mint's reset path restores baselines that
  predate the deletion.
- Windows licensing sits in notification mode (LicenseStatus 5, recurring
  slui 8198 events).

Not fully root-caused: the state was reverted away by the `domain-joined`
restore, after which the same CAD key-injection logon that had failed
worked first try. Follow-up for the next re-mint: mint from baselines that
postdate the local-claude deletion, or delete the local account as part of
the re-mint itself.

Also observed: CL01's 9/5 checkpoints (`pre-refresh-20260905`,
`estate-current-20260905`) still list in its tree but their AVHDX files are
gone (metadata outlived disks, from the window-8 re-mint merges). Harmless
until something tries to restore them; estate-side grooming is the owner's
call, not this repo's.

## Operator tools, live-qualified this window

**Canary `kerberos` check** (the window-8 recommendation it implements):

- Green estate: canary 8/8, `DC clock within 1s; klist minted
  krbtgt/ad.labdomain.dev (rc=0)`.
- Deliberate +10 min DC skew: **exactly the kerberos check reddened**
  (`DC clock is 601s ahead of the guest (Kerberos MaxClockSkew 300s):
  Kerberos/GPMC will fail while NTLM paths stay green -- seed the DC clock
  from the host (Set-Date), nltest /dsregdns, restart NetLogon`) while all
  seven NTLM/DNS checks stayed green — the window-8 trap signature as a
  pre-flight line. The bring-up tool's clock step then repaired it
  (601s -> 24s) and the canary went 8/8 green again.
- ADSI trap measured en route: a `DirectoryEntry` to the DNS server address
  binds **anonymously** from the PSDirect network-logon context (one
  rootDSE property, no `currentTime`) under every AuthenticationFlags
  value tried; `Get-ADRootDSE` (the RSAT module the `domain_account` check
  already uses) authenticates as the caller and returns `currentTime` as a
  DateTime. The probe reads time that way.

**`tools/estate_bringup.ps1`** — four live runs, from Off and from drift:

- The DC clock trap reproduced for real: after this window's DC restore,
  delta was **-170,785 s** (checkpoint-era time). The tool's step 2
  repaired it live (Set-Date from host UTC + `nltest /dsregdns` + NetLogon
  restart -> delta 24 s).
- The CAD key-injection logon established the console session on the
  healthy (post-restore) state, first try.
- The helper two-hop deploy + context smoke went green after two fixes the
  live runs surfaced: Server 2025's `nltest /dsgetdc` success marker is
  `The command completed successfully` (no `Found DC:` line exists to
  match), and the guest helper directory must exist before `Copy-Item`
  (it creates no remote intermediate directories).
- Known weakness, deliberately not fixed this window: the injection types
  blind after a fixed 6 s CAD wait. On the degraded state it mistimed (one
  4625 then a session that never settled); on the healthy state it worked.
  Follow-up: verify-then-type against the host-side thumbnail before each
  field.

**`tools/estate_teardown.ps1`**: guest-initiated shutdowns (`shutdown.exe
/s` over PSDirect, never `Stop-VM`), MS01 + DC01 to Off, exit 0.

## Estate left as found

DC01 and MS01 Off (via the teardown tool); CL01 and CAroot Off (untouched
all window); LabCA01 Running (untouched). `local/estate.toml` (gitignored)
now names `checkpoint_name = "domain-joined"` (the current baseline — the
old value pointed at the superseded 9/5 set) and `dc_vm_name = "LabDC01"`.

## Claim size

One estate, one host build, one UI language. The `-Confirm:$false` seam is
a Hyper-V PowerShell module behavior on THIS host's build (measured, not
enumerated across builds); the kerberos check catches the clock trap, not
every Kerberos failure mode.
