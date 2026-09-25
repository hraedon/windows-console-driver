# Estate window 13 — the composition corrections proven live (2026-09-25)

Window 12's two code corrections — WEL's `wait_ready` resolving its probe
identity from the backend config instead of the hardcoded enum (WEL PR #36,
`721688c`), and `estate_bringup`'s member-clock step 4/7 (WCD PR #20,
`8db0c84`) — were offline-qualified on 2026-09-24 with their live proof
deliberately deferred to this window. This window ran that proof: the same
certtmpl lane re-executed end to end under a **domain_operator-only** backend,
then bring-up over the reverted member, then the canary — all green, first
try, with no seam surprises.

The window also unblocked on credentials: the `svc_claude` host-control
secret that was dead domain-side on 2026-09-24 (kinit refused it estate-wide;
~7 auth attempts then stopped to protect the lockout counter) was refreshed
by the owner, and both domain credentials were owner-verified before this
session began. First canary after the refresh: 8/8 green.

## One run, verified — under one role label

Run id `e5d87d33-5cbb-4ebb-bea7-6f6fb19ce0e6`, transaction
`70cd570d-142d-453e-9d75-1307d067211b` (11:18:44Z–11:23:32Z), the same
qualified capability bytes as windows 10–12 (digest `a9169bf3…`, revision 1).
Record banked at `records/w13-r1-record.json`: state `verified`, 13 clauses
satisfied, 0 unresolved / 0 violated / 0 unclassified, all 11 deltas covered,
converged after 2 polls and 2 reproductions, cleanup `remaining=0` /
`removed=zz-welab-certtmpl-01`, and the prepare-phase context capture again
carries `uia_digest 9193a3df…` — the WI-L5 prepared-desktop fingerprint, third
window running.

The identity seam, re-pointed before the run (backups `*.pre-w13` on
mvmcc02): the WEL backend now declares **only** `[identity.domain_operator]`
(capability `cred:lab-guest-bootstrap`, env names unchanged), the lane's
`identities` and the transaction step's `identity` say `domain_operator`, and
the mvmcc02 WCD checkout's `local/estate.toml` carries
`identity_role = "domain_operator"` — the same label the workstation checkout
always used. The convergence wart from window 12 (one estate answering two
role labels depending on which checkout drives it) is retired: **one role
label end to end.** The `wait_ready` step answered under that backend in
2.6 s (journal: started 11:18:47.70Z, passed 11:18:50.26Z) — the exact step
that refused under the pre-#36 code with no `guest_bootstrap` identity
declared.

The directory was then asked directly, in a session that shares no channel
with the driver — PSDirect into **LabCL01** (a guest the lane never touched),
explicit-credential LDAP to LabDC01: **33 template objects, zero `zz-*` of any
kind, target absent.** (The window-12 re-check rode a member-side channel;
using CL01 removes even the member from the verification path.) The scenario's
`revert_environment` had restored the member to `domain-joined`, leaving it
Running, session-less, and — as measured within minutes — **404,644 s
(4.68 days) behind the host**: the checkpoint-era clock, precisely the
condition step 4/7 exists for.

## estate_bringup, all 7 steps, first run after the revert

```
[2/7] dc-clock:  within tolerance (delta -66s; MaxClockSkew 300s); no repair
[4/7] member-clock: delta -404644s exceeds MaxClockSkew 300s -- repairing (Set-Date from host UTC)
       after=2026-09-25 11:32:04Z  delta_s=2
[5/7] member-domain: locator answers from LabMS01 (NetBIOS domain LAB)
[6/7] console-session: established after injection (claude, console, Active, 11:32)
[7/7] helper: task WCDHelper present (state=Ready)
estate-bringup: READY (exit 0)
```

The member-clock repair is the live proof for PR #20's step: the same probe,
tolerance, and tz-safe `Set-Date` as the DC step, and `Set-Date` alone —
no dsregdns, no NetLogon restart — followed by an in-tolerance locator answer
and a first-try CAD-injection logon (the third consecutive first-try on this
estate). The closing canary, run from mvmcc02 against the re-pointed
`identity_role = "domain_operator"` estate file: **8/8 checks green, exit 0**
— including `kerberos` (klist mint over the just-repaired clock) and
`console_session` (active, unlocked).

## Estate facts measured this window

1. **LabDC01's VM-bus PSDirect channel is wedged while its directory services
   are healthy.** Direct `Invoke-Command -VMName LabDC01` from the host hung
   (>150 s, no answer) twice, while the same minute the DC answered Kerberos
   (canary `klist` mint) and LDAP (the CL01 re-check) normally. The DC has
   been up 5d4h untouched; this is the third idle-guest channel wedge on this
   estate (CA01's stale machine channel, CL01's pre-repair channel), and like
   those it is a channel fact, not a service fact. Nothing in the lane needs
   DC PSDirect; the working independent-directory channel is a healthy guest
   plus explicit-credential LDAP. If a future window needs DC PSDirect, budget
   a reboot or channel repair first.
2. **mvmhyperv01 cannot reach the lab directory by name.** Explicit-credential
   LDAP from the host to `LabDC01.ad.labdomain.dev` fails "the server is not
   operational" — the prod host's DNS does not resolve the lab domain, which
   is the designed prod/lab split, but it means host-side directory re-checks
   are not a thing; ride a guest.
3. **Re-confirmed the hard way:** PSDirect to lab guests must be VM-bus
   (`-VMName`). A WinRM `-ComputerName` hop from a host session into the lab
   domain crosses the no-trust boundary (Kerberos 0x80090311 — or, from the
   workstation's shaping of the same call, an indefinite hang). The canary
   never makes this mistake; hand-written probes have now made it twice.

## Estate left as found

All lab guests Running, CAroot Off, member clock repaired and console session
Active (11:32Z), helper present, canary green end-to-end from both the
workstation (pre-run) and mvmcc02 (post-run). Operator artifacts on mvmcc02:
`local/run-w13-r1-live.json` + empty `.stderr` (the full run JSON incl.
journal), `local/backend.toml.pre-w13`,
`local/scenarios/certtmpl-lane-live.json.pre-w13`, and
`/projects/windows-console-driver/local/estate.toml.pre-w13` — the re-pointed
files are the live ones, and the lane JSON now ships `domain_operator`
identities.
