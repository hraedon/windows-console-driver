# Estate window 17 — the window-16 post-state re-read from outside the member (2026-10-16)

The independence caveat window 16 stated plainly is closed. Its two post-state
checks rode LabMS01 — the runs' own guest — because every untouched-guest
channel hung; this window woke a sibling guest and re-read both post-states
from OUTSIDE the member, with the member not even powered.

## Estate found state, and what the window changed

Found (2026-10-16): LabMS01, LabDC01, LabCL01, LabCAroot all Off; LabCA01
Running with ~2d4h uptime (the host rebooted ~2026-10-14 and only LabCA01
auto-started). The canary was not run: its checks are member-centric
(`guest_psdirect` targets LabMS01) and this window deliberately never powered
the member. LabDC01 + LabCL01 were booted for the reads and shut down again
after; LabCA01 was left Running exactly as found; LabMS01 stayed Off
throughout — the strongest independence statement this estate can make about
a post-state read is now available: the guest the lanes drive could not have
served it.

## Channel facts measured this window

1. **A boot unwedges the guest VM-bus channel.** Host-relayed PSDirect into a
   freshly-booted LabCL01 answered first try (11:44Z), and PSDirect directly
   into LabCA01 answered as well — LabCA01's channel is fresh since the
   2026-10-14 host-side reboot even after two days idle. The window-13
   idle-guest wedge is per-channel idle state, not per-guest identity: DC01,
   CL01 and CA01 all hung for window 16, and every guest answers after a boot.
2. **The transport shape matters.** A one-shot
   `Invoke-Command -ComputerName <host>` relay carrying the guest
   PSCredential in `-ArgumentList` never completed the nested PSDirect (ten
   minutes of retries, twice); the production `session_repl.ps1` shape — one
   persistent host WinRM session with the nested PSDirect opened inside it —
   answered first try. Hand-written probes should reuse the runner, not the
   one-shot form.
3. **Remote registry from CL01 into CA01 is service-timer flaky.** The
   committed collector's `OpenRemoteBaseKey` succeeded at 11:44Z; an
   identical call minutes later answered "unauthorized" (the RemoteRegistry
   service's on-demand trigger idling out). PSDirect into the CA with a local
   read is the stable form.
4. **A locked console refuses graceful `Stop-VM`** ("the machine is locked
   and cannot be shut down without the force option", 0x800704F7);
   `Stop-Computer -Force` from inside PSDirect shuts the guest down cleanly.

## r1 re-read — the Certificate Templates container (w16-r1 post-state)

Explicit-credential LDAP from LabCL01 (a guest the w16 lane never touched) to
LabDC01, 2026-10-16 11:44Z, one level under `CN=Certificate Templates`:

- **33 objects; names digest
  `535c6544aa8e40b3e77c2f0ec38d4e1a5adcefeab5b7a1de2cbaabdb4f8e60f0` — the
  exact bytes of the w16-r1 record's banked pre-run digest** (the envelope
  delta's `before`), so the container's name list is byte-identical to what
  window 16 verified against, re-read through a channel that shares nothing
  with that run.
- 0 `zz-*` of any kind; 0 `Copy of …` orphans; `zz-wcd-certtmpl-w16` absent.
- The Public Key Services parent answers its eight children (AIA;CDP;
  Certificate Templates;Certification Authorities;Enrollment Services;KRA;
  NTAuthCertificates;OID) — the control that the zero is real.

## r2 re-read — the CA configuration (w16-r2 post-state)

The committed `tools/guest_scripts/officerrights_collect.ps1` run ON LabCL01
(remote registry + `certutil` RPC into LabCA01) — the same reviewed collector
the runs themselves used, transported to a guest the lane never touched:

- `officerrights.present=False`; `officerrights.certutil_rc=-2147024894`
  (0x80070002 — the CA's own RPC surface agrees the value does not exist).
  `EnrollmentAgentRights` is absent from the same value-name list.
- `security.bytes=320`, `security.sha256=
e0e944b288920b3851b7e5e522e31fd49ccb339522d7e603f38cbaff572f57cf` — the
  `e0e944b2…` reading windows 11/14/16 took, banked here as a full digest for
  the first time, still byte-identical.
- `published.count=11`; the forest still publishes exactly one enrollment
  object (`ca.directory.hosts=LabCA01.ad.labdomain.dev`).

**One delta, named: `config.value_count=51` where window 16 banked 50** (names
digest `c4cbfea7…` vs `99e7865d…`). Offline leave-one-out over the 51 names —
read directly on LabCA01 by PSDirect, local registry, no remote-registry
dependency: removing exactly `CRLAttemptRepublish` reproduces the banked
50-name digest `99e7865d…`, so that single value is the whole difference.
`CRLAttemptRepublish` is written by the CA service when it attempts CRL
republication; LabCA01's CertSvc restarted when the host rebooted it on
2026-10-14 (the 2d4h uptime), between window 16 and this one. No w16 claim is
touched — OfficerRights absent through both channels, the Security digest and
the published set all hold — the drift is service behavior on reboot, not a
lane mutation, and it is disclosed here rather than silently tolerated.

## Claim size

This window banks no new capability claim. It upgrades the independence grade
of two banked windows' post-state evidence from "member-side,
window-12-grade" to untouched-guest (the window-13/14 grade) with the run's
own guest not even powered, and it names the one post-w16 service-side drift.
One estate, one session, two re-reads, zero mutations, zero records minted.
