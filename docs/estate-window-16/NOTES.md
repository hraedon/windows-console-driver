# Estate window 16 — the baseline gate on every shipped surface (2026-10-09)

The rollout window 15 set up: the prepare-time baseline gate it proved on
gpmc is now banked on the other two shipped surfaces, each through one
verified qualification run. `profiles/certtmpl-server2025.toml` and
`profiles/certsrv-server2025.toml` each carry the two `[[baseline_values]]`
rows (ui_language `en-US`; mmc.exe FileVersion
`10.0.26100.32860 (WinBuild.160101.0800)`), banked from the records this
window produced. The values were not re-measured here — they were measured
in window 15's r1/r2 refusal probes on the same guest and the same console
session this window drove, and certtmpl.msc and certsrv.msc run inside the
same `mmc.exe` binary those probes versioned. What this window adds is the
verification: both runs armed with the banked rows and answered
banked==observed on all three prepare gates.

## Pre-flight

The estate stood exactly as window 15 left it: LabMS01 Running with the
`claude` console session Active, `WCDHelper` Ready, checkpoint present.
Canary **8/8 green, exit 0, first try**. Both profile edits were validated
to parse and load (`wcd.profiles.load_profile` answered with both rows)
BEFORE any run, per the discipline window 15's incidental finding asked for
— a profile that fails parsing is a raw traceback, so the check happens
first, not after.

## Run r1 — certtmpl.duplicate_template (revision 1)

`wcd --estate local/estate.toml exec-transaction --capability
capabilities/certtmpl.duplicate_template.json` with
`source_template=Computer`, `template_name=zz-wcd-certtmpl-w16`,
`validity_units=3`, `validity_period=Years`, `domain_dns=ad.labdomain.dev`
— the window-10 qualified argument set, a fresh zz- name. **Exit 0, record
`verified`** (banked at `records/w16-r1-record.json`, schema v2, digest
binding matches the committed revision-1 bytes), transaction
`f2f1ea61-c386-4aff-aeb9-64f2d89ce34d`. 13 clauses satisfied, 11/11 deltas
covered, converged after 2 polls / 2 reproductions. All three prepare gates
appear in `provenance.notes`:

```
surface fingerprint gate: banked 9193a3dfa818... observed 9193a3dfa818...
baseline gate: ui_language banked en-US observed en-US
baseline gate: binary_version C:\Windows\System32\mmc.exe banked 10.0.26100.32860 (WinBuild.160101.0800) observed 10.0.26100.32860 (WinBuild.160101.0800)
```

The observed transition matches window 10's shapes: container 33 → 34,
`expiration_100ns` 946080000000000 (3 × 365 days, the prediction that
window 10 turned into a measurement, holding again), overlap 42 days, and
the duplicate carries `schema_version 2` (presence-only clause; window 10's
duplicate carried 4 — a fact the observer emits, claimed as observed, not
predicted). Cleanup ran strictly: `remaining=0`,
`removed=zz-wcd-certtmpl-w16`, `unregistered=WCDLaunchCertTmpl`.

**Post-state** (re-queried after the run, read-only, by the operator): the
Certificate Templates container answers **33 objects, 0 `zz-*` of any kind,
0 `Copy of …` orphans**, with the Public Key Services parent answering its
eight children (AIA;CDP;Certificate Templates;Certification
Authorities;Enrollment Services;KRA;NTAuthCertificates;OID) as the control
that the zero is real. **Independence caveat, stated plainly:** this re-query
rode LabMS01 — the run's own guest — because every channel that would have
read from OUTSIDE the member hung: host-relayed PSDirect into LabDC01,
LabCL01, and LabCA01 each timed out (the idle-guest VM-bus wedge window 13
named, now affecting every guest except the constantly-driven member), and
this workstation has no network route into the lab directory (the prod/lab
split; LDAP 389/636 unreachable, though lab DNS resolves). The check is a
fresh directory read that shares nothing with the record's own claims, but
it is **member-side, window-12-grade independence, not the CL01-style
verification windows 13/14 achieved**. If the next window wakes a sibling
guest, re-running it from there would close the gap.

## Run r2 — certsrv.restrict_certificate_manager (revision 2)

The window-14 argument set exactly: `ca_host=LabCA01.ad.labdomain.dev`,
`ca_name=Lab Issuing CA 01`, `manager_principal=LAB\Domain Admins`,
`template_name=User`. **Exit 0, record `verified`** (banked at
`records/w16-r2-record.json`, schema v2, digest binding matches the
committed revision-2 bytes), transaction
`764ad6b4-3f71-4743-8a09-eccdd2e5132f`. 16 clauses satisfied (including
the revision-2 `certsrv.ca.directory.member` derivation), 10/10 deltas
covered, converged after 2 polls / 2 reproductions. The same three prepare
gates:

```
surface fingerprint gate: banked 9193a3dfa818... observed 9193a3dfa818...
baseline gate: ui_language banked en-US observed en-US
baseline gate: binary_version C:\Windows\System32\mmc.exe banked 10.0.26100.32860 (WinBuild.160101.0800) observed 10.0.26100.32860 (WinBuild.160101.0800)
```

The commit reproduced the windows-11/14 transition byte-for-byte: a 188-byte
`REG_BINARY` OfficerRights (`e4f0ec16…`, decoded sha `afc1777a…`,
`certutil_rc` −2147024894 → 0, 4 decoded rows) as the 51st value on a key
that held 50. Cleanup ran strictly: `remaining=0`,
`present_before=True / removed=True / absent_registry=True /
absent_certutil=True` with an empty residual, `unregistered=WCDLaunchCertSrv`.

**Post-state** (same member-side channel and caveat as r1): the CA's
configuration key holds **50 values with `OfficerRights` and
`EnrollmentAgentRights` both absent**, `certutil -getreg` answers
0x80070002 through the CA's own RPC surface, and the `Security` digest is
`e0e944b2…` (320 bytes) — **byte-identical to the readings windows 11 and
14 took** — so the blast radius stayed exactly the one registry value.

## Banking and claim size

Both profiles' `banked_from` rows point at the records this window banked,
whose `provenance.notes` carry banked==observed for each row; the profile
comments say the values were measured by window 15's refusal probes and
verified here. With this window, **all three shipped surfaces (gpmc,
certtmpl, certsrv) gate on both observable dependency kinds plus the
prepared-context digest** — a run on any of them now refuses before setup
on a guest whose UI language, mmc.exe version, or prepared desktop differs
from the qualified one.

Still true and still unclaimed: per-dialog fingerprints remain banked
nowhere (no qualification window has captured them as standalone facts);
`dpi`, `theme`, `os_build` remain declared-only kinds the parser refuses to
bank values for. And the window's independence caveat bounds the post-state
evidence: both post-state checks re-read the estate freshly but from the
member, not from an untouched guest. True size: ONE estate, ONE session
lineage (the same LabMS01 console session windows 10–15 drove), three
surfaces, five banked baseline rows in total, two verified records. It is
not portability — it is the mechanism that would refuse one.
