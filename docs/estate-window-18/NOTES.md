# Estate window 18 — the three context kinds measured and banked (2026-10-16)

The baseline gate's vocabulary grew this morning: `dpi`, `theme` and
`os_build` became observable kinds (the helper context reports the session
system DPI, the Personalize light/dark switches packed raw, and
`CurrentBuildNumber.UBR`), joining `ui_language` and `binary_version`. This
window measures all three live on the estate and banks them on the gpmc
surface — the window-15 pattern, repeated for the new kinds, on the branch
that makes them observable.

## Pre-flight

Estate found Off (as window 17 left it). `estate_bringup -RedeployHelper`:
DC boot + clock within tolerance (−63 s), member boot + clock (−2 s /
0 s), locator green, **the CAD-injection logon needed two attempts** (the
first typed account/secret/enter but no session appeared; the retry
established claude/console/Active at 12:32Z — the first first-try miss on
this estate since the injection tool existed). The helper was force-redeployed
(two-hop, principal LAB\claude) so the guest runs the context action that
reports the new fields; the smoke request answered. Canary **8/8 green,
exit 0**.

## Runs r1–r3 — the deliberate-mismatch refusal probes (the measuring)

The probe discipline is window 15's: bank deliberately wrong values in the
working-tree profile, run the qualified `gpmc.author_wmi_filter` revision 1,
and let the prepare refusal carry the observed values. All three refused at
prepare, exit 2, one line, no record minted, no gesture executed:

```
r1 (dpi banked '999'):    observed '96'
r2 (theme banked 'apps=9;system=9'): observed 'apps=1;system=1'
r3 (os_build banked '0.0'): observed '26100.33438'
```

So the qualified desktop is **DPI 96** (the 100 % scaling of the 1024×768
qualification resolution), **both Personalize switches light**
(`apps=1;system=1`), and **OS build 26100.33438** — the same 26100 family
the banked mmc.exe FileVersion (10.0.26100.32860) versions, the UBR
differing because the OS image has taken updates beyond the binary.

## Run r1 (armed) — verified with all five baseline rows

The measured values banked into `profiles/gpmc-server2025.toml`
(`banked_from` = this window's record), then the armed transaction, filter
`zz-wcd-baseline-w18`, query `SELECT * FROM Win32_OperatingSystem` — the
window-15 argument set. **Exit 0, record `verified`** (banked at
`records/w18-r1-record.json`, schema v2, digest binding `48893e60…` = the
committed revision-1 bytes, transaction `eda3cc51…`): ten envelope clauses
satisfied, 7/7 deltas covered, and the prepare gates now carry **all five
banked==observed lines** beside the fingerprint gate:

```
surface fingerprint gate: banked 9193a3dfa818... observed 9193a3dfa818...
baseline gate: ui_language banked en-US observed en-US
baseline gate: binary_version C:\Windows\System32\mmc.exe banked 10.0.26100.32860 (WinBuild.160101.0800) observed 10.0.26100.32860 (WinBuild.160101.0800)
baseline gate: dpi banked 96 observed 96
baseline gate: theme banked apps=1;system=1 observed apps=1;system=1
baseline gate: os_build banked 26100.33438 observed 26100.33438
```

Cleanup ran strictly: `remaining=0`, `removed=zz-wcd-baseline-w18`,
`unregistered=WCDLaunchGPMC`.

## Independent post-state

Queried from **LabDC01 over host-relayed PSDirect** (a channel the run never
touched; the DC's VM-bus channel was fresh from this window's boot):
`(name=zz-wcd-baseline-w18)` answers **0 objects**, the SOM container
answers **0 children** and **0 `zz-*` of any kind** — the filter the run
created is gone from the directory, confirmed outside the member.

## Claim size

One estate, one session lineage, one surface (gpmc — the other two shipped
surfaces' context values are the same guest, session and build, but their
profiles deliberately stay unbanked on the new kinds until each surface
re-qualifies, exactly as window 15 left them). Three refusals + one verified
run, one record minted. The estate was returned to its found state (member
and DC shut down; LabCA01 never touched, Running as found). A differently
scaled, dark-mode, or patched guest now refuses before setup on the gpmc
surface — the compatibility predicate covers all five observable dependency
kinds. Per-dialog fingerprints remain the one declared-only kind.
