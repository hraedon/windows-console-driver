# Estate window 15 — the baseline gate goes live (2026-10-09)

The WI-L5 tail, closed: prepare-time enforcement now covers the two
OBSERVABLE dependency kinds, not just the prepared-context digest. A banked
`[[baseline_values]]` row (`ui_language`, read from the helper context, or
`binary_version`, read through the helper's new read-only `file_version`
probe of the row's own path) is compared at prepare and a mismatch — or a
baseline that cannot be observed — refuses before setup: exit 2, one line,
no record, lease released. The window proved the gate in both directions on
the gpmc surface: two deliberate-mismatch refusals measured the estate's
true values, then the armed transaction ran `verified` with every gate
banked==observed.

## Pre-flight

The estate stood exactly as window 14 left it: all four ad.labdomain.dev
guests Running (CAroot Off as found), LabMS01's `claude` console session
Active since 10-01, `WCDHelper` Ready. Canary 8/8 green, exit 0, first try
(ran twice: at survey and again after the redeploy below).
`estate_bringup -RedeployHelper` walked all seven steps with nothing to
repair (DC delta −8 s, member 0 s, locator green, session active) and
re-deployed `guest/helper.ps1` two-hop + re-registered the task
(smoke = context answered). The redeploy is what carries this window's two
new helper capabilities to the guest; without it a banked run on an older
helper fails closed as an observed-`null` mismatch, never a pass.

## Runs r1 and r2 — deliberate-mismatch refusals (the measurement)

Each probe appended one uncommitted wrong-valued `[[baseline_values]]` row
to `profiles/gpmc-server2025.toml`, ran
`wcd exec-transaction` for `gpmc.author_wmi_filter`, and reverted the
profile. Both refusals are determinate by design — one precise line, exit 2,
no record written, no lease left behind — and the mismatch message itself is
the measuring instrument: the `observed` field carried the estate's true
value.

**r1** (`ui_language` banked as `qq-ZZ`):

```
transaction error: ui_language mismatch: banked 'qq-ZZ' from 'deliberate-mismatch probe (estate window 15, r1)', observed 'en-US'; the estate's UI language is not the qualified one, refusing before setup
```

**r2** (`binary_version` banked as `0.0.0.0`, path `C:\Windows\System32\mmc.exe`):

```
transaction error: binary_version mismatch (C:\Windows\System32\mmc.exe): banked '0.0.0.0' from 'deliberate-mismatch probe (estate window 15, r2)', observed '10.0.26100.32860 (WinBuild.160101.0800)'; the estate's binary is not the qualified one, refusing before setup
```

Measured: **ui_language `en-US`; mmc.exe FileVersion
`10.0.26100.32860 (WinBuild.160101.0800)`**. Both refusals exited 2 with no
`runs/w15-r*-refusal.json` emitted (refusals write no records) and a clean
working tree after each revert.

An incidental finding, banked as a note not a fix: a profile that fails
TOML/`ProfileInvalid` parsing surfaces as a raw traceback (exit 1) rather
than the house one-line error. Pre-existing behavior, unchanged here; worth
a small follow-up.

## Run r3 — the armed transaction

`gpmc.author_wmi_filter` revision 1, filter `zz-wcd-baseline-w15`, the
profile now carrying the two measured rows. **Exit 0, record `verified`**
(banked at `records/w15-r3-record.json`, schema v2, digest binding matches
the committed revision-1 bytes `48893e60…`). Ten envelope clauses satisfied,
7/7 deltas covered, converged after 2 polls / 2 reproductions; all three
prepare gates appear in `provenance.notes`:

```
surface fingerprint gate: banked 9193a3dfa818... observed 9193a3dfa818...
baseline gate: ui_language banked en-US observed en-US
baseline gate: binary_version C:\Windows\System32\mmc.exe banked 10.0.26100.32860 (WinBuild.160101.0800) observed 10.0.26100.32860 (WinBuild.160101.0800)
```

Cleanup ran strictly (`removed=zz-wcd-baseline-w15`, `remaining=0`).

**Independent post-state** (queried from LabDC01 over host-relayed
PowerShell Direct, a channel the run never touched): `(name=zz-wcd-baseline-w15)`
returns **0 objects** under `CN=SOM,CN=WMIPolicy,CN=System` and **0** across
the whole domain naming context, with controls proving the zero is real (the
SOM container resolves; its `WMIPolicy` parent answers with its four child
containers). The SOM container is empty — no sibling leftovers either.

## Banking and claim size

`profiles/gpmc-server2025.toml` now banks both rows, `banked_from` the r3
record whose notes carry banked==observed for each; the values were measured
by r1/r2 and the profile comment says so. The certtmpl and certsrv profiles
deliberately bank nothing yet: the values are session facts but the banking
discipline is per surface, and those surfaces re-qualify on their own
windows. Per-dialog fingerprints remain unbanked everywhere (no
qualification window has captured them as standalone facts); `dpi`, `theme`,
`os_build` remain declared-only kinds — the profile parser now refuses to
bank a value for a kind the executor cannot observe at prepare.

True size: this window proves the baseline gate on ONE estate, ONE surface
(gpmc), ONE console session. It is not portability, and it does not
generalize the gpmc records to a changed estate — it is the mechanism that
would refuse one.
