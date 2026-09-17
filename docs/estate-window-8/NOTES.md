# Estate window 8 — WEL-hosted lane validation (2026-09-15/16)

The first window in which WCD ran as the *seam* — driven by a WEL
`interactive_transaction` scenario rather than controller-direct — and the
window that closed WI-L1 (canary), WI-L5 (fingerprint gate), and the
record-contract gaps the seam exposed.

## What ran

Seven WEL-hosted lane runs of `gpmc.author_wmi_filter` rev 1 over the window
(journal `local/journal.jsonl` on mvmcc02): five failed or aborted before the
seam was whole, then **three consecutive green runs** (`f6c56304`,
`92fcc8d8`, `fc4a5a4d` — the last two after the baseline re-mint, i.e. the
lane is reproducible across estate generations), plus one deliberately
cancelled run (`6445dae8`) for the reconciliation-gate observation. A
controller-direct probe (`runs/w8-postreboot-probe.json`) isolated the estate
repair from the seam.

## Seam-contract findings (both fixed, measured live)

1. **CR/LF in `envelope_result.characterization`** — a verified record's own
   summary broke WEL's public data bounds. Fixed in PR #7 (`_characterize`
   emits single-line; the banked w7 record deliberately not rewritten).
2. **The record arrives bare, not enveloped** — WEL's decode demanded a
   correlated `{"operation_id", "operation", "output"}` envelope, but
   `wcd exec-transaction` prints the schema-v1 record bare on its dedicated
   subprocess pipe. Correlation for a one-process one-pipe launch is
   structural. Fixed WEL-side (WEL PR #14). Runs 3, 5, and 6 all died on
   this before any record validation ever ran.
3. **`quser` crashes the console probe when no session exists** —
   `No User exists for *` on stderr is a terminating error under EAP=Stop;
   a failed quser IS the answer. Fixed in PR #7.

## WI-L5 fingerprint gate — live verification

- Positive: every green lane run enforced the banked `prepared_context`
  digest (profile `gpmc-server2025.toml`, banked from the w7 record) and
  passed. The digest `9193a3df…50ea` is now identical across **16 records,
  windows 2–8**, including two estate generations (pre- and post-re-mint).
- Negative: a one-byte mutation of the banked digest refuses at prepare with
  exit 2 and `prepared surface fingerprint mismatch: banked … observed …;
  refusing before setup` — before any setup or mutation.

## Estate facts measured this window

- **The 7 h DC clock skew recurs on every DC restore** (the provisioning-era
  defect in WEL's topology doc): free-running `Local CMOS Clock` + a restore
  = the DC promotes the checkpoint-era time. Under that skew a member
  console's Kerberos fails as **GPMC "Access is denied" contacting the DC**
  while NTLM paths (PSDirect Negotiate) keep working — which is why it hides
  from canaries that only exercise NTLM. Fix: seed the DC clock from the host
  (`Set-Date` against `[DateTime]::UtcNow`, tz is UTC), `nltest /dsregdns`,
  restart NetLogon, then reboot the member for a clean channel. GPMC goes
  green immediately after.
- **`LAB` is the domain's NetBIOS name**, so `LAB\claude` is the *domain*
  user; there is no local-machine `claude` story. GPMC's identity on the
  console is the domain user via the interactive session.
- **`estate-current-20260905` became unrestorable on LabMS01**: VMMS
  `Restore-VMSnapshot` fails with a NullReferenceException even with the
  checkpoint tree and AVHDX chain intact, after ACL repair and a VMMS
  restart. Root cause unidentified; the checkpoint is superseded by the
  re-minted baselines. Record: `window8-vhdx-acl-fix` / `window8-vmms-restart`
  scripts in `C:\temp\lab`.
  **[CORRECTED 2026-09-17, window 9 — see docs/estate-window-9/NOTES.md]**
  The checkpoint was never unrestorable: `Restore-VMSnapshot` without
  `-Confirm:$false` throws that NullReferenceException in any headless
  WinRM session (the confirmation prompt dies before VMMS is contacted;
  zero VMMS events on failure). Both window-8 repair scripts omitted the
  flag; with it, the identical restore succeeds. The ACL repair and the
  VMMS restart were red herrings, and the 20790 security-info events fire
  on successful restores too.
- **A Standard-checkpoint revert of a powered-off guest lands it `Saved`**,
  not running — the guest must be running at revert for the running-state
  restore the runner assumes (cost the first `estate-domain-reset` run its
  client probe; reconciled with that as the reason).
- The Server Manager **WAC/Azure Arc promo dialog** reappears on every fresh
  console logon (it blocked run 3 of this window; dismissed host-side with
  Alt+F4 then). It does not block the lane once GPMC is launched —
  `wait_foreground` re-asserts the console.
- Console logon for a session-less member state is done by host-side key
  injection (CAD → username → TAB → password → ENTER via `Msvm_Keyboard`),
  then `deploy-helper.ps1` re-registers WCDHelper (both pre-date this repo's
  tooling; scripts preserved in `C:\temp\lab`).

## PRs this window

WCD #3 (canary), #4 (host credentials for Linux controllers), #5 (WI-L5
gate), #6 (estate anchoring + pwsh path), #7 (record-contract fixes). WEL
#12/#13 (seam config + lane example, prior session), #14 (bare-record
decode), #15 (cancelled-run exit), #16 (reconciliation procedure +
WI-007 closure).

## Claim size

This window validates ONE capability (`gpmc.author_wmi_filter` rev 1) through
the seam on ONE estate, in two generations of its baselines. Parm2's
`1;3;10;35;WQL;` prefix stays single-measurement (claim-registry W7 row).
Fingerprint-gating one estate is not portability.
