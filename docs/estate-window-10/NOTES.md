# Estate window 10 — cert-template qualification: phase 1 measured end-to-end, phase 2 open

2026-09-19, LabMS01 + LabDC01 on mvmhyperv01.ad.hraedon.com. The window
opened with the estate fully running (the owner's everything-running state);
bring-up was READY first pass and the canary 8/8.

## Outcome in one line

The duplicate-to-creation arc (phase 1) is deterministic through the helper
channel (40+ consecutive runs to the creation commit), the AD-side observer
stack is fully revised from live measurement, and the created-object property
sheet was observed open exactly once (captures/ct-propsheet.png) — but no
in-transaction gesture reproduced that opening (~20 attempts, every channel
combination). The capability stays rev-1 UNQUALIFIED; phase 2's property-sheet
opener is the single open item for the next window.

## Measured facts (durable — each backed by a banked artifact)

### AD schema — the rev-1 draft's assumptions were wrong

- Template objects are class `pKICertificateTemplate` (33 in the lab forest)
  and carry NO `msPKI-Validity-Period` / `msPKI-Validity-PeriodUnits` —
  Get-ADObject rejects those property names. Validity is
  `pKIExpirationPeriod` + `pKIOverlapPeriod`: 8-byte little-endian signed
  int64 of NEGATIVE 100ns ticks; a "year" is EXACTLY 365 days (the 5*365d
  blob is byte-identical to what CA/SubCA carry). Observer, collector,
  envelope, and category table revised to this encoding (commit 4856eaa).
- No `Computer` template exists in a 2025 forest's default set; the source is
  Workstation (schema v2, CN 'Workstation', display 'Workstation
  Authentication'). The console list shows DISPLAY names — CN/display
  divergence is real (CN 'Machine' displays as 'Computer').

### Console flow — the duplication is TWO dialogs, not one

- Context-menu Duplicate (Shift+F10 / DOWN / ENTER — single DOWN lands on
  Duplicate Template, 40/40) opens 'Properties of New Template': a
  COMPATIBILITY CHOOSER (one tab; no General exists yet).
- The chooser's OK CREATES the template as 'Copy of <source display name>'
  (commit #1) and returns to the console — NO follow-on dialog.
- The name + validity edits belong to the created row's own property sheet
  ('Copy of ... Properties', General tab with the two name fields and the
  validity row pre-filled 1 / years — captures/ct-propsheet.png).
- The fresh console enumerated BEFORE creation: the new row is INVISIBLE
  until F5 (captures/ct-post-composite.png — the selection never moved off
  Workstation pre-refresh). After F5, window-click + 'Copy' type-ahead
  selects the created row reliably (captures/ct-copy-selected.png).
- MMC auto-uniques repeated duplicates ('Copy 2 of ...'); every failed run
  left a stray that was swept directory-side before the next attempt.

### Input-channel seams

- Helper SendInput sequences truncate to ~1 event once an MMC context menu
  opens in this context: menu walks of depth 5-7, END/UP jumps, and two
  accelerator chars all failed to activate anything; the post-walk
  screenshots show the menu still open with the highlight one item down.
- A helper invocation immediately before VM-bus keyboard input leaves the
  row menu unable to open — the Actions-pane/node menu appears instead
  (captures/ct-post-hostwalk.png).
- The VM-bus keyboard delivered 250+ event sequences flawlessly at the
  LOGON screen, so the truncation is menu-context-specific, not a
  channel-wide limit. NOTE: the mid-window probes that claimed a measured
  menu item order (Properties at index 6) and a twice-reproduced
  isolation proof of the right-click+walk gesture were NOT preserved —
  treat both as unverified; tools/host_scripts/certtmpl_open_propsheet.ps1
  encodes the walk shape for the next window to re-measure.

### Transport seams (fixed and committed)

- Typed params in scriptblocks shipped from the pwsh 7 controller into the
  host's Windows PowerShell endpoint break downstream CIM instance binding
  ('className out of range' at Get-CimAssociatedInstance -InputObject);
  untyped params work. All host-op scripts untyped now (commit 43b4006).
  This seam had never fired before: pre-move runs used implicit host auth
  or pre-existing unlocked sessions.
- The LogonUI keyboard path could not establish claude's console session in
  any form: the preselected administrator tile eats account-first
  sequences; Ctrl+A does not select inside LogonUI password boxes; the
  shared bootstrap secret logs on administrator accidentally (an artifact
  session created this way was logged off). The DESIGNED mechanism worked
  first try: one-shot winlogon autologon (AutoAdminLogon=1 +
  AutoLogonCount=1 + DefaultPassword), keys and stored secret cleared
  immediately after. The claude console session it established is the
  state the estate was left in (the helper task's Interactive principal
  requires it).

### Channel-contract gate (committed)

A gesture-phase programmatic step is now legal when its declared channel is
in the contract's input_delivery (the VM-bus keyboard script IS input
delivery, not an operation under test), alongside the historical gpmc_com
route (commit 9d46fb7).

## Estate events

- An owner RDP session (sxmerrip, since 9/18 noon) and an owner console
  session (administrator, 9/18 8:16 PM) were on LabMS01 when the window
  opened. The administrator session was logged off (it pre-empted the
  helper task's claude-Interactive principal); the RDP session disconnected
  during the MS01 reboot and did not return. Both noted for the owner.
- Left state: all five lab VMs Running (as found), exactly 33 templates,
  mmc killed, WCDLaunchCertTmpl unregistered, autologon keys cleared,
  claude console session active (functional for the next window).

## Open item for the next window

**The phase-2 property-sheet opener, in-transaction.** What is known: the
sheet exists (ct-propsheet.png), F5 + type-ahead selection is reliable, and
helper-keyboard walks truncate inside menus while VM-bus input survives
helper-adjacent contexts only sometimes. Next steps, in order: (1) re-measure
the row-menu item order with a preserved artifact (the host thumbnail loop
in the window's operator scripts, C:\temp\lab, is the pattern); (2) make the
host gesture script VERIFY the sheet via host-side thumbnail before
returning (close the loop inside the script, no helper polling involved);
(3) only then re-run the transaction flow. The WEL-hosted run stays deferred
(it needs the qualified capability). gpo-studio's group-deny lane is
unaffected and still ready in its own window.
