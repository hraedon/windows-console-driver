# Estate window 5 — R10: Windows accepts Studio's scripts bundle

Date: 2026-09-05 (America/Phoenix)

Work-order R10 ran end-to-end against LabMS01 on the rebased baseline:
import a Studio-produced GPMC backup carrying `scripts.ini` / `psscripts.ini`,
let Windows consume it, re-export, and open the GPMC editor onto the result.
Pilot-style (controller-side PSDirect transactions, no capability envelope);
the channel and evidence are recorded in the claim-registry R10 row.

## Result

- `records/r10-record.json`: **verified**.
- `Import-GPO` accepted the bundle (backup id
  `{49227F28-6122-5999-8CEB-923CB9BF3001}`, archive SHA-256
  `cd650643…93f12`, pinned to gpo-studio commit `38e3e9f`) and created
  unlinked GPO `zz-studio-evidence-10-scripts-rt`.
- Windows registered the measured Scripts CSE pair
  `[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]`
  in `gPCMachineExtensionNames` on import.
- **Both INIs re-exported byte-identical**: `Backup-GPO` after import
  re-emitted `scripts.ini` and `psscripts.ini` byte-for-byte what Studio
  wrote — which is itself byte-identical to GPMC's own R2 captures. This is
  the strongest file-side acceptance: Windows re-emitting Studio's bytes as
  its own.
- **GPMC renders the imported scripts**: Startup Properties → Scripts tab
  shows `zz-studio-marker.cmd /c alpha beta` and `zz-studio-second.cmd`
  (empty parameter retained); PowerShell Scripts tab shows
  `zz-studio-marker.ps1 -Mode Alpha` with the ordering dropdown at
  **"Run Windows PowerShell scripts first"** — the bundle's non-default
  `[ScriptsConfig] StartExecutePSFirst=true` survived the round trip.
  Screenshots: gitignored `runs/r10-startup-{scripts,psscripts}-tab.png`,
  SHA-256s in the record.
- One anomaly recorded: `Get-GPOReport` after import contains **no** script
  entries (no `zz-studio*`, no Scripts CSE reference) even though the editor
  renders them. The report is not an oracle for Scripts CSE content on this
  build; the editor and the re-export bytes are.
- Strict cleanup: GPO removed, `zz-studio-evidence-*` re-query returned zero
  rows, guest staging removed.

With this, work-order requests R1–R10 are executed and banked. R7 (DC
console) and R11 (production write, needs go-ahead) remain.

## Estate findings on the rebased baseline (2026-09-05)

The estate was rebased (latest updates + CA integration; LabCA01 now exists
as a domain-joined intermediate CA; snapshots taken). Four new measured facts
matter for future run-sheets:

1. **Local/domain `claude` SID collision breaks task registration.** The
   guest carries a LOCAL `claude` account (machine SID
   `S-1-5-21-1593318887-…`) alongside domain `claude`
   (`S-1-5-21-343068944-…`). `Register-ScheduledTask -Principal` and
   `New-ScheduledTaskPrincipal` re-resolve the account and intermittently
   store the LOCAL SID — the task then never starts (event 332 "user … was
   not logged on"), and LSA name→SID lookups transiently fail with "No
   mapping between account names and security IDs". Workaround (measured
   reliable): build the task XML from a known-good committed task
   (`Export-ScheduledTask` → swap the `Actions` subtree via the XML DOM,
   keeping the domain-SID principal) and register with
   `Register-ScheduledTask -Xml`. The `gpme_launch` guest script needs this
   treatment before its next window.
2. **`Get-ADUser` on this build omits `ObjectSid` from the default property
   set** — it reads as empty rather than erroring. Always pass
   `-Properties ObjectSid`.
3. **GPME navigation on the rebased build has no `Policies` results-pane
   node** under Computer Configuration (the authoring run-sheets' `Policies`
   click was already soft). Navigate Computer Configuration → Windows
   Settings → … directly.
4. `uia_dump` rejects depth > 12 (`1..12` enforced), and the helper
   screenshot payload key is `png_base64`.

The gpreport anomaly and the four facts above are candidates for the next
offline batch: harden `gpme_launch` against the SID collision, and decide
whether any run-sheet relied on `Get-GPOReport` script rendering.
