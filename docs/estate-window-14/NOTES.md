# Estate window 14 — certsrv revision 2 live, and the adapter's first estate run (2026-09-30/10-01)

Two owed debts paid in one booked window, both first-try after pre-flight:
the **certsrv officer-rights revision-2 live qualification** (the only
"pending" row in the qualification ledger) and the **first live execution
through WEL's MCP adapter** (the adapter had 92 tests, all against fake
backends, and had never touched the estate). The window also found and fixed
two Windows-only seams that five Linux-driven windows could never see.

## Pre-flight

The estate had sat idle five days (window 13 left it lane-ready) and held:
**canary 8/8 green, exit 0, first try** — all five lab guests Running exactly
as found, console session still unlocked, Kerberos healthy, helper task Ready.
`estate_bringup` was not needed before the window. Independent pre-state:
`OfficerRights` and `EnrollmentAgentRights` both ABSENT on LabCA01 (the
window-11 cleanup held), CA answering, 11 published templates, three
certificate managers unchanged.

## Run 1 — certsrv.restrict_certificate_manager revision 2

`wcd --estate local/estate.toml exec-transaction` with
`ca_host=LabCA01.ad.labdomain.dev`, `ca_name=Lab Issuing CA 01`,
`manager_principal=LAB\Domain Admins`, `template_name=User`. **Exit 0, record
`verified`** (banked at `records/w14-r1-record.json`, schema v2, digest
binding matches the committed revision-2 bytes).

- **The revision-2 clause holds live**: all 16 envelope clauses satisfied
  including `certsrv.ca.directory.member` — the observer derived the CA host
  set from the directory's `pKIEnrollmentService` objects and refused nothing
  because the plan's CA is genuinely the forest's enrollment object.
- **The sheet re-proofed at its real timings** (WCD PR #19's `delay_ms`
  fix): all 32 sheet steps ok, first try, including the 600 ms menu walks.
- **Independent post-state**: `OfficerRights` ABSENT again (cleanup confirmed
  through both read channels), and the CA's `Security` digest is
  `e0e944b2…` — **byte-identical to the reading window 11 took five days
  earlier**, so the restriction gesture's blast radius stayed exactly the one
  registry value.

## Run 2 — the MCP adapter executes the WMI-filter lane on the estate

Driven from the workstation (a first for WEL — every prior WEL estate run was
mvmcc02-driven): `discover_capabilities` → `inspect_run` → `execute_run`
(`w14-mcp-r2`, `gpmc.author_wmi_filter`, destructive confirmed) through the
committed example catalog, the whole lane on the real estate. **Status
`passed`, all four steps** — inventory, wait_ready, the GPMC transaction, and
the revert cleanup — run `1d4bc0ac`, and the completion payload carries
**`capability_binding` verified**: revision 1, digest `48893e60…`, the record
stamped against the catalog's approved `transaction.json` bytes.

The durability contract proved live in the same session: resending the same
request id returned the existing run with `deduplicated: true` and dispatched
nothing (proven on both a failed attempt and the green run), `run_status`
reported the runner's own outcome with the historical
`reconciliation_was_required_at_completion` flag, and an independent AD survey
(LabCL01 PSDirect + explicit-cred LDAP) saw **0 `msWMI-Som` objects** — the
revert returned the directory to exactly-as-found.

Two refused attempts en route were each the adapter machinery working as
designed, and each banked something:

1. **`w14-mcp-r1` first attempt failed at step 1** — the backend could not
   spawn pwsh at all. Root cause: WEL's `plan_command` delivers the static
   PowerShell bootstrap as one `-EncodedCommand` element (~70 KB base64),
   past Windows' ~32 K command-line ceiling (`WinError 206`, surfacing as a
   misleading `FileNotFoundError`). Every prior WEL run was Linux-driven,
   where no such ceiling exists. **Fixed in WEL PR #40**: on Windows the
   bootstrap rides a temp `.ps1` file (`-File`), payload still on stdin.
2. **Second attempt (`a66f0868`) got through inventory and wait_ready but
   the driver child exited 1** constructing its transport: the WEL-launched
   child inherits only the plan's credential env names and a minimal runtime
   set — no `PATH`, and the workstation's `estate.toml` named the old
   `WCD_LAB_*` env vars and no absolute pwsh. mvmcc02's estate file had
   already converged on the plan's env names; the workstation file was
   re-pointed the same way (`password_env=GUEST_BOOTSTRAP_PASSWORD`,
   `host_password_env=HYPERV_CONTROL_PASSWORD`, absolute `pwsh_executable`;
   backup `local/estate.toml.pre-w14`). The run was surveyed clean (the
   driver died before any console work; 0 `msWMI-Som` objects) and
   reconciled per `docs/reconciliation-procedure.md`.

Also proven en route: **WEL PR #38's stderr surfacing paid for itself on its
first outing** — the failed attempt's journal carries the bounded driver
stderr (the traceback naming `cli.py:285 _default_transport`) in the step
detail, which is what made the diagnosis a read instead of a re-run.

## Estate left as found — and lane-ready

`estate_bringup` closed the window (the lane's revert had reset the member
clock to checkpoint era and dropped the console session): member clock
repaired to 2 s, first-try CAD re-logon, helper Ready. Closing canary **8/8,
exit 0**. All five lab guests Running, CAroot Off, console session Active.

## What this window changes

- The qualification ledger's one pending row is closed: certsrv
  officer-rights revision 2 is live-qualified (W14 claim-registry row).
- The MCP adapter is no longer lab-theory: it has executed a mutating
  capability on the estate with the record binding verified at the adapter
  (W14 composition row).
- Windows is now a proven controller platform for the whole pair — the
  workstation can host a window without mvmcc02.
