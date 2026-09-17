# windows-console-driver

Transactionally verified actuation for legacy Windows console surfaces — GPMC,
MMC snap-ins, legacy Win32 property sheets. The component behind
`windows-evidence-lab`'s `interactive_transaction` operation.

The one-sentence design rule: **the console driver is allowed to be unreliable;
the evidence runtime guarantees that nothing resting on it is believed without
independent proof.** See [`docs/contract.md`](docs/contract.md) for the working
agreement between the four independently owned components, and
[`docs/claim-registry.md`](docs/claim-registry.md) for which observers certify
which claims.

Status: driver-development phase. The transaction state machine,
transition-envelope engine, schema boundaries, and fake-desktop backend are
implemented and tested. Multiple Server 2025 estate windows have qualified
the guest helper's targeted UIA, screenshot, input, context, cleanup, and
reproduction paths for the shipped GPMC flows. Helper death/restart, unusual
desktop states, and new surfaces remain capability-specific qualification
work rather than assumed portability.

Real execution also requires `checkpoint_name` in the gitignored
`local/estate.toml`. The executor queries that exact Hyper-V checkpoint name;
an absent value or a different snapshot fails the recovery guard closed.

Before booking a window, `wcd estate-canary --estate local/estate.toml` makes
silent estate drift a pre-flight fact instead of a mid-lane failure: one
read-only pass over the seams a transaction depends on (host WinRM, guest
PSDirect, the recovery checkpoint, the domain account's enabled/password
state, the DC locator, Kerberos health — the DC clock read straight over
LDAP compared against the guest at the measured MaxClockSkew, plus a fresh
`klist` ticket mint, because clock skew kills GPMC's Kerberos path while
every NTLM probe stays green — the helper task, the console session), one
precise line per check, fail closed — exit 0 green, 3 when any check failed. It is
an operator tool; the default suite tests its logic against scripted fakes
and never touches a live host.

Execution currently requires a source checkout (normally `pip install -e
".[dev]"`). Profiles, run-sheets, schemas, capabilities, and guest scripts are
repository assets resolved from that checkout; a standalone wheel deployment
is not yet supported and fails closed if those artifacts are absent.

## Layout

- `src/wcd/` — controller library: envelope engine, transaction state machine,
  lease, profile schema, helper client, fake backend.
- `src/gpo_observers/` — independent GPO state observers for the shipped
  R1-R5 evidence families.
  Imports neither `gpo_studio` nor `wcd`, by test.
- `guest/` — in-guest helper (PowerShell 5.1) and host-side Hyper-V input
  backend.
- `profiles/` — driver profiles (commit-boundary maps, selectors,
  compatibility dependencies).
- `capabilities/` — capability specifications (intent, channel contract,
  envelope, cleanup, recovery).
