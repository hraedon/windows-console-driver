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

Status: foundation phase. The transaction state machine, transition-envelope
engine, and fake-desktop backend are implemented and tested. The guest helper
and Hyper-V input backend are implemented against their contracts but are
**unqualified** — their real behaviour is unknown until the first estate
window.

## Layout

- `src/wcd/` — controller library: envelope engine, transaction state machine,
  lease, profile schema, helper client, fake backend.
- `src/gpo_observers/` — independent GPO state observers (v1: the R2 set).
  Imports neither `gpo_studio` nor `wcd`, by test.
- `guest/` — in-guest helper (PowerShell 5.1) and host-side Hyper-V input
  backend.
- `profiles/` — driver profiles (commit-boundary maps, selectors,
  compatibility dependencies).
- `capabilities/` — capability specifications (intent, channel contract,
  envelope, cleanup, recovery).
