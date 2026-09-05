# Console-driver contract: transactionally verified actuation for legacy console surfaces

Status: v0 working agreement, written 2026-09-02. This document is the working
agreement between three independently owned components. Implementations may not
merge their responsibilities; the independence of observation from actuation is
the property the whole design exists to protect.

It follows the review round of 2026-09-02 (Sol feedback, three passes). The
one-sentence summary: **build a transactionally verified legacy-console driver,
not a GUI automation system.** The console driver is allowed to be unreliable;
the evidence runtime is responsible for ensuring that nothing depending on it is
believed without independent proof.

## 1. Components and ownership

Four owners. Each sees the others only through the interfaces stated here.

| Component | Repo/location | Owns | May never |
|---|---|---|---|
| Evidence runtime | `windows-evidence-lab` (existing) | Estate state, policy, journal, reconciliation, evidence store, cleanup, recovery strategy | Interpret a screen, inject input, or claim a transaction succeeded |
| Console driver | `windows-console-driver` (`wcd` package) | Session lease, context assertions, surface fingerprints, driver profiles, capability runtime, input injection, screenshots | Declare a transaction verified; interpret GPO semantics |
| GPO observers | `windows-console-driver` (`gpo_observers` package) | Turn observed Windows state into normalized facts (independent implementations) | Import from `gpo_studio`, `wcd`, or each other's implementation internals; actuate anything |
| Surface driver + capability specs | `wcd.profiles` + `capabilities/*.json` | How to manipulate a specific surface (GPMC on Server 2025); what semantic transition a capability intends | Observe state outside its own surface; certify its own effects |

The unit of work is the **verified transaction**, owned by the evidence
runtime:

```
pre-state oracle -> interactive transaction -> post-state oracle
        -> constrained-transition assertion -> convergence -> reproduce-once
```

A successfully injected click proves nothing. Only the declared state
transition, independently observed, proves something.

## 2. Transaction state machine

The operative state machine (evidence runtime property, mirrored by
`wcd.transaction`):

```
prepared
   |
   v
armed
   |
   v
commit-attempted
   +--> verified
   +--> disproven
   `--> indeterminate -> reconcile
```

- **prepared** — pre-state oracle complete; exclusive lease held; interactive
  context asserted; recovery strategy declared and demonstrated present.
- **armed** — capability invocation started; only pre-commit interactions have
  occurred.
- **commit-attempted** — the first declared commit point (or any potentially
  mutating action) has been crossed. Terminal for replay: **a capability is
  never replayed from the beginning after this point**, because its UI state is
  unknown and its effects may be partially durable. A single already-armed
  invocation may finish its remaining declared run-sheet steps (multi-dialog
  surfaces require this), but every later potentially mutating/commit action
  receives a fresh session/user/desktop and targeted-HWND context assertion.
  No failed step is retried and no second invocation is started. After the
  declared sheet finishes or aborts, the only legal continuations are oracle
  resolution or reconciliation.
- **verified** — envelope satisfied after the convergence window, and a second
  fresh observation reproduced the normalized state.
- **disproven** — envelope violated, with a **characterized delta** (what
  satisfied, what violated, what was unclassified). Disproven is a *result*, not
  a failure: for evidence work, what the surface actually did is the product.
- **indeterminate** — the runtime cannot resolve which transition occurred.
  Blocks unsafe retries per the WEL journal's existing reconciliation gate.

## 3. Transition envelope (not "exact delta")

The oracle is a **constrained transition with convergence semantics**, never
`post - pre == expected_delta`. Four clause kinds plus convergence:

```jsonc
{
  "require":  [ {"fact": "<fact-key>", "predicate": "<expr>"} ],
  "allow":    [ {"category": "<named volatile category>"} ],
  "forbid":   [ {"scope": "<named scope check>", "predicate": "<expr>"} ],
  "derive":   [ {"relation": "<expr over pre+post facts>"} ],
  "convergence": {"window_seconds": 90, "poll_seconds": 5, "reproduce": 2}
}
```

- **require** — must hold post-transaction.
- **allow** — named categories of tolerated change (timestamps, replication
  metadata). Each category is a *named field set*, not "stuff that looked
  volatile". **Any observed change not covered by require, allow, or derive is a
  violation** — this is what catches canonicalizers silently erasing something
  meaningful.
- **forbid** — every clause names its **enumerable blast radius**: the concrete
  scope check that would notice a violation (e.g. "extension lists of this GPC
  contain none of GUID set X", "every SYSVOL path is under this GPO's GUID",
  "the Policies container holds the same GPC object set as pre-state"). A
  forbid clause without a named scope check is a defect in the capability spec.
- **derive** — relations over pre/post facts rather than literal expected
  values (e.g. `post.version.machine == pre.version.machine + 1`).
- **convergence** — post-state may be asynchronous (AD/SYSVOL propagation).
  Poll within the window until every post-state fact referenced by require,
  derive, or forbid is stable; freeze the normalized state; take the declared
  number of fresh observations, spaced by the poll interval, which must
  reproduce it. An envelope that observes no post-state facts is invalid.
  Timeout is not failure: it is **indeterminate**.

Assertion output is always one of: satisfied / disproven (with characterized
delta) / indeterminate.

## 4. Channel contracts: selection belongs to the claim, not the runtime

The runtime does not choose channels by trust or cost. Each role of a
capability's execution pins the channels it may use:

| Concern | Contract (example, R2) |
|---|---|
| Setup | `may_use: [gpmc_com, powershell]` |
| Operation under test | `must_use: gpmc_ui` |
| Orientation | `may_use: [uia, msaa, hwnd, screenshot]` |
| Input delivery | `may_use: [helper_input, hyperv_input]` |
| Oracle | `must_not_use: gpmc_ui` |
| Cleanup | `must_use: programmatic_requery` |

The executor validates the run-sheet against this declaration before acquiring
or manipulating the console. Setup and cleanup admit only programmatic script
steps; a programmatic operation-under-test step must explicitly declare
`gpmc_com`; UI gestures require `gpmc_ui`, `helper_input`, and the orientation
channels their primitives actually use. Phase names are a closed vocabulary.

Rationale: using the more trusted channel can invalidate the experiment. If the
question is "what does GPMC author for this setting?", authoring via COM or by
writing the file directly optimizes away the test. The recorded provenance
states which rung was actually used for every gesture.

**Input delivery order** (inside a role that permits multiple): in-guest helper
(UIA/MSAA/HWND + window-relative SendInput) first; Hyper-V synthetic input as
the blind fallback that works when the helper is defeated. Absolute screen
coordinates are the bottom rung of the helper, permitted only when the
capability's channel contract and the profile's compatibility predicate both
allow them.

## 5. Evidence taxonomy and grades

Four categories; **the claim determines which category can certify it**:

- **orientation** — transient reads (UIA dumps, screenshots taken to decide the
  next gesture). Never supports a claim.
- **surface** — authoritative *for claims about what the UI displayed or
  allowed* ("does GPMC offer this combination?", "what does the editor show
  after import?").
- **state** — AD/SYSVOL/files/registry. Authoritative for machine-state claims.
- **behavior** — actually applying or consuming the result.

Surface evidence grades:

- **ordinary**: helper screenshot, host-retrieved and hash-bound. The helper
  actuates *and* captures, so its surface evidence is not independent.
- **corroborated**: the same moment also captured through the independent
  host-side Hyper-V framebuffer path (`capture_guest_console.ps1` mechanism).
  Coarse, but establishes "a dialog matching fingerprint X was foreground at
  commit time" without the helper's cooperation. State claims are always
  certified by observers, never by either capture path.

A claim registry (`docs/claim-registry.md`) maps each evidence claim to its
certifying observers and their independence relationship. This is bookkeeping
the project maintains claim-by-claim, so "limit the claim to what the second
oracle actually proves" is checkable in review rather than remembered in
folklore.

## 6. Driver profiles: commit boundaries and compatibility

### Commit boundaries

A driver profile classifies every action it can perform:

- `orientation_only` — provably reads surface state only.
- `reversible_pre_commit` — mutates only in-memory/surface state, undone by
  cancel/close before a commit point.
- `potentially_mutating` — may write external state (some MMC extensions commit
  on Apply; some child dialogs commit on close).
- `commit_point` — declared external mutation point.

Rules:

1. Profile classifications are **declared by the author and validated during
   driver development**, not discovered at runtime. GPMC facts known from the
   manual regime (e.g. the Scripts dialog flushes `scripts.ini` at OK) go in as
   initial facts.
2. Crossing an **undeclared** mutating boundary during qualified execution is a
   hard stop and a profile-invalid finding (the profile gets corrected; the
   transaction is indeterminate).
3. Everything before the first commit point must be **replayable from
   scratch**. After `commit-attempted`, replay is forbidden (see §2).
4. Capabilities declare their own first commit point and expected external
   effects.

### Compatibility predicate

Qualification is intended to bind to **observed surface properties**, not
administrative version labels. The profile currently declares what its
selectors depend on, but transaction execution does not yet collect or compare
a qualified binary/hash/language/dialog-fingerprint baseline. Therefore these
rows are dependency metadata, not an enforced compatibility predicate:

- **strong**: snap-in/binary module versions and content hashes; dialog/control
  tree fingerprint.
- **strong-if-used**: UI language (binds only if selectors contain text);
  DPI/resolution (binds only coordinate selectors); theme (binds only visual
  matching).
- **provenance**: OS build — recorded, not inherently invalidating.

Once baseline capture is implemented, a mismatch on a strong dependency must
refuse the capability. A mismatch on a weak one must degrade the driver to a
lower input rung *if the capability's channel contract still permits that
rung*, with provenance recorded. Until then, banked estate runs qualify only
the exact exercised environment and do not establish portable compatibility.

## 7. Lease and interactive context assertions

An **exclusive interactive-session lease** is held for the transaction's
duration. A kernel-backed controller lock excludes cooperating WCD processes
before wake/unlock or any later desktop action. It cannot technically prevent a
human or an unrelated tool from touching the console; exclusive operator access
is an estate precondition, and the fresh context/target checks below detect
observable interference before commit.

Before every commit point, the driver takes a fresh **interactive context
assertion**. Session, user, and desktop must match the prepared context exactly.
The surface identity is asserted through the run-sheet's current explicit HWND:
a fresh targeted UIA dump verifies the window still exists and matches the
selector, and the input request focus-guards that same HWND immediately before
injection. This split is required because each single-shot helper invocation can
self-shadow with its own transient console window; the helper's ambient
foreground HWND/PID is not a stable surface identity.

```
session_id + user identity + desktop name
+ targeted surface {hwnd, pid, process, title, class, rect, UIA digest}
```

Any deviation invalidates the pending operation -> **indeterminate** (never a
retry). Named unsupported states:

- **Secure Desktop / UAC prompt** — stop and reconcile. Never solved
  heroically. Privilege is handled at the *setup boundary*: elevated surfaces
  are launched pre-elevated before the transaction arms, so UAC cannot appear
  mid-capability.
- RDP disconnect/reconnect, session switch, resolution/DPI change, helper
  death/restart in another session — all appear as context mismatches.

## 8. Guest helper contract

`guest/helper.ps1` — Windows PowerShell 5.1, runs in the target user's
interactive session. Single-shot, stateless per invocation; JSON over stdin in,
JSON over stdout out; exit 0 ok / 2 error / 3 indeterminate. Actions:

- `context` — session id, user, desktop, foreground window + fingerprint.
- `uia_dump` — element tree of the foreground window (class, name, automation
  id, control type, rect, patterns).
- `screenshot` — PNG, base64.
- `key` — text or key-chord via SendInput.
- `mouse` — window-relative absolute position, button, click/double/down/up.
- `wait_foreground` — fingerprint match with timeout.

The helper **never interprets**: it returns facts and injects input. It never
types secrets — the policy layer prohibits secret parameters, and helper input
is logged as evidence.

## 9. Hyper-V input backend (fallback)

`guest/hyperv-input.ps1` — runs host-side through WinRM, exactly the route of
`capture_guest_console.ps1` (same realized-settings lesson applies): injects
via `Msvm_Keyboard` (`PressKey`, `TypeText`) and `Msvm_SyntheticMouse`
(absolute position, buttons). Returns `{ok, injected_count}` and **nothing
about where input landed** — blind by design. Usable only when the capability's
channel contract admits `hyperv_input`.

## 10. GPO observers (v1 — the R2 set)

`gpo_observers` — independently implemented; must not import `gpo_studio` or
`wcd`; enforced by a test that scans imports. Observer scripts run in the guest
(Windows PowerShell 5.1), emit normalized JSON facts; a Python normalizer
validates and types them.

1. `gpo_identity` — GPC GUID, domain DNS name.
2. `sysvol_tree_fingerprint` — recursive `-Force` enumeration, sha256 per file,
   posix-normalized relative paths. Two independently coded enumeration passes
   compared inside the observer (the WEL tree-collection lesson: one
   implementation comparing itself to itself is insufficient).
3. `ad_attributes` — selected GPC attributes, each labelled structural or
   volatile.
4. `version_values` — `gpt.ini` Version plus AD `versionNumber`, unpacked into
   machine/user halves.
5. `scripts_ini_semantics` — encoding facts (BOM presence/width, CR/LF counts)
   and parsed entry semantics for `scripts.ini`/`psscripts.ini` (sections,
   entries, parameters, order, config-section name).
6. `scope_forbid` — forbidden-GUID absence in extension lists; SYSVOL path
   containment; Policies-container object-set stability.

The grammar grows claim-by-claim (R3 adds `fdeploy.ini` semantics; R4 adds
security-template semantics). **No complete semantic model of Group Policy is
attempted** — only enough independently implemented observers to certify the
claims the evidence lanes make. Where a product parser exists (`gpo_studio`),
agreement tests may compare the two implementations on fixtures, but the
observer implementation shares no code with the product.

## 11. Capability specification

`capabilities/*.json` are revisioned documents. Current transaction-record v1
records the capability ID and run-sheet name, but not the capability revision
or a content digest; current qualification is therefore **not hash-bound**.
The qualification ledger binds banked evidence to revisions explicitly until a
future record version carries the immutable digest:

```jsonc
{
  "id": "gpmc.author_scripts_entry",
  "intent": "three script entries in this ordering, PowerShell-order flag set",
  "parameters": { "...": "typed schema" },
  "channel_contract": { "setup": ["powershell"], "operation_under_test": ["gpmc_ui"], "..." : "..." },
  "first_commit_point": "scripts dialog OK",
  "envelope": { "require": [], "allow": [], "forbid": [], "derive": [], "convergence": {} },
  "cleanup": { "strategy": "remove_gpo", "requery": "strict_absence" },
  "recovery": { "kind": "checkpoint_revert | logical_cleanup", "demonstration": "<recorded run>" }
}
```

Ownership split (deliberate): the **capability spec** declares intended
semantic transition; the **surface driver** knows how to manipulate the
surface; the **observers** independently report what Windows actually
produced; a separate **assertion engine** compares intent to observation. The
driver does not predict its own effects — that would make it actuator and
oracle at once (the "one loop built the manifest and the archive" failure,
relearned from WEL).

## 12. Modes and policy

- **Qualified execution (target state)** — the agent may invoke only
  hash-bound capability revisions whose compatibility predicate passes. Raw
  input is unreachable. The current CLI enforces schemas, profile action
  classes, channel contracts, lease/context/recovery guards, and independent
  envelopes, but does not yet enforce the capability hash or compatibility
  baseline described above.
- **Driver development** — raw inspect/input allowed, but only when the
  evidence runtime proves the target is a disposable estate with a
  demonstrated exact-baseline recovery route (checkpoint). A confirmation
  flag never makes a live or SURVEY-role target eligible.

**Recovery strategy per mutation, never "snapshot before mutate"**: every
mutation declares and demonstrates its recovery route. In the synthetic estate
that is checkpoint revert. Against a live directory it is logical cleanup:
unique-named object, record its id, delete exactly that object, strict absence
re-query, **residual accounting** (observed residue + declared-unobservable
residue, e.g. USN movement, audit events). Three terms, used precisely:

- **revert** — return disposable environment to exact baseline.
- **logical cleanup** — remove the functional change introduced.
- **residual accounting** — state what intentionally survives.

## 13. Testing strategy

- The transaction state machine, envelope engine, lease, and profile schema are
  tested against a **synthetic fake-desktop backend** (scripted window/dialog
  model) — no Windows required.
- Observers are tested against committed synthetic GPO-tree fixtures covering
  the R2 question space (UTF-16/LF/BOM variants, `[Policy]` vs
  `[ScriptsConfig]`, packed versions).
- Helper and Hyper-V input scripts are validated structurally (JSON contract
  round-trips, parse checks under Windows PowerShell 5.1). Banked Server 2025
  runs qualify the exercised targeted-UIA, screenshot, input, context, cleanup,
  and reproduction paths. Helper death/restart, unsupported desktop states,
  and new surfaces still require their own qualification.
- Every shipped capability is validated against the closed Draft 2020-12
  `docs/capability-schema-v0.json` before execution and in CI. Generated
  records are stamped/validated as transaction-record v1; the eight immutable
  estate records are validated through the explicit v0 compatibility path.
- Every real-environment result is certified against independent observation,
  never against the driver's report.

## 14. What this contract deliberately does not do

- No MCP/agent-facing tool surface yet. The boundary is
  runtime -> typed transaction contract -> driver RPC/CLI. The deferral is no
  longer about the primitive — eight transactions have been banked through the
  engine. The record schema is the actual interface an agent surface will
  program against. Version 1 is now frozen in
  `docs/transaction-record-schema-v1.json`; new records carry that version in
  `provenance`, while immutable pre-schema evidence is read through the
  explicit v0 compatibility path. Agent-surface design remains deferred until
  v1 has survived the next capability window without a revision.
- No general GUI-understanding/vision agent. Profiles and capabilities encode
  domain knowledge; the driver aims and verifies.
- No full Group Policy semantic model. The observer grammar grows from
  evidence questions.
- No coordinate-first automation. Fixed resolution makes coordinates reliable
  in a lab; they remain fragile by construction and are the last rung.
