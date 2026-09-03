# Surface onboarding runbook: adding a legacy console surface to the driver

This is the generalized deliverable of the first two estate windows: what it
takes to make a NEW legacy tool (secpol.msc, certificate templates, DFS
management, anything MMC-shaped) a bounded engineering task instead of an
adventure. Everything below was learned by driving GPMC/GPME on Server 2025
through the transactional engine; the structure is surface-agnostic.

## The invariant

Every new surface lands as FIVE artifacts, each owned separately (contract
section 1). If you are writing shell history, you are skipping one of them:

1. **Driver profile** (`profiles/<surface>.toml`) — every action the driver
   can perform on the surface, classified (`orientation_only` /
   `reversible_pre_commit` / `potentially_mutating` / `commit_point`), plus
   selectors and their compatibility dependencies. Content starts UNVERIFIED;
   qualification (step 5) validates it.
2. **Capability spec** (`capabilities/<id>.json`) — the semantic intent, the
   channel contract per role, the first commit point, the fact plan (which
   observers certify it), and the transition envelope. The envelope must
   predict its own intent's full blast radius: every fact the intent changes
   is either required, allowed by category, or derived. (The R2 re-run
   disproved its own envelope once for exactly this reason — the CSE
   registration, version bump, and extension-list change were all consequences
   of the intent that the envelope failed to predict.)
3. **Run-sheet** (`runsheets/<capability-id>.json`) — the "how": declared
   steps, each naming the profile action it instantiates. Setup and cleanup
   phases are programmatic (`guest` scripts); the gesture phase is
   helper-driven and is the ONLY channel allowed to touch the operation under
   test.
4. **Observers** (`gpo_observers/`) — independent implementations that turn
   machine state into facts. The guest transports bytes; all parsing is
   controller-side. The fact vocabulary they emit is what envelope predicates
   reference; the capability-seam test pins the agreement.
5. **Qualification run** — one real transaction in driver-development mode on
   the checkpoint-backed estate. First run DISPROVES or goes indeterminate;
   every characterized delta refines the profile, run-sheet, or envelope.
   The run is done when the envelope is satisfied AND reproduction passes AND
   strict-absence cleanup returns zero.

## What the first two windows measured (design constraints for any new surface)

- **PSDirect teardown race**: `Remove-PSSession` on a PSDirect session throws
  a terminating NullReferenceException ~25-50% of the time, AFTER the work
  succeeded, and `-ErrorAction SilentlyContinue` does not suppress it. Capture
  output before teardown; wrap the removal in try/catch. (Plumbing,
  `tools/session_repl.ps1`.)
- **The helper console self-shadows**: each task-scheduler invocation's own
  console takes and holds foreground while the helper runs. A foreground-based
  UIA dump sees the helper console, not the surface. All orientation is
  therefore **z-order-independent**: the top-level window enumeration
  (`windows` action) + hwnd-targeted `uia_dump`/`screenshot`. The foreground
  is forced deliberately, right before a gesture, via the mouse action's
  `focus_hwnd` (ALT-tap EnsureForeground).
- **Dialog focus resets across invocations**: a dialog click in one
  invocation and typing in the next do not compose — focus is back on the
  dialog's default control. Anything that must land in one focus context
  (click a combo, then type; open a menu, then pick an item) goes through the
  composite `keys` action: one invocation, click + chords + per-character
  text with delays.
- **Popup surfaces die between invocations**: context menus, ComboBox
  dropdown lists (`ComboLBox`), and menus opened by menu-key all close when
  the next invocation's console takes foreground. Never plan a
  open-then-act-across-invocations sequence.
- **Legacy Win32 controls are UIA-flat**: MMC dialogs expose their buttons,
  radios, and checkboxes as unnamed-class **Pane** elements whose NAME is the
  visible label. Filtering by `control_type == "Button"` finds nothing. Match
  by name; prefer placed matches (a rect) over rect-less duplicates.
- **The MMC scope tree is UIA-invisible; the results pane is not**:
  navigate by double-clicking ListItem entries in the results pane. Long
  lists are virtualized — items below the fold need type-ahead (click any
  item, type the name, ENTER) before they can be addressed.
- **PSDirect blackouts are real**: after a guest reboot, PowerShell Direct
  can answer nothing for a long window (measured 25-60 minutes in the first
  window). Classify as `booting_blackout` and wait; never retry hot.

## Onboarding checklist (per new surface)

1. **Recon** (one session, driver-development mode, checkpoint verified):
   launch the tool via a scheduled task (Interactive + Highest, no UAC
   mid-flight); `windows` enum → hwnd; hwnd-targeted dump at depth 12;
   record the window class, title, and control naming conventions (Pane vs
   Button vs ListItem).
2. **Map the dialog flows** for the capabilities the evidence lanes need.
   For each dialog: what opens it, which controls take text, what commits
   (OK? Apply? editor close?), what prompts appear (Server 2025 wording
   differs from the classic dialogs — the R4 radio dialog is titled "Add
   Object" and comes AFTER the ACL editor, not before).
3. **Write the profile** with every observed action classified. Undeclared
   actions refuse to run — that is the point. Mark everything UNVERIFIED
   until qualification proves it.
4. **Write the capability spec + run-sheet + observers** for the first
   capability. Choose the cheapest one first (a setup-only transaction like
   R1 exercises the whole engine with zero surface risk).
5. **Qualify**: run `wcd exec-transaction --capability ... --arg ...`.
   Expect: first run disproves or aborts (selectors, timing, focus); each
   characterized delta (the record carries the full delta) drives one
   refinement; rerun until `verified` with clean strict-absence cleanup.
   Then commit the artifacts together — profile, spec, run-sheet, observer,
   and the qualification record.
6. **Register the claims** in `docs/claim-registry.md` from the record, with
   the independence note (which channels observed vs actuated).

## Non-negotiables (whatever the surface)

- The oracle never shares a channel with the actuation.
- A disproven result is a RESULT: bank the characterized delta, fix the
  spec/profile, and let the next run verify. Never loosen an envelope to
  make a red run green — encode the measured truth instead.
- Cleanup is strict-absence verified, per-step independent (a failed backup
  never skips GPO removal), and residual-accounted.
- Values in evidence artifacts are synthetic; identifiers stay on the estate.
