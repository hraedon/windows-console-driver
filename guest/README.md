# guest/

Scripts that run on Windows machines, not on the controller. Both are
Windows PowerShell 5.1 (no pwsh assumed), single-shot, and speak JSON
envelopes with exit codes: 0 ok, 2 error, 3 indeterminate. Both are
implemented against their contracts (docs/contract.md sections 8 and 9) and
are **unqualified**: their real behaviour is unknown until the first estate
window, per contract section 13. Only the read-only actions of `helper.ps1`
have been smoke-tested against a live desktop.

## helper.ps1 -- in-guest console helper

Runs in the target user's interactive session. One JSON request object on
stdin, one single-line JSON response object on stdout, diagnostics on stderr
only. It returns facts and injects input; it never interprets either.

```console
C:\> echo {"action":"context"} | powershell -NoProfile -File helper.ps1
{"action":"context","ok":true,"session_id":2,"user":"LAB\\alice",
 "desktop":"Default","foreground":{"hwnd":943458438,"pid":25296,
 "process_name":"ZCode","title":"ZCode","class":"Chrome_WidgetWin_1",
 "rect":{...},"uia_digest":"856262..."},"notes":[]}
```

Actions and their requests (response envelopes are locked key-for-key by
`tests/test_helper_contract.py` against the TypedDicts in
`src/wcd/helper_client.py`):

| Action | Request (beyond `"action"`) |
|---|---|
| `context` | none |
| `uia_dump` | `depth` (1..12, default 4) |
| `screenshot` | `full` (bool; whole virtual screen instead of the foreground rect) |
| `key` | `text` and/or `vks: [{vk, modifiers: [ctrl\|alt\|shift\|win]}]` |
| `mouse` | `x`, `y` (window-relative), `button` (left\|right), `mouse_action` (click\|double\|down\|up), optional `hwnd` reference window |
| `wait_foreground` | `title_regex` and/or `class` and/or `pid`, `timeout_ms` (100..60000), `poll_ms` (50..2000) |

Inject actions (`key`, `mouse`) honour `-DryRun` (or the request field
`"dry_run": true`): the request is validated, `would_inject` carries the
computed summary -- including the window-relative to screen conversion
through the reference window (the foreground window of the same request, or
the explicit `hwnd`) -- and nothing is injected. **Tests and development
against a live desktop must use `-DryRun` for every inject action.**

Honesty rules baked into the envelope:

- Anything undeterminable is `null` plus an entry in `notes`
  (`"<field>: unresolved (...)"`) -- never a guess.
- Typed text is never echoed back: only its length and sha256. Text of 12+
  characters with upper case, lower case and a digit is marked
  `"secret_shaped_warning": true` and still proceeds -- the policy layer
  prohibits secrets; the helper only warns.
- `uia_digest` is a compatibility contract (`uia-digest-v1`: sha256 over the
  first 64 UIA elements, breadth-first, `name<US>class<US>control-type-id`);
  an over-budget walk reports null rather than a timing-dependent value. It
  legitimately changes when the content is dynamic.
- `wait_foreground` timeout is exit 3 (indeterminate) with the last observed
  foreground -- a result to reconcile, never a failure to retry.

## hyperv-input.ps1 -- host-side fallback injector

Runs on the Hyper-V host, through the same route as
`windows-evidence-lab/scripts/capture_guest_console.ps1` (credential from
`HYPERV_CONTROL_USERNAME`/`HYPERV_CONTROL_PASSWORD`, `New-PSSession
-Authentication Negotiate`, `Remove-PSSession` in finally). Injects via
`Msvm_Keyboard` (`PressKey` vk codes, `TypeText`) and `Msvm_SyntheticMouse`
(absolute 0..65535 normalized guest coordinates, `SetButtonState`).

```console
C:\> powershell -NoProfile -File hyperv-input.ps1 -HostName hv-01 `
       -VMName LabCL01 -Action mouse -X 32768 -Y 16384 -Button left `
       -MouseAction click
{"ok":true,"vm":"LabCL01","action":"mouse","injected_count":3,"note":"Blind channel: ..."}
```

`-VMName` must match `^[Ll]ab[A-Za-z0-9]{1,12}$` -- disposable guests only;
the naming convention is the guard against touching real machines.

`-ValidateOnly` validates the parameters and prints the plan JSON (exit 0)
without any network or WMI call; tests run every action through it. All
validation lives in the script body so every refusal is the JSON envelope
with exit 2, never a parameter-binding abort with exit 1.

**This channel is blind**: a real run returns `{ok, injected_count}` and
nothing about where the input landed or what it changed. Outcomes are
resolved through independent observation, never through this report.
