# Estate window 12 — the WEL-hosted certtmpl lane (2026-09-22)

The deferred composition thread, closed: the first WEL-hosted
`interactive_transaction` run of `certtmpl.duplicate_template`, executed
through WEL's scenario runner on mvmcc02 (checkout `e6ab5a1`, driver checkout
at `d17b7d4`) against the same qualified capability bytes window 10 verified
(digest `a9169bf3…`, pinned two ways in WEL's committed example).

**One run, verified.** Run id `b4c82b18-2dbe-48a1-8288-d96491dba53f`,
transaction `06095868-17f6-4367-89bb-89446be57cbe`, record banked at
`records/w12-r1-record.json` (state `verified`, 13 clauses satisfied,
0 unresolved / 0 violated / 0 unclassified, all 11 deltas covered, converged
after 2 polls and 2 reproductions, cleanup `remaining=0` /
`removed=zz-welab-certtmpl-01` / task unregistered). The prepare-phase context
capture in the record carries `uia_digest 9193a3df…` — the same prepared
desktop digest the GPMC surfaces banked, now also banked for certtmpl and
certsrv in this branch's profiles (WI-L5's promise kept at qualification).

The directory was then asked directly, in a session that shares no channel
with the driver: **33 template objects, zero `zz-*` of any kind, target
absent.** The scenario's final `revert_environment` restored the member to
`domain-joined` (12 s); the console session it consumed was re-established
afterwards with `estate_bringup`'s CAD injection, first try, twice in one day.

## What this window measured about the composition seam

These are the findings the lane existed to surface — each one cost a failed
attempt or a red canary before it was understood:

1. **The identity vocabulary is the seam.** WEL's `wait_ready` hardcodes
   `IdentityRole.GUEST_BOOTSTRAP` for every PSDirect probe
   (`hyperv.py:2084`), and the backend config refuses two identities bound to
   one credential capability — so a backend cannot declare `guest_bootstrap`
   and `domain_operator` over the same secret. Meanwhile WCD (since the
   record-v2 binding) refuses a plan whose `identity` differs from the
   estate's `identity_role`. The convergence that ran green: WEL backend
   `[identity.guest_bootstrap]`, lane identity `guest_bootstrap`, and the
   mvmcc02 WCD checkout's `local/estate.toml` set to
   `identity_role = "guest_bootstrap"`. The workstation's WCD estate file
   keeps `domain_operator` for WCD-direct runs — the same estate answers two
   role labels depending on which checkout drives it, which is a wart, not a
   design. The durable fix is WEL-side: resolve the PSDirect identity from
   the backend config instead of the hardcoded enum.
2. **Vault-mediated lab credentials are down on mvmcc02.** The lab AppRole in
   `~/.config/opencode/vault.env` no longer authenticates (login fails; the
   cert-watch AppRole is properly scoped away from `kv/homelab/lab/*`), so
   `acb exec` cannot inject the four credential envs or mint a checkout
   receipt. The run therefore proceeded under the interim conventions: the
   four env vars were injected by the operator from the sanctioned
   `C:\temp\lab` credential files, and `ACB_CHECKOUT_RECEIPT` was
   operator-minted (schema `acb.checkout-receipt.v1`, true capability ids and
   env-name bindings, 45-minute window). The receipt contract is provenance
   metadata by its own docstring — deliberately not an authorization token —
   and this disclosure is the honest provenance: the parent process was an
   operator shell, not `acb exec`. **Owner action needed: rotate the lab
   AppRole secret_id.**
3. **A revert-based lane resets the member's clock to the checkpoint era**
   (~44 h stale), exactly as every DC restore always has — but
   `estate_bringup`'s clock repair is DC-scoped, so the member needs its own.
   The canary catches it as kerberos red while every NTLM path stays green.
   Today's repair: a tz-safe `Set-Date` from host UTC over PSDirect
   (`offset = Now - UtcNow` added to the passed UTC — the guest is UTC here,
   but the recipe does not assume it). Follow-up worth a PR: a member-clock
   step in `estate_bringup`, or a WEL-side clock re-seed inside
   `revert_environment`.
4. **`revert_environment` on this host leaves the member Running** (the
   restore of a Running guest that window-9 measured as resuming-running
   holds through WEL's path too), but session-less by construction — the
   baseline has no console session. `estate_bringup` re-establishes it in
   about a minute, and did so first try both times today.

## Estate left as found

All lab guests Running (CAroot Off, as found), member clock re-seeded after
the post-run revert, console session Active, canary green end-to-end
(exit 0). The mvmcc02 operator artifacts: `local/run-certtmpl-1-live.json`
(the full run JSON incl. journal and backend result),
`local/run-certtmpl-1-live.failed1.json` (the identity-mismatch failure,
no mutation, transaction skipped), `local/scenarios/certtmpl-lane-live.json`
+ `capabilities/certtmpl.duplicate_template.json` (byte-identical to the
committed copy), and `local/backend.toml` with the identity section renamed
(backup `backend.toml.pre-certtmpl-lane`).

## Corrections (2026-09-24)

Both composition follow-ups named above are now closed in code, offline
qualified (their live proof rides the next window):

- The identity seam (finding 1): WEL's `wait_ready` no longer hardcodes
  `guest_bootstrap` — it resolves the probe identity from the backend's
  declared identities (bootstrap preferred when declared, else the sole
  declared role). A backend declaring only `[identity.domain_operator]` can
  now probe readiness, so the estate can carry one role label end to end
  and the mvmcc02 `identity_role = "guest_bootstrap"` convergence wart can
  be retired at the next lane run.
- The member clock (finding 3): `estate_bringup` grew step 4/7, the member
  clock — same probe, tolerance, and tz-safe Set-Date as the DC step, and
  deliberately no dsregdns/NetLogon restart (the 2026-09-22 repair went
  green on the canary with Set-Date alone).
