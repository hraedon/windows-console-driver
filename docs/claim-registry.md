# Claim registry

Bookkeeping for the independence discipline: each evidence claim this project
pursues maps to the observers that can certify it and the independence
relationship between them. "Limit the claim to what the second oracle actually
proves" is enforced here, in review, not in folklore.

Status: empty — no real-environment claims have been certified by this
component yet. The first entries land with the estate-window spike and the R2
pilot transaction.

| Claim | Certifying observer(s) | Category | Independence notes | Certified |
|---|---|---|---|---|
| GPMC (Server 2025) writes `scripts.ini` as UTF-16LE BOM + CRLF, split-style entries, empty `1Parameters=` retained | Oracle read via PSDirect (`oracle-read.ps1`), bytes + decoded | state | Observer is PowerShell Direct; actuation was helper UIA/keyboard via the console session — no shared code or channel | 2026-09-03 (R2 pilot) |
| `psscripts.ini` ordering is encoded as `[ScriptsConfig] StartExecutePSFirst=true`; no `[Policy]` section exists on the wire | Same oracle read | state | Same independence; the actuated dropdown ("Run Windows PowerShell scripts first") and the observed key are linked by one controlled transaction | 2026-09-03 (R2 pilot) |
| Machine version increments by exactly 1 in gpt.ini and AD `versionNumber` on this authoring transaction | Same oracle read (pre from R2 setup: new GPO at 0) | state | `derive` relation, not literal; both stores read independently | 2026-09-03 (R2 pilot) |
