# IIS evidence reads and guarded WEL writes

The remediation program's R3 decision is **option b**, a guarded WEL recipe.
Its two required writes do not justify weakening console capability schema v0.
WCD gains R4/R5 read primitives with no transport or estate requirement. They
can inspect a file copied through any already authorized collection channel.

```console
wcd read-iis-security-value --config <collected-apphost> --location "Synthetic Site/Enrollment"
wcd iis-config-history --config <collected-live-apphost> --history <collected-history-root> --location "Synthetic Site/Enrollment" --diff CFGHISTORY_0000000035
```

Repeat `--location` for multiple locations. History names are enumerated, never
treated as paths; `--diff live` compares every snapshot against live. Output
includes byte digest/size, collection-file mtime, per-location security values,
and comparison booleans/digests. Missing/malformed snapshots produce an explicit
error and CLI exit 3; invalid requests exit 2. No missing value becomes a schema
default. Flags are lists, enabled is boolean or unknown, and provider operations
preserve `clear`/`remove` plus order. The history mtime is that of the collected
copy unless the collection channel preserved the source timestamp.

`tools/guest_scripts/read_iis_security_value.ps1` separately reads effective
WebAdministration values and location-tag values from one captured file image.
It attaches provenance to both. Enum/flags objects are themselves values: the
negative fixture pins naive `.Value` to null while the helper returns typed truth.
The Python file parser does not infer effective configuration. Its `lock_state`
reports apphost declarations and their scope, not every possible child
web.config, schema default or runtime section lock.

## Live result, 2026-10-14 (operator timezone)

One Server 2025 CA, two enrollment locations. The effective API and committed
location tags both returned EPA `Require`, SSL `Ssl, Ssl128`. One read query over
the ten retained history snapshots identified 34/36 as the dirty variants and
29-33/35 as the original; live matched 35 byte-for-byte. Snapshots 27/28 from the
earlier report had already aged out and were not requalified. Snapshots 37/38
also matched the original at collection time.

The consuming WEL harness then separately seeded EPA and SSL at one location,
verified each entire committed XML delta, obtained a red CLOSE, restored the
explicit pinned pre-write bytes, and obtained green CLOSE across six declared
surfaces. Both enrollment locations were reread afterwards. Zero WEL tasks and
no window marker remained. Raw estate data, task payloads/parameters, write and
restore records, observations and verdicts remain in the operator's private
evidence corpus; the committed summary pins its inventory and the synthetic
test corpus. The summary is a read qualification record, not a native WCD
transaction record, and claims no WCD capability qualification.

## Correction to the proposed history oracle

IIS history is sampled periodically (default two minutes), not a transactional
one-snapshot-per-API-write log. A direct file write can also be captured by that
service. Therefore absence/surplus is telemetry, not failure of an exact API
count invariant, and history does not authenticate a writer. This follows the
Microsoft [configHistory reference](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/confighistory)
and [history service description](https://learn.microsoft.com/en-us/iis/manage/managing-your-configuration-settings/using-configuration-history-with-iis-7-and-iis-8).
WEL restores its explicit digest-pinned backup rather than selecting a history
snapshot by ordinal or age.

## Validation and next architectural boundary

WCD: full Windows suite 760 passed; Ruff and mypy (`wcd`, `gpo_observers`) clean.
The new guest helper passes PS 5.1 execution against fakes and ScriptAnalyzer.
The recursive analyzer also reports 20 pre-existing warnings in older operator
scripts; this change does not broaden exclusions or rewrite those scripts.
The touched registry prose is now anonymized. A bounded identifier scan of the
staged files passed; a whole-tree scan still finds identifiers in previously
banked records and older notes. Those immutable historical records were not
rewritten, and this increment does not claim a clean historical corpus.

WEL: Linux full suite 620 passed, 7 expected skips, 67 subtests; Windows exercised
all 42 new tests successfully. Its full Windows run hit four existing symlink
failures (`WinError 1314`, reproduced on the untouched checkout). Ruff, strict
mypy and recursive ScriptAnalyzer passed. These platform limits are not live
qualification gaps in the newly exercised job/restore paths.

Full WCD IIS capabilities remain a deliberate future schema version: define a
non-console channel contract, independent fact observers, exact envelope,
commit/cleanup/recovery policy and record binding, then qualify that revision.
No `iis.set_*` capability is advertised by this increment. The WEL recipe and
session-close protocol are documented in that repository's `docs/session-surfaces.md`.
