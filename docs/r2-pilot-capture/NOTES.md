# R2 pilot capture — 2026-09-03, first transactionally verified GUI capture

Authored entirely through the console driver loop (helper UIA/keyboard/mouse +
host-side Msvm_Keyboard for console unlock) on LabMS01 (Server 2025, build
26100 family); values are synthetic; GPO removed after capture, strict absence
re-query returned zero rows. Oracle: PowerShell Direct SYSVOL read, independent
of the actuation path. Answers:

1. scripts.ini is UTF-16LE with BOM (FF FE), CRLF endings, a leading blank
   line, split-style entries (0CmdLine=/0Parameters=), and an explicit empty
   1Parameters= for a parameterless script.
2. psscripts.ini carries [ScriptsConfig] with StartExecutePSFirst=true for the
   "Run Windows PowerShell scripts first" ordering. No [Policy] section exists
   on the wire; RunLogonScriptsSync / RunLogoffScriptsSync / LegacyScriptsFirst
   / PowerShellOrder appear nowhere.
3. Machine version incremented 0 -> 1 in gpt.ini and AD versionNumber.
4. gpt.ini retained displayName=New Group Policy Object (the name the GPO was
   created with via New-GPO; GPMC did not rewrite it).
