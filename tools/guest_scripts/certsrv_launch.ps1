# Setup script: launch the Certification Authority console (certsrv.msc) in
# the console session (scheduled task, Interactive + Highest => elevated
# token on the console desktop, no UAC mid-flight). Mirrors
# certtmpl_launch.ps1: the reliable route on the rebased estate is cloning
# the committed WCDHelper task's XML (which carries the domain-SID
# principal) and swapping only the Actions subtree.
#
# Unlike certtmpl.msc, this console administers a REMOTE service: the
# mutation it commits lands in LabCA01's registry while the gesture runs on
# the console guest. Whether it opens already targeted at a CA is a measured
# fact recorded in docs/estate-window-11/NOTES.md, not an assumption.
$ErrorActionPreference = 'Stop'

$templateName = 'WCDHelper'
if (-not (Get-ScheduledTask -TaskName $templateName -ErrorAction SilentlyContinue)) {
    throw "template task '$templateName' not found; cannot clone a domain-SID principal"
}
[xml]$doc = (Export-ScheduledTask -TaskName $templateName)
$ns = 'http://schemas.microsoft.com/windows/2004/02/mit/task'
$actions = $doc.Task.Actions
$exec = $doc.CreateElement('Exec', $ns)
$cmd = $doc.CreateElement('Command', $ns)
$cmd.InnerText = "$env:SystemRoot\System32\mmc.exe"
[void]$exec.AppendChild($cmd)
$argEl = $doc.CreateElement('Arguments', $ns)
# MEASURED 2026-09-21 (window 11 recon): certsrv.msc launched with no
# argument does not open a console frame at all -- it opens a modal #32770
# titled 'Microsoft Active Directory Certificate Services' reading "Cannot
# manage Active Directory Certificate Services. The system cannot find the
# file specified. 0x80070002", because the snap-in resolves the LOCAL
# CertSvc configuration and the console guest is not a CA.
#
# This launcher takes NO target parameter, and that absence is a measured
# result rather than an omission. Four command-line forms were tried against
# the live estate -- bare, a positional host, /computer=<host>, and
# /computer <host> -- and all four produced the identical modal with the
# frame behind it still titled "Certification Authority (Local)". The
# snap-in has no command-line target, so the target is set by the Retarget
# gesture inside the console, where the run-sheet declares it and the frame
# title proves it landed.
$argEl.InnerText = 'certsrv.msc'
[void]$exec.AppendChild($argEl)
$actions.RemoveAll()
[void]$actions.AppendChild($exec)

# MEASURED 2026-09-20 (certtmpl qualification window): the cloned XML also
# carries WCDHelper's Settings, whose ExecutionTimeLimit is PT5M -- sized for
# a helper invocation that answers in seconds. Task Scheduler applies it to
# the console this task launches, so mmc.exe was terminated five minutes
# after launch (LastTaskResult 267014 = SCHED_S_TASK_TERMINATED), mid-flow,
# with nothing in the surface's own behaviour to explain it. The console
# outlives its launcher on purpose; cleanup's mmc_kill is what ends it, so
# the clone is given an hour -- bounded, not unlimited, and far outside any
# transaction.
$settings = $doc.Task.Settings
if ($null -ne $settings.ExecutionTimeLimit) { $settings.ExecutionTimeLimit = 'PT1H' }

Register-ScheduledTask -TaskName 'WCDLaunchCertSrv' -Xml $doc.OuterXml -Force | Out-Null
Start-ScheduledTask -TaskName 'WCDLaunchCertSrv'
"launched=1"
