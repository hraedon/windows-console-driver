# Setup script: launch the Certificate Templates console (certtmpl.msc) in
# the console session (scheduled task, Interactive + Highest => elevated
# token on the console desktop, no UAC mid-flight). Mirrors gpmc_launch.ps1:
# the reliable route on the rebased estate is cloning the committed
# WCDHelper task's XML (which carries the domain-SID principal) and swapping
# only the Actions subtree. certtmpl.msc opens directly into the Certificate
# Templates container view: a flat, virtualized results list (no tree
# navigation before the first gesture).
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
$argEl.InnerText = 'certtmpl.msc'
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

Register-ScheduledTask -TaskName 'WCDLaunchCertTmpl' -Xml $doc.OuterXml -Force | Out-Null
Start-ScheduledTask -TaskName 'WCDLaunchCertTmpl'
"launched=1"
