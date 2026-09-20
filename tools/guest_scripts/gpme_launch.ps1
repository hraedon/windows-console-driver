# Setup script: deep-launch GPME straight onto a GPO in the console session
# (scheduled task, Interactive + Highest => elevated token on the console
# desktop, no UAC mid-flight).
# MEASURED 2026-09-03 (second estate window): the /gpobject:"domain\{guid}"
# form raises a "Group Policy Error" dialog on Server 2025 and mmc exits; the
# LDAP-path form opens the editor onto the GPO reliably.
# MEASURED 2026-09-05 (fifth estate window, rebased baseline): the cmdlet
# registration path is unreliable on the rebased guest — the estate carries a
# LOCAL 'claude' bootstrap account (machine SID) beside domain 'claude', and
# New-ScheduledTaskPrincipal re-resolves the account to the LOCAL SID
# intermittently (event 332 "user not logged on"; LSA lookups also transiently
# fail with "No mapping between account names and security IDs"). The reliable
# route is XML: clone a known-good committed task's XML (WCDHelper carries the
# domain-SID principal), swap the Actions subtree through the XML DOM, and
# register with -Xml. Passing the domain SID through New-ScheduledTaskPrincipal
# does NOT help — the re-resolution happens inside registration.
param([string]$Guid, [string]$Domain)
$ErrorActionPreference = 'Stop'
$dcParts = foreach ($label in $Domain.Split('.')) { "DC=$label" }
$ldap = 'LDAP://CN={' + $Guid + '},CN=Policies,CN=System,' + ($dcParts -join ',')
$arg = '/gpobject:"' + $ldap + '"'

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
$argEl.InnerText = "gpedit.msc $arg"
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

Register-ScheduledTask -TaskName 'WCDLaunchGPME' -Xml $doc.OuterXml -Force | Out-Null
Start-ScheduledTask -TaskName 'WCDLaunchGPME'
"launched=1"
