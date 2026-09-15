# Setup script: launch the GPMC main console in the console session
# (scheduled task, Interactive + Highest => elevated token on the console
# desktop, no UAC mid-flight). Mirrors gpme_launch.ps1: the reliable route on
# the rebased estate is cloning the committed WCDHelper task's XML (which
# carries the domain-SID principal) and swapping only the Actions subtree.
# Unlike gpme_launch there is no /gpobject argument: gpmc.msc opens onto the
# machine's own forest.
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
$argEl.InnerText = 'gpmc.msc'
[void]$exec.AppendChild($argEl)
$actions.RemoveAll()
[void]$actions.AppendChild($exec)

Register-ScheduledTask -TaskName 'WCDLaunchGPMC' -Xml $doc.OuterXml -Force | Out-Null
Start-ScheduledTask -TaskName 'WCDLaunchGPMC'
"launched=1"
