# Host script (hyperv_input channel): open the selected row's property sheet
# in the certtmpl.msc console via the VM-bus synthetic keyboard.
#
# MEASURED CONTEXT (window 10, runs 22-30): the helper channel's SendInput
# sequences TRUNCATE after roughly one event once an MMC context menu opens
# on this Server 2025 build -- six menu walks, END/UP jumps and two
# accelerator chars all failed to activate the Properties item, while the
# identical walk shape through the VM-bus keyboard (Msvm_Keyboard) drives
# the guest reliably: the logon injection delivered 250+ event sequences
# without loss. The VM-bus keyboard is hardware-level input and does not
# contend with the helper console's foreground self-shadowing at all.
# The capability's channel contract declares both input deliveries;
# this gesture rides hyperv_input.
#
# The walk: Shift+F10 opens the row's context menu (measured item order:
# Open, Duplicate Template, Delete, Rename, Refresh, -, Export List, -,
# Properties at index 6, -, Help), six DOWNs land on Properties, ENTER
# activates it. Params are UNtyped on purpose: typed params in scripts
# shipped from a pwsh 7 controller into the host's Windows PowerShell
# endpoint break downstream CIM instance binding (measured 2026-09-19).
param($VmName)
$ErrorActionPreference = 'Stop'

if (-not $VmName -or $VmName -notmatch '^[Ll]ab[A-Za-z0-9]{1,12}$') {
    throw "refusing:VmName must name a disposable lab guest, got length $($VmName.Length)"
}

$ns = 'root\virtualization\v2'
$vmObj = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "ElementName='$VmName'"
if (-not $vmObj) { throw "vm_not_found:$VmName" }
$kb = Get-CimAssociatedInstance -InputObject $vmObj -ResultClassName Msvm_Keyboard | Select-Object -First 1
if (-not $kb) { throw "no_keyboard:$VmName" }

function Press-VK([uint32]$vk) {
    $r = Invoke-CimMethod -InputObject $kb -MethodName PressKey -Arguments @{ keyCode = $vk }
    if ($r.ReturnValue -ne 0) { throw "press_failed:$vk" }
}
function Release-VK([uint32]$vk) {
    $r = Invoke-CimMethod -InputObject $kb -MethodName ReleaseKey -Arguments @{ keyCode = $vk }
    if ($r.ReturnValue -ne 0) { throw "release_failed:$vk" }
}
function Tap-VK([uint32]$vk) {
    Press-VK $vk
    Start-Sleep -Milliseconds 120
    Release-VK $vk
    Start-Sleep -Milliseconds 180
}

# Shift+F10 (context menu on the selected row), then the walk, all on the
# VM bus: menu open -> six DOWNs -> ENTER on Properties.
Press-VK 0x10
Press-VK 0x79
Start-Sleep -Milliseconds 150
Release-VK 0x79
Release-VK 0x10
Start-Sleep -Milliseconds 800

for ($i = 0; $i -lt 6; $i++) { Tap-VK 0x28 }
Start-Sleep -Milliseconds 150
Tap-VK 0x0D

'propsheet_walk_sent=1'
