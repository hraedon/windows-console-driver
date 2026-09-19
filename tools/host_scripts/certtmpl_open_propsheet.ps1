# Host script (hyperv_input channel): open the selected row's property sheet
# in the certtmpl.msc console via the VM-bus synthetic keyboard+mouse.
#
# MEASURED (window 10 phase-2 continuation, 2026-09-19, LabMS01):
# - The context-menu walk is DEAD as a gesture channel: VM-bus DOWN events
#   stop moving the menu highlight after ~3 presses while an MMC context
#   menu is open, and the helper channel truncates even sooner (runs
#   22-30). ALT+ENTER replaces the walk entirely: with keyboard focus in
#   the results list, ALT+ENTER on the selected row opens that row's
#   property sheet directly on the General tab.
# - Keyboard focus does NOT follow selection. A window-anchored click plus
#   type-ahead moves the SELECTION but leaves keyboard focus on the tree
#   pane (this is what failed run 33: VM-bus Shift+F10 went to the
#   tree-focused window and no row menu ever opened). Only a real click on
#   a results row puts keyboard focus in the list, so this script performs
#   its own click at a measured constant position (console maximized at
#   1024x768, results list center = 500,340) and re-types the row prefix.
# - Msvm_SyntheticMouse.SetAbsolutePosition takes RAW PIXELS on this stack
#   (the 0..32767 grid values clamp to the screen corner, measured: cursor
#   read back 1023,767 after a 16000,14512 request). ClickButton indices
#   measured: 1 = LEFT (selects the row under the cursor), 2 = RIGHT
#   (opens a context menu), 0 = no visible effect.
# - Helper-task invocations flash their own console window to the
#   FOREGROUND (probe measured foreground = "Administrator:
#   ...powershell.exe" ConsoleWindowClass right after a task run):
#   keyboard injected right after a helper step can land in that console
#   instead of MMC. The leading ESC plus mouse click self-anchor this
#   script against that seam.
# - GESTURE SHAPE IS LOAD-BEARING, measured the hard way: the exact
#   sequence below (bare [void] CIM key calls, one ESC at ~0.5s settle,
#   save-to-file thumbnail shots, the ALT+ENTER chord as consecutive
#   statements) opened the sheet on every live execution (3/3 standalone,
#   2/2 in-transaction-shaped); a "hardened" variant of this same script
#   (ReturnValue-checked key wrappers, bitmap-returning capture function,
#   longer ESC settle) failed the identical state 7/7 with the chord
#   landing as a no-op -- bisected across every delta in isolation, each
#   ruled out, the composite still failing. Do not refactor this script's
#   input-call shapes without a live re-verification window.
# - In-script verification (fail closed): the pre-chord and post-chord
#   frames are saved to a host temp dir and compared by file hash; equal
#   hashes mean the chord changed nothing and the script throws. No helper
#   polling involved.
# - Params are UNtyped on purpose: typed params in scripts shipped from a
#   pwsh 7 controller into the host's Windows PowerShell endpoint break
#   downstream CIM instance binding (measured 2026-09-19).
param($VmName, $RowPrefix)
$ErrorActionPreference = 'Stop'

if (-not $VmName -or $VmName -notmatch '^[Ll]ab[A-Za-z0-9]{1,12}$') {
    throw "refusing:VmName must name a disposable lab guest, got length $($VmName.Length)"
}
if (-not $RowPrefix -or $RowPrefix -notmatch '^[A-Za-z0-9][A-Za-z0-9 ]{0,31}$') {
    throw "refusing:RowPrefix must be a short alphanumeric list prefix, got [$RowPrefix]"
}

Add-Type -AssemblyName System.Drawing
$ns = 'root\virtualization\v2'
$service = Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemManagementService
$vm = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "ElementName='$VmName'"
if (-not $vm) { throw "vm_not_found:$VmName" }
$kb = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_Keyboard | Select-Object -First 1
if (-not $kb) { throw "no_keyboard:$VmName" }
$mouse = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_SyntheticMouse | Select-Object -First 1
if (-not $mouse) { throw "no_mouse:$VmName" }
$settings = @(Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_VirtualSystemSettingData |
  Where-Object { "$($_.VirtualSystemType)" -eq 'Microsoft:Hyper-V:System:Realized' })
if ($settings.Count -ne 1) { throw "expected 1 realized setting, got $($settings.Count)" }

function Press([uint32]$vk) { [void](Invoke-CimMethod -InputObject $kb -MethodName PressKey -Arguments @{ keyCode = $vk }) }
function Release([uint32]$vk) { [void](Invoke-CimMethod -InputObject $kb -MethodName ReleaseKey -Arguments @{ keyCode = $vk }) }
function TapVK([uint32]$vk) { Press $vk; Start-Sleep -Milliseconds 130; Release $vk; Start-Sleep -Milliseconds 400 }
function TypeLower([string]$Text) {
  for ($i = 0; $i -lt $Text.Length; $i++) {
    $vk = [uint32](0x41 + [int]([char]$Text[$i] - [char]'a'))
    Press $vk; Start-Sleep -Milliseconds 60; Release $vk; Start-Sleep -Milliseconds 110
  }
}
$dir = Join-Path $env:TEMP ("wcd-propsheet-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $dir -Force | Out-Null
function Shot([string]$tag) {
  $result = Invoke-CimMethod -InputObject $service -MethodName GetVirtualSystemThumbnailImage `
    -Arguments @{ TargetSystem = $settings[0]; WidthPixels = [uint16]800; HeightPixels = [uint16]600 }
  if ($result.ReturnValue -ne 0) { throw "thumbnail failed: $($result.ReturnValue)" }
  $data = $result.ImageData
  $bitmap = New-Object System.Drawing.Bitmap([int]800, [int]600)
  for ($y = 0; $y -lt 600; $y++) {
    for ($x = 0; $x -lt 800; $x++) {
      $i = ($y * 800 + $x) * 2
      if ($i + 1 -ge $data.Count) { break }
      $pixel = [int]$data[$i] -bor ([int]$data[$i + 1] -shl 8)
      $r = [int]((($pixel -shr 11) -band 0x1F) * 255 / 31)
      $g2 = [int]((($pixel -shr 5) -band 0x3F) * 255 / 63)
      $b = [int](($pixel -band 0x1F) * 255 / 31)
      $bitmap.SetPixel($x, $y, [System.Drawing.Color]::FromArgb($r, $g2, $b))
    }
  }
  $bitmap.Save((Join-Path $dir "$tag.png"), [System.Drawing.Imaging.ImageFormat]::Png)
  $bitmap.Dispose()
}

TapVK 0x1B
Start-Sleep -Milliseconds 500
[void](Invoke-CimMethod -InputObject $mouse -MethodName SetAbsolutePosition -Arguments @{ HorizontalPosition = [int32]500; VerticalPosition = [int32]340 })
Start-Sleep -Milliseconds 300
[void](Invoke-CimMethod -InputObject $mouse -MethodName ClickButton -Arguments @{ ButtonIndex = [uint32]1 })
Start-Sleep -Milliseconds 600
TypeLower $RowPrefix
Start-Sleep -Milliseconds 900
Shot 'selected'
Press 0x12; Start-Sleep -Milliseconds 150; Press 0x0D; Start-Sleep -Milliseconds 250; Release 0x0D; Release 0x12
Start-Sleep -Seconds 2
Shot 'sheet'
$a = (Get-FileHash (Join-Path $dir 'selected.png') -Algorithm MD5).Hash
$b = (Get-FileHash (Join-Path $dir 'sheet.png') -Algorithm MD5).Hash
if ($a -eq $b) { throw "sheet_not_open:frames=$dir" }
"propsheet_open=1 frames=$dir"
