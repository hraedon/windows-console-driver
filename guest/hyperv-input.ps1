#requires -Version 5
<#
.SYNOPSIS
    Blind host-side input fallback for a lab guest, through the hypervisor.

.DESCRIPTION
    guest/hyperv-input.ps1 implements the Hyper-V input backend
    (docs/contract.md section 9). It runs on the Hyper-V host and injects
    keyboard and mouse input into a guest via Msvm_Keyboard (PressKey,
    per-character PressKey; this build of Msvm_Keyboard has no TypeText) and
    Msvm_SyntheticMouse (absolute position, button state). It
    is the fallback used when the in-guest helper (helper.ps1) is defeated,
    and only when the capability's channel contract admits hyperv_input.

    ROUTE. Exactly the route of windows-evidence-lab's
    scripts/capture_guest_console.ps1: a PSCredential built from the
    HYPERV_CONTROL_USERNAME / HYPERV_CONTROL_PASSWORD environment variables
    (launch through the credential broker; no secret reaches argv, a file, or
    output), New-PSSession -ComputerName -Authentication Negotiate, the work
    inside Invoke-Command on that session, Remove-PSSession in finally.

    THE REALIZED-SETTINGS LESSON. A guest with checkpoints has MORE THAN ONE
    Msvm_VirtualSystemSettingData: one realized setting for the running
    machine, plus a snapshot setting for every checkpoint. Anything handed
    the whole array is really asking to operate on "several machines", and
    the failure reads like a WMI problem rather than what it is. Select
    VirtualSystemType 'Microsoft:Hyper-V:System:Realized' and require exactly
    one -- the same discipline as capture_guest_console.ps1.

    THIS CHANNEL IS BLIND. A real run returns {ok, injected_count} and
    NOTHING about where the input landed: not which window had focus, not
    whether the guest was showing a dialog, not whether the keystrokes
    reached Windows Setup instead of the logon screen. The related capture
    script found exactly that defect because nothing in any return value
    said so. injected_count proves that WMI accepted the requests and
    nothing more; the transaction machinery must resolve outcomes through
    independent observation, never through this channel's report.

    COORDINATES AND GESTURES. Mouse positions here are absolute 0..65535
    normalized guest display coordinates (Msvm_SyntheticMouse
    .SetAbsolutePosition), NOT the window-relative coordinates helper.ps1
    takes: whoever routes input to this backend does the conversion from the
    profile's recorded resolution facts. Buttons go through the mouse's own
    SetButtonState with a button index (0 = left, 1 = right) and a boolean
    state: click is one down/up pair, double is two, down/up are single
    states, always preceded by the absolute move. Keys go through
    Msvm_Keyboard.PressKey, which takes the virtual-key code the WMI
    contract calls "keyCode". MEASURED on Server 2025 (MPMLABHV01,
    2026-09-02): Msvm_Keyboard has no TypeText and PressKey has no
    scanCode parameter, so -Action text types per character through
    PressKey with a char-to-VK map and refuses unmapped characters.

    NAMING GUARD. -VMName must match ^[Ll]ab[A-Za-z0-9]{1,12}$: disposable
    guests only, the same estate naming convention capture_guest_console.ps1
    enforces. This is NOT a read-only operation, so the convention is the
    estate's guard against touching real machines and it is not worth making
    an exception to.

    -VALIDATEONLY. Validates every parameter, prints the plan JSON, exits 0,
    and touches neither the network nor WMI. WHY ALL VALIDATION LIVES IN THE
    SCRIPT BODY INSTEAD OF param() ATTRIBUTES: a parameter-binding abort
    exits 1 with prose on the error stream, while this script's callers read
    a JSON envelope and an exit code. Keeping validation in the body means
    every refusal is {ok: false, error: ...} with exit 2, uniformly, and
    -ValidateOnly can still enforce the same rules it would enforce on a
    real run.

    Per contract section 13, the real behaviour here is unknown until the
    first estate window: the method signatures, the button-index mapping and
    the return-code handling are written from the Msvm WMI contract and are
    unverified against a real host. Tests exercise only parameter validation
    and the plan; the injection path awaits the estate.
#>
[CmdletBinding()]
param(
    # The Hyper-V host to reach over WinRM.
    [string] $HostName,

    # Disposable guests only. The naming convention is the estate's guard
    # against touching real machines and it is not worth making an exception
    # to. Enforced in the body so a refusal is the JSON envelope, not a
    # binding abort -- see .DESCRIPTION.
    [string] $VMName,

    # One of: key (single vk chord), text (TypeText), mouse (position + buttons).
    [string] $Action,

    # -Action text: the string Msvm_Keyboard.TypeText will type. Never echoed
    # back; the plan and the result report only its length and sha256.
    [string] $Text,

    # -Action key: the virtual-key code for Msvm_Keyboard.PressKey.
    [int] $VKeyCode = 0,

    # -Action mouse: normalized guest display coordinates, 0..65535.
    [int] $X = -1,
    [int] $Y = -1,

    # -Action mouse: which button SetButtonState drives.
    [string] $Button = 'left',

    # -Action mouse: click | double | down | up.
    [string] $MouseAction = 'click',

    # Validate parameters, print the plan JSON, exit 0; no network, no WMI.
    [switch] $ValidateOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Diag {
    param([string] $Message)
    [Console]::Error.WriteLine(("hyperv-input: " + $Message))
}

# Every refusal is the JSON envelope with exit 2, never a binding abort.
function Write-Denial {
    param([string] $Message)
    $payload = @{ ok = $false; error = $Message; validate_only = [bool]$ValidateOnly }
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $payload -Compress -Depth 8))
    exit 2
}

function Get-Sha256Hex {
    param([byte[]] $Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

if ([string]::IsNullOrWhiteSpace($HostName)) {
    Write-Denial 'HostName is required (the Hyper-V host to reach over WinRM).'
}
if ($VMName -cnotmatch '^[Ll]ab[A-Za-z0-9]{1,12}$') {
    # Case-sensitive on purpose: -notmatch would fold case and accept 'LABcl01'.
    Write-Denial ("VMName '" + $VMName + "' is refused. Disposable guests only: the name must match " +
        "^[Ll]ab[A-Za-z0-9]{1,12}$ -- the estate naming convention is the guard against touching " +
        "real machines, and it is not worth making an exception to.")
}
if ("$Action".ToLowerInvariant() -cnotin @('key', 'text', 'mouse')) {
    Write-Denial ("Action '" + $Action + "' is not one of: key, text, mouse.")
}
$Action = "$Action".ToLowerInvariant()

$wmiCalls = @()
$actionPlan = @{}
if ($Action -eq 'key') {
    if ($VKeyCode -lt 1 -or $VKeyCode -gt 254) {
        Write-Denial "Action key needs -VKeyCode in 1..254 (the virtual-key code for Msvm_Keyboard.PressKey); got $VKeyCode."
    }
    $actionPlan = @{ vkey_code = $VKeyCode }
    $wmiCalls = @(
        'Get-CimInstance Msvm_ComputerSystem (ElementName filter)',
        'realized Msvm_VirtualSystemSettingData selection (exactly one)',
        'Get-CimAssociatedInstance Msvm_Keyboard (exactly one)',
        "Msvm_Keyboard.PressKey(keyCode=$VKeyCode)"
    )
} elseif ($Action -eq 'text') {
    if ([string]::IsNullOrEmpty($Text)) {
        Write-Denial 'Action text needs -Text (the string Msvm_Keyboard.TypeText will type).'
    }
    $actionPlan = @{
        text_length = $Text.Length
        text_sha256 = Get-Sha256Hex -Bytes ([System.Text.Encoding]::UTF8.GetBytes($Text))
    }
    $wmiCalls = @(
        'Get-CimInstance Msvm_ComputerSystem (ElementName filter)',
        'realized Msvm_VirtualSystemSettingData selection (exactly one)',
        'Get-CimAssociatedInstance Msvm_Keyboard (exactly one)',
        'Msvm_Keyboard.TypeText(unicodeText)'
    )
} else {
    if ($X -lt 0 -or $X -gt 65535 -or $Y -lt 0 -or $Y -gt 65535) {
        Write-Denial "Action mouse needs -X and -Y in 0..65535 (normalized guest display coordinates); got ($X, $Y)."
    }
    if ($Button -cnotin @('left', 'right')) {
        Write-Denial ("Button must be 'left' or 'right'; got '" + $Button + "'.")
    }
    if ($MouseAction -cnotin @('click', 'double', 'down', 'up')) {
        Write-Denial ("MouseAction must be one of click, double, down, up; got '" + $MouseAction + "'.")
    }
    $buttonIndex = 0
    if ($Button -ceq 'right') { $buttonIndex = 1 }
    $transitions = 1
    if ($MouseAction -ceq 'click') { $transitions = 2 }
    if ($MouseAction -ceq 'double') { $transitions = 4 }
    $actionPlan = @{
        x = $X
        y = $Y
        button = $Button
        mouse_action = $MouseAction
        button_index = $buttonIndex
        button_state_transitions = $transitions
    }
    $wmiCalls = @(
        'Get-CimInstance Msvm_ComputerSystem (ElementName filter)',
        'realized Msvm_VirtualSystemSettingData selection (exactly one)',
        'Get-CimAssociatedInstance Msvm_SyntheticMouse (exactly one)',
        "Msvm_SyntheticMouse.SetAbsolutePosition($X, $Y)",
        "Msvm_SyntheticMouse.SetButtonState(buttonIndex=$buttonIndex, buttonState) x $transitions"
    )
}

foreach ($required in 'HYPERV_CONTROL_USERNAME', 'HYPERV_CONTROL_PASSWORD') {
    if (-not (Get-Item "env:$required" -ErrorAction SilentlyContinue)) {
        Write-Denial ("$required is not present in the environment. Launch this script through " +
            'acb exec cred:lab-hyperv-control -- ...')
    }
}

if ($ValidateOnly) {
    $plan = [ordered]@{
        script = 'hyperv-input'
        host = $HostName
        vm_name = $VMName
        action = $Action
        validate_only = $true
        route = 'New-PSSession -Authentication Negotiate -> Invoke-Command -> root\virtualization\v2 WMI'
        wmi_calls = @($wmiCalls)
        note = 'Validation only: no session was created and no WMI call was made. This channel is blind: even a real run returns {ok, injected_count} and nothing about where the input landed.'
        credentials = 'HYPERV_CONTROL_USERNAME / HYPERV_CONTROL_PASSWORD are present in the environment; validate-only does not use them.'
    }
    foreach ($planKey in $actionPlan.Keys) { $plan[$planKey] = $actionPlan[$planKey] }
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{ ok = $true; validate_only = $true; plan = $plan } -Compress -Depth 8))
    exit 0
}

$credential = [System.Management.Automation.PSCredential]::new(
    $env:HYPERV_CONTROL_USERNAME,
    (ConvertTo-SecureString $env:HYPERV_CONTROL_PASSWORD -AsPlainText -Force))

try {
    $session = New-PSSession -ComputerName $HostName -Credential $credential -Authentication Negotiate
    try {
        $outcome = Invoke-Command -Session $session -ArgumentList $VMName, $Action, $Text, $VKeyCode, $X, $Y, $Button, $MouseAction -ScriptBlock {
            param($vmName, $action, $text, $vkeyCode, $x, $y, $button, $mouseAction)
            $ErrorActionPreference = 'Stop'
            Set-StrictMode -Version Latest

            $ns = 'root\virtualization\v2'
            $vm = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "ElementName='$vmName'"
            if (-not $vm) { throw "VM '$vmName' does not exist on this host." }
            if ("$($vm.EnabledState)" -ne '2') {
                throw "VM '$vmName' is not running (EnabledState $($vm.EnabledState)); a powered-off guest has nothing to inject into."
            }

            # A guest with checkpoints has MORE THAN ONE
            # Msvm_VirtualSystemSettingData: one realized setting for the
            # running machine, plus a snapshot setting for every checkpoint.
            # Handing the whole array onwards is really asking to operate on
            # several machines, and fails in ways that read like a WMI
            # problem. Found in the capture script's lesson of 2026-08-04;
            # mirrored here because input backends die the same way the
            # moment the estate starts taking checkpoints.
            $settings = @(Get-CimAssociatedInstance -InputObject $vm `
                    -ResultClassName Msvm_VirtualSystemSettingData |
                Where-Object { "$($_.VirtualSystemType)" -eq 'Microsoft:Hyper-V:System:Realized' })
            if ($settings.Count -ne 1) {
                throw "expected exactly one realized system setting for '$vmName', found $($settings.Count)."
            }

            $keyboard = @(Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_Keyboard)
            if ($keyboard.Count -ne 1) {
                throw "expected exactly one Msvm_Keyboard for '$vmName', found $($keyboard.Count)."
            }

            $injected = 0
            if ($action -eq 'key') {
                # PressKey takes the virtual-key code the WMI contract calls
                # "keyCode". A scancode path is deliberately not implemented;
                # recorded as a limitation in .DESCRIPTION.
                $result = Invoke-CimMethod -InputObject $keyboard[0] -MethodName PressKey `
                    -Arguments @{ keyCode = [uint32]$vkeyCode }
                if ($result.ReturnValue -ne 0) {
                    throw "Msvm_Keyboard.PressKey($vkeyCode) failed with $($result.ReturnValue)."
                }
                $injected += 1
            } elseif ($action -eq 'text') {
                # MEASURED on the Server 2025 host (2026-09-02, MPMLABHV01):
                # Msvm_Keyboard exposes only PressKey/ReleaseKey/TypeKey/
                # IsKeyPressed - there is NO TypeText method, and PressKey
                # takes a UInt32 virtual-key code with no scanCode parameter.
                # Text is therefore typed per character via PressKey with a
                # char-to-VK map (shift applied for upper/symbol forms).
                # Characters outside the map are refused rather than skipped.
                $map = New-Object 'System.Collections.Generic.Dictionary[char,object]'
                for ([int]$i = 0; $i -lt 26; $i++) {
                    $upper = [char](65 + $i); $lower = [char](97 + $i)
                    $map[$lower] = @{ vk = [uint32](0x41 + $i); shift = $false }
                    $map[$upper] = @{ vk = [uint32](0x41 + $i); shift = $true }
                }
                for ([int]$d = 0; $d -lt 10; $d++) {
                    $digit = [char](48 + $d)
                    $map[$digit] = @{ vk = [uint32](0x30 + $d); shift = $false }
                }
                $symbols = @{
                    ' ' = @{ vk = [uint32]0x20; shift = $false }
                    '!' = @{ vk = [uint32]0x31; shift = $true }
                    '@' = @{ vk = [uint32]0x32; shift = $true }
                    '#' = @{ vk = [uint32]0x33; shift = $true }
                    '$' = @{ vk = [uint32]0x34; shift = $true }
                    '%' = @{ vk = [uint32]0x35; shift = $true }
                    '^' = @{ vk = [uint32]0x36; shift = $true }
                    '&' = @{ vk = [uint32]0x37; shift = $true }
                    '*' = @{ vk = [uint32]0x38; shift = $true }
                    '(' = @{ vk = [uint32]0x39; shift = $true }
                    ')' = @{ vk = [uint32]0x30; shift = $true }
                    '-' = @{ vk = [uint32]0xBD; shift = $false }
                    '_' = @{ vk = [uint32]0xBD; shift = $true }
                    '=' = @{ vk = [uint32]0xBB; shift = $false }
                    '+' = @{ vk = [uint32]0xBB; shift = $true }
                    '[' = @{ vk = [uint32]0xDB; shift = $false }
                    ']' = @{ vk = [uint32]0xDD; shift = $false }
                    '\' = @{ vk = [uint32]0xDC; shift = $false }
                    ';' = @{ vk = [uint32]0xBA; shift = $false }
                    ':' = @{ vk = [uint32]0xBA; shift = $true }
                    "'" = @{ vk = [uint32]0xDE; shift = $false }
                    '"' = @{ vk = [uint32]0xDE; shift = $true }
                    ',' = @{ vk = [uint32]0xBC; shift = $false }
                    '<' = @{ vk = [uint32]0xBC; shift = $true }
                    '.' = @{ vk = [uint32]0xBE; shift = $false }
                    '>' = @{ vk = [uint32]0xBE; shift = $true }
                    '/' = @{ vk = [uint32]0xBF; shift = $false }
                    '?' = @{ vk = [uint32]0xBF; shift = $true }
                    '`' = @{ vk = [uint32]0xC0; shift = $false }
                    '~' = @{ vk = [uint32]0xC0; shift = $true }
                    "`t" = @{ vk = [uint32]0x09; shift = $false }
                    "`n" = @{ vk = [uint32]0x0D; shift = $false }
                }
                foreach ($ch in $symbols.Keys) { $map[$ch] = $symbols[$ch] }

                foreach ($ch in $text.ToCharArray()) {
                    if (-not $map.ContainsKey($ch)) {
                        throw "character '$ch' (U+$([int]$ch)) has no VK mapping; refusing rather than skipping."
                    }
                    $entry = $map[$ch]
                    if ($entry.shift) {
                        $null = Invoke-CimMethod -InputObject $keyboard[0] -MethodName PressKey `
                            -Arguments @{ keyCode = [uint32]0x10 }
                    }
                    $result = Invoke-CimMethod -InputObject $keyboard[0] -MethodName PressKey `
                        -Arguments @{ keyCode = $entry.vk }
                    if ($result.ReturnValue -ne 0) {
                        throw "Msvm_Keyboard.PressKey($($entry.vk)) failed with $($result.ReturnValue)."
                    }
                    $null = Invoke-CimMethod -InputObject $keyboard[0] -MethodName ReleaseKey `
                        -Arguments @{ keyCode = $entry.vk }
                    if ($entry.shift) {
                        $null = Invoke-CimMethod -InputObject $keyboard[0] -MethodName ReleaseKey `
                            -Arguments @{ keyCode = [uint32]0x10 }
                    }
                    $injected += 1
                }
            } else {
                $mouse = @(Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_SyntheticMouse)
                if ($mouse.Count -ne 1) {
                    throw "expected exactly one Msvm_SyntheticMouse for '$vmName', found $($mouse.Count)."
                }
                # Button-index mapping (0 = left, 1 = right) follows the
                # Msvm_SyntheticMouse WMI contract and is unverified against a
                # real host until the first estate window.
                $buttonIndex = [uint32]0
                if ($button -eq 'right') { $buttonIndex = [uint32]1 }
                $states = @()
                if ($mouseAction -eq 'click') { $states = @($true, $false) }
                elseif ($mouseAction -eq 'double') { $states = @($true, $false, $true, $false) }
                elseif ($mouseAction -eq 'down') { $states = @($true) }
                elseif ($mouseAction -eq 'up') { $states = @($false) }

                $position = Invoke-CimMethod -InputObject $mouse[0] -MethodName SetAbsolutePosition `
                    -Arguments @{ horizontalPosition = [int32]$x; verticalPosition = [int32]$y }
                if ($position.ReturnValue -ne 0) {
                    throw "Msvm_SyntheticMouse.SetAbsolutePosition($x, $y) failed with $($position.ReturnValue)."
                }
                $injected += 1
                foreach ($state in $states) {
                    $result = Invoke-CimMethod -InputObject $mouse[0] -MethodName SetButtonState `
                        -Arguments @{ buttonIndex = $buttonIndex; buttonState = [bool]$state }
                    if ($result.ReturnValue -ne 0) {
                        throw "Msvm_SyntheticMouse.SetButtonState($buttonIndex, $state) failed with $($result.ReturnValue)."
                    }
                    $injected += 1
                }
            }
            return @{ injected_count = $injected }
        }

        [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{
            ok = $true
            vm = $VMName
            action = $Action
            injected_count = $outcome.injected_count
            note = 'Blind channel: this reports only that the WMI requests were accepted, never where the input landed or what it changed. Resolve the outcome through independent observation.'
        } -Compress -Depth 8))
    } finally {
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    }
} catch {
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{
        ok = $false
        error = $_.Exception.Message
        vm = $VMName
        action = $Action
    } -Compress -Depth 8))
    Write-Diag ("injection failed: " + $_.Exception.Message)
    exit 2
}
exit 0
