#requires -Version 5
<#
.SYNOPSIS
    The console driver's hands inside a guest's interactive session: JSON in on
    stdin, JSON out on stdout, one invocation per request.

.DESCRIPTION
    guest/helper.ps1 implements the guest helper contract (docs/contract.md
    section 8). It is single-shot and stateless: each invocation reads exactly
    one JSON request object from stdin, writes exactly one single-line JSON
    response object to stdout, and exits 0 (ok), 2 (error) or 3
    (indeterminate). Diagnostics go to stderr and never to stdout, so a caller
    can parse stdout strictly.

    Actions:

    context          session id, user, desktop, and the foreground window with
                     its fingerprint {hwnd, pid, process_name, title, class,
                     rect, uia_digest}.
    uia_dump         UIA element tree of the foreground window, pre-order
                     (document order), to "depth" (default 4): {elements:
                     [{depth, name, class, automation_id, control_type,
                     control_type_id, rect, patterns}]}. Capped at 500
                     elements and a 5 second walk budget; a capped dump sets
                     "truncated": true and says so in the notes.
    screenshot       GDI capture (CopyFromScreen) of the foreground window
                     rect, or of the whole virtual screen with the request
                     field "full": true (or the -Full switch). Returns PNG,
                     base64, with its sha256 for hash-binding.
    key              SendInput: unicode text ("text") and/or a vk chord
                     sequence ("vks": [{"vk": 13, "modifiers": ["ctrl"]}])
                     with modifiers from ctrl, alt, shift, win. Honours
                     -DryRun.
    mouse            window-relative {x, y} converted to screen coordinates
                     through the REFERENCE WINDOW -- the foreground window
                     identified in this same request, or an explicit "hwnd"
                     -- plus "button" left|right (default left) and
                     "mouse_action" click|double|down|up (default click).
                     Honours -DryRun.
    wait_foreground  polls until the foreground window matches a fingerprint
                     subset ("title_regex" .NET regex IsMatch on the title,
                     "class" exact case-sensitive, "pid" exact) or times out;
                     timeout is exit 3 (indeterminate) with the last observed
                     foreground, never a plain failure.

    THE HELPER NEVER INTERPRETS. It returns facts and injects input; what a
    keystroke means, and whether a transaction succeeded, are other
    components' questions. It also never reads or understands what it is told
    to type: the text leaves the request and becomes a SendInput array, and
    only its length and sha256 are ever written to the response, to
    would_inject, or to any diagnostic. Input is logged as evidence, so
    secrets must not land in evidence. The policy layer prohibits secret
    parameters; the helper enforces only the part it can: text of 12 or more
    characters containing upper case, lower case and a digit is marked
    "secret_shaped_warning": true in the response and STILL PROCEEDS -- the
    warning is a signal for the policy layer, not a refusal.

    DRY RUN. The inject actions (key, mouse) accept the -DryRun switch, or the
    request field "dry_run": true (same effect): the request is fully
    validated, everything that can be computed without touching the session
    is computed -- including the window-relative to screen coordinate
    conversion -- and the response carries {ok: true, dry_run: true,
    would_inject: {...}} instead of injecting. The SendInput plumbing is not
    even loaded on that path. -DryRun is accepted but is a no-op for the
    read-only actions.

    THE UIA DIGEST IS PART OF THE COMPATIBILITY CONTRACT. uia_digest is
    sha256 over "uia-digest-v1:<count>:<records>", where records are the
    first 64 UIA elements of the foreground window INCLUDING the root, in
    breadth-first order, each record "name<US>class<US>control-type-id" with
    US = 0x1F and records separated by 0x1E, UTF-8 encoded, hashed lowercase
    hex. If the walk does not finish within its 2 second budget, the digest
    is null with an "unresolved" note rather than a value that would depend
    on timing. Changing N, the order, the fields, or the normalization
    changes every fingerprint; that is a deliberate, versioned decision
    (contract section 6), and the version prefix exists so a changed
    algorithm can never be mistaken for a changed surface. The digest IS
    sensitive to dynamic content -- live regions, animations, clocks -- and on
    such windows two correctly computed digests will legitimately differ;
    that is what a surface fingerprint is for, not a defect.

    HONESTY NOTES. Where a field cannot be determined it is null and the
    response's "notes" array says so ("<field>: unresolved (...)") instead of
    guessing. The desktop name comes from the foreground window's creating
    thread (GetWindowThreadProcessId -> GetThreadDesktop ->
    GetUserObjectInformationW UOI_NAME); it fails legitimately when that
    thread has exited by the time of the call, and is reported unresolved
    then. The helper is also the actuator, so its surface evidence is not
    independent (contract section 5): only the host-side framebuffer capture
    makes a screenshot corroborated. Per contract section 13, this helper's
    real behaviour is unknown until the first estate window; only the
    read-only actions have been smoke-tested against a live desktop.
#>
[CmdletBinding()]
param(
    # Dry-run guard for the inject actions (key, mouse). See .DESCRIPTION.
    [switch] $DryRun,

    # Capture the whole virtual screen instead of the foreground window rect
    # (same effect as the request field "full": true).
    [switch] $Full
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- Contract constants. Changing these changes the compatibility contract. --
$script:UIA_DIGEST_ELEMENTS = 64      # "first N UIA elements" of the digest
$script:UIA_DIGEST_BUDGET_MS = 2000   # over budget: digest unresolved, not approximate
$script:UIA_DUMP_MAX_ELEMENTS = 500
$script:UIA_DUMP_BUDGET_MS = 5000
$script:WAIT_TIMEOUT_MS_MAX = 60000
$script:WAIT_POLL_MS_MIN = 50
$script:WAIT_POLL_MS_MAX = 2000

$script:notes = [System.Collections.Generic.List[string]]::new()

function Add-Note {
    param([string] $Text)
    [void]$script:notes.Add($Text)
}

# Diagnostics go to stderr only; stdout carries exactly one JSON document.
function Write-Diag {
    param([string] $Message)
    [Console]::Error.WriteLine(("helper: " + $Message))
}

function Get-Prop {
    # StrictMode-safe property read from a ConvertFrom-Json object: a missing
    # property returns $null instead of raising.
    param([psobject] $Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Convert-IntProp {
    # JSON numbers arrive as int, long or double; refuse fractions silently
    # rounding away (a click on x=10.5 must not become x=10 unremarked).
    param([object] $Value, [string] $Name)
    if ($null -eq $Value) { return $null }
    if ($Value -is [int] -or $Value -is [long]) { return [int]$Value }
    if ($Value -is [double]) {
        if ([math]::Floor($Value) -ne $Value) { throw "$Name must be an integer, got $Value" }
        return [int]$Value
    }
    throw "$Name must be an integer, got a $($Value.GetType().Name)"
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

function Get-StringSha256Hex {
    param([string] $Text)
    return Get-Sha256Hex -Bytes ([System.Text.Encoding]::UTF8.GetBytes($Text))
}

# --- Win32 read-side interop -------------------------------------------------
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class WcdNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder text, int count);

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

    [DllImport("user32.dll")]
    public static extern bool IsIconic(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool IsWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern IntPtr GetThreadDesktop(uint threadId);

    // nIndex 2 = UOI_NAME
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern bool GetUserObjectInformation(IntPtr hObj, int nIndex, StringBuilder pvBuffer, int nBufferLength, out int lpnLengthNeeded);

    [DllImport("user32.dll")]
    public static extern bool CloseDesktop(IntPtr hDesktop);

    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();

    [DllImport("user32.dll")]
    public static extern int GetSystemMetrics(int nIndex);
}
'@

function Get-WindowRectHashtable {
    param([IntPtr] $Hwnd)
    $rect = [WcdNative+RECT]::new()
    if (-not [WcdNative]::GetWindowRect($Hwnd, [ref]$rect)) { return $null }
    return @{
        left = $rect.Left
        top = $rect.Top
        right = $rect.Right
        bottom = $rect.Bottom
        width = $rect.Right - $rect.Left
        height = $rect.Bottom - $rect.Top
    }
}

function Get-DesktopName {
    # The desktop of the thread that owns the window: the honest route, and an
    # honest null with a note when any step of it fails.
    param([IntPtr] $Hwnd)
    $procId = [uint32]0
    $threadId = [WcdNative]::GetWindowThreadProcessId($Hwnd, [ref]$procId)
    if ($threadId -eq 0) {
        Add-Note 'desktop: unresolved (GetWindowThreadProcessId returned no thread for the foreground window)'
        return $null
    }
    $desktopHandle = [WcdNative]::GetThreadDesktop($threadId)
    if ($desktopHandle -eq [IntPtr]::Zero) {
        Add-Note 'desktop: unresolved (GetThreadDesktop returned 0)'
        return $null
    }
    try {
        $nameBuilder = [System.Text.StringBuilder]::new(256)
        $needed = [int]0
        if ([WcdNative]::GetUserObjectInformation($desktopHandle, 2, $nameBuilder, 256, [ref]$needed)) {
            return $nameBuilder.ToString()
        }
        Add-Note 'desktop: unresolved (GetUserObjectInformation failed)'
        return $null
    } finally {
        [void][WcdNative]::CloseDesktop($desktopHandle)
    }
}

function Add-UiaSupport {
    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes
}

function Get-UiaDigest {
    # See .DESCRIPTION for the algorithm contract ("uia-digest-v1"). Returns
    # $null with an unresolved note rather than a timing-dependent value.
    param([IntPtr] $Hwnd)
    try {
        Add-UiaSupport
        $root = [System.Windows.Automation.AutomationElement]::FromHandle($Hwnd)
        $separation = [string][char]0x001F
        $recordSeparator = [string][char]0x001E
        $records = [System.Collections.Generic.List[string]]::new()
        $pending = [System.Collections.Generic.Queue[System.Windows.Automation.AutomationElement]]::new()
        $pending.Enqueue($root)
        $clock = [System.Diagnostics.Stopwatch]::StartNew()
        $overBudget = $false
        while ($records.Count -lt $script:UIA_DIGEST_ELEMENTS -and $pending.Count -gt 0) {
            if ($clock.ElapsedMilliseconds -gt $script:UIA_DIGEST_BUDGET_MS) { $overBudget = $true; break }
            $element = $pending.Dequeue()
            $current = $element.Current
            $typeId = 0
            if ($current.ControlType) { $typeId = $current.ControlType.Id }
            $name = [string]$current.Name
            $className = [string]$current.ClassName
            [void]$records.Add(($name + $separation + $className + $separation + $typeId))
            $children = $element.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)
            foreach ($child in $children) { $pending.Enqueue($child) }
        }
        if ($overBudget) {
            Add-Note ("uia_digest: unresolved (the UIA walk exceeded its " + $script:UIA_DIGEST_BUDGET_MS +
                " ms budget after " + $records.Count + " elements; a truncated digest would depend on timing, so none is reported)")
            return $null
        }
        $payload = "uia-digest-v1:" + $records.Count + ":" + [string]::Join($recordSeparator, $records)
        return Get-Sha256Hex -Bytes ([System.Text.Encoding]::UTF8.GetBytes($payload))
    } catch {
        Add-Note ("uia_digest: unresolved (UIA walk failed: " + $_.Exception.Message + ")")
        return $null
    }
}

function Get-WindowInfo {
    param([IntPtr] $Hwnd, [bool] $IncludeDigest)
    $procId = [uint32]0
    [void][WcdNative]::GetWindowThreadProcessId($Hwnd, [ref]$procId)
    $titleBuilder = [System.Text.StringBuilder]::new(512)
    [void][WcdNative]::GetWindowText($Hwnd, $titleBuilder, 512)
    $classBuilder = [System.Text.StringBuilder]::new(256)
    [void][WcdNative]::GetClassName($Hwnd, $classBuilder, 256)
    $rect = Get-WindowRectHashtable -Hwnd $Hwnd
    if (-not $rect) {
        Add-Note ("foreground.rect: unresolved (GetWindowRect failed for hwnd " + $Hwnd.ToInt64() + ")")
    }
    $processName = $null
    try {
        $processName = (Get-Process -Id $procId -ErrorAction Stop).ProcessName
    } catch {
        Add-Note ("foreground.process_name: unresolved (no accessible process for pid " + $procId + ": " + $_.Exception.Message + ")")
    }
    $digest = $null
    if ($IncludeDigest) { $digest = Get-UiaDigest -Hwnd $Hwnd }
    return @{
        hwnd = $Hwnd.ToInt64()
        pid = [int]$procId
        process_name = $processName
        title = $titleBuilder.ToString()
        class = $classBuilder.ToString()
        rect = $rect
        uia_digest = $digest
    }
}

function Get-ForegroundInfo {
    # Full foreground fingerprint, or $null with a note when there is no
    # foreground window on the calling desktop at all.
    $hwnd = [WcdNative]::GetForegroundWindow()
    if ($hwnd -eq [IntPtr]::Zero) {
        Add-Note 'foreground: unresolved (GetForegroundWindow returned 0; there is no foreground window on the calling desktop)'
        return $null
    }
    return Get-WindowInfo -Hwnd $hwnd -IncludeDigest $true
}

# --- UIA dump ----------------------------------------------------------------
function Invoke-UiaDump {
    param([IntPtr] $Hwnd, [int] $Depth)
    Add-UiaSupport
    $root = [System.Windows.Automation.AutomationElement]::FromHandle($Hwnd)
    $elements = [System.Collections.Generic.List[object]]::new()
    # Pre-order (document order) walk: the flat array with its depth field is
    # the tree. Children are pushed in reverse so they pop in document order.
    $stack = [System.Collections.Generic.Stack[object]]::new()
    $stack.Push(@($root, 0))
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $capped = $false
    $unavailable = 0
    while ($stack.Count -gt 0) {
        if ($elements.Count -ge $script:UIA_DUMP_MAX_ELEMENTS) { $capped = $true; break }
        if ($clock.ElapsedMilliseconds -gt $script:UIA_DUMP_BUDGET_MS) {
            $capped = $true
            Add-Note ("uia_dump: truncated (the walk exceeded its " + $script:UIA_DUMP_BUDGET_MS + " ms budget)")
            break
        }
        $frame = $stack.Pop()
        $element = $frame[0]
        $level = [int]$frame[1]
        try {
            $current = $element.Current
            $typeName = $null
            $typeId = $null
            if ($current.ControlType) {
                $typeName = ("$($current.ControlType.ProgrammaticName)" -replace '^ControlType\.', '')
                $typeId = $current.ControlType.Id
            }
            $patterns = @()
            foreach ($pattern in $element.GetSupportedPatterns()) {
                $patterns += (("$($pattern.ProgrammaticName)") -replace 'PatternIdentifiers\.Pattern$', '')
            }
            $rectOut = $null
            $bounds = $current.BoundingRectangle
            if (-not $bounds.IsEmpty) {
                $rectOut = @{
                    left = [int]$bounds.X
                    top = [int]$bounds.Y
                    right = ([int]($bounds.X + $bounds.Width))
                    bottom = ([int]($bounds.Y + $bounds.Height))
                    width = [int]$bounds.Width
                    height = [int]$bounds.Height
                }
            }
            [void]$elements.Add(@{
                depth = $level
                name = [string]$current.Name
                class = [string]$current.ClassName
                automation_id = [string]$current.AutomationId
                control_type = $typeName
                control_type_id = $typeId
                rect = $rectOut
                patterns = @($patterns)
            })
        } catch {
            # An element that stops answering mid-dump is reported as a null
            # placeholder so the shape stays honest about where it broke.
            $unavailable++
            [void]$elements.Add(@{
                depth = $level
                name = $null
                class = $null
                automation_id = $null
                control_type = $null
                control_type_id = $null
                rect = $null
                patterns = @()
            })
        }
        if ($level -lt $Depth) {
            $children = $element.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)
            for ($i = $children.Count - 1; $i -ge 0; $i--) {
                $stack.Push(@($children[$i], $level + 1))
            }
        }
    }
    if ($unavailable -gt 0) {
        Add-Note ("uia_dump: " + $unavailable + " element(s) stopped answering mid-walk and are reported with null fields")
    }
    return @{ elements = $elements; truncated = $capped }
}

# --- Screenshot --------------------------------------------------------------
function Invoke-Screenshot {
    param([IntPtr] $Hwnd, [bool] $FullMode)
    Add-Type -AssemblyName System.Drawing
    if ($FullMode) {
        $x = [WcdNative]::GetSystemMetrics(76)   # SM_XVIRTUALSCREEN
        $y = [WcdNative]::GetSystemMetrics(77)   # SM_YVIRTUALSCREEN
        $w = [WcdNative]::GetSystemMetrics(78)   # SM_CXVIRTUALSCREEN
        $h = [WcdNative]::GetSystemMetrics(79)   # SM_CYVIRTUALSCREEN
        $sourceRect = @{ left = $x; top = $y; right = ($x + $w); bottom = ($y + $h); width = $w; height = $h }
    } else {
        $sourceRect = Get-WindowRectHashtable -Hwnd $Hwnd
        if (-not $sourceRect) { throw ("screenshot: GetWindowRect failed for hwnd " + $Hwnd.ToInt64()) }
    }
    if ([int]$sourceRect.width -le 0 -or [int]$sourceRect.height -le 0) {
        throw ("screenshot: degenerate capture rect " + $sourceRect.left + "," + $sourceRect.top +
            " " + $sourceRect.width + "x" + $sourceRect.height)
    }
    $bitmap = [System.Drawing.Bitmap]::new([int]$sourceRect.width, [int]$sourceRect.height)
    try {
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        try {
            $graphics.CopyFromScreen(
                [int]$sourceRect.left, [int]$sourceRect.top, 0, 0,
                [System.Drawing.Size]::new([int]$sourceRect.width, [int]$sourceRect.height))
        } finally {
            $graphics.Dispose()
        }
        $stream = [System.IO.MemoryStream]::new()
        try {
            $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
            $png = $stream.ToArray()
        } finally {
            $stream.Dispose()
        }
    } finally {
        $bitmap.Dispose()
    }
    return @{ full = $FullMode; rect = $sourceRect; width = [int]$sourceRect.width; height = [int]$sourceRect.height; png = $png }
}

# --- SendInput interop, loaded ONLY when a real injection happens ------------
function Initialize-InputSupport {
    if ($script:InputSupportLoaded) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class WcdInput
{
    [StructLayout(LayoutKind.Sequential)]
    public struct MOUSEINPUT
    {
        public int dx;
        public int dy;
        public uint mouseData;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct INPUTUNION
    {
        [FieldOffset(0)] public MOUSEINPUT mi;
        [FieldOffset(0)] public KEYBDINPUT ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT
    {
        public uint type;
        public INPUTUNION u;
    }

    public const uint INPUT_MOUSE = 0;
    public const uint INPUT_KEYBOARD = 1;
    public const uint KEYEVENTF_KEYUP = 0x0002;
    public const uint KEYEVENTF_UNICODE = 0x0004;
    public const uint MOUSEEVENTF_MOVE = 0x0001;
    public const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
    public const uint MOUSEEVENTF_LEFTUP = 0x0004;
    public const uint MOUSEEVENTF_RIGHTDOWN = 0x0008;
    public const uint MOUSEEVENTF_RIGHTUP = 0x0010;
    public const uint MOUSEEVENTF_VIRTUALDESK = 0x4000;
    public const uint MOUSEEVENTF_ABSOLUTE = 0x8000;

    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    [DllImport("user32.dll")]
    public static extern int GetSystemMetrics(int nIndex);

    private static INPUT Key(uint vk, uint flags)
    {
        INPUT i = new INPUT();
        i.type = INPUT_KEYBOARD;
        i.u.ki.wVk = (ushort)vk;
        i.u.ki.dwFlags = flags;
        return i;
    }

    private static INPUT UnicodeKey(char c, bool up)
    {
        INPUT i = new INPUT();
        i.type = INPUT_KEYBOARD;
        i.u.ki.wScan = (ushort)c;
        i.u.ki.dwFlags = KEYEVENTF_UNICODE | (up ? KEYEVENTF_KEYUP : 0);
        return i;
    }

    private static INPUT MouseMove(int screenX, int screenY)
    {
        // Normalized over the whole virtual desktop, matching the absolute
        // flags below; clamped into range rather than wrapped.
        int vx = GetSystemMetrics(76);
        int vy = GetSystemMetrics(77);
        int vw = GetSystemMetrics(78);
        int vh = GetSystemMetrics(79);
        long denomX = Math.Max(vw - 1, 1);
        long denomY = Math.Max(vh - 1, 1);
        long nx = ((long)(screenX - vx) * 65535) / denomX;
        long ny = ((long)(screenY - vy) * 65535) / denomY;
        if (nx < 0) { nx = 0; }
        if (nx > 65535) { nx = 65535; }
        if (ny < 0) { ny = 0; }
        if (ny > 65535) { ny = 65535; }
        INPUT i = new INPUT();
        i.type = INPUT_MOUSE;
        i.u.mi.dx = (int)nx;
        i.u.mi.dy = (int)ny;
        i.u.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
        return i;
    }

    private static INPUT MouseButton(uint flags)
    {
        INPUT i = new INPUT();
        i.type = INPUT_MOUSE;
        i.u.mi.dwFlags = flags;
        return i;
    }

    private static int SendBatch(List<INPUT> events)
    {
        INPUT[] array = events.ToArray();
        uint sent = SendInput((uint)array.Length, array, Marshal.SizeOf(typeof(INPUT)));
        return (int)sent;
    }

    public static int SendUnicodeText(string text)
    {
        var all = new List<INPUT>();
        foreach (char c in text)
        {
            all.Add(UnicodeKey(c, false));
            all.Add(UnicodeKey(c, true));
        }
        int total = 0;
        const int chunk = 256;
        for (int offset = 0; offset < all.Count; offset += chunk)
        {
            int count = Math.Min(chunk, all.Count - offset);
            INPUT[] batch = new INPUT[count];
            all.CopyTo(offset, batch, 0, count);
            uint sent = SendInput((uint)count, batch, Marshal.SizeOf(typeof(INPUT)));
            total += (int)sent;
            if (sent != count) { return total; }
        }
        return total;
    }

    public static int SendChord(uint vk, string[] modifiers)
    {
        var events = new List<INPUT>();
        foreach (string m in modifiers) { events.Add(Key(ModifierVk(m), 0)); }
        events.Add(Key(vk, 0));
        events.Add(Key(vk, KEYEVENTF_KEYUP));
        for (int i = modifiers.Length - 1; i >= 0; i--) { events.Add(Key(ModifierVk(modifiers[i]), KEYEVENTF_KEYUP)); }
        return SendBatch(events);
    }

    private static uint ModifierVk(string modifier)
    {
        switch (modifier)
        {
            case "ctrl": return 0x11;
            case "alt": return 0x12;
            case "shift": return 0x10;
            case "win": return 0x5B;
            default: throw new ArgumentException("unknown modifier: " + modifier);
        }
    }

    public static int SendMouse(int screenX, int screenY, string button, string action)
    {
        var events = new List<INPUT>();
        events.Add(MouseMove(screenX, screenY));
        bool right = (button == "right");
        uint down = right ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_LEFTDOWN;
        uint up = right ? MOUSEEVENTF_RIGHTUP : MOUSEEVENTF_LEFTUP;
        if (action == "click")
        {
            events.Add(MouseButton(down));
            events.Add(MouseButton(up));
        }
        else if (action == "double")
        {
            events.Add(MouseButton(down));
            events.Add(MouseButton(up));
            events.Add(MouseButton(down));
            events.Add(MouseButton(up));
        }
        else if (action == "down")
        {
            events.Add(MouseButton(down));
        }
        else if (action == "up")
        {
            events.Add(MouseButton(up));
        }
        else
        {
            throw new ArgumentException("unknown mouse action: " + action);
        }
        return SendBatch(events);
    }
}
'@
    $script:InputSupportLoaded = $true
}

# --- Inject actions ----------------------------------------------------------
function Invoke-KeyAction {
    param([psobject] $Request, [bool] $DryRunMode)
    $text = Get-Prop -Object $Request -Name 'text'
    if ($null -ne $text -and $text -isnot [string]) { throw 'key: "text" must be a string when present' }
    $vksRaw = Get-Prop -Object $Request -Name 'vks'
    $chords = @()
    if ($null -ne $vksRaw) {
        # ConvertFrom-Json in Windows PowerShell 5.1 unwraps a single-element
        # JSON array to a scalar, so {"vks": [{...}]} arrives as one object;
        # @() makes the array-ness real again before anything below.
        $vksRaw = @($vksRaw)
        foreach ($entry in $vksRaw) {
            if ($entry -isnot [System.Management.Automation.PSCustomObject]) {
                throw 'key: each vks entry must be an object {vk, modifiers}'
            }
            $vk = Convert-IntProp -Value (Get-Prop -Object $entry -Name 'vk') -Name 'vks[].vk'
            if ($null -eq $vk -or $vk -lt 1 -or $vk -gt 254) {
                throw "key: vks[].vk must be an integer in 1..254, got $vk"
            }
            $mods = @()
            $modsRaw = Get-Prop -Object $entry -Name 'modifiers'
            if ($null -ne $modsRaw) {
                if ($modsRaw -isnot [System.Collections.IEnumerable]) { throw 'key: vks[].modifiers must be an array' }
                foreach ($modifier in $modsRaw) {
                    $modifierName = "$modifier"
                    if ($modifierName -cnotin @('ctrl', 'alt', 'shift', 'win')) {
                        throw ("key: vks[].modifiers entries must be one of ctrl, alt, shift, win; got '" + $modifierName + "'")
                    }
                    $mods += $modifierName
                }
            }
            $chords += @{ vk = $vk; modifiers = @($mods) }
        }
    }
    if (-not $text -and $chords.Count -eq 0) {
        throw 'key: the request needs "text", "vks", or both'
    }

    $secretWarning = $false
    $textLength = $null
    $textSha = $null
    if ($text) {
        $textLength = $text.Length
        $textSha = Get-StringSha256Hex -Text $text
        # Secret-shape heuristic. The policy layer prohibits secrets; the
        # helper only warns and never echoes the text back -- see .DESCRIPTION.
        # -cmatch: -match is case-insensitive and would defeat the check.
        $secretWarning = ($text.Length -ge 12 -and $text -cmatch '[A-Z]' -and $text -cmatch '[a-z]' -and $text -cmatch '[0-9]')
    }

    if ($DryRunMode) {
        $would = @{ kind = 'key' }
        if ($text) {
            $would.text_length = $textLength
            $would.text_sha256 = $textSha
        }
        if ($chords.Count -gt 0) { $would.vks = @($chords) }
        return @{
            exit = 0
            payload = @{
                ok = $true
                action = 'key'
                dry_run = $true
                would_inject = $would
                text_length = $textLength
                text_sha256 = $textSha
                chords_sent = $null
                injected_events = $null
                secret_shaped_warning = $secretWarning
                notes = @($script:notes)
            }
        }
    }

    Initialize-InputSupport
    $events = 0
    if ($text) {
        $sent = [WcdInput]::SendUnicodeText($text)
        $expected = 2 * $text.Length
        if ($sent -ne $expected) {
            throw ("SendInput accepted " + $sent + " of " + $expected +
                " unicode keyboard events; the delivery state of the text is unknown")
        }
        $events += $sent
    }
    foreach ($chord in $chords) {
        $sent = [WcdInput]::SendChord([uint32]$chord.vk, [string[]]@($chord.modifiers))
        $expected = (2 * @($chord.modifiers).Count) + 2
        if ($sent -ne $expected) {
            throw ("SendInput accepted " + $sent + " of " + $expected +
                " chord events for vk " + $chord.vk + "; the chord's delivery state is unknown")
        }
        $events += $sent
    }
    return @{
        exit = 0
        payload = @{
            ok = $true
            action = 'key'
            dry_run = $false
            would_inject = $null
            text_length = $textLength
            text_sha256 = $textSha
            chords_sent = $chords.Count
            injected_events = $events
            secret_shaped_warning = $secretWarning
            notes = @($script:notes)
        }
    }
}

function Invoke-MouseAction {
    param([psobject] $Request, [bool] $DryRunMode)
    $x = Convert-IntProp -Value (Get-Prop -Object $Request -Name 'x') -Name 'x'
    $y = Convert-IntProp -Value (Get-Prop -Object $Request -Name 'y') -Name 'y'
    if ($null -eq $x -or $null -eq $y) { throw 'mouse: "x" and "y" (window-relative integers) are required' }
    if ($x -lt 0 -or $y -lt 0 -or $x -gt 100000 -or $y -gt 100000) {
        throw "mouse: x/y must be within 0..100000, got ($x, $y)"
    }
    $button = Get-Prop -Object $Request -Name 'button'
    if ($null -eq $button) { $button = 'left' }
    if ("$button" -cnotin @('left', 'right')) {
        throw ("mouse: `"button`" must be 'left' or 'right', got '" + $button + "'")
    }
    $mouseAction = Get-Prop -Object $Request -Name 'mouse_action'
    if ($null -eq $mouseAction) { $mouseAction = 'click' }
    if ("$mouseAction" -cnotin @('click', 'double', 'down', 'up')) {
        throw ("mouse: `"mouse_action`" must be one of click, double, down, up, got '" + $mouseAction + "'")
    }

    # The reference window converts window-relative to screen coordinates: the
    # foreground window identified in this same request, unless an explicit
    # "hwnd" is given.
    $hwndGiven = Convert-IntProp -Value (Get-Prop -Object $Request -Name 'hwnd') -Name 'hwnd'
    $reference = 'foreground'
    if ($null -ne $hwndGiven) {
        $reference = 'hwnd'
        $refHwnd = [IntPtr]$hwndGiven
        if (-not [WcdNative]::IsWindow($refHwnd)) {
            throw "mouse: hwnd $hwndGiven is not a valid window on this desktop"
        }
    } else {
        $refHwnd = [WcdNative]::GetForegroundWindow()
        if ($refHwnd -eq [IntPtr]::Zero) {
            throw 'mouse: no foreground window to anchor the window-relative coordinates'
        }
    }
    $rect = Get-WindowRectHashtable -Hwnd $refHwnd
    if (-not $rect) {
        throw ("mouse: GetWindowRect failed for the reference window (hwnd " + $refHwnd.ToInt64() + ")")
    }
    $screenX = [int]$rect.left + $x
    $screenY = [int]$rect.top + $y

    if ($DryRunMode) {
        $would = @{
            kind = 'mouse'
            x = $x
            y = $y
            button = "$button"
            mouse_action = "$mouseAction"
            reference = $reference
            hwnd = $refHwnd.ToInt64()
            screen = @{ x = $screenX; y = $screenY }
        }
        return @{
            exit = 0
            payload = @{
                ok = $true
                action = 'mouse'
                dry_run = $true
                would_inject = $would
                x = $x
                y = $y
                button = "$button"
                mouse_action = "$mouseAction"
                reference = $reference
                hwnd = $refHwnd.ToInt64()
                screen = @{ x = $screenX; y = $screenY }
                injected_events = $null
                notes = @($script:notes)
            }
        }
    }

    Initialize-InputSupport
    $sent = [WcdInput]::SendMouse($screenX, $screenY, "$button", "$mouseAction")
    if ($sent -lt 1) {
        throw 'SendInput accepted no mouse events; the injection state is unknown'
    }
    return @{
        exit = 0
        payload = @{
            ok = $true
            action = 'mouse'
            dry_run = $false
            would_inject = $null
            x = $x
            y = $y
            button = "$button"
            mouse_action = "$mouseAction"
            reference = $reference
            hwnd = $refHwnd.ToInt64()
            screen = @{ x = $screenX; y = $screenY }
            injected_events = $sent
            notes = @($script:notes)
        }
    }
}

function Invoke-WaitForeground {
    param([psobject] $Request)
    $titleRegexText = Get-Prop -Object $Request -Name 'title_regex'
    $classWanted = Get-Prop -Object $Request -Name 'class'
    $pidWanted = Convert-IntProp -Value (Get-Prop -Object $Request -Name 'pid') -Name 'pid'
    if ($null -eq $titleRegexText -and $null -eq $classWanted -and $null -eq $pidWanted) {
        throw 'wait_foreground: provide at least one fingerprint criterion: "title_regex", "class", or "pid"'
    }
    $regex = $null
    if ($null -ne $titleRegexText) {
        if ($titleRegexText -isnot [string]) { throw 'wait_foreground: "title_regex" must be a string' }
        try {
            $regex = [System.Text.RegularExpressions.Regex]::new($titleRegexText)
        } catch {
            throw ("wait_foreground: title_regex is not a valid .NET regular expression: " + $_.Exception.Message)
        }
    }
    if ($null -ne $classWanted -and $classWanted -isnot [string]) { throw 'wait_foreground: "class" must be a string' }
    $timeoutMs = Convert-IntProp -Value (Get-Prop -Object $Request -Name 'timeout_ms') -Name 'timeout_ms'
    if ($null -eq $timeoutMs) { $timeoutMs = 10000 }
    if ($timeoutMs -lt 100 -or $timeoutMs -gt $script:WAIT_TIMEOUT_MS_MAX) {
        throw "wait_foreground: timeout_ms must be within 100..$($script:WAIT_TIMEOUT_MS_MAX), got $timeoutMs"
    }
    $pollMs = Convert-IntProp -Value (Get-Prop -Object $Request -Name 'poll_ms') -Name 'poll_ms'
    if ($null -eq $pollMs) { $pollMs = 250 }
    if ($pollMs -lt $script:WAIT_POLL_MS_MIN -or $pollMs -gt $script:WAIT_POLL_MS_MAX) {
        throw "wait_foreground: poll_ms must be within $($script:WAIT_POLL_MS_MIN)..$($script:WAIT_POLL_MS_MAX), got $pollMs"
    }

    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $last = $null
    while ($true) {
        $hwnd = [WcdNative]::GetForegroundWindow()
        if ($hwnd -ne [IntPtr]::Zero) {
            $procId = [uint32]0
            [void][WcdNative]::GetWindowThreadProcessId($hwnd, [ref]$procId)
            $titleBuilder = [System.Text.StringBuilder]::new(512)
            [void][WcdNative]::GetWindowText($hwnd, $titleBuilder, 512)
            $classBuilder = [System.Text.StringBuilder]::new(256)
            [void][WcdNative]::GetClassName($hwnd, $classBuilder, 256)
            $title = $titleBuilder.ToString()
            $classSeen = $classBuilder.ToString()
            $last = @{ title = $title; class = $classSeen; pid = [int]$procId }
            # Empty-string criteria are treated as absent, like missing ones.
            $matched = $true
            if ($regex -and -not $regex.IsMatch($title)) { $matched = $false }
            if ($classWanted -and $classSeen -cne $classWanted) { $matched = $false }
            if ($null -ne $pidWanted -and [int]$procId -ne $pidWanted) { $matched = $false }
            if ($matched) {
                # The match was a cheap read; the returned context is a fresh
                # full read taken after it. The foreground may move in between:
                # this is a helper fact, not a guarantee.
                $foreground = Get-ForegroundInfo
                $fgHwnd = [WcdNative]::GetForegroundWindow()
                $desktop = $null
                if ($fgHwnd -ne [IntPtr]::Zero) { $desktop = Get-DesktopName -Hwnd $fgHwnd }
                $context = @{
                    session_id = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
                    user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                    desktop = $desktop
                    foreground = $foreground
                }
                return @{
                    exit = 0
                    payload = @{
                        ok = $true
                        action = 'wait_foreground'
                        indeterminate = $false
                        matched = $true
                        waited_ms = $clock.ElapsedMilliseconds
                        context = $context
                        last_foreground = $null
                        error = $null
                        notes = @($script:notes)
                    }
                }
            }
        } else {
            $last = @{ title = $null; class = $null; pid = $null }
        }
        if ($clock.ElapsedMilliseconds -ge $timeoutMs) {
            return @{
                exit = 3
                payload = @{
                    ok = $false
                    action = 'wait_foreground'
                    indeterminate = $true
                    matched = $false
                    waited_ms = $clock.ElapsedMilliseconds
                    context = $null
                    last_foreground = $last
                    error = ("no foreground window matched the fingerprint within " + $timeoutMs + " ms")
                    notes = @($script:notes)
                }
            }
        }
        Start-Sleep -Milliseconds $pollMs
    }
}

# --- Dispatch ----------------------------------------------------------------
function Invoke-Dispatch {
    param([psobject] $Request, [bool] $DryRunMode, [bool] $FullMode)
    $action = Get-Prop -Object $Request -Name 'action'
    if ($null -eq $action -or "$action" -eq '') {
        throw 'the request is missing the "action" field'
    }
    switch -CaseSensitive ("$action") {
        'context' {
            $session = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
            $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $fgHwnd = [WcdNative]::GetForegroundWindow()
            $desktop = $null
            if ($fgHwnd -ne [IntPtr]::Zero) { $desktop = Get-DesktopName -Hwnd $fgHwnd }
            $foreground = Get-ForegroundInfo
            return @{
                exit = 0
                payload = @{
                    ok = $true
                    action = 'context'
                    session_id = $session
                    user = $user
                    desktop = $desktop
                    foreground = $foreground
                    notes = @($script:notes)
                }
            }
        }
        'uia_dump' {
            $depth = Convert-IntProp -Value (Get-Prop -Object $Request -Name 'depth') -Name 'depth'
            if ($null -eq $depth) { $depth = 4 }
            if ($depth -lt 1 -or $depth -gt 12) { throw "uia_dump: depth must be within 1..12, got $depth" }
            $fgHwnd = [WcdNative]::GetForegroundWindow()
            if ($fgHwnd -eq [IntPtr]::Zero) { throw 'uia_dump: no foreground window to dump' }
            $dump = Invoke-UiaDump -Hwnd $fgHwnd -Depth $depth
            return @{
                exit = 0
                payload = @{
                    ok = $true
                    action = 'uia_dump'
                    depth = $depth
                    truncated = $dump.truncated
                    element_count = $dump.elements.Count
                    elements = @($dump.elements.ToArray())
                    notes = @($script:notes)
                }
            }
        }
        'screenshot' {
            $fgHwnd = [WcdNative]::GetForegroundWindow()
            if (-not $FullMode -and $fgHwnd -eq [IntPtr]::Zero) {
                throw 'screenshot: no foreground window to capture (send "full": true for the whole virtual screen)'
            }
            $capture = Invoke-Screenshot -Hwnd $fgHwnd -FullMode $FullMode
            return @{
                exit = 0
                payload = @{
                    ok = $true
                    action = 'screenshot'
                    full = $capture.full
                    rect = $capture.rect
                    width = $capture.width
                    height = $capture.height
                    bytes = $capture.png.Length
                    png_sha256 = Get-Sha256Hex -Bytes $capture.png
                    png_base64 = [Convert]::ToBase64String($capture.png)
                    notes = @($script:notes)
                }
            }
        }
        'key' { return Invoke-KeyAction -Request $Request -DryRunMode $DryRunMode }
        'mouse' { return Invoke-MouseAction -Request $Request -DryRunMode $DryRunMode }
        'wait_foreground' { return Invoke-WaitForeground -Request $Request }
        default {
            throw ("unknown action '" + $action +
                "'; expected one of: context, uia_dump, screenshot, key, mouse, wait_foreground")
        }
    }
}

# --- Main --------------------------------------------------------------------
# Reading a redirected stdin as UTF-8 bytes is what actually guarantees the
# encoding; the [Console]::InputEncoding assignment is for an interactive
# console host and can legitimately refuse when stdin is redirected.
try { [Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }
try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }

function Read-RequestJson {
    $stream = [Console]::OpenStandardInput()
    $buffer = New-Object byte[] 8192
    $memory = [System.IO.MemoryStream]::new()
    while ($true) {
        $read = $stream.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) { break }
        [void]$memory.Write($buffer, 0, $read)
    }
    if ($memory.Length -eq 0) {
        throw 'the request body is empty; expected exactly one JSON object on stdin'
    }
    return [System.Text.Encoding]::UTF8.GetString($memory.ToArray())
}

$result = @{ exit = 2; payload = $null }
try {
    # Coordinates must be physical pixels before any window API is called.
    [void][WcdNative]::SetProcessDPIAware()
    $raw = Read-RequestJson
    $request = $null
    try {
        $request = ConvertFrom-Json -InputObject $raw
    } catch {
        throw ("the request is not valid JSON: " + $_.Exception.Message)
    }
    if ($request -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'the request must be a single JSON object'
    }
    $dryRunMode = [bool]$DryRun
    if ((Get-Prop -Object $request -Name 'dry_run') -eq $true) { $dryRunMode = $true }
    $fullMode = [bool]$Full
    if ((Get-Prop -Object $request -Name 'full') -eq $true) { $fullMode = $true }
    $result = Invoke-Dispatch -Request $request -DryRunMode $dryRunMode -FullMode $fullMode
} catch {
    $result = @{ exit = 2; payload = @{ ok = $false; error = $_.Exception.Message; notes = @($script:notes) } }
    Write-Diag ("action failed: " + $_.Exception.Message)
}

try {
    $json = ConvertTo-Json -InputObject $result.payload -Compress -Depth 16
    [Console]::Out.WriteLine($json)
} catch {
    [Console]::Error.WriteLine(("helper: failed to serialize the response: " + $_.Exception.Message))
}
exit $result.exit
