<#
.SYNOPSIS
Read effective IIS security values and the committed location-tag values.
.DESCRIPTION
Enums and flags are the object itself, not its absent .Value member. The
committed-file observation does not infer schema defaults or inherited values.
Effective reads have distinct provenance and never stand in for a file digest.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Location,
    [string]$ConfigPath = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"
)
$ErrorActionPreference = 'Stop'
Import-Module WebAdministration -ErrorAction Stop
$bytes = [IO.File]::ReadAllBytes($ConfigPath)
$settings = New-Object System.Xml.XmlReaderSettings
$settings.DtdProcessing = 'Prohibit'
$settings.XmlResolver = $null
$memory = New-Object IO.MemoryStream(,$bytes)
$reader = [Xml.XmlReader]::Create($memory, $settings)
$doc = New-Object Xml.XmlDocument
$doc.XmlResolver = $null
try { $doc.Load($reader) } finally { $reader.Dispose(); $memory.Dispose() }
$sha = [Security.Cryptography.SHA256]::Create()
try { $digest = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
finally { $sha.Dispose() }
$rows = @()
foreach ($app in $Location) {
    if (-not $app -or $app.Contains("'") -or $app.Contains('"') -or
        $app.Contains([string][char]10) -or $app.Contains([string][char]13)) { throw 'Invalid location.' }
    $auth = 'system.webServer/security/authentication/windowsAuthentication'
    $access = 'system.webServer/security/access'
    $effective = [ordered]@{ provenance = 'WebAdministration effective at application path';
        path = $app; error = $null; token_checking = $null; ssl_flags = $null;
        enabled = $null; providers = $null }
    try {
        $token = Get-WebConfigurationProperty -PSPath ('IIS:\Sites\' + $app) `
            -Filter ($auth + '/extendedProtection') -Name tokenChecking
        $flags = Get-WebConfigurationProperty -PSPath ('IIS:\Sites\' + $app) `
            -Filter $access -Name sslFlags
        $enabled = Get-WebConfigurationProperty -PSPath ('IIS:\Sites\' + $app) `
            -Filter $auth -Name enabled
        # Primitive values differ by property: enum/flags already ARE values;
        # enabled is a ConfigurationAttribute with a real Value member.
        $effective.token_checking = [string]$token
        $effective.ssl_flags = @(([string]$flags).Split(',') | ForEach-Object { $_.Trim() })
        $effective.enabled = [bool]$enabled.Value
        $effective.providers = @(Get-WebConfigurationProperty -PSPath ('IIS:\Sites\' + $app) `
            -Filter ($auth + '/providers') -Name '.' | ForEach-Object { [string]$_.value })
    } catch { $effective.error = 'effective_read_failed' }
    $nodes = @($doc.SelectNodes('/configuration/location') | Where-Object { $_.path -eq $app })
    if ($nodes.Count -gt 1) { throw 'Ambiguous committed location.' }
    $committed = [ordered]@{ provenance = 'applicationHost.config location tag';
        path = $app; present = ($nodes.Count -eq 1); token_checking = $null;
        ssl_flags = $null; enabled = $null; provider_operations = $null }
    if ($nodes.Count -eq 1) {
        $protection = $nodes[0].SelectSingleNode($auth + '/extendedProtection')
        $accessNode = $nodes[0].SelectSingleNode($access)
        $authNode = $nodes[0].SelectSingleNode($auth)
        if ($protection -and $protection.HasAttribute('tokenChecking')) {
            $committed.token_checking = $protection.GetAttribute('tokenChecking')
        }
        if ($accessNode -and $accessNode.HasAttribute('sslFlags')) {
            $committed.ssl_flags = @($accessNode.GetAttribute('sslFlags').Split(',') |
                ForEach-Object { $_.Trim() })
        }
        if ($authNode -and $authNode.HasAttribute('enabled')) {
            $committed.enabled = [bool]::Parse($authNode.GetAttribute('enabled'))
        }
        $providerNodes = @($nodes[0].SelectNodes($auth + '/providers/*'))
        $committed.provider_operations = @($providerNodes | ForEach-Object { $_.OuterXml })
    }
    $rows += @{ effective = $effective; committed = $committed }
}
@{ schema_version = 1; sha256 = $digest; locations = $rows } | ConvertTo-Json -Depth 12 -Compress
