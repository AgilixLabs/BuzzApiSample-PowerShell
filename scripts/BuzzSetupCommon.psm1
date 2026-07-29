<#
    Shared helpers for the Buzz API sample setup/run/cleanup scripts.

    These talk to the Buzz API for one-time setup tasks (admin login, key
    registration, account management). They use the legacy login3 command only
    to obtain a short-lived admin session token for setup — the sample
    application itself never uses login3, only OAuth.

    Interactive prompts fall back to environment variables when set, so the
    scripts can run unattended (useful for automated testing):
      BUZZ_SERVER_URL, BUZZ_ADMIN_USERNAME, BUZZ_ADMIN_PASSWORD, BUZZ_ADMIN_MFA
#>

Set-StrictMode -Version Latest

$script:Root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $script:Root 'BuzzHttp.psm1') -Force
Import-Module (Join-Path $script:Root 'BuzzCrypto.psm1') -Force
Import-Module (Join-Path $script:Root 'BuzzConfig.psm1') -Force

# ── Console output ─────────────────────────────────────────────────────────────
function Write-BuzzSection { param([string]$Title) Write-Host ("`n--- {0} {1}" -f $Title, ('-' * [Math]::Max(0, 50 - $Title.Length))) }
function Write-BuzzInfo { param([string]$Message) Write-Host ("  {0}" -f $Message) }
function Stop-Buzz { param([string]$Message) [Console]::Error.WriteLine("`nError: $Message"); exit 1 }

# ── Prompts (with environment-variable fallbacks) ──────────────────────────────
function Read-BuzzRequired {
    param([string]$Label, [string]$Default = '', [string]$EnvVar = $null)
    if ($EnvVar) { $v = [Environment]::GetEnvironmentVariable($EnvVar); if ($v) { return $v } }
    while ($true) {
        $suffix = if ($Default) { " [$Default]" } else { '' }
        $value = ''
        try { $value = Read-Host -Prompt "$Label$suffix" } catch { $value = '' }
        if ([string]::IsNullOrWhiteSpace($value)) { $value = $Default }
        if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
        if ($Default) { return $Default }
        Write-Host '  (required)'
    }
}

function Read-BuzzOptional {
    param([string]$Label, [string]$EnvVar = $null)
    if ($EnvVar) { $v = [Environment]::GetEnvironmentVariable($EnvVar); if ($v) { return $v } }
    $value = ''
    try { $value = Read-Host -Prompt "$Label (optional, press Enter to skip)" } catch { $value = '' }
    return $value
}

function Read-BuzzPassword {
    param([string]$Label, [string]$EnvVar = $null)
    if ($EnvVar) { $v = [Environment]::GetEnvironmentVariable($EnvVar); if ($v) { return $v } }
    $secure = Read-Host -Prompt $Label -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Confirm-Buzz {
    param([string]$Label, [bool]$DefaultYes = $false)
    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    $value = ''
    try { $value = Read-Host -Prompt "$Label $suffix" } catch { $value = '' }
    if ([string]::IsNullOrWhiteSpace($value)) { return $DefaultYes }
    return $value.Trim().ToLower().StartsWith('y')
}

# ── Buzz API calls ──────────────────────────────────────────────────────────
# /cmd/* endpoints authenticate a session token via the _token query parameter.
# /api/* (REST) endpoints authenticate via the Authorization: Bearer header.
function Invoke-BuzzCmdPost {
    param([string]$Server, [string]$Cmd, [object]$Body, [string]$Token)
    $url = "$Server/cmd/$Cmd"
    if ($Token) { $url += "?_token=$([Uri]::EscapeDataString($Token))" }
    $json = $Body | ConvertTo-Json -Depth 10 -Compress
    $resp = Invoke-BuzzHttp -Method 'POST' -Url $url -Body $json -Headers @{ 'Content-Type' = 'application/json'; 'Accept' = 'application/json' }
    return (ConvertFrom-BuzzJsonSafe $resp.Body)
}

function Invoke-BuzzCmdGet {
    param([string]$Server, [string]$Cmd, [hashtable]$Params, [string]$Token)
    $pairs = @()
    if ($Params) { foreach ($k in $Params.Keys) { $pairs += "$([Uri]::EscapeDataString([string]$k))=$([Uri]::EscapeDataString([string]$Params[$k]))" } }
    if ($Token) { $pairs += "_token=$([Uri]::EscapeDataString($Token))" }
    $url = "$Server/cmd/$Cmd"
    if ($pairs.Count -gt 0) { $url += '?' + ($pairs -join '&') }
    $resp = Invoke-BuzzHttp -Method 'GET' -Url $url -Headers @{ 'Accept' = 'application/json' }
    return (ConvertFrom-BuzzJsonSafe $resp.Body)
}

function Register-BuzzPublicKey {
    param([string]$Server, [string]$UserId, [string]$Kid, [string]$PublicKeyPem, [string]$Token)
    $url = "$Server/api/users/$UserId/keys/$Kid"
    $resp = Invoke-BuzzHttp -Method 'PUT' -Url $url -Body $PublicKeyPem -Headers @{ 'Authorization' = "Bearer $Token"; 'Content-Type' = 'application/x-pem-file' }
    return @($resp.StatusCode, $resp.Body)
}

function Remove-BuzzPublicKey {
    param([string]$Server, [string]$UserId, [string]$Kid, [string]$Token)
    $url = "$Server/api/users/$UserId/keys/$Kid"
    $resp = Invoke-BuzzHttp -Method 'DELETE' -Url $url -Headers @{ 'Authorization' = "Bearer $Token" }
    return @($resp.StatusCode, $resp.Body)
}

function ConvertFrom-BuzzJsonSafe {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return ($Text | ConvertFrom-Json) } catch { return $null }
}

function Get-BuzzProp {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [hashtable]) { return $Obj[$Name] }
    if ($Obj -is [System.Management.Automation.PSCustomObject]) {
        $p = $Obj.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    }
    return $null
}

function Get-BuzzResponseCode {
    param($Node)
    $resp = Get-BuzzProp $Node 'response'
    if ($resp -is [System.Management.Automation.PSCustomObject]) { return [string](Get-BuzzProp $resp 'code') }
    return [string](Get-BuzzProp $Node 'code')
}

function Get-BuzzResponseMessage {
    param($Node)
    $resp = Get-BuzzProp $Node 'response'
    $target = if ($resp -is [System.Management.Automation.PSCustomObject]) { $resp } else { $Node }
    return [string](Get-BuzzProp $target 'message')
}

# ── Admin login (login3, with optional MFA) ─────────────────────────────────────
function Get-BuzzAdminToken {
    param([string]$Server)
    while ($true) {
        $username = Read-BuzzAdminUsername
        $password = Read-BuzzPassword -Label 'Admin password' -EnvVar 'BUZZ_ADMIN_PASSWORD'

        Write-Host 'Logging in...' -NoNewline
        $resp = Invoke-BuzzCmdPost -Server $Server -Cmd 'login3' -Body @{ request = @{ cmd = 'login3'; username = $username; password = $password } }
        $code = Get-BuzzResponseCode $resp

        if ($code -and ($code -match '(?i)(factor|mfa|otp|challenge|verify|multifactor)')) {
            Write-Host ' MFA required.'
            $mfa = Read-BuzzRequired -Label 'MFA / one-time code' -EnvVar 'BUZZ_ADMIN_MFA'
            $partial = Get-BuzzProp (Get-BuzzProp $resp 'response') 'token'
            if (-not $partial) { $partial = Get-BuzzProp $resp 'token' }
            $resp = Invoke-BuzzCmdPost -Server $Server -Cmd 'verifylogin' -Body @{ request = @{ cmd = 'verifylogin'; token = $partial; code = $mfa } }
            $code = Get-BuzzResponseCode $resp
        }

        if ($code -ne 'OK') {
            $msg = Get-BuzzResponseMessage $resp
            Write-Host ("`n  Login failed (code: {0}){1}" -f $code, $(if ($msg) { ": $msg" } else { '' }))
            if ([Environment]::GetEnvironmentVariable('BUZZ_ADMIN_PASSWORD')) { Stop-Buzz 'Login failed with credentials from environment variables.' }
            Write-Host '  Please check your credentials and try again.  Press Ctrl+C to abort.'
            continue
        }

        $token = Get-BuzzProp (Get-BuzzProp (Get-BuzzProp $resp 'response') 'user') 'token'
        if (-not $token) { $token = Get-BuzzProp (Get-BuzzProp $resp 'user') 'token' }
        if (-not $token) { Write-Host "`n  Login succeeded but no token was returned.  Press Ctrl+C to abort."; continue }
        Write-Host ' OK'
        return [string]$token
    }
}

function Read-BuzzAdminUsername {
    $env = [Environment]::GetEnvironmentVariable('BUZZ_ADMIN_USERNAME')
    if ($env) { return $env }
    while ($true) {
        $value = Read-Host -Prompt 'Admin username (userspace/username, e.g. myschool/admin)'
        if ($value -match '^[^/]+/[^/]+$') { return $value.Trim() }
        Write-Host '  Username must be in userspace/username format.'
    }
}

# ── RSA key generation (writes PEM files) ────────────────────────────────────────
function New-BuzzKeyPair {
    param([string]$OutDir, [int]$Bits, [bool]$Overwrite = $false)
    if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
    $privPath = Join-Path (Resolve-Path -LiteralPath $OutDir) 'private_key.pem'
    $pubPath = Join-Path (Resolve-Path -LiteralPath $OutDir) 'public_key.pem'
    if (-not $Overwrite -and ((Test-Path $privPath) -or (Test-Path $pubPath))) {
        throw "Key file(s) already exist in $OutDir."
    }
    $rsa = New-BuzzRsaKey -Bits $Bits
    Export-BuzzPrivateKeyPem -Rsa $rsa | Set-Content -LiteralPath $privPath -Encoding Ascii -NoNewline
    Export-BuzzPublicKeyPem  -Rsa $rsa | Set-Content -LiteralPath $pubPath  -Encoding Ascii -NoNewline
    return @($privPath, $pubPath)
}

Export-ModuleMember -Function Write-BuzzSection, Write-BuzzInfo, Stop-Buzz,
Read-BuzzRequired, Read-BuzzOptional, Read-BuzzPassword, Confirm-Buzz,
Invoke-BuzzCmdPost, Invoke-BuzzCmdGet, Register-BuzzPublicKey, Remove-BuzzPublicKey,
Get-BuzzProp, Get-BuzzResponseCode, Get-BuzzResponseMessage, Get-BuzzAdminToken, New-BuzzKeyPair,
Get-BuzzConfigPath, Import-BuzzConfig, Export-BuzzConfig, Test-BuzzConfigComplete
