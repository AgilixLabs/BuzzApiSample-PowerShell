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
# Session tokens travel in an Authorization: Bearer header on both /cmd/* and /api/*
# endpoints.  A _token query parameter is also accepted by /cmd/*, but a credential in
# a URL is recorded by server and proxy access logs.
# Buzz returns XML unless JSON is requested via Accept.
function Get-BuzzAuthHeaders {
    param([string]$Token, [hashtable]$Extra)
    $headers = @{ 'Accept' = 'application/json' }
    if ($Token) { $headers['Authorization'] = "Bearer $Token" }
    if ($Extra) { foreach ($k in $Extra.Keys) { $headers[$k] = $Extra[$k] } }
    return $headers
}

function Invoke-BuzzCmdPost {
    param([string]$Server, [string]$Cmd, [object]$Body, [string]$Token)
    $url = "$Server/cmd/$Cmd"
    $json = $Body | ConvertTo-Json -Depth 10 -Compress
    $resp = Invoke-BuzzHttp -Method 'POST' -Url $url -Body $json `
        -Headers (Get-BuzzAuthHeaders -Token $Token -Extra @{ 'Content-Type' = 'application/json' })
    return (ConvertFrom-BuzzJsonSafe $resp.Body)
}

function Invoke-BuzzCmdGet {
    param([string]$Server, [string]$Cmd, [hashtable]$Params, [string]$Token)
    $pairs = @()
    if ($Params) { foreach ($k in $Params.Keys) { $pairs += "$([Uri]::EscapeDataString([string]$k))=$([Uri]::EscapeDataString([string]$Params[$k]))" } }
    $url = "$Server/cmd/$Cmd"
    if ($pairs.Count -gt 0) { $url += '?' + ($pairs -join '&') }
    $resp = Invoke-BuzzHttp -Method 'GET' -Url $url -Headers (Get-BuzzAuthHeaders -Token $Token)
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

# The per-entity result of a multi-object command (CreateUsers2, DeleteUsers).  Those
# commands report each entity's outcome under response.responses.response, while the
# OUTER code is OK whenever the request was merely well formed.  A per-entity
# AccessDenied therefore arrives inside an "OK" envelope, so the outer code alone
# cannot tell you whether the entity was actually created or deleted.
function Get-BuzzItemResult {
    param($Resp)
    $inner = Get-BuzzProp $Resp 'response'
    if ($null -eq $inner) { $inner = $Resp }
    $node = Get-BuzzProp (Get-BuzzProp $inner 'responses') 'response'
    if ($node -is [array]) { $node = if ($node.Count) { $node[0] } else { $null } }
    if ($null -eq $node) { return @{ code = ''; message = ''; userid = '' } }
    return @{
        code    = [string](Get-BuzzProp $node 'code')
        message = [string](Get-BuzzProp $node 'message')
        userid  = [string](Get-BuzzProp (Get-BuzzProp $node 'user') 'userid')
    }
}

# The short-lived token login3 returns alongside SecondFactorRequired.  Observed shape:
# response.token, duplicated at response.body.token.  There is no "user" node on that
# response, so response.user.token (where the session token lives on a *successful*
# login) does not exist yet.  remembermfa.token is deliberately ignored: it remembers a
# device and cannot complete this login.
function Get-BuzzSecondFactorToken {
    param($Resp)
    $inner = Get-BuzzProp $Resp 'response'
    if ($null -eq $inner) { $inner = $Resp }
    foreach ($candidate in @(
        (Get-BuzzProp (Get-BuzzProp $inner 'user') 'token'),
        (Get-BuzzProp $inner 'token'),
        (Get-BuzzProp (Get-BuzzProp $inner 'body') 'token')
    )) {
        if ($candidate -is [string] -and -not [string]::IsNullOrEmpty($candidate)) { return $candidate }
    }
    return ''
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

        # Multi-factor authentication.  login3 answers SecondFactorRequired when the
        # password was correct but the account has MFA configured, and returns a
        # short-lived token that is presented in an Authorization: Bearer header to
        # secondfactorauthenticate, which returns the real session token.  Putting the
        # token in the request body instead is ignored: AccessDenied userId='-1'.
        #   https://api.agilixbuzz.com/docs/entry/Command/Login3.md
        #   https://api.agilixbuzz.com/docs/entry/Command/SecondFactorAuthenticate.md
        if ($code -eq 'SecondFactorConfigurationNowRequired') {
            Write-Host "`n  This account must configure multi-factor authentication before it can"
            Write-Host '  be used.  Complete MFA setup in Buzz, then re-run this script.'
            if ([Environment]::GetEnvironmentVariable('BUZZ_ADMIN_PASSWORD')) { Stop-Buzz 'Admin account requires multi-factor authentication setup.' }
            Write-Host '  Press Ctrl+C to abort.'
            continue
        }

        if ($code -eq 'SecondFactorRequired') {
            Write-Host ' multi-factor authentication required.'
            $partial = Get-BuzzSecondFactorToken $resp
            if (-not $partial) {
                Write-Host "`n  Buzz asked for a second factor but no token could be found in its reply."
                if ([Environment]::GetEnvironmentVariable('BUZZ_ADMIN_PASSWORD')) { Stop-Buzz 'No second-factor token was returned.' }
                Write-Host '  Press Ctrl+C to abort.'
                continue
            }
            $otp = Read-BuzzRequired -Label 'One-time code from your authenticator app or email' -EnvVar 'BUZZ_ADMIN_MFA'
            $resp = Invoke-BuzzCmdPost -Server $Server -Cmd 'secondfactorauthenticate' `
                -Body @{ request = @{ cmd = 'secondfactorauthenticate'; otp = $otp } } -Token $partial
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
Get-BuzzProp, Get-BuzzResponseCode, Get-BuzzResponseMessage, Get-BuzzItemResult,
Get-BuzzSecondFactorToken, Get-BuzzAdminToken, New-BuzzKeyPair,
Get-BuzzConfigPath, Import-BuzzConfig, Export-BuzzConfig, Test-BuzzConfigComplete
