<#
.SYNOPSIS
    Interactive guided setup for Buzz OAuth 2.0 authentication.

.DESCRIPTION
      1. Prompt for the Buzz server URL.
      2. Log in as a Buzz administrator (supports MFA) to perform setup.
      3. Create (or reuse) an Application Identity account.
      4. Generate an RSA key pair (private key stored as a PEM file).
      5. Register the public key with Buzz.
      6. Write buzz-config.psd1 so .\sample.ps1 works immediately.

    Every prompt falls back to a BUZZ_* environment variable, so the whole flow
    can run unattended.
#>
[CmdletBinding()]
param(
    [string]$ServerUrl = '',
    [int]$Bits = 0,
    [string]$KeyDir = ''
)

$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot\BuzzSetupCommon.psm1" -Force
$root = Split-Path -Parent $PSScriptRoot
if (-not $KeyDir) { $KeyDir = $root }

function Get-BuzzDefaultKid {
    $now = [DateTimeOffset]::UtcNow
    return ('{0}-q{1}' -f $now.Year, [int](([int]$now.Month + 2) / 3))
}

function Get-BuzzCreatedUserId {
    param($Resp)
    $r = Get-BuzzProp $Resp 'response'; if (-not $r) { $r = $Resp }
    $responses = Get-BuzzProp $r 'responses'
    $inner = Get-BuzzProp $responses 'response'
    if ($inner -is [object[]]) { $inner = if ($inner.Count -gt 0) { $inner[0] } else { $null } }
    $user = Get-BuzzProp $inner 'user'
    # The CreateUsers2 response documents this as "userid".
    $id = Get-BuzzProp $user 'userid'
    return [string]$id
}

function Get-BuzzDomains {
    param([string]$Server, [string]$Token)
    # ListDomains, not "getdomains" -- the latter is not a Buzz command and always
    # answered "Unknown API command", so this silently returned @() on every run.
    # domainid=0 means "every domain this account has ReadDomain rights on"; limit=0
    # lifts the default 100-domain cap (capped server-side at 1000 for domainid=0).
    #   https://api.agilixbuzz.com/docs/entry/Command/ListDomains.md
    $resp = Invoke-BuzzCmdGet -Server $Server -Cmd 'listdomains' -Params @{ domainid = 0; limit = 0 } -Token $Token
    if ((Get-BuzzResponseCode $resp) -ne 'OK') { return @() }
    # When the account can read no domains the server answers OK with "domains":{},
    # so every level has to tolerate a missing or empty node.
    $domains = Get-BuzzProp (Get-BuzzProp (Get-BuzzProp $resp 'response') 'domains') 'domain'
    if ($null -eq $domains) { return @() }
    if ($domains -is [System.Management.Automation.PSCustomObject]) { $domains = @($domains) }
    $out = @()
    foreach ($d in $domains) {
        # The Domain schema names the identifier "id"; "domainid" is what you *send*.
        $out += , @([string](Get-BuzzProp $d 'id'), [string](Get-BuzzProp $d 'name'))
    }
    return $out
}

function Get-BuzzOrCreateAccount {
    param([string]$Server, [string]$Token)
    $createEnv = [Environment]::GetEnvironmentVariable('BUZZ_SETUP_CREATE_NEW')
    $doCreate = if ($null -ne $createEnv -and $createEnv -ne '') { $createEnv.ToLower().StartsWith('y') } else { Confirm-Buzz 'Create a new Application Identity account?' $true }

    if (-not $doCreate) {
        return Read-BuzzRequired -Label 'Existing Application Identity account userid' -EnvVar 'BUZZ_SETUP_OAUTH_USER_ID'
    }

    $targetDomain = [Environment]::GetEnvironmentVariable('BUZZ_SETUP_DOMAINID')
    if (-not $targetDomain) {
        Write-Host 'Fetching available domains...' -NoNewline
        $domains = Get-BuzzDomains -Server $Server -Token $Token
        if ($domains.Count -gt 0) {
            Write-Host " done`n"
            for ($i = 0; $i -lt $domains.Count; $i++) {
                Write-Host ('  {0,2}. {1,-30} (id: {2})' -f ($i + 1), $domains[$i][1], $domains[$i][0])
            }
            $choice = Read-BuzzRequired -Label "`nEnter domain number or type the domainid directly"
            if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $domains.Count) {
                $targetDomain = $domains[[int]$choice - 1][0]
            }
            else { $targetDomain = $choice }
        }
        else {
            # An empty list is normal when the admin holds no ReadDomain right anywhere,
            # or when the domain simply has no child domains.  Not an error -- just ask.
            Write-Host " done`n"
            Write-Host '  No domains were listed for this account, so enter the target domain directly.'
            $targetDomain = Read-BuzzRequired -Label 'Domain id for the new account (e.g. //myschool or a numeric id)'
        }
    }

    $username = Read-BuzzRequired -Label 'Username for the account (e.g. sis-sync)' -EnvVar 'BUZZ_SETUP_APP_USERNAME'
    $firstname = Read-BuzzRequired -Label 'First name (e.g. SIS)' -EnvVar 'BUZZ_SETUP_APP_FIRSTNAME'
    $lastname = Read-BuzzRequired -Label 'Last name (e.g. Sync)' -EnvVar 'BUZZ_SETUP_APP_LASTNAME'
    $email = Read-BuzzOptional -Label 'Email address' -EnvVar 'BUZZ_SETUP_APP_EMAIL'

    $user = @{ domainid = $targetDomain; type = 'applicationidentity'; username = $username; firstname = $firstname; lastname = $lastname }
    if ($email) { $user['email'] = $email }

    Write-Host ("`nCreating Application Identity account '{0}'..." -f $username) -NoNewline
    $resp = Invoke-BuzzCmdPost -Server $Server -Cmd 'createusers2' -Body @{ requests = @{ user = @($user) } } -Token $Token
    if ((Get-BuzzResponseCode $resp) -ne 'OK') {
        Stop-Buzz ("CreateUsers2 failed (code: {0})." -f (Get-BuzzResponseCode $resp))
    }
    # The outer OK only means the request parsed; CreateUsers2 reports the outcome for
    # the user it created under responses.response, so a denial arrives inside an "OK"
    # envelope and must be checked separately.
    $item = Get-BuzzItemResult $resp
    if ($item.code -and $item.code -ne 'OK') {
        $detail = if ($item.message) { " - $($item.message)" } else { '' }
        if ($item.code -eq 'AccessDenied') {
            Stop-Buzz ("CreateUsers2 was denied (code: {0}{1}).`n  The admin account needs the CreateUser right on domain {2}.`n  Grant it that right (and UpdateUser, so it can register the OAuth key), then re-run." -f $item.code, $detail, $targetDomain)
        }
        Stop-Buzz ("CreateUsers2 failed for the requested user (code: {0}{1})." -f $item.code, $detail)
    }
    $userId = Get-BuzzCreatedUserId $resp
    if (-not $userId) { Stop-Buzz 'CreateUsers2 succeeded but returned no userid.' }
    Write-Host (" OK (userid: {0})" -f $userId)
    return $userId
}

# ── Main flow ────────────────────────────────────────────────────────────────
Write-Host "`n=========================================================="
Write-Host '  Buzz OAuth 2.0 Application Setup (PowerShell)'
Write-Host '=========================================================='

Write-BuzzSection 'Step 1: Buzz Server URL'
if (-not $ServerUrl) { $ServerUrl = Read-BuzzRequired -Label 'Buzz API server URL (e.g. https://backgroundapi.agilixbuzz.com)' -EnvVar 'BUZZ_SERVER_URL' }
$server = $ServerUrl.TrimEnd('/')
Write-Host "  Server: $server"

Write-BuzzSection 'Step 2: Admin Login'
Write-Host 'Log in as a Buzz administrator to perform the one-time setup.'
Write-Host "This session is used only during setup and is not stored anywhere.`n"
$adminToken = Get-BuzzAdminToken -Server $server

Write-BuzzSection 'Step 3: Application Information'
Write-Host "Included in the User-Agent header so Agilix support can identify your integration.`n"
$contact = Read-BuzzRequired -Label 'Your contact info (name, email, or URL)' -EnvVar 'BUZZ_CONTACT_INFORMATION'
$appName = Read-BuzzRequired -Label 'Application name (e.g. SisSync)' -EnvVar 'BUZZ_APPLICATION_INFORMATION'

Write-BuzzSection 'Step 4: Application Identity Account'
Write-Host "This Buzz user represents your application.  It authenticates via OAuth only.`n"
$oauthUserId = Get-BuzzOrCreateAccount -Server $server -Token $adminToken

Write-BuzzSection 'Step 5: RSA Key Generation'
if (-not $Bits) {
    $envBits = [Environment]::GetEnvironmentVariable('BUZZ_SETUP_KEY_BITS')
    if ($envBits -and [int]$envBits -gt 0) { $Bits = [int]$envBits } else { $Bits = [int](Read-BuzzRequired -Label 'RSA key size in bits' -Default '2048') }
}
$kid = [Environment]::GetEnvironmentVariable('BUZZ_SETUP_KID')
if (-not $kid) { $kid = Read-BuzzRequired -Label 'Key id (kid) for this key' -Default (Get-BuzzDefaultKid) }
if ($kid -notmatch '^[A-Za-z0-9._-]{1,128}$') { Stop-Buzz "Invalid kid '$kid'. Allowed: ASCII letters, digits, -, _, .  Max 128 chars." }
Write-BuzzInfo "Kid : $kid"
$paths = New-BuzzKeyPair -OutDir $KeyDir -Bits $Bits -Overwrite:$true
$privPath = $paths[0]; $pubPath = $paths[1]
Write-Host "  Private key: $privPath"

Write-BuzzSection 'Step 6: Registering Public Key with Buzz'
Write-BuzzInfo "PUT $server/api/users/$oauthUserId/keys/$kid"
$reg = Register-BuzzPublicKey -Server $server -UserId $oauthUserId -Kid $kid -PublicKeyPem (Get-Content -Raw -LiteralPath $pubPath) -Token $adminToken
if ($reg[0] -eq 204) { Write-Host ' 204 OK' } else { Stop-Buzz ("Key registration returned HTTP {0}. {1}" -f $reg[0], $reg[1]) }

Write-BuzzSection 'Step 7: Writing Configuration'
$configPath = Export-BuzzConfig -Config @{
    ServerUrl              = $server
    ContactInformation     = $contact
    ApplicationInformation = $appName
    OAuthUserId            = $oauthUserId
    OAuthKid               = $kid
    PrivateKeyPath         = $privPath
}
Write-Host "  Written: $configPath"

Write-Host "`n=========================================================="
Write-Host '  Setup complete!'
Write-Host '=========================================================='
Write-Host "OAuth User ID : $oauthUserId"
Write-Host "Key ID (kid)  : $kid"
Write-Host "Private key   : $privPath"
Write-Host "Config file   : $configPath"
Write-Host "`nTo test:  .\sample.ps1`n"
