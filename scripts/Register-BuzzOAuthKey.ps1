<#
.SYNOPSIS
    Register an RSA public key with Buzz for OAuth 2.0 authentication.

.DESCRIPTION
    The admin Bearer token is read from -AdminToken, the BUZZ_ADMIN_TOKEN
    environment variable, or an interactive prompt (in that order).
    PUTting an existing kid REPLACES the key immediately — use a new kid to rotate.

.EXAMPLE
    .\scripts\Register-BuzzOAuthKey.ps1 -ServerUrl https://api.agilixbuzz.com -UserId 12345678 -Kid 2025-q2 -PublicKeyPath public_key.pem
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ServerUrl,
    [Parameter(Mandatory)][string]$UserId,
    [Parameter(Mandatory)][string]$Kid,
    [Parameter(Mandatory)][string]$PublicKeyPath,
    [string]$AdminToken
)

$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot\BuzzSetupCommon.psm1" -Force

$server = $ServerUrl.TrimEnd('/')
if ($Kid -notmatch '^[A-Za-z0-9._-]{1,128}$') {
    Stop-Buzz 'Invalid kid. Allowed: ASCII letters, digits, -, _, .  Max 128 chars.'
}
if (-not (Test-Path -LiteralPath $PublicKeyPath)) {
    Stop-Buzz "Public key file not found: $PublicKeyPath"
}
$pem = Get-Content -Raw -LiteralPath $PublicKeyPath
if ($pem -notmatch 'BEGIN PUBLIC KEY') {
    Stop-Buzz "File is not a SubjectPublicKeyInfo PEM ('-----BEGIN PUBLIC KEY-----')."
}

if (-not $AdminToken) {
    $AdminToken = [Environment]::GetEnvironmentVariable('BUZZ_ADMIN_TOKEN')
    if (-not $AdminToken) { $AdminToken = Read-BuzzPassword -Label 'Admin Bearer token' }
}
if (-not $AdminToken) { Stop-Buzz 'Admin token is required.' }

Write-Host 'Registering public key...'
Write-Host ("  URL  : {0}/api/users/{1}/keys/{2}" -f $server, $UserId, $Kid)
Write-Host ("  Kid  : {0}" -f $Kid)
Write-Host ("  File : {0}`n" -f (Resolve-Path -LiteralPath $PublicKeyPath))

$result = Register-BuzzPublicKey -Server $server -UserId $UserId -Kid $Kid -PublicKeyPem $pem -Token $AdminToken
$status = $result[0]; $body = $result[1]

switch ($status) {
    204 {
        Write-Host "Public key registered successfully (HTTP 204).`n"
        Write-Host 'Configure your application:'
        Write-Host ("  OAuthUserId = {0}" -f $UserId)
        Write-Host ("  OAuthKid    = {0}" -f $Kid)
    }
    400 {
        [Console]::Error.WriteLine('Error: HTTP 400 Bad Request')
        [Console]::Error.WriteLine('  - Public key must be SPKI PEM and at least 2048 bits.')
        [Console]::Error.WriteLine("  - Account $UserId must have been created with type=applicationidentity.")
        if ($body) { [Console]::Error.WriteLine("Response: $body") }
        exit 1
    }
    { $_ -in 401, 403 } {
        [Console]::Error.WriteLine("Error: HTTP $status - admin token lacks Update User rights on account $UserId.")
        exit 1
    }
    404 { [Console]::Error.WriteLine('Error: HTTP 404 - server URL or user id not found.'); exit 1 }
    default {
        [Console]::Error.WriteLine("Error: unexpected HTTP $status")
        if ($body) { [Console]::Error.WriteLine("Response: $body") }
        exit 1
    }
}
