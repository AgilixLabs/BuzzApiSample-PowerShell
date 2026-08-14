<#
.SYNOPSIS
    Remove all artifacts created by Setup-BuzzOAuth.ps1.

.DESCRIPTION
      1. Read buzz-config.psd1 to find the OAuth account details.
      2. Log in as a Buzz admin (supports MFA).
      3. Delete the registered OAuth public key from Buzz.
      4. Delete the Application Identity account from Buzz.
      5. Delete the local key files and buzz-config.psd1.

.EXAMPLE
    .\scripts\Cleanup-BuzzSample.ps1
    .\scripts\Cleanup-BuzzSample.ps1 -Yes     # skip confirmation
#>
[CmdletBinding()]
param([switch]$Yes)

$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot\BuzzSetupCommon.psm1" -Force

$configPath = Get-BuzzConfigPath
if (-not (Test-Path -LiteralPath $configPath)) {
    Write-Host 'buzz-config.psd1 not found - nothing to clean up.'
    return
}
$config = Import-PowerShellDataFile -LiteralPath $configPath

$server = ([string]$config.ServerUrl).TrimEnd('/')
$oauthUserId = [string]$config.OAuthUserId
$oauthKid = [string]$config.OAuthKid
$privateKeyPath = [string]$config.PrivateKeyPath

if (-not $server -or -not $oauthUserId) {
    Stop-Buzz 'buzz-config.psd1 is missing required fields (ServerUrl, OAuthUserId).'
}

Write-Host "`n========================================================"
Write-Host '  Buzz API Sample - Cleanup'
Write-Host "========================================================`n"
Write-Host 'This will:'
Write-Host ("  * Delete OAuth public key (kid: {0}) from Buzz" -f $oauthKid)
Write-Host ("  * Delete Application Identity account (userid: {0}) from Buzz" -f $oauthUserId)
if ($privateKeyPath) { Write-Host ("  * Delete local key files near: {0}" -f $privateKeyPath) }
Write-Host '  * Delete buzz-config.psd1'
if (-not $Yes -and -not (Confirm-Buzz "`nThis action is irreversible.  Continue?")) {
    Write-Host 'Aborted.'
    return
}

Write-Host "`n-- Admin login -----------------------------------------"
$adminToken = Get-BuzzAdminToken -Server $server

if ($oauthKid) {
    Write-Host ("`n-- Deleting OAuth key (kid: {0}) ----------------" -f $oauthKid)
    $del = Remove-BuzzPublicKey -Server $server -UserId $oauthUserId -Kid $oauthKid -Token $adminToken
    switch ($del[0]) {
        { $_ -in 200, 204 } { Write-Host ("OAuth key deleted (HTTP {0})." -f $del[0]) }
        404 { Write-Host 'OAuth key not found (already deleted or never registered).' }
        default { [Console]::Error.WriteLine("Warning: HTTP $($del[0]) deleting key. Continuing.") }
    }
}

Write-Host ("`n-- Deleting Application Identity account (userid: {0}) --" -f $oauthUserId)
$resp = Invoke-BuzzCmdPost -Server $server -Cmd 'deleteusers' -Body @{ requests = @{ user = @(@{ userid = $oauthUserId }) } } -Token $adminToken
# The per-user outcome is authoritative.  The OUTER code is OK whenever the request was
# merely well formed, so checking it first would report success for a delete that was
# actually denied or whose target did not exist.
$delItem = Get-BuzzItemResult $resp
$delCode = if ($delItem.code) { $delItem.code } else { Get-BuzzResponseCode $resp }
$delDetail = if ($delItem.message) { " - $($delItem.message)" } else { '' }
if ($delCode -eq 'OK') { Write-Host 'Application Identity account deleted.' }
else { [Console]::Error.WriteLine("Warning: delete returned code `"$delCode`"$delDetail. Continuing.") }

Write-Host "`n-- Removing local files --------------------------------"
$keyDir = if ($privateKeyPath) { Split-Path -Parent $privateKeyPath } else { Split-Path -Parent $PSScriptRoot }
foreach ($name in @('private_key.pem', 'public_key.pem')) {
    $p = Join-Path $keyDir $name
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force; Write-Host "Removed: $p" }
}
if ($privateKeyPath -and (Test-Path -LiteralPath $privateKeyPath)) { Remove-Item -LiteralPath $privateKeyPath -Force; Write-Host "Removed: $privateKeyPath" }
if (Test-Path -LiteralPath $configPath) { Remove-Item -LiteralPath $configPath -Force; Write-Host "Removed: $configPath" }

Write-Host "`n========================================================"
Write-Host '  Cleanup complete.  Environment is back to a clean state.'
Write-Host "========================================================`n"
