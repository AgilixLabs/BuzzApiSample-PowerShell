<#
.SYNOPSIS
    Buzz API OAuth 2.0 sample — read-only demo.

.DESCRIPTION
    Demonstrates read-only access to the Buzz API:
      1. Configuring the client with OAuth credentials.
      2. Calling getuser2 to verify authentication and discover the home domain.
      3. Calling getdomain2 to read domain details.

    The sample is intentionally read-only — it can be run repeatedly without
    modifying any data in the target domain.

    Quickest start:  .\scripts\Run-BuzzSample.ps1
#>

$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot\BuzzApiClient.psm1" -Force
Import-Module "$PSScriptRoot\BuzzConfig.psm1" -Force

function Get-Value($Obj, [string[]]$Names) {
    foreach ($n in $Names) {
        $p = $Obj.PSObject.Properties[$n]
        if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne '') { return $p.Value }
    }
    return $null
}

$config = Import-BuzzConfig
$userAgent = "BuzzApiClient/1.0.0 (PowerShell; $($config.ApplicationInformation); $($config.ContactInformation))"

# Show info/warn/error; suppress debug tracing for a clean demo.
$logger = {
    param($level, $message)
    if ($level -ne 'debug') { Write-Host ("{0}: {1}" -f $level.ToUpper(), $message) }
}

$client = New-BuzzApiClientFromPem `
    -ServerUrl $config.ServerUrl `
    -UserAgent $userAgent `
    -OAuthUserId $config.OAuthUserId `
    -OAuthKid $config.OAuthKid `
    -PrivateKeyPath $config.PrivateKeyPath `
    -Logger $logger

Write-Host ''
Write-Host '========================================================'
Write-Host '  Buzz API OAuth 2.0 Sample - Read-Only Demo (PowerShell)'
Write-Host '========================================================'
Write-Host ''

# getuser2: verify authentication and discover the home domain.
Write-Host '-- getuser2 (verify authentication) --------------------'
$userNode = $client.VerifyResponse($client.JsonRequest('GET', 'getuser2', $null, $null, $true), $true)
$user = $userNode.user

# The User schema names this "id".  ("userid" is the CreateUsers2 *response* field
# for a newly created user - a different command, not an alias here.)
$userId = Get-Value $user @('id')
$domainId = Get-Value $user @('domainid')
& $logger 'info' ("Authenticated as user {0} (`"{1} {2}`", userid: {3})" -f $user.username, $user.firstname, $user.lastname, $userId)
& $logger 'info' ("Home domain: {0}" -f $domainId)

# getdomain2: read details about the account's home domain.
if ($domainId) {
    Write-Host ''
    Write-Host '-- getdomain2 (read domain details) --------------------'
    $domainNode = $client.VerifyResponse($client.JsonRequest('GET', 'getdomain2', @{ domainid = "$domainId" }, $null, $true), $true)
    $domain = $domainNode.domain
    & $logger 'info' ("Domain name: {0}" -f $domain.name)
    & $logger 'info' ("Userspace  : {0}" -f $domain.userspace)
    $type = Get-Value $domain @('type')
    if ($type) { & $logger 'info' ("Type       : {0}" -f $type) }
}

Write-Host ''
Write-Host '========================================================'
Write-Host '  All API calls succeeded.  OAuth integration is working.'
Write-Host '  No data was created or modified.'
Write-Host '========================================================'
Write-Host ''
