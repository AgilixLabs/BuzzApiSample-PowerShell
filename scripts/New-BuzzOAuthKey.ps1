<#
.SYNOPSIS
    Generate an RSA key pair for Buzz OAuth 2.0 authentication.

.DESCRIPTION
    Outputs private_key.pem (keep secret; never commit) and public_key.pem
    (register with Register-BuzzOAuthKey.ps1). Uses only built-in .NET — no OpenSSL.

.EXAMPLE
    .\scripts\New-BuzzOAuthKey.ps1
    .\scripts\New-BuzzOAuthKey.ps1 -OutDir secrets -Bits 4096
#>
[CmdletBinding()]
param(
    [string]$OutDir = '.',
    [int]$Bits = 2048,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot\BuzzSetupCommon.psm1" -Force

if (-not $Force -and (Test-Path (Join-Path $OutDir 'private_key.pem'))) {
    if (-not (Confirm-Buzz 'Key files already exist and will be overwritten.  Continue?')) {
        Write-Host 'Aborted.'
        return
    }
    $Force = $true
}

try {
    if ($Bits -lt 2048) { throw 'Key size must be at least 2048 bits (Buzz minimum).' }
    $paths = New-BuzzKeyPair -OutDir $OutDir -Bits $Bits -Overwrite:$Force
    Write-Host ("`nRSA key pair generated ({0} bits):" -f $Bits)
    Write-Host ("  Private key : {0}" -f $paths[0])
    Write-Host ("  Public key  : {0}" -f $paths[1])
    Write-Host "`nNext step: register the public key with Buzz."
    Write-Host '  .\scripts\Register-BuzzOAuthKey.ps1 -ServerUrl https://backgroundapi.agilixbuzz.com -UserId <userid> -Kid <kid> -PublicKeyPath public_key.pem'
    Write-Host "`nIMPORTANT: Never commit private_key.pem to source control."
}
catch {
    Stop-Buzz $_.Exception.Message
}
