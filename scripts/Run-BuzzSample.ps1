<#
.SYNOPSIS
    Entry point for the Buzz API sample.

.DESCRIPTION
    If setup has not been completed (buzz-config.psd1 missing or the private key
    file not readable), the interactive setup runs first. Then the read-only
    sample runs.

.EXAMPLE
    .\scripts\Run-BuzzSample.ps1
    .\scripts\Run-BuzzSample.ps1 -Setup     # force re-running setup
#>
[CmdletBinding()]
param([switch]$Setup)

$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot\BuzzSetupCommon.psm1" -Force
$root = Split-Path -Parent $PSScriptRoot

if ($Setup -or -not (Test-BuzzConfigComplete)) {
    if ($Setup) { Write-Host "`n-- Running setup ---------------------------------------`n" }
    else { Write-Host "`n-- Setup not complete - starting interactive setup -----`n" }
    & "$PSScriptRoot\Setup-BuzzOAuth.ps1"
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        [Console]::Error.WriteLine("`nSetup did not complete.  Exiting.")
        exit 1
    }
}

Write-Host "`n-- Running the sample ----------------------------------"
& (Join-Path $root 'sample.ps1')
