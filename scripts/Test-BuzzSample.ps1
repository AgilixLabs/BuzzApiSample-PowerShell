<#
.SYNOPSIS
    Builds and checks this sample under a placeholder application name.  For maintainers.

.DESCRIPTION
    sample.ps1 deliberately stops at start until a developer replaces YOUR_APPLICATION_NAME with their
    own application's name.  The name goes in the User-Agent, and a User-Agent containing "Buzz" is
    treated as one of Agilix's own applications, so an unnamed copy must not be usable as is.  That
    also stops our own builds, so this script:

      1. parses every .ps1 and .psm1 file and fails on any parse error (the repository has no unit tests); this
         needs no name,
      2. with -Run, also runs the sample that way against the configured server, and
      3. checks the opposite: that starting sample.ps1 still fails on YOUR_APPLICATION_NAME.

    With -Run the name is defined the way scripts/Run-BuzzSample.ps1 does it for the quick start: a
    YOUR_APPLICATION_NAME function in the scope that calls sample.ps1.

    It never edits sample.ps1, and fails if the file changed during the run.  Exits non-zero on
    any failure.

.PARAMETER Run
    Also run the sample against the server in buzz-config.psd1.  Skipped when that file does not exist.

.EXAMPLE
    pwsh -File scripts/Test-BuzzSample.ps1
#>
[CmdletBinding()]
param(
    [switch]$Run
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$root = Split-Path $PSScriptRoot -Parent
$entryFile  = Join-Path $root 'sample.ps1'
$configFile = Join-Path $root 'buzz-config.psd1'
$checkName  = 'SampleCheck/1.0'

# Runs a native command and throws when it exits non-zero.
function Invoke-Native([string]$Name, [string]$Command, [string[]]$Arguments) {
    Write-Host "-- $Name"
    $global:LASTEXITCODE = 0
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Name failed (exit code $LASTEXITCODE)." }
}

# Runs a native command that must fail, and fail on the unset application name.
function Assert-FailsOnPlaceholder([string]$Name, [string]$Command, [string[]]$Arguments) {
    Write-Host "-- $Name (must fail on YOUR_APPLICATION_NAME)"
    $global:LASTEXITCODE = 0
    $output = @(& $Command @Arguments 2>&1 | ForEach-Object { "$_" })
    if ($LASTEXITCODE -eq 0) { throw "$Name succeeded without an application name; an unnamed copy is no longer stopped." }
    if (-not ($output | Where-Object { $_ -match 'YOUR_APPLICATION_NAME' })) {
        $output | ForEach-Object { Write-Host $_ }
        throw "$Name failed, but not on YOUR_APPLICATION_NAME (see output above)."
    }
    Write-Host '   failed as expected.'
}

# Returns the first of the named commands that is on PATH and runs.
function Get-Tool([string[]]$Names, [string]$VersionArgument = '--version') {
    foreach ($n in $Names) {
        $cmd = Get-Command $n -CommandType Application, ExternalScript -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $cmd) { continue }
        $global:LASTEXITCODE = 0
        try { & $cmd.Source $VersionArgument *> $null } catch { continue }
        if ($LASTEXITCODE -eq 0) { return $cmd.Source }
    }
    throw "None of $($Names -join ', ') was found on PATH."
}

$exitCode = 0
$tempDir = $null
Push-Location $root
try {
    $pwsh = [System.Environment]::ProcessPath
    $original = [System.IO.File]::ReadAllBytes($entryFile)
    $count = ([regex]::Matches([System.Text.Encoding]::UTF8.GetString($original), '= YOUR_APPLICATION_NAME\b')).Count
    if ($count -ne 1) {
        throw "Expected '= YOUR_APPLICATION_NAME' exactly once in $entryFile, found $count.  Restore it (git checkout) first."
    }
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('sample-check-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $tempDir)
    Write-Host '-- parse .ps1/.psm1'
    $files = Get-ChildItem -Path $root -Include '*.ps1', '*.psm1' -Recurse -File
    foreach ($f in $files) {
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
        if ($errors.Count -gt 0) {
            $errors | ForEach-Object { Write-Host "$($f.FullName):$($_.Extent.StartLineNumber): $($_.Message)" }
            throw "Parse errors in $($f.Name)."
        }
    }
    if ($Run) {
        if (Test-Path $configFile) {
            $command = "function YOUR_APPLICATION_NAME { '$checkName' }; & '$($entryFile.Replace("'", "''"))'"
            Invoke-Native 'sample.ps1 (named)' $pwsh @('-NoProfile', '-Command', $command)
        } else {
            Write-Host "-- $(Split-Path $configFile -Leaf) not found; not running the sample."
        }
    }
    Assert-FailsOnPlaceholder 'sample.ps1' $pwsh @('-NoProfile', '-File', $entryFile)
    $after = [System.IO.File]::ReadAllBytes($entryFile)
    if ([Convert]::ToBase64String($after) -ne [Convert]::ToBase64String($original)) {
        throw "$entryFile changed during the run."
    }
    Write-Host 'All checks passed.'
} catch {
    [Console]::Error.WriteLine("FAILED: $($_.Exception.Message)")
    $exitCode = 1
} finally {
    Pop-Location
    if ($tempDir -and (Test-Path $tempDir)) { Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue }
}
exit $exitCode
