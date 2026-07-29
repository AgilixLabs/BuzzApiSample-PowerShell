<#
.SYNOPSIS
    Reusable client for the Buzz API, authenticating with OAuth 2.0 JWT client
    credentials (RFC 6749 + RFC 7523).

.DESCRIPTION
    The client obtains and refreshes Bearer access tokens automatically, retries
    transient failures with exponential backoff, and honours rate-limit headers.

    Works on Windows PowerShell 5.1 and PowerShell 7+. No external dependencies.

    Create a client with New-BuzzApiClientFromPem (or New-BuzzApiClient), then call
    the returned object's .JsonRequest() and .VerifyResponse() methods.
#>

Set-StrictMode -Version Latest

Import-Module "$PSScriptRoot\BuzzCrypto.psm1" -Force
Import-Module "$PSScriptRoot\BuzzHttp.psm1" -Force

$script:RetriesToMake = 5
$script:InitialWaitMs = 1000
$script:MaxRetryWaitMs = 64000
$script:TokenRefreshMarginSec = 300
$script:SensitiveFields = @('token', 'access_token', 'refresh_token', 'password', 'client_assertion', 'client_secret')
$script:NoRetryStatus = @(400, 401, 402, 403, 405, 406, 407, 410, 411, 412, 413, 414, 415, 416,
    417, 421, 422, 424, 426, 428, 431, 451, 501, 505, 506, 508, 510, 511)

# ── Internal helpers ────────────────────────────────────────────────────────────
function Get-BuzzProp {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [hashtable]) { return $Obj[$Name] }
    if ($Obj -is [System.Management.Automation.PSCustomObject]) {
        $p = $Obj.PSObject.Properties[$Name]
        if ($p) { return $p.Value }
    }
    return $null
}

function Get-BuzzResponseCode {
    param($Node)
    if ($null -eq $Node) { return $null }
    $resp = Get-BuzzProp $Node 'response'
    if ($resp -is [System.Management.Automation.PSCustomObject]) { return Get-BuzzProp $resp 'code' }
    return Get-BuzzProp $Node 'code'
}

function ConvertTo-BuzzBase64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-BuzzJson {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return ($Text | ConvertFrom-Json) } catch { return $null }
}

function Test-BuzzStatusRetryable {
    param([int]$Status)
    return -not ($script:NoRetryStatus -contains $Status)
}

function Get-BuzzRetryAfterMs {
    param([string]$RetryAfter)
    if ([string]::IsNullOrWhiteSpace($RetryAfter)) { return $null }
    $v = $RetryAfter.Trim()
    if ($v -match '^\d+$') { return [int]$v * 1000 }
    try {
        $when = [DateTimeOffset]::Parse($v, [System.Globalization.CultureInfo]::InvariantCulture)
        $ms = ($when - [DateTimeOffset]::UtcNow).TotalMilliseconds
        if ($ms -lt 0) { $ms = 0 }
        return [int]$ms
    }
    catch { return $null }
}

function Get-BuzzJitterMs { return (Get-Random -Minimum 1 -Maximum 1000) }

function Get-BuzzWaitFromResponse {
    param([hashtable]$Headers, [int]$BaseMs)
    $ms = Get-BuzzRetryAfterMs $Headers['retry-after']
    if ($null -ne $ms -and $ms -gt 0) {
        return [Math]::Max($BaseMs, [Math]::Min($script:MaxRetryWaitMs, $ms))
    }
    $reset = $Headers['x-ratelimit-reset']
    if ($reset -and ($reset -match '^\d+$') -and [int]$reset -gt 0) {
        return [Math]::Max($BaseMs, [Math]::Min($script:MaxRetryWaitMs, [int]$reset * 1000))
    }
    return [Math]::Min($script:MaxRetryWaitMs, $BaseMs + (Get-BuzzJitterMs))
}

function Get-BuzzWaitFromRetryHeader {
    param([string]$RetryAfter, [int]$BaseMs)
    $ms = Get-BuzzRetryAfterMs $RetryAfter
    if ($null -ne $ms) { return [Math]::Min($script:MaxRetryWaitMs, [Math]::Max($BaseMs, $ms)) }
    return [Math]::Min($script:MaxRetryWaitMs, $BaseMs + (Get-BuzzJitterMs))
}

function ConvertTo-BuzzRedacted {
    param($Obj)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Management.Automation.PSCustomObject]) {
        $h = [ordered]@{}
        foreach ($p in $Obj.PSObject.Properties) {
            if ($script:SensitiveFields -contains $p.Name) { $h[$p.Name] = '[REDACTED]' }
            else { $h[$p.Name] = ConvertTo-BuzzRedacted $p.Value }
        }
        return $h
    }
    if ($Obj -is [object[]]) { return @($Obj | ForEach-Object { ConvertTo-BuzzRedacted $_ }) }
    return $Obj
}

function Get-BuzzRedactedUri {
    param([string]$Uri, [string]$ParamName)
    $q = $Uri.IndexOf('?')
    if ($q -lt 0) { return $Uri }
    $kept = @()
    foreach ($pair in $Uri.Substring($q + 1).Split('&')) {
        if (-not $pair.ToLower().StartsWith($ParamName.ToLower() + '=')) { $kept += $pair }
    }
    if ($kept.Count -gt 0) { return $Uri.Substring(0, $q) + '?' + ($kept -join '&') }
    return $Uri.Substring(0, $q)
}

# ── Client class ────────────────────────────────────────────────────────────────
class BuzzApiClient {
    [string]$ServerUrl
    [string]$UserAgent
    [string]$Token

    hidden [string]$OAuthUserId
    hidden [string]$OAuthKid
    hidden [object]$PrivateKey
    hidden [string]$TokenEndpoint
    hidden [bool]$VerboseLogging
    hidden [int]$TimeoutSec
    hidden [scriptblock]$Logger
    hidden [long]$TokenExpiryEpoch

    BuzzApiClient([string]$serverUrl, [string]$userAgent, [string]$oauthUserId, [string]$oauthKid,
        [object]$privateKey, [bool]$verboseLogging, [int]$timeoutSec, [scriptblock]$logger) {
        if ([string]::IsNullOrEmpty($oauthUserId)) { throw 'oauthUserId is required' }
        if ([string]::IsNullOrEmpty($oauthKid)) { throw 'oauthKid is required' }
        if ($null -eq $privateKey) { throw 'privateKey is required' }

        $this.ServerUrl = $serverUrl.Trim().TrimEnd('/')
        $this.UserAgent = $userAgent
        $this.OAuthUserId = $oauthUserId
        $this.OAuthKid = $oauthKid
        $this.PrivateKey = $privateKey
        $this.VerboseLogging = $verboseLogging
        $this.TimeoutSec = if ($timeoutSec -gt 0) { $timeoutSec } else { 600 }
        $this.Logger = $logger
        $this.TokenEndpoint = "$($this.ServerUrl)/api/oauth/token"
        $this.TokenExpiryEpoch = 0
    }

    [object] JsonRequest([string]$method, [string]$cmd, [hashtable]$params, [object]$jsonBody, [bool]$includeToken) {
        if ($includeToken) { $this.EnsureToken() }

        $content = $null
        if ($null -ne $jsonBody) { $content = ($jsonBody | ConvertTo-Json -Depth 10 -Compress) }

        $body = $this.RequestWithRetry($method, $cmd, $params, $content, $includeToken)
        $node = ConvertFrom-BuzzJson $body
        $this.TraceResponse($node)

        # If the token expired or was revoked, re-authenticate and retry once.
        if ($includeToken -and $this.Token -and ((Get-BuzzResponseCode $node) -eq 'NoAuthentication')) {
            $this.Log('debug', 'Re-authenticating because the request returned code "NoAuthentication"')
            $this.AuthenticateOAuth()
            $body = $this.RequestWithRetry($method, $cmd, $params, $content, $includeToken)
            $node = ConvertFrom-BuzzJson $body
            $this.TraceResponse($node)
        }
        return $node
    }

    [object] VerifyResponse([object]$responseJson, [bool]$checkChildResponses) {
        if ($null -eq $responseJson) {
            $this.Log('error', 'Buzz API call failed. Expected response.code to be OK, found: null')
            throw 'Buzz API call failed. Expected response.code to be OK, found: null'
        }
        $toVerify = $responseJson
        $inner = Get-BuzzProp $responseJson 'response'
        if ($inner -is [System.Management.Automation.PSCustomObject]) { $toVerify = $inner }

        if ((Get-BuzzProp $toVerify 'code') -ne 'OK') {
            $redacted = (ConvertTo-BuzzRedacted $responseJson) | ConvertTo-Json -Depth 10 -Compress
            $this.Log('error', "Buzz API call failed. Expected response.code to be OK, found: $redacted")
            throw "Buzz API call failed. Expected response.code to be OK, found: $redacted"
        }

        if ($checkChildResponses) {
            $responses = Get-BuzzProp $toVerify 'responses'
            if ($responses) {
                $child = Get-BuzzProp $responses 'response'
                if ($child -is [object[]]) { foreach ($item in $child) { $this.VerifyResponse($item, $true) } }
                elseif ($child -is [System.Management.Automation.PSCustomObject]) { $this.VerifyResponse($child, $true) }
            }
        }
        return $toVerify
    }

    hidden [void] EnsureToken() {
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ($this.Token -and ($now -lt ($this.TokenExpiryEpoch - $script:TokenRefreshMarginSec))) { return }
        $this.AuthenticateOAuth()
    }

    hidden [void] AuthenticateOAuth() {
        $this.Log('info', 'Requesting OAuth access token')
        $retriesRemaining = $script:RetriesToMake
        $baseWait = $script:InitialWaitMs
        while ($true) {
            $assertion = $this.BuildClientAssertion()
            $form = 'grant_type=client_credentials' +
            '&client_assertion_type=' + [Uri]::EscapeDataString('urn:ietf:params:oauth:client-assertion-type:jwt-bearer') +
            '&client_assertion=' + [Uri]::EscapeDataString($assertion)

            $resp = Invoke-BuzzHttp -Method 'POST' -Url $this.TokenEndpoint -Body $form `
                -Headers @{ 'User-Agent' = $this.UserAgent; 'Content-Type' = 'application/x-www-form-urlencoded' } `
                -TimeoutSec $this.TimeoutSec

            if ($resp.TransportError) {
                if ($retriesRemaining -gt 0) {
                    Start-Sleep -Milliseconds (Get-BuzzWaitFromRetryHeader $null $baseWait)
                    $retriesRemaining--; $baseWait *= 2; continue
                }
                throw "OAuth token request failed: $($resp.Error)"
            }
            if (($resp.StatusCode -eq 429 -or $resp.StatusCode -eq 503) -and $retriesRemaining -gt 0) {
                $wait = Get-BuzzWaitFromResponse $resp.Headers $baseWait
                $this.Log('warn', "OAuth token request rate-limited ($($resp.StatusCode)), backing off ${wait}ms, $retriesRemaining retries remaining")
                Start-Sleep -Milliseconds $wait; $retriesRemaining--; $baseWait *= 2; continue
            }
            if ($resp.StatusCode -lt 200 -or $resp.StatusCode -ge 300) {
                if ($retriesRemaining -gt 0 -and (Test-BuzzStatusRetryable $resp.StatusCode)) {
                    Start-Sleep -Milliseconds (Get-BuzzWaitFromRetryHeader $resp.Headers['retry-after'] $baseWait)
                    $retriesRemaining--; $baseWait *= 2; continue
                }
                $this.Log('error', "OAuth token request failed: $($resp.StatusCode) $($resp.Body)")
                throw "OAuth token request failed (HTTP $($resp.StatusCode)): $($resp.Body)"
            }

            $tokenJson = ConvertFrom-BuzzJson $resp.Body
            $accessToken = Get-BuzzProp $tokenJson 'access_token'
            if ([string]::IsNullOrEmpty($accessToken)) { throw 'OAuth token response did not contain an access_token.' }
            $expiresIn = 3600
            $ei = Get-BuzzProp $tokenJson 'expires_in'
            if ($null -ne $ei) {
                $parsed = 0
                if ([int]::TryParse([string]$ei, [ref]$parsed) -and $parsed -gt 0) { $expiresIn = $parsed }
            }
            $this.Token = [string]$accessToken
            $this.TokenExpiryEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $expiresIn
            $this.Log('info', "OAuth token obtained, expires in ${expiresIn}s")
            return
        }
    }

    hidden [string] BuildClientAssertion() {
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $header = @{ alg = 'RS256'; kid = $this.OAuthKid; typ = 'JWT' }
        $payload = @{
            iss = $this.OAuthUserId
            sub = $this.OAuthUserId
            aud = $this.TokenEndpoint
            iat = $now
            exp = $now + 120
            jti = [guid]::NewGuid().ToString('N')
        }
        $headerB64 = ConvertTo-BuzzBase64Url ([System.Text.Encoding]::UTF8.GetBytes(($header | ConvertTo-Json -Compress)))
        $payloadB64 = ConvertTo-BuzzBase64Url ([System.Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress)))
        $signingInput = "$headerB64.$payloadB64"
        $sig = Get-BuzzRs256Signature -Rsa $this.PrivateKey -Data ([System.Text.Encoding]::ASCII.GetBytes($signingInput))
        return "$signingInput." + (ConvertTo-BuzzBase64Url $sig)
    }

    hidden [string] RequestWithRetry([string]$method, [string]$cmd, [hashtable]$params, [string]$content, [bool]$includeToken) {
        $url = "$($this.ServerUrl)/cmd"
        if ($cmd) { $url += "/$cmd" }
        if ($params -and $params.Count -gt 0) {
            $pairs = foreach ($k in $params.Keys) { "$([Uri]::EscapeDataString([string]$k))=$([Uri]::EscapeDataString([string]$params[$k]))" }
            $url += '?' + ($pairs -join '&')
        }
        # A [string] parameter coerces $null to '', so test for content by emptiness.
        $hasContent = -not [string]::IsNullOrEmpty($content)
        $headers = @{ 'User-Agent' = $this.UserAgent; 'Accept' = 'application/json' }
        if ($hasContent) { $headers['Content-Type'] = 'application/json' }
        # OAuth always authenticates via the Authorization: Bearer header.
        if ($includeToken -and $this.Token) { $headers['Authorization'] = "Bearer $($this.Token)" }

        $retriesRemaining = $script:RetriesToMake
        $baseWait = $script:InitialWaitMs
        while ($true) {
            $this.TraceRequest($url)
            if ($hasContent) {
                $resp = Invoke-BuzzHttp -Method $method -Url $url -Body $content -Headers $headers -TimeoutSec $this.TimeoutSec
            }
            else {
                $resp = Invoke-BuzzHttp -Method $method -Url $url -Headers $headers -TimeoutSec $this.TimeoutSec
            }

            if ($resp.TransportError) {
                if ($retriesRemaining -gt 0) {
                    Start-Sleep -Milliseconds (Get-BuzzWaitFromRetryHeader $null $baseWait)
                    $retriesRemaining--; $baseWait *= 2; continue
                }
                throw "Request to $url failed: $($resp.Error)"
            }
            if ($resp.StatusCode -eq 429 -or $resp.StatusCode -eq 503) {
                if ($retriesRemaining -gt 0) {
                    $wait = Get-BuzzWaitFromResponse $resp.Headers $baseWait
                    $this.Log('warn', "Request rate/time limited ($($resp.StatusCode)), backing off ${wait}ms, $retriesRemaining retries remaining")
                    Start-Sleep -Milliseconds $wait; $retriesRemaining--; $baseWait *= 2; continue
                }
                throw "Server returned $($resp.StatusCode) (rate/time limited). No retries remaining."
            }
            if ($resp.StatusCode -lt 200 -or $resp.StatusCode -ge 300) {
                if ($retriesRemaining -gt 0 -and (Test-BuzzStatusRetryable $resp.StatusCode)) {
                    Start-Sleep -Milliseconds (Get-BuzzWaitFromRetryHeader $resp.Headers['retry-after'] $baseWait)
                    $retriesRemaining--; $baseWait *= 2; continue
                }
                $target = if ($cmd) { $cmd } else { $url }
                throw "Request to $target failed: HTTP $($resp.StatusCode)"
            }
            return $resp.Body
        }
        return $null
    }

    hidden [void] TraceRequest([string]$url) {
        # Bodies are never logged: request bodies may contain credentials.
        $level = if ($this.VerboseLogging) { 'info' } else { 'debug' }
        $this.Log($level, 'Request: ' + (Get-BuzzRedactedUri $url '_token'))
    }

    hidden [void] TraceResponse([object]$node) {
        if ($null -eq $node) { $this.Log('debug', 'Response was empty or not JSON'); return }
        $text = (ConvertTo-BuzzRedacted $node) | ConvertTo-Json -Depth 10 -Compress
        if ($text.Length -gt 1000) { $text = $text.Substring(0, 1000) }
        $this.Log('debug', "Response: $text")
    }

    hidden [void] Log([string]$level, [string]$message) {
        if ($this.Logger) { & $this.Logger $level $message }
        elseif ($level -ne 'debug') { [Console]::Error.WriteLine("$($level.ToUpper()): $message") }
    }
}

# ── Factory functions (public API) ───────────────────────────────────────────────
function New-BuzzApiClient {
    [OutputType([BuzzApiClient])]
    param(
        [Parameter(Mandatory)][string]$ServerUrl,
        [Parameter(Mandatory)][string]$UserAgent,
        [Parameter(Mandatory)][string]$OAuthUserId,
        [Parameter(Mandatory)][string]$OAuthKid,
        [Parameter(Mandatory)][object]$PrivateKey,
        [bool]$VerboseLogging = $false,
        [int]$TimeoutSec = 600,
        [scriptblock]$Logger = $null
    )
    return [BuzzApiClient]::new($ServerUrl, $UserAgent, $OAuthUserId, $OAuthKid, $PrivateKey, $VerboseLogging, $TimeoutSec, $Logger)
}

function New-BuzzApiClientFromPem {
    [OutputType([BuzzApiClient])]
    param(
        [Parameter(Mandatory)][string]$ServerUrl,
        [Parameter(Mandatory)][string]$UserAgent,
        [Parameter(Mandatory)][string]$OAuthUserId,
        [Parameter(Mandatory)][string]$OAuthKid,
        [Parameter(Mandatory)][string]$PrivateKeyPath,
        [bool]$VerboseLogging = $false,
        [int]$TimeoutSec = 600,
        [scriptblock]$Logger = $null
    )
    $pem = Get-Content -Raw -LiteralPath $PrivateKeyPath
    $rsa = Import-BuzzRsaPrivateKey -Pem $pem
    return [BuzzApiClient]::new($ServerUrl, $UserAgent, $OAuthUserId, $OAuthKid, $rsa, $VerboseLogging, $TimeoutSec, $Logger)
}

Export-ModuleMember -Function New-BuzzApiClient, New-BuzzApiClientFromPem
