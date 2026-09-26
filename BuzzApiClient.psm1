<#
.SYNOPSIS
    Reusable client for the Buzz API, authenticating with OAuth 2.0 JWT client
    credentials (RFC 6749 + RFC 7523).

.DESCRIPTION
    The client obtains and refreshes Bearer access tokens automatically, retries
    transient failures with exponential backoff, and handles throttling and backend
    pressure (HTTP 429/503 or a throttle code in the response envelope).

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
# The longest server-directed wait (Retry-After / X-RateLimit-Reset) the client will sit out before
# retrying. Rate-limit windows are five minutes and the server adds jitter, so several minutes is
# normal. Retrying before the server says to only burns quota, so a longer wait fails the request.
$script:MaxServerDirectedWaitMs = 600000
$script:TokenRefreshMarginSec = 300
$script:SensitiveFields = @('token', 'access_token', 'refresh_token', 'password', 'client_assertion', 'client_secret')
$script:NoRetryStatus = @(400, 401, 402, 403, 404, 405, 406, 407, 409, 410, 411, 412, 413, 414, 415, 416,
    417, 421, 422, 424, 426, 428, 431, 451, 501, 505, 506, 508, 510, 511)
# Envelope codes that mean "slow down and retry later" (compared case-insensitively). Throttles are
# usually reported with HTTP 200, so the envelope code is checked even when the HTTP status is a success.
# "TooManyRequests" is what every throttle collapses to when the server reports throttles generically;
# "Service Unavailable" is the code written when the server sheds load before a request is authenticated.
$script:ThrottleCodes = @('TooManyRequests', 'RetryLater', 'LimitExceeded', 'RateLimit', 'TimeLimit',
    'ServerOverwhelmed', 'BackendPressure', 'Service Unavailable', 'ServiceUnavailable')

# Thrown when the server throttles a request (rate limit, time limit, or backend pressure) and the
# client has run out of retries, or when items in a batch or multi-object request were throttled.
# It is a real .NET type (not a PowerShell class) so callers can `catch [BuzzApiThrottledException]`
# after a plain Import-Module. It derives from RuntimeException, the type of this module's other
# errors, so existing catch blocks still catch it. StatusCode is 429 or 503 even when the server
# wrapped the throttle in HTTP 200.
if (-not ('BuzzApiThrottledException' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Management.Automation;

public class BuzzApiThrottledException : RuntimeException
{
    // The envelope throttle code (e.g. "TimeLimit", "BackendPressure"), or the OAuth error code. Null if none was sent.
    public string Code { get; private set; }

    // How long the server asked the client to wait (Retry-After or X-RateLimit-Reset), if it said.
    public Nullable<TimeSpan> RetryAfter { get; private set; }

    // 429 or 503: the real HTTP status, or the status the envelope code stands for.
    public int StatusCode { get; private set; }

    // For batch and multi-object requests, the indexes of the throttled items to resubmit. Empty when the whole request was throttled.
    public int[] ThrottledItemIndexes { get; private set; }

    // The full response envelope, including the results of any items that were not throttled.
    public object Response { get; private set; }

    public BuzzApiThrottledException(string message, string code, object response, int[] throttledItemIndexes,
        Nullable<TimeSpan> retryAfter, int statusCode)
        : base(message)
    {
        Code = code;
        Response = response;
        ThrottledItemIndexes = throttledItemIndexes ?? new int[0];
        RetryAfter = retryAfter;
        StatusCode = statusCode;
    }
}
'@
}

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

function ConvertFrom-BuzzEnvelope {
    <#
        Parses a response body as the XML or JSON envelope. The server returns XML unless JSON is
        requested, and some error paths may ignore the Accept header, so XML is converted to the same
        shape ConvertFrom-Json gives: attributes and child elements become properties, repeated elements
        become arrays, and text content becomes '$value'. Returns $null for an empty body.
        Throws a FormatException for an unparseable body, or returns $null with -Lenient (for example,
        an HTML error page from a proxy).
    #>
    param([string]$Text, [string]$ContentType, [switch]$Lenient)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $isXml = ($ContentType -match 'xml') -or $Text.TrimStart().StartsWith('<')
    try {
        if (-not $isXml) { return ($Text | ConvertFrom-Json -ErrorAction Stop) }
        $settings = New-Object System.Xml.XmlReaderSettings
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $reader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader $Text), $settings)
        $doc = New-Object System.Xml.XmlDocument
        try { $doc.Load($reader) } finally { $reader.Dispose() }
        # get_* accessors avoid PowerShell's XML adapter, which exposes child elements as properties.
        $root = $doc.get_DocumentElement()
        if ($null -eq $root) { throw 'XML response has no root element.' }
        $envelope = [ordered]@{}
        $envelope[$root.get_LocalName()] = ConvertFrom-BuzzXmlElement $root
        return [pscustomobject]$envelope
    }
    catch {
        if ($Lenient) { return $null }
        throw [System.FormatException]::new("Could not parse the response body: $($_.Exception.Message)", $_.Exception)
    }
}

function ConvertFrom-BuzzXmlElement {
    param([System.Xml.XmlElement]$Element)
    $obj = [ordered]@{}
    foreach ($attr in $Element.get_Attributes()) {
        if ($attr.get_Name() -eq 'xmlns' -or $attr.get_Prefix() -eq 'xmlns') { continue }
        $obj[$attr.get_LocalName()] = $attr.get_Value()
    }
    $groups = [ordered]@{}
    $text = ''
    foreach ($node in $Element.get_ChildNodes()) {
        if ($node -is [System.Xml.XmlElement]) {
            $name = $node.get_LocalName()
            if (-not $groups.Contains($name)) { $groups[$name] = New-Object System.Collections.Generic.List[object] }
            $groups[$name].Add((ConvertFrom-BuzzXmlElement $node))
        }
        elseif ($node -is [System.Xml.XmlText] -or $node -is [System.Xml.XmlCDataSection]) { $text += $node.get_Value() }
    }
    foreach ($name in $groups.Keys) {
        $children = $groups[$name]
        if ($children.Count -eq 1) { $obj[$name] = $children[0] } else { $obj[$name] = $children.ToArray() }
    }
    if (-not [string]::IsNullOrWhiteSpace($text)) { $obj['$value'] = $text }
    return [pscustomobject]$obj
}

function Test-BuzzThrottleCode {
    param($Code)
    return ($null -ne $Code) -and ($script:ThrottleCodes -contains [string]$Code)
}

function Get-BuzzThrottleStatus {
    # The HTTP status to report for a throttle: the real one when the server sent 429/503, otherwise
    # the status the envelope code stands for (the server wraps these in HTTP 200 for legacy clients).
    param([int]$StatusCode, $Code)
    if ($StatusCode -eq 429 -or $StatusCode -eq 503) { return $StatusCode }
    if (@('ServerOverwhelmed', 'BackendPressure', 'Service Unavailable', 'ServiceUnavailable') -contains [string]$Code) { return 503 }
    return 429
}

function Get-BuzzChildResponses {
    # The per-item results of a batch or multi-object command (responses.response). JSON gives an
    # array; a single item converted from XML is an object. Callers wrap the output in @().
    param($Node)
    $items = Get-BuzzProp (Get-BuzzProp $Node 'responses') 'response'
    if ($items -is [array] -or $items -is [System.Management.Automation.PSCustomObject]) { return $items }
}

function Get-BuzzThrottledItemCount {
    # Counts throttled items at any depth, since a batch item can itself be a multi-object command with per-row results.
    param($Node)
    $count = 0
    foreach ($item in @(Get-BuzzChildResponses $Node)) {
        if (Test-BuzzThrottleCode (Get-BuzzProp $item 'code')) { $count++ }
        $count += Get-BuzzThrottledItemCount $item
    }
    return $count
}

function New-BuzzThrottledException {
    # A function rather than [BuzzApiThrottledException]::new() in the class, because class bodies
    # resolve type literals when the module is parsed, before Add-Type has run.
    param([string]$Message, $Code, $Response, [int[]]$ThrottledItemIndexes = @(), $RetryAfterMs = $null, [int]$StatusCode)
    $retryAfter = $null
    if ($null -ne $RetryAfterMs) { $retryAfter = [TimeSpan]::FromMilliseconds($RetryAfterMs) }
    $codeText = $null
    if ($null -ne $Code) { $codeText = [string]$Code }
    return ('BuzzApiThrottledException' -as [type])::new($Message, $codeText, $Response, $ThrottledItemIndexes, $retryAfter, $StatusCode)
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

function Get-BuzzServerDirectedWaitMs {
    # The wait the server asked for: Retry-After (delta-seconds or HTTP date) first, then
    # X-RateLimit-Reset, which Buzz sends as seconds until the rate-limit window resets (not a Unix
    # time). Sent on throttled responses whether the HTTP status is 200 or 429/503. $null if none.
    param([hashtable]$Headers)
    $ms = Get-BuzzRetryAfterMs $Headers['retry-after']
    if ($null -ne $ms -and $ms -gt 0) { return [long]$ms }
    $reset = $Headers['x-ratelimit-reset']
    if ($reset -and ($reset -match '^\d+$') -and [long]$reset -gt 0) { return [long]$reset * 1000 }
    return $null
}

function Get-BuzzThrottleWaitMs {
    # How long to back off from a throttle: the server-directed wait if there is one (never less than
    # the current exponential base), otherwise exponential backoff with jitter. A server-directed wait
    # is not capped here; the caller compares it with MaxServerDirectedWaitMs rather than retrying early.
    param($ServerWaitMs, [long]$BaseMs)
    if ($null -ne $ServerWaitMs) { return [long][Math]::Max([long]$ServerWaitMs, $BaseMs) }
    return [long][Math]::Min($script:MaxRetryWaitMs, $BaseMs + (Get-BuzzJitterMs))
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
    # UTC ticks before which no request from this client should be sent. Set whenever the server
    # signals throttling or backend pressure, so every request sharing this client backs off together
    # instead of each discovering the throttle separately. Guarded by ThrottleLock so the window only
    # ever moves forward, even if the client is used from more than one thread or runspace.
    hidden [long]$ThrottledUntilTicks
    hidden [object]$ThrottleLock

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
        $this.ThrottledUntilTicks = 0
        $this.ThrottleLock = New-Object object
    }

    [object] JsonRequest([string]$method, [string]$cmd, [hashtable]$params, [object]$jsonBody, [bool]$includeToken) {
        if ($includeToken) { $this.EnsureToken() }

        $content = $null
        if ($null -ne $jsonBody) { $content = ($jsonBody | ConvertTo-Json -Depth 10 -Compress) }

        $result = $this.RequestWithRetry($method, $cmd, $params, $content, $includeToken)
        $node = $result.Envelope
        $this.TraceResponse($node)

        # If the token expired or was revoked, re-authenticate and retry once. REST-style endpoints
        # report this as HTTP 401, possibly with no envelope; commands report code "NoAuthentication".
        $authRejected = ($result.StatusCode -eq 401) -or ((Get-BuzzResponseCode $node) -eq 'NoAuthentication')
        if ($includeToken -and $this.Token -and $authRejected) {
            $this.Log('debug', 'Re-authenticating because the request returned code "NoAuthentication"')
            $this.AuthenticateOAuth()
            $result = $this.RequestWithRetry($method, $cmd, $params, $content, $includeToken)
            $node = $result.Envelope
            $this.TraceResponse($node)
        }
        if ($result.StatusCode -eq 401) { throw "Request to $($result.Target) failed: HTTP 401" }
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

        $code = Get-BuzzProp $toVerify 'code'
        if ($code -ne 'OK') {
            $redacted = (ConvertTo-BuzzRedacted $responseJson) | ConvertTo-Json -Depth 10 -Compress
            $this.Log('error', "Buzz API call failed. Expected response.code to be OK, found: $redacted")
            if (Test-BuzzThrottleCode $code) {
                throw (New-BuzzThrottledException -Message "Buzz API call was throttled ($code): $redacted" -Code $code `
                        -Response $responseJson -StatusCode (Get-BuzzThrottleStatus 200 $code))
            }
            throw "Buzz API call failed. Expected response.code to be OK, found: $redacted"
        }

        if ($checkChildResponses) {
            $responses = @(Get-BuzzChildResponses $toVerify)

            # Batch and multi-object commands report per-item throttles under an outer OK. Report them
            # together so the caller can resubmit just those items. Throttled batch items were rejected
            # without running; a multi-object row that hit BackendPressure (e.g. a database timeout)
            # may have partially run.
            $throttledIndexes = @()
            for ($i = 0; $i -lt $responses.Count; $i++) {
                if (Test-BuzzThrottleCode (Get-BuzzProp $responses[$i] 'code')) { $throttledIndexes += $i }
            }
            if ($throttledIndexes.Count -gt 0) {
                $firstCode = Get-BuzzProp $responses[$throttledIndexes[0]] 'code'
                $indexList = $throttledIndexes -join ','
                $this.Log('warn', "$($throttledIndexes.Count) of $($responses.Count) items were throttled ($firstCode); resubmit items $indexList")
                throw (New-BuzzThrottledException `
                        -Message "$($throttledIndexes.Count) of $($responses.Count) items were throttled ($firstCode). Resubmit the items at indexes $indexList." `
                        -Code $firstCode -Response $responseJson -ThrottledItemIndexes $throttledIndexes `
                        -StatusCode (Get-BuzzThrottleStatus 200 $firstCode))
            }

            foreach ($item in $responses) { $this.VerifyResponse($item, $true) }
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
            # Wait out any throttle window first, then build a fresh assertion on every attempt:
            # JWTs expire in 2 minutes and a throttle wait can be up to 10, so an assertion built
            # before the wait (or reused) could be past its exp claim.
            $this.WaitForThrottleWindow()
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
            if ($resp.StatusCode -lt 200 -or $resp.StatusCode -ge 300) {
                # The token endpoint answers with RFC 6749 errors rather than the DLAP envelope:
                # rate limits and backend pressure are 429/503 with error "temporarily_unavailable" and Retry-After.
                $oauthError = Get-BuzzProp (ConvertFrom-BuzzEnvelope $resp.Body $resp.Headers['content-type'] -Lenient) 'error'
                if ($resp.StatusCode -eq 429 -or $resp.StatusCode -eq 503 -or $oauthError -eq 'temporarily_unavailable') {
                    $serverWait = Get-BuzzServerDirectedWaitMs $resp.Headers
                    $wait = Get-BuzzThrottleWaitMs $serverWait $baseWait
                    if ($retriesRemaining -gt 0 -and $wait -le $script:MaxServerDirectedWaitMs) {
                        $this.Log('warn', "OAuth token request throttled ($($resp.StatusCode), $oauthError), backing off ${wait}ms, $retriesRemaining retries remaining")
                        $this.ExtendThrottleWindow($wait)
                        $retriesRemaining--; $baseWait *= 2
                        continue    # the throttle window is awaited at the top of the loop
                    }
                    $this.ExtendThrottleWindow([Math]::Min($wait, $script:MaxServerDirectedWaitMs))
                    throw (New-BuzzThrottledException -Message "OAuth token request was throttled (HTTP $($resp.StatusCode)): $($resp.Body)" `
                            -Code $oauthError -Response $null -RetryAfterMs $serverWait -StatusCode (Get-BuzzThrottleStatus $resp.StatusCode $null))
                }
                if ($retriesRemaining -gt 0 -and (Test-BuzzStatusRetryable $resp.StatusCode)) {
                    Start-Sleep -Milliseconds (Get-BuzzWaitFromRetryHeader $resp.Headers['retry-after'] $baseWait)
                    $retriesRemaining--; $baseWait *= 2; continue
                }
                $this.Log('error', "OAuth token request failed: $($resp.StatusCode) $($resp.Body)")
                throw "OAuth token request failed (HTTP $($resp.StatusCode)): $($resp.Body)"
            }

            # Unlike a command, a token request is safe to resend, so a garbled token response is retried.
            $tokenJson = ConvertFrom-BuzzEnvelope $resp.Body $resp.Headers['content-type'] -Lenient
            $accessToken = Get-BuzzProp $tokenJson 'access_token'
            if ([string]::IsNullOrEmpty($accessToken)) {
                if ($retriesRemaining -gt 0) {
                    $this.Log('debug', 'OAuth token response did not contain an access_token; retrying')
                    Start-Sleep -Milliseconds (Get-BuzzWaitFromRetryHeader $null $baseWait)
                    $retriesRemaining--; $baseWait *= 2; continue
                }
                throw 'OAuth token response did not contain an access_token.'
            }
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

    # Sends a request, retrying transient failures, and returns [pscustomobject] with StatusCode,
    # Envelope (the parsed XML or JSON body, normalized to the ConvertFrom-Json shape) and Target.
    # Throttling is recognized from the HTTP status (429/503) or from the envelope code, since the
    # server usually reports throttles as HTTP 200 with a code like "TimeLimit" or "BackendPressure".
    hidden [object] RequestWithRetry([string]$method, [string]$cmd, [hashtable]$params, [string]$content, [bool]$includeToken) {
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
        $target = if ($cmd) { $cmd } else { $url }
        while ($true) {
            $this.WaitForThrottleWindow()
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

            # Parse strictly on success: a garbled success body is an error, and it is not retried because
            # the server already ran the command (resending a mutation or a batch could repeat it).
            # On failure the envelope is optional (for example, an HTML error page from a proxy).
            $isSuccess = $resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300
            $envelope = ConvertFrom-BuzzEnvelope $resp.Body $resp.Headers['content-type'] -Lenient:(-not $isSuccess)
            $code = Get-BuzzResponseCode $envelope

            # Time/rate limiting and backend pressure: HTTP 429/503 (REST-style), or an envelope throttle
            # code (usually with HTTP 200). Retry-After is sent either way; X-RateLimit-Reset is the fallback.
            if ($resp.StatusCode -eq 429 -or $resp.StatusCode -eq 503 -or (Test-BuzzThrottleCode $code)) {
                $serverWait = Get-BuzzServerDirectedWaitMs $resp.Headers
                $wait = Get-BuzzThrottleWaitMs $serverWait $baseWait
                $message = Get-BuzzProp (Get-BuzzProp $envelope 'response') 'message'
                if ($retriesRemaining -gt 0 -and $wait -le $script:MaxServerDirectedWaitMs) {
                    $this.Log('warn', ("Request throttled. StatusCode: {0}, Code: {1}, Message: {2}, Pressure: {3} {4}, backing off for {5} milliseconds, retries remaining: {6}" -f
                            $resp.StatusCode, $code, $message, $resp.Headers['x-backend-pressure-service'], $resp.Headers['x-backend-pressure-level'], $wait, $retriesRemaining))
                    $this.ExtendThrottleWindow($wait)
                    $retriesRemaining--; $baseWait *= 2
                    continue    # the throttle window is awaited at the top of the loop
                }
                $this.ExtendThrottleWindow([Math]::Min($wait, $script:MaxServerDirectedWaitMs))
                $reason = if ($retriesRemaining -gt 0) {
                    "server asked to wait $([long][Math]::Floor($wait / 1000))s, longer than the $($script:MaxServerDirectedWaitMs / 1000)s limit"
                }
                else { 'no retries remaining' }
                $codeText = if ($code) { $code } else { 'none' }
                throw (New-BuzzThrottledException -Message "Buzz API request was throttled (HTTP $($resp.StatusCode), code $codeText): $message ($reason)" `
                        -Code $code -Response $envelope -RetryAfterMs $serverWait -StatusCode (Get-BuzzThrottleStatus $resp.StatusCode $code))
            }

            if ($isSuccess) {
                $this.ExtendThrottleWindowForThrottledItems($envelope, $resp.Headers)
                return [pscustomobject]@{ StatusCode = $resp.StatusCode; Envelope = $envelope; Target = $target }
            }

            # 401 is returned so JsonRequest re-authenticates, whether or not an envelope came with it.
            # A REST-style error status with an envelope (e.g. 400 BadRequest, 404 ResourceNotFound) is
            # returned so the caller sees the server's code and message, just as it would for the same
            # error wrapped in HTTP 200.
            if ($resp.StatusCode -eq 401 -or ($code -and -not (Test-BuzzStatusRetryable $resp.StatusCode))) {
                return [pscustomobject]@{ StatusCode = $resp.StatusCode; Envelope = $envelope; Target = $target }
            }
            if ($retriesRemaining -gt 0 -and (Test-BuzzStatusRetryable $resp.StatusCode)) {
                Start-Sleep -Milliseconds (Get-BuzzWaitFromRetryHeader $resp.Headers['retry-after'] $baseWait)
                $retriesRemaining--; $baseWait *= 2; continue
            }
            $codeSuffix = if ($code) { " (code $code)" } else { '' }
            throw "Request to $target failed: HTTP $($resp.StatusCode)$codeSuffix"
        }
        return $null
    }

    # Backs off the whole client when a successful batch or multi-object response contains throttled
    # items, so resubmitting them (and any other request on this client) waits as the server asked.
    hidden [void] ExtendThrottleWindowForThrottledItems([object]$envelope, [hashtable]$headers) {
        $node = $envelope
        $inner = Get-BuzzProp $envelope 'response'
        if ($inner -is [System.Management.Automation.PSCustomObject]) { $node = $inner }
        $throttled = Get-BuzzThrottledItemCount $node
        if ($throttled -eq 0) { return }
        $wait = [Math]::Min((Get-BuzzThrottleWaitMs (Get-BuzzServerDirectedWaitMs $headers) $script:InitialWaitMs), $script:MaxServerDirectedWaitMs)
        $this.Log('warn', "$throttled items in the response were throttled; backing off for $wait milliseconds before the next request")
        $this.ExtendThrottleWindow($wait)
    }

    # Moves the client-wide throttle window out to at least waitMs from now (never backward).
    hidden [void] ExtendThrottleWindow([long]$waitMs) {
        $until = [DateTime]::UtcNow.Ticks + $waitMs * [TimeSpan]::TicksPerMillisecond
        [System.Threading.Monitor]::Enter($this.ThrottleLock)
        try { if ($until -gt $this.ThrottledUntilTicks) { $this.ThrottledUntilTicks = $until } }
        finally { [System.Threading.Monitor]::Exit($this.ThrottleLock) }
    }

    # Waits until the client-wide throttle window has passed.
    hidden [void] WaitForThrottleWindow() {
        while ($true) {
            [long]$remainingTicks = 0
            [System.Threading.Monitor]::Enter($this.ThrottleLock)
            try { $remainingTicks = $this.ThrottledUntilTicks - [DateTime]::UtcNow.Ticks }
            finally { [System.Threading.Monitor]::Exit($this.ThrottleLock) }
            if ($remainingTicks -le 0) { return }
            $waitMs = [int][Math]::Ceiling($remainingTicks / [TimeSpan]::TicksPerMillisecond)
            $this.Log('debug', "Waiting $waitMs milliseconds for the server's throttle window to pass")
            Start-Sleep -Milliseconds $waitMs
        }
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
