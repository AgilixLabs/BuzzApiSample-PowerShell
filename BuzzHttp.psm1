<#
    Low-level HTTP for the Buzz API sample.

    Uses System.Net.Http.HttpClient directly so behaviour (status codes, headers,
    transport errors) is identical on Windows PowerShell 5.1 (.NET Framework) and
    PowerShell 7+ (.NET 5+) — Invoke-WebRequest's error handling differs between them.
#>

Set-StrictMode -Version Latest

# On Windows PowerShell 5.1, System.Net.Http must be loaded, and modern TLS may not
# be enabled by default. Enable TLS 1.2 and (where the .NET Framework build supports
# it, e.g. 4.8) TLS 1.3 — some Buzz servers require TLS 1.3. PowerShell 7+ needs none
# of this (it negotiates modern TLS automatically).
if ($PSVersionTable.PSVersion.Major -lt 6) {
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    try {
        $sp = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if ([enum]::IsDefined([Net.SecurityProtocolType], 'Tls13')) {
            $sp = $sp -bor [Net.SecurityProtocolType]::Tls13
        }
        [Net.ServicePointManager]::SecurityProtocol = $sp
    }
    catch { }
}

# One shared HttpClient. Timeout is Infinite here; each call enforces its own
# timeout via a CancellationTokenSource.
$script:BuzzHttpClient = [System.Net.Http.HttpClient]::new()
$script:BuzzHttpClient.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan

function Invoke-BuzzHttp {
    <#
        Performs a single HTTP request.
        Returns [pscustomobject] with: StatusCode (int), Headers (hashtable, lower-cased),
        Body (string), TransportError (bool), Error (string).
    #>
    [CmdletBinding()]
    param(
        [string]$Method,
        [string]$Url,
        [string]$Body,
        [hashtable]$Headers,
        [int]$TimeoutSec = 600
    )

    $req = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::new($Method), $Url)

    $contentType = 'application/json'
    if ($Headers) {
        foreach ($k in $Headers.Keys) {
            if ($k -ieq 'Content-Type') {
                $contentType = [string]$Headers[$k]
            }
            else {
                [void]$req.Headers.TryAddWithoutValidation([string]$k, [string]$Headers[$k])
            }
        }
    }

    if (-not [string]::IsNullOrEmpty($Body)) {
        $content = [System.Net.Http.StringContent]::new($Body, [System.Text.Encoding]::UTF8, 'text/plain')
        $content.Headers.ContentType =
            [System.Net.Http.Headers.MediaTypeHeaderValue]::new($contentType)
        $req.Content = $content
    }

    $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSec))
    try {
        $resp = $script:BuzzHttpClient.SendAsync($req, $cts.Token).GetAwaiter().GetResult()
        $bodyStr = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()

        $hdrs = @{}
        foreach ($h in $resp.Headers) { $hdrs[$h.Key.ToLower()] = ($h.Value -join ',') }
        foreach ($h in $resp.Content.Headers) { $hdrs[$h.Key.ToLower()] = ($h.Value -join ',') }

        $result = [pscustomobject]@{
            StatusCode     = [int]$resp.StatusCode
            Headers        = $hdrs
            Body           = $bodyStr
            TransportError = $false
            Error          = $null
        }
        $resp.Dispose()
        return $result
    }
    catch {
        return [pscustomobject]@{
            StatusCode     = 0
            Headers        = @{}
            Body           = ''
            TransportError = $true
            Error          = $_.Exception.Message
        }
    }
    finally {
        $cts.Dispose()
        $req.Dispose()
    }
}

Export-ModuleMember -Function Invoke-BuzzHttp
