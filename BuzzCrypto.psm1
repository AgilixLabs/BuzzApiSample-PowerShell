<#
.SYNOPSIS
    RSA key helpers for the Buzz API sample — PEM key generation, import, and RS256 signing.

.DESCRIPTION
    Works on both Windows PowerShell 5.1 (.NET Framework) and PowerShell 7+ (.NET 5+).

    PowerShell 7+ has native PEM support (RSA.ImportFromPem / ExportPkcs8PrivateKey /
    ExportSubjectPublicKeyInfo). Windows PowerShell 5.1 runs on .NET Framework, which lacks
    those APIs, so this module encodes/decodes the PKCS#8 (private) and SubjectPublicKeyInfo
    (public) DER structures itself, using only built-in .NET types. No external dependencies.

    Everything is exposed through four functions so callers never see the version difference:
      New-BuzzRsaKey, Export-BuzzPrivateKeyPem, Export-BuzzPublicKeyPem,
      Import-BuzzRsaPrivateKey, Get-BuzzRs256Signature
#>

Set-StrictMode -Version Latest

$script:IsPS7 = $PSVersionTable.PSVersion.Major -ge 6

# rsaEncryption AlgorithmIdentifier: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
$script:RsaAlgId = [byte[]](0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00)

# ── DER encoding helpers ────────────────────────────────────────────────────────
function ConvertTo-DerLength {
    param([int]$Length)
    $out = [System.Collections.Generic.List[byte]]::new()
    if ($Length -lt 128) {
        $out.Add([byte]$Length)
    }
    else {
        $tmp = [System.Collections.Generic.List[byte]]::new()
        $n = $Length
        while ($n -gt 0) { $tmp.Insert(0, [byte]($n -band 0xFF)); $n = $n -shr 8 }
        $out.Add([byte](0x80 -bor $tmp.Count))
        $out.AddRange($tmp)
    }
    return , $out.ToArray()
}

function ConvertTo-DerTlv {
    param([byte]$Tag, [byte[]]$Value)
    $out = [System.Collections.Generic.List[byte]]::new()
    $out.Add($Tag)
    $out.AddRange([byte[]](ConvertTo-DerLength -Length $Value.Length))
    if ($Value.Length -gt 0) { $out.AddRange($Value) }
    return , $out.ToArray()
}

# Encode an unsigned big-endian magnitude as a DER INTEGER (adds a 0x00 sign byte if needed).
function ConvertTo-DerInteger {
    param([byte[]]$Magnitude)
    $start = 0
    while ($start -lt ($Magnitude.Length - 1) -and $Magnitude[$start] -eq 0) { $start++ }
    $m = [System.Collections.Generic.List[byte]]::new()
    for ($i = $start; $i -lt $Magnitude.Length; $i++) { $m.Add($Magnitude[$i]) }
    if ($m.Count -eq 0) { $m.Add([byte]0) }
    if (($m[0] -band 0x80) -ne 0) { $m.Insert(0, [byte]0) }
    return , (ConvertTo-DerTlv -Tag 0x02 -Value $m.ToArray())
}

function ConvertTo-DerSequence {
    param([byte[]]$Content)
    return , (ConvertTo-DerTlv -Tag 0x30 -Value $Content)
}

function Join-Bytes {
    param([System.Object[]]$Arrays)
    $out = [System.Collections.Generic.List[byte]]::new()
    foreach ($a in $Arrays) { if ($null -ne $a -and $a.Length -gt 0) { $out.AddRange([byte[]]$a) } }
    return , $out.ToArray()
}

# ── DER decoding (minimal cursor-based reader) ──────────────────────────────────
function Read-DerTlv {
    param([byte[]]$Der, [ref]$Pos)
    $tag = $Der[$Pos.Value]; $Pos.Value++
    $len = [int]$Der[$Pos.Value]; $Pos.Value++
    if ($len -ge 0x80) {
        $numBytes = $len -band 0x7F
        $len = 0
        for ($i = 0; $i -lt $numBytes; $i++) { $len = ($len -shl 8) -bor $Der[$Pos.Value]; $Pos.Value++ }
    }
    $val = New-Object byte[] $len
    if ($len -gt 0) { [Array]::Copy($Der, $Pos.Value, $val, 0, $len) }
    $Pos.Value += $len
    return [PSCustomObject]@{ Tag = $tag; Value = $val }
}

function Remove-DerSignByte {
    param([byte[]]$Bytes)
    if ($Bytes.Length -gt 1 -and $Bytes[0] -eq 0) {
        $out = New-Object byte[] ($Bytes.Length - 1)
        [Array]::Copy($Bytes, 1, $out, 0, $out.Length)
        return , $out
    }
    return , $Bytes
}

function Set-BytesLeftPad {
    param([byte[]]$Bytes, [int]$Length)
    if ($Bytes.Length -eq $Length) { return , $Bytes }
    $out = New-Object byte[] $Length
    if ($Bytes.Length -le $Length) {
        [Array]::Copy($Bytes, 0, $out, $Length - $Bytes.Length, $Bytes.Length)
    }
    else {
        [Array]::Copy($Bytes, $Bytes.Length - $Length, $out, 0, $Length)
    }
    return , $out
}

# ── PEM wrapping ────────────────────────────────────────────────────────────────
function ConvertTo-Pem {
    param([string]$Label, [byte[]]$Der)
    $b64 = [Convert]::ToBase64String($Der)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("-----BEGIN $Label-----")
    for ($i = 0; $i -lt $b64.Length; $i += 64) {
        $len = [Math]::Min(64, $b64.Length - $i)
        [void]$sb.AppendLine($b64.Substring($i, $len))
    }
    [void]$sb.AppendLine("-----END $Label-----")
    return $sb.ToString()
}

function ConvertFrom-Pem {
    param([string]$Pem)
    $lines = $Pem -split "`r?`n" | Where-Object { $_ -and $_ -notmatch '-----' }
    $b64 = ($lines -join '') -replace '\s', ''
    return , [Convert]::FromBase64String($b64)
}

# ── RSAParameters <-> DER ────────────────────────────────────────────────────────
function Export-BuzzPkcs8Der {
    param([System.Security.Cryptography.RSAParameters]$P)
    $version = [byte[]](ConvertTo-DerInteger -Magnitude ([byte[]](0)))
    $rsaPriv = [byte[]](ConvertTo-DerSequence -Content ([byte[]](Join-Bytes @(
                    $version,
                    [byte[]](ConvertTo-DerInteger -Magnitude $P.Modulus),
                    [byte[]](ConvertTo-DerInteger -Magnitude $P.Exponent),
                    [byte[]](ConvertTo-DerInteger -Magnitude $P.D),
                    [byte[]](ConvertTo-DerInteger -Magnitude $P.P),
                    [byte[]](ConvertTo-DerInteger -Magnitude $P.Q),
                    [byte[]](ConvertTo-DerInteger -Magnitude $P.DP),
                    [byte[]](ConvertTo-DerInteger -Magnitude $P.DQ),
                    [byte[]](ConvertTo-DerInteger -Magnitude $P.InverseQ)
                ))))
    $octet = [byte[]](ConvertTo-DerTlv -Tag 0x04 -Value $rsaPriv)
    $pkcs8 = [byte[]](ConvertTo-DerSequence -Content ([byte[]](Join-Bytes @($version, $script:RsaAlgId, $octet))))
    return , $pkcs8
}

function Export-BuzzSpkiDer {
    param([System.Security.Cryptography.RSAParameters]$P)
    $rsaPub = [byte[]](ConvertTo-DerSequence -Content ([byte[]](Join-Bytes @(
                    [byte[]](ConvertTo-DerInteger -Magnitude $P.Modulus),
                    [byte[]](ConvertTo-DerInteger -Magnitude $P.Exponent)
                ))))
    $bitStr = [byte[]](ConvertTo-DerTlv -Tag 0x03 -Value ([byte[]](Join-Bytes @([byte[]](0), $rsaPub))))
    $spki = [byte[]](ConvertTo-DerSequence -Content ([byte[]](Join-Bytes @($script:RsaAlgId, $bitStr))))
    return , $spki
}

# Parse a PKCS#8 (or PKCS#1) private key DER into RSAParameters.
function Import-BuzzRsaParameters {
    param([byte[]]$Der, [bool]$IsPkcs1)
    $pos = 0
    if ($IsPkcs1) {
        $rsaPrivDer = $Der
    }
    else {
        $outer = Read-DerTlv -Der $Der -Pos ([ref]$pos)      # PrivateKeyInfo SEQUENCE
        $ip = 0
        [void](Read-DerTlv -Der $outer.Value -Pos ([ref]$ip))  # version INTEGER
        [void](Read-DerTlv -Der $outer.Value -Pos ([ref]$ip))  # algorithm SEQUENCE
        $pk = Read-DerTlv -Der $outer.Value -Pos ([ref]$ip)    # privateKey OCTET STRING
        $rsaPrivDer = $pk.Value
    }
    $sp = 0
    $seq = Read-DerTlv -Der $rsaPrivDer -Pos ([ref]$sp)        # RSAPrivateKey SEQUENCE
    $cp = 0
    $c = $seq.Value
    [void](Read-DerTlv -Der $c -Pos ([ref]$cp))               # version
    $n = (Read-DerTlv -Der $c -Pos ([ref]$cp)).Value
    $e = (Read-DerTlv -Der $c -Pos ([ref]$cp)).Value
    $d = (Read-DerTlv -Der $c -Pos ([ref]$cp)).Value
    $p = (Read-DerTlv -Der $c -Pos ([ref]$cp)).Value
    $q = (Read-DerTlv -Der $c -Pos ([ref]$cp)).Value
    $dp = (Read-DerTlv -Der $c -Pos ([ref]$cp)).Value
    $dq = (Read-DerTlv -Der $c -Pos ([ref]$cp)).Value
    $qi = (Read-DerTlv -Der $c -Pos ([ref]$cp)).Value

    $modulus = [byte[]](Remove-DerSignByte -Bytes $n)
    $modLen = $modulus.Length
    $half = [int]($modLen / 2)

    $params = New-Object System.Security.Cryptography.RSAParameters
    $params.Modulus = $modulus
    $params.Exponent = [byte[]](Remove-DerSignByte -Bytes $e)
    $params.D = [byte[]](Set-BytesLeftPad -Bytes ([byte[]](Remove-DerSignByte -Bytes $d)) -Length $modLen)
    $params.P = [byte[]](Set-BytesLeftPad -Bytes ([byte[]](Remove-DerSignByte -Bytes $p)) -Length $half)
    $params.Q = [byte[]](Set-BytesLeftPad -Bytes ([byte[]](Remove-DerSignByte -Bytes $q)) -Length $half)
    $params.DP = [byte[]](Set-BytesLeftPad -Bytes ([byte[]](Remove-DerSignByte -Bytes $dp)) -Length $half)
    $params.DQ = [byte[]](Set-BytesLeftPad -Bytes ([byte[]](Remove-DerSignByte -Bytes $dq)) -Length $half)
    $params.InverseQ = [byte[]](Set-BytesLeftPad -Bytes ([byte[]](Remove-DerSignByte -Bytes $qi)) -Length $half)
    return $params
}

# ── Version-aware RSA object ─────────────────────────────────────────────────────
function New-RsaObject {
    # RSACng signs SHA-256 reliably on .NET Framework; RSA.Create() is fine on .NET 5+.
    if ($script:IsPS7) {
        return [System.Security.Cryptography.RSA]::Create()
    }
    return [System.Security.Cryptography.RSACng]::new()
}

# ── Public API ────────────────────────────────────────────────────────────────
function New-BuzzRsaKey {
    [OutputType([System.Security.Cryptography.RSA])]
    param([int]$Bits = 2048)
    if ($Bits -lt 2048) { throw "Key size must be at least 2048 bits (Buzz minimum)." }
    if ($script:IsPS7) {
        return [System.Security.Cryptography.RSA]::Create($Bits)
    }
    return [System.Security.Cryptography.RSACng]::new($Bits)
}

function Export-BuzzPrivateKeyPem {
    [OutputType([string])]
    param([System.Security.Cryptography.RSA]$Rsa)
    $p = $Rsa.ExportParameters($true)
    return ConvertTo-Pem -Label 'PRIVATE KEY' -Der ([byte[]](Export-BuzzPkcs8Der -P $p))
}

function Export-BuzzPublicKeyPem {
    [OutputType([string])]
    param([System.Security.Cryptography.RSA]$Rsa)
    $p = $Rsa.ExportParameters($false)
    return ConvertTo-Pem -Label 'PUBLIC KEY' -Der ([byte[]](Export-BuzzSpkiDer -P $p))
}

function Import-BuzzRsaPrivateKey {
    [OutputType([System.Security.Cryptography.RSA])]
    param([string]$Pem)
    $isPkcs1 = $Pem -match 'BEGIN RSA PRIVATE KEY'
    $der = [byte[]](ConvertFrom-Pem -Pem $Pem)
    $params = Import-BuzzRsaParameters -Der $der -IsPkcs1 $isPkcs1
    $rsa = New-RsaObject
    $rsa.ImportParameters($params)
    return $rsa
}

function Get-BuzzRs256Signature {
    [OutputType([byte[]])]
    param([System.Security.Cryptography.RSA]$Rsa, [byte[]]$Data)
    return , $Rsa.SignData($Data,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
}

Export-ModuleMember -Function New-BuzzRsaKey, Export-BuzzPrivateKeyPem, Export-BuzzPublicKeyPem,
Import-BuzzRsaPrivateKey, Get-BuzzRs256Signature
