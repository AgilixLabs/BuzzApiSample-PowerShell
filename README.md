# BuzzApiSample-PowerShell

A PowerShell sample and reusable client for the Buzz API. The client handles OAuth 2.0
authentication, automatic token refresh, exponential backoff, and rate-limit compliance so your
integration code can focus on business logic.

Runs on **Windows PowerShell 5.1** (stock on every supported Windows) and **PowerShell 7+**
(cross-platform). Uses only built-in .NET types — **no external modules or dependencies**.

## Authentication

The only authentication method supported by the client is **OAuth 2.0 JWT Client Credentials**
([RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) +
[RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)).
An RSA private key signs a short-lived JWT assertion; Buzz verifies the signature against the
registered public key and returns a Bearer access token valid for one hour. The private key
never leaves your system — there is no shared secret to intercept.

> The legacy username/password (`login3`) flow is **not** used by new integrations and is not
> part of the client. It appears only inside the setup/cleanup scripts, where an administrator
> must briefly authenticate to create the Application Identity account and register keys.

---

## Overview

**`sample.ps1`** demonstrates read-only access:
1. Configuring the client with OAuth credentials and a Buzz server URL.
2. Calling `getuser2` to verify authentication and discover the home domain.
3. Calling `getdomain2` to read domain details.

The sample is intentionally read-only — it can be run repeatedly without modifying any data.

**BuzzApiClient** (in `BuzzApiClient.psm1`) simplifies integration by:
- Managing OAuth tokens automatically — requesting and refreshing Bearer tokens as needed.
- Retrying transient failures with exponential backoff (1 s → 64 s, up to 5 retries).
- Honouring `Retry-After` and `X-RateLimit-Reset` headers from the server.
- Providing `.JsonRequest()` and `.VerifyResponse()` methods for common JSON API patterns.

The RSA key handling is pure PowerShell/.NET: PowerShell 7+ uses native PEM APIs, while Windows
PowerShell 5.1 (whose .NET Framework lacks them) uses a small built-in PKCS#8/SPKI DER
encoder/decoder — so the same PEM key files work on both.

---

## Requirements

- **Windows PowerShell 5.1** (built into Windows 10/11 and Windows Server 2016+) **or**
  **PowerShell 7+** (Windows/Linux/macOS — <https://aka.ms/powershell>).
- Nothing else — no modules to install.

You may need to allow the scripts to run in your session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Compatibility

Verified end-to-end on **Windows PowerShell 5.1** and **PowerShell 7.x**. The client enables
TLS 1.2 and (on .NET Framework 4.8+) TLS 1.3 automatically, so it works against modern
TLS-1.3-only Buzz endpoints from Windows PowerShell 5.1 as well as from PowerShell 7. Nothing
here discourages running on the latest PowerShell.

## Configuration

Configuration uses a **PowerShell data file** (`buzz-config.psd1`) — the platform-standard config
format, loaded with the built-in `Import-PowerShellDataFile`. Copy `buzz-config.example.psd1` to
`buzz-config.psd1` (gitignored) and fill it in, or let the setup script generate it:

```powershell
@{
    ServerUrl              = 'https://api.agilixbuzz.com'
    ContactInformation     = '+https://example.com/; admin@example.com'
    ApplicationInformation = 'MyApp'
    OAuthUserId            = '12345678'
    OAuthKid               = '2025-q2'
    PrivateKeyPath         = 'private_key.pem'
}
```

---

## Quickest start

### Run (setup + demo in one command)

The run script checks whether one-time setup has been completed. If not, it runs the interactive
setup first, then executes the read-only demo.

```powershell
.\scripts\Run-BuzzSample.ps1
.\scripts\Run-BuzzSample.ps1 -Setup    # force re-running setup
```

### Cleanup (return to a clean state)

Deletes the Application Identity account from Buzz, removes the registered OAuth key, and deletes
the local key files and `buzz-config.psd1`.

```powershell
.\scripts\Cleanup-BuzzSample.ps1
```

---

## OAuth setup (one time per application)

The setup script automates all of the following, but you can also perform the steps manually.

### Step 1 — Create an Application Identity account

An Application Identity account authenticates exclusively via OAuth. Create it with the
`createusers2` API and `type=applicationidentity`, using an admin account with the Create User
right in the target domain. Record the returned `userid` — this is your **OAuth User ID**
(`OAuthUserId`), used as the OAuth `client_id`.

### Step 2 — Generate an RSA key pair

```powershell
.\scripts\New-BuzzOAuthKey.ps1                       # writes private_key.pem + public_key.pem
.\scripts\New-BuzzOAuthKey.ps1 -OutDir secrets -Bits 4096
```

Choose a **Key ID** (`kid`), e.g. `2025-q2`. Allowed characters: ASCII letters, digits, `-`, `_`,
`.` (max 128).

> **SECURITY** — `private_key.pem` is gitignored. Store it in a secrets manager for production.
> Never commit it.

### Step 3 — Register the public key with Buzz

```powershell
.\scripts\Register-BuzzOAuthKey.ps1 `
    -ServerUrl https://api.agilixbuzz.com `
    -UserId 12345678 `
    -Kid 2025-q2 `
    -PublicKeyPath public_key.pem
# Admin Bearer token via -AdminToken, the BUZZ_ADMIN_TOKEN env var, or an interactive prompt.
```

A `204 No Content` response means the key is stored.

### Step 4 — Configure and run

Create `buzz-config.psd1` (see Configuration above) or run `.\scripts\Run-BuzzSample.ps1`, then:

```powershell
.\sample.ps1
```

---

## Using the client in your own code

```powershell
Import-Module .\BuzzApiClient.psm1

$client = New-BuzzApiClientFromPem `
    -ServerUrl 'https://api.agilixbuzz.com' `
    -UserAgent 'MyApp/1.0 (PowerShell; MyApp; admin@example.com)' `
    -OAuthUserId '12345678' `
    -OAuthKid '2025-q2' `
    -PrivateKeyPath 'private_key.pem'

# The client obtains and refreshes Bearer tokens automatically.
$user   = $client.VerifyResponse($client.JsonRequest('GET', 'getuser2', $null, $null, $true), $true)
$domain = $client.VerifyResponse($client.JsonRequest('GET', 'getdomain2', @{ domainid = '6' }, $null, $true), $true)
```

`JsonRequest(method, cmd, params, jsonBody, includeToken)` returns the parsed response (as a
`PSCustomObject`). `VerifyResponse(node, checkChildResponses)` throws unless `response.code`
equals `OK` (and recursively checks child responses from batch APIs).

---

## Key management

### Rotating a key (zero downtime)

1. Generate a new key pair and choose a new `kid`.
2. Register the new public key (PUTting a new `kid` leaves the old key active).
3. Update `OAuthKid` and `PrivateKeyPath` to the new key.
4. Once all instances have switched over, delete the old key:
   `DELETE {server}/api/users/{userid}/keys/{old-kid}` with an admin Bearer token.

### Revoking a compromised key

Register a new key, switch your app to it, then delete the compromised public key and revoke
outstanding tokens (`POST {server}/api/oauth/revoke` with form body `token=<access_token>`).

---

## Troubleshooting OAuth

| Error | Cause | Fix |
|-------|-------|-----|
| `invalid_client: The client_assertion JWT has expired.` | Clock skew or a slow retry. | Sync your system clock (NTP). A fresh JWT is built for every token request. |
| `invalid_client: No active key found for the specified 'kid'.` | `OAuthKid` doesn't match a registered key. | Re-register the key and verify the `kid` matches exactly. |
| `invalid_client: ... signature or claims are invalid.` | Wrong private key, or `iss`/`sub` mismatch. | Confirm `OAuthUserId` is the Application Identity account's `userid` and the key matches the registered public key. |
| `Could not create SSL/TLS secure channel` (Windows PowerShell 5.1) | Server requires a TLS version not enabled. | The client enables TLS 1.2/1.3 automatically; ensure you are on Windows PowerShell 5.1 with .NET Framework 4.8+ on a current Windows build. |
| HTTP 400 registering a key | Wrong PEM format or key too small. | Use an SPKI PEM (`-----BEGIN PUBLIC KEY-----`), minimum 2048 bits. |
| HTTP 401/403 registering a key | Admin token lacks Update User rights. | Use an admin with the Update User right on the account. |
