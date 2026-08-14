# Buzz API sample configuration.
# Copy this file to "buzz-config.psd1" and fill in the values, or run:
#     .\scripts\Run-BuzzSample.ps1
# which generates "buzz-config.psd1" for you.
#
# "buzz-config.psd1" is gitignored — never commit it.

@{
    # Buzz API server URL (no trailing slash).
    ServerUrl              = 'https://backgroundapi.agilixbuzz.com'

    # Included in the User-Agent header so Agilix support can identify your integration.
    ContactInformation     = '+https://example.com/; admin@example.com'
    ApplicationInformation = 'MyApp'

    # The userid of the Application Identity account (the OAuth client_id).
    OAuthUserId            = '12345678'

    # The key id (kid) chosen when the public key was registered with Buzz.
    OAuthKid               = '2025-q2'

    # Path to the RSA private key (PKCS#8 PEM).  Keep this file secret; never commit it.
    PrivateKeyPath         = 'private_key.pem'
}
