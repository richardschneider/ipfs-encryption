A secure key store implemented in JS

# Features

- Manages the lifecycle of a key
- Keys are encrypted at rest
- Enforces the use of safe key names
- Uses encrypted PKCS 8 for key storage
- Uses PKBDF2 for a "stetched" key encryption key
- Enforces NIST SP 800-131A and NIST SP 800-132
- Uses PKCS 7: CMS (aka RFC 2315) to encrypt and/or sign plain data
