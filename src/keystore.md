A secure key store implemented in JS

# Features

- Manages the lifecycle of a key
- Keys are encrypted at rest
- Enforces the use of safe key names
- Uses encrypted PKCS 8 for key storage
- Uses PKBDF2 for a "stetched" key encryption key
- Enforces NIST SP 800-131A and NIST SP 800-132
- Uses PKCS 7: CMS (aka RFC 5652) to provide cryptographically protected messages

# Usage

    const opts = {
      store: './keystore',
      createIfNeeded: true,
      passPhrase: 'some long easily remembered phrase'
    }
    const keystore = new Keystore(opts)

# API

Managing a key

- `createKey (name, type, size, callback)`
- `removeKey (name, callback)`
- `exportKey (name, password, callback)`
- `importKey (name, pem, password, callback)`
- `importPeer (name, peer, callback)`

A naming service for a key.  The `id` is a universally unique identifier for the key.  The `name` is local to the keystore.

- `listKeys (callback)`
- `findKeyById (id, callback)`
- `FindKeyByName (name, callback)`

Cryptographically protected messages

- `createAnonymousEncryptedData (name, plain, callback)`
- `readCmsData (cmsData, callback)`
