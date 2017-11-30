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

A naming service for a key

- `listKeys (callback)`
- `findKeyById (id, callback)`
- `findKeyByName (name, callback)`

Cryptographically protected messages

- `createAnonymousEncryptedData (name, plain, callback)`
- `readCmsData (cmsData, callback)`

## KeyInfo

The key management and naming service API all return a `KeyInfo` object.  The `id` is a universally unique identifier for the key.  The `name` is local to the keystore.

```
{
  name: 'rsa-key',
  id: 'QmYWYSUZ4PV6MRFYpdtEDJBiGs4UrmE6g8wmAWSePekXVW'
}
```

The key id is the SHA-256 [multihash](https://github.com/multiformats/multihash) of its public key. The *public key* is a [protobuf encoding](https://github.com/libp2p/js-libp2p-crypto/blob/master/src/keys/keys.proto.js) containing a type and the [DER encoding](https://en.wikipedia.org/wiki/X.690) of the PKCS [SubjectPublicKeyInfo](https://www.ietf.org/rfc/rfc3279.txt).