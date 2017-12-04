A secure key chain implemented in JS

# Features

- Manages the lifecycle of a key
- Keys are encrypted at rest
- Enforces the use of safe key names
- Uses encrypted PKCS 8 for key storage
- Uses PBKDF2 for a "stetched" key encryption key
- Enforces NIST SP 800-131A and NIST SP 800-132
- Uses PKCS 7: CMS (aka RFC 5652) to provide cryptographically protected messages

# Usage

    const datastore = new FsStore('./a-keystore')
    const opts = {
      passPhrase: 'some long easily remembered phrase'
    }
    const keychain = new Keychain(datastore, opts)

# API

Managing a key

- `createKey (name, type, size, callback)`
- `renameKey (oldName, newName, callback)`
- `removeKey (name, callback)`
- `exportKey (name, password, callback)`
- `importKey (name, pem, password, callback)`
- `importPeer (name, peer, callback)`

A naming service for a key

- `listKeys (callback)`
- `findKeyById (id, callback)`
- `findKeyByName (name, callback)`

Cryptographically protected messages

- `cms.createAnonymousEncryptedData (name, plain, callback)`
- `cms.readData (cmsData, callback)`

## KeyInfo

The key management and naming service API all return a `KeyInfo` object.  The `id` is a universally unique identifier for the key.  The `name` is local to the key chain.

```
{
  name: 'rsa-key',
  id: 'QmYWYSUZ4PV6MRFYpdtEDJBiGs4UrmE6g8wmAWSePekXVW'
  path: '... /rsa-key.pem'
}
```

The key id is the SHA-256 [multihash](https://github.com/multiformats/multihash) of its public key. The *public key* is a [protobuf encoding](https://github.com/libp2p/js-libp2p-crypto/blob/master/src/keys/keys.proto.js) containing a type and the [DER encoding](https://en.wikipedia.org/wiki/X.690) of the PKCS [SubjectPublicKeyInfo](https://www.ietf.org/rfc/rfc3279.txt).

## Private key storage

A private key is stored as an encrypted PKCS 8 structure in the PEM format. It is protected by a key generated from the key chain's *passPhrase* using **PBKDF2**.  Its file extension is `.p8`. 

See [details](https://github.com/richardschneider/ipfs-encryption/issues/10) for an in-depth discussion.

The default options for generating the derived encryption key are in the `dek` object
```
const defaultOptions = {
  createIfNeeded: true,

  //See https://cryptosense.com/parameter-choice-for-pbkdf2/
  dek: {
    keyLength: 512 / 8,
    iterationCount: 10000,
    salt: 'you should override this value with a crypto secure random number',
    hash: 'sha512'
  }
}
```

![key storage](../doc/private-key.png?raw=true)

### Physical storage

The actual physical storage of an encrypted key is left to implementations of [interface-datastore](https://github.com/ipfs/interface-datastore/).  A key benifit is that now the key chain can be used in browser with the [js-datastore-level](https://github.com/ipfs/js-datastore-level) implementation.
