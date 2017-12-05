'use strict'

const async = require('async')
const sanitize = require("sanitize-filename")
const forge = require('node-forge')
const deepmerge = require('deepmerge')
const crypto = require('crypto')
const libp2pCrypto = require('libp2p-crypto')
const util = require('./util')
const CMS = require('./cms')
const DS = require('interface-datastore')
const pull = require('pull-stream')

const keyExtension = '.p8'

// NIST SP 800-132
const NIST = {
  minKeyLength: 112 / 8,
  minSaltLength: 128 / 8,
  minIterationCount: 1000
}

const defaultOptions = {
  // See https://cryptosense.com/parametesr-choice-for-pbkdf2/
  dek: {
    keyLength: 512 / 8,
    iterationCount: 10000,
    salt: 'you should override this value with a crypto secure random number',
    hash: 'sha512'
  }
}

function validateKeyName (name) {
  if (!name) return false
  
  return name === sanitize(name.trim())
}

/**
 * Converts a key name into a datastore name.
 */
function DsName (name) {
  return new DS.Key('/' + name)
}

/**
 * Converts a datastore name into a key name.
 */
function KsName(name) {
  return name.toString().slice(1)
}

class Keychain {
  constructor (store, options) {
    if (!store) {
      throw new Error('store is required')
    }
    this.store = store
    if (this.store.opts) {
      this.store.opts.extension = keyExtension
    }

    const opts = deepmerge(defaultOptions, options)

    // Enforce NIST SP 800-132
    if (!opts.passPhrase || opts.passPhrase.length < 20) {
      throw new Error('passPhrase must be least 20 characters')
    }
    if (opts.dek.keyLength < NIST.minKeyLength) {
      throw new Error(`dek.keyLength must be least ${NIST.minKeyLength} bytes`)
    }
    if (opts.dek.salt.length < NIST.minSaltLength) {
      throw new Error(`dek.saltLength must be least ${NIST.minSaltLength} bytes`)
    }
    if (opts.dek.iterationCount < NIST.minIterationCount) {
      throw new Error(`dek.iterationCount must be least ${NIST.minIterationCount}`)
    }
    this.dek = opts.dek

    // Create the derived encrypting key
    let dek = forge.pkcs5.pbkdf2(
      opts.passPhrase,
      opts.dek.salt,
      opts.dek.iterationCount,
      opts.dek.keyLength,
      opts.dek.hash)
    dek = forge.util.bytesToHex(dek)
    Object.defineProperty(this, '_', { value: () => dek })

    // JS magick
    this._getKeyInfo = this.findKeyByName = this._getKeyInfo.bind(this)

    // Provide access to protected messages
    this.cms = new CMS(this)
  }

  static get options() {
    return defaultOptions
  }

  createKey (name, type, size, callback) {
    const self = this

    if (!validateKeyName(name) || name === 'self') {
      return callback(new Error(`Invalid key name '${name}'`))
    }
    const dsname = DsName(name)
    self.store.has(dsname, (err, exists) => {
      if (exists) return callback(new Error(`Key '${name}' already exists'`))

      switch (type.toLowerCase()) {
        case 'rsa':
          if (size < 2048) {
            return callback(new Error(`Invalid RSA key size ${size}`))
          }
          forge.pki.rsa.generateKeyPair({bits: size, workers: -1}, (err, keypair) => {
            if (err) return callback(err)

            const pem = forge.pki.encryptRsaPrivateKey(keypair.privateKey, this._());
            return self.store.put(dsname, pem, (err) => {
              if (err) return callback(err)

              self._getKeyInfo(name, callback)
            })
          })
          break;

        default:
          return callback(new Error(`Invalid key type '${type}'`))
      }
    })
  }

  listKeys (callback) {
    const self = this
    const query = {
      keysOnly: true
    }
    pull(
      self.store.query(query),
      pull.collect((err, res) => {
        if (err) return callback(err)

        const names = res.map(r => KsName(r.key))
        async.map(names, self._getKeyInfo, callback)
      })
    )
  }

  // TODO: not very efficent.
  findKeyById (id, callback) {
    this.listKeys((err, keys) => {
      if (err) return callback(err)

      const key = keys.find((k) => k.id === id)
      callback(null, key)
    })
  }

  removeKey (name, callback) {
    const self = this
    if (!validateKeyName(name) || name === 'self') {
      return callback(new Error(`Invalid key name '${name}'`))
    }
    const dsname = DsName(name)
    self.store.has(dsname, (err, exists) => {
      if (!exists) return callback(new Error(`Key '${name}' does not exist'`))

      self.store.delete(dsname, callback)
    })
  }

  renameKey(oldName, newName, callback) {
    const self = this
    if (!validateKeyName(oldName) || oldName === 'self') {
      return callback(new Error(`Invalid old key name '${oldName}'`))
    }
    if (!validateKeyName(newName) || newName === 'self') {
      return callback(new Error(`Invalid new key name '${newName}'`))
    }
    const oldDsname = DsName(oldName)
    const newDsname = DsName(newName)
    this.store.get(oldDsname, (err, res) => {
      if (err) {
        return callback(new Error(`Key '${oldName}' does not exist. ${err.message}`))
      }
      const pem = res.toString()
      self.store.has(newDsname, (err, exists) => {
        if (exists) return callback(new Error(`Key '${newName}' already exists'`))

        const batch = self.store.batch()
        batch.put(newDsname, pem)
        batch.delete(oldDsname)
        batch.commit((err) => {
          if (err) return callback(err)
          self._getKeyInfo(newName, callback)
        })
      })
    })
  }

  exportKey (name, password, callback) {
    if (!validateKeyName(name)) {
      return callback(new Error(`Invalid key name '${name}'`))
    }
    if (!password) {
      return callback(new Error('Password is required'))
    }

    const dsname = DsName(name)
    this.store.get(dsname, (err, res) => {
      if (err) {
        return callback(new Error(`Key '${name}' does not exist. ${err.message}`))
      }
      const pem = res.toString()
      try {
        const options = {
          algorithm: 'aes256',
          count: this.dek.iterationCount,
          saltSize: NIST.minSaltLength,
          prfAlgorithm: 'sha512'
        }
        const privateKey = forge.pki.decryptRsaPrivateKey(pem, this._())
        const res = forge.pki.encryptRsaPrivateKey(privateKey, password, options)
        return callback(null, res)
      } catch (e) {
        callback(e)
      }
    })
  }

  importKey(name, pem, password, callback) {
    const self = this
    if (!validateKeyName(name) || name === 'self') {
      return callback(new Error(`Invalid key name '${name}'`))
    }
    if (!pem) {
      return callback(new Error('PEM encoded key is required'))
    }
    const dsname = DsName(name)
    self.store.has(dsname, (err, exists) => {
      if (exists) return callback(new Error(`Key '${name}' already exists'`))
      try {
        const privateKey = forge.pki.decryptRsaPrivateKey(pem, password)
        if (privateKey === null) {
          return callback(new Error('Cannot read the key, most likely the password is wrong'))
        }
        const newpem = forge.pki.encryptRsaPrivateKey(privateKey, this._());
        return self.store.put(dsname, newpem, (err) => {
        if (err) return callback(err)

          this._getKeyInfo(name, callback)
        })
      } catch (err) {
        callback(err)
      }
    })
  }

  importPeer (name, peer, callback) {
    const self = this
    if (!validateKeyName(name)) {
      return callback(new Error(`Invalid key name '${name}'`))
    }
    if (!peer || !peer.privKey) {
      return callback(new Error('Peer.privKey \is required'))
    }
    const dsname = DsName(name)
    self.store.has(dsname, (err, exists) => {
      if (exists) return callback(new Error(`Key '${name}' already exists'`))

      const privateKeyProtobuf = peer.marshalPrivKey()
      libp2pCrypto.keys.unmarshalPrivateKey(privateKeyProtobuf, (err, key) => {
        try {
          const der = key.marshal()
          const buf = forge.util.createBuffer(der.toString('binary'));
          const obj = forge.asn1.fromDer(buf)
          const privateKey = forge.pki.privateKeyFromAsn1(obj)
          if (privateKey === null) {
            return callback(new Error('Cannot read the peer private key'))
          }
          const pem = forge.pki.encryptRsaPrivateKey(privateKey, this._());
          return self.store.put(dsname, pem, (err) => {
            if (err) return callback(err)

            this._getKeyInfo(name, callback)
          })
        } catch (err) {
          callback(err)
        }
      })
    })
  }

  _getKeyInfo (name, callback) {
    const self = this
    if (!validateKeyName(name)) {
      return callback(new Error(`Invalid key name '${name}'`))
    }

    const dsname = DsName(name)
    this.store.get(dsname, (err, res) => {
      if (err) {
        return callback(new Error(`Key '${name}' does not exist. ${err.message}`))
      }
      const pem = res.toString()
      try {
        const privateKey = forge.pki.decryptRsaPrivateKey(pem, this._())
        util.keyId(privateKey, (err, kid) => {
          if (err) return callback(err)

          const info = {
            name: name,
            id: kid
          }
          // Hack for our tests.
          if (self.store._encode) {
            info.path = self.store._encode(dsname).file
          }
          return callback(null, info)
        })
      } catch (e) {
        callback(e)
      }
    })
  }
  
  _encrypt (name, plain, callback) {
    if (!validateKeyName(name)) {
      return callback(new Error(`Invalid key name '${name}'`))
    }

    if (!Buffer.isBuffer(plain)) {
      return callback(new Error('Data is required'))
    }

    const dsname = DsName(name)
    this.store.get(dsname, (err, res) => {
      if (err) {
        return callback(new Error(`Key '${name}' does not exist. ${err.message}`))
      }
      const pem = res.toString()
      try {
        const privateKey = {
          key: pem,
          passphrase: this._(),
          padding: crypto.constants.RSA_PKCS1_PADDING
        }
        const res = {
          algorithm: 'RSA_PKCS1_PADDING',
          cipherData: crypto.publicEncrypt(privateKey, plain)
        }
        callback(null, res)
      } catch (err) {
        callback(err)
      }
    })
  }

  _decrypt (name, cipher, callback) {
    if (!validateKeyName(name)) {
      return callback(new Error(`Invalid key name '${name}'`))
    }

    if (!Buffer.isBuffer(cipher)) {
      return callback(new Error('Data is required'))
    }

    const dsname = DsName(name)
    this.store.get(dsname, (err, res) => {
      if (err) {
        return callback(new Error(`Key '${name}' does not exist. ${err.message}`))
      }
      const pem = res.toString()
      try {
        const privateKey = {
          key: pem,
          passphrase: this._(),
          padding: crypto.constants.RSA_PKCS1_PADDING
        }
        callback(null, crypto.privateDecrypt(privateKey, cipher))
      } catch (err) {
        callback(err)
      }
    })
  }

}

module.exports = Keychain
