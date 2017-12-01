'use strict'

const async = require('async')
const mkdirp = require('mkdirp')
const sanitize = require("sanitize-filename")
const forge = require('node-forge')
const deepmerge = require('deepmerge')
const crypto = require('crypto')
const libp2pCrypto = require('libp2p-crypto')
const path = require('path')
const fs = require('fs')
const util = require('./util')
const CMS = require('./cms')

const keyExtension = '.pem'

// NIST SP 800-132
const NIST = {
  minKeyLength: 112 / 8,
  minSaltLength: 128 / 8,
  minIterationCount: 1000
}

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

function validateKeyName (name) {
  if (!name) return false
  
  return name === sanitize(name.trim())
}

class Keystore {
  constructor (store, options) {
    let opts
    if (arguments.length === 2) {
      opts = deepmerge(defaultOptions, options)
      opts.store = store
    } else {
      opts = deepmerge(defaultOptions, store)
    }

    // Get the keystore folder.
    if (!opts.store || opts.store.trim().length === 0) {
      throw new Error('store is required')
    }
    opts.store = path.normalize(opts.store)
    if (!fs.existsSync(opts.store)) {
      if (opts.createIfNeeded) {
        mkdirp.sync(opts.store)
      }
      else {
        throw new Error(`The store '${opts.store}' does not exist`)
      }
    }
    this.store = opts.store

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
    this._ = () => dek

    // JS magick
    this._getKeyInfo = this.findKeyByName = this._getKeyInfo.bind(this)

    // Provide access to protected messages
    this.cms = new CMS(this)
  }

  createKey (name, type, size, callback) {
    if (!validateKeyName(name) || name === 'self') {
      return callback(new Error(`Invalid key name '${name}'`))
    }

    const keyPath = path.join(this.store, name + keyExtension)
    if(fs.existsSync(keyPath))
      return callback(new Error(`Key '${name}' already exists'`))

    switch (type.toLowerCase()) {
      case 'rsa':
        if (size < 2048) {
          return callback(new Error(`Invalid RSA key size ${size}`))
        }
        forge.pki.rsa.generateKeyPair({bits: size, workers: -1}, (err, keypair) => {
          if (err) return callback(err)

          const pem = forge.pki.encryptRsaPrivateKey(keypair.privateKey, this._());
          return fs.writeFile(keyPath, pem, (err) => {
            if (err) return callback(err)

            this._getKeyInfo(name, callback)
          })
        })
        break;

      default:
        return callback(new Error(`Invalid key type '${type}'`))
    }
  }

  listKeys (callback) {
    fs.readdir(this.store, (err, filenames ) => {
      if (err) return callback(err)

      const names = filenames
        .filter((f) => f.endsWith(keyExtension))
        .map((f) => f.slice(0, -keyExtension.length))
      async.map(names, this._getKeyInfo, callback)
    })
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
    if (!validateKeyName(name) || name === 'self') {
      return callback(new Error(`Invalid key name '${name}'`))
    }

    const keyPath = path.join(this.store, name + keyExtension)
    if(!fs.existsSync(keyPath)) {
      return callback(new Error(`Key '${name}' does not exist'`))
    }

    fs.unlink(keyPath, callback)
  }

  renameKey(oldName, newName, callback) {
    if (!validateKeyName(oldName) || oldName === 'self') {
      return callback(new Error(`Invalid old key name '${oldName}'`))
    }
    if (!validateKeyName(newName) || newName === 'self') {
      return callback(new Error(`Invalid new key name '${newName}'`))
    }
    const oldKeyPath = path.join(this.store, oldName + keyExtension)
    if(!fs.existsSync(oldKeyPath)) {
      return callback(new Error(`Key '${oldName}' does not exist'`))
    }
    const newKeyPath = path.join(this.store, newName + keyExtension)
    if(fs.existsSync(newKeyPath)) {
      return callback(new Error(`Key '${newName}' already exists'`))
    }

    const self = this
    fs.rename(oldKeyPath, newKeyPath, (err) => {
      if (err) return callback(err)
      self._getKeyInfo(newName, callback)
    })
  }

  exportKey (name, password, callback) {
    if (!validateKeyName(name)) {
      return callback(new Error(`Invalid key name '${name}'`))
    }
    if (!password) {
      return callback(new Error('Password is required'))
    }

    const keyPath = path.join(this.store, name + keyExtension)
    fs.readFile(keyPath, 'utf8', (err, pem) => {
      if (err) {
        return callback(new Error(`Key '${name}' does not exist. ${err.message}`))
      }
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
    if (!validateKeyName(name) || name === 'self') {
      return callback(new Error(`Invalid key name '${name}'`))
    }
    if (!pem) {
      return callback(new Error('PEM encoded key is required'))
    }
    const keyPath = path.join(this.store, name + keyExtension)
    if(fs.existsSync(keyPath))
      return callback(new Error(`Key '${name}' already exists'`))

    try {
      const privateKey = forge.pki.decryptRsaPrivateKey(pem, password)
      if (privateKey === null) {
        return callback(new Error('Cannot read the key, most likely the password is wrong'))
      }
      const newpem = forge.pki.encryptRsaPrivateKey(privateKey, this._());
      return fs.writeFile(keyPath, newpem, (err) => {
        if (err) return callback(err)

        this._getKeyInfo(name, callback)
      })
    } catch (err) {
      callback(err)
    }
  }

  importPeer (name, peer, callback) {
    if (!validateKeyName(name)) {
      return callback(new Error(`Invalid key name '${name}'`))
    }
    if (!peer || !peer.privKey) {
      return callback(new Error('Peer.privKey \is required'))
    }
    const keyPath = path.join(this.store, name + keyExtension)
    if(fs.existsSync(keyPath))
      return callback(new Error(`Key '${name}' already exists'`))

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
        return fs.writeFile(keyPath, pem, (err) => {
          if (err) return callback(err)

          this._getKeyInfo(name, callback)
        })
      } catch (err) {
        callback(err)
      }
    })
  }

  _getKeyInfo (name, callback) {
    if (!validateKeyName(name)) {
      return callback(new Error(`Invalid key name '${name}'`))
    }

    const keyPath = path.join(this.store, name + keyExtension)
    fs.readFile(keyPath, 'utf8', (err, pem) => {
      if (err) {
        return callback(new Error(`Key '${name}' does not exist. ${err.message}`))
      }
      try {
        const privateKey = forge.pki.decryptRsaPrivateKey(pem, this._())
        util.keyId(privateKey, (err, kid) => {
          if (err) return callback(err)

          const info = {
            name: name,
            id: kid,
            path: keyPath
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

    const keyPath = path.join(this.store, name + keyExtension)
    fs.readFile(keyPath, 'utf8', (err, key) => {
      if (err) {
        return callback(new Error(`Key '${name}' does not exist. ${err.message}`))
      }
      try {
        const privateKey = {
          key: key,
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

    const keyPath = path.join(this.store, name + keyExtension)
    fs.readFile(keyPath, 'utf8', (err, key) => {
      if (err) {
        return callback(new Error(`Key '${name}' does not exist. ${err.message}`))
      }
      try {
        const privateKey = {
          key: key,
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

module.exports = Keystore
