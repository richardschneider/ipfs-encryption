'use strict'

const async = require('async')
const mkdirp = require('mkdirp')
const sanitize = require("sanitize-filename")
const forge = require('node-forge')
const deepmerge = require('deepmerge')
const crypto = require('crypto')
const path = require('path')
const fs = require('fs')
const util = require('./util')

const keyExtension = '.pem'

const defaultOptions = {
  createIfNeeded: true,

  //See https://cryptosense.com/parameter-choice-for-pbkdf2/
  dek: {
    keyLength: 512 / 8,
    iterationCount: 10000,
    salt: 'you should override this value with a crypo secure random number',
    hash: 'sha512'
  }
}

function validateKeyName (name) {
  if (!name) return false
  
  return name === sanitize(name.trim())
}

class Keystore {
  constructor (options) {
    const opts = deepmerge(defaultOptions, options)
    
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

    // Enfore NIST SP 800-132
    const minKeyLength = 112 / 8
    const minSaltLength = 128 / 8
    const minIterationCount = 1000
    if (!opts.passPhrase || opts.passPhrase.length < 20) {
      throw new Error('passPhrase must be least 20 characters')
    }
    if (opts.dek.keyLength < minKeyLength) {
      throw new Error(`dek.keyLength must be least ${minKeyLength} bytes`)
    }
    if (opts.dek.salt.length < minSaltLength) {
      throw new Error(`dek.saltLength must be least ${minSaltLength} bytes`)
    }
    if (opts.dek.iterationCount < minIterationCount) {
      throw new Error(`dek.iterationCount must be least ${minIterationCount}`)
    }

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
  }

  createKey (name, type, size, callback) {
    if (!validateKeyName(name) || name === 'self') {
      return callback(new Error(`Invalid key name '${name}'`))
    }

    const keyPath = path.join(this.store, name + keyExtension)
    if(fs.existsSync(keyPath))
      return callback(new Error(`Key '${name} already exists'`))

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

  listKeys(callback) {
    fs.readdir(this.store, (err, filenames ) => {
      if (err) return callback(err)

      const names = filenames
        .filter((f) => f.endsWith(keyExtension))
        .map((f) => f.slice(0, -keyExtension.length))
      async.map(names, this._getKeyInfo, callback)
    })
  }

  // TODO: not very efficent.
  findKeyById(id, callback) {
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
      return callback(new Error(`Key '${name} does not exist'`))
    }
    
    fs.unlink(keyPath, callback)
  }

  createAnonymousEncryptedData(name, plain, callback) {
    if (!validateKeyName(name)) {
      return callback(new Error(`Invalid key name '${name}'`))
    }

    if (!Buffer.isBuffer(plain)) {
      return callback(new Error('Data is required'))
    }

    const keyPath = path.join(this.store, name + keyExtension)
    fs.readFile(keyPath, 'utf8', (err, key) => {
      if (err) {
        return callback(new Error(`Key '${name} does not exist. ${err.message}'`))
      }
      try {
        // create a p7 enveloped message
        const p7 = forge.pkcs7.createEnvelopedData()

        // add a recipient
        const privateKey = forge.pki.decryptRsaPrivateKey(key, this._())
        p7.addRecipient(util.certificateForKey(privateKey))

        // set content
        p7.content = forge.util.createBuffer(plain)

        // encrypt
        p7.encrypt()

        // convert message to PEM
        var pem = forge.pkcs7.messageToPem(p7)
        callback(null, pem)
      } catch (err) {
        callback(err)
      }
    })
  } 
  
  _getKeyInfo(name, callback) {
    if (!validateKeyName(name)) {
      return callback(new Error(`Invalid key name '${name}'`))
    }

    const keyPath = path.join(this.store, name + keyExtension)
    fs.readFile(keyPath, 'utf8', (err, pem) => {
      if (err) {
        return callback(new Error(`Key '${name} does not exist. ${err.message}'`))
      }
      try {
        const privateKey = forge.pki.decryptRsaPrivateKey(pem, this._())
        const info = {
          name: name,
          id: util.keyId(privateKey)
        }
        callback(null, info)
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
        return callback(new Error(`Key '${name} does not exist. ${err.message}'`))
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
        return callback(new Error(`Key '${name} does not exist. ${err.message}'`))
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
