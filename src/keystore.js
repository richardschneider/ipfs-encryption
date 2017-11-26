'use strict'

const mkdirp = require('mkdirp')
const sanitize = require("sanitize-filename")
const forge = require('node-forge')
const deepmerge = require('deepmerge')
const crypto = require('crypto')
const path = require('path')
const fs = require('fs')

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
          if (err) return callback(err);

          const pem = forge.pki.encryptRsaPrivateKey(keypair.privateKey, this._());
          return fs.writeFile(keyPath, pem, callback)
        })
        break;

      default:
        return callback(new Error(`Invalid key type '${type}'`))
    }
  }

  listKeys(callback) {
    fs.readdir(this.store, (err, filenames ) => {
      if (err) return callback(err)

      const keys = filenames
        .filter((f) => f.endsWith(keyExtension))
        .map((f) => {
          return {
            KeyName: f.slice(0, -keyExtension.length)
          }
        })
      callback(null, keys)
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
