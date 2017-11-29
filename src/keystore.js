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
      return callback(new Error(`Key '${name} does not exist'`))
    }
    
    fs.unlink(keyPath, callback)
  }

  createAnonymousEncryptedData (name, plain, callback) {
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
        const privateKey = forge.pki.decryptRsaPrivateKey(key, this._())
        util.certificateForKey(privateKey, (err, certificate) => {
          if (err) return callback(err)

          // create a p7 enveloped message
          const p7 = forge.pkcs7.createEnvelopedData()
          p7.addRecipient(certificate)
          p7.content = forge.util.createBuffer(plain)
          p7.encrypt()

          // convert message to DER
          const der = forge.asn1.toDer(p7.toAsn1()).getBytes()
          callback(null, Buffer.from(der, 'binary'))
        })
      } catch (err) {
        callback(err)
      }
    })
  } 
  
  readCmsData (cmsData, callback) {
    if (!Buffer.isBuffer(cmsData)) {
      return callback(new Error('CMS data is required'))
    }

    const self = this
    let cms
    try {
      const buf = forge.util.createBuffer(cmsData.toString('binary'));
      const obj = forge.asn1.fromDer(buf)
      cms = forge.pkcs7.messageFromAsn1(obj)
    } catch (err) {
      return callback(new Error('Invalid CMS: ' + err.message))
    }

    // Find a recipient whose key we hold. We only deal with recipient certs
    // issued by ipfs (O=ipfs).
    const recipients = cms.recipients
      .filter(r => r.issuer.find(a => a.shortName === 'O' && a.value === 'ipfs'))
      .filter(r => r.issuer.find(a => a.shortName === 'CN'))
      .map(r => {
        return {
          recipient: r,
          keyId: r.issuer.find(a => a.shortName === 'CN').value
        }
      })
    async.detect(
      recipients,
      (r, cb) => self.findKeyById(r.keyId, (err, info) => cb(null, !err && info)),
      (err, r) => {
        if (err) return callback(err)
        if (!r) return callback(new Error('No key found for decryption'))

        async.waterfall([
          (cb) => self.findKeyById(r.keyId, cb),
          (key, cb) => {
            const keyPath = path.join(this.store, key.name + keyExtension)
            fs.readFile(keyPath, 'utf8', cb)
          }
        ], (err, pem) => {
          if (err) return callback(err);

          const privateKey = forge.pki.decryptRsaPrivateKey(pem, this._())
          cms.decrypt(r.recipient, privateKey)
          async.setImmediate(() => callback(null, Buffer.from(cms.content.getBytes(), 'binary')))
        })
      }
    )
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
        return callback(new Error(`Key '${name} does not exist. ${err.message}'`))
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
      return callback(new Error(`Key '${name} already exists'`))

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
        util.keyId(privateKey, (err, kid) => {
          if (err) return callback(err)

          const info = {
            name: name,
            id: kid
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
