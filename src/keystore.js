'use strict'

const mkdirp = require('mkdirp')
const sanitize = require("sanitize-filename")
const forge = require('node-forge')
const path = require('path')
const fs = require('fs')

const keyExtension = '.pem'

const defaultOptions = {
  createIfNeeded: true
}

function validateKeyName (name) {
  if (!name) return false
  
  return name === sanitize(name.trim())
}

class Keystore {
  constructor (options) {
    const opts = Object.assign({}, defaultOptions, options)
    
    if (opts.createIfNeeded) {
      mkdirp.sync(opts.store)
    }

    if (!opts.passPhrase || opts.passPhrase.length < 20) {
      throw new Error('passPhrase is required of at least 20 characters')
    }
    //See https://cryptosense.com/parameter-choice-for-pbkdf2/
    const klen = 512 / 8
    const icount = 10000
    const salt = forge.random.getBytesSync(klen)
    let dek = forge.pkcs5.pbkdf2(opts.passPhrase, salt, icount, klen, 'sha512')
    dek = forge.util.bytesToHex(dek)

    this.store = opts.store
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

  encrypt (name, data, callback) {
    if (!validateKeyName(name)) {
      return callback(new Error(`Invalid key name '${name}'`))
    }

    const keyPath = path.join(this.store, name + keyExtension)
    if(!fs.existsSync(keyPath)) {
      return callback(new Error(`Key '${name} does not exist'`))
    }
    
    if (!Buffer.isBuffer(data)) {
      return callback(new Error('Data is required'))
    }
    
    callback(null, {})
  }

}

module.exports = Keystore
