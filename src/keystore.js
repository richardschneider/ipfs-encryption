'use strict'

const mkdirp = require('mkdirp')
const sanitize = require("sanitize-filename");
const RSA = require('node-rsa')
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

    if (!opts.passPhrase) {
      throw new Error('passPhrase is required')
    }

    this.store = opts.store
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
        const key = new RSA({b: size})
        const pem = key.exportKey('pkcs8')
        return fs.writeFile(keyPath, pem, callback)

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
    if(!fs.existsSync(keyPath))
      return callback(new Error(`Key '${name} does not exist'`))
    
    fs.unlink(keyPath, callback)
  }

}

module.exports = Keystore
