'use strict'

const mkdirp = require('mkdirp')
const sanitize = require("sanitize-filename");

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
  }
  
  createKey (name, type, size, callback) {
    if (!validateKeyName(name)) {
      return callback(new Error(`Invalid key name '${name}'`))
    }

    //throw new Error('NYI')
    callback()
  }
  
  listKeys(callback) {
    //throw new Error('NYI')
    callback()
  }
  
  removeKey (name, callback) {
    if (!validateKeyName(name)) {
      return callback(new Error(`Invalid key name '${name}'`))
    }
    
    //throw new Error('NYI')
    callback()
  }

}

module.exports = Keystore
