'use strict'

const mkdirp = require('mkdirp')

const defaultOptions = {
  createIfNeeded: true
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
  
  createKey (name, type, size) {
    throw new Error('NYI')
  }
}

module.exports = Keystore
