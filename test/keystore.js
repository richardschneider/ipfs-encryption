/* eslint-env mocha */
'use strict'

const chai = require('chai')
const dirtyChai = require('dirty-chai')
const expect = chai.expect
chai.use(dirtyChai)
const Keystore = require('..').Keystore
const os = require('os')
const path = require('path')
const fs = require('fs')

describe('Keystore', () => {
  const store = path.join(os.tmpdir(), 'test-keystore')
  const passPhrase = 'this is not a secure phrase'
  
  it('needs a pass phrase to encrypt a key', () => {
    expect(() => new Keystore({ store: store})).to.throw()
  })
  
  it('needs a store to persist a key', () => {
    expect(() => new Keystore({ passPhrase: passPhrase})).to.throw()
  })

  describe('Store', () => {
    it('is a folder', () => {
      const ks = new Keystore({ store: store, passPhrase: passPhrase})
      expect(fs.existsSync(store)).to.be.true()
      expect(fs.lstatSync(store).isDirectory()).to.be.true()
    })
    
  })
  
})