/* eslint-env mocha */
'use strict'

const chai = require('chai')
const dirtyChai = require('dirty-chai')
const expect = chai.expect
chai.use(dirtyChai)
chai.use(require('chai-string'))
const Keystore = require('..').Keystore
const os = require('os')
const path = require('path')
const fs = require('fs')
const rimraf = require('rimraf')
const async = require('async')

describe('keystore', () => {
  const store = path.join(os.tmpdir(), 'test-keystore')
  const emptyStore = path.join(os.tmpdir(), 'test-keystore-empty')
  const passPhrase = 'this is not a secure phrase'
  const rsaKeyName = 'rsa-key'
  let rsaKeyInfo
  let emptyKeystore

  before(() => {
    emptyKeystore = new Keystore({ store: emptyStore, passPhrase: passPhrase})
  })

  after((done) => {
    async.series([
      (cb) => rimraf(store, cb),
      (cb) => rimraf(emptyStore, cb)
    ], done)
  })

  it('needs a pass phrase to encrypt a key', () => {
    expect(() => new Keystore({ store: store})).to.throw()
  })

  it ('needs a NIST SP 800-132 non-weak pass phrase', () => {
    expect(() => new Keystore({ store: store, passPhrase: '< 20 character'})).to.throw()
  })

  it('needs a store to persist a key', () => {
    expect(() => new Keystore({ passPhrase: passPhrase})).to.throw()
  })

  describe('store', () => {
    it('is a folder', () => {
      const ks = new Keystore({ store: store, passPhrase: passPhrase})
      expect(fs.existsSync(store)).to.be.true()
      expect(fs.lstatSync(store).isDirectory()).to.be.true()
    })    
  })
  
  describe('key name', () => {
    it('is a valid filename', () => {
      const ks = new Keystore({ store: store, passPhrase: passPhrase})
      ks.removeKey('../../nasty', (err) => {
        expect(err).to.exist()
        expect(err).to.have.property('message', 'Invalid key name \'../../nasty\'')
      })
      ks.removeKey('', (err) => {
        expect(err).to.exist()
        expect(err).to.have.property('message', 'Invalid key name \'\'')
      })
      ks.removeKey('    ', (err) => {
        expect(err).to.exist()
        expect(err).to.have.property('message', 'Invalid key name \'    \'')
      })
      ks.removeKey(null, (err) => {
        expect(err).to.exist()
        expect(err).to.have.property('message', 'Invalid key name \'null\'')
      })
      ks.removeKey(undefined, (err) => {
        expect(err).to.exist()
        expect(err).to.have.property('message', 'Invalid key name \'undefined\'')
      })
    })    
  })

  describe('key', () => {
    const ks = new Keystore({ store: store, passPhrase: passPhrase})

    it('can be an RSA key', function (done) {
      this.timeout(20 * 1000)
      ks.createKey(rsaKeyName, 'rsa', 2048, (err, info) => {
        expect(err).to.not.exist()
        expect(info).exist()
        rsaKeyInfo = info
        done()
      })
    })

    it('has a name and id', () => {
      expect(rsaKeyInfo).to.have.property('name', rsaKeyName)
      expect(rsaKeyInfo).to.have.property('id')
    })

    it('is a PKCS #8 pem file in the store', () => {
      const pem = path.join(store, rsaKeyName + '.pem')
      expect(fs.existsSync(pem)).to.be.true()
      expect(fs.lstatSync(pem).isFile()).to.be.true()
      const contents = fs.readFileSync(pem, 'utf8')
      expect(contents).to.startsWith('-----BEGIN')
    })

    it('is a PKCS #8 encrypted pem file in the store', () => {
      const pem = path.join(store, rsaKeyName + '.pem')
      const contents = fs.readFileSync(pem, 'utf8')
      expect(contents).to.startsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----')
    })

    it('does not overwrite existing key', (done) => {
      ks.createKey(rsaKeyName, 'rsa', 2048, (err) => {
        expect(err).to.exist()
        done()
      })
    })

    it('cannot create the "self" key', (done) => {
      ks.createKey('self', 'rsa', 2048, (err) => {
        expect(err).to.exist()
        done()
      })
    })

    describe('implements NIST SP 800-131A', () => {
      it('disallows RSA length < 2048', (done) => {
        ks.createKey('bad-nist-rsa', 'rsa', 1024, (err) => {
          expect(err).to.exist()
          expect(err).to.have.property('message', 'Invalid RSA key size 1024')
          done()
        })
      })
    })

  })

  describe('query', () => {
    const ks = new Keystore({ store: store, passPhrase: passPhrase})

    it('finds all existing keys', (done) => {
      ks.listKeys((err, keys) => {
        expect(err).to.not.exist()
        expect(keys).to.exist()
        const mykey = keys.find((k) => k.name === rsaKeyName)
        expect(mykey).to.exist()
        done()
      })
    })
    
    it('finds a key by name', (done) => {
      ks.findKeyByName(rsaKeyName, (err, key) => {
        expect(err).to.not.exist()
        expect(key).to.exist()
        expect(key).to.deep.equal(rsaKeyInfo)
        done()
      })
    })

    it('finds a key by id', (done) => {
      ks.findKeyById(rsaKeyInfo.id, (err, key) => {
        expect(err).to.not.exist()
        expect(key).to.exist()
        expect(key).to.deep.equal(rsaKeyInfo)
        done()
      })
    })

    it('returns the key\'s name and id', (done) => {
      ks.listKeys((err, keys) => {
        expect(err).to.not.exist()
        expect(keys).to.exist()
        keys.forEach((key) => {
          expect(key).to.have.property('name')
          expect(key).to.have.property('id')
        })
        done()
      })
    })
  })

  describe('encryption', () => {
    const ks = new Keystore({ store: store, passPhrase: passPhrase})
    const plainData = Buffer.from('This a message from Alice to Bob')
    
    it('requires a known key name', (done) => {
      ks._encrypt('not-there', plainData, (err) => {
        expect(err).to.exist()
        done()
      })
    })
  
    it('requires some data', (done) => {
      ks._encrypt(rsaKeyName, null, (err) => {
        expect(err).to.exist()
        done()
      })
    })

    it('generates encrypted data and encryption algorithm', (done) => {
      ks._encrypt(rsaKeyName, plainData, (err, res) => {
        expect(err).to.not.exist()
        expect(res).to.have.property('cipherData')
        expect(res).to.have.property('algorithm')
        done()
      })
    })

    it('decrypts', (done) => {
      ks._encrypt(rsaKeyName, plainData, (err, res) => {
        expect(err).to.not.exist()
        expect(res).to.have.property('cipherData')
        ks._decrypt(rsaKeyName, res.cipherData, (err, plain) => {
          expect(err).to.not.exist()
          expect(plain.toString()).to.equal(plainData.toString())
          done()
        })
      })
    })

  })
  
  describe('encrypted data', () => {
    const ks = new Keystore({ store: store, passPhrase: passPhrase})
    const plainData = Buffer.from('This is a message from Alice to Bob')
    let cms

    it('is anonymous', (done) => {
      ks.createAnonymousEncryptedData(rsaKeyName, plainData, (err, msg) => {
        expect(err).to.not.exist()
        expect(msg).to.exist()
        expect(msg).to.be.instanceOf(Buffer)
        fs.writeFileSync('foo.p7', msg)
        cms = msg
        done()
      })
    })

    it('is a PKCS #7 message', (done) => {
      ks.readCmsData("not CMS", (err) => {
        expect(err).to.exist()
        done()
      })
    })

    it('is a PKCS #7 binary message', (done) => {
      ks.readCmsData(plainData, (err) => {
        expect(err).to.exist()
        done()
      })
    })

    it('cannot be read without the key', (done) => {
      emptyKeystore.readCmsData(cms, (err, plain) => {
        expect(err).to.exist()
        done()
      })
    })

    it('can be read with the key', (done) => {
      ks.readCmsData(cms, (err, plain) => {
        expect(err).to.not.exist()
        expect(plain).to.exist()
        expect(plain.toString()).to.equal(plainData.toString())
        done()
      })
    })

  })

  describe('exported key', () => {
    const ks = new Keystore({ store: store, passPhrase: passPhrase})
    let pemKey

    it('is a PKCS #8 encrypted pem', (done) => {
      ks.exportKey(rsaKeyName, 'password', (err, pem) => {
        expect(err).to.not.exist()
        expect(pem).to.startsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----')
        pemKey = pem
        done()
      })
    })

    it('can be imported', (done) => {
      ks.importKey('imported-key', pemKey, 'password', (err, key) => {
        expect(err).to.not.exist()
        expect(key.name).to.equal('imported-key')
        expect(key.id).to.equal(rsaKeyInfo.id)
        done()
      })
    })

    it('cannot be imported as an existing key name', (done) => {
      ks.importKey(rsaKeyName, pemKey, 'password', (err, key) => {
        expect(err).to.exist()
        done()
      })
    })

    it('cannot be imported with the wrong password', (done) => {
      ks.importKey('a-new-name-for-import', pemKey, 'not the password', (err, key) => {
        expect(err).to.exist()
        done()
      })
    })
})

  describe('key removal', () => {
    const ks = new Keystore({ store: store, passPhrase: passPhrase})

    it('cannot remove the "self" key', (done) => {
      ks.removeKey('self', (err) => {
        expect(err).to.exist()
        done()
      })
    })

    it('cannot remove an unknown key', (done) => {
      ks.removeKey('not-there', (err) => {
        expect(err).to.exist()
        done()
      })
    })

    it('can remove a known key', (done) => {
      ks.removeKey(rsaKeyName, (err) => {
        expect(err).to.not.exist()
        done()
      })
    })
})

})
