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
const PeerId = require('peer-id')

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

    it('has a name, id and path', () => {
      expect(rsaKeyInfo).to.have.property('name', rsaKeyName)
      expect(rsaKeyInfo).to.have.property('id')
      expect(rsaKeyInfo).to.have.property('path')
    })

    it('is a PKCS #8 pem file in the store', () => {
      const pem = rsaKeyInfo.path
      expect(fs.existsSync(pem)).to.be.true()
      expect(fs.lstatSync(pem).isFile()).to.be.true()
      const contents = fs.readFileSync(pem, 'utf8')
      expect(contents).to.startsWith('-----BEGIN')
    })

    it('is a PKCS #8 encrypted pem file in the store', () => {
      const pem = rsaKeyInfo.path
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
  
  describe('protected data', () => {
    const ks = new Keystore({ store: store, passPhrase: passPhrase})
    const plainData = Buffer.from('This is a message from Alice to Bob')
    let cms

    it('service is available', (done) => {
      expect(ks).to.have.property('cms')
      done()
    })

    it('is anonymous', (done) => {
      ks.cms.createAnonymousEncryptedData(rsaKeyName, plainData, (err, msg) => {
        expect(err).to.not.exist()
        expect(msg).to.exist()
        expect(msg).to.be.instanceOf(Buffer)
        // fs.writeFileSync('foo.p7', msg)
        cms = msg
        done()
      })
    })

    it('is a PKCS #7 message', (done) => {
      ks.cms.readData("not CMS", (err) => {
        expect(err).to.exist()
        done()
      })
    })

    it('is a PKCS #7 binary message', (done) => {
      ks.cms.readData(plainData, (err) => {
        expect(err).to.exist()
        done()
      })
    })

    it('cannot be read without the key', (done) => {
      emptyKeystore.cms.readData(cms, (err, plain) => {
        expect(err).to.exist()
        done()
      })
    })

    it('can be read with the key', (done) => {
      ks.cms.readData(cms, (err, plain) => {
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

  describe('peer id', () => {
    const ks = new Keystore({ store: store, passPhrase: passPhrase})
    const alicePrivKey = 'CAASpgkwggSiAgEAAoIBAQC2SKo/HMFZeBml1AF3XijzrxrfQXdJzjePBZAbdxqKR1Mc6juRHXij6HXYPjlAk01BhF1S3Ll4Lwi0cAHhggf457sMg55UWyeGKeUv0ucgvCpBwlR5cQ020i0MgzjPWOLWq1rtvSbNcAi2ZEVn6+Q2EcHo3wUvWRtLeKz+DZSZfw2PEDC+DGPJPl7f8g7zl56YymmmzH9liZLNrzg/qidokUv5u1pdGrcpLuPNeTODk0cqKB+OUbuKj9GShYECCEjaybJDl9276oalL9ghBtSeEv20kugatTvYy590wFlJkkvyl+nPxIH0EEYMKK9XRWlu9XYnoSfboiwcv8M3SlsjAgMBAAECggEAZtju/bcKvKFPz0mkHiaJcpycy9STKphorpCT83srBVQi59CdFU6Mj+aL/xt0kCPMVigJw8P3/YCEJ9J+rS8BsoWE+xWUEsJvtXoT7vzPHaAtM3ci1HZd302Mz1+GgS8Epdx+7F5p80XAFLDUnELzOzKftvWGZmWfSeDnslwVONkL/1VAzwKy7Ce6hk4SxRE7l2NE2OklSHOzCGU1f78ZzVYKSnS5Ag9YrGjOAmTOXDbKNKN/qIorAQ1bovzGoCwx3iGIatQKFOxyVCyO1PsJYT7JO+kZbhBWRRE+L7l+ppPER9bdLFxs1t5CrKc078h+wuUr05S1P1JjXk68pk3+kQKBgQDeK8AR11373Mzib6uzpjGzgNRMzdYNuExWjxyxAzz53NAR7zrPHvXvfIqjDScLJ4NcRO2TddhXAfZoOPVH5k4PJHKLBPKuXZpWlookCAyENY7+Pd55S8r+a+MusrMagYNljb5WbVTgN8cgdpim9lbbIFlpN6SZaVjLQL3J8TWH6wKBgQDSChzItkqWX11CNstJ9zJyUE20I7LrpyBJNgG1gtvz3ZMUQCn3PxxHtQzN9n1P0mSSYs+jBKPuoSyYLt1wwe10/lpgL4rkKWU3/m1Myt0tveJ9WcqHh6tzcAbb/fXpUFT/o4SWDimWkPkuCb+8j//2yiXk0a/T2f36zKMuZvujqQKBgC6B7BAQDG2H2B/ijofp12ejJU36nL98gAZyqOfpLJ+FeMz4TlBDQ+phIMhnHXA5UkdDapQ+zA3SrFk+6yGk9Vw4Hf46B+82SvOrSbmnMa+PYqKYIvUzR4gg34rL/7AhwnbEyD5hXq4dHwMNsIDq+l2elPjwm/U9V0gdAl2+r50HAoGALtsKqMvhv8HucAMBPrLikhXP/8um8mMKFMrzfqZ+otxfHzlhI0L08Bo3jQrb0Z7ByNY6M8epOmbCKADsbWcVre/AAY0ZkuSZK/CaOXNX/AhMKmKJh8qAOPRY02LIJRBCpfS4czEdnfUhYV/TYiFNnKRj57PPYZdTzUsxa/yVTmECgYBr7slQEjb5Onn5mZnGDh+72BxLNdgwBkhO0OCdpdISqk0F0Pxby22DFOKXZEpiyI9XYP1C8wPiJsShGm2yEwBPWXnrrZNWczaVuCbXHrZkWQogBDG3HGXNdU4MAWCyiYlyinIBpPpoAJZSzpGLmWbMWh28+RJS6AQX6KHrK1o2uw=='
    let alice

    before(function (done) {
      const encoded = Buffer.from(alicePrivKey, 'base64')
      PeerId.createFromPrivKey(encoded, (err, id) => {
        alice = id
        done()
      })
    })

    it('private key can be imported', (done) => {
      ks.importPeer('alice', alice, (err, key) => {
        expect(err).to.not.exist()
        expect(key.name).to.equal('alice')
        expect(key.id).to.equal(alice.toB58String())
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
