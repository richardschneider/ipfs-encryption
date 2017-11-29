'use strict'

const forge = require('node-forge')
const pki = forge.pki
const crypto = require('crypto');
const fs = require('fs');

exports = module.exports

// This should be a multi-hash
exports.keyId = (privateKey, callback) => {
  const publicKey = pki.setRsaPublicKey(privateKey.n, privateKey.e)
  const rsaPublicKey = forge.pki.publicKeyToRSAPublicKey(publicKey)
  const der = new Buffer(forge.asn1.toDer(rsaPublicKey).getBytes(), 'binary')
  const hash = crypto.createHash('sha256');
  hash.update(der)
  return callback(null, hash.digest('base64'))
}

exports.certificateForKey = (privateKey, callback) => {
  exports.keyId(privateKey, (err, kid) => {
    if (err) return callback(err)

    const publicKey = pki.setRsaPublicKey(privateKey.n, privateKey.e)
    const cert = pki.createCertificate();
    cert.publicKey = publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
    var attrs = [{
      name: 'organizationName',
      value: 'ipfs'
    }, {
      shortName: 'OU',
      value: 'keystore'
    }, {
      name: 'commonName',
      value: kid
    }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([{
      name: 'basicConstraints',
      cA: true
    }, {
      name: 'keyUsage',
      keyCertSign: true,
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: true
    }, {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true,
      codeSigning: true,
      emailProtection: true,
      timeStamping: true
    }, {
      name: 'nsCertType',
      client: true,
      server: true,
      email: true,
      objsign: true,
      sslCA: true,
      emailCA: true,
      objCA: true
    }]);
    // self-sign certificate
    cert.sign(privateKey)

    return callback(null, cert)
  })
}
