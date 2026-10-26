'use strict';
const { randomBytes, createHash, createCipheriv, createDecipheriv } = require('node:crypto');

const hash = data => createHash('sha256').update(data).digest('hex');
const newKek = () => randomBytes(32);

function canonicalManifest(m) {
  const expected = ['algorithm', 'docId', 'schema', 'sha256', 'version'];
  if (!m || Object.keys(m).sort().join('|') !== expected.join('|') ||
      typeof m.docId !== 'string' || !m.docId || !Number.isSafeInteger(m.version) || m.version < 1 ||
      !/^[a-f0-9]{64}$/.test(m.sha256) || m.algorithm !== 'AES-256-GCM' || m.schema !== 'SEDMS-TV2-NODE-v1') {
    throw new Error('INVALID_MANIFEST');
  }
  return Buffer.from(JSON.stringify(Object.fromEntries(expected.map(k => [k, m[k]]))), 'utf8');
}

function checkKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('AES_256_KEY_REQUIRED');
}

function seal(key, plaintext, aad) {
  checkKey(key);
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { nonce: nonce.toString('base64'), ciphertext: ciphertext.toString('base64'),
    tag: cipher.getAuthTag().toString('base64') };
}

function open(key, box, aad) {
  checkKey(key);
  const nonce = Buffer.from(box.nonce, 'base64');
  const tag = Buffer.from(box.tag, 'base64');
  if (nonce.length !== 12 || tag.length !== 16) throw new Error('INVALID_GCM_PARAMETERS');
  const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(Buffer.from(box.ciphertext, 'base64')), decipher.final()]);
}

function encryptDocument(plaintext, docId, version, kek) {
  checkKey(kek);
  const manifest = { algorithm: 'AES-256-GCM', docId, schema: 'SEDMS-TV2-NODE-v1',
    sha256: hash(plaintext), version };
  const aad = canonicalManifest(manifest);
  const dek = randomBytes(32);
  try {
    const data = seal(dek, plaintext, aad);
    const wrappedDek = seal(kek, dek, Buffer.concat([Buffer.from('SEDMS-DEK-v1\0'), aad]));
    return { manifest, data, wrappedDek, cipherSha256: hash(Buffer.from(data.ciphertext, 'base64')) };
  } finally { dek.fill(0); }
}

function decryptDocument(pkg, kek) {
  const aad = canonicalManifest(pkg.manifest);
  const dek = open(kek, pkg.wrappedDek, Buffer.concat([Buffer.from('SEDMS-DEK-v1\0'), aad]));
  try {
    const plaintext = open(dek, pkg.data, aad);
    if (hash(plaintext) !== pkg.manifest.sha256) throw new Error('PLAINTEXT_HASH_MISMATCH');
    return plaintext;
  } finally { dek.fill(0); }
}

module.exports = { hash, newKek, canonicalManifest, encryptDocument, decryptDocument };
