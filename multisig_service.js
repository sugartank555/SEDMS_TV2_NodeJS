'use strict';
const { generateKeyPairSync, createPrivateKey, sign, verify, KeyObject } = require('node:crypto');
const { canonicalManifest } = require('./crypto_engine');

function generateSigningKey() {
  return generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}
function publicPem(key) {
  return key.export({ type: 'spki', format: 'pem' });
}
function encryptedPrivatePem(key, password) {
  if (typeof password !== 'string' || !password) throw new Error('PASSWORD_REQUIRED');
  return key.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: password });
}
function loadPrivatePem(pem, password) {
  const key = createPrivateKey({ key: pem, format: 'pem', passphrase: password });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails.namedCurve !== 'prime256v1') {
    throw new Error('ECDSA_P256_REQUIRED');
  }
  return key;
}
function signManifest(privateKey, manifest) {
  return sign('sha256', canonicalManifest(manifest), privateKey);
}

class MultiSigService {
  #payload;
  #approvers;
  #signatures = new Map();
  constructor(manifest, approvers) {
    const entries = Object.entries(approvers);
    if (entries.length !== 2) throw new Error('EXACTLY_TWO_APPROVERS_REQUIRED');
    for (const [, key] of entries) {
      if (!(key instanceof KeyObject) || key.type !== 'public' || key.asymmetricKeyType !== 'ec' ||
          key.asymmetricKeyDetails.namedCurve !== 'prime256v1') throw new Error('ECDSA_P256_PUBLIC_KEY_REQUIRED');
    }
    if (new Set(entries.map(([, key]) => publicPem(key))).size !== 2) throw new Error('INDEPENDENT_KEYS_REQUIRED');
    this.#payload = canonicalManifest(manifest);
    this.#approvers = new Map(entries);
  }
  submitSignature(actor, signature) {
    if (!this.#approvers.has(actor)) throw new Error('UNAUTHORIZED_APPROVER');
    if (!Buffer.isBuffer(signature) || !verify('sha256', this.#payload, this.#approvers.get(actor), signature)) {
      throw new Error('INVALID_SIGNATURE');
    }
    if (this.#signatures.has(actor)) throw new Error('DUPLICATE_APPROVER');
    this.#signatures.set(actor, Buffer.from(signature));
    return this.status;
  }
  get validSignatureCount() {
    let count = 0;
    for (const [actor, signature] of this.#signatures) {
      if (verify('sha256', this.#payload, this.#approvers.get(actor), signature)) count++;
    }
    return count;
  }
  get status() {
    const count = this.validSignatureCount;
    return count === 2 ? 'ISSUED' : count === 1 ? 'PENDING_SECOND_SIGNATURE' : 'PENDING_APPROVAL';
  }
  requireIssued() {
    if (this.status !== 'ISSUED') throw new Error(`INSUFFICIENT_SIGNATURES (${this.validSignatureCount}/2)`);
  }
  exportSignatures() {
    return Object.fromEntries([...this.#signatures].map(([actor, sig]) => [actor, sig.toString('base64')]));
  }
}
module.exports = { generateSigningKey, publicPem, encryptedPrivatePem, loadPrivatePem, signManifest, MultiSigService };
