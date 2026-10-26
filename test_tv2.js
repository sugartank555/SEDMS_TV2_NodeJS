'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { newKek, encryptDocument, decryptDocument } = require('./crypto_engine');
const { generateSigningKey, signManifest, MultiSigService, encryptedPrivatePem, loadPrivatePem } = require('./multisig_service');

function setup() {
  const kek = newKek(), plaintext = Buffer.from('%PDF-1.4 Test document');
  const pkg = encryptDocument(plaintext, 'DOC-1', 1, kek);
  const keys = { admin1: generateSigningKey(), admin2: generateSigningKey() };
  const service = new MultiSigService(pkg.manifest, { admin1: keys.admin1.publicKey, admin2: keys.admin2.publicKey });
  const approve = actor => service.submitSignature(actor, signManifest(keys[actor].privateKey, pkg.manifest));
  return { kek, plaintext, pkg, keys, service, approve };
}
function flipBase64(data) { const b = Buffer.from(data, 'base64'); b[0] ^= 1; return b.toString('base64'); }

test('TC-NORM-01: exact roundtrip and randomized encryption', () => {
  const s = setup();
  assert.deepEqual(decryptDocument(s.pkg, s.kek), s.plaintext);
  const other = encryptDocument(s.plaintext, 'DOC-1', 1, s.kek);
  assert.notEqual(other.data.ciphertext, s.pkg.data.ciphertext);
  assert.notEqual(other.wrappedDek.ciphertext, s.pkg.wrappedDek.ciphertext);
});
test('changed ciphertext, tag, nonce or wrapped DEK rejected', () => {
  const s = setup();
  for (const box of ['data', 'wrappedDek']) for (const field of ['ciphertext', 'tag', 'nonce']) {
    const bad = structuredClone(s.pkg); bad[box][field] = flipBase64(bad[box][field]);
    assert.throws(() => decryptDocument(bad, s.kek));
  }
});
test('wrong KEK rejected', () => {
  const s = setup(); assert.throws(() => decryptDocument(s.pkg, newKek()));
});
test('changed document ID, version or hash invalidates decryption and signature', () => {
  const s = setup();
  for (const [field, value] of [['docId', 'DOC-2'], ['version', 2], ['sha256', '0'.repeat(64)]]) {
    const bad = structuredClone(s.pkg); bad.manifest[field] = value;
    assert.throws(() => decryptDocument(bad, s.kek));
    assert.throws(() => s.service.submitSignature('admin1', signManifest(s.keys.admin1.privateKey, bad.manifest)), /INVALID_SIGNATURE/);
  }
});
test('TC-NORM-02: two independent signers issue document', () => {
  const s = setup(); assert.equal(s.approve('admin1'), 'PENDING_SECOND_SIGNATURE');
  assert.equal(s.approve('admin2'), 'ISSUED'); s.service.requireIssued();
});
test('TC-SEC-03: one compromised account and repeated approval cannot issue', () => {
  const s = setup(); s.approve('admin1');
  assert.throws(() => s.service.requireIssued(), /INSUFFICIENT_SIGNATURES/);
  assert.throws(() => s.approve('admin1'), /DUPLICATE_APPROVER/);
  assert.equal(s.service.validSignatureCount, 1);
  assert.throws(() => s.service.requireIssued(), /INSUFFICIENT_SIGNATURES/);
});
test('wrong key or unauthorized signer rejected', () => {
  const s = setup(), sig = signManifest(s.keys.admin1.privateKey, s.pkg.manifest);
  assert.throws(() => s.service.submitSignature('admin2', sig), /INVALID_SIGNATURE/);
  assert.throws(() => s.service.submitSignature('outsider', sig), /UNAUTHORIZED_APPROVER/);
});
test('two identities sharing a public key rejected', () => {
  const s = setup();
  assert.throws(() => new MultiSigService(s.pkg.manifest,
    { admin1: s.keys.admin1.publicKey, admin2: s.keys.admin1.publicKey }), /INDEPENDENT_KEYS_REQUIRED/);
});
test('tampered signature rejected and caller cannot mutate stored signature', () => {
  const s = setup(), sig = signManifest(s.keys.admin1.privateKey, s.pkg.manifest);
  const bad = Buffer.from(sig); bad[bad.length - 1] ^= 1;
  assert.throws(() => s.service.submitSignature('admin1', bad), /INVALID_SIGNATURE/);
  s.service.submitSignature('admin1', sig); sig.fill(0);
  assert.equal(s.service.validSignatureCount, 1);
});
test('encrypted PKCS8 private key reload works; incorrect password fails', () => {
  const s = setup(), pem = encryptedPrivatePem(s.keys.admin1.privateKey, 'test-only-password');
  const restored = loadPrivatePem(pem, 'test-only-password');
  s.service.submitSignature('admin1', signManifest(restored, s.pkg.manifest));
  assert.throws(() => loadPrivatePem(pem, 'incorrect'));
});
