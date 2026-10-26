'use strict';
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { hash, newKek, encryptDocument, decryptDocument } = require('./crypto_engine');
const { generateSigningKey, signManifest, publicPem, MultiSigService } = require('./multisig_service');

function samplePdf() {
  const stream = 'BT /F1 18 Tf 50 780 Td (SEDMS TV2 - Node.js demo) Tj ET';
  const objects = ['<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    `<< /Length ${Buffer.byteLength(stream)} >>\nstream\n${stream}\nendstream`];
  let pdf = '%PDF-1.4\n';
  const offsets = [];
  objects.forEach((obj, i) => { offsets.push(Buffer.byteLength(pdf)); pdf += `${i + 1} 0 obj\n${obj}\nendobj\n`; });
  const xref = Buffer.byteLength(pdf);
  pdf += `xref\n0 6\n0000000000 65535 f \n`;
  for (const offset of offsets) pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(pdf);
}

function run() {
  const args = process.argv.slice(2);
  if (args.length && (args.length !== 2 || args[0] !== '--file')) throw new Error('Usage: node demo.js [--file "path.pdf"]');
  const content = args.length ? fs.readFileSync(args[1]) : samplePdf();
  if (content.subarray(0, 5).toString() !== '%PDF-') throw new Error('PDF_HEADER_REQUIRED (not full PDF validation)');
  const out = path.join(__dirname, 'output');
  fs.mkdirSync(out, { recursive: true });
  const write = (name, data) => fs.writeFileSync(path.join(out, name), data);
  const lines = [];
  const log = msg => { console.log(msg); lines.push(msg); };
  const kek = newKek();
  try {
    write('document_original.pdf', content);
    const pkg = encryptDocument(content, 'DOC-001', 1, kek);
    write('package.json', JSON.stringify(pkg, null, 2));
    write('document.enc', Buffer.from(pkg.data.ciphertext, 'base64'));
    const recovered = decryptDocument(pkg, kek);
    assert.deepEqual(recovered, content);
    write('document_recovered.pdf', recovered);
    log('TC-NORM-01: PASS - AES-256-GCM encryption/decryption; DEK wrapped by KEK');
    log('SHA-256 original : ' + hash(content));
    log('SHA-256 recovered: ' + hash(recovered));
    const keys = { admin1: generateSigningKey(), admin2: generateSigningKey() };
    const workflow = new MultiSigService(pkg.manifest, { admin1: keys.admin1.publicKey, admin2: keys.admin2.publicKey });
    for (const [actor, pair] of Object.entries(keys)) write(`${actor}_public.pem`, publicPem(pair.publicKey));
    log('Initial status: ' + workflow.status);
    workflow.submitSignature('admin1', signManifest(keys.admin1.privateKey, pkg.manifest));
    log('Admin 1 signed: ' + workflow.status + ' (1/2)');
    assert.throws(() => workflow.requireIssued(), /INSUFFICIENT_SIGNATURES/);
    log('TC-SEC-03: PASS - publication/share gate BLOCKED: INSUFFICIENT_SIGNATURES (1/2)');
    assert.throws(() => workflow.submitSignature('admin1', signManifest(keys.admin1.privateKey, pkg.manifest)), /DUPLICATE_APPROVER/);
    log('Admin 1 signs again: BLOCKED - DUPLICATE_APPROVER (still 1/2)');
    workflow.submitSignature('admin2', signManifest(keys.admin2.privateKey, pkg.manifest));
    workflow.requireIssued();
    log('TC-NORM-02: PASS - two verified signatures -> ISSUED (2/2)');
    write('signatures.json', JSON.stringify(workflow.exportSignatures(), null, 2));
    log('Evidence saved in output/. Demo keys exist in RAM for this run only.');
    write('demo_result.txt', lines.join('\n') + '\n');
  } finally { kek.fill(0); }
}
try { run(); } catch (err) { console.error('DEMO FAILED: ' + err.message); process.exitCode = 1; }
