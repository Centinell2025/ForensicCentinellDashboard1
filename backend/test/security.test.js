const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { encryptEvidence, decryptEvidence } = require('../src/security/envelope');

test('evidence envelope encryption round-trips and detects tampering', async () => {
  const masterKey = crypto.randomBytes(32);
  const kms = {
    async encryptDataKey(key) {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
      const body = Buffer.concat([cipher.update(key), cipher.final()]);
      return { keyId:'test-hsm-key', ciphertext:Buffer.concat([iv,cipher.getAuthTag(),body]) };
    },
    async decryptDataKey(wrapped) {
      const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, wrapped.subarray(0,12));
      decipher.setAuthTag(wrapped.subarray(12,28));
      return Buffer.concat([decipher.update(wrapped.subarray(28)),decipher.final()]);
    }
  };
  const plaintext = Buffer.from('synthetic forensic evidence');
  const encrypted = await encryptEvidence(plaintext, kms, { tenant:'test' });
  assert.notDeepEqual(encrypted.ciphertext, plaintext);
  assert.deepEqual(await decryptEvidence(encrypted, kms, { tenant:'test' }), plaintext);
  encrypted.authTag[0] ^= 1;
  await assert.rejects(() => decryptEvidence(encrypted, kms, { tenant:'test' }));
});
