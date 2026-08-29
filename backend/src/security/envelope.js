const crypto = require('crypto');

/** Encrypts evidence with a one-time AES-256-GCM data key.
 * kms.encryptDataKey must wrap the raw data key using an HSM/KMS-backed customer key.
 */
async function encryptEvidence(plaintext, kms, context) {
  if (!Buffer.isBuffer(plaintext)) throw new TypeError('Evidence must be a Buffer');
  const dataKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', dataKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const wrapped = await kms.encryptDataKey(dataKey, context);
    return {
      ciphertext, iv, authTag,
      encryptedDataKey: wrapped.ciphertext,
      kmsKeyId: wrapped.keyId,
      plaintextSha256: crypto.createHash('sha256').update(plaintext).digest('hex'),
      ciphertextSha256: crypto.createHash('sha256').update(ciphertext).digest('hex')
    };
  } finally { dataKey.fill(0); }
}

async function decryptEvidence(record, kms, context) {
  const dataKey = await kms.decryptDataKey(record.encryptedDataKey, record.kmsKeyId, context);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', dataKey, record.iv);
    decipher.setAuthTag(record.authTag);
    return Buffer.concat([decipher.update(record.ciphertext), decipher.final()]);
  } finally { dataKey.fill(0); }
}

module.exports = { encryptEvidence, decryptEvidence };
