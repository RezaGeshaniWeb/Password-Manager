'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Manages AES-256-GCM encryption keys and encrypt/decrypt operations.
 */
class EncryptionManager {
  /**
   * @param {string} keyPath Absolute path to the key file.
   */
  constructor(keyPath) {
    this.keyPath = keyPath;
    /** @type {Buffer|null} */
    this.key = null;
  }

  /**
   * Generate a cryptographically secure 256-bit key and persist it.
   * @returns {Buffer}
   */
  generateKey() {
    const key = crypto.randomBytes(32);
    this._writeKey(key);
    this.key = key;
    return key;
  }

  /**
   * Load the encryption key from disk.
   * @returns {Buffer}
   * @throws {Error} If the key file is missing or corrupted.
   */
  loadKey() {
    if (!fs.existsSync(this.keyPath)) {
      throw new Error('Encryption key file is missing.');
    }

    let raw;
    try {
      raw = fs.readFileSync(this.keyPath);
    } catch {
      throw new Error('Unable to read encryption key file.');
    }

    if (!Buffer.isBuffer(raw) || raw.length !== 32) {
      throw new Error('Encryption key file is corrupted.');
    }

    this.key = raw;
    return this.key;
  }

  /**
   * Ensure a key is available: load existing or generate a new one.
   * @returns {Buffer}
   */
  ensureKey() {
    if (fs.existsSync(this.keyPath)) {
      return this.loadKey();
    }
    return this.generateKey();
  }

  /**
   * Encrypt a UTF-8 string using AES-256-GCM.
   * Returns a base64 payload: iv:authTag:ciphertext
   * @param {string} plaintext
   * @returns {string}
   */
  encrypt(plaintext) {
    this._assertKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    const encrypted = Buffer.concat([
      cipher.update(String(plaintext ?? ''), 'utf8'),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();
    return [
      iv.toString('base64'),
      authTag.toString('base64'),
      encrypted.toString('base64'),
    ].join(':');
  }

  /**
   * Decrypt a payload produced by {@link EncryptionManager#encrypt}.
   * @param {string} payload
   * @returns {string}
   */
  decrypt(payload) {
    this._assertKey();
    if (typeof payload !== 'string' || !payload.includes(':')) {
      throw new Error('Invalid encrypted payload.');
    }

    const parts = payload.split(':');
    if (parts.length !== 3) {
      throw new Error('Corrupted encrypted payload.');
    }

    const [ivB64, tagB64, dataB64] = parts;
    const iv = Buffer.from(ivB64, 'base64');
    const authTag = Buffer.from(tagB64, 'base64');
    const data = Buffer.from(dataB64, 'base64');

    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, iv);
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([
        decipher.update(data),
        decipher.final(),
      ]);
      return decrypted.toString('utf8');
    } catch {
      throw new Error('Failed to decrypt data. Vault may be corrupted.');
    }
  }

  /**
   * Clear the key from memory as best-effort cleanup.
   */
  clearKey() {
    if (this.key) {
      this.key.fill(0);
      this.key = null;
    }
  }

  /**
   * @private
   * @param {Buffer} key
   */
  _writeKey(key) {
    const dir = path.dirname(this.keyPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(this.keyPath, key, { mode: 0o600 });
  }

  /**
   * @private
   */
  _assertKey() {
    if (!this.key || this.key.length !== 32) {
      throw new Error('Encryption key is not loaded.');
    }
  }
}

module.exports = { EncryptionManager };
