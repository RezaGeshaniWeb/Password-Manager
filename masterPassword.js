'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const KEY_LENGTH = 64;
const SALT_LENGTH = 16;
const MAX_LOGIN_ATTEMPTS = 3;

/**
 * Manages master password creation, hashing, and verification.
 */
class MasterPasswordManager {
  /**
   * @param {string} masterPath Absolute path to master.json.
   */
  constructor(masterPath) {
    this.masterPath = masterPath;
    this.failedAttempts = 0;
  }

  /**
   * Whether a master password has already been configured.
   * @returns {boolean}
   */
  isConfigured() {
    return fs.existsSync(this.masterPath);
  }

  /**
   * Validate password strength rules.
   * @param {string} password
   * @returns {{ valid: boolean, errors: string[] }}
   */
  validateStrength(password) {
    const errors = [];
    if (typeof password !== 'string' || password.length < 12) {
      errors.push('Password must be at least 12 characters long.');
    }
    if (!/[A-Z]/.test(password || '')) {
      errors.push('Password must contain an uppercase letter.');
    }
    if (!/[a-z]/.test(password || '')) {
      errors.push('Password must contain a lowercase letter.');
    }
    if (!/[0-9]/.test(password || '')) {
      errors.push('Password must contain a number.');
    }
    if (!/[^A-Za-z0-9]/.test(password || '')) {
      errors.push('Password must contain a special character.');
    }
    return { valid: errors.length === 0, errors };
  }

  /**
   * Create and persist a new master password.
   * @param {string} password
   * @throws {Error} If strength validation fails or write fails.
   */
  createMasterPassword(password) {
    const { valid, errors } = this.validateStrength(password);
    if (!valid) {
      throw new Error(errors.join(' '));
    }

    const salt = crypto.randomBytes(SALT_LENGTH);
    const hash = this._hashPassword(password, salt);

    const payload = {
      salt: salt.toString('base64'),
      hash: hash.toString('base64'),
      created_at: new Date().toISOString(),
    };

    this._writeMaster(payload);
    this.failedAttempts = 0;
  }

  /**
   * Verify a master password against the stored hash.
   * @param {string} password
   * @returns {boolean}
   */
  verifyPassword(password) {
    if (this.failedAttempts >= MAX_LOGIN_ATTEMPTS) {
      throw new Error('Maximum login attempts exceeded.');
    }

    const data = this._readMaster();
    const salt = Buffer.from(data.salt, 'base64');
    const expected = Buffer.from(data.hash, 'base64');
    const actual = this._hashPassword(password, salt);

    const match =
      expected.length === actual.length &&
      crypto.timingSafeEqual(expected, actual);

    if (!match) {
      this.failedAttempts += 1;
      return false;
    }

    this.failedAttempts = 0;
    return true;
  }

  /**
   * Remaining login attempts before lockout.
   * @returns {number}
   */
  remainingAttempts() {
    return Math.max(0, MAX_LOGIN_ATTEMPTS - this.failedAttempts);
  }

  /**
   * Whether login attempts have been exhausted.
   * @returns {boolean}
   */
  isLockedOut() {
    return this.failedAttempts >= MAX_LOGIN_ATTEMPTS;
  }

  /**
   * Maximum allowed login attempts.
   * @returns {number}
   */
  static get maxAttempts() {
    return MAX_LOGIN_ATTEMPTS;
  }

  /**
   * @private
   * @param {string} password
   * @param {Buffer} salt
   * @returns {Buffer}
   */
  _hashPassword(password, salt) {
    return crypto.scryptSync(password, salt, KEY_LENGTH, SCRYPT_PARAMS);
  }

  /**
   * @private
   * @returns {{ salt: string, hash: string, created_at?: string }}
   */
  _readMaster() {
    if (!fs.existsSync(this.masterPath)) {
      throw new Error('Master password file is missing.');
    }

    let parsed;
    try {
      const raw = fs.readFileSync(this.masterPath, 'utf8');
      parsed = JSON.parse(raw);
    } catch {
      throw new Error('Master password file is corrupted.');
    }

    if (
      !parsed ||
      typeof parsed.salt !== 'string' ||
      typeof parsed.hash !== 'string'
    ) {
      throw new Error('Master password file is corrupted.');
    }

    return parsed;
  }

  /**
   * @private
   * @param {object} payload
   */
  _writeMaster(payload) {
    const dir = path.dirname(this.masterPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(this.masterPath, JSON.stringify(payload, null, 2), {
      encoding: 'utf8',
      mode: 0o600,
    });
  }
}

module.exports = { MasterPasswordManager };
