'use strict';

const crypto = require('crypto');

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const NUMBERS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';

/**
 * Generates cryptographically secure passwords.
 */
class PasswordGenerator {
  /**
   * Generate a secure password based on the provided options.
   * @param {object} options
   * @param {number} [options.length=16]
   * @param {boolean} [options.includeSymbols=true]
   * @param {boolean} [options.includeNumbers=true]
   * @param {boolean} [options.includeUppercase=true]
   * @returns {string}
   */
  generate({
    length = 16,
    includeSymbols = true,
    includeNumbers = true,
    includeUppercase = true,
  } = {}) {
    const len = Number(length);
    if (!Number.isInteger(len) || len < 4 || len > 128) {
      throw new Error('Password length must be an integer between 4 and 128.');
    }

    let alphabet = LOWERCASE;
    /** @type {string[]} */
    const required = [this._pick(LOWERCASE)];

    if (includeUppercase) {
      alphabet += UPPERCASE;
      required.push(this._pick(UPPERCASE));
    }
    if (includeNumbers) {
      alphabet += NUMBERS;
      required.push(this._pick(NUMBERS));
    }
    if (includeSymbols) {
      alphabet += SYMBOLS;
      required.push(this._pick(SYMBOLS));
    }

    if (alphabet.length === 0) {
      throw new Error('At least one character set must be enabled.');
    }

    if (required.length > len) {
      throw new Error(
        `Length must be at least ${required.length} to satisfy selected character sets.`
      );
    }

    /** @type {string[]} */
    const chars = [...required];
    while (chars.length < len) {
      chars.push(this._pick(alphabet));
    }

    return this._shuffle(chars).join('');
  }

  /**
   * @private
   * @param {string} alphabet
   * @returns {string}
   */
  _pick(alphabet) {
    const index = crypto.randomInt(0, alphabet.length);
    return alphabet[index];
  }

  /**
   * Fisher–Yates shuffle using crypto.randomInt.
   * @private
   * @param {string[]} arr
   * @returns {string[]}
   */
  _shuffle(arr) {
    const copy = [...arr];
    for (let i = copy.length - 1; i > 0; i -= 1) {
      const j = crypto.randomInt(0, i + 1);
      [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
  }
}

module.exports = { PasswordGenerator };
