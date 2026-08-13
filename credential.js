'use strict';

/**
 * Represents a single credential record in the vault.
 */
class Credential {
  /**
   * @param {object} data
   * @param {string} data.id
   * @param {string} data.website
   * @param {string} data.username
   * @param {string} data.password
   * @param {string} [data.notes]
   * @param {string} data.created_at
   * @param {string} data.updated_at
   */
  constructor({ id, website, username, password, notes = '', created_at, updated_at }) {
    this.id = id;
    this.website = website;
    this.username = username;
    this.password = password;
    this.notes = notes;
    this.created_at = created_at;
    this.updated_at = updated_at;
  }

  /**
   * Create a Credential from a plain object.
   * @param {object} obj
   * @returns {Credential}
   */
  static fromObject(obj) {
    return new Credential(obj);
  }

  /**
   * Convert credential to a plain serializable object.
   * @returns {object}
   */
  toObject() {
    return {
      id: this.id,
      website: this.website,
      username: this.username,
      password: this.password,
      notes: this.notes,
      created_at: this.created_at,
      updated_at: this.updated_at,
    };
  }

  /**
   * Return a safe view without exposing the password.
   * @returns {object}
   */
  toSafeObject() {
    return {
      id: this.id,
      website: this.website,
      username: this.username,
      notes: this.notes,
      created_at: this.created_at,
      updated_at: this.updated_at,
    };
  }
}

module.exports = { Credential };
