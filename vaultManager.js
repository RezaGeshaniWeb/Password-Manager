'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Credential } = require('./credential');

/**
 * Manages credential CRUD, search, persistence, and export.
 */
class VaultManager {
  /**
   * @param {string} vaultPath Absolute path to vault.json.
   * @param {import('./encryptionManager').EncryptionManager} encryptionManager
   */
  constructor(vaultPath, encryptionManager) {
    this.vaultPath = vaultPath;
    this.encryption = encryptionManager;
    /** @type {Credential[]} */
    this.credentials = [];
  }

  /**
   * Load vault from disk. Creates an empty vault if missing.
   */
  load() {
    if (!fs.existsSync(this.vaultPath)) {
      this.credentials = [];
      this.save();
      return;
    }

    let parsed;
    try {
      const raw = fs.readFileSync(this.vaultPath, 'utf8');
      parsed = JSON.parse(raw);
    } catch {
      throw new Error('Vault file is corrupted and could not be parsed.');
    }

    if (!Array.isArray(parsed)) {
      throw new Error('Vault file is corrupted: expected an array.');
    }

    this.credentials = parsed.map((item) => {
      this._assertStoredShape(item);
      return Credential.fromObject({
        id: item.id,
        website: item.website,
        username: this.encryption.decrypt(item.username),
        password: this.encryption.decrypt(item.password),
        notes: this.encryption.decrypt(item.notes),
        created_at: item.created_at,
        updated_at: item.updated_at,
      });
    });
  }

  /**
   * Persist the vault to disk with sensitive fields encrypted.
   */
  save() {
    const dir = path.dirname(this.vaultPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const serialized = this.credentials.map((cred) => ({
      id: cred.id,
      website: cred.website,
      username: this.encryption.encrypt(cred.username),
      password: this.encryption.encrypt(cred.password),
      notes: this.encryption.encrypt(cred.notes || ''),
      created_at: cred.created_at,
      updated_at: cred.updated_at,
    }));

    fs.writeFileSync(this.vaultPath, JSON.stringify(serialized, null, 2), {
      encoding: 'utf8',
      mode: 0o600,
    });
  }

  /**
   * Add a new credential.
   * @param {{ website: string, username: string, password: string, notes?: string }} data
   * @returns {Credential}
   */
  addCredential(data) {
    this._validateFields(data);
    const now = new Date().toISOString();
    const credential = new Credential({
      id: crypto.randomUUID(),
      website: data.website.trim(),
      username: data.username.trim(),
      password: data.password,
      notes: (data.notes || '').trim(),
      created_at: now,
      updated_at: now,
    });
    this.credentials.push(credential);
    this.save();
    return credential;
  }

  /**
   * Update an existing credential by id.
   * @param {string} id
   * @param {{ website?: string, username?: string, password?: string, notes?: string }} updates
   * @returns {Credential}
   */
  updateCredential(id, updates) {
    const credential = this.getById(id);
    if (!credential) {
      throw new Error('Credential not found.');
    }

    if (updates.website !== undefined) {
      if (!String(updates.website).trim()) {
        throw new Error('Website cannot be empty.');
      }
      credential.website = String(updates.website).trim();
    }
    if (updates.username !== undefined) {
      if (!String(updates.username).trim()) {
        throw new Error('Username cannot be empty.');
      }
      credential.username = String(updates.username).trim();
    }
    if (updates.password !== undefined) {
      if (!String(updates.password)) {
        throw new Error('Password cannot be empty.');
      }
      credential.password = String(updates.password);
    }
    if (updates.notes !== undefined) {
      credential.notes = String(updates.notes).trim();
    }

    credential.updated_at = new Date().toISOString();
    this.save();
    return credential;
  }

  /**
   * Delete a credential by id.
   * @param {string} id
   * @returns {boolean}
   */
  deleteCredential(id) {
    const index = this.credentials.findIndex((c) => c.id === id);
    if (index === -1) {
      return false;
    }
    this.credentials.splice(index, 1);
    this.save();
    return true;
  }

  /**
   * List all credentials.
   * @returns {Credential[]}
   */
  listCredentials() {
    return [...this.credentials];
  }

  /**
   * Find a credential by id.
   * @param {string} id
   * @returns {Credential|undefined}
   */
  getById(id) {
    return this.credentials.find((c) => c.id === id);
  }

  /**
   * Case-insensitive search by website and/or username.
   * @param {{ website?: string, username?: string }} query
   * @returns {Credential[]}
   */
  search({ website, username } = {}) {
    const websiteQ = (website || '').trim().toLowerCase();
    const usernameQ = (username || '').trim().toLowerCase();

    if (!websiteQ && !usernameQ) {
      return [];
    }

    return this.credentials.filter((cred) => {
      const websiteMatch = websiteQ
        ? cred.website.toLowerCase().includes(websiteQ)
        : true;
      const usernameMatch = usernameQ
        ? cred.username.toLowerCase().includes(usernameQ)
        : true;
      return websiteMatch && usernameMatch;
    });
  }

  /**
   * Export vault data as a JSON string (decrypted in-memory values).
   * @returns {string}
   */
  exportToJson() {
    const payload = {
      exported_at: new Date().toISOString(),
      credentials: this.credentials.map((c) => c.toObject()),
    };
    return JSON.stringify(payload, null, 2);
  }

  /**
   * Write an export file to the given path.
   * @param {string} exportPath
   */
  exportToFile(exportPath) {
    fs.writeFileSync(exportPath, this.exportToJson(), {
      encoding: 'utf8',
      mode: 0o600,
    });
  }

  /**
   * @private
   * @param {{ website: string, username: string, password: string }} data
   */
  _validateFields(data) {
    if (!data || !String(data.website || '').trim()) {
      throw new Error('Website is required.');
    }
    if (!String(data.username || '').trim()) {
      throw new Error('Username is required.');
    }
    if (!String(data.password || '')) {
      throw new Error('Password is required.');
    }
  }

  /**
   * @private
   * @param {object} item
   */
  _assertStoredShape(item) {
    if (
      !item ||
      typeof item.id !== 'string' ||
      typeof item.website !== 'string' ||
      typeof item.username !== 'string' ||
      typeof item.password !== 'string' ||
      typeof item.notes !== 'string' ||
      typeof item.created_at !== 'string' ||
      typeof item.updated_at !== 'string'
    ) {
      throw new Error('Vault file is corrupted: invalid credential record.');
    }
  }
}

module.exports = { VaultManager };
