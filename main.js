'use strict';

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { MasterPasswordManager } = require('./masterPassword');
const { EncryptionManager } = require('./encryptionManager');
const { VaultManager } = require('./vaultManager');
const { PasswordGenerator } = require('./passwordGenerator');

const SESSION_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * Command-line interface for the Password Manager.
 */
class CLI {
  constructor() {
    this.storageDir = path.join(__dirname, 'storage');
    this.masterPath = path.join(this.storageDir, 'master.json');
    this.vaultPath = path.join(this.storageDir, 'vault.json');
    this.keyPath = path.join(this.storageDir, 'key.key');

    this.masterManager = new MasterPasswordManager(this.masterPath);
    this.encryptionManager = new EncryptionManager(this.keyPath);
    /** @type {VaultManager|null} */
    this.vaultManager = null;
    this.passwordGenerator = new PasswordGenerator();

    this.lastActivity = Date.now();
    /** @type {readline.Interface|null} */
    this.rl = null;
  }

  /**
   * Entry point.
   * @returns {Promise<void>}
   */
  async run() {
    this._ensureStorageDir();
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true,
    });

    try {
      console.log('\n=== Secure Password Manager ===\n');

      if (!this.masterManager.isConfigured()) {
        await this._setupMasterPassword();
      } else {
        const ok = await this._login();
        if (!ok) {
          console.log('Access denied. Exiting.');
          return;
        }
      }

      this.encryptionManager.ensureKey();
      this.vaultManager = new VaultManager(this.vaultPath, this.encryptionManager);
      this.vaultManager.load();
      this._touch();

      await this._mainLoop();
    } catch (err) {
      console.error(`\nFatal error: ${err.message}`);
    } finally {
      this.encryptionManager.clearKey();
      if (this.rl) {
        this.rl.close();
      }
    }
  }

  /**
   * @private
   */
  _ensureStorageDir() {
    if (!fs.existsSync(this.storageDir)) {
      fs.mkdirSync(this.storageDir, { recursive: true });
    }
  }

  /**
   * @private
   * @returns {Promise<void>}
   */
  async _setupMasterPassword() {
    console.log('First launch — create a Master Password.\n');
    console.log('Rules: min 12 chars, uppercase, lowercase, number, special character.\n');

    while (true) {
      const password = await this._askHidden('Create Master Password: ');
      const confirm = await this._askHidden('Confirm Master Password: ');

      if (password !== confirm) {
        console.log('Passwords do not match. Try again.\n');
        continue;
      }

      try {
        this.masterManager.createMasterPassword(password);
        console.log('\nMaster Password created successfully.\n');
        return;
      } catch (err) {
        console.log(`\n${err.message}\n`);
      }
    }
  }

  /**
   * @private
   * @returns {Promise<boolean>}
   */
  async _login() {
    console.log('Please log in with your Master Password.\n');

    while (!this.masterManager.isLockedOut()) {
      const password = await this._askHidden('Master Password: ');
      try {
        if (this.masterManager.verifyPassword(password)) {
          console.log('\nLogin successful.\n');
          return true;
        }
        const remaining = this.masterManager.remainingAttempts();
        console.log(
          `\nIncorrect password. Attempts remaining: ${remaining}\n`
        );
      } catch (err) {
        console.log(`\n${err.message}`);
        return false;
      }
    }

    console.log('\nToo many failed attempts.');
    return false;
  }

  /**
   * @private
   * @returns {Promise<void>}
   */
  async _mainLoop() {
    while (true) {
      if (this._isSessionExpired()) {
        console.log('\nSession timed out. Please log in again.\n');
        const ok = await this._login();
        if (!ok) {
          console.log('Access denied. Exiting.');
          return;
        }
        this._touch();
      }

      this._printMenu();
      const choice = (await this._ask('Select an option: ')).trim();
      this._touch();

      try {
        switch (choice) {
          case '1':
            await this._addCredential();
            break;
          case '2':
            await this._viewCredentials();
            break;
          case '3':
            await this._searchCredential();
            break;
          case '4':
            await this._updateCredential();
            break;
          case '5':
            await this._deleteCredential();
            break;
          case '6':
            await this._generatePassword();
            break;
          case '7':
            await this._exportVault();
            break;
          case '8':
            console.log('\nGoodbye.');
            return;
          default:
            console.log('\nInvalid option. Please choose 1–8.\n');
        }
      } catch (err) {
        console.log(`\nError: ${err.message}\n`);
      }
    }
  }

  /**
   * @private
   */
  _printMenu() {
    console.log('---------- Main Menu ----------');
    console.log('1. Add Credential');
    console.log('2. View Credentials');
    console.log('3. Search Credential');
    console.log('4. Update Credential');
    console.log('5. Delete Credential');
    console.log('6. Generate Password');
    console.log('7. Export Vault');
    console.log('8. Exit');
    console.log('--------------------------------');
  }

  /**
   * @private
   * @returns {Promise<void>}
   */
  async _addCredential() {
    console.log('\n--- Add Credential ---');
    const website = (await this._ask('Website: ')).trim();
    const username = (await this._ask('Username: ')).trim();
    let password = await this._askHidden('Password (leave empty to generate): ');

    if (!password) {
      password = this.passwordGenerator.generate({ length: 16 });
      console.log('Generated a secure password (not displayed here for safety).');
      const reveal = (await this._ask('Show generated password? (y/N): '))
        .trim()
        .toLowerCase();
      if (reveal === 'y' || reveal === 'yes') {
        console.log(`Generated password: ${password}`);
      }
    }

    const notes = (await this._ask('Notes (optional): ')).trim();
    const cred = this.vaultManager.addCredential({
      website,
      username,
      password,
      notes,
    });
    console.log(`\nCredential added (ID: ${cred.id}).\n`);
  }

  /**
   * @private
   * @returns {Promise<void>}
   */
  async _viewCredentials() {
    console.log('\n--- Stored Credentials ---');
    const list = this.vaultManager.listCredentials();
    if (list.length === 0) {
      console.log('No credentials stored.\n');
      return;
    }

    list.forEach((cred, index) => {
      console.log(`\n[${index + 1}] ID: ${cred.id}`);
      console.log(`    Website : ${cred.website}`);
      console.log(`    Username: ${cred.username}`);
      console.log(`    Notes   : ${cred.notes || '(none)'}`);
      console.log(`    Created : ${cred.created_at}`);
      console.log(`    Updated : ${cred.updated_at}`);
    });

    const show = (await this._ask('\nReveal a password by number (Enter to skip): ')).trim();
    if (show) {
      const idx = Number(show) - 1;
      if (Number.isInteger(idx) && idx >= 0 && idx < list.length) {
        console.log(`Password: ${list[idx].password}`);
      } else {
        console.log('Invalid selection.');
      }
    }
    console.log('');
  }

  /**
   * @private
   * @returns {Promise<void>}
   */
  async _searchCredential() {
    console.log('\n--- Search Credential ---');
    const website = (await this._ask('Website (optional): ')).trim();
    const username = (await this._ask('Username (optional): ')).trim();

    if (!website && !username) {
      console.log('Enter at least a website or username to search.\n');
      return;
    }

    const results = this.vaultManager.search({ website, username });
    if (results.length === 0) {
      console.log('No matches found.\n');
      return;
    }

    console.log(`\nFound ${results.length} result(s):`);
    results.forEach((cred, index) => {
      console.log(`\n[${index + 1}] ${cred.website} | ${cred.username}`);
      console.log(`    ID: ${cred.id}`);
      console.log(`    Notes: ${cred.notes || '(none)'}`);
    });
    console.log('');
  }

  /**
   * @private
   * @returns {Promise<void>}
   */
  async _updateCredential() {
    console.log('\n--- Update Credential ---');
    const list = this.vaultManager.listCredentials();
    if (list.length === 0) {
      console.log('No credentials to update.\n');
      return;
    }

    list.forEach((cred, index) => {
      console.log(`[${index + 1}] ${cred.website} (${cred.username}) — ${cred.id}`);
    });

    const selection = (await this._ask('Select number to update: ')).trim();
    const idx = Number(selection) - 1;
    if (!Number.isInteger(idx) || idx < 0 || idx >= list.length) {
      console.log('Invalid selection.\n');
      return;
    }

    const current = list[idx];
    console.log('Leave a field empty to keep the current value.');

    const website = (await this._ask(`Website [${current.website}]: `)).trim();
    const username = (await this._ask(`Username [${current.username}]: `)).trim();
    const password = await this._askHidden('New password (empty = keep): ');
    const notes = (await this._ask(`Notes [${current.notes || ''}]: `)).trim();

    /** @type {object} */
    const updates = {};
    if (website) updates.website = website;
    if (username) updates.username = username;
    if (password) updates.password = password;
    if (notes !== '') updates.notes = notes;

    if (Object.keys(updates).length === 0) {
      console.log('No changes made.\n');
      return;
    }

    this.vaultManager.updateCredential(current.id, updates);
    console.log('\nCredential updated.\n');
  }

  /**
   * @private
   * @returns {Promise<void>}
   */
  async _deleteCredential() {
    console.log('\n--- Delete Credential ---');
    const list = this.vaultManager.listCredentials();
    if (list.length === 0) {
      console.log('No credentials to delete.\n');
      return;
    }

    list.forEach((cred, index) => {
      console.log(`[${index + 1}] ${cred.website} (${cred.username}) — ${cred.id}`);
    });

    const selection = (await this._ask('Select number to delete: ')).trim();
    const idx = Number(selection) - 1;
    if (!Number.isInteger(idx) || idx < 0 || idx >= list.length) {
      console.log('Invalid selection.\n');
      return;
    }

    const target = list[idx];
    const confirm = (
      await this._ask(`Delete "${target.website}" / ${target.username}? (y/N): `)
    )
      .trim()
      .toLowerCase();

    if (confirm !== 'y' && confirm !== 'yes') {
      console.log('Cancelled.\n');
      return;
    }

    this.vaultManager.deleteCredential(target.id);
    console.log('\nCredential deleted.\n');
  }

  /**
   * @private
   * @returns {Promise<void>}
   */
  async _generatePassword() {
    console.log('\n--- Generate Password ---');
    const lengthRaw = (await this._ask('Length [16]: ')).trim();
    const length = lengthRaw ? Number(lengthRaw) : 16;

    const includeUppercase = await this._askYesNo('Include uppercase? (Y/n): ', true);
    const includeNumbers = await this._askYesNo('Include numbers? (Y/n): ', true);
    const includeSymbols = await this._askYesNo('Include symbols? (Y/n): ', true);

    const password = this.passwordGenerator.generate({
      length,
      includeUppercase,
      includeNumbers,
      includeSymbols,
    });

    console.log(`\nGenerated password: ${password}\n`);
  }

  /**
   * @private
   * @returns {Promise<void>}
   */
  async _exportVault() {
    console.log('\n--- Export Vault ---');
    console.log('Master Password verification required.\n');

    const password = await this._askHidden('Master Password: ');
    if (!this.masterManager.verifyPassword(password)) {
      console.log('\nVerification failed. Export aborted.\n');
      return;
    }

    const defaultName = `vault-export-${Date.now()}.json`;
    const name = (
      await this._ask(`Export filename [${defaultName}]: `)
    ).trim() || defaultName;

    const exportPath = path.isAbsolute(name)
      ? name
      : path.join(this.storageDir, name);

    this.vaultManager.exportToFile(exportPath);
    console.log(`\nVault exported to: ${exportPath}\n`);
  }

  /**
   * @private
   */
  _touch() {
    this.lastActivity = Date.now();
  }

  /**
   * @private
   * @returns {boolean}
   */
  _isSessionExpired() {
    return Date.now() - this.lastActivity > SESSION_TIMEOUT_MS;
  }

  /**
   * @private
   * @param {string} prompt
   * @returns {Promise<string>}
   */
  _ask(prompt) {
    return new Promise((resolve) => {
      this.rl.question(prompt, (answer) => resolve(answer ?? ''));
    });
  }

  /**
   * Hidden password input (no echo).
   * @private
   * @param {string} prompt
   * @returns {Promise<string>}
   */
  _askHidden(prompt) {
    return new Promise((resolve) => {
      const stdin = process.stdin;
      const stdout = process.stdout;

      if (!stdin.isTTY) {
        this.rl.question(prompt, (answer) => resolve(answer ?? ''));
        return;
      }

      this.rl.pause();
      stdout.write(prompt);

      const wasRaw = Boolean(stdin.isRaw);
      stdin.setRawMode(true);
      stdin.resume();

      let password = '';

      const cleanup = () => {
        stdin.removeListener('data', onData);
        if (stdin.isTTY) {
          stdin.setRawMode(wasRaw);
        }
        this.rl.resume();
      };

      const onData = (chunk) => {
        const char = chunk.toString('utf8');

        if (char === '\n' || char === '\r' || char === '\u0004') {
          cleanup();
          stdout.write('\n');
          resolve(password);
          return;
        }

        if (char === '\u0003') {
          cleanup();
          stdout.write('\n');
          process.exit(0);
        }

        if (char === '\u007f' || char === '\b') {
          if (password.length > 0) {
            password = password.slice(0, -1);
          }
          return;
        }

        if (char === '\u001b') {
          return;
        }

        password += char;
      };

      stdin.on('data', onData);
    });
  }

  /**
   * @private
   * @param {string} prompt
   * @param {boolean} defaultYes
   * @returns {Promise<boolean>}
   */
  async _askYesNo(prompt, defaultYes) {
    const answer = (await this._ask(prompt)).trim().toLowerCase();
    if (!answer) return defaultYes;
    if (answer === 'y' || answer === 'yes') return true;
    if (answer === 'n' || answer === 'no') return false;
    return defaultYes;
  }
}

async function main() {
  const cli = new CLI();
  await cli.run();
}

if (require.main === module) {
  main();
}

module.exports = { CLI };
