/*
 * login.js, a user authentication tool.
 * usermgmt.js, a user account management tool.
 *
 * Made for the second laboratory assignment for the course Computer Security
 * at the Faculty of Electrical Engineering and Computing
 * at the University of Zagreb, Croatia in the academic year 2020/2021.
 *
 * © 2021 Borna Cafuk, All rights reserved
 * JMBAG (matriculation number): 0036513396
 */
const { promisify } = require("util");
const crypto = require("crypto");

const FORMAT_IDENTIFIER = "usermgmt";
const VERSION = 2;

const SALT_SIZE = 32;
const KEY_LENGTH = 64;

const scrypt = promisify(crypto.scrypt);
const randomBytes = promisify(crypto.randomBytes);

function assertType(value, expectedType, description = "the value") {
  if (value === null)
    throw new Error(
      `Expected ${description} to be of type ${expectedType}, but was null`
    );
  if (typeof value !== expectedType)
    throw new Error(
      `Expected ${description} to be of type ${expectedType}, but was ${typeof value}`
    );
}

async function hashPassword(salt, password) {
  return await scrypt(Buffer.from(password, "utf-8"), salt, KEY_LENGTH);
}

class PasswordHash {
  #salt;
  #hash;

  constructor(salt, hash) {
    this.#salt = salt;
    this.#hash = hash;
  }

  static async generate(password) {
    const salt = await randomBytes(SALT_SIZE);
    return new PasswordHash(salt, await hashPassword(salt, password));
  }

  async matches(password) {
    if (this.#hash.length !== KEY_LENGTH) return false;

    const expectedHash = await hashPassword(this.#salt, password);
    return crypto.timingSafeEqual(this.#hash, expectedHash);
  }

  static deserialize(rawObject) {
    assertType(rawObject.salt, "string", "the salt");
    assertType(rawObject.hash, "string", "the password hash");

    return new PasswordHash(
      Buffer.from(rawObject.salt, "base64"),
      Buffer.from(rawObject.hash, "base64")
    );
  }

  serialize() {
    return {
      salt: this.#salt.toString("base64"),
      hash: this.#hash.toString("base64"),
    };
  }
}

class UserEntry {
  #currentPassword;
  #oldPasswords = [];
  changeForced = false;

  static async create(password) {
    const entry = new UserEntry();
    entry.#currentPassword = await PasswordHash.generate(password);
    return entry;
  }

  async check(password) {
    return await this.#currentPassword.matches(password);
  }

  async hasBeenUsed(password) {
    if (await this.#currentPassword.matches(password)) return true;

    for (const oldPassword of this.#oldPasswords)
      if (await oldPassword.matches(password)) return true;

    return false;
  }

  async setPassword(password) {
    if (await this.hasBeenUsed(password))
      throw new Error("Reusing a password is not allowed");

    this.#oldPasswords.push(this.#currentPassword);
    this.#currentPassword = await PasswordHash.generate(password);
  }

  static deserialize(rawObject) {
    const entry = new UserEntry();

    assertType(rawObject.currentPassword, "object", "the current password");
    entry.#currentPassword = PasswordHash.deserialize(
      rawObject.currentPassword
    );

    assertType(rawObject.changeForced, "boolean", "the change flag");
    entry.changeForced = rawObject.changeForced;

    for (const rawPassword of rawObject.oldPasswords) {
      assertType(rawPassword, "object", "the old password");
      entry.#oldPasswords.push(PasswordHash.deserialize(rawPassword));
    }

    return entry;
  }

  serialize() {
    return {
      currentPassword: this.#currentPassword.serialize(),
      oldPasswords: this.#oldPasswords.map((oldPassword) =>
        oldPassword.serialize()
      ),
      changeForced: this.changeForced,
    };
  }
}

class HashStore {
  #userEntries = new Map();

  containsUser(username) {
    return this.#userEntries.has(username);
  }

  async put(username, password) {
    const userEntry = this.#userEntries.get(username);

    if (userEntry !== undefined) {
      await userEntry.setPassword(password);
      userEntry.changeForced = false;
    } else {
      this.#userEntries.set(username, await UserEntry.create(password));
    }
  }

  async check(username, password) {
    const entry = this.#userEntries.get(username);

    if (entry === undefined) return false;

    return await entry.check(password);
  }

  remove(username) {
    this.#userEntries.delete(username);
  }

  isChangeForced(username) {
    return this.#userEntries.get(username).changeForced;
  }

  forceChange(username) {
    this.#userEntries.get(username).changeForced = true;
  }

  static #deserialize(json) {
    const storeObject = JSON.parse(json);

    if (storeObject.format !== FORMAT_IDENTIFIER)
      throw new Error("The hash store file is of the wrong format");

    if (storeObject.version !== VERSION)
      throw new Error(
        `Unknown hash store file version: ${storeObject.version}`
      );

    const hashStore = new HashStore();
    for (const [username, rawEntry] of storeObject.entries) {
      assertType(username, "string", "the username");
      assertType(rawEntry, "object", `the entry for ${username}`);

      hashStore.#userEntries.set(username, UserEntry.deserialize(rawEntry));
    }

    return hashStore;
  }

  #serialize() {
    const rawEntries = [];

    for (const [username, entry] of this.#userEntries)
      rawEntries.push([username, entry.serialize()]);

    return JSON.stringify({
      format: FORMAT_IDENTIFIER,
      version: VERSION,
      entries: rawEntries,
    });
  }

  static async read(file) {
    const json = await file.readFile("utf-8");
    return HashStore.#deserialize(json);
  }

  async write(file) {
    const json = this.#serialize();
    await file.truncate(0);
    await file.write(json, 0, "utf-8");
  }
}

module.exports = HashStore;
