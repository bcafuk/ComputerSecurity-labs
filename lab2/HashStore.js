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

const STORE_FILENAME = "usermgmt.json";

const FORMAT_IDENTIFIER = "usermgmt";
const VERSION = 1;

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

class UserEntry {
  salt;
  hash;
  changeForced;

  constructor(salt, hash, changeForced = false) {
    this.salt = salt;
    this.hash = hash;
    this.changeForced = changeForced;
  }
}

class HashStore {
  #userEntries = new Map();

  async put(username, password) {
    const salt = await randomBytes(SALT_SIZE);
    const entry = new UserEntry(salt, await hashPassword(salt, password));
    this.#userEntries.set(username, entry);
  }

  async check(username, expectedPassword) {
    const entry = this.#userEntries.get(username);

    if (entry === undefined) return false;
    if (entry.hash.length !== KEY_LENGTH) return false;

    const expectedHash = await hashPassword(entry.salt, expectedPassword);
    return crypto.timingSafeEqual(entry.hash, expectedHash);
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
      assertType(rawEntry.salt, "string", `the salt for ${username}`);
      assertType(rawEntry.hash, "string", `the password hash for ${username}`);
      assertType(
        rawEntry.changeForced,
        "boolean",
        `the change flag for ${username}`
      );

      hashStore.#userEntries.set(
        username,
        new UserEntry(
          Buffer.from(rawEntry.salt, "base64"),
          Buffer.from(rawEntry.hash, "base64"),
          rawEntry.changeForced
        )
      );
    }

    return hashStore;
  }

  #serialize() {
    const rawEntries = [];

    for (const [username, entry] of this.#userEntries) {
      rawEntries.push([
        username,
        {
          salt: entry.salt.toString("base64"),
          hash: entry.hash.toString("base64"),
          changeForced: entry.changeForced,
        },
      ]);
    }

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

module.exports = {
  HashStore,
  STORE_FILENAME,
};
