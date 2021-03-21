const util = require("util");
const crypto = require("crypto");

const DERIVE_HASH_ALGORITHM = "sha256";
const SALT_SIZE = 32;
const KEY_LENGTH = 32;

const DIGEST_ALGORITHM = "sha256";
const DIGEST_SIZE = 256 / 8;

const CIPHER_ALGORITHM = "aes-256-cbc";
const IV_SIZE = 256 / 8;

function deriveKey(password, salt) {
  return util.promisify(crypto.pbkdf2)(
    Buffer.from(password, "ascii"),
    salt,
    100000,
    KEY_LENGTH,
    DERIVE_HASH_ALGORITHM
  );
}

function createHmac(key) {
  return crypto.createHmac(DIGEST_ALGORITHM, key);
}

function createCipher(key, iv) {
  return crypto.createCipheriv(CIPHER_ALGORITHM, key, iv);
}
function createDecipher(key, iv) {
  return crypto.createDecipheriv(CIPHER_ALGORITHM, key, iv);
}

const randomBytes = util.promisify(crypto.randomBytes);

class PasswordStore {
  #salt;
  #sitePasswords = new Map(); // Secret!

  constructor(salt) {
    this.#salt = salt;
  }

  put(address, sitePassword) {
    this.#sitePasswords.set(address, sitePassword);
  }

  get(address) {
    const sitePassword = this.#sitePasswords.get(address);
    if (sitePassword === undefined)
      throw new Error(`No password exists for the address ${address}`);
    return sitePassword;
  }

  #deriveKey(masterPassword) {
    return deriveKey(masterPassword, this.#salt);
  }

  static async initialize() {
    return new PasswordStore(await randomBytes(SALT_SIZE));
  }

  static async read(file, masterPassword) {
    // TODO: Reading from file
    return await PasswordStore.initialize();
  }

  async write(file, masterPassword) {
    // TODO: Writing to file
  }
}

module.exports = PasswordStore;
