/*
 * pwman.js
 *
 * A simple password manager.
 *
 * Made for the first laboratory assignment for the course Computer Security
 * at the Faculty of Electrical Engineering and Computing
 * at the University of Zagreb, Croatia in the academic year 2020/2021.
 *
 * © 2021 Borna Cafuk, All rights reserved
 * JMBAG (matriculation number): 0036513396
 */
const { promisify } = require("util");
const crypto = require("crypto");

const FORMAT_IDENTIFIER = Buffer.from("pwmanjs", "ascii");
const VERSION = 1;
const HEADER_SIZE = FORMAT_IDENTIFIER.length + 2;

const DERIVE_HASH_ALGORITHM = "sha256";
const SALT_SIZE = 32;
const KEY_ITERATIONS = 100000;

const DIGEST_ALGORITHM = "sha256";
const DIGEST_SIZE = 256 / 8;
const DIGEST_KEY_LENGTH = 256 / 8;

const CIPHER_ALGORITHM = "aes-256-cbc";
const IV_SIZE = 128 / 8;
const CIPHER_KEY_LENGTH = 256 / 8;

const pbkdf2 = promisify(crypto.pbkdf2);
const randomBytes = promisify(crypto.randomBytes);

async function deriveKeys(salt, masterPassword) {
  const key = await pbkdf2(
    Buffer.from(masterPassword, "utf-8"),
    salt,
    KEY_ITERATIONS,
    DIGEST_KEY_LENGTH + CIPHER_KEY_LENGTH,
    DERIVE_HASH_ALGORITHM
  );

  return {
    digestKey: key.subarray(0, DIGEST_KEY_LENGTH),
    cipherKey: key.subarray(DIGEST_KEY_LENGTH),
  };
}

class PasswordStore {
  #sitePasswords = new Map(); // Secret!

  put(address, sitePassword) {
    this.#sitePasswords.set(address, sitePassword);
  }

  get(address) {
    const sitePassword = this.#sitePasswords.get(address);
    if (sitePassword === undefined)
      throw new Error(`No password exists for the address ${address}`);
    return sitePassword;
  }

  static async #deserialize(buffer, masterPassword) {
    const actualMagicNumber = buffer.subarray(0, FORMAT_IDENTIFIER.length);

    if (!actualMagicNumber.equals(FORMAT_IDENTIFIER))
      throw new Error(
        "The password store file is of the wrong format or corrupt"
      );

    const actualVersion = buffer.readUInt16BE(FORMAT_IDENTIFIER.length);
    if (actualVersion !== VERSION)
      throw new Error(`Unknown password store file version: ${actualVersion}`);

    const salt = buffer.subarray(HEADER_SIZE, HEADER_SIZE + SALT_SIZE);
    const actualDigest = buffer.subarray(
      HEADER_SIZE + SALT_SIZE,
      HEADER_SIZE + SALT_SIZE + DIGEST_SIZE
    );
    const ivAndCiphertext = buffer.subarray(
      HEADER_SIZE + SALT_SIZE + DIGEST_SIZE
    );

    const { digestKey, cipherKey } = await deriveKeys(salt, masterPassword);

    const hmac = crypto.createHmac(DIGEST_ALGORITHM, digestKey);
    hmac.update(ivAndCiphertext);
    const expectedDigest = hmac.digest();

    if (!crypto.timingSafeEqual(actualDigest, expectedDigest))
      throw new Error(
        "The password might be incorrect or the password store file may be corrupt"
      );

    const iv = ivAndCiphertext.subarray(0, IV_SIZE);
    const ciphertext = ivAndCiphertext.subarray(IV_SIZE);

    const decipher = crypto.createDecipheriv(CIPHER_ALGORITHM, cipherKey, iv);

    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString("utf-8");

    const passwordStore = new PasswordStore();
    passwordStore.#sitePasswords = new Map(JSON.parse(plaintext));
    return passwordStore;
  }

  async #serialize(masterPassword) {
    const header = Buffer.alloc(HEADER_SIZE);

    FORMAT_IDENTIFIER.copy(header);
    header.writeUInt16BE(VERSION, FORMAT_IDENTIFIER.length);

    const plaintext = Buffer.from(
      JSON.stringify([...this.#sitePasswords]),
      "utf-8"
    );

    const salt = await randomBytes(SALT_SIZE);
    const [{ digestKey, cipherKey }, iv] = await Promise.all([
      deriveKeys(salt, masterPassword),
      randomBytes(IV_SIZE),
    ]);

    const cipher = crypto.createCipheriv(CIPHER_ALGORITHM, cipherKey, iv);
    const ivAndCiphertext = Buffer.concat([
      iv,
      cipher.update(plaintext),
      cipher.final(),
    ]);

    const hmac = crypto.createHmac(DIGEST_ALGORITHM, digestKey);
    hmac.update(ivAndCiphertext);
    const digest = hmac.digest();

    return Buffer.concat([header, salt, digest, ivAndCiphertext]);
  }

  static async read(file, masterPassword) {
    const buffer = await file.readFile();
    return await PasswordStore.#deserialize(buffer, masterPassword);
  }

  async write(file, masterPassword) {
    const buffer = await this.#serialize(masterPassword);
    await file.truncate(buffer.length);
    await file.write(buffer, 0, buffer.length, 0);
  }
}

module.exports = PasswordStore;
