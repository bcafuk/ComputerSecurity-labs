/*
 * login.js
 *
 * A user authentication tool.
 *
 * Made for the second laboratory assignment for the course Computer Security
 * at the Faculty of Electrical Engineering and Computing
 * at the University of Zagreb, Croatia in the academic year 2020/2021.
 *
 * © 2021 Borna Cafuk, All rights reserved
 * JMBAG (matriculation number): 0036513396
 */
const fsPromises = require("fs/promises");
const prompts = require("prompts");
const HashStore = require("./HashStore");
const {
  STORE_FILENAME,
  PASSWORD_REQUIREMENTS,
  validatePassword,
} = require("./common");

const USAGE = "usage: node login.js <username>";

function exit(code, reason) {
  if (reason) console.log(reason);
  process.exit(code);
}

async function login(username) {
  const file = await fsPromises.open(STORE_FILENAME, "r+");
  const store = await HashStore.read(file);

  const { password } = await prompts({
    type: "invisible",
    name: "password",
    message: `Password for ${username}`,
  });

  if (password === undefined) exit(3, "Login cancelled.");

  if (!(await store.check(username, password)))
    throw new Error("Username or password incorrect.");

  if (store.isChangeForced(username)) {
    console.log(
      `The administrator has required a password change on your account. Please choose a new password.\n${PASSWORD_REQUIREMENTS}`
    );

    const { newPassword } = await prompts({
      type: "password",
      name: "newPassword",
      message: `New password for ${username}`,
      validate: (p) => {
        return p === password
          ? "The new password must be different than the old password."
          : validatePassword(p);
      },
    });

    if (newPassword === undefined)
      throw new Error("Password change cancelled.");

    const { newPasswordRepeated } = await prompts({
      type: "password",
      name: "newPasswordRepeated",
      message: `Repeat new password for ${username}`,
      validate: (p) =>
        p === newPassword ? true : "The passwords do not match.",
    });

    if (newPasswordRepeated === undefined)
      throw new Error("Password change cancelled.");

    await store.put(username, newPassword);
    await store.write(file);
  }
}

const username = process.argv[2];
if (username === undefined) exit(1, USAGE);

login(username)
  .then(() => console.log("Login successful"))
  .catch((reason) => exit(2, reason.message));
