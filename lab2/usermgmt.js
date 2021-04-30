/*
 * usermgmt.js
 *
 * A user account management tool.
 *
 * Made for the second laboratory assignment for the course Computer Security
 * at the Faculty of Electrical Engineering and Computing
 * at the University of Zagreb, Croatia in the academic year 2020/2021.
 *
 * © 2021 Borna Cafuk, All rights reserved
 * JMBAG (matriculation number): 0036513396
 */
const fsPromises = require("fs/promises");
const fs = require("fs");
const prompts = require("prompts");
const HashStore = require("./HashStore");
const {
  STORE_FILENAME,
  PASSWORD_REQUIREMENTS,
  validatePassword,
} = require("./common");

const USAGE = `usage: node usermgmt.js <command> <username>
    accepted commands:
        add       - adds a new user to the database
        passwd    - changes an existing user's password
        forcepass - forces a password change on a user's next login
        del       - deletes a user from the database`;

async function promptPassword(
  username,
  cancelMessage = "Password entry cancelled."
) {
  console.log(PASSWORD_REQUIREMENTS);

  const { password } = await prompts({
    type: "password",
    name: "password",
    message: `New password for ${username}`,
    validate: validatePassword,
  });
  if (password === undefined) throw new Error(cancelMessage);

  const { passwordRepeated } = await prompts({
    type: "password",
    name: "passwordRepeated",
    message: `Repeat new password for ${username}`,
    validate: (p) => (p === password ? true : "The passwords do not match."),
  });
  if (passwordRepeated === undefined) throw new Error(cancelMessage);

  return password;
}

function exit(code, reason) {
  if (reason) console.log(reason);
  process.exit(code);
}

async function loadStore() {
  const file = await fsPromises.open(
    STORE_FILENAME,
    fs.constants.O_RDWR | fs.constants.O_CREAT,
    0o600
  );
  const stats = await file.stat();

  const store = stats.size === 0 ? new HashStore() : await HashStore.read(file);
  return [file, store];
}

async function add(username) {
  const [file, store] = await loadStore();

  if (store.containsUser(username))
    throw new Error(`The user ${username} already exists in the database.`);

  const password = await promptPassword(username, "Adding user cancelled");

  await store.put(username, password);
  await store.write(file);
  file.close();
}

async function passwd(username) {
  const [file, store] = await loadStore();

  if (!store.containsUser(username))
    throw new Error(`The user ${username} doesn't exist in the database.`);

  const password = await promptPassword(
    username,
    "Changing password cancelled"
  );

  await store.put(username, password);
  await store.write(file);
  file.close();
}

async function forcepass(username) {
  const [file, store] = await loadStore();

  if (!store.containsUser(username))
    throw new Error(`The user ${username} doesn't exist in the database.`);

  await store.forceChange(username);
  await store.write(file);
  file.close();
}

async function del(username) {
  const [file, store] = await loadStore();

  if (!store.containsUser(username))
    throw new Error(`The user ${username} doesn't exist in the database.`);

  await store.remove(username);
  await store.write(file);
  file.close();
}

const [command, username] = process.argv.slice(2);

if (!command || !username) exit(1, USAGE);

switch (command) {
  case "add":
    add(username)
      .then(() => console.log(`User ${username} successfully added.`))
      .catch((reason) => exit(2, reason.message));
    break;

  case "passwd":
    passwd(username)
      .then(() => console.log(`Successfully changed password of ${username}.`))
      .catch((reason) => exit(2, reason.message));
    break;

  case "forcepass":
    forcepass(username)
      .then(() =>
        console.log(
          `${username} will be required to change their password on next login.`
        )
      )
      .catch((reason) => exit(2, reason.message));
    break;

  case "del":
    del(username)
      .then(() =>
        console.log(`User ${username} successfully removed from the database.`)
      )
      .catch((reason) => exit(2, reason.message));
    break;

  default:
    exit(1, USAGE);
}
