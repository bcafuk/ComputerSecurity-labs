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
const inquirer = require("inquirer");
const PasswordStore = require("./PasswordStore");

const STORE_FILENAME = "store.pwmanjs";
const USAGE = `usage:
    node pwman.js init
        Prompts for the master password, and
        creates an empty store in the current directory.
    node pwman.js put <address>
        Prompts for the master password,
        prompts for the site password, and
        saves the entered site password in the store.
        This command overwrites any existing password for the address.
    node pwman.js get <address>
        Prompts for the master password,
        and prints the stored site password for the given address.`;

const masterPasswordPrompt = {
  type: "password",
  name: "masterPassword",
  message: "Master password",
};

function exit(code, reason) {
  if (reason) console.log(reason);
  process.exit(code);
}

async function init(masterPassword) {
  // TODO: Creating file
  const file = null;

  const store = await PasswordStore.initialize(masterPassword);
  await store.write(file, masterPassword);
}

async function get(masterPassword, address) {
  // TODO: Opening file
  const file = null;

  const store = await PasswordStore.read(file, masterPassword);
  return store.get(address);
}

async function put(masterPassword, address, sitePassword) {
  // TODO: Opening file
  const file = null;

  const store = await PasswordStore.read(file, masterPassword);
  store.put(address, sitePassword);
  await store.write(file, masterPassword);
}

const [command, address] = process.argv.slice(2);

switch (command) {
  case "init":
    inquirer
      .prompt(masterPasswordPrompt)
      .then(({ masterPassword }) => init(masterPassword))
      .then(() => console.log("Password manager initialized."))
      .catch((reason) => exit(2, reason.message));

    break;

  case "put":
    if (!address) exit(1, USAGE);

    inquirer
      .prompt([
        masterPasswordPrompt,
        {
          type: "password",
          name: "sitePassword",
          message: `Site password for ${address}`,
        },
      ])
      .then(({ masterPassword, sitePassword }) =>
        put(masterPassword, address, sitePassword)
      )
      .then(() => console.log(`Stored password for ${address}`))
      .catch((reason) => exit(2, reason.message));

    break;

  case "get":
    if (!address) exit(1, USAGE);

    inquirer
      .prompt(masterPasswordPrompt)
      .then(({ masterPassword }) => get(masterPassword, address))
      .then((sitePassword) =>
        console.log(`The password for ${address} is ${sitePassword}`)
      )
      .catch((reason) => exit(2, reason.message));

    break;

  case undefined:
  default:
    exit(1, USAGE);
}
