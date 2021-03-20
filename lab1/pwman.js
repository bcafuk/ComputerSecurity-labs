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

const usage = `usage:
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

const [command, address] = process.argv.slice(2);

switch (command) {
  case "init":
    inquirer.prompt(masterPasswordPrompt).then((answers) => {
      const { masterPassword } = answers;
    });

    break;

  case "put":
    if (!address) exit(1, usage);

    inquirer
      .prompt([
        masterPasswordPrompt,
        {
          type: "password",
          name: "sitePassword",
          message: `Site password for ${address}`,
        },
      ])
      .then((answers) => {
        const { masterPassword, sitePassword } = answers;
      });

    break;

  case "get":
    if (!address) exit(1, usage);

    inquirer.prompt(masterPasswordPrompt).then((answers) => {
      const { masterPassword } = answers;
    });

    break;

  case undefined:
  default:
    exit(1, usage);
}
