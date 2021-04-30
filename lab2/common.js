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
const STORE_FILENAME = "usermgmt.json";

const PASSWORD_REQUIREMENTS =
  "The password must be at least 8 characters long and must contain at least 1 lowercase letter, 1 uppercase letter and 1 digit.";

const LOWERCASE_REGEX = /[a-z]/;
const UPPERCASE_REGEX = /[A-Z]/;
const DIGIT_REGEX = /\d/;

function validatePassword(password) {
  if (password.length < 8)
    return "The password must be at least 8 characters long";

  if (password.search(LOWERCASE_REGEX) === -1)
    return "The password must have at 1 lowercase letter";

  if (password.search(UPPERCASE_REGEX) === -1)
    return "The password must have at 1 uppercase letter";

  if (password.search(DIGIT_REGEX) === -1)
    return "The password must have at 1 digit";

  return true;
}

module.exports = { STORE_FILENAME, PASSWORD_REQUIREMENTS, validatePassword };
