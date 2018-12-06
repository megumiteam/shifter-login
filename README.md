# Shifter Login

A magic link login plugin for WordPress sites on Shifter

## Usage

`wp shiter-login`

### Login

Login command paired with a valid and registered user email will return a token based magic link that is valid for 10 minues.

`wp shifter-login login`

| Argument     | Description                                | Example                                         |
|--------------|--------------------------------------------|-------------------------------------------------|
| --user_email | A valid user and registered email address  | wp shifer-login login --user_email=foo@bar.baz  |