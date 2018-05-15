# sec-ed-cert
This is a simple repository that allows you to generate PGP keys with openPGP and importing them into GPG.

The reason why you may want to do this is in the case where you need to use different kinds of curves for different technologies. For instance, if you have an ed25519 key, you will be unable to use this with Ethereum or Bitcoin (which use secp256k1). To address this, you create a secp256k1 key and sign it with the private key of your ed25519 key and vice versa - this shows that you control both keys and that they trust one-another.

## Dependencies

Before you get started, you should have [node](https://nodejs.org/en/download/) and [GPG](https://www.gnupg.org/download/) installed. You can also insatll gpg with [brew, yum, or apt-get](http://blog.ghostinthemachines.com/2015/03/01/how-to-use-gpg-command-line/).

## Env

This repository includes a `.env` file at the root directory. The variables stored in here will directly affect the metadata (Real-Name / Email) and passphrases for the ed25519 and secp256k1 keys that will be generated.

## Commands

`npm run test` will create a ed25519 and secp256k1 keypair with the variables from `.env`, have them sign each other with their private keys (create certs), and then export the armored public and private keys of both to `data` directory.

`npm run import` will run the `import_privkeys.sh` script, which will import the generated private keys into your gpg keyring.

`npm run clean` will remove all of the files in the `data` directory.

## Contributing
If anything here is unclear, innaccurate, or could be improved, please submit an issue or make a pull request.
