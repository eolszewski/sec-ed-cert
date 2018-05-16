# sec-ed-cert
This is a simple repository that allows you to generate PGP keys with openPGP and importing them into GPG.

The reason why you may want to do this is in the case where you need to use different kinds of curves for different technologies. For instance, if you have an ed25519 key, you will be unable to use this with Ethereum or Bitcoin (which use secp256k1). To address this, you create a secp256k1 key and sign it with the private key of your ed25519 key and vice versa - this shows that you control both keys and that they trust one-another.

## Dependencies

Before you get started, you should have [node](https://nodejs.org/en/download/) and [GPG](https://www.gnupg.org/download/) installed. You can also insatll gpg with [brew, yum, or apt-get](http://blog.ghostinthemachines.com/2015/03/01/how-to-use-gpg-command-line/).

## Manual Instruction (GPG Only)
[Keysigning with GPG](https://wiki.debian.org/Keysigning) is a good reference and can be used as a how to for generating keys with GPG and signing other keys with them.

Included in this repository is a `config/` folder which will allow you to batch your GPG key configuration when generating new keys. These files allow you to specify the following fields:
- Key-Type
- Key-Curve
- Key-Usage
- Name-Real
- Name-Email
- Expire-Date
- Passphrase

Please modify them as needed. For the purposes of this repository, there is a focus on generating an secp256k1 and ed25519 keypair. 

These commands will generate these keys for you and add them to your gpg keyring:

```
gpg --batch --yes --gen-key ./config/gen-secp256k1.ecdsa
gpg --batch --yes --gen-key ./config/gen-ed25519.eddsa
```

After adding these keys, you can view the keys in your keyring with:

```
gpg --list-keys
```

Get the identifiers for each key (located under 'pub' when listing) and use the keys to sign one another like so:

```
gpg -u BEEA1E6AA72EADF515CE975179C30B5C7F1662E5 --sign-key AAA4850E4577112FF75B71F7B8BC5B8057CB3424
```

Note, the `-u` flag is to specify the local user that is going to be performing the `--sign-key` operation.

These commands will ask if you really wish to do this and ask for your passphrase. After inputting your passphrase, a certificate will be created on the key being signed, effectively stating that the signing key trusts them. 

You should now be able to upload these keys and use them with the Transmute Platform.

## Key Generation with OpenPGP.js

### Env

This repository includes a `.env` file at the root directory. The variables stored in here will directly affect the metadata (Real-Name / Email) and passphrases for the ed25519 and secp256k1 keys that will be generated.

### Commands

`npm run test` will create a ed25519 and secp256k1 keypair with the variables from `.env`, have them sign each other with their private keys (create certs), and then export the armored public and private keys of both to `data` directory.

`npm run import` will run the `import_privkeys.sh` script, which will import the generated private keys into your gpg keyring.

`npm run clean` will remove all of the files in the `data` directory.

## Contributing
If anything here is unclear, innaccurate, or could be improved, please submit an issue or make a pull request.
