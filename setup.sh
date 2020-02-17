#!/bin/sh

# Create a Key
gpg --batch --yes --no-tty --gen-key ./config/gen-secp256k1.ecdsa
gpg --batch --yes --no-tty --gen-key ./config/gen-ed25519.eddsa

# # Sign and Verify
echo "secret" | gpg --batch --pinentry-mode loopback --command-fd 0 -u "Test User (ed25519)" --sign-key "Test User (secp256k1)"
# gpg --verify ./data/doc2.sig 

# # Export Armored Public Key
# gpg --export -a "Alice" > ./data/public_key.asc

# # Export a Private Key
# echo "secret" | gpg --batch --pinentry-mode loopback --command-fd 0 --export-secret-key "Alice" > ./data/private.key
# # Armored
# echo "secret" | gpg --batch --pinentry-mode loopback --command-fd 0 --export-secret-key -a "Alice" > ./data/private_key.asc
# # cat private.key

# # Export All
# # gpg -a --export > ./data/public_keys.asc
# # echo "secret" | gpg --batch --pinentry-mode loopback --command-fd 0 -a --export-secret-keys > ./data/private_keys.asc
# gpg --export-ownertrust > ./data/trust.txt

# npm run test:ci

gpg --output ./data/sec_revocation_cert.asc -u "Test User (secp256k1)" --gen-revoke DEDC7F21177BC0F6A2ADE0B0B4938ECC40652D30
gpg --export -a "Test User (ed25519)" > ./data/ed_revoked_public_key.asc
gpg --import revoke.asc




    const armoredEdPub = (await fs.readFileAsync(
      path.join(__dirname, '../../../data/ed_public_key.asc')
    )).toString();
    const edPub = openpgp.key.readArmored(
      armoredEdPub
    ).keys[0];
    test_user_ed_public_key = edPub;

    const armoredSecPub = (await fs.readFileAsync(
      path.join(__dirname, '../../../data/sec_public_key.asc')
    )).toString();
    const secPub = openpgp.key.readArmored(
      armoredSecPub
    ).keys[0];
    test_user_sec_public_key = secPub;