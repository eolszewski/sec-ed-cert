const _sodium = require('libsodium-wrappers');
const secrets = require('secrets.js-grempe');

const init_sodium = async () => {
    await _sodium.ready;
    return _sodium;
};

const ciphertext_to_plaintext = async (ciphertext, password) => {

    const password_key = await key_from_password_and_salt({
        password,
        salt: ciphertext.password_salt
    });

    return {
        data: await decrypt_json_with_password({
            data: ciphertext.data,
            key: password_key
        }),
    };
};

const decrypt_json_with_asymmetric_keypair = async (ciphertext, nonce, sender_public_key, recipient_private_key) => {
    const sodium = await init_sodium();

    const decrypted = sodium.crypto_box_open_easy(
        ciphertext,
        nonce,
        sender_public_key,
        recipient_private_key
    );

    return JSON.parse(new Buffer(decrypted).toString());
};

const decrypt_json_with_password = async ({ data, key }) => {
    const sodium = await init_sodium();

    const decrypted = sodium.crypto_secretbox_open_easy(
        sodium.from_hex(data.encrypted),
        sodium.from_hex(data.nonce),
        sodium.from_hex(key)
    );
    
    return JSON.parse(new Buffer(decrypted).toString());
};

const encrypt_json_with_asymmetric_keypair = async (data, nonce, recipient_public_key, sender_private_key) => {
    const sodium = await init_sodium();
    const data_string = JSON.stringify(data);

    const ciphertext = sodium.crypto_box_easy(
        data_string,
        nonce,
        recipient_public_key,
        sender_private_key
    );

    return ciphertext;
};

const encrypt_json_with_password = async ({ data, key }) => {
    const sodium = await init_sodium();
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const data_string = JSON.stringify(data);
    const encrypted = sodium.crypto_secretbox_easy(
        data_string,
        nonce,
        sodium.from_hex(key)
    );
    
    return {
        nonce: sodium.to_hex(nonce),
        encrypted: sodium.to_hex(encrypted)
    };
};

const key_from_password_and_salt = async ({ password, salt }) => {
    const sodium = await init_sodium();
    
    const id_password_key = sodium.to_hex(
        sodium.crypto_pwhash(
            sodium.crypto_box_SEEDBYTES,
            password,
            sodium.from_hex(salt),
            sodium.crypto_pwhash_OPSLIMIT_MIN,
            sodium.crypto_pwhash_MEMLIMIT_MIN,
            sodium.crypto_pwhash_ALG_DEFAULT
        )
    );

    return id_password_key;
};

const new_box_keypair = async () => {
    const sodium = await init_sodium();

    return sodium.crypto_box_keypair();
};

const new_keypair = async () => {
    const sodium = await init_sodium();

    let keypair = sodium.crypto_sign_keypair();

    return {
        publicKey: sodium.to_hex(keypair.publicKey),
        privateKey: sodium.to_hex(keypair.privateKey),
        keyType: keypair.keyType
    };
};

const new_nonce = async () => {
    const sodium = await init_sodium();

    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);

    return nonce;
};

const plaintext_to_ciphertext = async (plaintext, password) => {
    const sodium = await init_sodium();
    const password_salt = sodium.to_hex(
        sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES)
    );

    const password_key = await key_from_password_and_salt({
        password,
        salt: password_salt
    });

    return {
        password_salt: password_salt,
        data: await encrypt_json_with_password({
            data: plaintext,
            key: password_key
        }),
    };
};

const recovery_claim = async (primary, recovery) => {
    const sodium = await init_sodium();
    const message = `${primary.publicKey} <- ${recovery.publicKey}`;

    const recovery_attestation = sodium.crypto_sign_detached(
        message,
        sodium.from_hex(recovery.privateKey)
    );

    return {
        message,
        recovery_attestation: sodium.to_hex(recovery_attestation)
    };
};

const recovery_keypair_from_shares = async (shares) => {
    const recovery_keypair = secrets.combine(shares);

    return recovery_keypair;
};

const shares_from_recovery_keypair = async (recovery_keypair, share_num, share_threshold) => {
    const shares = secrets.share(recovery_keypair.privateKey, share_num, share_threshold);

    return shares;
};

const verify_recovery_keypair = async ({ claim, recovery }) => {
    const sodium = await init_sodium();

    const claim_signed_by_recovery = sodium.crypto_sign_verify_detached(
        sodium.from_hex(claim.recovery_attestation),
        claim.message,
        sodium.from_hex(recovery.publicKey)
    );

    return claim_signed_by_recovery;
};

module.exports = {
    ciphertext_to_plaintext,
    decrypt_json_with_asymmetric_keypair,
    encrypt_json_with_asymmetric_keypair,
    key_from_password_and_salt,
    new_box_keypair,
    new_keypair,
    new_nonce,
    plaintext_to_ciphertext,
    recovery_claim,
    recovery_keypair_from_shares,
    shares_from_recovery_keypair,
    verify_recovery_keypair
};