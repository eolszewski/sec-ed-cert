const _sodium = require('libsodium-wrappers');
const secrets = require('secrets.js-grempe');

const init_sodium = async () => {
    await _sodium.ready;
    return _sodium;
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

const new_keypair = async () => {
    const sodium = await init_sodium();

    let keypair = sodium.crypto_sign_keypair();
    return {
        publicKey: sodium.to_hex(keypair.publicKey),
        privateKey: sodium.to_hex(keypair.privateKey),
        keyType: keypair.keyType
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
    key_from_password_and_salt,
    new_keypair,
    recovery_claim,
    recovery_keypair_from_shares,
    shares_from_recovery_keypair,
    verify_recovery_keypair
};