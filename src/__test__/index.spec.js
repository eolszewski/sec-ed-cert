require('dotenv').config()

const path = require('path');
const openpgp = require('openpgp');
const Promise = require('bluebird');
const fs = Promise.promisifyAll(require('fs'));

const { Console } = require('console');
global.console = new Console(process.stderr, process.stderr);

describe('sec-ed-cert', () => {
  let originalTimeout;

  beforeEach(function () {
    originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 30000;
  });

  afterEach(function () {
    jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
  });

  it('can generate keys and export them to the data directory', async () => {
    // Generate and decrypt a new ed25519 pgp key
    const edOptions = {
      userIds: [{ name: process.env.ED25519_USER_NAME, email: process.env.ED25519_USER_EMAIL }],
      curve: 'ed25519',
      passphrase: process.env.ED25519_USER_PASSPHRASE
    };
    const edKeyPair = await openpgp.generateKey(edOptions);
    const edPrivKey = openpgp.key.readArmored(
      edKeyPair.privateKeyArmored
    ).keys[0];

    await edPrivKey.decrypt(process.env.ED25519_USER_PASSPHRASE);
    const edPrivKeyPrimaryKey = edPrivKey.primaryKey;
    const edUser = edPrivKey.users[0];

    // Generate and decrypt a new secp256k1 pgp key
    const secOptions = {
      userIds: [{ name: process.env.SECP256K1_USER_NAME, email: process.env.SECP256K1_USER_EMAIL }],
      curve: 'secp256k1',
      passphrase: process.env.SECP256K1_USER_PASSPHRASE
    };

    const secKeyPair = await openpgp.generateKey(secOptions);
    const secPrivKey = openpgp.key.readArmored(
      secKeyPair.privateKeyArmored
    ).keys[0];
    await secPrivKey.decrypt(process.env.SECP256K1_USER_PASSPHRASE);
    const secPrivKeyPrimaryKey = secPrivKey.primaryKey;
    const secUser = secPrivKey.users[0];

    // 
    // Recovery
    // 

    // Generate and decrypt a new ed25519 pgp key
    const edRecoveryOptions = {
      userIds: [{ name: process.env.ED25519_USER_NAME, email: process.env.ED25519_USER_EMAIL }],
      curve: 'ed25519',
      passphrase: process.env.ED25519_USER_PASSPHRASE
    };
    const edRecoveryKeyPair = await openpgp.generateKey(edRecoveryOptions);
    const edRecoveryPrivKey = openpgp.key.readArmored(
      edRecoveryKeyPair.privateKeyArmored
    ).keys[0];

    await edRecoveryPrivKey.decrypt(process.env.ED25519_USER_PASSPHRASE);
    const edRecoveryPrivKeyPrimaryKey = edRecoveryPrivKey.primaryKey;
    const edRecoveryUser = edRecoveryPrivKey.users[0];

    // Generate and decrypt a new secp256k1 pgp key
    const secRecoveryOptions = {
      userIds: [{ name: process.env.SECP256K1_USER_NAME, email: process.env.SECP256K1_USER_EMAIL }],
      curve: 'secp256k1',
      passphrase: process.env.SECP256K1_USER_PASSPHRASE
    };

    const secRecoveryKeyPair = await openpgp.generateKey(secRecoveryOptions);
    const secRecoveryPrivKey = openpgp.key.readArmored(
      secRecoveryKeyPair.privateKeyArmored
    ).keys[0];

    await secRecoveryPrivKey.decrypt(process.env.SECP256K1_USER_PASSPHRASE);
    const secRecoveryPrivKeyPrimaryKey = secRecoveryPrivKey.primaryKey;
    const secRecoveryUser = secRecoveryPrivKey.users[0];

    // edPrivKey, secRecoveryPrivKey trust secPrivKey
    let trustedSec = await secPrivKey.toPublic().signPrimaryUser([edPrivKey, secRecoveryPrivKey]);
    expect(await trustedSec.users[0].otherCertifications[0].verify(
      edPrivKeyPrimaryKey, { userid: secUser.userId, key: trustedSec.primaryKey }
    )).toBe(true);
    expect(await trustedSec.users[0].otherCertifications[1].verify(
      secRecoveryPrivKeyPrimaryKey, { userid: secUser.userId, key: trustedSec.primaryKey }
    )).toBe(true);

    // secPrivKey, edRecoveryPrivKey trust edPrivKey
    let trustedEd = await edPrivKey.toPublic().signPrimaryUser([secPrivKey, edRecoveryPrivKey]);
    expect(await trustedEd.users[0].otherCertifications[0].verify(
      secPrivKeyPrimaryKey, { userid: edUser.userId, key: trustedEd.primaryKey }
    )).toBe(true);
    expect(await trustedEd.users[0].otherCertifications[1].verify(
      edRecoveryPrivKeyPrimaryKey, { userid: edUser.userId, key: trustedEd.primaryKey }
    )).toBe(true);

    // edPrivKey, secRecoveryPrivKey trust edRecoveryPrivKey
    let trustedRecoveryEd = await edRecoveryPrivKey.toPublic().signPrimaryUser([edPrivKey, secRecoveryPrivKey]);
    expect(await trustedRecoveryEd.users[0].otherCertifications[0].verify(
      edPrivKeyPrimaryKey, { userid: edRecoveryUser.userId, key: trustedRecoveryEd.primaryKey }
    )).toBe(true);
    expect(await trustedRecoveryEd.users[0].otherCertifications[1].verify(
      secRecoveryPrivKeyPrimaryKey, { userid: edRecoveryUser.userId, key: trustedRecoveryEd.primaryKey }
    )).toBe(true);

    // secPrivKey, edRecoveryPrivKey trust secRecoveryPrivKey
    let trustedRecoverySec = await secRecoveryPrivKey.toPublic().signPrimaryUser([secPrivKey, edRecoveryPrivKey]);
    expect(await trustedRecoverySec.users[0].otherCertifications[0].verify(
      secPrivKeyPrimaryKey, { userid: secRecoveryUser.userId, key: trustedRecoverySec.primaryKey }
    )).toBe(true);
    expect(await trustedRecoverySec.users[0].otherCertifications[1].verify(
      edRecoveryPrivKeyPrimaryKey, { userid: secRecoveryUser.userId, key: trustedRecoverySec.primaryKey }
    )).toBe(true);

    // Exporting armored public keys
    await fs.writeFileAsync(
      path.join(__dirname, '../../data/ed_public_key.asc'), trustedEd.armor()
    )
    await fs.writeFileAsync(
      path.join(__dirname, '../../data/sec_public_key.asc'), trustedSec.armor()
    )

    // Exporting private keys
    await fs.writeFileAsync(
      path.join(__dirname, '../../data/ed_private.key'), edPrivKey.armor()
    )
    await fs.writeFileAsync(
      path.join(__dirname, '../../data/sec_private.key'), secPrivKey.armor()
    )

    // Exporting armored public keys
    await fs.writeFileAsync(
      path.join(__dirname, '../../data/ed_recovery_public_key.asc'), trustedRecoveryEd.armor()
    )
    await fs.writeFileAsync(
      path.join(__dirname, '../../data/sec_recovery_public_key.asc'), trustedRecoverySec.armor()
    )

    // Exporting private keys
    await fs.writeFileAsync(
      path.join(__dirname, '../../data/ed_recovery_private.key'), edRecoveryPrivKey.armor()
    )
    await fs.writeFileAsync(
      path.join(__dirname, '../../data/sec_recovery_private.key'), secRecoveryPrivKey.armor()
    )
  });
});