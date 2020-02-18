const lmnop = require('../lmnop');

describe('lmnop.verify_recovery', () => {
  it('generates new primary, recovery keypairs, signs with recovery, verifies signature', async () => {
    const primary = await lmnop.new_keypair();
    const recovery = await lmnop.new_keypair();

    const claim = await lmnop.recovery_claim(primary, recovery);
    expect(lmnop.verify_recovery_keypair(claim, recovery));
  });

  it('generates new recovery keypair, shatters into SSS shares, and combines them to reform recovery keypair', async () => {
    const share_threshold = 2;
    const share_num = 3;

    const recovery = await lmnop.new_keypair();

    const shares = await lmnop.shares_from_recovery_keypair(recovery, share_num, share_threshold);

    const recovered_recovery_sk = await lmnop.recovery_keypair_from_shares(shares.slice(1));

    expect(recovery.privateKey).toEqual(recovered_recovery_sk);
  });

  it('generates new primary keypair, encrypts it with a password, and recovers it with the same password', async () => {
    const password = "8*BDi#c3DgCv0gW7";

    const primary = await lmnop.new_keypair();

    const ciphertext = await lmnop.plaintext_to_ciphertext(primary.privateKey, password);
    const plaintext = await lmnop.ciphertext_to_plaintext(ciphertext, password);

    expect(primary.privateKey).toEqual(plaintext.data);
  });

  it('generates new primary keypair, signs plaintext with pk_1 and decrypts with sk_1', async () => {
    const json = { "message": "Hello world!" };
    const nonce = await lmnop.new_nonce();

    const primary_0 = await lmnop.new_box_keypair();
    const primary_1 = await lmnop.new_box_keypair();

    const ciphertext = await lmnop.encrypt_json_with_asymmetric_keypair(json, nonce, primary_1.publicKey, primary_0.privateKey);
    const decoded = await lmnop.decrypt_json_with_asymmetric_keypair(ciphertext, nonce, primary_0.publicKey, primary_1.privateKey);

    expect(decoded.message).toBe(json.message);
  });

  it('generates a new recovery keypair, shatters it, encrypts each share, decrypts each share, and combines the share to recover the keypair', async () => {
    const share_threshold = 3;
    const share_num = 5;

    const primary_key_0 = await lmnop.new_box_keypair();
    const primary_key_1 = await lmnop.new_box_keypair();
    const primary_key_2 = await lmnop.new_box_keypair();
    const primary_key_3 = await lmnop.new_box_keypair();
    const primary_key_4 = await lmnop.new_box_keypair();

    const password_0 = "Anx%J1Gnree52mTY";
    const password_1 = "un81072$@d&hNpWr";
    const password_2 = "A%kbTT3#Z2EwX$41";
    const password_3 = "UEWn%d2ml5L377rE";
    const password_4 = "hauP%Y%H63QC*Ye1";

    const nonce_0 = await lmnop.new_nonce();
    const nonce_1 = await lmnop.new_nonce();
    const nonce_2 = await lmnop.new_nonce();
    const nonce_3 = await lmnop.new_nonce();
    
    // Generate new recovery key
    const recovery = await lmnop.new_keypair();

    // Generate recovery key shares
    const shares = await lmnop.shares_from_recovery_keypair(recovery, share_num, share_threshold);

    // Send shares to other 4 recipients with asymmetric crypto
    const ciphertext_0 = await lmnop.encrypt_json_with_asymmetric_keypair({ 'share': shares[0] }, nonce_0, primary_key_1.publicKey, primary_key_0.privateKey);
    const ciphertext_1 = await lmnop.encrypt_json_with_asymmetric_keypair({ 'share': shares[1] }, nonce_1, primary_key_2.publicKey, primary_key_0.privateKey);
    const ciphertext_2 = await lmnop.encrypt_json_with_asymmetric_keypair({ 'share': shares[2] }, nonce_2, primary_key_3.publicKey, primary_key_0.privateKey);
    const ciphertext_3 = await lmnop.encrypt_json_with_asymmetric_keypair({ 'share': shares[3] }, nonce_3, primary_key_4.publicKey, primary_key_0.privateKey);

    // Have shares decrypted by 4 recipients
    const decoded_0 = await lmnop.decrypt_json_with_asymmetric_keypair(ciphertext_0, nonce_0, primary_key_0.publicKey, primary_key_1.privateKey);
    const decoded_1 = await lmnop.decrypt_json_with_asymmetric_keypair(ciphertext_1, nonce_1, primary_key_0.publicKey, primary_key_2.privateKey);
    const decoded_2 = await lmnop.decrypt_json_with_asymmetric_keypair(ciphertext_2, nonce_2, primary_key_0.publicKey, primary_key_3.privateKey);
    const decoded_3 = await lmnop.decrypt_json_with_asymmetric_keypair(ciphertext_3, nonce_3, primary_key_0.publicKey, primary_key_4.privateKey);

    expect(decoded_0.share).toBe(shares[0]);
    expect(decoded_1.share).toBe(shares[1]);
    expect(decoded_2.share).toBe(shares[2]);
    expect(decoded_3.share).toBe(shares[3]);

    // Encrypt everything with local passwords
    const ciphertext_4 = await lmnop.plaintext_to_ciphertext(decoded_0.share, password_1);
    const ciphertext_5 = await lmnop.plaintext_to_ciphertext(decoded_1.share, password_2);
    const ciphertext_6 = await lmnop.plaintext_to_ciphertext(decoded_2.share, password_3);
    const ciphertext_7 = await lmnop.plaintext_to_ciphertext(decoded_3.share, password_4);
    const ciphertext_8 = await lmnop.plaintext_to_ciphertext(shares[4], password_0);

    // Decrypt everything with local passwords
    const decoded_4 = await lmnop.ciphertext_to_plaintext(ciphertext_4, password_1);
    const decoded_5 = await lmnop.ciphertext_to_plaintext(ciphertext_5, password_2);
    const decoded_6 = await lmnop.ciphertext_to_plaintext(ciphertext_6, password_3);
    const decoded_7 = await lmnop.ciphertext_to_plaintext(ciphertext_7, password_4);
    const decoded_8 = await lmnop.ciphertext_to_plaintext(ciphertext_8, password_0);

    expect(decoded_4.data).toBe(decoded_0.share);
    expect(decoded_5.data).toBe(decoded_1.share);
    expect(decoded_6.data).toBe(decoded_2.share);
    expect(decoded_7.data).toBe(decoded_3.share);
    expect(decoded_8.data).toBe(shares[4]);

    // Combine shares into recovery key
    const recovered_shares = [decoded_4.data, decoded_5.data, decoded_6.data, decoded_7.data, decoded_8.data];
    const recovered_recovery_sk = await lmnop.recovery_keypair_from_shares(recovered_shares.slice(2));

    expect(recovery.privateKey).toEqual(recovered_recovery_sk);
  });
});
