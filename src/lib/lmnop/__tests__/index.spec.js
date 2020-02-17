const lmnop = require('../lmnop');

describe('lmnop.verify_recovery', () => {
  it('generates new primary, recovery keypairs, signs with recovery, verifies signature', async () => {
    const primary = await lmnop.new_keypair();
    const recovery = await lmnop.new_keypair();

    const claim = await lmnop.recovery_claim(primary, recovery);
    expect(lmnop.verify_recovery_keypair(claim, recovery));
  });

  it('generates new recovery keypair, shatters into SSS shares, and combines them to reform recovery keypair', async () => {
    const recovery = await lmnop.new_keypair();

    const shares = await lmnop.shares_from_recovery_keypair(recovery, 3, 2);

    const recovered_recovery = await lmnop.recovery_keypair_from_shares(shares.slice(1));

    expect(recovery.privateKey).toEqual(recovered_recovery);
  });
});
