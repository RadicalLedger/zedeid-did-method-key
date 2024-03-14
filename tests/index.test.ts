import { BIP32Factory } from 'bip32';
import * as ecc from 'tiny-secp256k1';
import KeyMethod from '../src/index';

describe('HD Wallet Key Method', function () {
    it('create master node', async () => {
        const seed = '000102030405060708090a0b0c0d0e0f';

        const bip32 = BIP32Factory(ecc);
        const masterNode = bip32.fromSeed(Buffer.from(seed, 'hex'));

        const keyMethod = new KeyMethod();
        const keys = await keyMethod.getKeys(masterNode);

        expect(keys).toEqual({
            privateKey: 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35',
            publicKey: 'e4c2d43d39541b739d431b90532f71a6221bedb1991cd0ac4f9f1fe6759bd72b',
            did: 'did:key:z6MkurFJqdePvMpkRG9kTRStYpsr4q6cPKhZZPxd73L1miPk',
            address: 'z6MkurFJqdePvMpkRG9kTRStYpsr4q6cPKhZZPxd73L1miPk',
            chainCode: '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508',
            verificationKey: {
                id: 'did:key:z6MkurFJqdePvMpkRG9kTRStYpsr4q6cPKhZZPxd73L1miPk#z6MkurFJqdePvMpkRG9kTRStYpsr4q6cPKhZZPxd73L1miPk',
                type: 'Ed25519VerificationKey2018',
                controller: 'did:key:z6MkurFJqdePvMpkRG9kTRStYpsr4q6cPKhZZPxd73L1miPk',
                publicKeyBase58: 'GPzGFPPxapLHJmK3mrV3hjKrFFpkySTCsP3hGmMzrVcN',
                privateKeyBase58:
                    '5f8YbEuVeiWG1wMSUo9PRxLCUhNLuefAZkiurGkxkJBMZdxnQCuVYxDzMT6rNLS9K4w1akvB43zHWFBbt8qUehkN'
            }
        });
    });
});
