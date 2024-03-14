import { Ed25519VerificationKey2018 } from '@transmute/ed25519-signature-2018';
import Base58 from 'base-58';

export default class KeyMethod {
    /**
     *
     * @param node BIP32Interface
     * @returns {KeysInterface} { did, address, privateKey, publicKey, chainCode, verificationKey }.
     */
    async getKeys(node: BIP32Interface): Promise<KeysInterface> {
        const privateKey = node.privateKey?.toString('hex');
        const chainCode = node.chainCode?.toString('hex');
        const verificationKey: VerificationKeyInterface =
            await createVerificationMethod(privateKey);
        const publicKey = Buffer.from(Base58.decode(verificationKey.publicKeyBase58)).toString(
            'hex'
        );

        const did = verificationKey.controller;
        const address = did.replace('did:key:', '');

        return { did, address, privateKey, publicKey, chainCode, verificationKey };
    }
}

export async function createVerificationMethod(seed: any) {
    const k = await Ed25519VerificationKey2018.generate({
        secureRandom: () => {
            return Buffer.from(seed, 'hex');
        }
    });

    let jwk = await k.export({
        privateKey: true,
        type: 'Ed25519VerificationKey2018'
    });

    return jwk;
}
