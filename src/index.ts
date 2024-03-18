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
        const verificationKey: VerificationKeyInterface = await createVerificationMethod(
            privateKey,
            true
        );
        const publicKey = Buffer.from(Base58.decode(verificationKey.publicKeyBase58)).toString(
            'hex'
        );

        const did = verificationKey.controller;
        const address = did.replace('did:key:', '');

        const { didDocument } = await this.getDocument(privateKey as string);

        return { did, address, privateKey, publicKey, chainCode, didDocument };
    }

    /**
     *
     * @param privateKey - private key in Buffer or Hex string format
     */
    async getDocument(privateKey: Buffer | string): Promise<CreateDidDocumentInterface> {
        const verificationKey: VerificationKeyInterface =
            await createVerificationMethod(privateKey);
        const didDocument = {
            '@context': [
                'https://www.w3.org/ns/did/v1',
                'https://w3id.org/security/suites/ed25519-2018/v1',
                'https://w3id.org/security/suites/x25519-2019/v1'
            ],
            id: verificationKey.controller,
            verificationMethod: [verificationKey],
            authentication: [verificationKey.id],
            assertionMethod: [verificationKey.id],
            capabilityInvocation: [verificationKey.id],
            capabilityDelegation: [verificationKey.id]
        };

        return { didDocument };
    }
}

export async function createVerificationMethod(seed: any, includePvt: boolean = false) {
    const k = await Ed25519VerificationKey2018.generate({
        secureRandom: () => {
            return Buffer.from(seed, 'hex');
        }
    });

    let jwk = await k.export({
        privateKey: includePvt,
        type: 'Ed25519VerificationKey2018'
    });

    return jwk;
}
