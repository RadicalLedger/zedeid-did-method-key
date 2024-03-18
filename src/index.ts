import { Ed25519VerificationKey2018 } from '@transmute/ed25519-signature-2018';
import Base58 from 'base-58';

export default class KeyMethod {
    /**
     *
     * @param node BIP32Interface
     * @returns {KeysInterface} { did, address, privateKey, publicKey, chainCode, didDocument }.
     */
    async getKeys(node: BIP32Interface): Promise<KeysInterface> {
        const privateKey = node.privateKey?.toString('hex');
        const chainCode = node.chainCode?.toString('hex');
        const verificationKey: VerificationKeyInterface = await this.createVerificationMethod(
            privateKey as string
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
     * @param privateKey - private key as a hex string
     * @returns {CreateDidDocumentInterface}
     */
    async getDocument(privateKey: string): Promise<CreateDidDocumentInterface> {
        const verificationKey: VerificationKeyInterface = await this.createVerificationMethod(
            privateKey as string
        );
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

    /**
     *
     * @param seed - seed as a hex string
     * @param includePrivateKey - include private key
     * @returns {VerificationKeyInterface}
     */
    async createVerificationMethod(
        seed: string,
        includePrivateKey: boolean = false
    ): Promise<VerificationKeyInterface> {
        const k = await Ed25519VerificationKey2018.generate({
            secureRandom: () => {
                return Buffer.from(seed, 'hex');
            }
        });

        let jwk = await k.export({
            privateKey: includePrivateKey,
            type: 'Ed25519VerificationKey2018'
        });

        return jwk;
    }
}
