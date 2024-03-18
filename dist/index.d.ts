/// <reference types="node" />
export default class KeyMethod {
    /**
     *
     * @param node BIP32Interface
     * @returns {KeysInterface} { did, address, privateKey, publicKey, chainCode, verificationKey }.
     */
    getKeys(node: BIP32Interface): Promise<KeysInterface>;
    /**
     *
     * @param privateKey - private key in Buffer or Hex string format
     */
    getDocument(privateKey: Buffer | string): Promise<CreateDidDocumentInterface>;
}
export declare function createVerificationMethod(
    seed: any,
    includePvt?: boolean
): Promise<
    | import('@transmute/ed25519-key-pair').JsonWebKey2020
    | import('@transmute/ed25519-key-pair').Ed25519VerificationKey2018
>;
