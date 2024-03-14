export default class KeyMethod {
    /**
     *
     * @param node BIP32Interface
     * @returns {KeysInterface} { did, address, privateKey, publicKey, chainCode, verificationKey }.
     */
    getKeys(node: BIP32Interface): Promise<KeysInterface>;
}
export declare function createVerificationMethod(
    seed: any
): Promise<
    | import('@transmute/ed25519-key-pair').JsonWebKey2020
    | import('@transmute/ed25519-key-pair').Ed25519VerificationKey2018
>;
