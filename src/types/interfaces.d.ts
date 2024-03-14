interface VerificationKeyInterface {
    publicKeyBase58?: string;
    controller: string;
    [x: string | symbol]: any;
}

interface KeysInterface {
    did: string;
    address: string;
    privateKey: string | undefined;
    publicKey: string;
    chainCode: string;
    verificationKey: VerificationKeyInterface;
}

interface BIP32Interface {
    chainCode: Buffer;
    privateKey?: Buffer;
    [x: string | symbol]: any;
}

interface MethodInterface {
    getKeys(node: BIP32Interface): Promise<KeysInterface>;
    getMasterKeys(): Promise<KeysInterface>;
    getDocument(): any;
}
