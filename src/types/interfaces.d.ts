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
    didDocument: DidDocumentInterface;
}

interface BIP32Interface {
    chainCode: Buffer;
    privateKey?: Buffer;
    [x: string | symbol]: any;
}

interface DidDocumentInterface {
    '@context': Object | string;
    id: string;
    verificationMethod: Object;
    authentication: Object;
    assertionMethod: Object;
    capabilityInvocation: Object;
    capabilityDelegation: Object;
}

interface CreateDidDocumentInterface {
    didDocument: DidDocumentInterface;
}

interface MethodInterface {
    getKeys(node: BIP32Interface): Promise<KeysInterface>;
    getMasterKeys(): Promise<KeysInterface>;
    getDocument(): Promise<CreateDidDocumentInterface>;
    createVerificationMethod(): Promise<VerificationKeyInterface>;
}
