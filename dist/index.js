'use strict';
var __importDefault =
    (this && this.__importDefault) ||
    function (mod) {
        return mod && mod.__esModule ? mod : { default: mod };
    };
Object.defineProperty(exports, '__esModule', { value: true });
exports.createVerificationMethod = void 0;
const ed25519_signature_2018_1 = require('@transmute/ed25519-signature-2018');
const base_58_1 = __importDefault(require('base-58'));
class KeyMethod {
    /**
     *
     * @param node BIP32Interface
     * @returns {KeysInterface} { did, address, privateKey, publicKey, chainCode, verificationKey }.
     */
    async getKeys(node) {
        var _a, _b;
        const privateKey =
            (_a = node.privateKey) === null || _a === void 0 ? void 0 : _a.toString('hex');
        const chainCode =
            (_b = node.chainCode) === null || _b === void 0 ? void 0 : _b.toString('hex');
        const verificationKey = await createVerificationMethod(privateKey, true);
        const publicKey = Buffer.from(
            base_58_1.default.decode(verificationKey.publicKeyBase58)
        ).toString('hex');
        const did = verificationKey.controller;
        const address = did.replace('did:key:', '');
        const { didDocument } = await this.getDocument(privateKey);
        return { did, address, privateKey, publicKey, chainCode, didDocument };
    }
    /**
     *
     * @param privateKey - private key in Buffer or Hex string format
     */
    async getDocument(privateKey) {
        const verificationKey = await createVerificationMethod(privateKey);
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
exports.default = KeyMethod;
async function createVerificationMethod(seed, includePvt = false) {
    const k = await ed25519_signature_2018_1.Ed25519VerificationKey2018.generate({
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
exports.createVerificationMethod = createVerificationMethod;
//# sourceMappingURL=index.js.map
