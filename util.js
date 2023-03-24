import NodeRSA from "node-rsa";

export function extractPublicKeyAsPEM(publicKey) {
    const pubKey = publicKey.getAttribute({
        modulus: null,
        publicExponent: null
    });

    const rsaPubKey = new NodeRSA();
    rsaPubKey.importKey({
        n: pubKey.modulus,
        e: pubKey.publicExponent
    });

    // Export the public key in PKCS#8 PEM format
    return rsaPubKey.exportKey('pkcs8-public-pem');
}
