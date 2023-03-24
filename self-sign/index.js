import graphene from "graphene-pk11";
import forge from "node-forge";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from 'node:url';
import { getRSAKeyPair, getSignerFn, initHSM, loginHSMCU } from "../hsm.js";
import { extractPublicKeyAsPEM } from "../util.js";

export default function generateCertificate() {
    const mod = initHSM();
    const slot = mod.getSlots(0);
    let forgeCert = null;

    // Check if the slot is initialized and a token is present in it
    if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {
        const session = loginHSMCU(slot);
        const keys = getRSAKeyPair(session);

        // Extract the public key from the generated key pair and convert it to a PEM format
        const pemPublicKey = extractPublicKeyAsPEM(keys.publicKey);
        const publicKey = forge.pki.publicKeyFromPem(pemPublicKey);
        const signerFn = getSignerFn(session, keys);

        // Create X.509 Certificate
        forgeCert = createSelfSignedX509Cert(publicKey, signerFn);

        // Export the created certificate if needed for verification
        const certPem = forge.pki.certificateToPem(forgeCert);
        const __filename = fileURLToPath(import.meta.url);
        const __dirname = path.dirname(__filename);

        fs.writeFileSync(path.join(__dirname, "cert.pem"), certPem, "utf-8");

        // Logout of the HSM and close the session
        session.logout();
        session.close();
    }
    mod.finalize();

    return forgeCert;
}

function createSelfSignedX509Cert(publicKey, signerFn) {
    const forgeCert = forge.pki.createCertificate();
    forgeCert.publicKey = publicKey;
    forgeCert.serialNumber = '01';
    // As an example, we're making the certificate valid 1 year before and 2 years after the
    // current date.
    forgeCert.validity.notBefore = new Date();
    forgeCert.validity.notBefore.setFullYear(forgeCert.validity.notBefore.getFullYear() - 1);
    forgeCert.validity.notAfter = new Date();
    forgeCert.validity.notAfter.setFullYear(forgeCert.validity.notBefore.getFullYear() + 2);
    // Set the attributes (common name, country, state, locality, organization, organizational
    // unit) of the subject and issuer
    // Note: The following are all fake values.
    const attrs = [{
        name: 'commonName',
        value: 'Sample Name'
    }, {
        name: 'countryName',
        value: 'US'
    }, {
        shortName: 'ST',
        value: 'Virginia'
    }, {
        name: 'localityName',
        value: 'Blacksburg'
    }, {
        name: 'organizationName',
        value: 'Test'
    }, {
        shortName: 'OU',
        value: 'Test'
    }];
    forgeCert.setSubject(attrs);
    forgeCert.setIssuer(attrs);
    // Set the extensions of the certificate (basic constraints, key usage, extended key 
    // usage, subject alternative name, and subject key identifier)
    forgeCert.setExtensions([{
        name: 'basicConstraints',
        cA: true
    }, {
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true
    }, {
        name: 'extKeyUsage',
        serverAuth: true,
        clientAuth: true,
        codeSigning: true,
        emailProtection: true,
        timeStamping: true
    }, {
        name: 'nsCertType',
        client: true,
        server: true,
        email: true,
        objsign: true,
        sslCA: true,
        emailCA: true,
        objCA: true
    }, {
        name: 'subjectAltName',
        altNames: [{
            type: 6, // URI
            value: 'http://example.org/webid#me'
        }, {
            type: 7, // IP
            ip: '127.0.0.1'
        }]
    }, {
        name: 'subjectKeyIdentifier'
    }]);


    // Important: Make sure to use a SHA-256 message digest
    // instead of the default SHA-1. Adobe Acrobat won't
    // treat a SHA-1 signed certificate as valid.
    forgeCert.sign(signerFn, forge.md.sha256.create());

    return forgeCert;
}
