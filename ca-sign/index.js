import graphene from "graphene-pk11";
import forge from "node-forge";
import { execSync } from "node:child_process";
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
        const forgeCsr = createCSR(publicKey, signerFn);
        forgeCert = createLeafX509Cert(forgeCsr);

        // Logout of the HSM and close the session
        session.logout();
        session.close();
    } else {
        console.error("Slot is not initialized")
    }
    mod.finalize();

    return forgeCert;
}

function createCSR(publicKey, signerFn) {
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = publicKey;
    // Note: The following are all fake values.
    csr.setSubject([{
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
    }]);
    csr.sign(signerFn, forge.md.sha256.create());
    console.log("CSR created.")
    return csr;
}

function createLeafX509Cert(forgeCsr) {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);

    // We're going to use OpenSSL to create this certificate.
    // Hence, we export the CSR as a file and specify a path
    // for OpenSSL to write to.
    const csrPath = path.join(__dirname, "client-csr.pem");
    const csrPem = forge.pki.certificationRequestToPem(forgeCsr);
    fs.writeFileSync(csrPath, csrPem, "utf-8");

    const outputPath = path.join(__dirname, "client-cert.pem");
    const caKeyPath = path.join(__dirname, "ca.key");
    const caCertPath = path.join(__dirname, "ca.cert.pem");

    signCSR(csrPath, caKeyPath, caCertPath, outputPath);

    const certPem = fs.readFileSync(outputPath, "utf-8");
    return forge.pki.certificateFromPem(certPem);
}

function signCSR(csrPath, caPrivKeyPath, caCertPath, outputPath) {
    // Use OpenSSL to create certificate pem signed by CA
    execSync(`openssl x509 -req -days 720 -in ${csrPath} -CA ${caCertPath} -CAkey ${caPrivKeyPath} -CAcreateserial -out ${outputPath}`);
}
