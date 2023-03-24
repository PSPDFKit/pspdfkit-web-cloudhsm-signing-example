import cors from "cors";
import express from "express";
import graphene from "graphene-pk11";
import forge from "node-forge";
import { Buffer } from "node:buffer";
import generateCASignedCert from "./ca-sign/index.js";
import { getRSAKeyPair, getSignerFn, initHSM, loginHSMCU } from "./hsm.js";
import generateSelfSignedCert from "./self-sign/index.js";

function generateSignature(fileContents, certificate) {
    const mod = initHSM();
    const slot = mod.getSlots(0);

    // Signature result to return. `null` if we can't connect to the HSM.
    let result = null;

    // Check if the slot is initialized and a token is present in it
    if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {
        const session = loginHSMCU(slot);
        const keys = getRSAKeyPair(session);
        const signerFn = getSignerFn(session, keys);

        // Create PKCS#7 container of signature + certificate
        const p7 = createPKCS7Signature(fileContents, certificate, signerFn);
        // Convert the PKCS#7 to a Base64-encoded string for sending it over the network.
        result = Buffer.from(forge.asn1.toDer(p7.toAsn1()).getBytes(), "binary").toString("base64");

        // Logout of the HSM and close the session
        session.logout();
        session.close();
    } else {
        console.error("Slot is not initialized")
    }
    mod.finalize();
    return result;
}

function createPKCS7Signature(fileContents, cert, signerFn) {
    const p7 = forge.pkcs7.createSignedData();

    p7.content = new forge.util.ByteBuffer(fileContents);
    p7.addCertificate(cert);
    p7.addSigner({
        key: signerFn,
        certificate: cert,
        // this bit is important, you must choose a supported algorithm by the key vault
        // sha1 is not supported, for example.
        digestAlgorithm: forge.pki.oids.sha256,
        authenticatedAttributes: [
            {
                type: forge.pki.oids.contentType,
                value: forge.pki.oids.data,
            }, {
                type: forge.pki.oids.messageDigest,
                // value will be auto-populated at signing time
            }, {
                type: forge.pki.oids.signingTime,
                value: new Date(),
            },
        ],
    })

    p7.sign({ detached: true });

    return p7;
}

// Basic Express.js server with a /sign endpoint
// that receives the contents to sign and returns
// the PKCS#7 container that PSPDFKit adds to the
// document.
const app = express()
const PORT = 3756;

let caSignedCert = null;
let selfSignedCert = null;

app.use(cors());
app.use(express.json());

app.post("/sign", (req, res) => {
    const mode = req.query.mode || 'self-signed';
    const certificate = mode === 'ca' ? caSignedCert : selfSignedCert;

    console.log("Will sign with the following certificate: ", mode);
    const { encodedContents } = req.body;
    const fileContents = Buffer.from(encodedContents, 'base64');
    const result = generateSignature(fileContents, certificate);
    res.json({ p7: result });
});

app.listen(PORT, () => {
    console.log("Server running on PORT ", PORT);

    caSignedCert = generateCASignedCert();
    console.log("RSA key pair and leaf X.509 certificate generated and ready to use.")
    selfSignedCert = generateSelfSignedCert();
    console.log("Self-signed X.509 certificate generated and ready to use.");
});
