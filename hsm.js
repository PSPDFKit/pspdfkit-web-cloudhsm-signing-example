import graphene from "graphene-pk11";

// Initializes the cloud HSM and returns a module object
export function initHSM() {
    const Module = graphene.Module;

    const mod = Module.load("/opt/cloudhsm/lib/libcloudhsm_pkcs11.so", "CloudHSM");

    mod.initialize();

    return mod;
}

// Opens a session with the given slot and logs in using the user PIN stored in the environment variable
// See https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-pin.html for the format of the pin.
// <CU_user_name>:<password>
export function loginHSMCU(slot) {
    const session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);
    session.login(process.env.PIN, graphene.UserType.User);

    return session
}

export function getRSAKeyPair(session) {
    const privateKeys = session.find({ class: graphene.ObjectClass.PRIVATE_KEY });

    if (privateKeys.length > 0) {
        console.log("Existing private key found in the HSM...");
        // get first private key and public key
        const privateKey = privateKeys.items(0);
        const publicKey = session.find({ class: graphene.ObjectClass.PUBLIC_KEY }).items(0);

        return { privateKey, publicKey }
    }

    console.log("No key pair found. Will use the HSM to create a new one...");

    return session.generateKeyPair(graphene.KeyGenMechanism.RSA, {
        keyType: graphene.KeyType.RSA,
        modulusBits: 2048, // Set the size of the key to 2048 bits
        publicExponent: new Uint8Array([1, 0, 1]), // Set the public exponent to 65537 (0x010001)
        token: true, // Store the key on the HSM
        verify: true, // The key can be used for verification
        encrypt: true, // The key can be used for encryption
        wrap: true,  // The key can be used for wrapping other keys
        extractable: true, // The key can be extracted
    }, {
        keyType: graphene.KeyType.RSA,
        token: true, // Store the key on the HSM
        sign: true, // The key can be used for signing
        decrypt: true, // The key can be used for decryption
        unwrap: true, // The key can be used for unwrapping other keys
        extractable: false, // Important: we don't want to allow this key to be extracted
    });
}

export function getSignerFn(session, keys) {
    // Add custom signer function that will communicate with the HSM to sign inside of it.
        // https://github.com/digitalbazaar/forge/issues/861
        // This is used instead of passing a proper private key to `node-forge`, since we don't have
        // any, due to the private key being contained in the HSM and not accessible outside of it.
        return {
            sign: (md) => {
                // Create a signature prefix (ASN.1 sequence) to indicate that the signature is a digest
                // of a previously hashed message. See https://stackoverflow.com/a/47106124
                const prefix = Buffer.from([
                    0x30, 0x31, 0x30, 0x0d,
                    0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03,
                    0x04, 0x02, 0x01, 0x05,
                    0x00, 0x04, 0x20
                ]);

                // Concatenate the prefix and the message digest
                let buf = Buffer.concat([prefix, Buffer.from(md.digest().toHex(), 'hex')]);

                // Important: Since we're signing message digests (i.e. hashed messages), we need
                // to be careful to not hash it again when signing. Thus, we are using RSA_PKCS
                // instead of SHA256_RSA_PKCS here.
                let sign = session.createSign("RSA_PKCS", keys.privateKey);
                return sign.once(buf).toString('binary');
            }
        };
}
