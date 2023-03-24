# PSPDFKit for Web + AWS CloudHSM Signing example

This Node application is a Web Server that implements a digital signing service that performs the signing via a [HSM](https://en.wikipedia.org/wiki/Hardware_security_module) exposed via the AWS CloudHSM service.

## Setup

* Install depedencies with `npm install`.
* If you'd like to run the example using a self-signed CA certificate, follow the instructions in `ca-sign/README.md` or simply go to that directory and run the `generate-certificate.sh` script.
* Start the server via  `PIN=<my-login-credentials> node index.js`, where `<my-login-credentials>` needs to be replaced with the credentials of a valid [Crypto user](https://docs.aws.amazon.com/cloudhsm/latest/userguide/manage-hsm-users.html#crypto-user) of the HSM. These crendetials need to be provided in a `user:password` syntax.

e.g.:

```
PIN=user:pass node index.js
```

* On PSPDFKit for Web Standalone, you can implement a logic similar to perform the HTTP calls to perform the signing:

```js
async function generatePKCS7({ fileContents, hash }) {
  const encodedContents = btoa(String.fromCharCode.apply(null, new Uint8Array(fileContents)));

  const response = await fetch("http://<your-url>/sign?mode=ca", {
    method: "POST",
    body: JSON.stringify({
      hash,
      encodedContents
    }),
    headers: {
      "Content-Type": "application/json"
    }
  });
  const json = await response.json();

  const arrayBuffer = base64ToArrayBuffer(json.p7);

  return arrayBuffer;
}

function base64ToArrayBuffer(base64) {
  var binary_string = window.atob(base64);
  var len = binary_string.length;
  var bytes = new Uint8Array(len);

  for (var i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }

  return bytes.buffer;
}
```

Where `<your-url>` needs to be replaced with a valid URL pointing to this running Node.js HTTP Server.

Note the presence of a `?mode=ca` query parameter in the URL. You can remove it to use a self-signed certificate instead.

Here's how one would use the PSPDFKit for Web API to start the signing:

```js
instance.signDocument(null, generatePKCS7);
```

## Related resources

* [AWS CloudHSM Getting Started Guide](https://docs.aws.amazon.com/cloudhsm/latest/userguide/getting-started.html)
* [How to create new Crypto Users in the HSM](https://docs.aws.amazon.com/cloudhsm/latest/userguide/cli-users.html)
* [How to setup PKCS#11 support in the EC2 instance](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library-install.html)
