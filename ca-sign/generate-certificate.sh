#!/bin/sh

set -e

CA_CN="Test CA for $(hostname -s) $(date +%Y)"
SIGNER_CN="Testing Document Signer for $(hostname -s)"

CA_KEY_FILENAME="ca.key"
CA_CERT_FILENAME="ca.cert.pem"

echo "*** Preparing CA"
if test -f "${CA_KEY_FILENAME}"; then
  echo "*** CA key ('${CA_KEY_FILENAME}') already exists, skipping"
else
  openssl genrsa -out ${CA_KEY_FILENAME} 2048
  echo "*** Created CA key ('${CA_KEY_FILENAME}')."

  openssl req \
    -x509 -new -nodes -key ${CA_KEY_FILENAME} \
    -subj "/CN=${CA_CN}" \
    -days 3650 \
    -out ${CA_CERT_FILENAME}
  echo "*** Created CA certificate ('${CA_CERT_FILENAME}')"
fi

echo "*** Done."

