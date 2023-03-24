# Setting up Certification Authority

## Prerequisites

This should work on any modern Mac or Linux system with OpenSSL or LibreSSL installed.

### OpenSSL on macOS

OpenSSL implementation (more specifically, [LibreSSL](https://www.libressl.org/)) is included in macOS.

## Certificate generation

The following two steps are also implemented in [generate-certificates.sh](./generate-certificates.sh), which runs without parameters.

### 1. Prepare Certification Authority

Generate CA private key:

```
openssl genrsa -out test-ca.key 2048
```

This will create file `test-ca.key` which will be required on the next steps. 

Generate self signed CA certificate valid for ten years:

```
openssl req \
  -x509 -new -nodes -key test-ca.key \
  -subj "/CN=My Test CA v1" \
  -days 3650 -reqexts v3_req -extensions v3_ca \
  -out test-ca.cert
```
