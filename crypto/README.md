# Crypto

This directory contains code to generate crypto keys, and encrypt and decrypt
data.

The folder contains the following C++ libraries:
1.  secret-data: a class to store keys and sensitive data. The class ensures
    that data are wiped out properly during the object destruction.

1.  ec-keys: a wrapper around BoringSSL functions to generate elliptic curve
    prime256v1 key pairs used by TVS and its client to establish a secure
    session. The class also provides a method to wrap the private key with an
    AES-256 AEAD key (to store private keys in GCP Spanner)

1.  aead-crypter: wrapper around BoringSSL functions to generate, and encrypt
    and decrypt data using AES-256 AEAD scheme.

1.  test-ec-key: generate elliptic curve prime256v1 keys for unit-tests. The
    function performs necessary encoding/decoding for unit-tests.

The folder also contains a Rust crate `secret-sharing` to split and recover
secrets using Shamir's secret schema. The crate exports an interface to C++ code.
