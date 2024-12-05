# Key Manager

This directory contains code to managing key materials for a tee verification
service (TVS).

TVS needs to store keys it uses to encrypt RPC channels and secrets for the
clients. The secrets are often HPKE key pairs.
The key materials and secrets are stored in GCP Spanner and encrypted using GCP
KMS.

The folder contains the following C++ libraries:

1.  kms-client-interface: describes an interface for a KMS client
    implementation. The client is used by key_manager to encrypt decrypt secrets
    and key materials.

1.  gcp-kms-client: a client for GCK KMS to encrypt/decrypt TVS key materials
    and client secrets.The client implements the interface in
    kms-client-interface.

1.  key-fetcher-interface: describes an interface to fetch key materials from
    storage. The fetcher should be able to decrypt encrypted materials.

1.  key-fetcher-local: a key fetcher that fetches keys and secrets passed via
    command line arguments. Keys are passed as plain text. This implementation
    is used for testing only.

1.  key-fetcher-gcp: a key fetcher that fetches keys and secrets from a GCP
    Spanner database. The key materials and secerts are encrypted using envelop
    encryption where the data are key encryption keys are encrypted using keys
    stored in GCP KMS.

1.  test-key-fetcher: a key fetcher implementation for unit-test.

1.  public-key-fetcher: interface to fetch client public keys from storage.

1.  public-key-fetcher-local: returns client public keys from command line
    arguments

1.  public-key-fetcher-gcp: returns client public keys from a GCP Spanner
    database.

The directory contains a test CLI to generate keys `key-gen`. The CLI outputs
keys in hex digit format.

NOTE: this CLI is meant to be used for testing only.

To generate a pair of prime256v1 to be used either by TVS server or client run
the following:

```shell
 bazel run //key_manager:key-gen -- --key-type secp128r1
```

To generate a random 256-bit data, to be used as AES-256 AEAD key run the
following:

```shell
 bazel run //key_manager:key-gen -- --key-type random256-key
```

To generate a pair of HPKE keys run the following:

```shell
bazel run //key_manager:key-gen -- --key-type x25519-hkdf-sha256
```
To generate an HPKE key pair and split them multiple ways using Shamir's secret
schema you need to provide the number of splits and the threshold (minimum
number of shares required to recover the secret).

You can run the following the generate an HPKE pair, split them 3 ways with
threshold of 2.

```shell
bazel run //key_manager:key-gen -- --key-type x25519-hkdf-sha256 --split --numshares 3 --threshold 3
```
