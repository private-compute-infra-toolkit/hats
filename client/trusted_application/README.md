# Trusted Application

The directory contains an application that is used for testing HATs CVM
interaction with CVM. The application receives an AES-256 AEAD encrypted
message, decrypt the message and send it back.
The AES-256 AEAD encryption key is stored in a tee-verification service (TVS),
and returned to HATs orchestrator upon successful attestation verification.
The orchestrator passes the private key to the application.


To run the test:

All the instructions below assumes that the current working directory is HATs
repository root (all paths are relative to the repository root).

1. Compile the binaries:

    ```shell
    $ ./client/trusted_application/build-for-test.sh
    ```

1. Run the test:

    ```shell
    $ bazel run //client/trusted_application:trusted_application_test
    ```
