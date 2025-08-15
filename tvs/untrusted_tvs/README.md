# Untrusted TVS

Runs an attestation service attestation verification service to verify that a
remote service runs in a Confidential VMs (CVMS) with an endorsed hardware and
software stack matching certain a predefined appraisal policies

The service is split into two parts:

1.  Untrusted TVS: runs outside the CVM. This part talks to the outside word,
    and pipes requests to the trusted TVS that runs inside an Oak's restricted
    kernel (potentially in a CVM). The untrusted part launches a VMM that runs
    the trusted TVS.
1.  Trusted TVS: receives encrypted traffic from the client, validates the
    provided attestation report. If the report is accepted, the service returns
    keys/secrets to the client so that it can process user data.

To run TVS in local mode:

1.  Generate TVS primary noise key:

    ```shell
    $ bazel run //key_manager:key-gen
    ```

    NOTE: the above step generates a pair of keys. The private key is passed to
    the server, while the public key is given to the client.

1.  Generate TVS secondary noise key:

    ```shell
    $ bazel run //key_manager:key-gen
    ```

    NOTE: the above step generates a pair of keys. The private key is passed to
    the server, while the public key is given to the client. This client key
    serves as alternative to the primary key (for e.g. key rotation).

1.  Generate an authentication key for the client:

    ```shell
    $ bazel run //key_manager:key-gen
    ```

    NOTE: the above step generates a pair of keys. The public key is passed to
    the server, while the private key is given to the client.

1.  Generate a pair of HPKE keys to be returned to the client:

    ```shell
    $ bazel run //key_manager:key-gen -- --key-type=x25519-hkdf-sha256
    ```

    NOTE: Any secret works, this just creates a realistic secret similar to
    standard use case.

1.  Compile Oak's binaries: stage0, restricted kernel and orchestrator (initrd).

1. Compile the trusted TVS (enclave app):
   ```shell
   $ bazel build -c opt //tvs/trusted_tvs/enclave_app:enclave_main
   ```

1.  Run the server:

    ```shell
    $ bazel build -c opt //tvs/standalone_server:tvs-server_main
    $ bazel-bin/tvs/standalone_server/tvs-server_main \
        --port=8080 \
        --primary_private_key=<tvs-primary-private-key> \
        --secondary_private_key=<tvs-secondary-private-key> \
        --appraisal_policy_file=<path to appraisal policy> \
        --user_authentication_public_key=<client-authentication-public-key> \
        --user_key_id=<id of the client secret> \
        --user_public_key=<public portion of the client key in hex> \
        --user_secret=<full or partial private key in hex>
        --vmm_binary=<path to qemu binary> \
        --bios_binary=<path to Oak's stage0> \
        --kernel=<path Oak's restricted kernel> \
        --initrd=<path to Oak's orchestrator> \
        --app_binary=<path to tvs enclave> \
    ```

    NOTE: `user_key_id`, `user_public_key`, and `user_secret` determine what
    gets returned to the client, and otherwise can be any valid number (id) or
    hex (key/secret).

NOTE: You can run the service in GCP mode where keys and user secrets are stored
in Spanner and encrypted using KMS keys by following the same
[instructions to run standalone TVS](../README.md), and adding the extra flags
(to pass the path to various binaries).

## Manually test the service:
You can test the server by using a pre-built test keys and appraisal policies.


### Build the binaries:

From the repository root run:

```shell
$ ./tvs/untrusted_tvs/build.sh
```

### Run the service:

From the repository root run:

```shell
$ tvs/untrusted_tvs/binaries/tvs-server_main \
    --port=8080 \
    --primary_private_key=0000000000000000000000000000000000000000000000000000000000000001 \
    --appraisal_policy_file=tvs/test_data/on-perm-reference.txtpb \
    --user_authentication_public_key=04a99c16a302716404b075086c8c125ea93d0822330f8a46675c8f7e5760478024811211845d43e6addae5280660ba3b5ba0f78834b79ec9449b626a725728b76d \
    --vmm_binary=$(which qemu-system-x86_64) \
    --bios_binary=tvs/untrusted_tvs/binaries/stage0_bin \
    --kernel=tvs/untrusted_tvs/binaries/wrapper_bzimage_virtio_console_channel \
    --initrd=tvs/untrusted_tvs/binaries/oak_orchestrator \
    --app_binary=tvs/untrusted_tvs/binaries/enclave_main \
    --memory_size=20G
```

### Run the client:

To send a valid report:

```shell
$ bazel build -c opt //tvs/test_client:tvs-client_main
$ bazel-bin/tvs/test_client/tvs-client_main \
   --tvs_address=localhost:8080 \
   --tvs_public_key=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
   --nouse_tls \
   --evidence_file=tvs/test_data/evidence_v1_genoa.txtpb \
   --tee_certificate_file=tvs/test_data/vcek_genoa.crt \
   --application_signing_key=be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c \
   --tvs_authentication_key=f1af8f26497c24e3944709baccd6b6f4c9326fd902317189f4b2c4adfe2e6af9
```

To send an invalid report:

```shell
$ bazel build -c opt //tvs/test_client:tvs-client_main
$ bazel-bin/tvs/test_client/tvs-client_main \
   --tvs_address=localhost:8080 \
   --tvs_public_key=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
   --nouse_tls \
   --evidence_file=tvs/test_data/evidence_v2_genoa.txtpb \
   --tee_certificate_file=tvs/test_data/vcek_genoa.crt \
   --application_signing_key=90c6593892237eb36a525902340c02a6865a13e37ed9eb73b5123b312a0bb3b0 \
   --tvs_authentication_key=f1af8f26497c24e3944709baccd6b6f4c9326fd902317189f4b2c4adfe2e6af9
```

## Run the integration test:

From the repository root run:

```shell
$ ./tvs/untrusted_tvs/build.sh
$ bazel run  //tvs/untrusted_tvs:tvs-service_test
```
