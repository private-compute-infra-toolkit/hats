# Test client for KV server

The directory contains a CLI to to send test request to KV server running in
Hats CVM.

The CLI is handy if you want to perform an end-to-end test on Hats CVM
system. In particular, it tests tee verification service (TVS),
launcher, Hats orchestrator and services inside the CVM, Parc server and KV
integration with the key fetcher.

The CLI crafts a request to KV-server, encrypt it with an HPKE public key
(the private portion is held by KV-server inside a CVM) and prints out the
response.

The CLI takes the following command line flags:

* `--kv_server`: address of the KV-server.

* `--public_key`: HPKE public key (x25519-hkdf-sha256) to encrypt requests.
The key should be in hex string format.

* `--key_id`: 8-bit key id. The server might have access to multiple keys,
and the client needs to tell the server which one to use.

NOTE: the server perform a module operation of key_id over 256.

* `--data_key`: a key to lookup its value in the KV-server.

## Use the tool for end-to-end testing

This section illustrate the steps to use the tool to perform an end-to-end
testing on Hats systems running KV-server. You will start a CVM that runs
KV-server, the CVM orchestrator talks to a TVS to obtain HPKE private keys, pass
the keys to KV-server, and the launcher starts a PARC server that loads data
into KV.

All the instructions below assumes that the current working directory is HATs
repository root (all paths are relative to the repository root).

1. Build the binaries by running:

    ```shell
    $ ./client/scripts/build-kv.sh
    ```

    This builds Oak's stage0, kernel, initrd, HATs system image, launcher, TVS
    server and build KV-server and package it into a tar bundle. It will also
    The built binaries are copied to `./client/prebuilt`. The script also copies
    and appraisal policy and CVM configuration file to the directory.

    NOTE: if you want to test on an insecure VM run
    `./client/scripts/build-kv-insecure.sh` instead.

1. Generate a pair of prime256v1 of keys to use it as an authentication key to
   the TVS by running:

   ```shell
   $ bazel run //key_manager:key-gen -- --key-type secp128r1
   ```
   The command above prints a public and private key in hex string format.
   The private key is passed to the CVM through the launcher, the public key
   is given to the TVS.

1. Generate a pair of HPKE for KV-server by running:

    ```shell
    $ bazel run //key_manager:key-gen -- --key-type x25519-hkdf-sha256
    ```
    The command above prints a public and private key in hex string format.
    The private key is passed to TVS (it will give it to the CVM if it passes
    the attestation process). The public key is used to encrypt requests sent
    by the CLI client.

1. Run an instance of TVS in local mode (this in contract to a GCP mode where
keys are stored in Spanner encrypted by KMS):

    ```shell
    $ ./client/prebuilt/tvs-server_main \
    --port=7779  \
    --primary_private_key=0000000000000000000000000000000000000000000000000000000000000001   \
    --appraisal_policy_file=./client/prebuilt/appraisal_policy.prototext \
    --user_authentication_public_key=<public key of prime256v1 from two steps above> \
    --user_secret=<private HPKE key from one step above> \
    --user_key_id=1 \
    --enable_policy_signature
    ```
    You can change the port number passed to TVS. You also can change
    ```---primary_private_key``` but you need to provide the public part to the
    CVM. You can do so by changing the value in client/system_image/tvs_public_keys.txt.
    You also need to change system_image_sha256 field in the appraisal policy as
    the system image hash will change.

    NOTE: if you test to test on an insecure VM pass
    `--accept_insecure_policies` as an additional flag to the TVS

1. Launch the CVM:

    ```shell
    $ cd client/prebuilt/
    $ ./launcher_main \
     --tvs_addresses=localhost:7779 \
     --use_tls=false \
     --launcher_config_path=./launcher_config.prototext \
     --tvs_authentication_key=<private key of prime256v1 from three steps above> \
     --minloglevel=0 \
     --stderrthreshold=0
    ```
1. Send encrypted requests to KV server: once the CVM starts and launches KV
   server, you can send encrypted requests to the server and inspect the response.
   The launcher starts a PARC server and makes it accessible to the KV server
   to load key/value data from it.
   The text version of the key/value data are in
   `client/test_data/parc_data/blob_root/kv_data.csv`.
   Pick a key from the file, encrypt it and send it and expect the server
   to respond with the corresponding value, in this example we will use hats100.

   To send an encrypted request run the following:

   ```shell
   $ cd client/kv-test-client/
   $ bazel run :kv-test-client_main -- \
   --public_key=<public HPKE key from four steps above> \
   --key_id=1 \
   --kv_server=localhost:8050 \
   --data_key=hats100
   ```
    You should receive the following response with the following value:

    ```
    YOyybkGOOjEJzsYrcaJBHJklrJYTibRZTOlPPisgTjDYNczZgpokpnXqHPcDKJPEMulDNriOXewoayszrapHSJmyhwEXziQraCNlvPLFCcpcxNXCNWcqoaFnjewWxZjsVrAerUqsEfDBFMOXQRSmqbJQVneJcWUZbmiVKYWTmmPQnAreUcywcsMMCUyegDriagvduqRKEaObfdObNgpVkEeRfwOOTVFrGVxVVsCrfXAsjXuSgaJlEokraQmMVmdlzvpQphrbBuPmbcwFFaNiqChklJIuYTtmOoNukohnXxfD
    ```

    This means that the CVM was able to attest itself with TVS, obtain the HPKE
    private key and pass it to KV-server. And that KV-server was able to reach
    to the PARC server and load the data properly.
