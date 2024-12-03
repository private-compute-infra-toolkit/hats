# TEE Verification Service (TVS)

An attestation verification service to verify that a remote service runs in a
Confidential VMs (CVMS) with an endorsed hardware and software stack matching
certain a predefined appraisal policies.

In order to run the service you need:

1.  An elliptical curve prime256v1 private key.

1.  An appraisal policy that contains a list of acceptable measurements.

1.  One registered client: the client is registered by providing the public
    portion of an elliptical curve prime256v1 key.

The client needs to initiate a noise KK handshake session, send an attestation
report (DICE certificate) with hardware endorsement, and sign the handshake hash
with the DICE application layer private key. If the attestation report is
accepted, the server returns a list of secrets to the client (a full or partial
private keys).

The server runs in two modes:

1.  GCP: keys, user secrets, client authentication keys, and appraisal policies
    are stored in Spanner. Further, GCP KMS is used to encrypt data encryption
    keys that encrypts the stored keys.

1.  Local (for testing): TVS keys, a user secret, a client authentication key,
    and an appraisal policy are passed as a flag to the server.

## TVS in local mode:

NOTE: TVS in local mode allows for one user only.

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
    ```

    NOTE: `user_key_id`, `user_public_key`, and `user_secret` determine what
    gets returned to the client, and otherwise can be any valid number (id) or
    hex (key/secret).

Alternatively, you can use the following pre-built test keys and appraisal
policies:

```shell
$ bazel build -c opt //tvs/standalone_server:tvs-server_main
$ bazel-bin/tvs/standalone_server/tvs-server_main \
    --port=8080 \
    --primary_private_key=0000000000000000000000000000000000000000000000000000000000000001 \
    --appraisal_policy_file=tvs/test_data/on-perm-reference.textproto \
    --user_authentication_public_key=04a99c16a302716404b075086c8c125ea93d0822330f8a46675c8f7e5760478024811211845d43e6addae5280660ba3b5ba0f78834b79ec9449b626a725728b76d
```

### To run a test client:

The general format is as follows.

```shell
$ bazel build -c opt //tvs/test_client:tvs-client_main
$ bazel-bin/tvs/test_client/tvs-client_main \
   --tvs_address=localhost:8080 \
   --tvs_public_key=<tvs-primary-or-secondary-public-key> \
   --nouse_tls \
   --verify_report_request_file=<path to request report file> \
   --application_signing_key=<signing key for the request report file> \
   --tvs_authentication_key=<client-authentication-private-key>
```

These examples are for the pre-built keys example above. Substitute as
necessary.

#### Test with valid report

```shell
$ bazel build -c opt //tvs/test_client:tvs-client_main
$ bazel-bin/tvs/test_client/tvs-client_main \
   --tvs_address=localhost:8080 \
   --tvs_public_key=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
   --nouse_tls \
   --verify_report_request_file=tvs/test_data/good_verify_request_report.textproto \
   --application_signing_key=b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23 \
   --tvs_authentication_key=f1af8f26497c24e3944709baccd6b6f4c9326fd902317189f4b2c4adfe2e6af9
```

#### Test with invalid report

```shell
$ bazel build -c opt //tvs/test_client:tvs-client_main
$ bazel-bin/tvs/test_client/tvs-client_main \
    --tvs_address=localhost:8080 \
    --tvs_public_key=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
    --nouse_tls \
    --verify_report_request_file=tvs/test_data/bad_verify_request_report.textproto \
    --application_signing_key=df2eb4193f689c0fd5a266d764b8b6fd28e584b4f826a3ccb96f80fed2949759 \
    --tvs_authentication_key=f1af8f26497c24e3944709baccd6b6f4c9326fd902317189f4b2c4adfe2e6af9
```

### To run a test client in split trust mode:

The general format is as follows. \
Note: provide the tvs_public_keys and tvs_addresses in the same order \
(i.e tvs_public_keys[i] corresponds to the tvs listening on tvs_addresses[i])

```shell
$ bazel build -c opt //tvs/test_client:tvs-client-split_main
$ bazel-bin/tvs/test_client/tvs-client-split_main \
   --tvs_addresses=localhost:8080,localhost:8082 \
   --tvs_public_keys=<tvs1-primary-or-secondary-public-key>,<tvs2-primary-or-secondary-public-key> \
   --nouse_tls \
   --verify_report_request_file=<path to request report file> \
   --application_signing_key=<signing key for the request report file> \
   --tvs_authentication_key=<client-authentication-private-key>
```

These examples are for the pre-built keys example above. Substitute as
necessary.

#### Test with valid report

```shell
$ bazel build -c opt //tvs/test_client:tvs-client-split_main
$ bazel-bin/tvs/test_client/tvs-client-split_main \
   --tvs_addresses=localhost:8080,localhost:8081 \
   --tvs_public_keys=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,045b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
   --nouse_tls \
   --verify_report_request_file=tvs/test_data/good_verify_request_report.textproto \
   --application_signing_key=b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23 \
   --tvs_authentication_key=f1af8f26497c24e3944709baccd6b6f4c9326fd902317189f4b2c4adfe2e6af9
```

#### Test with invalid report

```shell
$ bazel build -c opt //tvs/test_client:tvs-client-split_main
$ bazel-bin/tvs/test_client/tvs-client-split_main \
    --tvs_addresses=localhost:8080,localhost:8081 \
    --tvs_public_keys=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,056b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
    --nouse_tls \
    --verify_report_request_file=tvs/test_data/bad_verify_request_report.textproto \
    --application_signing_key=df2eb4193f689c0fd5a266d764b8b6fd28e584b4f826a3ccb96f80fed2949759 \
    --tvs_authentication_key=f1af8f26497c24e3944709baccd6b6f4c9326fd902317189f4b2c4adfe2e6af9
```

## Run TVS in GCP Mode:

To deploy a new TVS Cloud Run you need to create, KMS encryption key, Spanner
database, and populate the database with keys.

1.  [Create a KMS asymmetric encryption key](https://cloud.google.com/kms/docs/create-key)
1.  Create a Spanner database.

    1.  Obtain GCP credentials:

        ```shell
        $ gcloud auth login
        $ gcloud config set project <gcp-project-name>
        $ gcloud auth application-default login
        ```

        NOTE: `gcloud auth application-default login` is to enable database_main
        CLI to talk to Spanner and KMS, while `gcloud auth login` is for the
        gcloud CLI.

    1.  Create a Spanner database instance:

        ```shell
        $ gcloud spanner instances create <instance_name> \
            --config=<region> \
            --description="TVS instance" \
            --nodes=<nodes>
        ```

    1.  Create a Spanner database: \
        Note: to test the split trust client, create n databases for n tvs
        instances

        ```shell
        $ bazel build //production:database_main
        $ bazel-bin/production/database_main \
            --operation=create_database \
            --spanner_database=<gcp_project>/<database_instance>/<database_name>
        ```

1.  Populate Spanner database with keys: \
    Note: to test the split trust client, repeat for n tvs instances

    ```shell
    $ bazel build //production:database_main
    $ bazel-bin/production/database_main --operation=create_tvs_keys \
        --spanner_database=<gcp_project>/<database_instance>/<database_name> \
        --key_resource_name=<kms_key_resource_name>
    ```

1.  Insert at least one appraisal policy: \
    Note: to test the split trust client, repeat for n tvs instances

    ```shell
    $ bazel build //production:database_main
    $ bazel-bin/production/database_main \
        --operation=insert_appraisal_policy \
        --spanner_database=<gcp_project>/<database_instance>/<database_name> \
        --appraisal_policy_path=<path to appraisal policy>
    ```

1.  Register a user:

    1.  Create a pair of elliptical curve prime256v1 keys for authentication:

        ```shell
        $ bazel run //key_manager:key-gen
        ```

    1.  Insert user information to the TVS database:

        ```shell
        $ bazel build //production:database_main
        $ bazel-bin/production/database_main \
            --operation=register_or_update_user \
            --spanner_database=<gcp_project>/<database_instance>/<database_name> \
            --key_resource_name=<kms_key_resource_name> \
            --user_authentication_public_key=<public key from the above step> \
            --user_name=<user_name> \
            --user_origin=<domain>
        ```

    1.  Insert user information to the TVS database: \
        Note: insert spanner_databases and kms_resource_names in the same
        corresponding order

        ```shell
        $ bazel build //production:database_main
        $ bazel-bin/production/database_main \
            --operation=register_or_update_user_split_trust \
            --spanner_databases=<gcp_project>/<database_instance>/<database_name>,<gcp_project>/<database_instance>/<database_name2> \
            --key_resource_names=<kms_key_resource_name1>,<kms_key_resource_name2> \
            --user_authentication_public_key=<public key from the above step> \
            --user_name=<user_name> \
            --user_origin=<domain>
        ```

1.  Run TVS server: \
    Note: If using the split trust test client, run n tvs instances

    ```shell
    $ bazel build //tvs/standalone_server:tvs-server_main --define platform=gcp
    $ bazel-bin/tvs/standalone_server/tvs-server_main --port=8080 \
        --project_id=<project_id> \
        --instance_id=<spanner_instance> \
        --database_id=<spanner_database_id>
    ```

### To run a test client:

#### Test with valid report

```shell
bazel build -c opt //tvs/test_client:tvs-client_main
bazel-bin/tvs/test_client/tvs-client_main \
    --tvs_address=localhost:8080 \
    --tvs_public_key=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
    --use_tls \
    --verify_report_request_file=tvs/test_data/good_verify_request_report.textproto \
    --application_signing_key=b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23
```

#### Test with invalid report

```shell
bazel build -c opt //tvs/test_client:tvs-client_main
bazel-bin/tvs/test_client/tvs-client_main \
    --tvs_address=localhost:8080 \
    --tvs_public_key=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
    --use_tls \
    --verify_report_request_file=tvs/test_data/bad_verify_request_report.textproto \
    --application_signing_key=df2eb4193f689c0fd5a266d764b8b6fd28e584b4f826a3ccb96f80fed2949759
```

### To run a test client in split trust mode:

#### Test with valid report

```shell
$ bazel build -c opt //tvs/test_client:tvs-client-split_main
$ bazel-bin/tvs/test_client/tvs-client-split_main \
   --tvs_addresses=localhost:8080,localhost:8081 \
   --tvs_public_keys=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,045b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
   --use_tls \
   --verify_report_request_file=tvs/test_data/good_verify_request_report.textproto \
   --application_signing_key=b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23 \
```

#### Test with invalid report

```shell
$ bazel build -c opt //tvs/test_client:tvs-client-split_main
$ bazel-bin/tvs/test_client/tvs-client-split_main \
    --tvs_addresses=localhost:8080,localhost:8081 \
    --tvs_public_keys=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,056b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
    --use_tls \
    --verify_report_request_file=tvs/test_data/bad_verify_request_report.textproto \
    --application_signing_key=df2eb4193f689c0fd5a266d764b8b6fd28e584b4f826a3ccb96f80fed2949759 \
```

To run TVS in split trust mode follow the instructions to run [Untrusted TVS](untrusted_tvs/README.md).
