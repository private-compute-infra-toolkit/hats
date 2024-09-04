# TVS in Production

This directory contains helpers to deploy TVS in production.

## Update TVS in GCP (for internal use)

There are two Cloud Run test TVS instances Hats GCP projects: tvs-server and
 tvs-server-authn (the second enables IAM authentication).

The deployed TVS uses the following Spanner database:

*   Project ID: ps-hats-playground

*   Instance ID: tvs-instance

*   Database ID: tvs-db

Note that the image is built on top of http://gcr.io/distroless/cc-debian12.

To update the deployment with a binary build from the current repository, you
need to update the image and then re-deploy the service:

1.  Obtain GCP credentials:

    ```shell
    $ gcloud auth login
    $ gcloud config set project ps-hats-playground
    $ gcloud auth configure-docker us-docker.pkg.dev
    ```

1.  Build and push TVS server image:

    ```shell
    $ bazel run //production:push_tvs_image --define platform=gcp
    ```

The above command will build an image, push it to the artifact registry and tag
it with *latest*.

1.  Deploy TVS Cloud Run instance that allows unauthenticated requests:

    ```shell
    $ gcloud run deploy tvs-service \
    --image=us-docker.pkg.dev/ps-hats-playground/gcr.io/tvs_image:latest \
    --use-http2 --min-instances 3 --region us-central1 \
    --allow-unauthenticated
    ```

1.  Deploy TVS Cloud Run instance that enforces IAM authentication:

    ```shell
    $ gcloud run deploy tvs-service-authn \
        --image=us-docker.pkg.dev/ps-hats-playground/gcr.io/tvs_image:latest \
        --use-http2 --min-instances 3 --region us-central1 \
        --no-allow-unauthenticated
    ```

### Test tvs-server in GCP

To send test request to tvs-server in GCP, you can use the following test key
for noise authentication
(92d113dcf5f9d5cf2823724e30cfcce4e3bfb39bc1b0eaae7b7b92063cced052).

For TVS public key, you can query the TVS database (or use
042e74bb902c240274100314da105239f36ce1667658758685c57478e46ec55629b66636bdea80332a5b66354e98eac54e3aae245b421d9463597cdc8da946eb74):

```shell
$ gcloud spanner databases execute-sql tvs-db --instance=tvs-instance \
  --sql='SELECT * from TVSPublicKeys'
```

#### Test with valid report
Note: To run the split client, use the build target :tvs-client-split_main and use --tvs_addresses=tvs_address1,tvs_address2 instead of --tvs_addresses and use --tvs_public_keys=pub_key1,pub_key2 instead of --tvs_public_key

```shell
$ bazel build -c opt //tvs/test_client:tvs-client_main
$ bazel-bin/tvs/test_client/tvs-client_main \
    --tvs_address=tvs-service-gaig7cicoq-uc.a.run.app:443 \
    --tvs_public_key=042e74bb902c240274100314da105239f36ce1667658758685c57478e46ec55629b66636bdea80332a5b66354e98eac54e3aae245b421d9463597cdc8da946eb74 \
    --tvs_authentication_key=92d113dcf5f9d5cf2823724e30cfcce4e3bfb39bc1b0eaae7b7b92063cced052 \
    --use_tls \
    --verify_report_request_file=tvs/test_data/good_verify_request_report.textproto \
    --application_signing_key=b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23
```

#### Test with invalid report
Note: To run the split client, use the build target :tvs-client-split_main and use --tvs_addresses=tvs_address1,tvs_address2 instead of --tvs_addresses and use --tvs_public_keys=pub_key1,pub_key2 instead of --tvs_public_key

```shell
$ bazel build -c opt //tvs/test_client:tvs-client_main
$ bazel-bin/tvs/test_client/tvs-client_main \
    --tvs_address=tvs-service-gaig7cicoq-uc.a.run.app:443 \
    --tvs_public_key=042e74bb902c240274100314da105239f36ce1667658758685c57478e46ec55629b66636bdea80332a5b66354e98eac54e3aae245b421d9463597cdc8da946eb74 \
    --tvs_authentication_key=92d113dcf5f9d5cf2823724e30cfcce4e3bfb39bc1b0eaae7b7b92063cced052 \
    --use_tls \
    --verify_report_request_file=tvs/test_data/bad_verify_request_report.textproto \
    --application_signing_key=df2eb4193f689c0fd5a266d764b8b6fd28e584b4f826a3ccb96f80fed2949759
```

### Test tvs-server-authn in GCP

You need to pass in an authenticator with the request through --access_token. To
pass an access token for your account: \
Note: To run the split client, use the build target :tvs-client-split_main and use --tvs_addresses=tvs_address1,tvs_address2 instead of --tvs_addresses and use --tvs_public_keys=pub_key1,pub_key2 instead of --tvs_public_key

```shell
$ bazel build -c opt //tvs/test_client:tvs-client_main
$ bazel-bin/tvs/test_client/tvs-client_main \
    --tvs_address=tvs-service-authn-gaig7cicoq-uc.a.run.app:443 \
    --tvs_public_key=042e74bb902c240274100314da105239f36ce1667658758685c57478e46ec55629b66636bdea80332a5b66354e98eac54e3aae245b421d9463597cdc8da946eb74 \
    --tvs_authentication_key=92d113dcf5f9d5cf2823724e30cfcce4e3bfb39bc1b0eaae7b7b92063cced052 \
    --use_tls \
    --verify_report_request_file=tvs/test_data/good_verify_request_report.textproto \
    --application_signing_key=b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23 \
    --access_token=$(gcloud auth print-identity-token)
```

To impersonate a service account, you can pass an impersonation access token.
You need permission to impersonate an account, and the impersonation account
needs to have cloud run invoker permission.

To pass an impersonation access token for a service account: \
Note: To run the split client, use the build target :tvs-client-split_main and use --tvs_addresses=tvs_address1,tvs_address2 instead of --tvs_addresses and use --tvs_public_keys=pub_key1,pub_key2 instead of --tvs_public_key

```shell
$ bazel build -c opt //tvs/test_client:tvs-client_main
$ bazel-bin/tvs/test_client/tvs-client_main \
    --tvs_address=tvs-service-authn-gaig7cicoq-uc.a.run.app:443 \
    --tvs_public_key=042e74bb902c240274100314da105239f36ce1667658758685c57478e46ec55629b66636bdea80332a5b66354e98eac54e3aae245b421d9463597cdc8da946eb74 \
    --tvs_authentication_key=92d113dcf5f9d5cf2823724e30cfcce4e3bfb39bc1b0eaae7b7b92063cced052 \
    --use_tls \
    --verify_report_request_file=tvs/test_data/good_verify_request_report.textproto \
    --application_signing_key=b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23 \
    --access_token=$(gcloud auth print-identity-token --impersonate-service-account <service-account>@<project>.iam.gserviceaccount.com)
```

## Deploy a new TVS Cloud Run instance in GCP

To deploy a new TVS Cloud Run you need to create, KMS encryption key, Spanner
database, populate the database with keys, deploy an image to the registry and
deploy a Cloud Run Instance.

1.  [Create a KMS asymmetric encryption key](https://cloud.google.com/kms/docs/create-key)
1.  Create a Spanner database:

    a. Obtain GCP credentials:

    ```shell
    $ gcloud auth login
    $ gcloud config set project <gcp-project-name>
    $ gcloud auth application-default login
    ```

    NOTE: `gcloud auth application-default login` is to enable database_main CLI
    to talk to Spanner and KMS, while `gcloud auth login` is for the gcloud CLI.

    a. Create a Spanner database instance:

    ```shell
    $ gcloud spanner instances create <instance_name> \
    --config=<region> \
    --description="TVS instance" \
    --nodes=<nodes>
    ```

    a. Create a Spanner database: \
    Note: For split trust, create n databases for n tvs instances

    ```shell
    $ bazel build //production:database_main
    $ bazel-bin/production/database_main \
        --operation=create_database \
        --spanner_database=<gcp_project>/<database_instance>/<database_name>
    ```

1.  Populate Spanner database with keys:

    ```shell
    $ bazel build //production:database_main
    $ bazel-bin/production/database_main --operation=create_tvs_keys \
    --spanner_database=<gcp_project>/<database_instance>/<database_name> \
    --key_resource_name=<kms_key_resource_name>
    ```

1.  Insert at least one appraisal policy:

    ```shell
    $ bazel build //production:database_main
    $ bazel-bin/production/database_main \
        --operation=insert_appraisal_policy \
        --spanner_database=<gcp_project>/<database_instance>/<database_name> \
        --appraisal_policy_path=<path to appraisal policy>
    ```

1.  Register a user using split trust:

    a. Create a pair of elliptical curve prime256v1 keys for authentication:

    ```shell
    $ bazel run //key_manager:key-gen
    ```

    a. Insert user information to the TVS database:

    ```shell
    $ bazel build //production:database_main
    $ bazel-bin/production/database_main \
    --operation=register_or_update_user_split_trust
    --spanner_databases=<gcp_project>/<database_instance>/<database_name1>,<gcp_project>/<database_instance>/<database_name2> \
    --key_resource_names=<kms_key_resource_name1>,<kms_key_resource_name2> \
    --user_authentication_public_key=<public key from the above step> \
    --user_name=<user_name> \
    --user_origin=<domain>
    ```

1.  Register a user:

    a. Create a pair of elliptical curve prime256v1 keys for authentication:

    ```shell
    $ bazel run //key_manager:key-gen
    ```

    a. Insert user information to the TVS database:

    ```shell
    $ bazel build //production:database_main
    $ bazel-bin/production/database_main \
    --operation=register_or_update_user
    --spanner_database=<gcp_project>/<database_instance>/<database_name> \
    --key_resource_name=<kms_key_resource_name> \
    --user_authentication_public_key=<public key from the above step> \
    --user_name=<user_name> \
    --user_origin=<domain>
    ```

1.  Create and deploy an image to GCP:

    a. Obtain GCP credentials:

    ```shell
    $ gcloud auth login
    $ gcloud config set project <gcp-project>
    $ gcloud auth configure-docker us-docker.pkg.dev
    ```

    a. Open production/BUILD for editing.

    a. Pass in the Spanner database information you created earlier in the
    entrypoint in the "tvs_image" rule.

    a. Change "oci_push* rule to point to your GCP repository.

    a. Build & push TVS server image:

    ```shell
    $ bazel run //production:push_tvs_image --define platform=gcp
    ```

1.  Deploy TVS Cloud Run instance:

    ```shell
    $ gcloud run deploy tvs-service --image=<image_url> --use-http2  --min-instances 3 --region <region>
    ```
