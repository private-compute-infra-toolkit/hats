# TEE Verification Service

This is the Privacy Sandbox repo for the TEE Verification Service (TVS). It aims
to verify TEEs such as AMD SEV-SNP or Intel TDX enclaves running in Confidential
VMs (CVMS) anywhere, in an open and publicly verifiable way.

## Testing locally

### To run a test server:

```
$ bazel build -c opt //tvs/untrusted_tvs:tvs-server_main
$ bazel-bin/tvs/untrusted_tvs/tvs-server_main \
   --port=8080 \
   --tvs_private_key=0000000000000000000000000000000000000000000000000000000000000001 \
   --appraisal_policy_file=tvs/test_data/on-perm-reference.textproto
```

### To run a test client:

#### Test with valid report

```
$ bazel build -c opt //tvs/test_client:tvs-client_main
$ bazel-bin/tvs/test_client/tvs-client_main \
   --tvs_address=localhost:8080 \
   --tvs_public_key=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
   --nouse_tls \
   --verify_report_request_file=tvs/test_data/good_verify_request_report.prototext \
   --application_signing_key=b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23
```

#### Test with invalid report

```
$ bazel build -c opt //tvs/test_client:tvs-client_main
$ bazel-bin/tvs/test_client/tvs-client_main \
    --tvs_address=localhost:8080 \
    --tvs_public_key=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
    --nouse_tls \
    --verify_report_request_file=tvs/test_data/bad_verify_request_report.prototext \
    --application_signing_key=df2eb4193f689c0fd5a266d764b8b6fd28e584b4f826a3ccb96f80fed2949759
```

## Testing on GCP:

### To run a server on GCP:
1. Build a docker container
```
$ docker build -t tvs-server -f tvs/Dockerfile .
```
1. Authenticate with GCP:
```
$ gcloud auth login
```
1. Tag docker container:
```
$ docker tag tvs-server gcr.io/<project-name>/<your-image-name>
```
1. Push the containe:
```
docker push gcr.io/<project-name>/<your-image-name>
```
1. Deploy the image:
```
$ gcloud run deploy --image=gcr.io/<project-name>/<your-image-name> --use-http2  --min-instances 3 --allow-unauthenticated --region us-central1
```
The command outputs a service URL similar to https://tvs-server-gaig7cicoq-uc.a.run.app

### To run a test client against the cloud instance

Note that you need to enable `use_tls` and you need to provide the service name from above without https:// prefix, and suffix it with :443.

#### Test with valid report

```
$ bazel build -c opt //tvs/test_client:tvs-client_main
$ bazel-bin/tvs/test_client/tvs-client_main \
  --tvs_address=<service_name>:443 \
  --tvs_public_key=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
  --use_tls \
  --verify_report_request_file=tvs/test_data/good_verify_request_report.prototext \
  --application_signing_key=b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23
```

#### Test with invalid report

```
bazel build -c opt //tvs/test_client:tvs-client_main
bazel-bin/tvs/test_client/tvs-client_main \
  --tvs_address=<service_name>:443 \
  --tvs_public_key=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
  --use_tls \
  --verify_report_request_file=tvs/test_data/bad_verify_request_report.prototext \
  --application_signing_key=df2eb4193f689c0fd5a266d764b8b6fd28e584b4f826a3ccb96f80fed2949759
```

#### Test with GCP credentials

If the cloud service requires authentication, you can pass in an access token.

To pass an access token for your account:

```
$ bazel build -c opt //tvs/test_client:tvs-client_main
$ bazel-bin/tvs/test_client/tvs-client_main \
  --tvs_address=<service_name>:443 \
  --tvs_public_key=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
  --use_tls \
  --verify_report_request_file=tvs/test_data/good_verify_request_report.prototext \
  --application_signing_key=b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23 \
  --access_token=$(gcloud auth print-identity-token)
```

To impersonate a service account, you can pass an impersonation access token.
You need permission to impersonate an account.

To pass an impersonation access toke for a service account:

```
$ bazel build -c opt //tvs/test_client:tvs-client_main
$ bazel-bin/tvs/test_client/tvs-client_main \
  --tvs_address=<service_name>:443 \
  --tvs_public_key=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
  --use_tls \
  --verify_report_request_file=tvs/test_data/good_verify_request_report.prototext \
  --application_signing_key=b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23 \
  --access_token=$(gcloud auth print-identity-token --impersonate-service-account <service-account>@<project>.iam.gserviceaccount.com)
```
