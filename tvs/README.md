# TEE Verification Service

This is the Privacy Sandbox repo for the TEE Verification Service (TVS). It aims
to verify TEEs such as AMD SEV-SNP or Intel TDX enclaves running in Confidential
VMs (CVMS) anywhere, in an open and publicly verifiable way.

## To run a test server:

```
bazel build -c opt //tvs/untrusted_tvs:tvs-server_main
bazel-bin/tvs/untrusted_tvs/tvs-server_main \
  --port=8080 \
  --tvs_private_key=0000000000000000000000000000000000000000000000000000000000000001 \
  --appraisal_policy_file=tvs/test_data/on-perm-reference.textproto
```

## To run a test client:

### Test with valid report

```
bazel build -c opt //tvs/test_client:tvs-client_main
bazel-bin/tvs/test_client/tvs-client_main \
  --tvs_address=localhost:8080 \
  --tvs_public_key=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
  --nouse_tls \
  --verify_report_request_file=tvs/test_data/good_verify_request_report.prototext
```

### Test with invalid report

bazel build -c opt //tvs/test_client:tvs-client_main
bazel-bin/tvs/test_client/tvs-client_main \
--tvs_address=localhost:8080 \
--tvs_public_key=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
\
--nouse_tls \
--verify_report_request_file=tvs/test_data/bad_verify_request_report.prototext
```
