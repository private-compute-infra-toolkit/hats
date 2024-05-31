This directory contains a CLI and libraries to test the TEE Verification Service (TVS).

To run a test client CLI:

```
bazel run //tvs/test_client:tvs-client_main -- \
  --tvs_address=localhost:8080 \
  --tvs_public_key=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 \
  --nouse_tls
```
