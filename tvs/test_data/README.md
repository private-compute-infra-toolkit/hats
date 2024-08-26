# TVS Test Data

This directory contains files used in TVS unit-test code.

Text and binary version of the proto are kept in the directory. Text proto is
kept for readability purposes.

## Updating Test Files

To update or add a new test file, create or update an existing textproto and use
`protoc` to convert textproto to binaryproto.

 `protoc` is available under `protobuf-compiler` packages in Debian based
operating systems.

```
 protoc --encode="<proto_message>" <proto_defintion_file> < <textproto> > <binary_proto>
```

For example, to regenerate good\_evidence.textproto run the following: `protoc
--encode="oak.attestation.v1.Evidence"
bazel-hats/external/oak/proto/attestation/evidence.proto <
tvs/test_data/good_evidence.prototext > tvs/test_data/good_evidence.binarypb`

Note that you might need to run `bazel build //...` in order to populate
`bazel-hats`. Alternativley, you can pull `Oak` repository and point `protoc` to
the Oak proto directory.
