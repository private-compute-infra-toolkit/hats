# TVS Test Data

This directory contains files used in TVS unit-test code.

The folder contains Oak evidence proto files generated from CVMs running HATs
stack.

Text and binary version of the proto are kept in the directory. Text proto is
kept for readability purposes.

There are evidence files generated from two SEV SNP CPUs: Genoa and Milan.
From each CPU two evidence were generated from two different images. The images
were slightly modified to print out the application layer signing keys.

The files can be groupd into the following:

## Evidence from Milan CPU
### Evidence from system\_bundle\_test\_single image:

* evidence\_v1\_milan.binarypb: binary proto of Oak evidence.

* evidence\_v1\_milan.txtpb: text proto of Oak evidence.

* evidence\_v1\_milan\_signing\_key: application signing key in hex format.

* vcek\_milan.crt: tee certificate for the AMD SEV SNP from which the evidence
  were generfated. The certificate can be downloaded from:

    ```
    https://kdsintf.amd.com/vcek/v1/Milan/891CA540622657B4FF5F89A856F03BC7DA10CEEE093C6BFFDF64575D0E758D468557C675B74A16168ECE7558C8DF2D080B4B97836228BBB3CE1866D3E6149162?blSPL=04&teeSPL=00&snpSPL=23&ucodeSPL=213
    ```

### Evidence from system\_bundle\_test\_xor\_2 image:

* evidence\_v2\_milan.binarypb: binary proto of Oak evidence.

* evidence\_v2\_milan.txtpb: text proto of Oak evidence.

* evidence\_v2\_milan\_signing\_key: application signing key in hex format.

* vcek\_milan.crt: tee certificate for the AMD SEV SNP from which the evidence
  were generfated. The certificate can be downloaded from:

    ```
    https://kdsintf.amd.com/vcek/v1/Milan/891CA540622657B4FF5F89A856F03BC7DA10CEEE093C6BFFDF64575D0E758D468557C675B74A16168ECE7558C8DF2D080B4B97836228BBB3CE1866D3E6149162?blSPL=04&teeSPL=00&snpSPL=23&ucodeSPL=213
    ```

## Evidence from Genoa CPU
### Evidence from system\_bundle\_test\_single image:

* evidence\_v1\_genoa.binarypb: binary proto of Oak evidence.

* evidence\_v1\_genoa.txtpb: text proto of Oak evidence.

* evidence\_v1\_genoa\_signing\_key: application signing key in hex format.

* vcek\_genoa.crt: tee certificate for the AMD SEV SNP from which the evidence
  were generfated. The certificate can be downloaded from:

    ```
    https://kdsintf.amd.com/vcek/v1/Genoa/D2421D976F95CE0BA849B7CC5C789122F1E59C77A037272C137AE4D188BB102ADBC7C53D0302BFF82A432C94A305DEC7A7A270CEB19A10F04A83316C6486968D?blSPL=10&teeSPL=00&snpSPL=25&ucodeSPL=84
    ```

### Evidence from system\_bundle\_test\_xor\_2 image:

* evidence\_v2\_genoa.binarypb: binary proto of Oak evidence.

* evidence\_v2\_genoa.txtpb: text proto of Oak evidence.

* evidence\_v2\_genoa\_signing\_key: application signing key in hex format.

* vcek\_genoa.crt: tee certificate for the AMD SEV SNP from which the evidence
  were generfated. The certificate can be downloaded from:

    ```
    https://kdsintf.amd.com/vcek/v1/Genoa/D2421D976F95CE0BA849B7CC5C789122F1E59C77A037272C137AE4D188BB102ADBC7C53D0302BFF82A432C94A305DEC7A7A270CEB19A10F04A83316C6486968D?blSPL=10&teeSPL=00&snpSPL=25&ucodeSPL=84
    ```
## Stage0 Binary File

This stage0 binary file was compiled from oak commit d6f890b76203f55446f46edb51b8690eca3adb4c, and is the stage0 OVMF binary that matches with the Genoa and Milan test data evidence. This stage0_bin file is used for testing, primarily for the dynamic_attestation feature.

## Updating Test Files

To update or add a new test file, create or update an existing textproto and use
`protoc` to convert textproto to binaryproto.

`protoc` is available under `protobuf-compiler` packages in Debian based
operating systems.

```shell
 protoc --encode="<proto_message>" <proto_defintion_file> -I<proto_dep1> \
   -I<proto_dep2> ... -I<proto_dep3> < <textproto> > <binary_proto>
```

For example, to regenerate good\_evidence.txtpb run the following:

```shell
protoc --encode="oak.attestation.v1.Evidence" \
  bazel-hats/external/oak/proto/attestation/evidence.proto \
  < tvs/test_data/good_evidence.txtpb \
  > tvs/test_data/good_evidence.binarypb
```

Note that you might need to run `bazel build //...` in order to populate
`bazel-hats`. Alternatively, you can pull `Oak` repository and point `protoc` to
the Oak proto directory.

To convert a proto that depends on multiple protos e.g. VerifyReportRequest, run
the following:

```shell
protoc --encode="pcit.tvs.VerifyReportRequest" \
  tvs/proto/tvs_messages.proto -Itvs/proto -Ibazel-hats/external/oak \
 < tvs/test_data/good_verify_request_report.txtpb \
 > tvs/test_data/good_verify_request_report.binarypb
```


# Milan
Tee certificate
https://kdsintf.amd.com/vcek/v1/Milan/891CA540622657B4FF5F89A856F03BC7DA10CEEE093C6BFFDF64575D0E758D468557C675B74A16168ECE7558C8DF2D080B4B97836228BBB3CE1866D3E6149162?blSPL=04&teeSPL=00&snpSPL=23&ucodeSPL=213
https://kdsintf.amd.com/vcek/v1/Milan/891CA540622657B4FF5F89A856F03BC7DA10CEEE093C6BFFDF64575D0E758D468557C675B74A16168ECE7558C8DF2D080B4B97836228BBB3CE1866D3E6149162?blSPL=04&teeSPL=00&snpSPL=23&ucodeSPL=213

## Evidence

### Milan single
I0814 23:00:08.183023   79345 logs-service.cc:55] oak-orchestrator.service: XXX application key : 2f66807a3ea52469d24f9fced66c5b097b963a86e1c317b1cc1315b2cccf2c52 04646336874c5bb503ae8db60529ed07a2ea86d7e1f55b47f192a6f8cb135b9ab4936487177e2c634798eb9eafea33217cac0bf6624ceda8ec4e23d50abdebaf5e


## system_bundle_test_xor_2.tar

I0814 23:03:15.848781   79633 logs-service.cc:55] oak-orchestrator.service: XXX application key : cc41cd2d558fdb88c2e8acc6b2868a02b388b8e506d13faa962d0ac1cffce52c 04ad0e636c95af1a45db405d106790deb15b71c0a492915061ef63a3ea5a7573180346df578b1eb1ac86f6257159962f549bfdacc41a5bb287ae07bf7df1c002c0


# Genoa
Tee certificate
https://kdsintf.amd.com/vcek/v1/Genoa/D2421D976F95CE0BA849B7CC5C789122F1E59C77A037272C137AE4D188BB102ADBC7C53D0302BFF82A432C94A305DEC7A7A270CEB19A10F04A83316C6486968D?blSPL=10&teeSPL=00&snpSPL=25&ucodeSPL=84

## single
I0814 16:14:40.636075 1431536 logs-service.cc:55] oak-orchestrator.service: XXX application key : be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c 047d3ff731f23f0658e8e1cc287d81eb51d57aee9fad76a6d2b2e66e66ee23d0c5dd5fc844be9e08e91b395a8f369b663457aa38861dfaf3bc9911423d96422b9a


## system_bundle_test_xor_2.tar
I0814 16:16:32.738916 1431868 logs-service.cc:55] oak-orchestrator.service: XXX application key : 90c6593892237eb36a525902340c02a6865a13e37ed9eb73b5123b312a0bb3b0 049053ad41da02ec42745df9496ce3ed586859c475bda756e673805163972f8e2a998dec1ef14b7c8dad96a900b24bc3f003f816a0047b7fe4e8ac15eb0f400ad5
