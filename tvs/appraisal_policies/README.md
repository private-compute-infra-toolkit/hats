# Appraisal Policies

This directory contains code and configurations related to appraisal policies.

Appraisal policy is a set of digests (hashes) and configuration that is used to
evaluate attestation reports. The policy is
policies to describe acceptable attestation report.

The policy describes a full Oak container system.
The following is an example that describes a workload running in Oak's container
on AMD SNP-SEV CVM:

```
policies {
  description: "Policy for KV running in an AMD SEV-SNP CVM. Cores: 1, RAM: 8000000 KB"
  measurement {
    stage0_measurement {
      amd_sev {
        sha384: "79a2cde473c9bb5708b16e9dd5ad0f3a38ed9da8c1d75f8c4bd5bc80dc1ea994d31987dab22e7feb910945e038e006a4"
        min_tcb_version {
          boot_loader: 7
          snp: 15
          microcode: 62
        }
      }
    }
    kernel_image_sha256: "eca5ef41f6dc7e930d8e9376e78d19802c49f5a24a14c0be18c8e0e3a8be3e84"
    kernel_setup_data_sha256: "9745b0f42d03054bb49033b766177e571f51f511c1368611d2ee268a704c641b"
    init_ram_fs_sha256: "7cd4896bdd958f67a6a85cc1cc780761ac9615bc25ae4436aad1d4e9d2332c1a"
    memory_map_sha256: "c9a26ba0a492465327894303dc6b1bd23a41cc1093fe96daa05fa7de0d25e392"
    acpi_table_sha256: "453d27f58b75156f3f9fdbd4d4cf1eaec4fb5a3968fb6aca198ebb56ad9f20fc"
    kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$"
    system_image_sha256: "49a3b093050502412e0c7dd2f58a9f2197ca0c48c3a46fad048da80a04bfc601"
    container_binary_sha256: "cb31d889e33eaf9e3b43cdbeb3554903c36b5e037c5187e876a69e8c5b5d864c"
  }
  signature {
    signature: "7ac4d3eec543041c5b98f1f73efc299f95820480bcee90f0f8a7aa237fe702cd1ad27a1614e42682edc3908b54a2f1b03b47bd803eba8f80884417f20eb82537"
    signer: "hats"
  }
}
```

The folder contains the following C++ libraries:

1.  policy-fetcher-interface: describes an interface for policy fetcher
    implementation. Policy fetcher retrieves policies from data storage. An
    implementation of a policy fetcher should implement the following methods:

    *   GetLatestNPolicies: retrieves **n** most recent policies. The method has
        the following signature

        ```
            absl::StatusOr<AppraisalPolicies> GetLatestNPolicies(int n)
        ```

    *   GetLatestNPoliciesForDigest: retrieves **n** most recent policies that
        has have `application_digest`. Note that the digest is in
        binary representation (versus hexdigit string). The method has the
        following signature

    ```
    absl::StatusOr<AppraisalPolicies> GetLatestNPoliciesForDigest(
        absl::string_view application_digest, int n) = 0;
    ```

1.  policy-fetcher-local: fetches policies passed via command line flags. The
    class loads policies from a file location specified via
    `--appraisal_policy_file`.

1.  policy-fetcher-gcp: fetches policies from a Spanner GCP database. The class
    connect to a spanner database specified by the following flags:
    `--project_id`, `--instance_id`, and `database_id`.

    The implementation expect policies to be stored in a table called
    `AppraisalPolicies`, with the following schema:

    ~~~
    CREATE TABLE AppraisalPolicies (
       PolicyId INT64 DEFAULT (GET_NEXT_SEQUENCE_VALUE(SEQUENCE UserIdSequence)),
       ApplicationDigest BYTES(MAX) NOT NULL,
       Policy BYTES(MAX) NOT NULL,
       UpdateTimestamp TIMESTAMP NOT NULL,
     ) PRIMARY KEY(PolicyId);

     CREATE INDEX ApplicationDigestIndex ON AppraisalPolicies(ApplicationDigest);

     CREATE SEQUENCE PolicyIdSequence OPTIONS (
       sequence_kind = 'bit_reversed_positive'
     );
    ~~~

    *   PolicyId: a string used to identify the appraisal policy.
    *   ApplicationDigest: sha256 of the application bundle (in binary format).
        fetch policies for a certain application.
    *   UpdateTimestamp: timestamp of the last update to the row.
    *   Policy: binary representation of the appraisal policy proto.

The folder contains the following Rust crates:

1. policy_manager: validates measurements against a given appraisal policies.
   The crate takes serialized appraisal policies, decode them
   and convert them to Oak's ReferenceValue proto.

1. policy_signature: validates and generate signatures attached to an appraisal
   policy.

1. dynamic_policy_manager: validate measurements against appraisal policies from
   storage. The crate calls C++ PolicyFetcher object to retrieve policies from
   storage and then passes the to policy_mnager for validation.

## Create an Appraisal Policy

To create appraisal policy for your application to be accepted by a Tee
Verification Service (TVS), you need to specify digests for various components
of the CVM stack, command line parameters, and minimum TCB versions.

Start building the necessary components by following the instructions to build
[HATs CVM](../../client/README.md).

*   amd_sev stage0 measurement:

    *   sha384: use [sev-snp-measure](https://github.com/virtee/sev-snp-measure)
        to calculate the hash. Run the following command from any machine:

        ```shell
        $ ./sev-snp-measure.py --ovmf=<path to stage0> \
          --mode=snp \
          --vcpu-family=<family> \
          --vcpu-model=<model> \
          --vcpu-stepping=<stepping> \
          --vcpus <num_cpus>
        ```

        *   `--ovmf` is the path to stage0_bin. The file is in system_bundle.tar
            in the prebuilt directory.

        *   `--vcpu-family`: is the SEV-SNP CPU family running the CVM. You can
            get the model by running `cat /proc/cpuinfo | grep "cpu family"` in
            the SEV-SNP machine.

        *   `--vcpu-model`: is the SEV-SNP CPU model running the CVM. You can
            get the model by running `cat /proc/cpuinfo | grep "model" | grep -v
            name` in the SEV-SNP machine.

        *   `--vcpu-model`: is the SEV-SNP CPU stepping running the CVM. You can
            get the model by running `cat /proc/cpuinfo | grep "stepping"` in
            the SEV-SNP machine.

        *   `--vcpus`: the number of virtual CPUs in the CVM. This should
            matches `num_cpus` in the
            [launcher configuration proto](../../client/proto/launcher_config.proto)

    *   min_tcb_version: is the minimum accepted TCB version. You can get the
        TCB version in your SEV_SNP machine by using
        [snphost tool](https://github.com/virtee/snphost). You can run the
        following:

        ```shell
        $ snphost show tcb
        ```

*   kernel_image_sha256: Copy *Kernel image digest* from the launcher log.

*   kernel_setup_data_sha256: Copy *Kernel setup data digest* from the launcher
    log.

*   init_ram_fs_sha256: Copy *Initial RAM disk digest* from the launcher log.

*   memory_map_sha256: Copy *E820 table digest* from the launcher log.

*   acpi_table_sha256: Copy *ACPI table generation digest* from the launcher
    log.

*   kernel_cmd_line_regex: Write a regular expression that matches *Kernel
    command-line* from the launcher log.

*   system_image_sha256: sha256 digest of system.tar.xz file is in
    system_bundle.tar in the prebuilt directory.

*   container_binary_sha256: sha256 digest of the application tarball bundle.

Note: follow the instructions in [HATs CVM](../../client/README.md).
 to run the launcher and add `--qemu_log_to_std` parameter to print measurements
 to standard output.
