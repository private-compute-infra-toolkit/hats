# TVS client

This directory contains code intended to run in the client machine.

For example, scripts and code to run and launch oak containers.

## Launch Oak containers system with KV server using SEV-SNP and QEMU {#build-basic}

Note: this setup is based on AMD's
[V15 patch](https://lore.kernel.org/kvm/20240502231140.GC13783@ls.amr.corp.intel.com/T/).

1.  Build Oak stack and KV server in your workstation, or cloudtop:

    *   Navigate into the cloned hats directory: `$ cd hats`

    *   Fetch the needed submodules `$ git submodule update --init --recursive`

    *   Build the KV server, base system image, stage0, stage1, linux kernels,
        launchers, etc. `$ ./scripts/build.sh`

    The artifacts will be located at the `prebuilt` sub-directory.

1.  Build QEMU from Yu's branch on an SEV-SNP server:

    *   Install build dependencies:

        Note: make sure you have build dependencies installed. On the SEV-SNP
        workstation by running the command `sudo apt build-dep qemu`. The
        command will not work on your workstation or cloudtop as toolchains are
        missing.

        Run the following to get a list of build dependencies and install the
        missing ones: `$ apt-rdepends --build-depends --follow=DEPENDS qemu` You
        might not be able to use QEMU binaries built on your workstation or
        cloudtop.

    *   Fetch QEMU from Yu's branch and build the binary:

        Note: Yu's branch is one commit ahead of AMD's branch
        [snp-v4-wip3c](https://github.com/amdese/qemu/commits/snp-v4-wip3c)

        ```
        $ git clone https://github.com/dingelish/qemu.git \
            --branch ding-qemu/ding-snp-v4-wip3c-patched
        $ cd qemu
        $ ./configure --enable-kvm --target-list=x86_64-softmmu
        $ make -j32
        ```

        The output binary is `./build/qemu-system-x86_64`.

1.  Copy binaries to SEV-SNP machine:

    Copy the prebuilt folder that contains the binaries you built in the first
    step to the SEV-SNP machine (you can use `scp` or `rsync). Copy
    qemu-system-x86 binary from the previous step to the same folder.

1.  Run oak_container_launcher:

    The command will run the launcher that runs the oak container. You may need
    to tweak he path in the script a little to make it work on the SEV-SNP
    server.

    `./scripts/start-oak-sevsnp.sh`

    Note, in this QEMU setup, you do not need shortleash. The local network
    between ost and guest has hardcoded IP addresses: 10.0.2.100 for host and
    10.0.2.15 for guest.

    gLinux offers grpc-cli in its apt. On the SNP machine you need to compile it
    from source.

    ```
    $ git clone --recursive --branch v1.64.0 https://github.com/grpc/grpc
    $ cd grpc
    $ mkdir -p cmake/build
    $ cd cmake/build
    $ cmake -DgRPC_BUILD_TESTS=ON ../..
    $ make -j32 grpc_cli
    $ ls -l grpc_cli
    ```

    Finally run this command to talk with the KV server

    ```
    $ ./grpc/cmake/build/grpc_cli call localhost:50051 \
        kv_server.v1.KeyValueService.GetValues \
       'kv_internal: "hi"'  \
       --channel_creds_type=insecure
    ```

## Launch Oak containers system with TVS

The goal of this section is to provide instructions on launching Oak containers
with QEMU on SEV-SNP that talks to a TVS server and obtains a JWT token.

1.  Build Oak stack with a patched orchestrator and launcher.

    In your workstation or cloudtop:

    *   Navigate into the cloned hats directory:

        ```
        $ cd hats
        ```

    *   Fetch the needed submodules:

        ```
        $ git submodule update --init --recursive
        ```

    *   Call the build script and pass it the TVS public key, which will be
        baked into the configuration that launches the orchestrator:

        ```
        $ ./scripts/build-for-hats.sh <tvs_public_key_in_hex_format>
        ```

    The artifacts will be located at the `prebuilt` sub-directory.

1.  Build QEMU: follow the same instructions in
    [the previous section](#build-basic)

1.  Copy binaries to SEV-SNP machine:

    Copy the prebuilt folder that contains the binaries you built in the first
    step to the SEV-SNP machine (you can use `scp` or `rsync1). Copy
    qemu-system-x86 binary from the previous step to the same folder.

1.  Run oak_container_launcher and TVS server:

    To run a TVS server that listens to port 7774, use the instructions:

    ```
    $ bazel build -c opt //tvs/untrusted_tvs:all
    $ bazel-bin/tvs/untrusted_tvs/tvs-server_main \
      --port=7774 \
      --tvs_private_key=<private_key> \
      --appraisal_policy_file=tvs/appraisal_policies/digests2.prototext

    ```

    Launch the container and pass it the TVS address you ran above.
    `./scripts/start-hats-sevsnp.sh http://localhost:7779`

## Launch Oak containers system with TVS and Parc

The goal of this section is to provide instructions on launching a binary in Oak
Containers (with QEMU on SEP-SNP) that communicate with Parc and TVS. The
orchestrator talks to TVS, obtains a token and pass it to the trusted
application. The trusted application communicates with Parc to fetch
configuration and data.

1.  Build Oak containers stack and hats launcher and orchestrator:

    In your workstation or cloudtop:

    *   Navigate into the cloned hats directory:

        ```
        $ cd hats
        ```

    *   Fetch the needed submodules:

        ```
        $ git submodule update --init --recursive
        ```

    *   Copy the binary you intend to run in a confidential VM to
        client/prebuilt. `$ mkdir -p client/prebuilt && cp <YOUR_BINARY>
        client/prebuilt/`

    *   Modify client/scripts/launch-trusted-app.sh to run your application.
        Note: your application is copied to the CVM under `/usr/bin/server`.
        Result from TVS attestation validation is passed to the shell script as
        the first argument - saved into `$1`.

    *   Call the build script and pass it the TVS public key, which will be
        baked into the configuration that launches the orchestrator:

        ```
        $ ./scripts/build-for-parc.sh <tvs_public_key_in_hex_format>
        ```

    The artifacts will be located in the `prebuilt` sub-directory. Parc
    configuration/data will be located in `prebuilt/parc` sub-directory.

1.  Build QEMU: follow the same instructions in
    [the previous section](#build-basic)

1.  Copy binaries to SEV-SNP machine:

    Copy the prebuilt folder that contains the binaries you built in the first
    step to the SEV-SNP machine (you can use `scp` or `rsync1). Copy
    qemu-system-x86 binary from the previous step to the same folder.

1.  Run hats launcher and TVS server:

    To run a TVS server that listens to port 7774, use the instructions:

    ```
    $ bazel build -c opt //tvs/untrusted_tvs:all
    $ bazel-bin/tvs/untrusted_tvs/tvs-server_main \
      --port=7774 \
      --tvs_private_key=<private_key> \
      --appraisal_policy_file=tvs/appraisal_policies/digests2.prototext \
      --token=<private_hpke_key>
    ```

    Launch the container and pass it the TVS address you ran above.
    `./scripts/start-hats-parc-sevsnp.sh localhost:7779`

1.  (Optional): To run KV-Server that fetches an HPKE private key from TVS You
    can apply client/kv-server.patch to a KV server so that it takes the private
    key as a flag. After running KV-server in a CVM, send encrypted OHTTP
    requests using the public key corresponding the private key passed to the
    private server. You can use the binary in `client/kv-test-client` as
    follows: `kv-test-client --public_key=<public_hpke_key>`. The default park
    data, contains the following keys: foo0, foo1, foo2, foo3, and foo4.

## Steps to download VCEK cert, CA cert and CRL from AMD

After running `./scripts/build.sh` you have a `snphost` binary in the prebuilt
directory. Copy that to the SNP machine and run

```
sudo ./snphost show vcek-url # gives you the URL to download VCEK
sudo ./snphost fetch ca pem . # download the ca cert to `.` in pem format
sudo ./snphost fetch vcek pem . # download the vcek to `.` in pem format
sudo ./snphost fetch crl . # download the revokation list to `.`
```

If you need the certificates in `der` format, just replace `pem` with `der`.

## Steps to launch Oak containers system with KV server using Cloud Hypervisor

```
./scripts/build.sh
./scripts/setup-network.sh
./scripts/start-ch.sh
```

Login with root/root, and run `dhclient` to acquire an IP. Then you can run `apt
update` and install more packages. To shut down, run `poweroff`. The KV server
automatically starts on system startup.

To clean up the network settings, run

```
./scripts/clean_network.sh
```
