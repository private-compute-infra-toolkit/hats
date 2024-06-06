# TVS client

This directory contains code intended to run in the client machine.

For example, scripts and code to run and launch oak containers.

## Launch Oak containers system with KV server using SEV-SNP and QEMU

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
