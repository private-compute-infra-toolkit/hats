# HATs CVM (Client Code)

This directory contains code and configuration to a workload in a CVM.

HATs provides a framework to run application in confidential virtual machines
with remote attestation. The goal is to provide a mechanism to run workload and
*ensure* the workload is running in a CVM operated on approved hardware and
software. To do so, HATs utilizes Oak containers with hardware capable of
generating attestation reports with signatures chained to trusted vendors.
Client package the workload into a runtime bundle and run it in HATs CVM that
that generates an attestation report containing measurements of the CVM stack.
The CVM launches the workload after it receives clearance and necessary
materials from the tee verification service (TVS). The TVS typically stores
cryptographic key materials that are released after it receives a valid report
over an authenticated channel. The measurements in the attestation report should
pass the appraisal policy loaded into the TVS.

NOTE: All the instructions below assumes that the current working directory is
HATs repository root (all paths are relative to the repository root).

NOTE: You can run HATs framework on insecure VM for testing.

# Prerequisite

In order to use HATs CVM you need:

1.  AMD SEV-SNP machine running Linux: the machine should have SEV-SNP enabled
    in the BIOS and the kernel.

1.  QEMU (version >= 9.2.0-rc3): build QEMU in the SNP machine.

    Installation and version can be checked with e.g. `$
    /usr/bin/qemu-system-x86_64 --version`

    *   Install build dependencies:

        Note: make sure you have build dependencies installed. On the SEV-SNP
        workstation by running the command `sudo apt build-dep qemu`. The
        command will not work on your workstation or cloudtop as toolchains are
        missing.

        Run the following to get a list of build dependencies and install the
        missing ones: `$ apt-rdepends --build-depends --follow=DEPENDS qemu`.
        You may need to install `apt-rdepends` first. You might not be able to
        use QEMU binaries built on your workstation or cloudtop.

    *   Download and compile QEMU:

        ```shell
        $ wget https://download.qemu.org/qemu-9.2.0-rc3.tar.xz
        $ tar xvJf qemu-9.2.0-rc3.tar.xz
        $ cd qemu-9.2.0-rc3
        $ ./configure --enable-slirp --enable-kvm --target-list=x86_64-softmmu
        $ make -j32
        ```

    *   Copy the build QEMU binary to a known location e.g. `/usr/local/bin`:

        ```shell
        $ cp qemu-9.2.0-rc3/build/qemu-system-x86_64 /usr/local/bin/
        ```

    *   Give the current user permission to use `/dev/kvm` and `/dev/sev`. You
        can do so by adding the user to `kvm` group, and give the group read
        access to the devices:

        ```shell
        $ sudo usermod -G kvm ${USER}
        $ sudo chgrp kvm /dev/kvm
        $ sudo chgrp kvm /dev/sev
        $ sudo chmod g+r+w /dev/kvm
        $ sudo chmod g+r+w /dev/sev
        ```

1.  Build CVM binaries: Oak's stage0, kernel, stage1, and HATs system image. You
    can use `./client/trusted_application/build_for_test.sh` to build the binaries. The
    script copies the built binaries to `./client/prebuilt`.

    NOTE: the binaries can be built from your workstation. They do not need to
    be build on the SEV-SNP server.

1.  Build the TVS server:

    ```shell
    $ bazel build -c opt //tvs/standalone_server:tvs-server_main
    ```

    Or you can use `./client/trusted_application/build_for_test.sh` that builds the TVS server
    and copies it to `./client/prebuilt`. In this case use
    `./client/prebuilt/tvs-server_main` over `bazel-bin/client/tvs-server_main`.

1.  Run a TVS Server: follow this [instructions](../tvs/README.md).

1.  Write a CVM configuration file:

    ```textproto
    cvm_config {
        cvm_type: CVMTYPE_SEVSNP
        runc_runtime_bundle: <path to the workload runtime bundle>
        hats_system_bundle: "client/prebuilt/system_bundle.tar"
        num_cpus: 4
        ramdrive_size_kb: 10485760
        ram_size_kb: 8000000
        vmm_binary: "/usr/local/bin/qemu-system-x86_64"
        network_config {
            inbound_only {
                host_enclave_app_proxy_port: <port that the workload listens to>
            }
        }
    }
    ```

1.  Run the launcher in an SEV-SNP machine:

    ```shell
    $ ./client/prebuilt/launcher_main \
        --tvs_addresses=localhost:7779 \
        --use_tls=false \
        --launcher_config_path=<path to launcher configuration from previous step> \
        --tvs_authentication_key=<authentication key from setting up TVS> \
    ```

    NOTE: In case of `Error downloading certificate from ...` with error code
    77, please specify the CA bundle with `--curl_opt_cainfo='<path to ca bundle
    certs>'`. You can find the CA bundle with `curl-config --ca` if curl is
    installed.

## Launch Oak containers system with TVS and Trusted Application
Please follow the instructions in trusted_application folder to spin up an
example of a fully attested Trusted Application. Here the Trusted Application
is a simple echo server that receives encrypted messages, then decrypts the
message with the keys derived from the TVS and returns it.

# CVM Networking

HATs offers three way to configure networking for a CVM:

NOTE: networking configuration is visible in the attestation report, and needs
to be specified in the TVS appraisal policy. The configuration are passed to the
CVM via kernel command line arguments.

1.  inbound_only: only inbound traffic to a single port from the host to the
    CVM. The configuration specifies a port in the host that is forwarded to
    port 8080 in the CVM. Outbound connection to the host is allowed but there
    are no routing rules added to tell the CVM to use the host as a gateway.

1.  inbound_and_outbound: arbitrary outbound traffic to the network is allowed
    (the host can forward the traffic to the outside world). only inbound
    traffic to a single port from the host to the CVM. The configuration
    specifies a port in the host that is forwarded to port 8080 in the CVM.

1.  virtual_bridge: a TAP interface connected to the CVM is added to a virtual
    bridge in the host. The user can add the physical network interface to the
    bridge to allow CVM to connect to the DHCP in the network. Or the user can
    create a subnet for the CVM in the host and if they choose to they can route
    traffic from and to the CVM.

For illustration, we will create a toy shell and try it with the different
network configuration.

## Setup

1.Build CVM binaries: Oak's stage0, kernel, stage1, and HATs system image.

```shell
   $ ./client/trusted_application/build_for_test.sh
```

The script copies the binaries to `client/prebuilt`. Copy the directory to the
SEV-SNP machine.

1.  Open your favorite editor and copy the following code (we will name the file
    reverse-shell.cc):

    ```c++
    #include <netinet/in.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <sys/socket.h>
    #include <unistd.h>

    #include <cstdlib>

    int main(int argc, char** argv) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("socket() failed\n");
        return 1;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                    sizeof(opt))) {
        printf("setsockopt() failed\n");
        return 1;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        printf("bind() failed\n");
        return 1;
    }

    if (listen(server_fd, 3) < 0) {
        printf("listen() failed\n");
        return 1;
    }

    while (true) {
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) <
            0) {
        printf("accept() failed\n");
        return 1;
        }
        printf("Accepting connection...\n");
        dup2(new_socket, 0);
        dup2(new_socket, 1);
        dup2(new_socket, 2);
        system("/bin/sh");
    }
    }
    ```

1.  Compile the program and copy it to the `/tmp` directory:

    ```shell
    $ g++ reverse-shell.cc -o reverse-shell
    $ cp reverse-shell /tmp/
    ```

1.  Package the program into a runtime bundle:

    *   Create a temporary directory:

        ```shell
        $ mkdir /tmp/my_bundle
        ```

    *   Create a rootf: we will use busybox docker image:

        ```shell
        $ cd /tmp/my_bundle
        $ mkdir rootfs
        $ docker export $(docker create busybox) | tar -C rootfs -xvf -
        ```

    *   Copy your reverse-shell into the rootfs:

        ```shell
        $ cp /tmp/reverse-shell rootfs/bin/
        ```

    *   Create a rootless spec:

        ```shell
        $ cd /tmp/my_bundle
        $ runc spec --rootless
        ```

    *   Open `/tmp/my_bundle/config.json` and change the *args* section to be as
        follows:

        ```json
                    "args": [
                            "/bin/reverse-shell"
                    ],
        ```

    *   Create a bundle tarball:

        ```shell
        $ cd /tmp/my_bundle
        $ tar cf runtime_bundle.tar *
        ```

    *   Copy runtime_bundle.tar to the prebuilt directory.

1.  Create an appraisal policy:

    *   Calculate the sha256 of the runtime_bundle.tar

        ```shell
        $ openssl sha256 runtime_bundle.tar
        ```

    *   Create the following appraisal policy in the prebuilt directory and call
        it appraisal_policy.txtpb:

        ```textproto
        policies {
          measurement {
            stage0_measurement {
              amd_sev {
                sha384: "4cca87bd71495f8484343f9524bf9a866c98851b8bfcadbd385fdc798ace74fce976ebe70c3d6ded70b86980cab5e4c5"
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
            acpi_table_sha256: "6006fa52084ec0da69ff2e63bb4abba78a4aeeb457f4eb4d3a75b3b114ec862d"
            kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$"
            system_image_sha256: "49a3b093050502412e0c7dd2f58a9f2197ca0c48c3a46fad048da80a04bfc601"
            container_binary_sha256: "<digest from the step above>"
          }
        }
        ```

1.  Generate a pair of prime256v1 of keys to use it as an authentication key to
    the TVS by running:

    ```shell
    $ bazel run //key_manager:key-gen -- --key-type secp128r1
    ```

    The command above prints a public and private key in hex string format. The
    private key is passed to the CVM through the launcher, the public key is
    given to the TVS.

1.  Run TVS server: navigate to the prebuilt directory and run the following

    ```shell
    $ ./tvs-server_main \
    --port=7779  \
    --primary_private_key=0000000000000000000000000000000000000000000000000000000000000001   \
    --appraisal_policy_file=./appraisal_policy.txtpb \
    --user_authentication_public_key=<public key of prime256v1 from the steps above> \
    --user_key_id=1 \
    ```

## inbound_only networking mode:

1.  Create or edit a file in the prebuilt directory launcher_config.txtpb and
    copy the following:

    ```textproto
    cvm_config {
        cvm_type: CVMTYPE_SEVSNP
        runc_runtime_bundle: "./runtime_bundle.tar"
        hats_system_bundle: "./system_bundle.tar"
        num_cpus: 4
        ramdrive_size_kb: 10485760
        ram_size_kb: 8000000
        vmm_binary: "/usr/local/bin/qemu-system-x86_64"
        network_config {
          inbound_only {
            host_enclave_app_proxy_port: 8050
          }
        }
    }
    ```

1.  Launch the CVM:

    ```shell
    ./launcher_main \
        --tvs_addresses=localhost:7779 \
        --use_tls=false \
        --launcher_config_path=./launcher_config.txtpb \
        --tvs_authentication_key=<private key of prime256v1 from above> \
        --minloglevel=0 \
        --stderrthreshold=0
    ```

1.  Connect to the CVM from the host over port 8050: after the CVM boots and
    launches your program run the following from the host:

    ```shell
    $ nc localhost 8050
    ls
    ```

    You will see the following:

    ```shell
    bin
    dev
    etc
    home
    lib
    lib64
    oak_utils
    proc
    root
    sys
    tmp
    usr
    var
    ```

1.  Try to connect from the CVM to the outside world (this should fail).

    ```shell
    $ nc localhost 8050
    nslookup www.google.com 4.2.2.2
    nslookup: can't connect to remote host (4.2.2.2): Network is unreachable
    ```

## inbound_and_outbound networking mode:

1.  Create or edit a file in the prebuilt directory launcher_config.txtpb and
    copy the following:

    ```textproto
    cvm_config {
      cvm_type: CVMTYPE_SEVSNP
      runc_runtime_bundle: "./runtime_bundle.tar"
      hats_system_bundle: "./system_bundle.tar"
      num_cpus: 4
      ramdrive_size_kb: 10485760
      ram_size_kb: 8000000
      vmm_binary: "/usr/local/bin/qemu-system-x86_64"
      network_config {
        inbound_and_outbound {
          host_enclave_app_proxy_port: 8050
        }
      }
    }
    ```

1.  Modify the kernel_cmd_line_regex in the appraisal policy to be

    ```
    kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15::10.0.2.2:255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$"
    ```

1.  Restart the TVS server

1.  Launch the CVM:

    ```shell
    ./launcher_main \
        --tvs_addresses=localhost:7779 \
        --use_tls=false \
        --launcher_config_path=./launcher_config.txtpb \
        --tvs_authentication_key=<private key of prime256v1 from above> \
        --minloglevel=0 \
        --stderrthreshold=0
    ```

1.  Connect to the CVM from the host over port 8050: after the CVM boots and
    launches your program run the following from the host:

    ```shell
    $ nc localhost 8050
    nslookup www.google.com 4.2.2.2
    Server:         4.2.2.2
    Address:        4.2.2.2:53

    Non-authoritative answer:
    Name:   www.google.com
    Address: 142.250.191.36

    Non-authoritative answer:
    Name:   www.google.com
    Address: 2607:f8b0:4005:80e::2004
    ```

You notice that the CVM was able to reach the outside world as it was using the
host as a gateway.

# virtual_bridge networking mode:

We will assign a routable IP address to the CVM. The IP address is accessible
from the host, and can be accessible from the network.

1.  Create virtual bridge and assign 192.168.111.11 address to it:

    ```shell
    $ sudo ip link add my_bridge type bridge
    $ sudo ip link set my_bridge up
    $ sudo ip addr add 192.168.111.11/24 dev my_bridge
    ```

1.  Create or edit a file in the prebuilt directory `launcher_config.txtpb` and
    copy the following:

    ```textproto
    cvm_config {
      cvm_type: CVMTYPE_SEVSNP
      runc_runtime_bundle: "./runtime_bundle.tar"
      hats_system_bundle: "./system_bundle.tar"
      num_cpus: 4
      ramdrive_size_kb: 10485760
      ram_size_kb: 8000000
      vmm_binary: "/usr/local/bin/qemu-system-x86_64"
      network_config {
        virtual_bridge {
            virtual_bridge_device: "my_bridge"
            cvm_ip_addr: "192.168.111.12"
            cvm_gateway_addr: "192.168.111.11"
        }
      }
    }
    ```

    We gave the CVM 192.168.111.12 address, and told it the gateway is the host
    (192.168.111.11) and we told the launcher to add the TAP interface to
    my_bridge.

1.  Modify the `kernel_cmd_line_regex` in the appraisal policy to be

    ```
    kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=192.168.111.12::192.168.111.11:255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$"
    ```

1.  Restart the TVS server

1.  Launch the CVM (notice you either need root or ADMIN_NET_CAP):

    ```shell
    sudo ./launcher_main \
        --tvs_addresses=localhost:7779 \
        --use_tls=false \
        --launcher_config_path=./launcher_config.txtpb \
        --tvs_authentication_key=<private key of prime256v1 from above> \
        --minloglevel=0 \
        --stderrthreshold=0
    ```

1.  Connect to the CVM from the host over port 8080: after the CVM boots and
    launches your program run the following from the host:

    You will see the following:

    ```shell
    bin
    dev
    etc
    home
    lib
    lib64
    oak_utils
    proc
    root
    sys
    tmp
    usr
    var
    ```

Notice that we connected to the CVM using its address and the port that the
workload is listening to instead of a forwarded port. In this mode you can reach
the CVM directly.
