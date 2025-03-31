# System Image

This directory contains files and bazel rules to build a system image usable
by HATs CVMs.

The system image is a tarball of a Linux OS filesystem.

The image is built on top of Oak's system image, which builds on top of a
stripped down version of Debian OS. HATs system image override some files in
Oak's system image and add one more file.

In particular the following files are added/overridden to the system image.

1.  tvs_public_keys.txt: contains the TVS public keys in hex string format. The
    keys are prefixed with an index (starting from zero) with colon ":"
    separating the index from the key. The index tells the orchestrator what TVS
    instance the key belongs to. The user passes the launcher a number of TVS
    addresses and the index corresponds to their position in the list. The file
    is copied to `/hats/`.

1.  oak-orchestrator.service: tells systemd how to start the orchestrator. In
    HATs we use vsock to communicate with the launcher, and this file modifies
    the one Oak's uses to replace TCP/IP address with vsock. The file is copied
    to `/etc/systemd/system/`.

1. oak-syslogd.service: tells systemd how to start the syslogd agent. The agent
    relies logs printed to stdout/stderr to the launcher. In HATs we use vsock
    to communicate with the launcher, and this file modifies the one Oak's uses
    to replace TCP/IP address with vsock. The file is copied
    to `/etc/systemd/system/`.

1. 10-enp0s1.network: an empty file to nullify the network interface
   configuration. In HATs we use kernel command line parameters to configure the
   network. We do so for the following reasons:

   * Network configuration is in the attestation report: this way we can specify
   the acceptable configuration in the TVS appraisal policies.

   * HATs support multiple networking modes: SLiRP vs. virtual bridges.

    The files is copied to /etc/systemd/network/

1. HATs orchestrator: the binary that fetches and measures the workload from the
orchestrator, talks to the TVS to obtain the workload secrets, and pass the
secrets to the workload. The binary is compiled from
`//client/orchestrator:orchestrator_main` and copied to `/usr/bin/`.

1. Oak's syslogd and containers agents: are compiled from Oak's repository
and copied to `/usr/bin/`.
