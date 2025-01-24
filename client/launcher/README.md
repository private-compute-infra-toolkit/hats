# HATs Launcher

This directory contains libraries and a binary to launch HATs CVM.

The folder contains the following C++ libraries:

1. launcher: starts RPC servers for the CVMs, and launches a VMM. The launcher
passes the system image and workload bundle to the CVM.

1. launcher-server: implements RPC services for the CVMs. In particular it
implements the following services:

    * LauncherOakServer: passes the system image and workload bundle to the CVM.

    * LauncherServer: proxies requests to TVS, and passes chip endorsement
    certificate to the orchestrator in the CVM.

1. logs-service: implements RPC services for the CVM to exports its log to the
   launcher.

1. qemu: manages and start qemu VMMs.

1. certificates: downloads chip endorsement certificates from the vendor's key
   distribution portoal. The library reads the CPU model, and ID information to
   find the certificate. The library select one launcher to download the tee
   certificate instead of each one downloading a clone.

The folder contains `launcher_main` binaries to launch a CVM. The binary
exports the following command line flags:

* `--launcher_config_path`: a path to a configuration proto files that contains the
  VMM settings and whether or not to start auxiliary services.

* `--tvs_addresses`: Comma separated list of tvs addresses to use in the
  following format: <tvs address 1>, <tvs address 2>.

* `--use_tls`: wheter or not to use TLS to when talking to the TVS.

* `--tvs_access_token`: a token to be attached to the gRPC meta-data for
  authentication. Used by GCP to authenticate requests.

* `--vmm_log_to_std`: whether or not to send VMM logs to standard output.
  By default logs are written to a temporary file.
