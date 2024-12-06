# HATs orchestrator

This directory contains code for HATs orchestrator. The orchestrator is
responsible to obtain the workload from the launcher, measures the workload,
send the attestation report to the TVS through the launcher, and run the workload
in a runc container.
HATs orchestator is modified version of Oak's to add a mechanism to talk to the
TVS and passes secrets to the workload.

The orchestrator also exports a number of RPCs to the workload over unix domain
sockets to pass secrets obtained from the TVS.

The directory contains the following Rust crates:

1. tvs-grpc-client: A client to talk to the TVS through the launcher over
   vsock. TVS uses bidirectional streaming gRPC.

1. hats-server: exports a number of gRPC services to the workload over UDS
socket.


The directory contains orchestrator_main binary and receives the following
command line flags:

* `--launcher-addr`: the address to reach the launcher.

* `--container-dir`: directory to unpack workload tarball into.

* `--ipc-socket-path`: UDS socket path over which the orchestrator exports
its services to the workload.

* `--runtime-user`: user name to run the workload container under. The
orchestrator uses runs the workload in a rootless container where the root
inside the container is mapped to the runtime-user.

* `--tvs-public-keys-file`: contains the TVS public keys in hex string format.
    The keys are prefixed with an index (starting from zero) with colon ":"
    separating the index from the key. The index tells the orchestrator what TVS
    instance the key belongs to. The user passes the launcher a number of TVS
    addresses and the index corresponds to their position in the list.
