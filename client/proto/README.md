# Client Proto

The directory contains proto files for HATs CVM RPC services and configuration.

* launcher_config.proto: describes configuration used by the launcher.
In particular it has CVM configuration and the auxiliary services that runs
outside the CVM.

* launcher.proto: defines RPC services exported by the launcher the CVM.

* orchestrator.proto: defines RPC services exported by HATs orchestator to the
workload in the CVM.

* trusted_service.proto: RPC service used by the test application in
`client/trusted_application/`.
