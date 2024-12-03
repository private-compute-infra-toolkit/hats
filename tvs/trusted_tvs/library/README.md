# Trusted TVS library

The directory contains the core implementation of trusted TVS library crate/

Trusted TVS can be used in C++ or Rust code, or can be used in Oak's restricted
kernel (no\_std environment). For Oak's restricted kernel the library implements
TvsEnclave RPC service and export it over MicroRpc.

The crate export the following modules:

1. service: public interface to use the crate. Clients use this crate to create
   a Service object that owns key materials, policies and means to fetch user
   secrets.
1. request\_handler: an object to handle a single attestation session. The user
   obtain a handler for every request from *service*.
1. interface: provide an interface to C++ code to use the crate.

The available feature flags are:

1. no\_std: running the crate in a non\_std environment e.g. Oak's restricted
   kernel.
1. default: enable creating crate to be used in Rust code and export the crate
   to C++.
1. enclave: export TvsEnclave RPC service over MicroRpc to be used in Oak's
   restricted kernel.
