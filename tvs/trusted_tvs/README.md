# Trusted TVS

This directory contains the trusted part of TVS that would eventually run in
a confidential VM.
TVS is split into two parts:
* Trusted part is written in Rust and performs sensitive operations such as
measurement verification, and minting JWT tokens. Communication between clients
and the trusted part is end-to-end encrypted using NK handshake.
* Untrusted part interfaces with cloud services and clients.

The two parts are statically linked - they live in the same binary. This model
lays the grounds for full isolation in the future by running the trusted part
in an enclave.
